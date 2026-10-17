"""Shared plumbing for the `agentconnect` commands: exit codes, error mapping,
output helpers and daemon-API conveniences. Protocol logic stays in the
daemon; nothing here decides anything about a group."""

from __future__ import annotations

import json
import re
import time
import unicodedata
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer

from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.config import Config, ConfigError, load_config
from agentconnect.sas_emoji import describe_emoji, render_emoji

# Exit codes (documented in docs/cli.md and `agentconnect --help`).
EXIT_OK = 0
EXIT_FAILED = 1  # the daemon or relay reported an error
EXIT_USAGE = 2  # bad arguments, bad invite URL, bad configuration
EXIT_REFUSED = 3  # refused: declined at a prompt, wrong token, wrong relay
EXIT_INTERCEPTED = 4  # invite already used or revoked: possible interception
EXIT_UNREACHABLE = 5  # the daemon is not running
EXIT_MISMATCH = 6  # the human reported different short codes; the group was left

EXIT_CODES_HELP = (
    "Exit codes: 0 ok, 1 failed, 2 usage or bad invite, 3 refused (declined, "
    "wrong token, other relay), 4 invite already used or revoked (possible "
    "interception), 5 daemon not running, 6 short-code mismatch reported."
)

HUMAN_ONLY_HELP = (
    "HUMAN ONLY: uses the human token. Never give an agent the human token or "
    "run this for the human; it exists so a person can make this decision."
)

INTERCEPTION_WARNING = (
    "This invite was already used or revoked. If you didn't expect this, the "
    "link may have been intercepted. Tell the sender."
)
SHARE_REMINDER = (
    "Share this over a channel you trust. After joining, compare the short code "
    "with the other members over a different channel (a call or in person)."
)
COMPARE_REMINDER = (
    "Compare the short code with the other members over a different channel "
    "(a call or in person), then run `agentconnect verify <group>`."
)

# SPEC 4.3: the maximum invite lifetime.
MAX_TTL_SECS = 7 * 86_400
_TTL_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86_400}
_MISMATCH_RELAY = "different relay"


class CliError(Exception):
    """A failure to report: a machine-readable code, a message, an exit code."""

    def __init__(self, code: str, message: str, exit_code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.code, self.message, self.exit_code = code, message, exit_code


def clean(text: object) -> str:
    """Peer-supplied text made safe for a terminal: control, format (bidi)
    and surrogate characters become ``?``. Names and purposes are attacker
    controlled (SPEC 4.2)."""
    return "".join("?" if unicodedata.category(c)[0] == "C" else c for c in str(text))


def emit_json(value: Any) -> None:
    typer.echo(json.dumps(value, ensure_ascii=False))


def emit_error(error: CliError, as_json: bool) -> None:
    if as_json:
        emit_json({"error": {"code": error.code, "message": error.message}})
    else:
        typer.echo(error.message, err=True)


def map_api_error(e: ApiClientError) -> CliError:  # noqa: PLR0911
    """A daemon error as a readable message and an exit code."""
    if e.code == "not_running":
        return CliError(
            "daemon_unreachable",
            "cannot reach the daemon; start it with `agentconnect daemon run`",
            EXIT_UNREACHABLE,
        )
    if e.code == "auth_failed":
        return CliError("auth_failed", "the daemon rejected the API token", EXIT_REFUSED)
    if e.code == "human_only":
        return CliError(
            "human_only",
            "this operation needs the human token; it is for a person, not an agent",
            EXIT_REFUSED,
        )
    if e.code == "forbidden":
        return CliError("forbidden", e.message or "not allowed", EXIT_REFUSED)
    if e.code == "invite_not_open":
        return CliError("invite_not_open", INTERCEPTION_WARNING, EXIT_INTERCEPTED)
    if e.code == "bad_request":
        if _MISMATCH_RELAY in e.message:
            return CliError(
                "wrong_relay",
                "This invite is for a different relay than this daemon uses. "
                "AgentConnect v0 supports one relay, so nothing was sent. "
                "Ask the sender for a link on your relay.",
                EXIT_REFUSED,
            )
        return CliError("bad_request", e.message or "invalid request", EXIT_USAGE)
    friendly = {
        "not_found": "not found",
        "expired": "expired",
        "stale_epoch": "the group changed; look at the new short code and try again",
        "rate_limited": "rate limited; try again shortly",
        "relay": "the relay refused the request",
    }
    detail = e.message or friendly.get(e.code, e.code)
    return CliError(e.code, detail, EXIT_FAILED)


@contextmanager
def guard(as_json: bool) -> Generator[None]:
    """Turn failures into a message (or JSON error) and the right exit code."""
    try:
        yield
    except CliError as e:
        emit_error(e, as_json)
        raise typer.Exit(e.exit_code) from None
    except ApiClientError as e:
        err = map_api_error(e)
        emit_error(err, as_json)
        raise typer.Exit(err.exit_code) from None
    except typer.Abort:
        emit_error(CliError("aborted", "aborted; nothing was changed", EXIT_REFUSED), as_json)
        raise typer.Exit(EXIT_REFUSED) from None


def load(path: Path | None) -> Config:
    try:
        return load_config(path)
    except ConfigError as e:
        raise CliError("config", f"config error: {e}", EXIT_USAGE) from None


def connect(path: Path | None, *, human: bool = False) -> ApiClient:
    """A client for the daemon. ``human=True`` reads the human token, only
    for the operations SPEC 6.2 and 11 reserve to a person."""
    return ApiClient(load(path), human=human)


def pause(seconds: float) -> None:
    """Wait between polls (a seam: tests replace it)."""
    time.sleep(seconds)


def parse_ttl(text: str) -> int:
    """``90``, ``30m``, ``24h`` or ``7d`` as seconds."""
    m = re.fullmatch(r"(\d+)([smhd]?)", text.strip().lower())
    if m is None:
        msg = f"bad --ttl {text!r}; use e.g. 30m, 24h or 7d"
        raise CliError("bad_ttl", msg, EXIT_USAGE)
    secs = int(m.group(1)) * _TTL_UNITS[m.group(2) or "s"]
    if not 0 < secs <= MAX_TTL_SECS:
        raise CliError("bad_ttl", "--ttl must be between 1 second and 7 days", EXIT_USAGE)
    return secs


def resolve_group(api: ApiClient, ref: str) -> str:
    """A group id from a full id, a unique id prefix, or an exact name."""
    groups = api.request("GET", "/v0/groups")["groups"]
    for g in groups:
        if g["group_id"] == ref:
            return str(g["group_id"])
    found = [g for g in groups if g["group_id"].startswith(ref)] or [
        g for g in groups if g["name"] == ref
    ]
    if len(found) == 1:
        return str(found[0]["group_id"])
    if not found:
        raise CliError("not_found", f"no group matches {ref!r}", EXIT_FAILED)
    raise CliError("ambiguous", f"{ref!r} matches {len(found)} groups; use more characters")


def events_after(api: ApiClient, after: int = 0) -> Iterator[dict[str, Any]]:
    """Every event with ``seq > after``, in order."""
    while True:
        page = api.request("GET", f"/v0/events?after={after}")["events"]
        yield from page
        if not page:
            return
        after = int(page[-1]["seq"])


@dataclass(frozen=True)
class Sas:
    decimal: str
    emoji: str
    names: str
    indices: list[int]

    @classmethod
    def of(cls, raw: dict[str, Any]) -> Sas:
        idx = [int(i) for i in raw["emoji_indices"]]
        return cls(str(raw["decimal"]), render_emoji(idx), describe_emoji(idx), idx)

    def as_json(self) -> dict[str, Any]:
        return {"decimal": self.decimal, "emoji": self.emoji, "emoji_names": self.names.split(", ")}

    def lines(self) -> list[str]:
        return [f"  {self.emoji}", f"  ({self.names})", f"  {self.decimal}"]


def unverified_hint(info: dict[str, Any]) -> str | None:
    """The agent-facing nudge when other members exist and aren't all verified."""
    trust = info["trust_state"]
    if trust["members"] > 1 and trust["self"] != "verified" and "sas" in info:
        decimal = info["sas"]["decimal"]
        return f"ask your human to compare the short code {decimal} with the other members"
    return None


def pending_for(api: ApiClient, group_id: str) -> list[dict[str, Any]]:
    return [
        a for a in api.request("GET", "/v0/approvals")["approvals"] if a["group_id"] == group_id
    ]


def group_view(api: ApiClient, group_id: str) -> dict[str, Any]:
    """The stable JSON shape of one group (docs/cli.md, ``groups show``)."""
    info = api.request("GET", f"/v0/groups/{group_id}")
    trust = info["trust_state"]
    others = max(trust["members"] - 1, 0)
    sas = Sas.of(info["sas"]).as_json() if "sas" in info else None
    return {
        "group_id": info["group_id"],
        "name": info["name"],
        "purpose": info["purpose"],
        "status": info["status"],
        "epoch": info["epoch"],
        "out_of_sync": info["out_of_sync"],
        "out_of_sync_reason": info["out_of_sync_reason"],
        "require_verified": bool(info["policy"].get("require_verified")),
        "trust_state": trust,
        "verified_summary": f"{trust['verified_members']} of {others} verified",
        "sas": sas,
        "members": [
            {
                "identity": m["identity"],
                "fingerprint": m["fingerprint"],
                "display_name": m["display_name"],
                "display_name_verified": m["display_name_verified"],
                "role": m["role"],
                "verified": m["verified"],
                "self": m["self"],
                "instances": len(m["instances"]),
            }
            for m in info["members"]
        ],
        "pending_approvals": len(pending_for(api, group_id)),
        "hint": unverified_hint(info),
    }
