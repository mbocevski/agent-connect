"""Shared plumbing for the `agentconnect` commands: exit codes, error mapping,
output helpers and daemon-API conveniences. Protocol logic stays in the
daemon; nothing here decides anything about a group."""

from __future__ import annotations

import json
import re
import time
import unicodedata
from collections.abc import Callable, Generator, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, override

import typer
from typer.core import TyperCommand

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
EXIT_UNVERIFIED = 7  # a listing failed verification: a suspect directory, not "no answer"

# The same codes with their meaning, for the docs (scripts/gen_reference.py).
EXIT_CODES: tuple[tuple[int, str, str], ...] = (
    (EXIT_OK, "EXIT_OK", "Success."),
    (
        EXIT_FAILED,
        "EXIT_FAILED",
        "Failed: the daemon or relay reported an error (not found, relay down, ...).",
    ),
    (
        EXIT_USAGE,
        "EXIT_USAGE",
        "Usage: bad arguments, malformed invite URL, bad configuration, an unreadable or "
        "invalid card or token file.",
    ),
    (
        EXIT_REFUSED,
        "EXIT_REFUSED",
        "Refused: declined at a prompt, human-only operation, the group changed while "
        "comparing, invite for a different relay (nothing is sent), a listing token for "
        "another identity or key, a local API socket another user serves (nothing is sent).",
    ),
    (
        EXIT_INTERCEPTED,
        "EXIT_INTERCEPTED",
        "Interception warning: the invite was already used or revoked.",
    ),
    (EXIT_UNREACHABLE, "EXIT_UNREACHABLE", "The daemon is not running or unreachable."),
    (
        EXIT_MISMATCH,
        "EXIT_MISMATCH",
        "`verify` mismatch: you reported different codes and left the group.",
    ),
    (
        EXIT_UNVERIFIED,
        "EXIT_UNVERIFIED",
        "`knock`: the listing the directory served failed verification (signature, "
        "canonical form, the token under the pinned keys, another name's listing, or "
        "older than one seen before). The directory may be lying; nothing was sent.",
    ),
)

EXIT_CODES_HELP = (
    "Exit codes: 0 ok, 1 failed, 2 usage or bad invite, 3 refused (declined, "
    "wrong token, other relay), 4 invite already used or revoked (possible "
    "interception), 5 daemon not running, 6 short-code mismatch reported, 7 a "
    "listing failed verification."
)

HUMAN_ONLY_HELP = (
    "HUMAN ONLY: uses the human token. Never give an agent the human token or "
    "run this for the human; it exists so a person can make this decision."
)
LOCAL_ONLY_HELP = (
    "LOCAL ONLY: works on a stopped runtime's data directory, with no API and "
    "no token. A person runs it; no agent tool offers it."
)

INTERCEPTION_WARNING = (
    "This invite was already used or revoked. If you didn't expect this, the "
    "link may have been intercepted. Tell the sender."
)
SHARE_REMINDER = (
    "Share this over a channel you trust. After joining, compare the short code "
    "with the other members over a different channel (a call or in person)."
)
REPLICA_REMINDER = (
    "Accept it on the replica's host only (`agentconnect accept <url>` there): only an "
    "instance of your own identity can join through it, and with --instance only that one. "
    "Without --instance, approve only the request whose instance is the one `identity "
    "import` printed. The other members will see a new instance of yours join."
)
COMPARE_REMINDER = (
    "Compare the short code with each other member over a different channel (a call "
    "or in person): both of you run `agentconnect verify <group> <member>` at the same time."
)

# SPEC 4.3: the maximum invite lifetime.
MAX_TTL_SECS = 7 * 86_400
_TTL_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86_400}


# Publish refusals that are about the files or the token the person gave:
# fix the input (usage) or get the right token (refused).
LISTING_EXITS = {
    "unknown_directory": EXIT_USAGE,
    "bad_card": EXIT_USAGE,
    "bad_token": EXIT_USAGE,
    "token_not_for_identity": EXIT_REFUSED,
    "unknown_key": EXIT_REFUSED,
}


# Knock refusals: a listing that fails verification is a suspect directory
# (unverified), not a failure to answer; the rest are about the request.
KNOCK_EXITS = {
    "listing_invalid": EXIT_UNVERIFIED,
    "listing_mismatch": EXIT_UNVERIFIED,
    "listing_rolled_back": EXIT_UNVERIFIED,
    "token_invalid": EXIT_UNVERIFIED,
    "self_knock": EXIT_REFUSED,
    "bad_listing_ref": EXIT_USAGE,
    "unknown_directory": EXIT_USAGE,
}
NO_ANSWER = (
    "No answer by {time}. The owner may be offline or busy, or chose not to answer; "
    "nothing tells them apart."
)


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
    if e.code in ("forbidden", "not_permitted"):
        # not_permitted: the group policy doesn't let this identity (SPEC 9.2).
        return CliError(e.code, e.message or "not allowed", EXIT_REFUSED)
    if e.code == "peer_refused":
        return CliError(
            "peer_refused",
            "the daemon refused this OS user (separate-user mode); human commands run "
            "as the daemon's user, see docs/isolation.md",
            EXIT_REFUSED,
        )
    if e.code == "peer_mismatch":
        # Not the daemon's socket; the message names the path and the UIDs.
        return CliError("peer_mismatch", e.message, EXIT_REFUSED)
    if e.code == "invite_not_open":
        return CliError("invite_not_open", INTERCEPTION_WARNING, EXIT_INTERCEPTED)
    if e.code == "wrong_relay":
        return CliError(
            "wrong_relay",
            "This invite is for a different relay than this daemon uses. "
            "AgentConnect v0 supports one relay, so nothing was sent. "
            "Ask the sender for a link on your relay.",
            EXIT_REFUSED,
        )
    if e.code == "bad_request":
        return CliError("bad_request", e.message or "invalid request", EXIT_USAGE)
    if e.code in LISTING_EXITS:
        return CliError(e.code, e.message or e.code, LISTING_EXITS[e.code])
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


def options_first(params: Iterable[Any], args: list[str]) -> list[str]:
    """``args`` reordered as the known options (with their values), then
    ``--``, then every other token in its original order.

    Group, invite and request ids are random base64url, so they can start
    with ``-``; so can a message text. The parser would take such a token
    for an option. Only exact names of the command's own options count as
    options here; anything else is a positional, and ``--`` makes the
    parser read it as one. Everything after a ``--`` the user typed stays
    positional."""
    arity: dict[str, int] = {}
    for p in params:
        if getattr(p, "param_type_name", None) != "option":
            continue
        n = 0 if getattr(p, "is_flag", False) or getattr(p, "count", False) else p.nargs
        for name in (*p.opts, *p.secondary_opts):
            arity[name] = n
    options: list[str] = []
    positionals: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            positionals.extend(args[i + 1 :])
            break
        name, attached = arg.split("=", 1)[0], "=" in arg
        if arg.startswith("--") and name in arity:
            take = 0 if attached else arity[name]
        elif arg in arity:
            take = arity[arg]
        else:
            positionals.append(arg)
            i += 1
            continue
        if i + take >= len(args) and take:
            raise MissingValueError(name)
        options.extend(args[i : i + 1 + take])
        i += 1 + take
    return [*options, "--", *positionals] if positionals else options


class MissingValueError(ValueError):
    """An option that takes a value came last, without one."""


class IdArgsCommand(TyperCommand):
    """A command whose positional arguments may start with ``-`` (ids are
    random base64url). See :func:`options_first`."""

    @override
    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        try:
            ordered = options_first(self.get_params(ctx), args)
        except MissingValueError as e:
            msg = f"option {e.args[0]!r} requires an argument"
            raise typer.BadParameter(msg, ctx=ctx) from None
        return super().parse_args(ctx, ordered)


def load(path: Path | None, *, need_relay: bool = False) -> Config:
    try:
        cfg = load_config(path)
        if need_relay:
            cfg.require_relay()
        return cfg
    except ConfigError as e:
        raise CliError("config", f"config error: {e}", EXIT_USAGE) from None


def connect(path: Path | None, *, human: bool = False) -> ApiClient:
    """A client for the daemon. ``human=True`` reads the human token, only
    for the operations SPEC 6.2 and 11 reserve to a person."""
    return ApiClient(load(path), human=human)


def connect_preferring_human(path: Path | None) -> ApiClient:
    """The human token when this user can read it, else the agent token: for
    an operation either may run whose answer is the human's when it can be
    (leaving after the owner's close, SPEC 7.3)."""
    config = load(path)
    try:
        return ApiClient(config, human=True)
    except (ApiClientError, OSError):
        return ApiClient(config)


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


def events_after(
    api: ApiClient, after: int = 0, on_gap: Callable[[int], None] | None = None
) -> Iterator[dict[str, Any]]:
    """Every event with ``seq > after``, in order. ``on_gap`` hears the
    lowest ``seq`` left when retention removed some of them."""
    while True:
        reply = api.request("GET", f"/v0/events?after={after}")
        if reply.get("gap") and on_gap is not None:
            on_gap(int(reply.get("oldest_available", 0)))
            on_gap = None
        page = reply["events"]
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
    if trust["members"] > 1 and trust["self"] != "verified" and info["status"] == "active":
        return (
            "ask your human to compare the short code with each other member: "
            f"`agentconnect verify {info['group_id']} <member>` on both sides"
        )
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
        "leaving": info.get("leaving"),
        "policy_summary": info["policy_summary"],
        "floor": info["floor"],
        "pending_leaves": info["pending_leaves"],
        "members": [
            {
                "identity": m["identity"],
                "fingerprint": m["fingerprint"],
                "display_name": m["display_name"],
                "display_name_verified": m["display_name_verified"],
                "role": m["role"],
                "verified": m["verified"],
                "self": m["self"],
                "instances": [
                    {
                        "instance_id": i["instance_id"],
                        "leaf_index": i["leaf_index"],
                        "joined_epoch": i["joined_epoch"],
                        "self": bool(i.get("self")),
                        "new_since_verified": None
                        if m["instances_since_verified"] is None
                        else i["instance_id"] in m["instances_since_verified"],
                    }
                    for i in m["instances"]
                ],
            }
            for m in info["members"]
        ],
        "pending_approvals": len(pending_for(api, group_id)),
        "hint": unverified_hint(info),
    }
