"""`agentconnect knock`, `knocks` and knock approvals against a fake daemon API
(docs/discovery.md)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agentconnect import cli, cli_support
from agentconnect.apiclient import ApiClientError
from agentconnect.cli_json import SCHEMAS
from agentconnect.shapes import conforms

runner = CliRunner()
BIDI = chr(0x202E)
REF = "directory.example.org/a/release-planner"
GID = "G" * 43
SAS = {"decimal": "1234-5678-9012", "emoji_indices": [0, 1, 2, 3, 4, 5, 6]}


def inspected(*, domain: str | None = None, state: str = "unclaimed", fetch: str | None = None):
    return {
        "listing": {
            "url": "https://directory.example.org/a/release-planner.json",
            "directory": "directory.example.org",
            "name": "release-planner",
            "identity": "ac:v0:alice",
            "fingerprint": "3f9a 0c21",
            "display_name": "Release planner" + BIDI,
            "description": "Plans release trains.",
            "version": "1.0.0",
            "organization": "Example Ltd" if state == "verified" else None,
            "skills": [{"name": "Planning", "description": "Plans.", "tags": ["planning"]}],
            "sha256": "ab" * 32,
            "token_expires_at": 1_800_000_000,
        },
        "owner": {"domain": domain, "state": state, "fetch": fetch, "checked_at": None},
        "door": {"expires_at": 1_790_600_000},
        "untrusted": True,
        "notice": "Listing text ...",
        "warnings": [],
    }


SENT = {
    "knock_id": "K1",
    "status": "queued",
    "gives_up_at": 1_790_003_900,
    "listing": {
        "directory": "directory.example.org",
        "name": "release-planner",
        "identity": "ac:v0:alice",
        "fingerprint": "3f9a 0c21",
    },
    "owner": {"domain": None, "state": "unclaimed"},
}
GROUP = {
    "group_id": GID,
    "name": "release-planner",
    "purpose": "Plans release trains.",
    "status": "active",
    "epoch": 1,
    "policy": {"require_verified": False},
    "out_of_sync": False,
    "out_of_sync_reason": None,
    "trust_state": {"self": "unverified", "verified_members": 0, "members": 2},
    "members": [],
    "sas": SAS,
    "policy_summary": {
        "invite": "owner",
        "remove": "owner",
        "max_members": 50,
        "max_agent_turns": 20,
    },
    "floor": {"mode": "free", "pinned": False, "moderator": None},
    "pending_leaves": [],
}
KNOCK_APPROVAL = {
    "kind": "knock",
    "request_id": "kn-AAAAAAAAAAAAAAAA",
    "group_id": None,
    "identity": "ac:v0:bob",
    "display_name": "Bob's agent" + BIDI,
    "display_name_verified": False,
    "fingerprint": "1a2b 3c4d",
    "received_at": 1_790_000_000,
    "listing": {"directory": "directory.example.org", "name": "release-planner"},
    "note": "About the release" + BIDI,
    "note_verified": False,
    "ts": 1_790_000_000,
    "lapses_at": 1_790_003_600,
    "known": {"groups": 1, "verified_in": ["Deploy review"]},
}


def event(kind: str, seq: int = 1, **data: Any) -> dict[str, Any]:
    return {
        "seq": seq,
        "group_id": GID if kind == "joined" else None,
        "type": kind,
        "data": data,
        "at": 1,
        "event_id": "e",
    }


class Fake:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp: Path) -> None:
        self.routes: dict[str, Any] = {
            "POST /v0/knocks/inspect": lambda b: inspected(),
            "POST /v0/knocks": SENT,
            "GET /v0/events?after=0": {"events": [event("joined", knock_id="K1")]},
            "GET /v0/events?after=1": {"events": []},
            f"GET /v0/groups/{GID}": GROUP,
            "GET /v0/approvals": {"approvals": [KNOCK_APPROVAL], "messages": []},
            "GET /v0/knocks": {"knocks": [], "untrusted": True},
        }
        self.calls: list[tuple[bool, str, Any]] = []
        self.pauses: list[float] = []
        fake = self
        config = tmp / "config.toml"
        config.write_text("[knock]\ndomain_check = false\n", encoding="utf-8")
        monkeypatch.setenv("AC_CONFIG", str(config))

        class Api:
            def __init__(self, human: bool) -> None:
                self.human = human

            def request(self, method: str, path: str, body: Any = None) -> Any:
                key = f"{method} {path}"
                fake.calls.append((self.human, key, body))
                value = fake.routes[key]
                if isinstance(value, ApiClientError):
                    raise value
                return value(body) if callable(value) else value

        monkeypatch.setattr(cli, "connect", lambda _c, human=False: Api(human))
        monkeypatch.setattr(cli_support, "pause", self.pauses.append)

    def run(self, *args: str, input: str | None = None) -> Any:
        return runner.invoke(cli.app, list(args), input=input)

    def json(self, *args: str) -> tuple[int, Any]:
        result = self.run(*args, "--json")
        return result.exit_code, json.loads(result.stdout)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Fake:
    return Fake(monkeypatch, tmp_path)


def test_knock_shows_the_listing_asks_and_joins(fake: Fake) -> None:
    result = fake.run("knock", REF, input="y\n")
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Listing     release-planner on directory.example.org" in out
    assert "Owner       no owner claimed" in out
    assert "Release planner?" in out  # cleaned
    assert BIDI not in out
    assert "written by the listing's owner, not verified" in out
    assert "A listing proves who signed it, not what the agent does or who runs it." in out
    assert "Joined release-planner" in out
    assert "1234-5678-9012" in out
    keys = [k for _, k, _ in fake.calls]
    assert keys[:2] == ["POST /v0/knocks/inspect", "POST /v0/knocks"]
    assert not any(human for human, _, _ in fake.calls)  # the agent token
    assert fake.calls[1][2] == {"listing": REF, "listing_sha256": "ab" * 32, "domain_check": False}


def test_knock_declined_sends_nothing(fake: Fake) -> None:
    result = fake.run("knock", REF, input="n\n")
    assert result.exit_code == 3
    assert [k for _, k, _ in fake.calls] == ["POST /v0/knocks/inspect"]


def test_knock_asks_before_checking_the_owner_domain(fake: Fake) -> None:
    def answer(body: dict[str, Any]) -> dict[str, Any]:
        if body.get("domain_check"):
            return inspected(domain="example.com", state="verified")
        return inspected(domain="example.com", state="unchecked")

    fake.routes["POST /v0/knocks/inspect"] = answer
    result = fake.run("knock", REF, "--note", "hi", "--name", "Bob", input="y\ny\n")
    assert result.exit_code == 0, result.output
    assert "Check example.com now?" in result.output
    assert "example.com: verified by this daemon just now" in result.output
    assert "Example Ltd" in result.output
    bodies = [b for _, k, b in fake.calls if k.startswith("POST")]
    assert [b.get("domain_check") for b in bodies] == [False, True, True]
    assert (bodies[2]["display_name"], bodies[2]["note"]) == ("Bob", "hi")


@pytest.mark.parametrize(
    ("owner", "line"),
    [
        ({"state": "failed", "fetch": "unreachable"}, "could not fetch example.com"),
        ({"state": "failed"}, "example.com does not vouch for this key"),
        ({"state": "revoked"}, "example.com: revoked this key"),
        ({"state": "stale"}, "example.com: vouched before, not at the last check"),
    ],
)
def test_the_owner_line_says_what_the_check_found(
    fake: Fake, owner: dict[str, Any], line: str
) -> None:
    fake.routes["POST /v0/knocks/inspect"] = lambda b: inspected(domain="example.com", **owner)
    result = fake.run("knock", REF, "--yes", "--wait", "0")
    assert result.exit_code == 0, result.output
    assert line in result.output


def test_no_domain_check_skips_the_fetch(fake: Fake) -> None:
    fake.routes["POST /v0/knocks/inspect"] = lambda b: inspected(
        domain="example.com", state="unchecked"
    )
    result = fake.run("knock", REF, "--no-domain-check", input="y\n")
    assert result.exit_code == 0, result.output
    assert "example.com: not checked, --no-domain-check" in result.output
    assert "Check example.com now?" not in result.output
    assert [b.get("domain_check") for _, k, b in fake.calls if k.startswith("POST")] == [
        False,
        False,
    ]


def test_knock_json_joined_and_sent(fake: Fake) -> None:
    code, data = fake.json("knock", REF, "--yes")
    assert code == 0
    assert conforms(data, SCHEMAS["knock (joined)"]), data
    assert data["sas"]["decimal"] == SAS["decimal"]
    fake.routes["GET /v0/events?after=0"] = {"events": []}
    code, data = fake.json("knock", REF, "--yes", "--wait", "0")
    assert code == 0
    assert conforms(data, SCHEMAS["knock (sent)"]), data
    # Without --yes, --json can't ask.
    assert fake.json("knock", REF)[0] == 2


def test_no_answer_is_exit_1_and_says_nothing_about_why(fake: Fake) -> None:
    fake.routes["GET /v0/events?after=0"] = {"events": [event("knock_lapsed", knock_id="K1")]}
    code, data = fake.json("knock", REF, "--yes")
    assert code == 1
    assert data["error"]["code"] == "no_answer"
    assert "nothing tells them apart" in data["error"]["message"]
    fake.routes["GET /v0/events?after=0"] = {
        "events": [event("knock_failed", knock_id="K1", code="door_not_open")]
    }
    code, data = fake.json("knock", REF, "--yes")
    assert (code, data["error"]["code"]) == (1, "door_not_open")


def test_the_wait_polls_until_the_answer(fake: Fake) -> None:
    fake.routes["GET /v0/events?after=0"] = {"events": [event("knock_sent", knock_id="K1")]}
    fake.routes["GET /v0/events?after=1"] = [
        {"events": []},
        {"events": [event("joined", 2, knock_id="K1")]},
    ]
    fake.routes["GET /v0/events?after=2"] = {"events": []}

    def successive(answers: list[Any]) -> Callable[[Any], Any]:
        return lambda _b: answers.pop(0) if len(answers) > 1 else answers[0]

    fake.routes["GET /v0/events?after=1"] = successive(fake.routes["GET /v0/events?after=1"])
    code, data = fake.json("knock", REF, "--yes", "--wait", "5")
    assert code == 0
    assert data["status"] == "joined"
    assert fake.pauses


@pytest.mark.parametrize(
    ("code", "exit_code"),
    [
        ("listing_invalid", 7),
        ("listing_mismatch", 7),
        ("listing_rolled_back", 7),
        ("token_invalid", 7),
        ("self_knock", 3),
        ("wrong_relay", 3),
        ("human_only", 3),
        ("bad_listing_ref", 2),
        ("unknown_directory", 2),
        ("bad_request", 2),
        ("door_closed", 1),
        ("listing_withdrawn", 1),
        ("not_found", 1),
        ("too_many_knocks", 1),
        ("rate_limited", 1),
        ("already_pending", 1),
        ("not_running", 5),
    ],
)
def test_knock_exit_codes(fake: Fake, code: str, exit_code: int) -> None:
    error = ApiClientError(400, code, "refused")
    fake.routes["POST /v0/knocks/inspect"] = error
    result = fake.run("knock", REF, "--yes")
    assert result.exit_code == exit_code, result.output
    fake.routes["POST /v0/knocks/inspect"] = lambda b: inspected()
    fake.routes["POST /v0/knocks"] = error
    assert fake.run("knock", REF, "--yes").exit_code == exit_code


def test_exit_code_7_is_documented() -> None:
    assert (7, "EXIT_UNVERIFIED") in [(c, n) for c, n, _ in cli_support.EXIT_CODES]
    assert "7 a listing failed verification" in cli_support.EXIT_CODES_HELP


def test_knocks_lists_this_agents_knocks(fake: Fake) -> None:
    row = {
        "knock_id": "K1",
        "directory": "directory.example.org",
        "name": "release-planner" + BIDI,
        "fingerprint": "3f9a",
        "owner_state": "unclaimed",
        "display_name": "Release planner",
        "description": "Plans" + BIDI,
        "status": "joined",
        "created_at": 1_790_000_000,
        "gives_up_at": 1_790_003_900,
        "group_id": GID,
    }
    fake.routes["GET /v0/knocks"] = {"knocks": [row], "untrusted": True}
    result = fake.run("knocks")
    assert result.exit_code == 0
    assert "identity  3f9a" in result.output
    assert "owner     unclaimed (this daemon's check)" in result.output
    assert 'about     "Plans?"' in result.output
    assert "release-planner? on directory.example.org" in result.output
    assert f"[joined, group {GID}]" in result.output
    code, data = fake.json("knocks")
    assert code == 0
    assert conforms(data, SCHEMAS["knocks"])
    fake.routes["GET /v0/knocks"] = {"knocks": [], "untrusted": True}
    assert "No knocks." in fake.run("knocks").output


def test_a_knock_approval_is_shown_and_approved_with_the_human_token(fake: Fake) -> None:
    out = fake.run("approvals").output
    assert "Knock kn-AAAAAAAAAAAAAAAA on release-planner (directory.example.org)" in out
    assert '"Bob\'s agent?" (a claimed name, not verified)' in out
    assert '"About the release?" (written by the knocker, not verified)' in out
    assert 'member of 1 group(s) with you, verified in "Deploy review"' in out
    assert BIDI not in out
    code, data = fake.json("approvals", "list")
    assert code == 0
    assert conforms(data, SCHEMAS["approvals list"]), data
    rid = KNOCK_APPROVAL["request_id"]
    fake.routes[f"POST /v0/approvals/{rid}/approve"] = {"status": "approving", "group_id": GID}
    result = fake.run("approvals", "approve", str(rid), "--purpose", "Plan 1.4", input="y\n")
    assert result.exit_code == 0, result.output
    assert "Approving creates a new group with this agent. Start it?" in result.output
    human, key, body = fake.calls[-1]
    assert (human, key, body) == (
        True,
        f"POST /v0/approvals/{rid}/approve",
        {"purpose": "Plan 1.4"},
    )
    code, data = fake.json("approvals", "approve", str(rid), "--yes")
    assert code == 0
    assert conforms(data, SCHEMAS["approvals approve (knock)"]), data
    assert fake.calls[-1][2] is None  # no purpose: the listing's description


def test_a_declined_knock_approval_changes_nothing(fake: Fake) -> None:
    rid = str(KNOCK_APPROVAL["request_id"])
    result = fake.run("approvals", "approve", rid, input="n\n")
    assert result.exit_code == 3
    assert not [k for _, k, _ in fake.calls if k.endswith("/approve")]


def test_a_knock_is_rejected_with_the_human_token(fake: Fake) -> None:
    rid = str(KNOCK_APPROVAL["request_id"])
    fake.routes[f"POST /v0/approvals/{rid}/reject"] = {"status": "rejected"}
    code, data = fake.json("approvals", "reject", rid)
    assert code == 0
    assert data == {"request_id": rid, "status": "rejected"}
    assert fake.calls[-1][:2] == (True, f"POST /v0/approvals/{rid}/reject")


def test_purpose_is_for_knocks_only(fake: Fake) -> None:
    join = {
        "kind": "join",
        "request_id": "r1",
        "group_id": GID,
        "identity": "ac:v0:bob",
        "display_name": "bob",
        "display_name_verified": False,
        "fingerprint": "fp",
        "received_at": 1,
    }
    fake.routes["GET /v0/approvals"] = {"approvals": [join], "messages": []}
    result = fake.run("approvals", "approve", "r1", "--purpose", "x", "--yes")
    assert result.exit_code == 2
