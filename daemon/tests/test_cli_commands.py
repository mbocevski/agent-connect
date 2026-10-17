"""The lifecycle commands against a fake daemon API (no daemon, no network)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agentconnect import cli, cli_support
from agentconnect.apiclient import ApiClientError
from agentconnect.cli_json import SCHEMAS
from agentconnect.sas_emoji import SAS_EMOJI
from agentconnect.shapes import conforms

runner = CliRunner()
GID = "G" * 43
BOB = "ac:v0:bob"
ME = "ac:v0:me"
SAS = {"decimal": "1234-5678-9012", "emoji_indices": [0, 1, 2, 3, 4, 5, 6]}
BIDI = chr(0x202E)  # right-to-left override
URL = "https://relay.example/i/abc#v=0&s=xyz"  # not a secret: a fixture


def member(identity: str, *, me: bool = False, verified: bool = False) -> dict[str, Any]:
    return {
        "identity": identity,
        "fingerprint": f"fp-{identity[-3:]}",
        "display_name": identity[-3:],
        "display_name_verified": False,
        "role": "owner" if me else "member",
        "verified": verified,
        "instances": [{"instance_id": "i"}],
        "self": me,
    }


def group_info(*, verified: bool = False, members: int = 2, epoch: int = 1) -> dict[str, Any]:
    ms = [member(ME, me=True)] + ([member(BOB, verified=verified)] if members > 1 else [])
    return {
        "group_id": GID,
        "name": "Ops",
        "purpose": "Deploys",
        "status": "active",
        "epoch": epoch,
        "policy": {"require_verified": False},
        "out_of_sync": False,
        "out_of_sync_reason": None,
        "trust_state": {
            "self": "verified" if verified else "unverified",
            "verified_members": 1 if verified else 0,
            "members": members,
        },
        "members": ms,
        "sas": SAS,
    }


APPROVAL = {
    "request_id": "r1",
    "group_id": GID,
    "identity": BOB,
    "display_name": "bob" + BIDI,
    "display_name_verified": False,
    "fingerprint": "fp-bob",
    "received_at": 1000,
}
META = {
    "group_name": "Ops",
    "purpose": "Deploys",
    "inviter_name": "alice",
    "member_count": 1,
    "status": "open",
}


class FakeApi:
    """Answers by ``METHOD path`` (a value, or a callable of the body)."""

    def __init__(self, human: bool, routes: dict[str, Any], calls: list[tuple[bool, str, Any]]):
        self.human, self.routes, self.calls = human, routes, calls

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        key = f"{method} {path}"
        self.calls.append((self.human, key, body))
        value = self.routes[key]
        if isinstance(value, list):  # successive answers
            value = value.pop(0) if len(value) > 1 else value[0]
        if isinstance(value, ApiClientError):
            raise value
        return value(body) if callable(value) else value


class Fake:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.routes: dict[str, Any] = {
            "GET /v0/groups": {
                "groups": [
                    {"group_id": GID, "name": "Ops", "status": "active", "epoch": 1, "members": 2}
                    | {"out_of_sync": False}
                ]
            },
            f"GET /v0/groups/{GID}": group_info(),
            "GET /v0/approvals": {"approvals": []},
            "GET /v0/events?after=0": {"events": []},
        }
        self.calls: list[tuple[bool, str, Any]] = []
        self.pauses: list[float] = []
        monkeypatch.setattr(
            cli, "connect", lambda _c, human=False: FakeApi(human, self.routes, self.calls)
        )
        monkeypatch.setattr(cli_support, "pause", self.pauses.append)

    def run(self, *args: str, input: str | None = None) -> Any:
        return runner.invoke(cli.app, list(args), input=input)

    def json(self, *args: str, input: str | None = None) -> Any:
        result = self.run(*args, "--json", input=input)
        return result.exit_code, json.loads(result.stdout.splitlines()[-1])

    def posts(self, suffix: str) -> list[tuple[bool, Any]]:
        return [(h, b) for h, k, b in self.calls if k.endswith(suffix)]


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Fake:
    return Fake(monkeypatch)


# -- invites -----------------------------------------------------------------------


def test_group_create(fake: Fake) -> None:
    fake.routes["POST /v0/groups"] = lambda b: {"group_id": GID}
    code, out = fake.json("group", "create", "--purpose", "Deploys", "--name", "Ops")
    assert (code, out) == (0, {"group_id": GID, "name": "Ops", "purpose": "Deploys"})
    assert conforms(out, SCHEMAS["group create"])
    assert fake.posts("/v0/groups")[0][1] == {"name": "Ops", "purpose": "Deploys"}
    assert "Created group x" in fake.run("group", "create", "--purpose", "x").stdout


def test_invite_create_implicit_group_prints_url_and_reminder(fake: Fake) -> None:
    fake.routes["POST /v0/groups"] = {"group_id": GID}
    fake.routes[f"POST /v0/groups/{GID}/invites"] = {
        "url": URL,
        "invite_id": "abc",
        "expires_at": 5,
    }
    result = fake.run("invite", "create", "--purpose", "Deploys")
    assert result.exit_code == 0
    assert URL in result.stdout
    assert cli_support.SHARE_REMINDER in result.stdout
    assert fake.posts("/invites")[0][1] == {"ttl_secs": 86_400, "max_uses": 1}
    assert fake.posts("/v0/groups")[0][1]["name"] == "Deploys"


def test_invite_create_options_and_policy(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/invites"] = {
        "url": URL,
        "invite_id": "abc",
        "expires_at": 5,
    }
    fake.routes[f"POST /v0/groups/{GID}/policy"] = {"require_verified": True}
    code, out = fake.json(
        "invite",
        "create",
        "--group",
        GID[:6],
        "--ttl",
        "2h",
        "--max-uses",
        "3",
        "--require-verified",
    )
    assert code == 0
    assert conforms(out, SCHEMAS["invite create"])
    assert fake.posts("/invites")[0][1] == {"ttl_secs": 7200, "max_uses": 3}
    assert fake.posts("/policy")[0][1] == {"require_verified": True}


@pytest.mark.parametrize("ttl", ["soon", "8d", "0"])
def test_bad_ttl_is_a_usage_error(fake: Fake, ttl: str) -> None:
    code, out = fake.json("invite", "create", "--ttl", ttl)
    assert (code, out["error"]["code"]) == (2, "bad_ttl")


def test_purpose_with_group_is_usage_error(fake: Fake) -> None:
    assert fake.run("invite", "create", "--group", GID, "--purpose", "x").exit_code == 2


def test_revoke(fake: Fake) -> None:
    fake.routes["DELETE /v0/invites/abc"] = {"revoked": "abc"}
    assert fake.json("invite", "revoke", "abc") == (0, {"revoked": "abc"})
    assert conforms(fake.json("invite", "revoke", "abc")[1], SCHEMAS["invite revoke"])
    assert "Revoked" in fake.run("invite", "revoke", "abc").stdout


# -- accept ----------------------------------------------------------------------------


def accept_routes(fake: Fake, events: Any) -> None:
    fake.routes["POST /v0/invites/inspect"] = {"meta": META, "warning": None, "untrusted": True}
    fake.routes["POST /v0/invites/accept"] = {"invite_id": "abc", "status": "pending"}
    fake.routes["GET /v0/events?after=0"] = events


def joined(seq: int = 1) -> dict[str, Any]:
    return {
        "events": [
            {
                "seq": seq,
                "group_id": GID,
                "type": "joined",
                "data": {"invite_id": "abc", "sas": SAS},
                "at": 1,
            }
        ]
    }


def test_accept_confirms_then_joins_and_shows_the_sas(fake: Fake) -> None:
    accept_routes(fake, joined())
    result = fake.run("accept", URL, input="y\n")
    assert result.exit_code == 0, result.output
    assert "Invited by alice" in result.stdout
    assert SAS_EMOJI[0][0] in result.stdout
    assert "1234-5678-9012" in result.stdout
    assert "different channel" in result.stdout


def test_accept_declined_sends_nothing(fake: Fake) -> None:
    accept_routes(fake, joined())
    result = fake.run("accept", URL, input="n\n")
    assert result.exit_code == 3
    assert not fake.posts("/accept")


def test_accept_json_schema_and_hint(fake: Fake) -> None:
    accept_routes(fake, joined())
    code, out = fake.json("accept", URL, "--yes")
    assert code == 0
    assert out["status"] == "joined"
    assert out["hint"] == (
        "ask your human to compare the short code 1234-5678-9012 with the other members"
    )
    assert conforms(out, SCHEMAS["accept (approved)"])


def test_accept_json_needs_yes(fake: Fake) -> None:
    accept_routes(fake, joined())
    code, out = fake.json("accept", URL)
    assert (code, out["error"]["code"]) == (2, "needs_yes")


def test_accept_waits_for_approval_then_times_out_pending(fake: Fake) -> None:
    accept_routes(fake, {"events": []})
    code, out = fake.json("accept", URL, "--yes", "--wait", "3")
    assert code == 0
    assert out["status"] == "pending"
    assert out["group_id"] is None
    assert conforms(out, SCHEMAS["accept (still pending)"])
    assert fake.pauses == [1.0, 1.0]
    assert "Not approved yet" in fake.run("accept", URL, "--yes", "--wait", "0").stdout


def test_accept_join_failed(fake: Fake) -> None:
    ev = {
        "seq": 1,
        "group_id": None,
        "type": "join_failed",
        "data": {"invite_id": "abc", "reason": "x"},
    }
    accept_routes(fake, {"events": [ev]})
    code, out = fake.json("accept", URL, "--yes")
    assert (code, out["error"]["code"]) == (1, "join_failed")


@pytest.mark.parametrize("status", ["exhausted", "revoked"])
def test_accept_used_or_revoked_invite_warns_loudly(fake: Fake, status: str) -> None:
    accept_routes(fake, {"events": []})
    fake.routes["POST /v0/invites/inspect"] = {
        "meta": META | {"status": status},
        "warning": cli_support.INTERCEPTION_WARNING,
    }
    result = fake.run("accept", URL, "--yes")
    assert result.exit_code == 4
    assert "may have been intercepted" in result.output
    assert not fake.posts("/accept")


def test_accept_relay_says_not_open(fake: Fake) -> None:
    accept_routes(fake, {"events": []})
    fake.routes["POST /v0/invites/inspect"] = ApiClientError(409, "invite_not_open", "gone")
    code, out = fake.json("accept", URL, "--yes")
    assert code == 4
    assert out["error"]["message"] == cli_support.INTERCEPTION_WARNING


def test_accept_expired_invite(fake: Fake) -> None:
    accept_routes(fake, {"events": []})
    fake.routes["POST /v0/invites/inspect"] = {
        "meta": META | {"status": "expired"},
        "warning": None,
    }
    assert fake.run("accept", URL, "--yes").exit_code == 1


def test_accept_other_relay_is_a_clear_refusal(fake: Fake) -> None:
    msg = "the invite is for a different relay"
    fake.routes["POST /v0/invites/inspect"] = ApiClientError(400, "bad_request", msg)
    result = fake.run("accept", URL, "--yes")
    assert result.exit_code == 3
    assert "different relay" in result.output
    assert "nothing was sent" in result.output


def test_accept_bad_url_is_usage(fake: Fake) -> None:
    fake.routes["POST /v0/invites/inspect"] = ApiClientError(400, "bad_request", "bad url")
    assert fake.run("accept", "nonsense", "--yes").exit_code == 2


# -- groups ------------------------------------------------------------------------------


def test_groups_list_and_default(fake: Fake) -> None:
    for args in (("groups",), ("groups", "list")):
        assert GID in fake.run(*args).stdout
    code, out = fake.json("groups", "list")
    assert code == 0
    assert conforms(out, SCHEMAS["groups list"])


def test_groups_show_human(fake: Fake) -> None:
    fake.routes["GET /v0/approvals"] = {"approvals": [APPROVAL]}
    out = fake.run("groups", "show", GID[:5]).stdout
    assert "0 of 1 verified" in out
    assert "Pending approvals  1" in out
    assert "1234-5678-9012" in out
    assert "owner" in out


def test_groups_show_json_hint_only_while_unverified(fake: Fake) -> None:
    _, out = fake.json("groups", "show", GID)
    assert out["hint"] is not None
    assert out["verified_summary"] == "0 of 1 verified"
    assert conforms(out, SCHEMAS["groups show"])
    fake.routes[f"GET /v0/groups/{GID}"] = group_info(verified=True)
    _, out = fake.json("groups", "show", "Ops")
    assert out["hint"] is None
    assert out["verified_summary"] == "1 of 1 verified"
    fake.routes[f"GET /v0/groups/{GID}"] = group_info(members=1)
    assert fake.json("groups", "show", GID)[1]["hint"] is None


def test_unknown_and_ambiguous_group(fake: Fake) -> None:
    assert fake.json("groups", "show", "nope")[1]["error"]["code"] == "not_found"
    fake.routes["GET /v0/groups"] = {
        "groups": [{"group_id": "Aa", "name": "x"}, {"group_id": "Ab", "name": "y"}]
    }
    code, out = fake.json("groups", "show", "A")
    assert (code, out["error"]["code"]) == (1, "ambiguous")


# -- approvals ---------------------------------------------------------------------------


def test_approvals_list_shows_fingerprint_and_sas(fake: Fake) -> None:
    fake.routes["GET /v0/approvals"] = {"approvals": [APPROVAL]}
    out = fake.run("approvals").stdout
    assert "fp-bob" in out
    assert "1234-5678-9012" in out
    assert BIDI not in out  # bidi control stripped from the claimed name
    code, data = fake.json("approvals", "list")
    assert code == 0
    assert conforms(data, SCHEMAS["approvals list"])
    fake.routes["GET /v0/approvals"] = {"approvals": []}
    assert "No pending" in fake.run("approvals", "list").stdout


def test_approve_uses_the_human_token_and_confirms(fake: Fake) -> None:
    fake.routes["GET /v0/approvals"] = {"approvals": [APPROVAL]}
    fake.routes["POST /v0/approvals/r1/approve"] = {"status": "approving"}
    assert fake.run("approvals", "approve", "r1", input="n\n").exit_code == 3
    assert not fake.posts("/approve")
    result = fake.run("approvals", "approve", "r1", input="y\n")
    assert result.exit_code == 0
    assert "agentconnect verify" in result.stdout
    assert fake.posts("/approve")[0][0] is True  # human scope
    code, out = fake.json("approvals", "approve", "r1", "--yes")
    assert (code, out["status"]) == (0, "approving")
    assert conforms(out, SCHEMAS["approvals approve"])
    assert fake.json("approvals", "approve", "r1")[1]["error"]["code"] == "needs_yes"


def test_reject_and_unknown_request(fake: Fake) -> None:
    fake.routes["GET /v0/approvals"] = {"approvals": [APPROVAL]}
    fake.routes["POST /v0/approvals/r1/reject"] = {"status": "rejected"}
    assert fake.json("approvals", "reject", "r1") == (
        0,
        {"request_id": "r1", "status": "rejected"},
    )
    assert conforms(fake.json("approvals", "reject", "r1")[1], SCHEMAS["approvals reject"])
    assert fake.posts("/reject")[0][0] is True
    assert "Rejected" in fake.run("approvals", "reject", "r1").stdout
    assert fake.run("approvals", "reject", "zzz").exit_code == 1


def test_human_only_refusal_maps_to_refused(fake: Fake) -> None:
    fake.routes["GET /v0/approvals"] = {"approvals": [APPROVAL]}
    fake.routes["POST /v0/approvals/r1/reject"] = ApiClientError(403, "human_only", "x")
    code, out = fake.json("approvals", "reject", "r1")
    assert (code, out["error"]["code"]) == (3, "human_only")


# -- verify ---------------------------------------------------------------------------------


def test_verify_yes_marks_every_other_member(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/members/{BOB}/verify"] = {"verified": True}
    result = fake.run("verify", GID, input="y\n")
    assert result.exit_code == 0, result.output
    assert "Do the other members see exactly this code? [y/N]" in result.stdout
    assert fake.posts("/verify")[0] == (True, {"verified": True})
    code, out = fake.json("verify", GID, input="y\n")
    assert (code, out) == (0, {"outcome": "verified", "group_id": GID, "verified": [BOB]})
    assert conforms(out, SCHEMAS["verify (verified)"])


def test_verify_default_answer_is_no(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/sas/mismatch"] = {"status": "left"}
    result = fake.run("verify", GID, input="\n")
    assert result.exit_code == 6
    assert not fake.posts("/verify")


def test_verify_without_a_person_never_verifies(fake: Fake) -> None:
    result = fake.run("verify", GID, input="")  # no answer at all: EOF
    assert result.exit_code == 3
    assert not fake.posts("/verify")
    assert not fake.posts("/mismatch")


def test_verify_refuses_when_the_group_changed_meanwhile(fake: Fake) -> None:
    fake.routes[f"GET /v0/groups/{GID}"] = [group_info(), group_info(epoch=2)]
    result = fake.run("verify", GID, input="y\n")
    assert result.exit_code == 3
    assert "changed while you compared" in result.output
    assert not fake.posts("/verify")


def test_verify_needs_other_members_and_an_active_group(fake: Fake) -> None:
    fake.routes[f"GET /v0/groups/{GID}"] = group_info(members=1)
    assert fake.json("verify", GID)[1]["error"]["code"] == "no_members"
    fake.routes[f"GET /v0/groups/{GID}"] = {**group_info(), "status": "left"}
    assert fake.json("verify", GID)[1]["error"]["code"] == "not_active"


def mismatch_event(transfer: dict[str, Any] | None) -> dict[str, Any]:
    data: dict[str, Any] = {"epoch": 1, "sas": SAS}
    if transfer is not None:
        data["transfer"] = transfer
    return {"events": [{"seq": 9, "group_id": GID, "type": "sas_mismatch", "data": data, "at": 1}]}


def test_verify_no_reports_the_mismatch_and_handover(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/sas/mismatch"] = {"status": "left"}
    fake.routes["GET /v0/events?after=0"] = mismatch_event({"new_owner": BOB, "confirmed": True})
    fake.routes["GET /v0/events?after=9"] = {"events": []}
    code, out = fake.json("verify", GID, input="n\n")
    assert code == 6
    assert out == {
        "outcome": "mismatch",
        "group_id": GID,
        "status": "left",
        "ownership_transfer": {"new_owner": BOB, "confirmed": True, "new_owner_name": "bob"},
    }
    assert conforms(out, SCHEMAS["verify (mismatch)"])
    assert fake.posts("/mismatch")[0] == (True, {"epoch": 1})
    text = fake.run("verify", GID, input="n\n").stdout
    assert "handed to bob" in text
    assert "You have left" in text


def test_verify_no_unconfirmed_handover_and_non_owner(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/sas/mismatch"] = {"status": "left"}
    fake.routes["GET /v0/events?after=9"] = {"events": []}
    fake.routes["GET /v0/events?after=0"] = mismatch_event({"new_owner": BOB, "confirmed": False})
    assert "NOT confirmed" in fake.run("verify", GID, input="n\n").stdout
    fake.routes["GET /v0/events?after=0"] = mismatch_event(None)
    out = fake.run("verify", GID, input="n\n").stdout
    assert "don't rejoin" in out
    out = fake.json("verify", GID, input="n\n")[1]
    assert out["ownership_transfer"] is None
    assert conforms(out, SCHEMAS["verify (mismatch)"])


# -- leave, send, events, errors ------------------------------------------------------------


def test_leave(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/leave"] = [{"status": "left"}, {"status": "leaving"}]
    assert fake.json("leave", GID) == (0, {"group_id": GID, "status": "left"})
    assert conforms(fake.json("leave", GID)[1], SCHEMAS["leave"])
    assert "Leaving" in fake.run("leave", GID).stdout
    fake.routes[f"POST /v0/groups/{GID}/leave"] = ApiClientError(403, "forbidden", "transfer first")
    assert fake.run("leave", GID).exit_code == 3


def test_send_with_recipients_and_hint(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/messages"] = {"msg_id": "m1"}
    code, out = fake.json("send", GID, "hello", "--to", BOB)
    assert code == 0
    assert conforms(out, SCHEMAS["send"])
    assert fake.posts("/messages")[0] == (False, {"text": "hello", "to": [BOB]})
    assert "Note: ask your human" in fake.run("send", GID, "hi").stdout


def test_events_list_follow_and_interrupt(fake: Fake, monkeypatch: pytest.MonkeyPatch) -> None:
    ev = {"seq": 3, "group_id": GID, "type": "joined", "data": {}, "at": 0, "event_id": "e3"}
    fake.routes["GET /v0/events?after=0"] = {"events": [ev]}
    fake.routes["GET /v0/events?after=3"] = {"events": []}
    assert "3  1970-01-01 00:00 UTC  joined" in fake.run("events").stdout
    lines = fake.run("events", "--json").stdout.splitlines()
    assert conforms(json.loads(lines[0]), SCHEMAS["events (one object per line)"])

    def stop(_s: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_support, "pause", stop)
    assert fake.run("events", "--follow").exit_code == 0


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ApiClientError(0, "not_running", "x"), 5),
        (ApiClientError(401, "auth_failed", "x"), 3),
        (ApiClientError(404, "not_found", "no such"), 1),
        (ApiClientError(409, "stale_epoch", ""), 1),
        (ApiClientError(502, "relay", "down"), 1),
    ],
)
def test_error_mapping(fake: Fake, error: ApiClientError, code: int) -> None:
    fake.routes["GET /v0/groups"] = error
    result = fake.run("groups")
    assert result.exit_code == code
    assert result.output.strip()
    got, out = fake.json("groups")
    assert (got, out["error"]["code"] in {error.code, "daemon_unreachable"}) == (code, True)


def test_config_errors_are_usage(tmp_path: Path) -> None:
    bad = tmp_path / "c.toml"
    bad.write_text('[relay]\nurl = "http://x"\n', encoding="utf-8")
    result = runner.invoke(cli.app, ["groups", "--config", str(bad)])
    assert result.exit_code == 2
    assert runner.invoke(cli.app, ["groups", "--json", "--config", str(bad)]).exit_code == 2


def test_clean_strips_control_characters() -> None:
    assert cli_support.clean("a\x1b[31mb" + BIDI + "c\n") == "a?[31mb?c?"


def test_status_over_fake(fake: Fake) -> None:
    fake.routes["GET /v0/status"] = {
        "identity": ME,
        "fingerprint": "fp",
        "relay": {"url": "ws://r", "connected": True},
        "groups": 1,
        "out_of_sync": [],
        "outbox_queued": 0,
        "inbox_pending": 0,
        "pending_approvals": 0,
    }
    assert "connected" in fake.run("status").stdout
    assert fake.json("status")[1]["identity"] == ME


def test_help_documents_exit_codes_and_the_human_token() -> None:
    top = runner.invoke(cli.app, ["--help"]).stdout
    assert "Exit codes" in top
    assert "human token" in top
    assert "HUMAN ONLY" in runner.invoke(cli.app, ["verify", "--help"]).stdout
    assert "HUMAN ONLY" in runner.invoke(cli.app, ["approvals", "approve", "--help"]).stdout


def test_ttl_units() -> None:
    assert [cli_support.parse_ttl(t) for t in ("90", "30m", "24h", "7d")] == [
        90,
        1800,
        86400,
        604800,
    ]
