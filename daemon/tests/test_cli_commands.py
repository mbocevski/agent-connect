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
        "instances": [
            {
                "instance_id": ("0" if me else "1") * 16,
                "mailbox_id": "m",
                "leaf_index": 0 if me else 1,
                "joined_epoch": 0 if me else 1,
                "self": me,
            }
        ],
        "instances_since_verified": [],
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
        "policy_summary": {
            "invite": "owner",
            "remove": "owner",
            "max_members": 50,
            "max_agent_turns": 20,
        },
        "floor": {"mode": "free", "pinned": False, "moderator": None},
        "pending_leaves": [],
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


def test_a_replica_invite_uses_the_human_token_and_needs_a_group(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/invites"] = {
        "url": URL,
        "invite_id": "abc",
        "expires_at": 5,
    }
    code, out = fake.json("invite", "create", "--group", GID, "--replica")
    assert code == 0
    assert conforms(out, SCHEMAS["invite create"])
    assert out["replica"] is True
    assert "replica's host" in out["reminder"]
    assert fake.posts("/invites") == [(True, {"ttl_secs": 86400, "max_uses": 1, "replica": True})]
    shown = fake.run("invite", "create", "--group", GID, "--replica").stdout
    assert "Replica invite for group" in shown
    # A plain invite stays on the agent token and doesn't say replica.
    code, out = fake.json("invite", "create", "--group", GID)
    assert (code, out["replica"]) == (0, False)
    assert fake.posts("/invites")[-1] == (False, {"ttl_secs": 86400, "max_uses": 1})
    code, out = fake.json("invite", "create", "--replica")
    assert (code, out["error"]["code"]) == (2, "bad_args")


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
    fake.routes["POST /v0/invites/inspect"] = ApiClientError(400, "wrong_relay", "elsewhere")
    result = fake.run("accept", URL, "--yes")
    assert result.exit_code == 3
    assert "different relay" in result.output
    assert "nothing was sent" in result.output
    code, out = fake.json("accept", URL, "--yes")
    assert (code, out["error"]["code"]) == (3, "wrong_relay")
    assert not fake.posts("/accept")


def test_wrong_relay_comes_from_the_error_code_not_its_message(fake: Fake) -> None:
    msg = "the invite is for a different relay"
    fake.routes["POST /v0/invites/inspect"] = ApiClientError(400, "bad_request", msg)
    code, out = fake.json("accept", URL, "--yes")
    assert (code, out["error"]["code"]) == (2, "bad_request")


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


def test_groups_show_lists_instances_and_a_blocked_leave(fake: Fake) -> None:
    out = fake.run("groups", "show", GID).stdout
    assert f"instance {'0' * 16}  leaf 0  since epoch 0  (this one)" in out
    assert f"instance {'1' * 16}  leaf 1  since epoch 1" in out
    assert "Policy    invite owner, remove owner, at most 50 instances, 20 agent turns" in out
    assert "Floor     free, moderator none" in out
    assert "Leaving" not in out
    info = group_info()
    info["leaving"] = {"since": 1_700_000_000, "blocked": True}
    fake.routes[f"GET /v0/groups/{GID}"] = info
    out = fake.run("groups", "show", GID).stdout
    assert "Leaving   since 2023-11-14 22:13 UTC" in out
    assert "hand ownership over" in out
    _, view = fake.json("groups", "show", GID)
    assert conforms(view, SCHEMAS["groups show"])
    assert view["leaving"] == {"since": 1_700_000_000, "blocked": True}
    assert view["members"][0]["instances"] == [
        {
            "instance_id": "0" * 16,
            "leaf_index": 0,
            "joined_epoch": 0,
            "self": True,
            "new_since_verified": False,
        }
    ]


def test_groups_show_flags_new_instances_pending_leaves_and_the_floor(fake: Fake) -> None:
    info = group_info(verified=True)
    bob = info["members"][1]
    bob["instances"].append({**bob["instances"][0], "instance_id": "2" * 16, "joined_epoch": 3})
    bob["instances_since_verified"] = ["2" * 16]
    info["pending_leaves"] = [{"identity": BOB, "instance_id": "1" * 16}]
    info["floor"] = {"mode": "moderated", "pinned": True, "moderator": BOB}
    fake.routes[f"GET /v0/groups/{GID}"] = info
    out = fake.run("groups", "show", GID).stdout
    assert f"instance {'2' * 16}  leaf 1  since epoch 3  NEW since you verified" in out
    assert "NEW since you verified" not in out.split(f"instance {'1' * 16}")[1].split("\n")[0]
    assert f"Leaving   {BOB} instance {'1' * 16}" in out
    assert f"Floor     moderated, pinned, moderator {BOB}" in out
    _, view = fake.json("groups", "show", GID)
    assert conforms(view, SCHEMAS["groups show"])
    assert [i["new_since_verified"] for i in view["members"][1]["instances"]] == [False, True]
    assert view["pending_leaves"] == info["pending_leaves"]
    # Verified before the daemon recorded the epoch: unknown (review 52 F3).
    bob["instances_since_verified"] = None
    out = fake.run("groups", "show", GID).stdout
    assert out.count("unknown: verify again") == 2
    _, view = fake.json("groups", "show", GID)
    assert conforms(view, SCHEMAS["groups show"])
    assert [i["new_since_verified"] for i in view["members"][1]["instances"]] == [None, None]


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


def test_requests_that_claim_one_identity_say_so(fake: Fake) -> None:
    """Review 52 F2: the human sees that several requests claim the
    identity, and chooses."""
    assert "requests claim" not in fake.run("approvals").stdout
    twice = [{**APPROVAL, "request_id": r, "identity_requests": 2} for r in ("r1", "r2")]
    fake.routes["GET /v0/approvals"] = {"approvals": twice}
    out = " ".join(fake.run("approvals").stdout.split())
    assert out.count("2 requests claim this identity") == 2
    _, data = fake.json("approvals", "list")
    assert conforms(data, SCHEMAS["approvals list"])
    assert [a["identity_requests"] for a in data["approvals"]] == [2, 2]


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
    # The epoch whose code was shown goes with the answer (SPEC 11).
    assert fake.posts("/verify")[0] == (True, {"verified": True, "epoch": 1})
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


# -- ids that start with "-" ----------------------------------------------------------------

# Random base64url ids can start with "-" (or "--"); every command that takes
# one positionally must still read it as the id, not as an option. "-y..."
# and "--json..." start like options these commands have.
DASH_IDS = ["-" + "G" * 21, "--" + "G" * 20, "-y" + "G" * 20, "--json" + "G" * 16]


def dashed(fake: Fake, gid: str) -> None:
    """Re-key the fake's group routes to ``gid``."""
    fake.routes["GET /v0/groups"]["groups"][0]["group_id"] = gid
    fake.routes[f"GET /v0/groups/{gid}"] = {**group_info(), "group_id": gid}
    approval = {**APPROVAL, "request_id": gid, "group_id": gid}
    fake.routes["GET /v0/approvals"] = {"approvals": [approval]}


@pytest.mark.parametrize("gid", DASH_IDS)
def test_every_id_argument_may_start_with_a_dash(fake: Fake, gid: str) -> None:
    dashed(fake, gid)
    fake.routes[f"POST /v0/groups/{gid}/leave"] = {"status": "left"}
    fake.routes[f"POST /v0/groups/{gid}/messages"] = {"msg_id": "m1"}
    fake.routes[f"POST /v0/groups/{gid}/members/{BOB}/verify"] = {"verified": True}
    fake.routes[f"POST /v0/groups/{gid}/invites"] = {"url": URL, "invite_id": gid, "expires_at": 5}
    fake.routes[f"POST /v0/approvals/{gid}/approve"] = {"status": "approving"}
    fake.routes[f"POST /v0/approvals/{gid}/reject"] = {"status": "rejected"}
    fake.routes[f"DELETE /v0/invites/{gid}"] = {"revoked": gid}

    code, shown = fake.json("groups", "show", gid)
    assert (code, shown["group_id"]) == (0, gid)
    assert fake.json("verify", gid, input="y\n") == (
        0,
        {"outcome": "verified", "group_id": gid, "verified": [BOB]},
    )
    assert fake.json("leave", gid) == (0, {"group_id": gid, "status": "left"})
    # Options before, between and after the positionals; a text that starts
    # with "-" is a positional too.
    code, sent = fake.json("send", "--to", BOB, gid, "-1 is the answer")
    assert (code, sent["group_id"]) == (0, gid)
    assert fake.posts("/messages")[-1][1] == {"text": "-1 is the answer", "to": [BOB]}
    assert fake.run("send", gid, "--to", BOB, "hi").exit_code == 0
    code, made = fake.json("invite", "create", "--group", gid)
    assert (code, made["group_id"]) == (0, gid)
    assert fake.json("invite", "revoke", gid) == (0, {"revoked": gid})
    code, approved = fake.json("approvals", "approve", gid, "--yes")
    assert (code, approved["request_id"]) == (0, gid)
    assert fake.json("approvals", "approve", "-y", gid)[0] == 0
    assert fake.run("send", f"--to={BOB}", gid, "hi").exit_code == 0
    assert fake.posts("/messages")[-1][1] == {"text": "hi", "to": [BOB]}
    assert fake.json("approvals", "reject", gid)[1] == {"request_id": gid, "status": "rejected"}
    # An explicit "--" still works, and real options are still options.
    assert fake.run("leave", "--json", "--", gid).exit_code == 0
    assert "Show a group" in fake.run("groups", "show", "--help").stdout


@pytest.mark.parametrize("gid", DASH_IDS)
def test_the_group_commands_take_ids_that_start_with_a_dash(fake: Fake, gid: str) -> None:
    dashed(fake, gid)
    fake.routes[f"POST /v0/groups/{gid}/policy"] = {"status": "committing"}
    fake.routes[f"POST /v0/groups/{gid}/members/{BOB}/role"] = {"status": "committing"}
    fake.routes[f"POST /v0/groups/{gid}/owner"] = {"status": "committing"}
    assert fake.json("group", "policy", gid, "--invite", "members")[1]["group_id"] == gid
    assert fake.json("group", "role", gid, BOB, "admin")[1]["group_id"] == gid
    assert fake.json("group", "transfer", "--yes", gid, BOB)[1]["group_id"] == gid


# -- roles and the policy ------------------------------------------------------------------


def test_group_policy_sends_what_changes_with_the_human_token(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/policy"] = {"status": "committing"}
    code, out = fake.json(
        "group",
        "policy",
        GID,
        "--invite",
        "members",
        "--remove",
        "admins",
        "--max-members",
        "5",
        "--floor",
        "mention",
        "--moderator",
        "none",
        "--max-agent-turns",
        "4",
    )
    assert code == 0
    assert conforms(out, SCHEMAS["group policy"])
    changes = {
        "invite": "members",
        "remove": "admins",
        "max_members": 5,
        "floor": "mention",
        "floor_moderator": None,
        "max_agent_turns": 4,
    }
    assert out == {"group_id": GID, "status": "committing", "changes": changes}
    assert fake.posts("/policy")[-1] == (True, changes)
    fake.json("group", "policy", GID, "--moderator", BOB, "--floor-pinned")
    assert fake.posts("/policy")[-1] == (True, {"floor_moderator": BOB, "floor_pinned": True})
    assert "policy_changed" in fake.run("group", "policy", GID, "--remove", "owner").stdout


def test_turning_require_verified_on_alone_uses_the_agent_token(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/policy"] = {"status": "unchanged"}
    assert "Nothing to change" in fake.run("group", "policy", GID, "--require-verified").stdout
    assert fake.posts("/policy")[-1] == (False, {"require_verified": True})
    fake.run("group", "policy", GID, "--no-require-verified")
    assert fake.posts("/policy")[-1] == (True, {"require_verified": False})
    code, out = fake.json("group", "policy", GID)
    assert (code, out["error"]["code"]) == (2, "bad_args")


def test_a_refused_policy_change_is_refused_not_failed(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/policy"] = ApiClientError(
        403, "not_permitted", "not permitted: committer may not change this policy"
    )
    code, out = fake.json("group", "policy", GID, "--invite", "members")
    assert (code, out["error"]["code"]) == (3, "not_permitted")
    assert "may not change" in out["error"]["message"]


def test_group_role_and_transfer_use_the_human_token(fake: Fake) -> None:
    fake.routes[f"POST /v0/groups/{GID}/members/{BOB}/role"] = {"status": "committing"}
    fake.routes[f"POST /v0/groups/{GID}/owner"] = {"status": "committing"}
    code, out = fake.json("group", "role", GID, BOB, "admin")
    assert code == 0
    assert conforms(out, SCHEMAS["group role"])
    assert fake.posts("/role")[-1] == (True, {"role": "admin"})
    assert "role_changed" in fake.run("group", "role", GID, BOB, "member").stdout
    assert fake.json("group", "role", GID, BOB, "owner")[1]["error"]["code"] == "bad_args"

    assert fake.json("group", "transfer", GID, BOB)[1]["error"]["code"] == "needs_yes"
    result = fake.run("group", "transfer", GID, BOB, input="n\n")
    assert result.exit_code == 3
    assert fake.posts("/owner") == []
    assert f"over to bob ({BOB})" in fake.run("group", "transfer", GID, BOB, input="y\n").stdout
    assert fake.posts("/owner")[-1] == (True, {"identity": BOB, "keep_admin": True})
    code, out = fake.json("group", "transfer", GID, BOB, "--yes", "--no-keep-admin")
    assert code == 0
    assert conforms(out, SCHEMAS["group transfer"])
    assert fake.posts("/owner")[-1] == (True, {"identity": BOB, "keep_admin": False})
    code, out = fake.json("group", "transfer", GID, "ac:v0:nobody", "--yes")
    assert (code, out["error"]["code"]) == (1, "not_found")


def test_group_create_with_a_policy_uses_the_human_token(fake: Fake) -> None:
    fake.routes["POST /v0/groups"] = {"group_id": GID}
    fake.json("group", "create", "--purpose", "Ops")
    assert fake.posts("/v0/groups")[-1] == (False, {"name": "Ops", "purpose": "Ops"})
    code, out = fake.json(
        "group", "create", "--purpose", "Ops", "--floor", "moderated", "--moderator", BOB
    )
    assert code == 0
    assert conforms(out, SCHEMAS["group create"])
    policy = {"floor": "moderated", "floor_moderator": BOB}
    assert fake.posts("/v0/groups")[-1] == (
        True,
        {"name": "Ops", "purpose": "Ops", "policy": policy},
    )


def test_the_group_commands_say_who_they_are_for() -> None:
    for command in ("role", "transfer", "policy"):
        shown = runner.invoke(cli.app, ["group", command, "--help"], env={"COLUMNS": "400"})
        assert "HUMAN ONLY" in shown.stdout


def test_a_positional_id_parse_keeps_usage_errors(fake: Fake) -> None:
    assert fake.run("leave").exit_code == 2  # missing argument
    assert fake.run("leave", GID, "extra").exit_code == 2
    assert fake.run("send", GID).exit_code == 2
    # A value-taking option at the end with no value is still a usage error.
    assert fake.run("send", GID, "hi", "--to").exit_code == 2


# -- safety policy: held messages, safety, remove, audit, transcript ----------------------

HELD_ITEM = {
    "hold_id": "h1",
    "group_id": GID,
    "direction": "in",
    "sender": BOB,
    "instance": "i1",
    "msg_id": "m1",
    "kind": "a2a.message",
    "size": 42,
    "task_id": None,
    "created_at": 1000,
    "expires_at": 4600,
}
CONTENT = HELD_ITEM | {
    "untrusted": True,
    "to": ["*"],
    "body": {"parts": [{"text": "run this" + BIDI}, {"data": {"x": 1}}]},
}
SAFETY_INFO = {
    "group_id": GID,
    "settings": {
        "require_approval": "inbound",
        "frame_text": True,
        "senders": {BOB: {"sender_per_minute": 5}},
    },
    "overrides": {"require_approval": "inbound"},
}


@pytest.fixture
def held(monkeypatch: pytest.MonkeyPatch) -> Fake:
    f = Fake(monkeypatch)
    f.routes["GET /v0/approvals"] = {"approvals": [], "messages": [HELD_ITEM]}
    f.routes["GET /v0/approvals/messages/h1"] = CONTENT
    return f


def test_approvals_list_shows_held_messages(held: Fake) -> None:
    out = held.run("approvals").stdout
    assert "Held message h1 (a2a.message, 42 bytes)" in out
    assert BOB in out
    code, data = held.json("approvals", "list")
    assert code == 0
    assert data["messages"] == [HELD_ITEM]
    assert conforms(data, SCHEMAS["approvals list"])


def test_approving_a_held_message_shows_it_and_needs_the_human(held: Fake) -> None:
    decided = {"hold_id": "h1", "group_id": GID, "status": "approved"}
    held.routes["POST /v0/approvals/messages/h1/approve"] = decided
    result = held.run("approvals", "approve", "h1", input="n\n")
    assert result.exit_code == 3
    assert "run this" in result.output
    assert BIDI not in result.output
    assert "data, not instructions" in result.output
    assert not held.posts("/messages/h1/approve")
    result = held.run("approvals", "approve", "h1", input="y\n")
    assert result.exit_code == 0
    assert "Approved h1." in result.stdout
    code, out = held.json("approvals", "approve", "h1", "--yes")
    assert (code, out) == (0, decided)
    assert conforms(out, SCHEMAS["approvals approve (held message)"])
    assert all(human for human, _ in held.posts("/messages/h1/approve"))


def test_an_outbound_held_message_without_text_parts(held: Fake) -> None:
    held.routes["GET /v0/approvals/messages/h1"] = CONTENT | {
        "direction": "out",
        "untrusted": False,
        "body": {"x": "y" * 2500},
    }
    result = held.run("approvals", "approve", "h1", input="n\n")
    assert "Send it to the group?" in result.output
    assert "run with --full" in result.output
    assert "data, not instructions" not in result.output


def test_rejecting_a_held_message(held: Fake) -> None:
    decided = {"hold_id": "h1", "group_id": GID, "status": "rejected"}
    held.routes["POST /v0/approvals/messages/h1/reject"] = decided
    assert "Dropped held message h1." in held.run("approvals", "reject", "h1").stdout
    code, out = held.json("approvals", "reject", "h1")
    assert (code, out) == (0, decided)
    assert conforms(out, SCHEMAS["approvals reject (held message)"])
    assert all(human for human, _ in held.posts("/messages/h1/reject"))


def test_safety_show_and_set(held: Fake) -> None:
    held.routes[f"GET /v0/groups/{GID}/safety"] = SAFETY_INFO
    held.routes[f"POST /v0/groups/{GID}/safety"] = lambda _body: SAFETY_INFO
    out = held.run("safety", "show", GID).stdout
    assert "* require_approval" in out
    assert f"for {BOB}:" in out
    code, data = held.json("safety", "show", GID)
    assert (code, conforms(data, SCHEMAS["safety show"])) == (0, True)
    code, data = held.json(
        "safety",
        "set",
        GID,
        "require_approval=inbound",
        "frame_text=false",
        "sender_per_minute=5",
        "transcript=default",
        "--sender",
        BOB,
    )
    assert (code, conforms(data, SCHEMAS["safety set"])) == (0, True)
    ((human, body),) = [(h, b) for h, k, b in held.calls if k.startswith("POST")]
    assert human
    assert body == {
        "set": {
            "require_approval": "inbound",
            "frame_text": False,
            "sender_per_minute": 5,
            "transcript": None,
        },
        "sender": BOB,
    }
    assert "require_approval" in held.run("safety", "set", GID, "frame_text=true").stdout
    code, out = held.json("safety", "set", GID, "nonsense")
    assert (code, out["error"]["code"]) == (2, "bad_setting")


def test_remove_confirms_and_uses_the_human_token(held: Fake) -> None:
    held.routes[f"POST /v0/groups/{GID}/members/{BOB}/remove"] = {"status": "removing"}
    assert held.run("remove", GID, BOB, input="n\n").exit_code == 3
    assert not held.posts("/remove")
    result = held.run("remove", GID, BOB, input="y\n")
    assert result.exit_code == 0
    assert "member_removed" in result.stdout
    code, out = held.json("remove", GID, BOB, "--yes")
    assert (code, out) == (0, {"group_id": GID, "identity": BOB, "status": "removing"})
    assert conforms(out, SCHEMAS["remove"])
    assert all(human for human, _ in held.posts("/remove"))
    assert held.json("remove", GID, BOB)[1]["error"]["code"] == "needs_yes"
    assert held.json("remove", GID, "ac:v0:nobody", "--yes")[1]["error"]["code"] == "not_found"


def test_remove_some_instances(held: Fake) -> None:
    route = f"POST /v0/groups/{GID}/members/{BOB}/remove"
    held.routes[route] = {"status": "removing"}
    result = held.run("remove", GID, BOB, "--instance", "1" * 16, input="y\n")
    assert result.exit_code == 0
    assert "instance_removed" in result.stdout
    assert held.posts("/remove") == [(True, {"instances": ["1" * 16]})]
    code, out = held.json("remove", GID, BOB, "--instance", "1" * 16, "--yes")
    assert out["instances"] == ["1" * 16]
    assert conforms(out, SCHEMAS["remove"])
    # One's own identity: only its other instances, named.
    me = f"POST /v0/groups/{GID}/members/{ME}/remove"
    held.routes[me] = {"status": "removing"}
    code, out = held.json("remove", GID, ME, "--yes")
    assert (code, out["error"]["code"]) == (2, "bad_request")
    code, out = held.json("remove", GID, ME, "--instance", "2" * 16, "--yes")
    assert code == 0


ROW: dict[str, Any] = {
    "seq": 1,
    "group_id": GID,
    "at": 1000,
    "direction": "in",
    "sender": BOB,
    "msg_id": "m1",
    "kind": "a2a.message",
    "size": 9000,
    "decision": "drop",
    "reason": "too_large",
}


def test_audit(held: Fake) -> None:
    held.routes["GET /v0/audit?after=0"] = {"audit": [ROW, ROW | {"reason": ""}]}
    held.routes[f"GET /v0/audit?after=3&group={GID}"] = {"audit": []}
    out = held.run("audit").stdout
    assert "drop (too_large)" in out
    code, data = held.json("audit")
    assert (code, conforms(data, SCHEMAS["audit"])) == (0, True)
    assert held.json("audit", "--group", GID, "--after", "3") == (0, {"audit": []})
    assert all(human for human, key, _ in held.calls if "/v0/audit" in key)


def test_transcript(held: Fake) -> None:
    entry = {k: ROW[k] for k in ("seq", "group_id", "at", "direction", "sender", "msg_id")}
    rows = [
        entry | {"kind": "a2a.message", "inner": {"body": {"parts": [{"text": "hi" + BIDI}]}}},
        entry | {"kind": "control.pause", "inner": {"body": {"reason": "human"}}},
    ]
    held.routes[f"GET /v0/groups/{GID}/transcript?after=0"] = {
        "transcript": rows,
        "untrusted": True,
    }
    out = held.run("transcript", GID).stdout
    assert "hi" in out
    assert BIDI not in out
    assert "control.pause" in out
    code, data = held.json("transcript", GID)
    assert (code, conforms(data, SCHEMAS["transcript"])) == (0, True)
    held.routes[f"GET /v0/groups/{GID}/transcript?after=0"] = {"transcript": [], "untrusted": True}
    assert "No transcript entries" in held.run("transcript", GID).stdout
    held.routes[f"GET /v0/groups/{GID}/transcript?after=0"] = ApiClientError(403, "human_only", "x")
    assert held.json("transcript", GID)[1]["error"]["code"] == "human_only"


def test_status_shows_held_messages(held: Fake) -> None:
    held.routes["GET /v0/status"] = {
        "identity": "ac:v0:me",
        "fingerprint": "fp",
        "relay": {"url": "wss://r", "connected": True},
        "groups": 1,
        "out_of_sync": [],
        "outbox_queued": 0,
        "inbox_pending": 0,
        "pending_approvals": 0,
        "held_messages": 2,
    }
    assert "2 message(s) waiting for approval" in held.run("status").stdout


# -- review regressions: the preview shows everything, peer text prints safely -----

ESC = "\x1b]52;c;aGk=\x07\x1b[2K"
FULL_BODY = {
    "parts": [
        {"text": "hello"},
        {"data": {"cmd": "rm -rf /"}},
        {"raw": "QUJD", "filename": "x.sh", "mediaType": "text/x-sh"},
    ],
    "metadata": {"hidden": "instructions"},
}


def test_the_preview_shows_every_part_and_the_routing(held: Fake) -> None:
    held.routes["GET /v0/approvals/messages/h1"] = CONTENT | {
        "body": FULL_BODY,
        "addressee": [BOB],
        "reply_to": ["m0"],
    }
    out = held.run("approvals", "approve", "h1", input="n\n").output
    for shown in ("hello", '"cmd": "rm -rf /"', "x.sh", "text/x-sh", "hidden", BOB, "m0"):
        assert shown in out, shown


def test_a_truncated_preview_needs_full_before_yes(held: Fake) -> None:
    held.routes["GET /v0/approvals/messages/h1"] = CONTENT | {
        "body": {"parts": [{"text": "a" * 3000 + "THE END"}]}
    }
    held.routes["POST /v0/approvals/messages/h1/approve"] = {
        "hold_id": "h1",
        "group_id": GID,
        "status": "approved",
    }
    result = held.run("approvals", "approve", "h1", "--yes")
    assert result.exit_code == 2
    assert "--full" in result.output
    assert not held.posts("/messages/h1/approve")
    assert "THE END" not in held.run("approvals", "approve", "h1", input="n\n").output
    full = held.run("approvals", "approve", "h1", "--yes", "--full")
    assert full.exit_code == 0
    assert "THE END" in full.output
    # --json shows the whole message on stderr and approves with --yes.
    code, out = held.json("approvals", "approve", "h1", "--yes")
    assert (code, out["status"]) == (0, "approved")


def test_peer_strings_are_printed_without_control_sequences(held: Fake) -> None:
    held.routes["GET /v0/approvals"] = {
        "approvals": [],
        "messages": [HELD_ITEM | {"kind": ESC, "sender": "ac:v0:" + ESC}],
    }
    held.routes["GET /v0/audit?after=0"] = {
        "audit": [ROW | {"kind": ESC, "sender": ESC, "reason": ESC, "msg_id": ESC}]
    }
    entry = {k: ROW[k] for k in ("seq", "group_id", "at", "direction", "msg_id")}
    held.routes[f"GET /v0/groups/{GID}/transcript?after=0"] = {
        "transcript": [entry | {"sender": ESC, "kind": ESC, "inner": {"body": {"text": ESC}}}],
        "untrusted": True,
    }
    for args in (("approvals",), ("audit",), ("transcript", GID)):
        out = held.run(*args).output
        assert "\x1b" not in out, args
        assert "\x07" not in out, args
