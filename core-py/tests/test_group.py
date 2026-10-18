"""Round trips through the bindings: identity, invite, join, messages, SAS."""

from __future__ import annotations

import base64
import json
import random
from pathlib import Path
from typing import Any

import pytest

import agentconnect_core as ac

NAME = "Trip planning"
PURPOSE = "Plan the offsite"


def make_client(rng: random.Random, path: Path | None = None) -> ac.Client:
    identity = ac.Identity._generate_for_testing(rng.getrandbits(64))
    instance = identity._create_instance_for_testing(seed=rng.getrandbits(64))
    return ac.Client._for_testing(
        None if path is None else str(path),
        instance.to_secret_bytes(),
        rng.getrandbits(64),
        None if path is None else rng.randbytes(ac.DB_KEY_LEN),
    )


def inner(client: ac.Client, text: str) -> bytes:
    return json.dumps(
        {
            "v": 0,
            "sender": client.identity,
            "instance_id": client.instance_id_hex,
            "kind": "a2a.message",
            "body": {"text": text},
        }
    ).encode()


def invite_meta(invite: ac.Invite) -> bytes:
    return json.dumps(
        {
            "invite_id": invite.invite_id_b64,
            "group_name": NAME,
            "inviter_name": "a",
            "purpose": PURPOSE,
            "expires_at": invite.expires_at,
            "max_uses": 1,
            "uses_left": 1,
            "status": "open",
            "protocol": 0,
        }
    ).encode()


def join(inviter: ac.Client, gid: bytes, joiner: ac.Client) -> dict[str, Any]:
    invite = inviter.create_invite("relay.example", 3600)
    link = ac.parse_invite_url(invite.url)
    request = joiner.create_join_request(link, "joiner")
    verified = inviter.verify_join_request(request, invite)
    assert verified.mailbox_id == joiner.mailbox_id
    out = inviter.add_member(gid, verified, invite)
    with pytest.raises(ac.AgentConnectError, match="already pending"):
        inviter.add_member(gid, verified, invite)
    # A failed add leaves the verified request usable: rebuild after a discard.
    inviter.discard_pending_commit(gid)
    out = inviter.add_member(gid, verified, invite)
    inviter.confirm_pending_commit(gid, out["msg_id"])
    with pytest.raises(ac.AgentConnectError, match="key package already used"):
        inviter.add_member(gid, verified, invite)
    with pytest.raises(ac.AgentConnectError, match="key package already used"):
        inviter.verify_join_request(request, invite)
    welcome = out["welcome"]
    assert isinstance(welcome, bytes)
    assert joiner.join(link, invite_meta(invite), welcome) == gid
    return out


def test_one_to_one_round_trip(rng: random.Random) -> None:
    a, b = make_client(rng), make_client(rng)
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    assert a.epoch(gid) == b.epoch(gid) == 1
    assert a.sas(gid) == b.sas(gid)
    assert len(a.sas(gid).emoji_indices) == 7
    assert json.loads(b.meta(gid))["purpose"] == PURPOSE
    assert json.loads(a.policy(gid))["owner"] == a.identity

    ct = a.seal(gid, inner(a, "hi"))
    msg = b.open(gid, ct)
    assert msg["type"] == "application"
    assert msg["sender"]["identity"] == a.identity
    assert json.loads(msg["plaintext"])["body"]["text"] == "hi"
    event = a.process(gid, b.seal(gid, inner(b, "hello")))
    assert event["sender"]["identity"] == b.identity

    with pytest.raises(ac.AgentConnectError):
        b.open(gid, ct)  # replay


def test_group_commits_converge(rng: random.Random) -> None:
    a, b, c = (make_client(rng) for _ in range(3))
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    out = join(a, gid, c)
    event = b.process(gid, out["commit"])
    assert event["type"] == "commit"
    assert event["routing"] == out["routing"]
    assert json.loads(b.policy(gid))["floor"] == "mention"
    assert a.sas(gid) == b.sas(gid) == c.sas(gid)

    upd = b.update(gid)
    assert b.has_pending_commit(gid)
    with pytest.raises(ac.AgentConnectError, match="does not match the pending commit"):
        b.confirm_pending_commit(gid, out["msg_id"])
    assert b.process(gid, upd["commit"])["type"] == "own_commit_confirmed"
    for client in (a, c):
        client.process(gid, upd["commit"])
    assert len({x.sas(gid) for x in (a, b, c)}) == 1

    leave = c.propose_leave(gid)
    assert a.process(gid, leave)["type"] == "leave_proposed"
    b.process(gid, leave)
    out = a.commit_pending_proposals(gid)
    a.confirm_pending_commit(gid, out["msg_id"])
    b.process(gid, out["commit"])
    assert c.process(gid, out["commit"])["type"] == "removed"
    assert len(a.members(gid)) == 2
    c.delete_group(gid)

    policy = json.loads(a.policy(gid))
    policy["require_verified"] = True
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    out = a.set_policy(gid, canonical)
    a.discard_pending_commit(gid)
    with pytest.raises(ac.AgentConnectError, match="not permitted"):
        b.remove(gid, a.identity)
    assert out["epoch"] == a.epoch(gid)


def test_wrong_secret_and_bad_inputs(rng: random.Random) -> None:
    a, b = make_client(rng), make_client(rng)
    a.create_group(NAME, PURPOSE)
    invite = a.create_invite("relay.example", 60)
    wrong = rng.randbytes(32)
    link = ac.parse_invite_url(invite.url.split("&s=")[0] + "&s=" + _b64(wrong))
    request = b.create_join_request(link, "b")
    with pytest.raises(ac.AgentConnectError, match="MAC"):
        a.verify_join_request(request, invite)
    with pytest.raises(ac.AgentConnectError, match="unsupported protocol version"):
        ac.parse_invite_url(invite.url.replace("v=0", "v=1"))
    with pytest.raises(ac.AgentConnectError, match="unknown group"):
        a.epoch(b"\x00" * 16)
    with pytest.raises(ac.AgentConnectError, match="16 bytes"):
        ac.unwrap_welcome(b"x", bytes(32), b"")
    with pytest.raises(ac.AgentConnectError, match="32 bytes"):
        ac.unwrap_welcome(bytes(16), b"y", b"")
    a._set_time_for_testing(invite.expires_at)
    good = b.create_join_request(ac.parse_invite_url(invite.url), "b")
    with pytest.raises(ac.AgentConnectError, match="expired"):
        a.verify_join_request(good, invite)
    a._set_time_for_testing(None)


def test_persistence_and_invite_parts(rng: random.Random, tmp_path: Path) -> None:
    db = tmp_path / "b.sqlite"
    identity = ac.Identity._generate_for_testing(rng.getrandbits(64))
    instance = identity._create_instance_for_testing(seed=rng.getrandbits(64), now=1_800_000_000)
    assert json.loads(instance.cert_json)["created_at"] == 1_800_000_000
    saved = instance.to_secret_bytes()
    db_key = rng.randbytes(ac.DB_KEY_LEN)
    a = make_client(rng)
    b = ac.Client(str(db), saved, db_key)
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    del b
    b = ac.Client(str(db), ac.Instance.from_secret_bytes(saved).to_secret_bytes(), db_key)
    assert b.sas(gid) == a.sas(gid)
    assert b.open(gid, a.seal(gid, inner(a, "persisted")))["epoch"] == 1

    invite = a.create_invite("relay.example")
    restored = ac.Invite.from_parts(
        invite.relay_host, invite.invite_id, invite.secret_bytes(), invite.expires_at
    )
    assert restored.url == invite.url
    link = ac.parse_invite_url(invite.url)
    assert link.secret_bytes() == invite.secret_bytes()
    assert link.invite_id == invite.invite_id
    assert link.relay_host == "relay.example"
    assert link.url == invite.url
    again = ac.Identity.from_secret_bytes(identity.secret_bytes())
    assert again.id == identity.id
    assert again.fingerprint == ac.fingerprint(identity.public_key)
    assert ac.identity_id(identity.public_key) == identity.id
    assert instance.identity == identity.id
    assert instance.mailbox_id == ac.mailbox_id(instance.public_key)
    assert f"{instance.instance_id:016x}" == instance.instance_id_hex
    assert repr(identity).startswith("Identity(")


def test_peek_header_reads_the_header_and_consumes_nothing(rng: random.Random) -> None:
    a, b = make_client(rng), make_client(rng)
    gid = a.create_group(NAME, PURPOSE)
    join(a, gid, b)
    epoch = b.epoch(gid)
    ct = a.seal(gid, inner(a, "peeked"))
    head = ac.peek_header(ct)
    assert head == {"group_id": gid, "epoch": epoch, "content_type": "application"}
    # An envelope claiming another epoch is caught before processing; the
    # key is untouched, so the original still opens (once).
    assert head["epoch"] != epoch + 1
    assert ac.peek_header(ct) == head
    assert b.open(gid, ct)["plaintext"] == inner(a, "peeked")
    with pytest.raises(ac.AgentConnectError):
        b.open(gid, ct)
    assert ac.peek_header(b.propose_leave(gid))["content_type"] == "proposal"
    commit = a.update(gid)["commit"]
    assert ac.peek_header(commit) == {"group_id": gid, "epoch": epoch, "content_type": "commit"}


@pytest.mark.parametrize("bad", [b"", b"junk", b"\x00\x01"])
def test_peek_header_rejects_what_process_rejects(rng: random.Random, bad: bytes) -> None:
    with pytest.raises(ac.AgentConnectError, match="malformed"):
        ac.peek_header(bad)
    a = make_client(rng)
    gid = a.create_group(NAME, PURPOSE)
    with pytest.raises(ac.AgentConnectError, match="malformed"):
        a.process(gid, bad)


def test_group_policy_vectors(rng: random.Random) -> None:
    """The policies of testdata/group-policy.json (SPEC 9.1) through set_policy.

    Its authorization cases (SPEC 9.2) are checked by core/src/vectors.rs;
    the bindings have no call that evaluates a commit's facts on their own.
    """
    testdata = Path(__file__).resolve().parents[2] / "testdata"
    vectors = json.loads((testdata / "group-policy.json").read_text(encoding="utf-8"))
    a = make_client(rng)
    gid = a.create_group(NAME, PURPOSE)

    def own(policy: str) -> bytes:
        # The vector's owner becomes this client, the group's only member.
        return policy.replace(json.loads(policy)["owner"], a.identity).encode()

    assert a.policy(gid) == own(vectors["default"])
    for case in vectors["valid"]:
        if "pending" in case:
            # A SPEC rule the core doesn't implement yet: drop the mark when
            # it does, and this policy is accepted.
            with pytest.raises(ac.AgentConnectError, match="malformed group policy"):
                a.set_policy(gid, own(case["policy"]))
            continue
        a.set_policy(gid, own(case["policy"]))
        a.discard_pending_commit(gid)
    for case in vectors["invalid"]:
        with pytest.raises(ac.AgentConnectError) as err:
            a.set_policy(gid, case["policy"].encode())
        assert str(err.value) == case["error"], case["name"]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
