"""The processing journal through the bindings (ADR-004): journalled
process/confirm/join, replays, pending entries, consumption and failpoints."""

from __future__ import annotations

import json
import random
from pathlib import Path

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


def test_journalled_processing_replays_until_consumed(rng: random.Random, tmp_path: Path) -> None:
    a = make_client(rng)
    b = make_client(rng, tmp_path / "b.db")
    gid = a.create_group(NAME, PURPOSE)
    invite = a.create_invite("relay.example", 3600)
    link = ac.parse_invite_url(invite.url)
    verified = a.verify_join_request(b.create_join_request(link, "b"), invite)
    out = a.add_member(gid, verified, invite)
    a.confirm_pending_commit(gid, out["msg_id"], key="own/1", context=b"c")
    # The fan-out copy under the same key is the same entry.
    echo = a.process(gid, out["commit"], key="own/1")
    assert echo["type"] == "own_commit_confirmed"
    assert echo["replayed"] is True
    assert a.journal_consume("own/1", gid)

    b._arm_failpoint_for_testing("join.before_commit")
    with pytest.raises(ac.AgentConnectError, match=r"failpoint join\.before_commit"):
        b.join(link, invite_meta(invite), out["welcome"], key="w", context=b"env")
    assert b.join(link, invite_meta(invite), out["welcome"], key="w", context=b"env") == gid
    assert b.join(link, invite_meta(invite), out["welcome"], key="w") == gid
    (welcome,) = b.journal_pending()
    assert welcome["welcome"] is True
    assert welcome["event"] is None
    assert (welcome["group_id"], welcome["context"]) == (gid, b"env")
    assert b.journal_consume("w")

    ct = a.seal(gid, inner(a, "hi"))
    for action in ("error", "panic"):
        b._arm_failpoint_for_testing("process.before_commit", action)
        with pytest.raises((ac.AgentConnectError, ac.CoreError)):
            b.process(gid, ct, key="a/1", context=b"x")
    b._arm_failpoint_for_testing("process.after_mls", times=3)
    b._clear_failpoints_for_testing()
    first = b.process(gid, ct, key="a/1", context=b"x")
    assert first["replayed"] is False
    assert json.loads(first["plaintext"])["body"]["text"] == "hi"
    assert b.process(gid, ct, key="a/1")["replayed"] is True
    (pending,) = b.journal_pending()
    assert pending["key"] == "a/1"
    assert pending["event"]["plaintext"] == first["plaintext"]
    assert b.journal_consume("a/1", gid)
    assert not b.journal_consume("nope", gid)
    assert b.journal_pending() == []
    with pytest.raises(ac.AgentConnectError, match="already processed") as e:
        b.process(gid, ct, key="a/1")
    assert e.value.kind == "duplicate"
    assert b.journal_purge(2**40) == 2  # the Welcome and the message
    with pytest.raises(ac.AgentConnectError, match="failpoint name"):
        b._arm_failpoint_for_testing("no.such.point")
    with pytest.raises(ac.AgentConnectError, match="error or panic"):
        b._arm_failpoint_for_testing("process.after_mls", "explode")
