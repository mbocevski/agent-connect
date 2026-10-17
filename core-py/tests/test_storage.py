"""Encryption at rest: the on-disk store is SQLCipher under a required key."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

import agentconnect_core as ac

NAME = "PLAINTEXT-MARKER-group-name"
PURPOSE = "PLAINTEXT-MARKER-purpose"
MESSAGE = "PLAINTEXT-MARKER-message-body"


def instance_bytes(rng: random.Random) -> bytes:
    identity = ac.Identity._generate_for_testing(rng.getrandbits(64))
    return identity._create_instance_for_testing(seed=rng.getrandbits(64)).to_secret_bytes()


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


def populate(rng: random.Random, db: Path, db_key: bytes) -> bytes:
    """A (memory) and B (on disk) share a group; A sends B a message."""
    a = ac.Client._for_testing(None, instance_bytes(rng), rng.getrandbits(64))
    b = ac.Client._for_testing(str(db), instance_bytes(rng), rng.getrandbits(64), db_key)
    gid = a.create_group(NAME, PURPOSE)
    invite = a.create_invite("relay.example", 3600)
    link = ac.parse_invite_url(invite.url)
    verified = a.verify_join_request(b.create_join_request(link, "joiner"), invite)
    out = a.add_member(gid, verified, invite)
    a.confirm_pending_commit(gid, out["msg_id"])
    welcome = out["welcome"]
    assert isinstance(welcome, bytes)
    assert b.join(link, invite_meta(invite), welcome) == gid
    inner = json.dumps(
        {
            "v": 0,
            "sender": a.identity,
            "instance_id": a.instance_id_hex,
            "kind": "a2a.message",
            "body": {"text": MESSAGE},
        }
    ).encode()
    assert b.open(gid, a.seal(gid, inner))["plaintext"] == inner
    return gid


def disk_bytes(directory: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(directory.iterdir()))


def markers(gid: bytes) -> list[bytes]:
    return [
        b"SQLite format 3",
        b"agentconnect_records",
        b"openmls",
        b"CREATE TABLE",
        NAME.encode(),
        PURPOSE.encode(),
        MESSAGE.encode(),
        gid,
        gid.hex().encode(),
        json.dumps(list(gid), separators=(",", ":"))[1:-1].encode(),
    ]


def test_the_database_file_holds_no_plaintext(rng: random.Random, tmp_path: Path) -> None:
    db_key = rng.randbytes(ac.DB_KEY_LEN)
    gid = populate(rng, tmp_path / "state.db", db_key)
    data = disk_bytes(tmp_path)
    assert len(data) > 4096
    for marker in markers(gid):
        assert marker not in data, marker


def test_a_wrong_or_missing_key_fails(rng: random.Random, tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    db_key = rng.randbytes(ac.DB_KEY_LEN)
    populate(rng, db, db_key)
    saved = instance_bytes(rng)
    with pytest.raises(ac.AgentConnectError, match="wrong database key"):
        ac.Client(str(db), saved, rng.randbytes(ac.DB_KEY_LEN))
    with pytest.raises(ac.AgentConnectError, match="required for an on-disk store"):
        ac.Client(str(db), saved)
    with pytest.raises(ac.AgentConnectError, match="32 bytes"):
        ac.Client(str(db), saved, db_key[:16])
    with pytest.raises(ac.AgentConnectError, match="in-memory store takes none"):
        ac.Client(None, saved, db_key)
    # The failed attempts changed nothing.
    ac.Client(str(db), saved, db_key)


def test_rekey_moves_the_store_to_the_new_key(rng: random.Random, tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    old, new = rng.randbytes(ac.DB_KEY_LEN), rng.randbytes(ac.DB_KEY_LEN)
    gid = populate(rng, db, old)
    with pytest.raises(ac.AgentConnectError, match="wrong database key"):
        ac.rekey_store(str(db), new, old)
    with pytest.raises(ac.AgentConnectError, match="32 bytes"):
        ac.rekey_store(str(db), old, new[:31])
    ac.rekey_store(str(db), old, new)
    saved = instance_bytes(rng)
    with pytest.raises(ac.AgentConnectError, match="wrong database key"):
        ac.Client(str(db), saved, old)
    ac.Client(str(db), saved, new)
    data = disk_bytes(tmp_path)
    for marker in markers(gid):
        assert marker not in data, marker
