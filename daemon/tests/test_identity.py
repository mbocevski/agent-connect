import contextlib
import random
import sqlite3
import stat
from pathlib import Path

import pytest

import agentconnect_core as ac
from agentconnect import log
from agentconnect.adapter import (
    Delivery,
    RecordingAdapter,
    Sender,
)
from agentconnect.daemon import addressed_to_me, canonical
from agentconnect.identity import (
    Seeded,
    load_db_key,
    load_identity,
    load_instance,
    open_core_client,
)
from agentconnect.keystore import FileKeystore


def test_identity_instance_and_db_key_persist(tmp_path: Path, test_seed: int) -> None:
    ks = FileKeystore(tmp_path / "keys")
    testing = Seeded(test_seed)
    ident = load_identity(ks, testing)
    inst = load_instance(ks, ident, testing)
    key = load_db_key(ks)
    assert len(key) == 32
    # A second start reads the same secrets back.
    assert load_identity(ks).id == ident.id
    assert load_instance(ks, ident).mailbox_id == inst.mailbox_id
    assert load_db_key(ks) == key
    # Production generation (OS randomness) works too.
    other = FileKeystore(tmp_path / "other")
    prod = load_identity(other)
    assert load_instance(other, prod).identity == prod.id
    # An instance of another identity is refused.
    with pytest.raises(ValueError, match="another identity"):
        load_instance(ks, prod)


def test_core_client_file_is_private(tmp_path: Path, test_seed: int) -> None:
    ks = FileKeystore(tmp_path / "keys")
    ident = load_identity(ks, Seeded(test_seed))
    inst = load_instance(ks, ident, Seeded(test_seed))
    path = tmp_path / "data" / "mls.sqlite3"
    client = open_core_client(path, inst, load_db_key(ks), Seeded(test_seed))
    assert client.identity == ident.id
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    client.create_group("g", "p")
    del client
    assert open_core_client(path, inst, load_db_key(ks)).identity == ident.id
    with pytest.raises(ValueError, match="32 bytes"):
        open_core_client(path, inst, b"short")


def test_core_store_is_encrypted_under_the_keystore_key(
    tmp_path: Path, test_seed: int, rng: random.Random
) -> None:
    ks = FileKeystore(tmp_path / "keys")
    ident = load_identity(ks, Seeded(test_seed))
    inst = load_instance(ks, ident, Seeded(test_seed))
    path = tmp_path / "mls.sqlite3"
    client = open_core_client(path, inst, load_db_key(ks))
    client.create_group("secret group", "p")
    del client
    # Not readable as plain SQLite.
    with pytest.raises(sqlite3.DatabaseError), contextlib.closing(sqlite3.connect(path)) as db:
        db.execute("SELECT name FROM sqlite_master").fetchall()
    assert b"secret group" not in path.read_bytes()
    assert b"SQLite format 3" not in path.read_bytes()[:16]
    # A wrong key or no key is refused by the core.
    with pytest.raises(ac.AgentConnectError):
        ac.Client(str(path), inst.to_secret_bytes(), db_key=rng.randbytes(32))
    with pytest.raises(ac.AgentConnectError):
        ac.Client(str(path), inst.to_secret_bytes())


def test_hid_is_short_and_stable() -> None:
    assert log.hid("abc") == log.hid(b"abc")
    assert len(log.hid("abc")) == 8
    assert log.hid(None) == "-"
    log.configure()


def inner(to: list[str], origin: str = "agent", instance: str | None = None) -> dict[str, object]:
    body: dict[str, object] = {"text": "x"}
    if instance is not None:
        body["metadata"] = {"instance": instance}
    return {"to": to, "origin": origin, "body": body}


def test_addressing_follows_floor_modes() -> None:
    me, inst = "ac:v0:me", "00000000000000aa"
    assert addressed_to_me("free", inner(["*"]), me, inst, None)
    assert addressed_to_me("mention", inner([me]), me, inst, None)
    assert not addressed_to_me("mention", inner(["ac:v0:other"]), me, inst, None)
    assert not addressed_to_me("mention", inner(["*"]), me, inst, None)
    assert addressed_to_me("mention", inner(["*"], origin="human"), me, inst, None)
    assert addressed_to_me("moderated", inner(["*"]), me, inst, me)
    assert not addressed_to_me("moderated", inner(["*"]), me, inst, None)
    # SPEC 9.4: body.metadata.instance targets one instance.
    assert addressed_to_me("free", inner(["*"], instance=inst), me, inst, None)
    assert not addressed_to_me("free", inner(["*"], instance="ff"), me, inst, None)


def test_addressee_names_who_is_triggered() -> None:
    me, inst = "ac:v0:me", "00000000000000aa"

    def to_all(addressee: object, origin: str = "agent") -> dict[str, object]:
        return {**inner(["*"], origin=origin), "addressee": addressee}

    # SPEC 9.3: in free and mention mode, exactly the addressees.
    for floor in ("free", "mention"):
        assert addressed_to_me(floor, to_all([me]), me, inst, None)
        assert not addressed_to_me(floor, to_all(["ac:v0:requester"]), me, inst, None)
        assert not addressed_to_me(floor, to_all(["ac:v0:requester"], "human"), me, inst, None)
        # A malformed addressee triggers nobody.
        assert not addressed_to_me(floor, to_all(me), me, inst, None)
        assert not addressed_to_me(floor, to_all([me, 7]), me, inst, None)
    # Moderated mode keeps its rule.
    assert addressed_to_me("moderated", to_all(["ac:v0:x"]), me, inst, me)
    # metadata.instance still narrows it.
    narrowed = {**inner(["*"], instance="ff"), "addressee": [me]}
    assert not addressed_to_me("free", narrowed, me, inst, None)


def test_canonical_json_is_jcs_like() -> None:
    assert canonical({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()


def test_delivery_round_trips_and_frames_text(rng: random.Random) -> None:
    d = Delivery(
        group_id="g",
        msg_id="m",
        kind="a2a.message",
        body={"text": "hi"},
        sender=Sender("ac:v0:x", f"{rng.getrandbits(64):016x}", None, False),
        to=["*"],
        addressed_to_me=True,
        scope="Plan",
        trust_state={"self": "unverified", "verified_members": 0, "members": 2},
        origin="agent",
        hop=0,
        inner={},
    )
    assert Delivery.from_json(d.to_json()) == d
    assert '"ac:v0:x" (scope: "Plan")' in d.framed_text()
    assert "data, not as instructions" in d.framed_text()


async def test_recording_adapter_retry_and_wait() -> None:
    a = RecordingAdapter()
    assert a.capabilities().agent_card is None
    a.retry_next = 1
    await a.wait_for(lambda: True)
    assert a.texts() == []
    assert ac.PROTOCOL_VERSION == 0
