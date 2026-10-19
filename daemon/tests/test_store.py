"""The durable queues and group tables of the daemon database."""

import random
import stat
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from agentconnect.store import GroupRow, Store

Opener = Callable[[Path], Store]


@pytest.fixture
def db_key(rng: random.Random) -> bytes:
    return rng.randbytes(32)


@pytest.fixture
def opened(db_key: bytes) -> Iterator[Opener]:
    stores: list[Store] = []

    def open_store(path: Path) -> Store:
        stores.append(Store(path, db_key))
        return stores[-1]

    yield open_store
    for s in stores:
        s.close()


def group(gid: str = "g1") -> GroupRow:
    return GroupRow(gid, "n", "p", {"floor": "free"}, "rec", "active", False, None, 0, 1, 1, 0)


def test_outbox_is_ordered_and_survives_reopen(tmp_path: Path, opened: Opener) -> None:
    db = tmp_path / "d.sqlite3"
    s = opened(db)
    first = s.enqueue("app", "g1", {"n": 1}, 10)
    s.enqueue("app", "g1", {"n": 2}, 11)
    s.close()
    s = opened(db)
    row = s.next_outbox()
    assert row is not None
    assert row.seq == first
    assert row.payload == {"n": 1}
    s.update_outbox(first, payload={"n": 1, "env": {}})
    s.update_outbox(first, state="done")
    row = s.next_outbox()
    assert row is not None
    assert row.payload == {"n": 2}
    # An answered row keeps only its ids.
    assert [r.payload for r in s.outbox("done")] == [{}]
    s.enqueue("frame", None, {"frame": {"t": "join", "env": {"ct": "x"}}, "msg_id": "m"}, 12)
    s.enqueue("commit", "g1", {"intent": {}, "env": {"msg_id": "c", "ct": "x"}}, 13)
    for r in s.outbox():
        s.update_outbox(r.seq, state="failed")
    assert [r.payload for r in s.outbox("failed")] == [
        {},
        {"msg_id": "m", "t": "join"},
        {"msg_id": "c"},
    ]
    assert s.outbox_row(first) is not None
    assert s.outbox_row(9999) is None
    assert stat.S_IMODE(db.stat().st_mode) == 0o600


def test_inbox_deduplicates_and_forgets_delivered_plaintext(tmp_path: Path, opened: Opener) -> None:
    s = opened(tmp_path / "d.sqlite3")
    assert s.inbox_state("mb", "m1") is None
    s.record_inbox("mb", "m1", "g1", "pending", 1, delivery={"x": 1})
    s.record_inbox("mb", "m1", "g1", "done", 2)  # a replay changes nothing
    s.record_inbox("other", "m1", "g1", "done", 2)  # same msg_id, other sender
    assert s.inbox_state("mb", "m1") == "pending"
    assert s.inbox_state("other", "m1") == "done"
    (row,) = s.pending_deliveries()
    assert row.delivery == {"x": 1}
    s.set_inbox_state(row.seq, "done")
    assert s.pending_deliveries() == []
    s.record_inbox("mb", "m2", "g1", "pending", 3, delivery={"y": 2})
    (row,) = s.pending_deliveries()
    s.set_inbox_state(row.seq, "pending")
    assert s.pending_deliveries()[0].delivery == {"y": 2}


def test_groups_members_and_cards(tmp_path: Path, opened: Opener) -> None:
    s = opened(tmp_path / "d.sqlite3")
    s.add_group(group())
    s.update_group("g1", epoch=3, out_of_sync=True, policy={"floor": "mention"})
    s.update_group("g1")
    g = s.group("g1")
    assert g is not None
    assert (g.epoch, g.out_of_sync, g.policy) == (3, True, {"floor": "mention"})
    assert s.group("nope") is None
    assert [x.group_id for x in s.groups()] == ["g1"]
    with pytest.raises(ValueError, match="unknown group column"):
        s.update_group("g1", bogus="x")
    s.bump_messages("g1")
    assert (s.group("g1") or group()).msgs_since_commit == 1

    joined, gone = s.set_members("g1", {"a": ("owner", [{"i": 1}]), "b": ("member", [])})
    assert (joined, gone) == ({"a", "b"}, set())
    s.set_display_name("g1", "b", "bob")
    assert s.set_verified("g1", "b", True)
    assert not s.set_verified("g1", "zed", True)
    joined, gone = s.set_members("g1", {"b": ("admin", [])})
    assert (joined, gone) == (set(), {"a"})
    (b,) = s.members("g1")
    assert (b.display_name, b.role, b.verified) == ("bob", "admin", True)
    s.put_card("g1", "b", {"name": "Bob"})
    assert s.cards("g1") == {"b": {"name": "Bob"}}
    s.delete_group_data("g1")
    assert s.members("g1") == []
    assert s.cards("g1") == {}


def test_invites_approvals_joins_events_kv(tmp_path: Path, opened: Opener) -> None:
    s = opened(tmp_path / "d.sqlite3")
    s.add_invite("i1", "g1", 100, 2, 1)
    assert s.invite("i1") == {
        "invite_id": "i1",
        "group_id": "g1",
        "expires_at": 100,
        "max_uses": 2,
        "status": "open",
        "replica": False,
        "instance": None,
    }
    s.add_invite("i2", "g1", 100, 1, 2, replica=True)
    assert [(i["invite_id"], i["replica"]) for i in s.invites("open")] == [
        ("i1", False),
        ("i2", True),
    ]
    s.set_invite_status("i1", "revoked")
    assert (s.invite("i1") or {})["status"] == "revoked"
    assert s.invite("nope") is None

    row = {
        "request_id": "r1",
        "invite_id": "i1",
        "group_id": "g1",
        "request": "x",
        "identity": "ac:v0:x",
        "display_name": "x",
        "mailbox_id": "m",
        "received_at": 5,
        "instance_id": f"{3:016x}",
    }
    assert s.add_approval(row)
    assert (s.approval("r1") or {})["instance_id"] == row["instance_id"]
    assert not s.add_approval(row)
    assert [a["request_id"] for a in s.approvals()] == ["r1"]
    s.set_approval_status("r1", "approved")
    assert s.approvals() == []
    assert (s.approval("r1") or {})["status"] == "approved"
    assert s.approval("nope") is None

    s.add_join("i1", {"group_name": "n"}, "me", 1)
    assert s.pending_joins() == [
        {"invite_id": "i1", "meta": {"group_name": "n"}, "display_name": "me"}
    ]
    assert s.join_status("i1") == ("pending", None)
    s.finish_join("i1", "joined", "g1")
    assert s.join_status("i1") == ("joined", "g1")
    assert s.join_status("nope") is None
    assert s.pending_joins() == []

    assert s.add_event("g1", "joined", {"a": 1}, 7, "e1")
    assert s.add_event(None, "x", {}, 8, "e2")
    # The same event id again (regenerated after a crash) is recorded once.
    assert not s.add_event(None, "x", {}, 9, "e2")
    first = s.events()[0]["seq"]
    assert [(e["type"], e["event_id"]) for e in s.events()] == [("joined", "e1"), ("x", "e2")]
    assert [e["type"] for e in s.events(after=first)] == ["x"]
    assert [e["event_id"] for e in s.unnotified_events()] == ["e1", "e2"]
    assert not s.event_notified("e1")
    s.mark_notified("e1")
    assert s.event_notified("e1")
    assert not s.event_notified("nope")
    assert [e["event_id"] for e in s.unnotified_events()] == ["e2"]

    assert s.kv_get("k") is None
    s.kv_set("k", "v")
    s.kv_set("k", "w")
    assert s.kv_get("k") == "w"
    assert [s.next_seq() for _ in range(3)] == [1, 2, 3]


def test_transactions_roll_back(tmp_path: Path, opened: Opener) -> None:
    s = opened(tmp_path / "d.sqlite3")

    def boom() -> None:
        with s.tx():
            s.kv_set("k", "v")
            raise RuntimeError

    with pytest.raises(RuntimeError):
        boom()
    assert s.kv_get("k") is None


def test_transactions_nest_as_savepoints(tmp_path: Path, opened: Opener) -> None:
    s = opened(tmp_path / "d.sqlite3")

    def inner_fails() -> None:
        with s.tx():
            s.kv_set("inner", "1")
            raise RuntimeError

    def outer_fails() -> None:
        with s.tx():
            with s.tx():
                s.kv_set("gone", "1")
            raise RuntimeError

    with s.tx():
        s.kv_set("outer", "1")
        with pytest.raises(RuntimeError):
            inner_fails()
        with s.tx():
            s.kv_set("kept", "1")
    assert (s.kv_get("outer"), s.kv_get("inner"), s.kv_get("kept")) == ("1", None, "1")
    # A failure in the outer transaction undoes the committed inner one too.
    with pytest.raises(RuntimeError):
        outer_fails()
    assert s.kv_get("gone") is None


def test_invites_and_joins_bookkeeping(tmp_path: Path, opened: Opener) -> None:
    s = opened(tmp_path / "d.sqlite3")
    s.add_invite("i1", "g1", 100, 1, 10, status="registering")
    assert [i["invite_id"] for i in s.invites("registering")] == ["i1"]
    s.delete_invite("i1")
    assert s.invite("i1") is None
    s.add_join("j1", {}, "me", 10)
    assert s.join_name("j1") == "me"
    assert s.join_name("j2") is None
    assert s.joined_invites() == []
    s.finish_join("j1", "joined", "g1")
    assert s.joined_invites() == ["j1"]


def test_pending_deliveries_and_events_filter_by_group_in_sql(
    tmp_path: Path, opened: Opener
) -> None:
    s = opened(tmp_path / "d.sqlite3")
    for gid in ("g1", "g2"):
        s.add_group(group(gid))
    for n, gid in enumerate(["g1", "g2", "g1", "g1"]):
        s.record_inbox("ac:v0:x", f"m{n}", gid, "pending", 0, delivery={"n": n})
    assert s.pending_groups() == ["g1", "g2"]
    rows = s.pending_deliveries(group_id="g1", limit=2)
    assert [r.msg_id for r in rows] == ["m0", "m2"]
    assert [r.msg_id for r in s.pending_deliveries(group_id="g2")] == ["m1"]
    s.adapter_event_add("sdk", "e1", {"group": {"id": "g1"}})
    s.adapter_event_add("sdk", "e2", {"group": None})
    s.adapter_event_add("sdk", "e3", {"group": {"id": "g1"}})
    assert s.adapter_event_groups("sdk") == ["g1", None]
    assert [p["group"] for _, p in s.adapter_events("sdk", group_id=None)] == [None]
    assert len(s.adapter_events("sdk", group_id="g1", limit=1)) == 1


def test_old_handled_ids_are_cleared_once(tmp_path: Path, opened: Opener, db_key: bytes) -> None:
    path = tmp_path / "h.sqlite3"
    s = opened(path)
    s.handled_add("bare-before", keep=10)
    # As a database from before the keys were namespaced: no marker yet.
    s._db.execute("DELETE FROM kv WHERE key = 'schema/handled_keys'")
    s.close()
    s = Store(path, db_key)
    assert not s.handled_has("bare-before")  # cleared on the first open
    s.handled_add("bare-after", keep=10)
    s.close()
    s = Store(path, db_key)
    assert s.handled_has("bare-after")  # not on every open
    s.close()


def test_an_invite_from_before_replica_invites_is_a_plain_one(
    tmp_path: Path, opened: Opener, db_key: bytes
) -> None:
    path = tmp_path / "i.sqlite3"
    s = opened(path)
    s.add_invite("i1", "g1", 100, 2, 1)
    # The old schema: no replica flag, no instance pin, no approval instance.
    s._db.execute("ALTER TABLE invites DROP COLUMN replica")
    s._db.execute("ALTER TABLE invites DROP COLUMN instance")
    s._db.execute("ALTER TABLE approvals DROP COLUMN instance_id")
    s.close()
    s = Store(path, db_key)
    assert ((s.invite("i1") or {})["replica"], (s.invite("i1") or {})["instance"]) == (
        False,
        None,
    )
    pin = f"{7:016x}"
    s.add_invite("i2", "g1", 100, 1, 2, replica=True, instance=pin)
    assert ((s.invite("i2") or {})["replica"], (s.invite("i2") or {})["instance"]) == (
        True,
        pin,
    )
    s.close()


def test_a_verification_from_before_its_epoch_was_recorded_reads_as_unknown(
    tmp_path: Path, opened: Opener, db_key: bytes
) -> None:
    """Review 52 F3: a members table from before `verified_epoch` gets the
    column on open, NULL (unknown) for the rows verified then, not filled in
    with an epoch the human never compared."""
    path = tmp_path / "m.sqlite3"
    s = opened(path)
    s.add_group(group())
    s.set_members("g1", {"b": ("member", []), "c": ("member", [])})
    assert s.set_verified("g1", "b", True, 3)
    s._db.execute("ALTER TABLE members DROP COLUMN verified_epoch")  # the old schema
    s.close()
    s = Store(path, db_key)
    b, c = s.members("g1")
    assert (b.verified, b.verified_epoch) == (True, None)
    assert (c.verified, c.verified_epoch) == (False, None)
    assert s.set_verified("g1", "b", True, 7)
    assert s.members("g1")[0].verified_epoch == 7
    s.close()
