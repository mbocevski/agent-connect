"""The durable queues and group tables of the daemon database."""

import stat
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from agentconnect.store import GroupRow, Store

Opener = Callable[[Path], Store]


@pytest.fixture
def opened() -> Iterator[Opener]:
    stores: list[Store] = []

    def open_store(path: Path) -> Store:
        stores.append(Store(path))
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
    assert [r.payload for r in s.outbox("done")] == [{"n": 1, "env": {}}]
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
    }
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
    }
    assert s.add_approval(row)
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

    first = s.add_event("g1", "joined", {"a": 1}, 7)
    s.add_event(None, "x", {}, 8)
    assert [e["type"] for e in s.events()] == ["joined", "x"]
    assert [e["type"] for e in s.events(after=first)] == ["x"]

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
