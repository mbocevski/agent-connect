"""The listings and doors tables of the daemon database (docs/discovery.md)."""

from __future__ import annotations

import contextlib
import random
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

import agentconnect_core as ac
from agentconnect.store import MAX_LISTINGS_SEEN, GroupRow, Store


def test_the_tables_appear_in_an_existing_database_and_survive_reopening(
    tmp_path: Path, rng: random.Random
) -> None:
    path, key = tmp_path / "d.sqlite3", rng.randbytes(32)
    Store(path, key).close()  # a database from before discovery
    s = Store(path, key)
    assert s.listings() == []
    s.put_listing(
        {
            "directory": "directory.example.org",
            "name": "release-planner",
            "state": "publishing",
            "content": "{}",
            "token": "{}",
            "token_expires_at": 100,
            "created_at": 1,
            "updated_at": 1,
        }
    )
    secret = ac.Door.generate(10_000).to_secret_bytes()
    s.add_door(
        door_id="d1",
        directory="directory.example.org",
        name="release-planner",
        secret=secret,
        expires_at=50,
        now=1,
    )
    s.close()
    s = Store(path, key)
    row = s.listing("directory.example.org", "release-planner")
    assert row is not None
    assert (row["seq"], row["max_signed_seq"], row["attempts"], row["token_warned"]) == (0, 0, 0, 0)
    (door,) = s.doors("directory.example.org", "release-planner")
    assert door["state"] == "registering"
    assert "secret" not in door  # door queries never read the keys
    assert s.door_secrets() == [("d1", secret)]
    assert s.doors("other.example") == []
    s.update_door("d1", state="current")
    s.drop_door_secret("d1", "closing")
    s.update_listing("directory.example.org", "release-planner", seq=7)
    assert s.door_secrets() == []
    assert s.doors()[0]["state"] == "closing"
    assert s.listings()[0]["seq"] == 7
    with pytest.raises(ValueError, match="unknown listing column"):
        s.update_listing("directory.example.org", "release-planner", bogus=1)
    with pytest.raises(ValueError, match="unknown door column"):
        s.update_door("d1", bogus=1)
    s.delete_door("d1")
    assert s.doors() == []
    assert s.listing("directory.example.org", "nothing") is None
    s.close()


def _store(tmp_path: Path, rng: random.Random) -> tuple[Path, bytes, Store]:
    path, key = tmp_path / "d.sqlite3", rng.randbytes(32)
    return path, key, Store(path, key)


def test_the_agents_events_get_a_sequence_of_their_own(tmp_path: Path, rng: random.Random) -> None:
    path, key, s = _store(tmp_path, rng)
    for i, (kind, agent) in enumerate(
        [("a", True), ("held", False), ("b", True), ("held", False), ("c", True)]
    ):
        s.add_event(None, kind, {}, i, f"e{i}", agent=agent)
    assert [e["seq"] for e in s.events()] == [1, 2, 3, 4, 5]
    assert [(e["seq"], e["type"]) for e in s.agent_events()] == [(1, "a"), (2, "b"), (3, "c")]
    assert [e["type"] for e in s.agent_events(after=2)] == ["c"]
    assert not s.add_event(None, "a", {}, 9, "e0")  # the same event again: nothing new
    assert s.agent_visible("e0")
    assert not s.agent_visible("e1")
    assert not s.agent_visible("missing")
    # A database from before the agent's sequence is numbered once, in order.
    s._db.execute("UPDATE events SET agent_seq = NULL")
    s.kv_set("schema/agent_seq", "0")
    s.close()
    s = Store(path, key)
    s.number_agent_events(frozenset({"held"}))
    assert [(e["seq"], e["type"]) for e in s.agent_events()] == [(1, "a"), (2, "b"), (3, "c")]
    s.number_agent_events(frozenset())  # done already: nothing changes
    assert len(s.agent_events()) == 3
    s.close()


def test_a_group_keeps_its_hidden_state_and_origin(tmp_path: Path, rng: random.Random) -> None:
    path, key, s = _store(tmp_path, rng)
    origin = {"kind": "knock", "directory": "directory.example.org", "name": "release-planner"}
    s.add_group(
        GroupRow("g", "n", "p", {}, "none", "active", False, None, 0, 1, 1, 0, True, origin)
    )
    s.add_event("g", "member_joined", {"identity": "x"}, 1, "e1", agent=False)
    s.add_event("g", "message_held", {}, 2, "e2", agent=False)
    s.add_event(None, "listing_renewed", {}, 3, "e3")
    s.close()
    s = Store(path, key)
    group = s.group("g")
    assert group is not None
    assert (group.hidden, group.origin) == (True, origin)
    with s.tx():
        s.update_group("g", hidden=False)
        released = s.release_agent_events("g", frozenset({"message_held"}))
    assert [e["type"] for e in released] == ["member_joined"]
    assert [(e["seq"], e["type"]) for e in s.agent_events()] == [
        (1, "listing_renewed"),
        (2, "member_joined"),
    ]
    assert (s.group("g") or group).hidden is False
    s.update_group("g", origin=None)
    assert (s.group("g") or group).origin is None
    s.delete_group("g")
    assert s.group("g") is None
    s.close()


def _request(rid: str, **kw: Any) -> dict[str, Any]:
    return {
        "request_id": rid,
        "knock_id": f"k-{rid}",
        "door_id": "door",
        "directory": "directory.example.org",
        "name": "release-planner",
        "identity": "ac:v0:bob",
        "mailbox_id": "mbox",
        "kp_ref": f"r-{rid}",
        "display_name": "Bob",
        "note": "hi",
        "ts": 100,
        "lapses_at": 3700,
        "received_at": 110,
        "status": "pending",
    } | kw


def test_knock_requests_lose_their_secret_and_text_when_decided(
    tmp_path: Path, rng: random.Random
) -> None:
    _, _, s = _store(tmp_path, rng)
    secret = rng.randbytes(64)
    s.add_knock_request(_request("kn-1"), secret)
    s.add_knock_request(_request("kn-2", identity="ac:v0:carol", door_id="other"), secret)
    assert "knock" not in (s.knock_request("kn-1") or {})
    assert s.knock_request_secret("kn-1") == secret
    assert s.open_knock_counts("door", "directory.example.org", "release-planner", "ac:v0:bob") == (
        1,
        1,
    )
    assert s.decide_knock_request(
        "kn-1", "approving", 200, keep_secret=True, keep_name=True, group_id="g", purpose="p"
    )
    row = s.knock_request("kn-1")
    assert row is not None
    assert (row["status"], row["display_name"], row["note"], row["group_id"]) == (
        "approving",
        "Bob",
        None,
        "g",
    )
    assert s.knock_request_secret("kn-1") == secret
    assert s.knock_request_for_group("g") == row
    assert not s.decide_knock_request("kn-1", "rejected", 300)  # not pending any more
    assert s.decide_knock_request("kn-1", "approved", 300, expect=("approving",))
    assert s.knock_request_secret("kn-1") is None
    assert (s.knock_request("kn-1") or {})["display_name"] is None
    assert [r["request_id"] for r in s.knock_requests("pending")] == ["kn-2"]
    assert len(s.knock_requests()) == 2
    s.purge_knock_requests(301)  # decided before then: gone; pending stays
    assert [r["request_id"] for r in s.knock_requests()] == ["kn-2"]
    s.close()


def test_sent_knocks_lose_their_secret_when_they_end(tmp_path: Path, rng: random.Random) -> None:
    _, _, s = _store(tmp_path, rng)
    secret = rng.randbytes(64)
    row = {
        "knock_id": "k1",
        "directory": "directory.example.org",
        "name": "release-planner",
        "identity": "ac:v0:alice",
        "door_id": "door",
        "listing": b"{}",
        "listing_sha256": "00",
        "owner_domain": None,
        "owner_state": "unclaimed",
        "display_name": "me",
        "msg_id": "m1",
        "ts": 100,
        "gives_up_at": 4000,
        "created_at": 100,
        "status": "queued",
    }
    s.add_knock(row, secret)
    s.add_knock({**row, "knock_id": "k2", "door_id": "d2", "created_at": 50}, secret)
    assert "secret" not in (s.knock("k1") or {})
    assert s.knock_secret("k1") == secret
    assert s.knocks_since(100) == 1
    assert s.knocks_since(0, "d2") == 1
    assert [k["knock_id"] for k in s.knocks("queued", "sent")] == ["k2", "k1"]
    s.update_knock("k1", status="sent", sent_once=1)
    with pytest.raises(ValueError, match="unknown knock column"):
        s.update_knock("k1", secret=b"")
    assert s.end_knock("k1", "lapsed", 4000)
    assert not s.end_knock("k1", "failed", 4001)  # ended already
    assert s.knock_secret("k1") is None
    s.knock_joined("k2", "g", 4002)  # a journalled join is recorded whatever the state
    assert (s.knock("k2") or {})["status"] == "joined"
    s.purge_knocks(4001)
    assert [k["knock_id"] for k in s.knocks()] == ["k2"]
    s.close()


def test_a_listed_peer_goes_with_its_group(tmp_path: Path, rng: random.Random) -> None:
    _, _, s = _store(tmp_path, rng)
    peer = {
        "group_id": "g",
        "identity": "ac:v0:alice",
        "directory": "directory.example.org",
        "name": "release-planner",
        "owner_domain": None,
        "owner_state": "unclaimed",
        "listing_sha256": "00",
        "recorded_at": 1,
    }
    s.add_listed_peer(peer)
    assert s.listed_peer("g") == peer
    s.delete_group_data("g")
    assert s.listed_peer("g") is None
    s.close()


def test_listings_seen_keep_the_newest_1024_of_90_days(tmp_path: Path, rng: random.Random) -> None:
    _, _, s = _store(tmp_path, rng)
    for i in range(MAX_LISTINGS_SEEN + 5):
        s.put_listing_seen({"directory": "d", "name": f"n{i}", "seen_at": 1000 + i}, keep_since=0)
    assert s.listing_seen("d", "n0") is None
    assert s.listing_seen("d", f"n{MAX_LISTINGS_SEEN + 4}") is not None
    s.put_listing_seen({"directory": "d", "name": "new", "seen_at": 5000}, keep_since=4000)
    assert s.listing_seen("d", f"n{MAX_LISTINGS_SEEN + 4}") is None
    assert s.listing_seen("d", "new") is not None
    s.close()


@settings(max_examples=40, deadline=None)
# A knock id remembered again after the ledger forgot it, before the table was purged.
@example(steps=[("remember", 0, 0, 0), ("restart", 1), ("remember", 0, 1, 0)])
@given(
    steps=st.lists(
        st.one_of(
            st.tuples(
                st.just("remember"), st.integers(0, 15), st.integers(0, 15), st.integers(0, 50)
            ),
            st.tuples(st.just("purge"), st.integers(0, 60)),
            st.tuples(st.just("restart"), st.integers(0, 60)),
            st.tuples(st.just("rollback"), st.integers(0, 15), st.integers(0, 15)),
        ),
        max_size=30,
    )
)
def test_the_ledger_and_its_table_agree_with_a_reference(steps: list[tuple[Any, ...]]) -> None:
    """``KnockLedger`` with the ``knock_ledger`` table, as the knock service
    uses them, against a model: a knock id or KeyPackageRef seen and not yet
    past its ``forget_after`` is always a replay, across restarts (the ledger
    is rebuilt from the table) and rolled-back transactions."""
    with tempfile.TemporaryDirectory() as tmp:
        key = random.Random(len(steps)).randbytes(32)  # noqa: S311 - a test database key
        store = Store(Path(tmp) / "d.sqlite3", key)
        ledger = ac.KnockLedger()
        model: dict[str, tuple[str, int]] = {}  # knock id -> (ref, forget_after)
        clock = 0

        def seen(kid: str, ref: str) -> bool:
            live = {k: v for k, v in model.items() if v[1] >= clock}
            return kid in live or ref in {r for r, _ in live.values()}

        def remember(kid: str, ref: str, until: int) -> None:
            ledger.insert(_id(kid), _id(ref), until)
            store.ledger_add(kid, ref, until)

        for step in steps:
            if step[0] == "remember":
                kid, ref, until = f"k{step[1]}", f"r{step[2]}", clock + step[3]
                replay = any(
                    k == _id(kid) or r == _id(ref) for k, r, u in ledger.entries() if u >= clock
                )
                assert replay == seen(kid, ref)
                if not replay:
                    with store.tx():
                        remember(kid, ref, until)
                    model[kid] = (ref, until)
            elif step[0] == "rollback":
                kid, ref = f"k{step[1]}", f"r{step[2]}"
                with contextlib.suppress(RuntimeError), store.tx():
                    store.ledger_add(kid, ref, clock + 10)
                    raise RuntimeError
            elif step[0] == "purge":
                clock = max(clock, step[1])
                store.ledger_purge(clock)
                ledger.purge(clock)
            else:  # a restart: the ledger is rebuilt from the table
                clock = max(clock, step[1])
                store.close()
                store = Store(Path(tmp) / "d.sqlite3", key)
                ledger = ac.KnockLedger()
                for kid, ref, until in store.ledger_rows(clock):
                    ledger.insert(_id(kid), _id(ref), until)
        for kid, (ref, until) in model.items():
            if until >= clock:
                assert any(k == _id(kid) for k, _, _ in ledger.entries())
                assert (kid, ref, until) in store.ledger_rows(clock)
        store.close()


def _id(text: str) -> bytes:
    """A 16-byte id for a model name (the ledger stores raw ids)."""
    return text.encode().ljust(16, b".")
