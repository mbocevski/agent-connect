"""Floor control (agentconnect.runtime.floor, SPEC 9.3): who is the
effective moderator, who may grant, whom ``moderated`` triggers, the moderator
in ``role_changed``, and the floor tables. The harness runs grants between
real daemons (``harness/tests/test_floor.py``)."""

from __future__ import annotations

import random
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agentconnect.failpoints import FailpointError
from agentconnect.runtime.engine import Engine, addressed_to_me, canonical
from agentconnect.runtime.floor import (
    FloorService,
    effective_moderator,
    facts_of,
    floor_event,
    floor_write,
    fold,
    may_grant,
)
from agentconnect.runtime.groups import policy_events
from agentconnect.schemas import MAX_COUNTER, MAX_FLOOR_COUNTER, normalize
from agentconnect.store import GroupRow, Store


class Ids:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def identity(self) -> str:
        return f"ac:v0:{self.rng.getrandbits(128):032x}"

    def instance(self) -> str:
        return f"{self.rng.getrandbits(64):016x}"


@pytest.fixture
def ids(rng: random.Random) -> Ids:
    return Ids(rng)


@pytest.fixture
def store(tmp_path: Path, rng: random.Random) -> Iterator[Store]:
    s = Store(tmp_path / "d.sqlite3", rng.randbytes(32))
    yield s
    s.close()


def moderated(owner: str, moderator: str | None = None) -> dict[str, Any]:
    return {"owner": owner, "admins": [], "floor": "moderated", "floor_moderator": moderator}


def inner(
    to: list[str] | None = None,
    *,
    origin: str = "agent",
    addressee: list[str] | None = None,
    instance: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"text": "x"}
    if instance is not None:
        body["metadata"] = {"instance": instance}
    out: dict[str, Any] = {"to": to or ["*"], "origin": origin, "body": body}
    if addressee is not None:
        out["addressee"] = addressee
    return out


def test_the_effective_moderator_is_the_moderator_while_it_is_a_member(ids: Ids) -> None:
    owner, mod, other = ids.identity(), ids.identity(), ids.identity()
    assert effective_moderator(moderated(owner, mod), [owner, mod]) == mod
    # Gone, or never set: the owner (SPEC 9.3).
    assert effective_moderator(moderated(owner, mod), [owner, other]) == owner
    assert effective_moderator(moderated(owner), [owner, mod]) == owner
    assert effective_moderator({"floor": "moderated", "owner": None}, [owner]) is None


def test_only_the_effective_moderator_or_the_owner_grants_and_only_when_moderated(
    ids: Ids,
) -> None:
    owner, mod, other = ids.identity(), ids.identity(), ids.identity()
    facts = facts_of(moderated(owner, mod), [owner, mod, other])
    assert may_grant(facts, mod)
    assert may_grant(facts, owner)
    assert not may_grant(facts, other)
    # The moderator left: it may no longer grant, the owner still may.
    gone = facts_of(moderated(owner, mod), [owner, other])
    assert not may_grant(gone, mod)
    assert may_grant(gone, owner)
    for floor in ("free", "mention"):
        assert not may_grant(facts_of({**moderated(owner, mod), "floor": floor}, [owner]), owner)


def test_moderated_triggers_the_holder_and_the_effective_moderator(ids: Ids) -> None:
    me, other = ids.identity(), ids.identity()
    mine, theirs = ids.instance(), ids.instance()
    # The holder and the moderator, whatever `to` and `origin` say.
    for message in (inner(), inner([other]), inner(origin="human")):
        assert addressed_to_me("moderated", message, me, mine, me, None)
        assert addressed_to_me("moderated", message, me, mine, other, me)
        assert not addressed_to_me("moderated", message, me, mine, other, None)
        assert not addressed_to_me("moderated", message, me, mine, other, other)
    # `addressee` is ignored in moderated mode (SPEC 9.3)...
    assert not addressed_to_me("moderated", inner(addressee=[me]), me, mine, other, None)
    assert addressed_to_me("moderated", inner(addressee=[other]), me, mine, other, me)
    # ...and the instance hint still narrows it (SPEC 9.4).
    assert addressed_to_me("moderated", inner(instance=mine), me, mine, other, me)
    assert not addressed_to_me("moderated", inner(instance=theirs), me, mine, other, me)
    # The holder means nothing in the other modes.
    assert not addressed_to_me("mention", inner(), me, mine, None, me)


def test_a_floor_event_says_mode_moderators_holder_who_and_why(ids: Ids) -> None:
    owner, mod = ids.identity(), ids.identity()
    facts = facts_of(moderated(owner, mod), [owner, mod])
    assert floor_event(facts, owner, mod, "grant") == {
        "mode": "moderated",
        "moderator": mod,
        "effective_moderator": mod,
        "holder": owner,
        "by": mod,
        "reason": "grant",
    }


def test_a_grant_is_judged_on_the_facts_of_its_epoch(ids: Ids) -> None:
    owner, mod, other = ids.identity(), ids.identity(), ids.identity()
    inst = ids.instance()
    facts = facts_of(moderated(owner, mod), [owner, mod, other])
    body = {"holder": other, "counter": 5}
    assert floor_write(facts, 7, mod, inst, body) == ((7, 5, mod, inst), other)
    assert floor_write(facts, 7, mod, inst, {"holder": None, "counter": 1}) == (
        (7, 1, mod, inst),
        None,
    )
    # No facts for the epoch, a sender that may not grant, a non-member.
    assert floor_write(None, 7, mod, inst, body) is None
    assert floor_write(facts, 7, other, inst, body) is None
    assert floor_write(facts, 7, mod, inst, {"holder": ids.identity(), "counter": 1}) is None
    # A copy carries the key of the grant it copies, never from a later epoch.
    copy = {**body, "copy": {"epoch": 6, "sender": owner, "instance": inst}}
    assert floor_write(facts, 7, mod, inst, copy) == ((6, 5, owner, inst), other)
    later = {**body, "copy": {"epoch": 8, "sender": owner, "instance": inst}}
    assert floor_write(facts, 7, mod, inst, later) is None
    # A copy of "nobody", with the key of the reset or drop that made it.
    empty = {"holder": None, "counter": 0, "copy": {"epoch": 7, "sender": "", "instance": other}}
    assert floor_write(facts, 7, mod, inst, empty) == ((7, 0, "", other), None)


def test_the_register_folds_writes_in_key_order_whatever_order_they_came_in(
    ids: Ids, rng: random.Random
) -> None:
    mod, x, y = ids.identity(), ids.identity(), ids.identity()
    inst = ids.instance()
    writes = [
        (3, 1, mod, inst, "grant", x),
        (4, 0, "", "", "reset", None),
        (4, 2, mod, inst, "grant", y),
        (5, 0, "", y, "drop", y),
        (5, 1, mod, inst, "grant", x),
    ]
    for _ in range(20):
        shuffled = rng.sample(writes, len(writes))
        assert fold(None, None, sorted(shuffled)) == (x, (5, 1, mod, inst))
    # A grant from before a reset loses to it, however late it arrives; the
    # source is then the reset, so a copy of "nobody" can name it.
    assert fold(None, None, sorted(writes[:2])) == (None, (4, 0, "", ""))
    # A drop clears only the identity it names.
    assert fold(None, None, sorted([writes[0], (5, 0, "", y, "drop", y)])) == (
        x,
        (3, 1, mod, inst),
    )
    assert fold(x, (2, 1, mod, inst), []) == (x, (2, 1, mod, inst))


def test_a_floor_counter_starts_again_each_epoch_and_stays_below_2_to_the_32(ids: Ids) -> None:
    """Counters order grants within an epoch only, so none needs more than
    2**32: a jump past it is malformed. Epochs may go up to what SQLite holds."""
    who = ids.identity()
    assert normalize("control.floor", {"holder": who, "counter": MAX_FLOOR_COUNTER}) == {
        "holder": who,
        "counter": MAX_FLOOR_COUNTER,
    }
    for counter in (MAX_FLOOR_COUNTER + 1, MAX_COUNTER, -1, True, "1", None):
        assert normalize("control.floor", {"holder": who, "counter": counter}) is None
    copy = {
        "epoch": MAX_COUNTER,
        "sender": who,
        "instance": ids.instance(),
        "join": MAX_COUNTER,
        "seq": MAX_FLOOR_COUNTER,
    }
    assert normalize("control.floor", {"holder": who, "counter": 1, "copy": copy}) is not None
    for bad in (
        {**copy, "epoch": MAX_COUNTER + 1},
        {**copy, "join": -1},
        {**copy, "seq": MAX_FLOOR_COUNTER + 1},
        {k: v for k, v in copy.items() if k != "seq"},
        {**copy, "sender": "x"},
        {**copy, "instance": "XYZ"},
        "copy",
    ):
        assert normalize("control.floor", {"holder": who, "counter": 1, "copy": bad}) is None
    # The key of a commit's reset or drop: no sender, counter 0.
    for instance in ("", who):
        reset = {"epoch": 3, "sender": "", "instance": instance, "join": 3, "seq": 1}
        body = {"holder": None, "counter": 0, "copy": reset}
        assert normalize("control.floor", body) == body
        assert normalize("control.floor", {**body, "counter": 1}) is None
    bad_drop = {"epoch": 3, "sender": "", "instance": "x", "join": 3, "seq": 1}
    assert normalize("control.floor", {"holder": None, "counter": 0, "copy": bad_drop}) is None


async def test_one_failing_journal_entry_does_not_stop_the_replay() -> None:
    """A pending entry that fails for good fails alone (SR-11): it is
    recorded as failed and consumed, and the entries after it are replayed.
    A transient failure still goes to the inbound worker, which retries the
    whole replay."""
    done: list[str] = []
    failed: list[str] = []

    async def replay(entry: dict[str, Any]) -> None:
        if entry["key"] == "poison":
            raise OverflowError
        if entry["key"] == "transient":
            raise FailpointError
        done.append(str(entry["key"]))

    async def fail(entry: dict[str, Any], error: Exception) -> bool:
        assert isinstance(error, OverflowError)
        failed.append(str(entry["key"]))
        return True

    entries = [{"key": "poison"}, {"key": "next"}]
    fake = SimpleNamespace(
        client=SimpleNamespace(journal_pending=lambda: entries),
        _replay_entry=replay,
        _fail_entry=fail,
        _count=lambda _key: 1,
        _uncount=lambda _key: None,
    )
    await Engine._replay_journal(fake)  # ty: ignore[invalid-argument-type]
    assert (done, failed) == (["next"], ["poison"])
    entries[:] = [{"key": "transient"}, {"key": "after"}]
    with pytest.raises(FailpointError):
        await Engine._replay_journal(fake)  # ty: ignore[invalid-argument-type]


def test_role_changed_covers_the_moderator(ids: Ids) -> None:
    owner, mod, admin = ids.identity(), ids.identity(), ids.identity()
    before = {**moderated(owner), "admins": [admin]}
    after = {**moderated(owner, mod), "admins": [admin]}
    s = {
        "committer": {"identity": owner},
        "policy_changed": True,
        "previous_policy": canonical(before),
        "policy": canonical(after),
    }
    _, *roles = policy_events(s, after)
    assert roles == [
        (
            "role_changed",
            {
                "identity": mod,
                "from": "member",
                "to": "member",
                "moderator_from": False,
                "moderator_to": True,
                "by": owner,
            },
        )
    ]
    # An admin made moderator, then dropped from both: one event each time.
    s["previous_policy"], s["policy"] = s["policy"], canonical({**moderated(owner, admin)})
    changed = {d["identity"]: d for _, d in policy_events(s, after)[1:]}
    assert (changed[admin]["from"], changed[admin]["to"]) == ("admin", "member")
    assert (changed[admin]["moderator_from"], changed[admin]["moderator_to"]) == (False, True)
    assert (changed[mod]["moderator_from"], changed[mod]["moderator_to"]) == (True, False)


def test_the_floor_tables_keep_a_state_per_group_and_writes_by_key(store: Store, ids: Ids) -> None:
    gid, who, instance = "g1", ids.identity(), ids.instance()
    store.add_group(GroupRow(gid, "n", "p", {}, "rec", "active", False, None, 0, 1, 1, 0))
    assert store.floor(gid) is None
    store.set_floor(gid, who, {"counter": 3})
    assert store.floor(gid) == (who, {"counter": 3})
    key = (2, 3, who, instance)
    assert store.add_floor_write(gid, key, "grant", who)
    assert not store.add_floor_write(gid, key, "grant", None)  # one write per key
    store.add_floor_write(gid, (1, 0, "", ""), "reset", None)
    assert store.floor_writes(gid) == [(1, 0, "", "", "reset", None), (*key, "grant", who)]
    store.drop_floor_writes(gid, 2)
    assert store.floor_writes(gid) == [(*key, "grant", who)]
    store.delete_group_data(gid)
    assert (store.floor(gid), store.floor_writes(gid)) == (None, [])


def test_a_legacy_summary_tells_a_floor_change_from_the_kept_facts(ids: Ids) -> None:
    """A commit summary journalled before the core reported policies has no
    ``previous_policy``: the facts kept for the epoch before tell."""
    owner, mod = ids.identity(), ids.identity()
    before = facts_of(moderated(owner), [owner, mod])
    after = facts_of(moderated(owner, mod), [owner, mod])
    legacy = {"policy_changed": True, "previous_policy": None}
    assert FloorService._floor_changed(legacy, before, after)
    assert not FloorService._floor_changed(legacy, before, before)
    assert not FloorService._floor_changed(legacy, None, after)
    assert not FloorService._floor_changed({"policy_changed": False}, before, after)


def test_a_send_that_fails_after_the_group_went_changes_nothing() -> None:
    engine = SimpleNamespace(store=SimpleNamespace(group=lambda _gid: None))
    assert FloorService(engine).unsent("g1", "m1") is None  # ty: ignore[invalid-argument-type]
