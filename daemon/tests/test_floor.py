"""Floor control (agentconnect.runtime.floor, SPEC 9.3): who is the
effective moderator, who may grant, whom ``moderated`` triggers, the moderator
in ``role_changed``, and the floor tables. The harness runs grants between
real daemons (``harness/tests/test_floor.py``)."""

from __future__ import annotations

import random
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agentconnect.runtime.engine import addressed_to_me, canonical
from agentconnect.runtime.floor import effective_moderator, floor_event, may_grant
from agentconnect.runtime.groups import policy_events
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
    members = [owner, mod, other]
    policy = moderated(owner, mod)
    assert may_grant(policy, members, mod)
    assert may_grant(policy, members, owner)
    assert not may_grant(policy, members, other)
    # The moderator left: it may no longer grant, the owner still may.
    assert not may_grant(policy, [owner, other], mod)
    assert may_grant(policy, [owner, other], owner)
    for floor in ("free", "mention"):
        assert not may_grant({**policy, "floor": floor}, members, owner)


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
    assert floor_event(moderated(owner, mod), mod, owner, mod, "grant") == {
        "mode": "moderated",
        "moderator": mod,
        "effective_moderator": mod,
        "holder": owner,
        "by": mod,
        "reason": "grant",
    }


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


def test_the_floor_tables_keep_a_row_per_group_and_a_seq_per_sender_instance(
    store: Store, ids: Ids
) -> None:
    gid, who, instance = "g1", ids.identity(), ids.instance()
    store.add_group(GroupRow(gid, "n", "p", {}, "rec", "active", False, None, 0, 1, 1, 0))
    assert store.floor(gid) is None
    store.set_floor(gid, mode="moderated", moderator=None, effective=who, holder=None)
    store.set_floor(gid, holder=who, granted_by=who, granted_seq=7, sender_instance=instance, at=5)
    row = store.floor(gid)
    assert row is not None
    assert (row["holder"], row["granted_seq"], row["mode"], row["effective"]) == (
        who,
        7,
        "moderated",
        who,
    )
    assert store.floor_seq(gid, who, instance) is None
    store.set_floor_seq(gid, who, instance, 7)
    store.set_floor_seq(gid, who, instance, 9)
    assert store.floor_seq(gid, who, instance) == 9
    # Per identity too: another identity's instance with the same id is apart.
    assert store.floor_seq(gid, ids.identity(), instance) is None
    store.delete_group_data(gid)
    assert (store.floor(gid), store.floor_seq(gid, who, instance)) == (None, None)
