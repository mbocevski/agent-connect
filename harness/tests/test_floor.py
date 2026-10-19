"""Floor control on the real relay (SPEC 9.3, docs/groups.md#floor-control):
in a ``moderated`` group only the effective moderator and the floor holder
are triggered; grants come from the effective moderator or the owner and
are ignored otherwise; the holder resets with membership and the policy;
newcomers get the grant again; the loop guard still holds; and the floor
switch to ``mention`` counts identities and respects ``floor_pinned``."""

from __future__ import annotations

import random
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.adapter import Delivery
from agentconnect.runtime import AgentApi
from agentconnect.runtime.engine import DaemonError, new_msg_id
from agentconnect_harness.cluster import WAIT, Cluster, Node, converged, status

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]


def data(node: Node, kind: str) -> list[dict[str, Any]]:
    return [e.data for e in node.adapter.unique_events() if e.type == kind]


def holder(node: Node, gid: str) -> str | None:
    floor = node.daemon.group_info(gid)["floor"]
    return None if floor["holder"] is None else str(floor["holder"])


def floor_event(  # noqa: PLR0913, PLR0917
    mode: str, moderator: str | None, effective: str | None, who: str | None, by: str, reason: str
) -> dict[str, Any]:
    return {
        "mode": mode,
        "moderator": moderator,
        "effective_moderator": effective,
        "holder": who,
        "by": by,
        "reason": reason,
    }


async def say(node: Node, gid: str, text: str, reply_to: Delivery | None = None) -> None:
    """The node's agent sends ``text`` to everyone."""
    send = node.adapter.send
    assert send is not None
    await send(gid, {"text": text}, reply_to=None if reply_to is None else [reply_to.msg_id])


def got(node: Node, text: str) -> Delivery | None:
    return next(
        (
            d
            for d in node.adapter.deliveries
            if d.kind == "a2a.message" and d.body == {"text": text}
        ),
        None,
    )


async def heard(nodes: list[Node], text: str) -> dict[str, bool]:
    """Wait until every node has ``text``; whether it triggered each one."""
    for n in nodes:
        await n.adapter.wait_for(lambda n=n: got(n, text) is not None, WAIT)
    return {n.name: bool(d.addressed_to_me) for n in nodes if (d := got(n, text)) is not None}


def forge(node: Node, gid: str, holder_: str | None, seq: int | None = None) -> None:
    """A ``control.floor`` built by a modified daemon: it skips the grant's
    checks and goes straight to the outbox (what the receivers must judge)."""
    inner = node.daemon.inner("control.floor", {"holder": holder_}, ["*"], origin="agent")
    if seq is not None:
        inner["seq"] = seq
    node.daemon._enqueue("app", gid, {"inner": inner, "msg_id": new_msg_id()})


def grants_seen(node: Node) -> list[Delivery]:
    return [d for d in node.adapter.deliveries if d.kind == "control.floor"]


async def moderated(nodes: list[Node], gid: str, **fields: Any) -> None:
    """The owner's human makes the floor moderated, with ``fields``."""
    owner = nodes[0]
    assert owner.daemon.change_policy(gid, {"floor": "moderated", **fields}) == "committing"
    await converged(nodes, gid)


# -- scenario 8: the moderated floor ------------------------------------------------------------


async def test_the_moderator_grants_the_floor_and_the_holder_is_triggered(
    cluster: Cluster, group: GroupFixture
) -> None:
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, floor_moderator=b.me)
    for n in (a, b, c):
        assert data(n, "floor_changed")[-1] == floor_event(
            "moderated", b.me, b.me, None, a.me, "policy"
        )
        assert data(n, "role_changed")[-1] == {
            "identity": b.me,
            "from": "member",
            "to": "member",
            "moderator_from": False,
            "moderator_to": True,
            "by": a.me,
        }
        floor = n.daemon.group_info(gid)["floor"]
        assert (floor["effective_moderator"], floor["holder"]) == (b.me, None)

    # No holder yet: only the moderator is triggered, not even the owner.
    await say(c, gid, "before any grant")
    assert await heard([a, b], "before any grant") == {"n0": False, "n1": True}

    # The moderator's agent grants c the floor.
    answer = await AgentApi(b.daemon).grant_floor(gid, c.me)
    assert (answer["status"], answer["holder"]) == ("granted", c.me)
    await a.wait(lambda: holder(a, gid) == holder(c, gid) == c.me)
    assert holder(b, gid) == c.me
    for n in (a, b, c):
        assert data(n, "floor_changed")[-1] == floor_event(
            "moderated", b.me, b.me, c.me, b.me, "grant"
        )
    # A grant triggers nobody: every member gets it as context.
    for n in (a, c):
        await n.adapter.wait_for(lambda n=n: bool(grants_seen(n)), WAIT)
        assert [(d.body, d.addressed_to_me) for d in grants_seen(n)] == [({"holder": c.me}, False)]

    await say(a, gid, "the owner speaks")
    assert await heard([b, c], "the owner speaks") == {"n1": True, "n2": True}
    await say(c, gid, "the holder speaks")
    assert await heard([a, b], "the holder speaks") == {"n0": False, "n1": True}
    await converged([a, b, c], gid)

    # The holder leaves: nobody holds the floor any more.
    assert await c.daemon.leave(gid) == "leaving"
    await c.wait(lambda: status(c, gid) == "left")
    await converged([a, b], gid)
    for n in (a, b):
        last = data(n, "floor_changed")[-1]
        assert (last["holder"], last["reason"], last["effective_moderator"]) == (
            None,
            "reset",
            b.me,
        )
        assert holder(n, gid) is None

    # The moderator grants the owner, then a newcomer learns it from the
    # moderator's daemon: it starts with nobody and gets the grant again.
    await AgentApi(b.daemon).grant_floor(gid, a.me)
    await a.wait(lambda: holder(a, gid) == a.me)
    d = await cluster.node("d")
    await cluster.invite(a, d, gid)
    await d.wait(lambda: holder(d, gid) == a.me)
    assert data(d, "floor_changed") == [floor_event("moderated", b.me, b.me, a.me, b.me, "grant")]
    await d.adapter.wait_for(lambda: bool(grants_seen(d)), WAIT)
    (regrant,) = grants_seen(d)
    assert (regrant.sender.identity, regrant.to) == (b.me, [d.me])
    await converged([a, b, d], gid)
    # The others took the grant again too, and nothing changed for them.
    assert [e["reason"] for e in data(a, "floor_changed")].count("grant") == 2


async def test_the_owner_may_grant_and_a_policy_change_resets_the_holder(
    group: GroupFixture,
) -> None:
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid)  # no moderator: the owner moderates
    assert a.daemon.group_info(gid)["floor"]["effective_moderator"] == a.me
    # The owner's human grants with the human token (origin human, hop 0).
    a.daemon.grant_floor(gid, b.me, origin="human")
    await a.wait(lambda: holder(b, gid) == holder(c, gid) == b.me)
    await c.adapter.wait_for(lambda: bool(grants_seen(c)), WAIT)
    (grant,) = grants_seen(c)
    assert (grant.origin, grant.hop) == ("human", 0)
    assert data(a, "floor_changed")[-1] == floor_event("moderated", None, a.me, b.me, a.me, "grant")
    # Granting again to the same holder sends it again, and reports nothing.
    events = len(data(c, "floor_changed"))
    a.daemon.grant_floor(gid, b.me, origin="human")
    await c.adapter.wait_for(lambda: len(grants_seen(c)) == 2, WAIT)
    assert len(data(c, "floor_changed")) == events
    # A commit that changes the moderator resets the holder everywhere.
    assert a.daemon.change_policy(gid, {"floor_moderator": c.me}) == "committing"
    await converged([a, b, c], gid)
    for n in (a, b, c):
        assert data(n, "floor_changed")[-1] == floor_event(
            "moderated", c.me, c.me, None, a.me, "policy"
        )
    # Back to mention: the floor is no longer the moderator's to grant.
    assert a.daemon.change_policy(gid, {"floor": "mention"}) == "committing"
    await converged([a, b, c], gid)
    with pytest.raises(DaemonError) as e:
        c.daemon.grant_floor(gid, b.me)
    assert e.value.code == "not_moderated"
    assert data(b, "floor_changed")[-1]["mode"] == "mention"


async def test_grants_the_policy_does_not_allow_are_ignored(
    group: GroupFixture, rng: random.Random
) -> None:
    (a, b, c), gid = await group(3)
    # Not moderated yet: even the owner's grant is ignored.
    forge(a, gid, b.me)
    await say(a, gid, "m1")
    await heard([b, c], "m1")
    assert (holder(b, gid), grants_seen(b), grants_seen(c)) == (None, [], [])

    await moderated([a, b, c], gid, floor_moderator=b.me)
    # A plain member's grant, and a grant to someone who isn't a member.
    forge(c, gid, c.me)
    await say(c, gid, "m2")
    forge(b, gid, f"ac:v0:{rng.getrandbits(128):032x}")
    # And the moderator's own grant without a usable seq.
    forge(b, gid, c.me, seq=-1)
    await say(b, gid, "m3")
    await heard([a, b], "m2")
    await heard([a, c], "m3")
    assert {holder(n, gid) for n in (a, b, c)} == {None}
    assert (grants_seen(a), grants_seen(b), grants_seen(c)) == ([], [], [])

    # A real grant, then an older one from the same instance (the relay held
    # it back): the older one can't undo the newer.
    await AgentApi(b.daemon).grant_floor(gid, c.me)
    await a.wait(lambda: holder(a, gid) == holder(c, gid) == c.me)
    forge(b, gid, a.me, seq=1)
    await say(b, gid, "m4")
    await heard([a, c], "m4")
    assert holder(a, gid) == holder(c, gid) == c.me
    assert len(grants_seen(a)) == 1
    audited = [r["reason"] for r in a.daemon.store.audit(gid, 0) if r["kind"] == "control.floor"]
    assert audited.count("floor_ignored") == 4

    # This daemon refuses what its peers would ignore.
    with pytest.raises(DaemonError) as e:
        c.daemon.grant_floor(gid, c.me)
    assert e.value.code == "not_permitted"
    with pytest.raises(DaemonError) as e:
        b.daemon.grant_floor(gid, "ac:v0:nobody")
    assert e.value.code == "not_found"
    with pytest.raises(DaemonError) as e:
        b.daemon.send_message(gid, {"holder": None}, kind="control.floor")
    assert e.value.code == "bad_request"
    with pytest.raises(DaemonError) as e:
        await AgentApi(b.daemon).send(gid, {"holder": None}, kind="control.floor")
    assert e.value.code == "bad_request"


async def test_the_loop_guard_holds_between_the_moderator_and_the_holder(
    group: GroupFixture,
) -> None:
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, max_agent_turns=3)
    a.daemon.grant_floor(gid, b.me, origin="human")
    await a.wait(lambda: holder(b, gid) == holder(c, gid) == b.me)
    await say(a, gid, "t1")
    assert await heard([b, c], "t1") == {"n1": True, "n2": False}
    await say(b, gid, "t2", got(b, "t1"))
    assert await heard([a, c], "t2") == {"n0": True, "n2": False}
    await say(a, gid, "t3", got(a, "t2"))
    assert await heard([b, c], "t3") == {"n1": True, "n2": False}
    await say(b, gid, "t4", got(b, "t3"))
    # Hop 4 > 3: the moderator isn't triggered; it pauses the group once.
    assert await heard([a, c], "t4") == {"n0": False, "n2": False}
    hit = got(a, "t4")
    assert hit is not None
    assert hit.hop == 4
    await a.adapter.wait_for(lambda: bool(a.adapter.of_type("loop_guard")), WAIT)
    await b.adapter.wait_for(
        lambda: any(d.kind == "control.pause" for d in b.adapter.deliveries), WAIT
    )
    # A new grant neither triggers anyone nor resets the count.
    a.daemon.grant_floor(gid, c.me, origin="human")
    await c.wait(lambda: holder(c, gid) == c.me)
    await say(b, gid, "t5", got(b, "t3"))
    assert await heard([a, c], "t5") == {"n0": False, "n2": False}
    assert len(a.adapter.of_type("loop_guard")) == 1


# -- scenario 9: the floor switch -------------------------------------------------------------


async def test_floor_pinned_free_survives_a_third_member(cluster: Cluster) -> None:
    a = await cluster.node("a")
    gid = a.daemon.create_group("Pinned", "Free for three", {"floor": "free"})
    await a.idle()
    b, c = await cluster.node("b"), await cluster.node("c")
    await cluster.invite(a, b, gid)
    await cluster.invite(a, c, gid)
    await converged([a, b, c], gid)
    for n in (a, b, c):
        floor = n.daemon.group_info(gid)["floor"]
        assert (floor["mode"], floor["pinned"]) == ("free", True)
        assert data(n, "floor_changed") == []
    # Free: an agent broadcast triggers everyone.
    await say(c, gid, "hello both")
    assert await heard([a, b], "hello both") == {"a": True, "b": True}


async def test_an_unpinned_floor_switches_with_the_third_identity(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    for n in (a, b, c):
        assert n.daemon.group_info(gid)["floor"]["mode"] == "mention"
    # The inviter's commit switched it; members that saw it say so.
    for n in (a, b):
        assert data(n, "floor_changed") == [
            floor_event("mention", None, a.me, None, a.me, "policy")
        ]


async def test_a_replica_does_not_switch_a_one_to_one_to_mention(cluster: Cluster) -> None:
    a = await cluster.node("a")
    gid = a.daemon.create_group("Pair", "One to one")
    await a.idle()
    b = await cluster.node("b")
    await cluster.invite(a, b, gid)
    b2 = await cluster.node("b2", identity_of=b)
    await cluster.invite(a, b2, gid)
    await converged([a, b, b2], gid)
    info = a.daemon.group_info(gid)
    assert len(info["members"]) == 2
    assert sum(len(m["instances"]) for m in info["members"]) == 3
    for n in (a, b, b2):
        assert n.daemon.group_info(gid)["floor"]["mode"] == "free"
    await say(a, gid, "to both of b")
    assert await heard([b, b2], "to both of b") == {"b": True, "b2": True}
    assert a.daemon.group_info(gid)["floor"]["pinned"] is False
