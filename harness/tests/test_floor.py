"""Floor control on the real relay (SPEC 9.3, docs/groups.md#floor-control):
in a ``moderated`` group only the effective moderator and the floor holder
are triggered; grants come from the effective moderator or the owner and
are ignored otherwise; the holder resets with membership and the policy;
newcomers get the grant again; the loop guard still holds; and the floor
switch to ``mention`` counts identities and respects ``floor_pinned``."""

from __future__ import annotations

import base64
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


def raw(gid: str) -> bytes:
    return base64.urlsafe_b64decode(gid + "=" * (-len(gid) % 4))


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


def forge(node: Node, gid: str, holder_: str | None, counter: int = 1, **extra: Any) -> None:
    """A ``control.floor`` built by a modified daemon: it skips the grant's
    checks and goes straight to the outbox (what the receivers must judge)."""
    body = {"holder": holder_, "counter": counter, **extra}
    inner = node.daemon.inner("control.floor", body, ["*"], origin="agent")
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
        assert [(d.body["holder"], d.addressed_to_me) for d in grants_seen(n)] == [(c.me, False)]

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
    await a.wait(lambda: holder(a, gid) == holder(b, gid) == holder(c, gid) == b.me)
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
    # And the moderator's own grant with a counter out of range: malformed.
    forge(b, gid, c.me, counter=-1)
    await say(b, gid, "m3")
    await heard([a, b], "m2")
    await heard([a, c], "m3")
    assert {holder(n, gid) for n in (a, b, c)} == {None}
    assert (grants_seen(a), grants_seen(b), grants_seen(c)) == ([], [], [])

    # A real grant, then an older one (a lower counter in the same epoch,
    # held back by the relay): valid, but it loses to the newer one.
    await AgentApi(b.daemon).grant_floor(gid, c.me)
    await a.wait(lambda: holder(a, gid) == holder(b, gid) == holder(c, gid) == c.me)
    forge(b, gid, a.me, counter=0)
    await say(b, gid, "m4")
    await heard([a, c], "m4")
    assert holder(a, gid) == holder(b, gid) == holder(c, gid) == c.me
    await a.adapter.wait_for(lambda: len(grants_seen(a)) == 2, WAIT)
    audited = [r["reason"] for r in a.daemon.store.audit(gid, 0) if r["kind"] == "control.floor"]
    assert (audited.count("floor_ignored"), audited.count("malformed")) == (2, 1)

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


# -- convergence: every member ends with the same holder --------------------------------------


async def mark(sender: Node, receivers: list[Node], gid: str, text: str) -> None:
    """``sender``'s agent says ``text``; wait until every receiver has it.
    One sender's messages arrive in order, so whatever ``sender`` queued
    before has been processed by then."""
    await say(sender, gid, text)
    for n in receivers:
        await n.adapter.wait_for(lambda n=n: got(n, text) is not None, WAIT)


async def agreed(nodes: list[Node], gid: str) -> str | None:
    """Wait until every node is idle and has the same holder; that holder."""
    for n in nodes:
        await n.idle()
    await nodes[0].wait(lambda: len({holder(n, gid) for n in nodes}) == 1)
    return holder(nodes[0], gid)


async def test_a_grant_after_a_moderator_change_is_judged_in_its_epoch(
    group: GroupFixture,
) -> None:
    """The owner's human changes the moderator and grants before the commit
    is confirmed. The grant goes out in the commit's epoch, where the owner
    may grant and the policy reset is older: everyone ends with b."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, floor_moderator=b.me)
    assert a.daemon.change_policy(gid, {"floor_moderator": c.me}) == "committing"
    a.daemon.grant_floor(gid, b.me, origin="human")
    await mark(a, [b, c], gid, "r1")
    await a.wait(
        lambda: all(n.daemon.group_info(gid)["floor"]["moderator"] == c.me for n in (a, b, c))
    )
    assert await agreed([a, b, c], gid) == b.me
    await converged([a, b, c], gid)


async def test_a_grant_after_the_holders_removal_is_refused_everywhere(
    group: GroupFixture,
) -> None:
    """b holds the floor; the owner removes c and grants c before the removal
    is confirmed. The grant goes out in the epoch without c, so it names no
    member: every member, the owner included, keeps b."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid)  # the owner moderates
    a.daemon.grant_floor(gid, b.me, origin="human")
    await a.wait(lambda: holder(a, gid) == holder(b, gid) == holder(c, gid) == b.me)
    a.daemon.remove_member(gid, c.me)
    a.daemon.grant_floor(gid, c.me, origin="human")
    await a.wait(lambda: status(c, gid) == "removed")
    await mark(a, [b], gid, "r2")
    assert await agreed([a, b], gid) == b.me
    await converged([a, b], gid)


async def test_concurrent_grants_end_with_one_holder(group: GroupFixture) -> None:
    """The owner and the moderator grant at once: whatever order the relay
    gives them, every member takes the one with the greater key."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, floor_moderator=b.me)
    a.daemon.grant_floor(gid, c.me, origin="human")
    await AgentApi(b.daemon).grant_floor(gid, a.me)
    await mark(a, [b, c], gid, "r3a")
    await mark(b, [a, c], gid, "r3b")
    assert await agreed([a, b, c], gid) in (a.me, c.me)
    await converged([a, b, c], gid)


async def test_two_moderator_replicas_granting_at_once_end_with_one_holder(
    cluster: Cluster, group: GroupFixture
) -> None:
    """Two instances of the moderator, triggered by the same message, grant
    different members at once: one key wins on every member."""
    (a, b, c), gid = await group(3)
    b2 = await cluster.node("b2", identity_of=b)
    await cluster.invite(a, b2, gid)
    await moderated([a, b, c, b2], gid, floor_moderator=b.me)
    await AgentApi(b.daemon).grant_floor(gid, a.me)
    await AgentApi(b2.daemon).grant_floor(gid, c.me)
    await mark(b, [a, c, b2], gid, "r3c")
    await mark(b2, [a, b, c], gid, "r3d")
    assert await agreed([a, b, c, b2], gid) in (a.me, c.me)
    await converged([a, b, c, b2], gid)


async def test_a_join_after_concurrent_grants_keeps_the_agreed_holder(
    cluster: Cluster, group: GroupFixture
) -> None:
    """The copy a newcomer gets carries the grant's own key: existing members
    already have it, so an unrelated join never moves the floor."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, floor_moderator=b.me)
    a.daemon.grant_floor(gid, c.me, origin="human")
    await AgentApi(b.daemon).grant_floor(gid, a.me)
    await mark(a, [b, c], gid, "r3e")
    await mark(b, [a, c], gid, "r3f")
    before = await agreed([a, b, c], gid)
    changes = {n.name: len(data(n, "floor_changed")) for n in (a, b, c)}
    d = await cluster.node("d")
    await cluster.invite(a, d, gid)
    await d.wait(lambda: holder(d, gid) == before)
    assert await agreed([a, b, c, d], gid) == before
    assert {n.name: len(data(n, "floor_changed")) for n in (a, b, c)} == changes
    await converged([a, b, c, d], gid)


async def test_a_grant_after_an_owner_transfer_is_refused_everywhere(
    group: GroupFixture,
) -> None:
    """The owner moderates (no floor_moderator), hands ownership over and
    grants before the transfer is confirmed. In the transfer's epoch it may
    no longer grant: nobody takes it, the old owner included, and the new
    owner can grant. The transfer moves the effective moderator only."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid)
    assert a.daemon.transfer_ownership(gid, b.me, keep_admin=True) == "committing"
    a.daemon.grant_floor(gid, c.me, origin="human")
    await mark(a, [b, c], gid, "r4")
    await a.wait(
        lambda: all(n.daemon.group_info(gid)["policy"]["owner"] == b.me for n in (a, b, c))
    )
    assert await agreed([a, b, c], gid) is None
    for n in (a, b, c):
        last = data(n, "floor_changed")[-1]
        assert (last["reason"], last["effective_moderator"], last["holder"]) == (
            "moderator",
            b.me,
            None,
        )
    await AgentApi(b.daemon).grant_floor(gid, c.me)
    await a.wait(lambda: holder(a, gid) == holder(b, gid) == holder(c, gid) == c.me)


async def test_a_moderator_replica_on_a_lower_leaf_still_gets_and_sends_the_floor(
    cluster: Cluster, group: GroupFixture
) -> None:
    """The moderator's new replica takes a blank lower leaf. Its sibling, in
    the group before the commit, sends it the floor; it then sends the floor
    to the holder's replica that joins next."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, floor_moderator=c.me)
    await AgentApi(c.daemon).grant_floor(gid, a.me)
    await a.wait(lambda: holder(a, gid) == holder(b, gid) == holder(c, gid) == a.me)
    assert await b.daemon.leave(gid) == "leaving"
    await b.wait(lambda: status(b, gid) == "left")
    await converged([a, c], gid)
    c2 = await cluster.node("c2", identity_of=c)
    await cluster.invite(a, c2, gid)
    leaves = {m["mailbox_id"]: int(m["leaf_index"]) for m in a.daemon.client.members(raw(gid))}
    assert leaves[c2.daemon.mailbox] < leaves[c.daemon.mailbox]
    await c2.wait(lambda: holder(c2, gid) == a.me)
    a2 = await cluster.node("a2", identity_of=a)
    await cluster.invite(a, a2, gid)
    await a2.wait(lambda: holder(a2, gid) == a.me)
    await a2.adapter.wait_for(lambda: bool(grants_seen(a2)), WAIT)
    (copy,) = grants_seen(a2)
    assert copy.sender.instance_id == c2.daemon.instance.instance_id_hex
    await say(c, gid, "r5")
    assert await heard([a, a2], "r5") == {"n0": True, "a2": True}
    await converged([a, c, c2, a2], gid)


async def test_the_named_moderator_joining_gets_the_floor_from_the_owner(
    cluster: Cluster, group: GroupFixture
) -> None:
    """``floor_moderator`` names an identity before it joins: the owner
    moderates until then. When it joins it becomes the effective moderator
    (``reason: moderator``) and the owner sends it the floor."""
    (a, b), gid = await group(2)
    d = await cluster.node("d")
    await moderated([a, b], gid, floor_moderator=d.me)
    a.daemon.grant_floor(gid, b.me, origin="human")
    await a.wait(lambda: holder(a, gid) == holder(b, gid) == b.me)
    await cluster.invite(a, d, gid)
    await d.wait(lambda: holder(d, gid) == b.me)
    for n in (a, b):
        last = data(n, "floor_changed")[-1]
        assert (last["reason"], last["effective_moderator"], last["holder"]) == (
            "moderator",
            d.me,
            b.me,
        )
    assert d.daemon.group_info(gid)["floor"]["effective_moderator"] == d.me
    await converged([a, b, d], gid)


async def test_the_copy_for_newcomers_is_a_daemon_control_at_hop_zero(
    cluster: Cluster, group: GroupFixture
) -> None:
    """The moderator's last trigger was at the loop guard's limit. The copy
    a newcomer gets is the daemon's own control (hop 0, replying to
    nothing), so it trips nobody's loop guard."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, floor_moderator=b.me, max_agent_turns=1)
    await AgentApi(b.daemon).grant_floor(gid, c.me)
    await a.wait(lambda: holder(a, gid) == holder(c, gid) == c.me)
    await say(c, gid, "hop one")
    assert (await heard([b], "hop one"))["n1"] is True
    d = await cluster.node("d")
    await cluster.invite(a, d, gid)
    await d.adapter.wait_for(lambda: bool(grants_seen(d)), WAIT)
    (copy,) = grants_seen(d)
    assert (copy.hop, copy.sender.identity, "reply_to" in copy.inner) == (0, b.me, False)
    await converged([a, b, c, d], gid)
    assert [e for n in (a, c, d) for e in n.adapter.of_type("loop_guard")] == []


async def test_a_counter_out_of_range_is_a_malformed_grant(group: GroupFixture) -> None:
    """A counter SQLite can't hold (2**63) is dropped as malformed when it is
    parsed: nothing is half-recorded, the journal empties, and a restart
    replays nothing."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, floor_moderator=b.me)
    forge(b, gid, c.me, counter=2**63)
    await mark(b, [a, c], gid, "r6")
    await c.idle()
    assert c.daemon.client.journal_pending() == []
    assert holder(c, gid) is None
    audited = [r["reason"] for r in c.daemon.store.audit(gid, 0) if r["kind"] == "control.floor"]
    assert audited == ["malformed"]
    # A copy naming a key out of range is refused the same way.
    forge(b, gid, c.me, counter=1, copy={"epoch": 2**63, "sender": b.me, "instance": "0" * 16})
    await mark(b, [c], gid, "r6b")
    assert holder(c, gid) is None


async def test_an_agents_grants_count_against_its_send_rate(group: GroupFixture) -> None:
    """A grant from the agent is a message the agent sends: past its send
    rate it is refused, while the human's grants are not counted."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, floor_moderator=b.me)
    api = AgentApi(b.daemon)
    for i in range(30):  # the default sender_per_minute
        await api.grant_floor(gid, (a.me, c.me)[i % 2])
    with pytest.raises(DaemonError) as e:
        await api.grant_floor(gid, a.me)
    assert e.value.code == "rate_limited"
    for i in range(40):
        b.daemon.grant_floor(gid, (a.me, c.me)[i % 2], origin="human")


async def test_a_group_without_floor_state_takes_grants(group: GroupFixture) -> None:
    """A member whose database predates floor control has no floor row, or
    a row without the current epoch's facts: it takes them from the group
    when a grant arrives, and agrees with the others."""
    (a, b, c), gid = await group(3)
    await moderated([a, b, c], gid, floor_moderator=b.me)
    c.daemon.store._db.execute("DELETE FROM floor_state WHERE group_id = ?", (gid,))
    row = a.daemon.store.floor(gid)
    assert row is not None
    a.daemon.store.set_floor(gid, row[0], {**row[1], "facts": {}})
    await AgentApi(b.daemon).grant_floor(gid, c.me)
    await a.wait(lambda: holder(a, gid) == holder(b, gid) == holder(c, gid) == c.me)
