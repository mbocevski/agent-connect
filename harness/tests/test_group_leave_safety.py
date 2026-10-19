"""Leaves under a stale view, an out-of-sync group, racing commits and
removals (docs/groups.md): the leave timeout never deletes the owner's only
instance, acts only once the runtime has caught up with the relay, and every
member, the leaver included, reports what the commit says."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Awaitable, Callable
from typing import Any

from agentconnect.runtime.engine import MAX_TRANSIENT_RETRIES
from agentconnect.runtime.groups import LEAVE_COMMIT_GRACE_SECS, update_threshold
from agentconnect_harness.cluster import WAIT, Cluster, Node, converged, status
from agentconnect_harness.proxy import Frame, RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]
Cut = Callable[[Node], Awaitable[None]]
Proxy = Callable[[Node], RelayProxy]

LEAVE_TIMEOUT = 3600  # the lowest groups.leave_timeout_secs


async def until(predicate: Callable[[], bool]) -> None:
    """Poll what no runtime announces (a proxy filter's record), yielding
    to the loop: a node's wait wakes only on the runtimes' change pulses."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing to wait on
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


def raw(gid: str) -> bytes:
    return base64.urlsafe_b64decode(gid + "=" * (-len(gid) % 4))


def data(node: Node, kind: str) -> list[dict[str, Any]]:
    return [e.data for e in node.adapter.unique_events() if e.type == kind]


def owner(node: Node, gid: str) -> str:
    return str(json.loads(node.daemon.client.policy(raw(gid)))["owner"])


def instance_of(node: Node) -> str:
    return node.daemon.instance.instance_id_hex


def proposal(env: dict[str, Any]) -> bool:
    return bool(env.get("kind") == "proposal")


def hold_first_proposal(held: list[Frame]) -> Callable[[Frame], list[Frame]]:
    def hold(frame: Frame) -> list[Frame]:
        env = frame.get("env") or {}
        if frame.get("t") == "deliver" and proposal(env) and not held:
            held.append(frame)
            return []
        return [frame]

    return hold


async def build(cluster: Cluster, n: int, **overrides: Any) -> tuple[list[Node], str]:
    first = await cluster.node(**overrides)
    gid = first.daemon.create_group("Leaves", "Leaves under a stale view")
    await first.idle()
    nodes = [first]
    for _ in range(n - 1):
        joiner = await cluster.node(**overrides)
        await cluster.invite(first, joiner, gid)
        nodes.append(joiner)
    return nodes, gid


async def test_an_offline_leaver_handed_ownership_keeps_its_state(
    cluster: Cluster, advance: Advance, malicious_relay: Proxy, partition: Cut, heal: Cut
) -> None:
    """Its laptop sleeps through the leave timeout while the owner hands it
    the group: it wakes up past the deadline, catches up, finds itself the
    owner, and keeps its state."""
    (a, b, c), gid = await build(cluster, 3, groups_leave_timeout_secs=LEAVE_TIMEOUT)
    for n in (a, c):  # nobody stores b's leave, so the owner may hand b the group
        malicious_relay(n).drop_deliveries(proposal)
    assert await b.daemon.leave(gid) == "leaving"
    await b.idle()
    await partition(b)
    a.daemon.set_policy(gid, owner=b.me, admins=[])
    await c.wait(lambda: owner(c, gid) == b.me)
    await advance(LEAVE_TIMEOUT + 60)  # past the deadline, still asleep
    assert status(b, gid) == "active"
    await heal(b)
    await b.wait(lambda: owner(b, gid) == b.me)
    await b.wait(lambda: any(d["timed_out"] for d in data(b, "leave_blocked")))
    assert status(b, gid) == "active"
    assert data(b, "left") == []
    await converged([a, b, c], gid)


async def test_an_offline_kept_owner_instance_never_times_out(
    cluster: Cluster, advance: Advance, malicious_relay: Proxy, partition: Cut, heal: Cut
) -> None:
    """The lowest owner instance leaves and sleeps; its sibling's leave is
    committed meanwhile, so it is the owner's only instance. It never saw
    that, but as an instance of the owner its leave never times out."""
    a1 = await cluster.node("owner", groups_leave_timeout_secs=LEAVE_TIMEOUT)
    gid = a1.daemon.create_group("Owners", "Kept owner instance offline")
    await a1.idle()
    a2 = await cluster.node("replica", identity_of=a1, groups_leave_timeout_secs=LEAVE_TIMEOUT)
    await cluster.invite(a1, a2, gid)
    b = await cluster.node("member", groups_leave_timeout_secs=LEAVE_TIMEOUT)
    await cluster.invite(a1, b, gid)
    held: list[Frame] = []
    malicious_relay(a2).drop_deliveries(proposal)  # a2 never sees a1's leave
    malicious_relay(b).server_filters.append(hold_first_proposal(held))
    assert await a1.daemon.leave(gid) == "leaving"
    await a1.idle()
    await until(lambda: bool(held))
    await partition(a1)
    assert await a2.daemon.leave(gid) == "leaving"
    await b.wait(lambda: len(b.daemon.client.pending_leaves(raw(gid))) == 1)
    await malicious_relay(b).inject(held[0])
    await b.idle()
    pending = [m["instance_id_hex"] for m in b.daemon.client.pending_leaves(raw(gid))]
    assert pending == [instance_of(a2)]  # b stored both and keeps a1
    await advance(LEAVE_COMMIT_GRACE_SECS)
    await a2.wait(lambda: status(a2, gid) == "left")
    await advance(LEAVE_TIMEOUT)
    await a1.wait(lambda: any(d["timed_out"] for d in data(a1, "leave_blocked")))
    assert status(a1, gid) == "active"
    await heal(a1)
    await converged([a1, b], gid)
    assert data(a1, "left") == []
    assert a1.daemon.group_info(gid)["leaving"]["blocked"] is True


async def test_a_sleeping_leaver_times_out_only_once_it_caught_up(
    cluster: Cluster, advance: Advance, malicious_relay: Proxy, partition: Cut, heal: Cut
) -> None:
    (a, b, c), gid = await build(cluster, 3, groups_leave_timeout_secs=LEAVE_TIMEOUT)
    for n in (a, b):
        malicious_relay(n).drop_deliveries(proposal)
    await c.daemon.leave(gid)
    await c.idle()
    await partition(c)
    await advance(LEAVE_TIMEOUT + 60)
    assert status(c, gid) == "active"  # offline: its view may be stale
    await heal(c)
    await c.wait(lambda: status(c, gid) == "left")
    assert data(c, "left") == [{"confirmed": False}]


async def test_an_out_of_sync_group_does_not_retry_a_leave_commit(
    group: GroupFixture, advance: Advance, malicious_relay: Proxy
) -> None:
    (a, b, c), gid = await group(3)
    malicious_relay(b).drop_deliveries(proposal)
    await a.daemon.mark_out_of_sync(gid, "commit_rejected")
    await c.daemon.leave(gid)
    await a.wait(lambda: len(a.daemon.client.pending_leaves(raw(gid))) == 1)
    await a.idle()
    for _ in range(5):
        await advance(LEAVE_COMMIT_GRACE_SECS)
        await a.idle()
    assert data(a, "commit_failed") == []
    assert not [r for r in a.daemon.store.outbox("failed") if r.kind == "commit"]


async def test_a_leave_proposes_once_when_an_update_comes_first(group: GroupFixture) -> None:
    """The notice runs the cadence update first: its commit doesn't queue a
    second proposal, so every member reports the leave once."""
    (a, b, c), gid = await group(3)
    threshold = update_threshold(gid, c.epoch(gid), instance_of(c))
    c.daemon.store.update_group(gid, msgs_since_commit=threshold)
    await c.daemon.leave(gid)
    await c.wait(lambda: status(c, gid) == "left")
    await converged([a, b], gid)
    assert len([r for r in c.daemon.store.outbox("done") if r.kind == "proposal"]) == 1
    for n in (a, b):
        assert len(data(n, "member_leaving")) == 1


async def test_a_leave_proposes_once_when_a_commit_lands_first(
    group: GroupFixture, advance: Advance, malicious_relay: Proxy
) -> None:
    (a, b, c), gid = await group(3)
    # The notice can't go out yet, so the proposal row waits behind it.
    malicious_relay(c).fail_next("send", "rate_limited", kind="application")
    await c.daemon.leave(gid)
    await c.wait(lambda: c.clock.sleepers > 0)
    epoch = c.epoch(gid)
    a.daemon.update(gid)
    await c.wait(lambda: c.epoch(gid) == epoch + 1)
    await advance(1)
    await c.wait(lambda: status(c, gid) == "left")
    await converged([a, b], gid)
    assert len([r for r in c.daemon.store.outbox("done") if r.kind == "proposal"]) == 1
    for n in (a, b):
        assert len(data(n, "member_leaving")) == 1


async def test_a_removal_racing_a_leave_is_a_removal_for_the_leaver_too(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b, c), gid = await group(3)
    for n in (a, b):
        malicious_relay(n).drop_deliveries(proposal)
    await c.daemon.leave(gid)
    await c.idle()
    a.daemon.remove_member(gid, c.me)
    await c.wait(lambda: status(c, gid) == "removed")
    assert data(c, "removed") == [{"by": a.me}]
    assert data(c, "left") == []
    await b.wait(lambda: bool(data(b, "member_removed")))
    assert data(b, "member_left") == []


async def test_a_removal_journalled_by_an_older_daemon_falls_back_to_the_leave(
    group: GroupFixture,
) -> None:
    """A summary replayed from a journal entry an older daemon wrote may
    predate the core's `left`: a leaving instance then reports a leave."""
    (a, b), gid = await group(2)
    b.daemon.store.kv_set(f"leaving/{gid}", "1")
    summary = {"committer": {"identity": a.me}, "removed": [], "left": []}
    await b.daemon.groups.on_removed(gid, summary, legacy=True)
    assert data(b, "left") == [{"confirmed": True, "by": a.me}]


async def test_a_leaver_is_never_the_one_to_commit_leaves(
    cluster: Cluster, advance: Advance, malicious_relay: Proxy
) -> None:
    """The lowest leaf has just asked to leave when another member's leave
    arrives: it doesn't build a commit the core would refuse."""
    a = await cluster.node("owner")
    gid = a.daemon.create_group("Leaves", "The lowest leaf leaves")
    await a.idle()
    a2 = await cluster.node("replica", identity_of=a)
    await cluster.invite(a, a2, gid)
    c = await cluster.node("member")
    await cluster.invite(a, c, gid)
    held: list[Frame] = []
    malicious_relay(a).server_filters.append(hold_first_proposal(held))
    await c.daemon.leave(gid)
    await until(lambda: bool(held))
    await a.daemon.leave(gid)
    await malicious_relay(a).inject(held[0])
    await a.idle()
    await advance(LEAVE_COMMIT_GRACE_SECS)
    await a.wait(lambda: status(a, gid) == "left" and status(c, gid) == "left")
    assert data(a, "commit_failed") == []
    assert {"identity": c.me, "by": a.me} in data(a2, "member_left")


async def until_owner(node: Node, gid: str, advance: Advance) -> None:
    """Drive the retries and the reconnect on the fake clock, one pause at
    a time, until the redelivered commit makes ``node`` the owner; the group
    stays active all along."""
    for _ in range(40):
        await node.wait(lambda: owner(node, gid) == node.me or node.clock.sleepers > 0)
        if owner(node, gid) == node.me:
            return
        assert status(node, gid) == "active"
        await advance(300)
    raise AssertionError("the commit was never redelivered")


def give_up_next_frame(node: Node) -> None:
    """Arm the next received frame to fail transiently until the inbound
    worker gives it up (unacked), and drive its retries."""
    node.daemon.failpoints.arm("receive.before_core", "raise", times=MAX_TRANSIENT_RETRIES)


async def test_a_frame_given_up_in_the_drain_is_not_caught_up(
    cluster: Cluster, advance: Advance, malicious_relay: Proxy, partition: Cut, heal: Cut
) -> None:
    """The transfer commit reaches the sleeping leaver in its reconnect
    drain, but processing it fails until the inbound worker gives it up: the
    leaver hasn't caught up, so it doesn't time out, and once the commit is
    redelivered it finds itself the owner."""
    (a, b, c), gid = await build(cluster, 3, groups_leave_timeout_secs=LEAVE_TIMEOUT)
    for n in (a, c):
        malicious_relay(n).drop_deliveries(proposal)
    assert await b.daemon.leave(gid) == "leaving"
    await b.idle()
    await partition(b)
    a.daemon.set_policy(gid, owner=b.me, admins=[])
    await a.wait(lambda: owner(a, gid) == b.me)
    await advance(LEAVE_TIMEOUT + 60)
    give_up_next_frame(b)
    await heal(b)
    await until_owner(b, gid, advance)
    await b.wait(lambda: any(d["timed_out"] for d in data(b, "leave_blocked")))
    assert data(b, "processing_failed")
    assert status(b, gid) == "active"
    assert data(b, "left") == []


async def test_a_live_frame_given_up_after_catching_up_is_not_caught_up(
    cluster: Cluster, advance: Advance, malicious_relay: Proxy
) -> None:
    """Caught up, the leaver fails to process the live commit that hands it
    the group: its view misses it again, so the deadline deletes nothing."""
    (a, b, c), gid = await build(cluster, 3, groups_leave_timeout_secs=LEAVE_TIMEOUT)
    for n in (a, c):
        malicious_relay(n).drop_deliveries(proposal)
    assert await b.daemon.leave(gid) == "leaving"
    await b.idle()
    assert b.daemon.caught_up()
    give_up_next_frame(b)
    a.daemon.set_policy(gid, owner=b.me, admins=[])
    await a.wait(lambda: owner(a, gid) == b.me)
    await until(lambda: "receive.before_core" in b.daemon.failpoints.fired)
    await until_owner(b, gid, advance)
    await advance(LEAVE_TIMEOUT)
    await b.wait(lambda: any(d["timed_out"] for d in data(b, "leave_blocked")))
    assert data(b, "processing_failed")
    assert status(b, gid) == "active"
    assert data(b, "left") == []


async def test_a_commit_during_the_proposal_send_still_ends_the_leave(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    """A commit lands while the leave proposal waits for the relay's
    `accepted`: that proposal is for the epoch that ended, so the leaver
    proposes again in the new one, and the leave completes with no other
    commit and no timeout."""
    (a, b, c), gid = await group(3)
    dropped = {"a": 0, "b": 0}
    for name, n in (("a", a), ("b", b)):

        def drop_first(frame: Frame, name: str = name) -> list[Frame]:
            env = frame.get("env") or {}
            if frame.get("t") == "deliver" and proposal(env) and not dropped[name]:
                dropped[name] += 1  # it arrives after the commit: stale
                return []
            return [frame]

        malicious_relay(n).server_filters.append(drop_first)
    sent: list[str] = []
    held: list[Frame] = []

    def watch(frame: Frame) -> list[Frame]:
        env = frame.get("env") or {}
        if frame.get("t") == "send" and proposal(env):
            sent.append(str(env["msg_id"]))
        return [frame]

    def hold_accept(frame: Frame) -> list[Frame]:
        if frame.get("t") == "accepted" and frame.get("msg_id") in sent and not held:
            held.append(frame)
            return []
        return [frame]

    malicious_relay(c).client_filters.append(watch)
    malicious_relay(c).server_filters.append(hold_accept)
    await c.daemon.leave(gid)
    await until(lambda: bool(held))
    epoch = c.epoch(gid)
    b.daemon.update(gid)
    await c.wait(lambda: c.epoch(gid) == epoch + 1)
    await malicious_relay(c).inject(held[0])
    await c.wait(lambda: status(c, gid) == "left")
    await converged([a, b], gid)
    assert len(sent) == 2  # one proposal per epoch
    for n in (a, b):
        assert data(n, "member_left") == [{"identity": c.me, "by": a.me}]
        assert len(data(n, "member_leaving")) == 1  # the first one was dropped
