"""Group membership on the real relay (docs/groups.md): leaves committed by
the right member and reported as leaves, removals with who made them, a
dead replica's removal, leaves that end without a commit, and the update
cadence's threshold."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.runtime.engine import DaemonError
from agentconnect.runtime.groups import LEAVE_COMMIT_GRACE_SECS, update_threshold
from agentconnect.store import OutboxRow
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


def instance_of(node: Node) -> str:
    return node.daemon.instance.instance_id_hex


def is_proposal(frame: Frame) -> bool:
    return bool(frame.get("t") == "deliver" and (frame.get("env") or {}).get("kind") == "proposal")


async def build(cluster: Cluster, n: int, **overrides: Any) -> tuple[list[Node], str]:
    """``n`` distinct members; ``overrides`` go to every node's config."""
    first = await cluster.node(**overrides)
    gid = first.daemon.create_group("Membership", "Exercise leaves and removals")
    await first.idle()
    nodes = [first]
    for _ in range(n - 1):
        joiner = await cluster.node(**overrides)
        await cluster.invite(first, joiner, gid)
        nodes.append(joiner)
    return nodes, gid


@pytest.mark.parametrize("size", [3, 5])
async def test_leaves_and_removals_converge_and_say_who(group: GroupFixture, size: int) -> None:
    nodes, gid = await group(size)
    a, leaver, removed = nodes[0], nodes[-2], nodes[-1]
    staying = [n for n in nodes if n not in (leaver, removed)]

    assert await leaver.daemon.leave(gid) == "leaving"
    assert await leaver.daemon.leave(gid) == "leaving"  # asked twice: one notice
    assert leaver.daemon.group_info(gid)["leaving"]["blocked"] is False
    await leaver.wait(lambda: status(leaver, gid) == "left")
    await converged([*staying, removed], gid)
    for n in [*staying, removed]:
        assert data(n, "member_leaving") == [
            {"identity": leaver.me, "instance_id": instance_of(leaver)}
        ]
        # The lowest leaf not leaving (the creator's) committed it.
        assert data(n, "member_left") == [{"identity": leaver.me, "by": a.me}]
        assert data(n, "member_removed") == []
        # The notice came first, as context only.
        (notice,) = [d for d in n.adapter.deliveries if d.kind == "control.leave"]
        assert not notice.addressed_to_me
        assert notice.sender.identity == leaver.me
    assert data(leaver, "left") == [{"confirmed": True, "by": a.me}]
    assert leaver.daemon.group_info(gid)["leaving"] is None

    a.daemon.remove_member(gid, removed.me)
    await removed.wait(lambda: status(removed, gid) == "removed")
    await converged(staying, gid)
    assert data(removed, "removed") == [{"by": a.me}]
    for n in staying:
        assert data(n, "member_removed") == [{"identity": removed.me, "by": a.me}]
    assert len(a.daemon.client.members(raw(gid))) == size - 2


async def test_another_instance_of_the_leavers_identity_commits_its_leave(
    group: GroupFixture,
) -> None:
    """The committer is the lowest leaf not leaving, whoever's it is: here the
    only other leaf is the leaver's own identity's."""
    (a, a2), gid = await group(2, "replicas")
    assert await a2.daemon.leave(gid) == "leaving"
    await a2.wait(lambda: status(a2, gid) == "left")
    await a.wait(lambda: len(a.daemon.client.members(raw(gid))) == 1)
    assert data(a, "instance_left") == [
        {"identity": a.me, "instance_id": instance_of(a2), "by": a.me}
    ]


async def test_the_next_member_commits_a_leave_after_the_grace_period(
    group: GroupFixture, advance: Advance, partition: Cut, heal: Cut
) -> None:
    (a, b, c), gid = await group(3)
    await partition(a)  # the member that would commit it
    await c.daemon.leave(gid)
    await b.wait(lambda: len(b.daemon.client.pending_leaves(raw(gid))) == 1)
    await b.idle()
    assert status(c, gid) == "active"
    await advance(LEAVE_COMMIT_GRACE_SECS)
    await c.wait(lambda: status(c, gid) == "left")
    await heal(a)
    await converged([a, b], gid)
    for n in (a, b):
        assert data(n, "member_left") == [{"identity": c.me, "by": b.me}]


async def test_owner_instances_leaving_at_once_keep_one_whose_leave_waits_for_a_transfer(
    cluster: Cluster, advance: Advance, malicious_relay: Proxy
) -> None:
    a = await cluster.node("owner", groups_leave_timeout_secs=LEAVE_TIMEOUT)
    gid = a.daemon.create_group("Owners", "Two owner instances leave at once")
    await a.idle()
    # Leaves 0 and 1 are the owner's, 2 the member's: whichever proposal
    # reaches the member first, it isn't the one to commit.
    a2 = await cluster.node("replica", identity_of=a, groups_leave_timeout_secs=LEAVE_TIMEOUT)
    await cluster.invite(a, a2, gid)
    b = await cluster.node("member")
    await cluster.invite(a, b, gid)

    # Each owner instance proposes before it sees the other's proposal.
    sent: set[str] = set()
    held: dict[str, list[Frame]] = {"owner": [], "replica": []}
    for node in (a, a2):

        def watch(frame: Frame, name: str = node.name) -> list[Frame]:
            if frame.get("t") == "send" and (frame.get("env") or {}).get("kind") == "proposal":
                sent.add(name)
            return [frame]

        def hold(frame: Frame, name: str = node.name) -> list[Frame]:
            if is_proposal(frame) and len(sent) < 2:
                held[name].append(frame)
                return []
            return [frame]

        malicious_relay(node).client_filters.append(watch)
        malicious_relay(node).server_filters.append(hold)
    assert await a.daemon.leave(gid) == "leaving"
    assert await a2.daemon.leave(gid) == "leaving"
    await until(lambda: len(sent) == 2)
    for node in (a, a2):
        for frame in held[node.name]:
            await malicious_relay(node).inject(frame)

    # Every member stored both leaves, so the commit leaves out the leave of
    # the owner instance with the lowest leaf (SPEC 9.2). That instance's
    # leave ended without a commit, and it can tell.
    stays, went = a, a2
    await went.wait(lambda: status(went, gid) == "left")
    assert data(went, "left") == [{"confirmed": True, "by": a.me}]
    await converged([stays, b], gid)
    for n in (stays, b):
        assert data(n, "instance_left") == [
            {"identity": a.me, "instance_id": instance_of(went), "by": a.me}
        ]
    await stays.wait(lambda: bool(data(stays, "leave_blocked")))
    (blocked,) = data(stays, "leave_blocked")
    assert (blocked["reason"], blocked["timed_out"]) == ("owner_must_transfer", False)
    assert stays.daemon.group_info(gid)["leaving"]["blocked"] is True
    with pytest.raises(DaemonError, match="transfer ownership"):
        await stays.daemon.leave(gid)

    # The timeout never deletes the owner's last instance's state.
    await advance(LEAVE_TIMEOUT)
    await stays.wait(lambda: len(data(stays, "leave_blocked")) == 2)
    assert data(stays, "leave_blocked")[1]["timed_out"] is True
    assert status(stays, gid) == "active"
    assert data(stays, "left") == []

    # Once ownership moved, the leave goes on.
    stays.daemon.set_policy(gid, owner=b.me, admins=[])
    await stays.wait(lambda: status(stays, gid) == "left")
    assert data(stays, "left") == [{"confirmed": True, "by": b.me}]
    await b.wait(lambda: data(b, "member_left") == [{"identity": a.me, "by": b.me}])
    assert {(r["identity"], r["from"], r["to"]) for r in data(b, "role_changed")} == {
        (a.me, "owner", "member"),
        (b.me, "member", "owner"),
    }


async def test_a_transfer_that_drops_the_new_owners_leave_blocks_it(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b, c), gid = await group(3)
    # The owner never sees b's proposal; c stores it and waits its turn.
    malicious_relay(a).drop_deliveries(lambda env: env.get("kind") == "proposal")
    await b.daemon.leave(gid)
    await c.wait(lambda: len(c.daemon.client.pending_leaves(raw(gid))) == 1)
    a.daemon.set_policy(gid, owner=b.me, admins=[])
    await b.wait(lambda: bool(data(b, "leave_blocked")))
    await converged([a, b, c], gid)
    assert b.daemon.group_info(gid)["leaving"]["blocked"] is True
    assert c.daemon.client.pending_leaves(raw(gid)) == []
    for n in (a, b, c):
        roles = {(r["identity"], r["from"], r["to"], r["by"]) for r in data(n, "role_changed")}
        assert roles == {(a.me, "owner", "member", a.me), (b.me, "member", "owner", a.me)}
        changed = data(n, "policy_changed")[-1]
        assert changed["roles_known"] is True
        assert changed["previous_policy"]["owner"] == a.me
        assert changed["policy"]["owner"] == b.me


async def test_a_leave_nobody_commits_ends_locally_after_the_timeout(
    cluster: Cluster, advance: Advance, malicious_relay: Proxy
) -> None:
    (a, b, c), gid = await build(cluster, 3, groups_leave_timeout_secs=LEAVE_TIMEOUT)
    for n in (a, b):
        malicious_relay(n).drop_deliveries(lambda env: env.get("kind") == "proposal")
    await c.daemon.leave(gid)
    await c.idle()
    await advance(LEAVE_TIMEOUT - 1)
    assert status(c, gid) == "active"
    await advance(1)
    await c.wait(lambda: status(c, gid) == "left")
    assert data(c, "left") == [{"confirmed": False}]
    # The others never saw the leave: c's leaf stays until someone removes it.
    assert len(a.daemon.client.members(raw(gid))) == 3


async def test_a_dead_replica_is_removed_by_its_own_identity(
    cluster: Cluster, group: GroupFixture
) -> None:
    (a, b, c), gid = await group(3)
    b2 = await cluster.node("b2", identity_of=b)
    await cluster.invite(a, b2, gid)
    for n in (a, b, c):
        assert data(n, "instance_joined") == [
            {"identity": b.me, "instance_id": instance_of(b2), "by": a.me}
        ]
        assert [d["identity"] for d in data(n, "member_joined")].count(b.me) <= 1
    info_b = next(m for m in b.daemon.group_info(gid)["members"] if m["identity"] == b.me)
    assert {i["instance_id"]: i["self"] for i in info_b["instances"]} == {
        instance_of(b): True,
        instance_of(b2): False,
    }

    with pytest.raises(DaemonError, match="leave instead"):
        b.daemon.remove_instances(gid, b.me, [instance_of(b)])
    with pytest.raises(DaemonError, match="no such instance"):
        b.daemon.remove_instances(gid, b.me, [instance_of(a)])
    with pytest.raises(DaemonError, match="16 hex"):
        b.daemon.remove_instances(gid, b.me, ["B2"])
    with pytest.raises(DaemonError, match="no such member"):
        b.daemon.remove_instances(gid, "ac:v0:nobody", [instance_of(b2)])
    # A plain member may not remove another identity's instance: the core refuses.
    c.daemon.remove_instances(gid, b.me, [instance_of(b2)])
    await c.wait(lambda: bool(data(c, "commit_failed")))
    assert data(c, "commit_failed")[0]["intent"] == "remove_instances"

    await b2.stop()  # the replica died
    b.daemon.remove_instances(gid, b.me, [instance_of(b2)])
    await converged([a, b, c], gid)
    for n in (a, b, c):
        assert data(n, "instance_removed") == [
            {"identity": b.me, "instance_id": instance_of(b2), "by": b.me}
        ]
        assert data(n, "member_removed") == []
    assert [m["instance_id_hex"] for m in a.daemon.client.members(raw(gid))].count(
        instance_of(b2)
    ) == 0


async def test_the_update_threshold_is_drawn_per_instance_and_epoch(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    epoch = a.epoch(gid)
    threshold = update_threshold(gid, epoch, instance_of(a))
    assert 900 <= threshold <= 1000
    a.daemon.store.update_group(gid, msgs_since_commit=threshold - 1)
    a.daemon.send_message(gid, {"text": "below"})
    assert await b.wait_texts(gid, 1) == ["below"]
    assert a.epoch(gid) == epoch
    a.daemon.send_message(gid, {"text": "at it"})
    await b.wait_texts(gid, 2)
    assert a.epoch(gid) == epoch + 1


async def test_a_queued_proposal_that_can_no_longer_go_out_is_dropped(
    cluster: Cluster, group: GroupFixture
) -> None:
    (a, b), gid = await group(2)
    group_a, group_b = a.daemon.store.group(gid), b.daemon.store.group(gid)
    assert group_a is not None
    assert group_b is not None
    row = OutboxRow(0, "proposal", gid, {}, "queued")
    # The leave ended meanwhile.
    assert await b.daemon.groups.run_proposal(row, group_b) == "failed"
    # The owner's last instance: the leave waits for a transfer.
    a.daemon.store.kv_set(f"leaving/{gid}", "1")
    assert await a.daemon.groups.run_proposal(row, group_a) == "failed"
    await a.wait(lambda: bool(data(a, "leave_blocked")))
    assert [d["reason"] for d in data(a, "leave_blocked")] == ["owner_must_transfer"]
    # The core refuses for another reason (a commit of its own is pending).
    b.daemon.store.kv_set(f"leaving/{gid}", "1")
    b.daemon.client.update(raw(gid))
    assert await b.daemon.groups.run_proposal(row, group_b) == "failed"
    assert data(b, "leave_blocked") == []
    b.daemon.client.discard_pending_commit(raw(gid))
    # A leave recorded before its start time was kept starts its timeout on restart.
    b.daemon.store.kv_set(f"leaving_since/{gid}", "")
    await b.restart()
    since = b.daemon.groups.leave_state(gid)
    assert since is not None
    assert since["since"] == b.daemon.now()

    # The timer skips a group whose MLS state is gone, and goes on.
    solo = await cluster.node("solo")
    sgid = solo.daemon.create_group("Solo", "")
    await solo.idle()
    solo.daemon.client.delete_group(raw(sgid))
    assert await solo.daemon.groups.step() is None
