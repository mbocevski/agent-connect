"""Roles and the policy on the real relay (docs/groups.md): multi-use
invites, role changes, ownership transfers, policy changes built against
the policy in force, departed roles, commits the policy forbids, invites
closed when their inviter may no longer invite, and the group view."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

import agentconnect_core as ac
from agentconnect.runtime.engine import DaemonError
from agentconnect_harness.cluster import WAIT, Cluster, Node, converged, status
from agentconnect_harness.proxy import Frame, RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Proxy = Callable[[Node], RelayProxy]


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


def policy(node: Node, gid: str) -> dict[str, Any]:
    return dict(json.loads(node.daemon.client.policy(raw(gid))))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def roles(node: Node, gid: str) -> list[tuple[str, str, str]]:
    return sorted((d["identity"], d["from"], d["to"]) for d in data(node, "role_changed"))


# -- multi-use invites (G10) -----------------------------------------------------------------


async def test_three_members_join_by_one_multi_use_invite_and_converge(
    group: GroupFixture,
) -> None:
    (a, b, c), gid = await group(3, invite="multi")
    await converged([a, b, c], gid)
    assert policy(a, gid)["floor"] == "mention"  # the third identity switched it
    (invite,) = a.daemon.store.invites("exhausted")
    assert invite["max_uses"] == 2
    assert len(a.daemon.store.approvals("approved")) == 2


async def test_a_multi_use_invite_needs_one_human_approval_per_join(cluster: Cluster) -> None:
    a = await cluster.node(auto_approve=False)
    gid = a.daemon.create_group("Approvals", "One decision per joiner")
    await a.idle()
    url = (await a.daemon.create_invite(gid, max_uses=2))["url"]
    b, c = await cluster.node(), await cluster.node()
    await b.daemon.accept_invite(url)
    await c.daemon.accept_invite(url)
    await a.wait(lambda: len(a.daemon.join_approvals()) == 2)
    by = {x["identity"]: x["request_id"] for x in a.daemon.join_approvals()}
    a.daemon.approve(by[b.me])
    a.daemon.reject(by[c.me])
    await b.wait(lambda: b.daemon.store.group(gid) is not None)
    await converged([a, b], gid)
    assert a.daemon.join_approvals() == []
    assert c.daemon.store.group(gid) is None
    assert [x["identity"] for x in a.daemon.store.approvals("rejected")] == [c.me]


async def test_a_full_group_keeps_a_join_waiting_for_the_human(cluster: Cluster) -> None:
    """G10: an approval whose Add would pass ``max_members`` is refused
    (``group_full``) and stays pending, even with auto-approve; after a
    removal the human approves it."""
    a = await cluster.node()
    gid = a.daemon.create_group("Small", "Two instances at most", {"max_members": 2})
    await a.idle()
    url = (await a.daemon.create_invite(gid, max_uses=2))["url"]
    b, c = await cluster.node(), await cluster.node()
    await b.daemon.accept_invite(url)
    await b.wait(lambda: b.daemon.store.group(gid) is not None)
    await converged([a, b], gid)
    await c.daemon.accept_invite(url)
    await a.wait(lambda: len(a.daemon.join_approvals()) == 1)
    (waiting,) = a.daemon.join_approvals()
    with pytest.raises(DaemonError) as e:
        a.daemon.approve(waiting["request_id"])
    assert e.value.code == "group_full"
    assert a.daemon.join_approvals() == [waiting]
    a.daemon.remove_member(gid, b.me)
    await b.wait(lambda: status(b, gid) == "removed")
    assert a.daemon.approve(waiting["request_id"]) == {"status": "approving"}
    await c.wait(lambda: c.daemon.store.group(gid) is not None)
    await converged([a, c], gid)


# -- the lifecycle: roles, removal, leave, transfer (G3) --------------------------------------


@pytest.mark.parametrize("size", [3, 5])
async def test_the_lifecycle_converges_after_every_step(group: GroupFixture, size: int) -> None:
    nodes, gid = await group(size, invite="multi")
    a, b = nodes[0], nodes[1]
    removed = nodes[-1]
    staying = nodes[:-1]

    assert a.daemon.set_role(gid, b.me, "admin") == "committing"
    await converged(nodes, gid)
    for n in nodes:
        assert data(n, "role_changed") == [
            {"identity": b.me, "from": "member", "to": "admin", "by": a.me}
        ]
    assert a.daemon.set_role(gid, b.me, "admin") == "unchanged"
    assert a.daemon.set_policy(gid, remove="admins") == "committing"
    await converged(nodes, gid)

    b.daemon.remove_member(gid, removed.me)
    await removed.wait(lambda: status(removed, gid) == "removed")
    await converged(staying, gid)
    assert data(removed, "removed") == [{"by": b.me}]
    for n in staying:
        assert data(n, "member_removed") == [{"identity": removed.me, "by": b.me}]

    if size == 5:
        leaver = nodes[3]
        assert await leaver.daemon.leave(gid) == "leaving"
        await leaver.wait(lambda: status(leaver, gid) == "left")
        staying = nodes[:3]
        await converged(staying, gid)
        for n in staying:
            assert data(n, "member_left") == [{"identity": leaver.me, "by": a.me}]

    new_owner = staying[-1]
    assert a.daemon.transfer_ownership(gid, new_owner.me) == "committing"
    await converged(staying, gid)
    assert policy(a, gid)["owner"] == new_owner.me
    expected = sorted(
        [
            (b.me, "member", "admin"),
            (new_owner.me, "admin" if new_owner is b else "member", "owner"),
            (a.me, "owner", "admin"),
        ]
    )
    for n in staying:
        assert roles(n, gid) == expected

    assert await a.daemon.leave(gid) == "leaving"
    await a.wait(lambda: status(a, gid) == "left")
    rest = staying[1:]
    await converged(rest, gid)
    for n in rest:
        assert data(n, "member_left")[-1]["identity"] == a.me
        assert policy(n, gid)["owner"] == new_owner.me


async def test_the_owners_last_instance_hands_over_then_leaves(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    with pytest.raises(DaemonError) as e:
        await a.daemon.leave(gid)
    assert e.value.code == "forbidden"
    for target, code in ((a.me, "bad_request"), ("ac:v0:nobody", "not_found")):
        with pytest.raises(DaemonError) as e:
            a.daemon.transfer_ownership(gid, target)
        assert e.value.code == code
    with pytest.raises(DaemonError) as e:
        b.daemon.transfer_ownership(gid, c.me)
    assert e.value.code == "not_permitted"
    assert a.daemon.transfer_ownership(gid, c.me, keep_admin=False) == "committing"
    await converged([a, b, c], gid)
    assert policy(b, gid)["owner"] == c.me
    assert policy(b, gid)["admins"] == []
    assert sorted(roles(b, gid)) == sorted([(c.me, "member", "owner"), (a.me, "owner", "member")])
    assert await a.daemon.leave(gid) == "leaving"
    await a.wait(lambda: status(a, gid) == "left")
    await converged([b, c], gid)
    assert data(c, "member_left") == [{"identity": a.me, "by": b.me}]


async def test_a_transfer_unblocks_a_leave_waiting_for_it(
    cluster: Cluster, malicious_relay: Proxy
) -> None:
    """A transfer that dropped the new owner's pending leave left it the
    owner's last instance (``leave_blocked``); handing ownership on lets
    the leave go on."""
    a = await cluster.node()
    gid = a.daemon.create_group("Unblock", "A leave that waits for a transfer")
    await a.idle()
    b, c = await cluster.node(), await cluster.node()
    for joiner in (b, c):
        await cluster.invite(a, joiner, gid)
    for n in (a, c):
        malicious_relay(n).drop_deliveries(lambda env: env.get("kind") == "proposal")
    assert await b.daemon.leave(gid) == "leaving"
    await b.idle()
    assert a.daemon.transfer_ownership(gid, b.me) == "committing"
    await b.wait(lambda: b.daemon.group_info(gid)["leaving"]["blocked"])
    assert [d["reason"] for d in data(b, "leave_blocked")] == ["owner_must_transfer"]
    for n in (a, c):
        malicious_relay(n).server_filters.clear()
    assert b.daemon.transfer_ownership(gid, a.me) == "committing"
    await b.wait(lambda: status(b, gid) == "left")
    await converged([a, c], gid)
    assert policy(c, gid)["owner"] == a.me


async def test_a_transfer_to_a_member_on_its_way_out_is_refused(
    group: GroupFixture, partition: Callable[[Node], Awaitable[None]]
) -> None:
    """The core's dry run counts pending leaves as gone (R2): a transfer to
    a member whose every instance is leaving is refused before it is
    queued, instead of leaving the group with an owner on its way out."""
    (a, b, c), gid = await group(3)
    assert a.daemon.transfer_ownership(gid, b.me) == "committing"
    await converged([a, b, c], gid)
    await partition(a)  # the lowest leaf, which would commit the leave at once
    assert await c.daemon.leave(gid) == "leaving"
    await b.wait(lambda: len(b.daemon.client.pending_leaves(raw(gid))) == 1)
    with pytest.raises(DaemonError) as e:
        b.daemon.transfer_ownership(gid, c.me)
    assert e.value.code == "not_permitted"
    assert b.daemon.store.outbox() == []


# -- what each role may do (G3), and commits the policy forbids --------------------------------


async def test_an_admin_changes_the_floor_only(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    assert a.daemon.set_role(gid, b.me, "admin") == "committing"
    await converged([a, b, c], gid)
    for field, value in (("invite", "members"), ("max_members", 10)):
        with pytest.raises(DaemonError) as e:
            b.daemon.change_policy(gid, {field: value})
        assert e.value.code == "not_permitted"
    with pytest.raises(DaemonError) as e:
        b.daemon.set_role(gid, c.me, "admin")
    assert e.value.code == "not_permitted"
    with pytest.raises(DaemonError) as e:
        c.daemon.change_policy(gid, {"require_verified": True})
    assert e.value.code == "not_permitted"
    assert b.daemon.store.outbox() == []
    assert b.daemon.change_policy(gid, {"floor": "moderated", "floor_moderator": b.me}) == (
        "committing"
    )
    await converged([a, b, c], gid)
    p = policy(c, gid)
    assert (p["floor"], p["floor_pinned"], p["floor_moderator"]) == ("moderated", True, b.me)
    assert data(c, "policy_changed")[-1]["by"] == b.me
    with pytest.raises(DaemonError) as e:
        b.daemon.change_policy(gid, {"owner": b.me})
    assert e.value.code == "bad_request"


@pytest.mark.parametrize("grab", ["owner", "admin", "invite"])
async def test_a_policy_change_beyond_the_committers_role_is_rejected_by_every_member(
    group: GroupFixture, grab: str
) -> None:
    """A member that skips its own core's checks (a modified daemon) commits
    a policy change its role doesn't allow: making itself the owner or an
    admin, or, as an admin, widening who may invite. The honest members
    reject it, stay where they were and say so."""
    (a, b, m), gid = await group(3)
    if grab == "invite":
        assert a.daemon.set_role(gid, m.me, "admin") == "committing"
        await converged([a, b, m], gid)
    before = policy(a, gid)
    epoch, sas = a.epoch(gid), a.sas(gid)
    bad = {
        "owner": {**before, "owner": m.me},
        "admin": {**before, "admins": [m.me]},
        "invite": {**before, "invite": "members"},
    }[grab]
    m.unchecked_commit(gid, policy=canonical(bad), meta=m.daemon.client.meta(raw(gid)))
    for honest in (a, b):
        await honest.wait(lambda h=honest: bool(data(h, "unauthorized_commit")))
        info = honest.daemon.group_info(gid)
        assert (info["epoch"], info["sas"]["decimal"]) == (epoch, sas)
        assert info["out_of_sync_reason"] == "commit_rejected"
        assert policy(honest, gid) == before
        assert data(honest, "role_changed")[len(data(honest, "role_changed")) :] == []
    # The committer alone moved on: its short code shows the fork.
    assert m.daemon.client.sas(raw(gid)).decimal != sas


# -- concurrent changes (G2) -----------------------------------------------------------------


async def test_a_policy_change_rebuilt_after_a_conflict_keeps_the_concurrent_one(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    """The owner's change and an admin's floor change are built in the same
    epoch. The relay takes the owner's; the admin's is rebuilt against the
    policy that commit made, so both survive."""
    (a, b, c), gid = await group(3)
    assert a.daemon.set_role(gid, b.me, "admin") == "committing"
    await converged([a, b, c], gid)
    held: list[Frame] = []
    released: list[bool] = []

    def hold_until_the_conflict(frame: Frame) -> list[Frame]:
        env = frame.get("env") or {}
        if released:
            return [frame]
        if frame.get("t") == "deliver" and env.get("kind") == "commit":
            held.append(frame)
            return []
        if frame.get("t") == "error" and frame.get("code") == "epoch_conflict":
            released.append(True)
            return [frame, *held]
        return [frame]

    malicious_relay(b).server_filters.append(hold_until_the_conflict)
    assert a.daemon.change_policy(gid, {"invite": "members"}) == "committing"
    await until(lambda: bool(held))
    assert b.daemon.change_policy(gid, {"floor": "moderated"}) == "committing"
    await until(lambda: bool(released))
    await converged([a, b, c], gid)
    p = policy(c, gid)
    assert (p["invite"], p["floor"], p["floor_pinned"]) == ("members", "moderated", True)
    assert data(b, "commit_failed") == []
    assert [d["by"] for d in data(c, "policy_changed")][-2:] == [a.me, b.me]


async def test_a_change_the_policy_already_has_fails_quietly(group: GroupFixture) -> None:
    """Two members ask for the same change at once: the second, rebuilt,
    finds nothing to do and tells nobody."""
    (a, b), gid = await group(2)
    assert a.daemon.set_role(gid, b.me, "admin") == "committing"
    await converged([a, b], gid)
    assert a.daemon.change_policy(gid, {"floor": "mention"}) == "committing"
    assert b.daemon.change_policy(gid, {"floor": "mention"}) == "committing"
    await converged([a, b], gid)
    assert policy(a, gid)["floor"] == "mention"
    assert data(a, "commit_failed") == data(b, "commit_failed") == []
    assert a.daemon.change_policy(gid, {"floor": "mention"}) == "unchanged"


async def test_a_change_queued_behind_an_own_commit_is_checked_when_built(
    group: GroupFixture,
) -> None:
    """With an own commit waiting for the relay the dry run can't run (the
    policy was validated first); the change is queued and the core decides
    as it builds it."""
    (a, b), gid = await group(2)
    pending = a.daemon.client.update(raw(gid))
    assert pending["epoch"] == a.epoch(gid)
    with pytest.raises(DaemonError) as e:
        a.daemon.change_policy(gid, {"max_members": 0})
    assert e.value.code == "bad_request"
    assert a.daemon.change_policy(gid, {"invite": "admins"}) == "committing"
    a.daemon.client.discard_pending_commit(raw(gid))
    await converged([a, b], gid)
    assert policy(b, gid)["invite"] == "admins"


async def test_a_dry_run_that_fails_otherwise_is_not_a_refusal(group: GroupFixture) -> None:
    """Only the core's policy kinds are `not_permitted`: another failure is
    an error of its own, and nothing is queued."""
    (a, _b), gid = await group(2)
    real = a.daemon.client

    class Failing:
        def __getattr__(self, name: str) -> Any:
            return getattr(real, name)

        def check_policy_change(self, _gid: bytes, _policy: bytes) -> None:
            raise ac.AgentConnectError("storage error: the disk is gone")

    a.daemon.client = Failing()  # ty: ignore[invalid-assignment]
    try:
        with pytest.raises(ac.AgentConnectError, match="storage error"):
            a.daemon.change_policy(gid, {"invite": "members"})
    finally:
        a.daemon.client = real
    assert a.daemon.store.outbox() == []


# -- departed roles (G11) --------------------------------------------------------------------


@pytest.mark.parametrize("cleanup", [True, False])
async def test_a_departed_admin_loses_the_role(cluster: Cluster, cleanup: bool) -> None:
    a = await cluster.node(groups_cleanup_departed_roles=cleanup)
    gid = a.daemon.create_group("Roles", "Departed admins")
    await a.idle()
    b, c = await cluster.node(), await cluster.node()
    for joiner in (b, c):
        await cluster.invite(a, joiner, gid)
    assert a.daemon.set_role(gid, b.me, "admin") == "committing"
    await converged([a, b, c], gid)
    assert a.daemon.change_policy(gid, {"floor": "moderated", "floor_moderator": b.me}) == (
        "committing"
    )
    await converged([a, b, c], gid)
    assert await b.daemon.leave(gid) == "leaving"
    await b.wait(lambda: status(b, gid) == "left")
    await converged([a, c], gid)
    p = policy(c, gid)
    if not cleanup:
        assert (p["admins"], p["floor_moderator"]) == ([b.me], b.me)
        return
    assert (p["admins"], p["floor_moderator"]) == ([], None)
    assert data(c, "role_changed")[-1] == {
        "identity": b.me,
        "from": "admin",
        "to": "member",
        "by": a.me,
    }
    assert data(c, "policy_changed")[-1]["by"] == a.me
    # Rejoining, it is a plain member.
    back = await cluster.node(identity_of=b)
    await cluster.invite(a, back, gid)
    await converged([a, c, back], gid)
    assert (
        next(m for m in c.daemon.group_info(gid)["members"] if m["identity"] == b.me)["role"]
        == "member"
    )


# -- invites (G3) and the view (G8, G12) -----------------------------------------------------


async def test_an_inviter_that_may_no_longer_invite_closes_its_invites(
    group: GroupFixture,
) -> None:
    (a, b), gid = await group(2)
    assert a.daemon.change_policy(gid, {"invite": "members"}) == "committing"
    await converged([a, b], gid)
    made = await b.daemon.create_invite(gid, max_uses=3)
    assert a.daemon.change_policy(gid, {"invite": "owner"}) == "committing"
    await converged([a, b], gid)
    await b.wait(lambda: b.daemon.store.invite(made["invite_id"])["status"] == "revoked")  # ty: ignore[not-subscriptable]
    assert b.daemon.keystore.get(f"invite/{made['invite_id']}") is None
    meta = await b.daemon.rest.invite_meta(made["invite_id"])
    assert meta["status"] == "revoked"
    # The owner may still invite: its invites stay open.
    mine = await a.daemon.create_invite(gid)
    assert a.daemon.change_policy(gid, {"remove": "admins"}) == "committing"
    await converged([a, b], gid)
    assert a.daemon.store.invite(mine["invite_id"])["status"] == "open"  # ty: ignore[not-subscriptable]


async def test_a_removed_member_closes_its_invites(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    assert a.daemon.change_policy(gid, {"invite": "members"}) == "committing"
    await converged([a, b], gid)
    made = await b.daemon.create_invite(gid)
    a.daemon.remove_member(gid, b.me)
    await b.wait(lambda: status(b, gid) == "removed")
    await b.wait(lambda: b.daemon.store.invite(made["invite_id"])["status"] == "revoked")  # ty: ignore[not-subscriptable]


async def test_the_view_shows_the_policy_the_floor_and_new_instances(cluster: Cluster) -> None:
    """G12 and G8: the policy summary and the floor; each instance's first
    epoch; a new instance of a verified member flagged, the flag kept (SPEC
    11); pending leaves."""
    a = await cluster.node()
    gid = a.daemon.create_group("View", "What the human sees", {"floor": "mention"})
    await a.idle()
    b = await cluster.node()
    await cluster.invite(a, b, gid)
    a.daemon.mark_verified(gid, b.me)
    b2 = await cluster.node(identity_of=b)
    await cluster.invite(a, b2, gid)
    info = a.daemon.group_info(gid)
    assert info["policy_summary"] == {
        "invite": "owner",
        "remove": "owner",
        "max_members": 50,
        "max_agent_turns": 20,
    }
    assert info["floor"] == {"mode": "mention", "pinned": True, "moderator": None}
    bob = next(m for m in info["members"] if m["identity"] == b.me)
    assert bob["verified"] is True
    first = b.daemon.instance.instance_id_hex
    second = b2.daemon.instance.instance_id_hex
    epochs = {i["instance_id"]: i["joined_epoch"] for i in bob["instances"]}
    assert epochs == {first: 1, second: 2}
    assert bob["instances_since_verified"] == [second]
    # The verification is per epoch: verifying again covers the new instance.
    a.daemon.mark_verified(gid, b.me)
    bob = next(m for m in a.daemon.group_info(gid)["members"] if m["identity"] == b.me)
    assert bob["instances_since_verified"] == []
    assert info["pending_leaves"] == []
    me = next(m for m in info["members"] if m["self"])
    assert [i["joined_epoch"] for i in me["instances"]] == [0]
