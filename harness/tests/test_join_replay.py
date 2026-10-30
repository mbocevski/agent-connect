"""SPEC §6.2 "Replays": the inviter remembers every JoinRequest that passed
its checks, by request id and KeyPackageRef, whatever became of it (decided,
lapsed or dropped), until its invite expires plus the ledger's grace. A
malicious relay that re-delivers the envelope under a fresh ``msg_id`` gets
nothing: no new approval, no event, nothing sent to the joiner, and one
audit row with the reason code. Under the same ``msg_id`` from another
sender (past the inbox's deduplication) it is dropped earlier, by the
sender check (SPEC 6.2 step 3). The
ledger is persisted, bounded and purged on the current clock. On both hosts.
"""

from __future__ import annotations

import json
import random
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

import agentconnect_core as ac
from agentconnect.relay import b64
from agentconnect.runtime.engine import APPROVAL_TIMEOUT_SECS, DaemonError
from agentconnect_harness.cluster import Cluster, Node
from agentconnect_harness.proxy import RelayProxy

Advance = Callable[[float], Awaitable[None]]
Proxy = Callable[[Node], RelayProxy]
Frame = dict[str, Any]


async def requested(
    cluster: Cluster, *, ttl_secs: int = 86_400, max_uses: int = 3, joiners: int = 1
) -> tuple[Node, list[Node], str, dict[str, Any]]:
    """An inviter whose human approves, and ``joiners`` pending requests."""
    a = await cluster.node("a", auto_approve=False)
    gid = a.daemon.create_group("Replay", "")
    await a.idle()
    invite = await a.daemon.create_invite(gid, ttl_secs=ttl_secs, max_uses=max_uses)
    nodes = []
    for i in range(joiners):
        joiner = await cluster.node(f"j{i}")
        await joiner.daemon.accept_invite(invite["url"])
        await a.wait(lambda n=i + 1: len(a.daemon.join_approvals()) == n)
        nodes.append(joiner)
    return a, nodes, gid, invite


def frame_of(proxy: RelayProxy, joiner: Node) -> Frame:
    return next(
        f
        for f in reversed(proxy.delivered)
        if f["env"].get("kind") == "join_request" and f["env"]["sender"] == joiner.daemon.mailbox
    )


async def redeliver(
    a: Node, frame: Frame, rng: random.Random, *, same_msg_id: bool = False
) -> dict[str, Any]:
    """The relay delivers the envelope again: under a fresh ``msg_id``, or
    under the same one from another sender (past the inbox's deduplication)."""
    again = json.loads(json.dumps(frame))
    if same_msg_id:
        again["env"]["sender"] = b64(rng.randbytes(16))
    else:
        again["env"]["msg_id"] = b64(rng.randbytes(16))
    env = again["env"]
    await a.proxy.inject(again)
    await a.wait(lambda: a.daemon.store.inbox_state(env["sender"], env["msg_id"]) is not None)
    return dict(env)


def join_audit(a: Node) -> list[str]:
    return [r["reason"] for r in a.daemon.store.audit(limit=1000) if r["kind"] == "join_request"]


def pending_events(a: Node) -> int:
    return len([e for e in a.daemon.store.events(limit=10_000) if e["type"] == "pending_approval"])


def assert_silent(a: Node, joiners: list[Node], approvals: int) -> None:
    """No new approval, no event for the agent, nothing to the joiners."""
    assert pending_events(a) == approvals
    assert len(a.adapter.of_type("pending_approval")) == approvals
    assert not a.daemon.store.outbox()
    for j in joiners:
        assert not [f for f in j.proxy.delivered if f["env"]["sender"] == a.daemon.mailbox]


async def test_a_rejected_request_replayed_is_dropped_silently(
    cluster: Cluster, malicious_relay: Proxy, rng: random.Random
) -> None:
    a, (b,), _gid, _invite = await requested(cluster)
    frame = frame_of(malicious_relay(a), b)
    (request,) = a.daemon.join_approvals()
    a.daemon.reject(request["request_id"])
    await redeliver(a, frame, rng)
    await redeliver(a, frame, rng, same_msg_id=True)
    assert a.daemon.join_approvals() == []
    assert (a.daemon.store.approval(request["request_id"]) or {})["status"] == "rejected"
    assert join_audit(a) == ["join_replay"]
    assert_silent(a, [b], approvals=1)
    with pytest.raises(DaemonError):
        a.daemon.approve(request["request_id"])


async def test_a_lapsed_request_replayed_is_dropped(
    cluster: Cluster, malicious_relay: Proxy, advance: Advance, rng: random.Random
) -> None:
    a, (b,), _gid, _invite = await requested(cluster)
    frame = frame_of(malicious_relay(a), b)
    await advance(APPROVAL_TIMEOUT_SECS + 1)
    assert a.daemon.join_approvals() == []  # lapsed
    await redeliver(a, frame, rng)
    assert a.daemon.join_approvals() == []
    assert join_audit(a) == ["join_replay"]
    assert_silent(a, [b], approvals=1)


async def test_a_request_refused_by_the_use_limit_replayed_is_dropped(
    cluster: Cluster, malicious_relay: Proxy, rng: random.Random
) -> None:
    """A single-use invite: the human approves b, and c is refused by the
    limit without a human decision. b's Add then fails, which frees the
    use, so c's request passes the invite check again; it is still a replay."""
    a, (b, c), gid, invite = await requested(cluster, max_uses=1, joiners=2)
    proxy = malicious_relay(a)
    first, second = a.daemon.join_approvals()
    proxy.fail_next("send", "quota_exceeded", kind="commit")
    a.daemon.approve(first["request_id"])
    with pytest.raises(DaemonError, match="no uses left"):
        a.daemon.approve(second["request_id"])
    await a.idle()
    assert (a.daemon.store.approval(first["request_id"]) or {})["status"] == "failed"
    assert a.daemon.store.uses_taken(invite["invite_id"]) == 0
    for joiner in (b, c):
        await redeliver(a, frame_of(proxy, joiner), rng)
    assert a.daemon.join_approvals() == []
    assert join_audit(a) == ["join_replay", "join_replay"]
    assert pending_events(a) == 2
    assert len(a.daemon.store.members(gid)) == 1


async def test_a_replay_after_a_restart_is_dropped(
    cluster: Cluster, malicious_relay: Proxy, rng: random.Random
) -> None:
    a, (b,), _gid, _invite = await requested(cluster)
    frame = frame_of(malicious_relay(a), b)
    (request,) = a.daemon.join_approvals()
    a.daemon.reject(request["request_id"])
    await a.restart()
    await redeliver(a, frame, rng)
    assert a.daemon.join_approvals() == []
    assert join_audit(a) == ["join_replay"]
    assert pending_events(a) == 1
    assert len(a.daemon.store.ledger_rows(a.daemon.now(), ledger="join")) == 1


async def test_past_the_ledgers_window_the_invite_refuses_the_replay(
    cluster: Cluster, malicious_relay: Proxy, advance: Advance, rng: random.Random
) -> None:
    a, (b,), _gid, invite = await requested(cluster, ttl_secs=600)
    frame = frame_of(malicious_relay(a), b)
    (request,) = a.daemon.join_approvals()
    a.daemon.reject(request["request_id"])
    (row,) = a.daemon.store.ledger_rows(a.daemon.now(), ledger="join")
    assert row[2] == invite["expires_at"] + ac.LEDGER_GRACE_SECS
    await advance(row[2] + 1 - a.daemon.now())
    await redeliver(a, frame, rng)
    # Forgotten by the ledger, and refused by the invite's own expiry.
    assert a.daemon.store.ledger_rows(0, ledger="join") == []
    assert a.daemon.join_approvals() == []
    assert join_audit(a) == []
    assert pending_events(a) == 1


async def test_a_full_ledger_drops_new_requests_and_keeps_live_ones(
    cluster: Cluster, malicious_relay: Proxy, rng: random.Random
) -> None:
    a, (b,), gid, invite = await requested(cluster)
    proxy = malicious_relay(a)
    frame = frame_of(proxy, b)
    # A ledger of one entry, kept across a reload (a rollback or a restart
    # would rebuild it at the same capacity).
    a.daemon._join_capacity = 1
    a.daemon._join_ledger = a.daemon._load_join_ledger()
    c = await cluster.node("c")
    await c.daemon.accept_invite(invite["url"])
    await a.wait(lambda: "join_ledger_full" in join_audit(a))
    assert len(a.daemon.join_approvals()) == 1  # b's, nothing evicted
    await redeliver(a, frame, rng)
    assert join_audit(a) == ["join_ledger_full", "join_replay"]
    assert len(a.daemon.join_approvals()) == 1
    assert pending_events(a) == 1
    assert_silent(a, [c], approvals=1)
    assert len(a.daemon.store.members(gid)) == 1


async def test_a_forward_clock_jump_doesnt_purge_live_entries(
    cluster: Cluster, malicious_relay: Proxy, advance: Advance, rng: random.Random
) -> None:
    """An entry lives until its invite expires, not an hour from receipt,
    so a clock that jumps past the hour forgets nothing. A jump past the
    invite's expiry does purge the entry, but the same pass has already
    expired the invite, so a replay after the clock is put right is still
    refused."""
    a, (b,), _gid, _invite = await requested(cluster)
    frame = frame_of(malicious_relay(a), b)
    (request,) = a.daemon.join_approvals()
    a.daemon.reject(request["request_id"])
    start = a.clock.now()
    await advance(2 * APPROVAL_TIMEOUT_SECS)
    await redeliver(a, frame, rng)  # each frame purges at the clock's now first
    assert join_audit(a) == ["join_replay"]
    assert len(a.daemon.store.ledger_rows(a.daemon.now(), ledger="join")) == 1
    a.clock.advance(2 * 86_400)
    await a.daemon.expire()
    assert a.daemon.store.ledger_rows(0, ledger="join") == []
    a.clock.set(start)  # the clock is put right again
    await redeliver(a, frame, rng)
    assert a.daemon.join_approvals() == []
    assert pending_events(a) == 1


async def test_a_flooded_invite_tells_the_human_and_not_the_agent(cluster: Cluster) -> None:
    """Over the invite's pending cap a request is dropped silently, and the
    human (only) hears that the invite is being flooded."""
    a = await cluster.node("a", auto_approve=False, policy_max_pending_joins_per_invite=1)
    gid = a.daemon.create_group("Flood", "")
    await a.idle()
    invite = await a.daemon.create_invite(gid, max_uses=3)
    for name in ("b", "c"):
        joiner = await cluster.node(name)
        await joiner.daemon.accept_invite(invite["url"])
    await a.wait(lambda: "join_invite_full" in join_audit(a))
    assert len(a.daemon.join_approvals()) == 1
    (flooded,) = [e for e in a.daemon.store.events(limit=1000) if e["type"] == "invite_flooded"]
    assert flooded["data"]["invite_id"] == invite["invite_id"]
    assert flooded["data"]["reason"] == "join_invite_full"
    assert not a.adapter.of_type("invite_flooded")
    assert not [e for e in a.daemon.store.agent_events(limit=1000) if e["type"] == "invite_flooded"]
    assert not [h for h in a.handled if getattr(h, "type", None) == "invite_flooded"]


async def test_a_used_up_invite_forgets_its_requests(cluster: Cluster) -> None:
    """Stored `exhausted` is final (its secret is gone and step 1 refuses), so
    its requests are forgotten as for a revoked or expired invite."""
    a, _joiners, gid, invite = await requested(cluster, max_uses=1, joiners=2)
    assert len(a.daemon.store.ledger_rows(0, ledger="join")) == 2
    first, _second = a.daemon.join_approvals()
    a.daemon.approve(first["request_id"])
    await a.wait(
        lambda: (a.daemon.store.invite(invite["invite_id"]) or {})["status"] == "exhausted"
    )
    assert a.daemon.store.ledger_rows(0, ledger="join") == []
    assert len(a.daemon._join_ledger) == 0
    assert len(a.daemon.store.members(gid)) == 2
