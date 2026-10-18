"""Invite and join secrets don't outlive their invites (SPEC §6.1, §4.3),
and frames parked for a pending join are bounded."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from agentconnect.runtime.engine import (
    JOIN_CLOSED_GRACE_SECS,
    MAX_PARKED_GROUPS,
    MAX_PARKED_PER_GROUP,
    new_msg_id,
)
from agentconnect_harness.cluster import Cluster

Advance = Callable[[float], Awaitable[None]]


async def test_expired_invites_and_joins_lose_their_secrets(
    cluster: Cluster, advance: Advance
) -> None:
    a = await cluster.node("a", auto_approve=False)
    b = await cluster.node("b")
    gid = a.daemon.create_group("Short", "")
    await a.idle()
    invite = await a.daemon.create_invite(gid, ttl_secs=600)
    iid = invite["invite_id"]
    await b.daemon.accept_invite(invite["url"])
    await a.wait(lambda: len(a.daemon.approvals()) == 1)
    assert a.daemon.keystore.get(f"invite/{iid}") is not None
    assert b.daemon.keystore.get(f"join/{iid}") is not None
    # The core stamps expires_at from the system clock, a little ahead of
    # the cluster's fake clock: leave some slack.
    await advance(600 + 30)
    await a.daemon.expire()
    assert (a.daemon.store.invite(iid) or {})["status"] == "expired"
    assert a.daemon.keystore.get(f"invite/{iid}") is None
    # The joiner waits out the grace period for an in-flight Welcome.
    await b.daemon.expire()
    assert b.daemon.store.join_status(iid) == ("pending", None)
    await advance(JOIN_CLOSED_GRACE_SECS)
    await b.daemon.expire()
    assert b.daemon.store.join_status(iid) == ("expired", None)
    assert b.daemon.keystore.get(f"join/{iid}") is None
    assert b.adapter.of_type("join_failed")[0].data["reason"] == "expired"


async def test_parked_frames_are_bounded_and_deduplicated(cluster: Cluster) -> None:
    n = await cluster.node("p")
    d = n.daemon

    def env(group_id: str, msg_id: str) -> dict[str, object]:
        return {"sender": "s", "msg_id": msg_id, "group_id": group_id}

    first = env("g0", new_msg_id())
    d._park("g0", first)
    d._park("g0", dict(first))  # a replay
    assert len(d._parked["g0"]) == 1
    for _ in range(MAX_PARKED_PER_GROUP + 10):
        d._park("g0", env("g0", new_msg_id()))
    assert len(d._parked["g0"]) == MAX_PARKED_PER_GROUP
    for i in range(1, MAX_PARKED_GROUPS + 5):
        d._park(f"g{i}", env(f"g{i}", new_msg_id()))
    assert len(d._parked) == MAX_PARKED_GROUPS
    # Nothing pending: the next sweep drops them all.
    await d.expire()
    assert d._parked == {}
