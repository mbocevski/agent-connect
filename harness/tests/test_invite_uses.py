"""SPEC §6.2 step 1 and §4.3: an invite admits at most ``max_uses`` joiners,
counted at approval time, and a joiner that loses the race is told the link
was already used."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest

from agentconnect.daemon import INVITE_WARNING, JOIN_CLOSED_GRACE_SECS, DaemonError
from agentconnect.relay import RelayError
from agentconnect_harness.cluster import Cluster, Node

Advance = Callable[[float], Awaitable[None]]


def joined(node: Node, gid: str) -> bool:
    return node.daemon.store.group(gid) is not None


async def test_two_concurrent_redemptions_of_a_single_use_link(
    cluster: Cluster, advance: Advance
) -> None:
    a = await cluster.node("a", auto_approve=True)
    gid = a.daemon.create_group("One use", "")
    await a.idle()
    b = await cluster.node("b")
    c = await cluster.node("c")
    invite = await a.daemon.create_invite(gid, max_uses=1)
    # The legitimate joiner and a link thief redeem it at the same time.
    await asyncio.gather(
        b.daemon.accept_invite(invite["url"]), c.daemon.accept_invite(invite["url"])
    )
    await a.wait(lambda: len(a.daemon.store.approvals("approved")) == 1)
    await a.wait(
        lambda: (a.daemon.store.invite(invite["invite_id"]) or {})["status"] == "exhausted"
    )
    await a.idle()
    (approved,) = a.daemon.store.approvals("approved")
    winner, loser = (b, c) if approved["identity"] == b.me else (c, b)
    await winner.wait(lambda: joined(winner, gid))
    # Exactly one was added.
    assert len(a.daemon.store.members(gid)) == 2
    assert {m.identity for m in a.daemon.store.members(gid)} == {a.me, winner.me}
    assert not joined(loser, gid)
    # The loser gets the "already used" warning once the invite has been
    # seen closed for the grace period.
    await loser.daemon.check_joins()
    assert loser.daemon.store.join_status(invite["invite_id"]) == ("pending", None)
    await advance(JOIN_CLOSED_GRACE_SECS)
    await loser.daemon.check_joins()
    assert loser.daemon.store.join_status(invite["invite_id"]) == ("failed", None)
    assert loser.daemon.keystore.get(f"join/{invite['invite_id']}") is None
    (failed,) = loser.adapter.of_type("join_failed")
    assert failed.data["warning"] == INVITE_WARNING
    assert failed.data["reason"] == "invite_used"
    assert winner.daemon.store.join_status(invite["invite_id"]) == ("joined", gid)


async def test_a_human_cannot_approve_more_than_max_uses(cluster: Cluster) -> None:
    a = await cluster.node("a", auto_approve=False)
    gid = a.daemon.create_group("One use", "")
    await a.idle()
    b = await cluster.node("b")
    c = await cluster.node("c")
    invite = await a.daemon.create_invite(gid, max_uses=1)
    await b.daemon.accept_invite(invite["url"])
    await c.daemon.accept_invite(invite["url"])
    await a.wait(lambda: len(a.daemon.approvals()) == 2)
    first, second = a.daemon.approvals()
    a.daemon.approve(first["request_id"])
    with pytest.raises(DaemonError, match="no uses left"):
        a.daemon.approve(second["request_id"])
    assert (a.daemon.store.approval(second["request_id"]) or {})["status"] == "rejected"
    await a.idle()
    assert len(a.daemon.store.members(gid)) == 2


async def test_check_joins_tolerates_relay_trouble(
    cluster: Cluster, advance: Advance, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = await cluster.node("a", auto_approve=False)
    gid = a.daemon.create_group("Slow", "")
    await a.idle()
    b = await cluster.node("b")
    invite = await a.daemon.create_invite(gid)
    await b.daemon.accept_invite(invite["url"])
    answers: list[Any] = [
        httpx.ConnectError("down"),
        RelayError("internal"),
        {"status": "open"},
        RelayError("invite_not_open"),
    ]

    async def meta(_invite_id: str) -> dict[str, Any]:
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(b.daemon.rest, "invite_meta", meta)
    for _ in range(3):
        await b.daemon.check_joins()
    assert b.daemon.store.join_status(invite["invite_id"]) == ("pending", None)
    # Unknown at the relay counts as closed: seen once, then failed after the grace.
    await b.daemon.check_joins()
    answers.append({"status": "revoked"})
    await advance(JOIN_CLOSED_GRACE_SECS - 1)
    await b.daemon.check_joins()
    assert b.daemon.store.join_status(invite["invite_id"]) == ("pending", None)
    answers.append({"status": "revoked"})
    await advance(1)
    await b.daemon.check_joins()
    assert b.daemon.store.join_status(invite["invite_id"]) == ("failed", None)
