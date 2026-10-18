"""SPEC §11: when the human says the codes differ, the instance leaves the
group and raises ``sas_mismatch``. Human-only, like verification."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.runtime.api import ApiError, ApiServer
from agentconnect.runtime.engine import TRANSFER_TIMEOUT_SECS, DaemonError
from agentconnect_harness.cluster import Cluster, Node, status
from agentconnect_harness.proxy import RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Proxy = Callable[[Node], RelayProxy]
Advance = Callable[[float], Awaitable[None]]


async def test_a_mismatch_leaves_and_alerts(group: GroupFixture, malicious_relay: Proxy) -> None:
    (a, _b, c), gid = await group(3)
    # A fork: c's next commit reaches only c, so c's code differs.
    malicious_relay(c).fork_own_commits()
    c.daemon.update(gid)
    await c.wait(lambda: c.epoch(gid) == a.epoch(gid) + 1)
    assert c.sas(gid) != a.sas(gid)
    epoch = c.epoch(gid)
    with pytest.raises(DaemonError, match="was for epoch"):
        await c.daemon.sas_mismatch(gid, epoch - 1)
    assert await c.daemon.sas_mismatch(gid, epoch) == "left"
    (alert,) = c.adapter.of_type("sas_mismatch")
    assert alert.data["epoch"] == epoch
    assert status(c, gid) == "left"
    assert c.daemon.group_info(gid)["out_of_sync_reason"] == "sas_mismatch"
    with pytest.raises(DaemonError):
        c.daemon.send_message(gid, {"text": "gone"})


async def test_a_non_owner_mismatch_removes_its_leaf(group: GroupFixture) -> None:
    (a, b, _c), gid = await group(3)
    assert await b.daemon.sas_mismatch(gid) == "left"
    # The leave proposal went out; the remaining members commit it.
    await a.wait(lambda: b.me not in {m.identity for m in a.daemon.store.members(gid)})
    assert status(b, gid) == "left"


def owner(node: Node, gid: str) -> str | None:
    g = node.daemon.store.group(gid)
    return None if g is None else str(g.policy.get("owner"))


async def test_the_owner_hands_over_then_deletes(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    assert await a.daemon.sas_mismatch(gid) == "left"
    assert status(a, gid) == "left"
    (alert,) = a.adapter.of_type("sas_mismatch")
    # b has the lowest leaf after a (no admins): it is the new owner.
    assert alert.data["transfer"] == {"new_owner": b.me, "confirmed": True}
    for n in (b, c):
        await n.wait(lambda n=n: owner(n, gid) == b.me)
    # No longer the owner, the old leaf is removed under the normal rules
    # (here through the leave proposal it sent after the transfer).
    for n in (b, c):
        await n.wait(lambda n=n: a.me not in {m.identity for m in n.daemon.store.members(gid)})
    assert status(b, gid) == status(c, gid) == "active"


async def test_an_unconfirmed_transfer_still_deletes(
    group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    (a, b), gid = await group(2)

    def swallow(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        return [] if frame.get("t") == "send" and env.get("kind") == "commit" else [frame]

    malicious_relay(a).client_filters.append(swallow)
    task = asyncio.ensure_future(a.daemon.sas_mismatch(gid))
    await a.wait(lambda: a.clock.sleepers > 0)
    await advance(TRANSFER_TIMEOUT_SECS)
    assert await asyncio.wait_for(task, 5) == "left"
    assert status(a, gid) == "left"
    (alert,) = a.adapter.of_type("sas_mismatch")
    assert alert.data["transfer"] == {"new_owner": b.me, "confirmed": False}
    # Nothing reached b: the group stays as it was there.
    assert owner(b, gid) == a.me


async def test_a_sole_owner_just_deletes(cluster: Cluster) -> None:
    a = await cluster.node("solo")
    gid = a.daemon.create_group("Alone", "")
    await a.idle()
    assert await a.daemon.sas_mismatch(gid) == "left"
    assert status(a, gid) == "left"
    (alert,) = a.adapter.of_type("sas_mismatch")
    assert "transfer" not in alert.data


async def test_the_api_operation_is_human_only(group: GroupFixture) -> None:
    (a, _b), gid = await group(2)
    server = ApiServer(a.daemon)
    agent = {"authorization": f"Bearer {server.tokens['agent']}"}
    human = {"authorization": f"Bearer {server.tokens['human']}"}
    path = f"/v0/groups/{gid}/sas/mismatch"
    with pytest.raises(ApiError, match="human token"):
        await server.handle("POST", path, agent, b"{}")
    with pytest.raises(ApiError, match="integer"):
        await server.handle("POST", path, human, b'{"epoch": "1"}')
    assert await server.handle("POST", path, human, b"{}") == (200, {"status": "left"})
