"""SPEC §11: when the human says the codes differ, the instance leaves the
group and raises ``sas_mismatch``. Human-only, like verification."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from agentconnect.api import ApiError, ApiServer
from agentconnect.daemon import DaemonError
from agentconnect_harness.cluster import Node, status
from agentconnect_harness.proxy import RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Proxy = Callable[[Node], RelayProxy]


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


async def test_the_owner_just_deletes_its_state(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    assert await a.daemon.sas_mismatch(gid) == "left"
    assert status(a, gid) == "left"
    assert a.adapter.of_type("sas_mismatch")
    assert status(b, gid) == "active"


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
