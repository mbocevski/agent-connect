"""A daemon wait that cleans up its helper tasks never swallows the
cancellation of the task running it: cancelled during that cleanup, the
task stops."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.runtime import engine as daemon_mod
from agentconnect_harness.cluster import Cluster, Node

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]


class Stubborn:
    """A coroutine that, once cancelled, finishes only after ``release``
    (or a second cancellation), so its awaiter is stuck in its cleanup."""

    def __init__(self) -> None:
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()

    async def run(self, *_a: object, **_k: object) -> Any:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            await self.release.wait()
            raise


async def cancel_during_cleanup(stub: Stubborn, outer: asyncio.Task[Any]) -> None:
    await stub.cancelled.wait()
    assert not outer.done()
    outer.cancel()
    stub.release.set()
    with pytest.raises(asyncio.CancelledError):
        await outer
    assert outer.cancelled()


def sleeping(
    mp: pytest.MonkeyPatch, node: Node, seconds: float, stand_in: Callable[[float], Awaitable[None]]
) -> None:
    """Replace the daemon's ``_sleep(seconds)`` (other durations sleep as usual)."""
    real = node.daemon._sleep

    async def sleep(s: float) -> None:
        await (stand_in(s) if s == seconds else real(s))

    mp.setattr(node.daemon, "_sleep", sleep)


async def test_await_epoch_can_be_cancelled_during_its_cleanup(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, _b), gid = await group(2)
    stub = Stubborn()
    sleeping(monkeypatch, a, daemon_mod.REBUILD_WAIT_SECS, stub.run)

    async def at_once(_predicate: object, within: float = 0) -> None:
        return None

    monkeypatch.setattr(a.daemon, "wait_until", at_once)
    outer = asyncio.ensure_future(a.daemon._await_epoch(gid, a.epoch(gid)))
    await cancel_during_cleanup(stub, outer)


async def test_ownership_transfer_can_be_cancelled_during_its_cleanup(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, _b), gid = await group(2)
    await a.idle()
    stub = Stubborn()
    real = a.daemon._request

    async def request(frame: dict[str, Any], msg_id: str) -> dict[str, Any]:
        if frame.get("t") == "send" and frame["env"]["kind"] == "commit":
            return await stub.run()
        return await real(frame, msg_id)

    async def no_wait(_s: float) -> None:
        return None

    monkeypatch.setattr(a.daemon, "_request", request)
    sleeping(monkeypatch, a, daemon_mod.TRANSFER_TIMEOUT_SECS, no_wait)
    row = a.daemon.store.group(gid)
    assert row is not None
    outer = asyncio.ensure_future(a.daemon._transfer_ownership(row))
    await cancel_during_cleanup(stub, outer)


async def test_ownership_transfer_cancelled_while_waiting_stops_the_send(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, _b), gid = await group(2)
    await a.idle()
    stub = Stubborn()
    started = asyncio.Event()
    real = a.daemon._request

    async def request(frame: dict[str, Any], msg_id: str) -> dict[str, Any]:
        if frame.get("t") == "send" and frame["env"]["kind"] == "commit":
            started.set()
            return await stub.run()
        return await real(frame, msg_id)

    monkeypatch.setattr(a.daemon, "_request", request)
    row = a.daemon.store.group(gid)
    assert row is not None
    outer = asyncio.ensure_future(a.daemon._transfer_ownership(row))
    await started.wait()  # the send and the (fake-clock) timer are both pending
    await asyncio.sleep(0)
    outer.cancel()
    stub.release.set()
    with pytest.raises(asyncio.CancelledError):
        await outer
    assert stub.cancelled.is_set()


async def test_stop_can_be_cancelled_and_still_releases_everything(cluster: Cluster) -> None:
    n = await cluster.node("n")
    stub = Stubborn()
    n.daemon._tasks.append(asyncio.ensure_future(stub.run()))
    await asyncio.sleep(0)
    await cancel_during_cleanup(stub, asyncio.ensure_future(n.daemon.stop()))
    assert not n.daemon.running
    # The data-directory lock and the databases were released: the same
    # node starts again on its state.
    await n.start()
    assert n.daemon.running
