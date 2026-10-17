"""Cancelling helper tasks never swallows the caller's own cancellation."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentconnect.clock import FakeClock
from agentconnect.sse import SseAdapter
from agentconnect.store import Store
from agentconnect.tasks import cancel_and_wait
from agentconnect.webhook import WebhookAdapter


class Stubborn:
    """A coroutine that, once cancelled, takes its time to finish: it waits
    for ``release`` (or a second cancellation) before it re-raises. While
    it does, whoever awaits it is stuck in its cleanup."""

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
    """Cancel ``outer`` while it waits for ``stub`` to finish cancelling,
    and check that ``outer`` really stops."""
    await stub.cancelled.wait()
    assert not outer.done()
    outer.cancel()
    stub.release.set()
    with pytest.raises(asyncio.CancelledError):
        await outer
    assert outer.cancelled()


async def test_the_tasks_own_cancellation_is_absorbed() -> None:
    stub = Stubborn()
    t = asyncio.ensure_future(stub.run())
    await asyncio.sleep(0)
    stub.release.set()
    await cancel_and_wait(t)
    assert t.cancelled()
    await cancel_and_wait()  # nothing to do


async def test_the_callers_cancellation_propagates() -> None:
    stub = Stubborn()
    inner = asyncio.ensure_future(stub.run())
    await asyncio.sleep(0)
    await cancel_during_cleanup(stub, asyncio.ensure_future(cancel_and_wait(inner)))
    assert inner.cancelled()


async def test_ignored_exceptions_are_absorbed_and_others_raised() -> None:
    async def fail(exc: BaseException) -> None:
        raise exc

    ignored = asyncio.ensure_future(fail(TimeoutError()))
    other = asyncio.ensure_future(fail(KeyError("x")))
    await asyncio.sleep(0)
    await cancel_and_wait(ignored, ignore=(TimeoutError,))
    with pytest.raises(KeyError):
        await cancel_and_wait(other, ignore=(TimeoutError,))


async def test_finished_tasks_are_fine() -> None:
    done = asyncio.ensure_future(asyncio.sleep(0))
    await done
    await cancel_and_wait(done)


async def stuck_closing(
    close: Callable[[], Awaitable[None]], install: Callable[[asyncio.Task[Any]], None]
) -> None:
    stub = Stubborn()
    task = asyncio.ensure_future(stub.run())
    install(task)
    await asyncio.sleep(0)
    await cancel_during_cleanup(stub, asyncio.ensure_future(close()))


async def test_sse_close_lets_the_caller_be_cancelled(
    tmp_path: Path, fake_clock: FakeClock
) -> None:
    store = Store(tmp_path / "daemon.sqlite3", secrets.token_bytes(32))
    hub = SseAdapter(fake_clock, feed=store)

    def install(t: asyncio.Task[Any]) -> None:
        hub._purger = t

    await stuck_closing(hub.close, install)
    store.close()


async def test_webhook_close_lets_the_caller_be_cancelled(fake_clock: FakeClock) -> None:
    adapter = WebhookAdapter(
        "http://127.0.0.1:9/hook",
        secrets.token_urlsafe(16),
        fake_clock,
        transport=httpx.MockTransport(lambda _r: httpx.Response(200)),
    )

    def install(t: asyncio.Task[Any]) -> None:
        adapter._worker = t

    await stuck_closing(adapter.close, install)
