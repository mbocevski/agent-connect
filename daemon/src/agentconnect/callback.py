"""The in-process adapter: deliveries and events go to Python callbacks.

The embedded SDK registers it, so an agent running the runtime in its own
process gets messages without a webhook or a socket. The callbacks receive
the same JSON payloads the webhook and SSE adapters send
(:mod:`agentconnect.payloads`), so the SDK parses one shape in every mode.

Semantics match the webhook adapter (``docs/adapters/webhook.md``):

* **Messages** are handed over by the runtime's delivery workers, in order
  within each group; groups don't wait for each other. A callback that
  returns is an ack. One that raises, or still runs after ``timeout``
  seconds (on the runtime's clock; it is then cancelled), is ``RETRY``: the
  runtime retries that group with exponential backoff and hands over nothing
  later in that group before it, as for a webhook that answers 500 or times
  out. Nothing is dead-lettered.
* **Events** are queued in the runtime's encrypted database and handed over
  by workers of their own, in order within each group, with the same
  timeout and a backoff on failure, so a slow handler never holds up the
  runtime or another group. The queue keeps the newest 10 000 per adapter.
  A crash before the callback returned hands the event over again after the
  restart.
* Until :meth:`CallbackAdapter.open` is called (the SDK's ``serve()``),
  nothing is handed over: messages wait in the inbox, events in the queue.

Every callback runs in a task of its own; :meth:`CallbackAdapter.in_handler`
tells whether the caller is one (the embedded host uses it to shut down from
inside a handler without waiting on that handler), and
:meth:`CallbackAdapter.drain` waits until none runs.

A callback failure is logged with the exception type only, never the
message or its body.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from agentconnect import log
from agentconnect.adapter import (
    Capabilities,
    Delivery,
    DeliveryResult,
    Event,
    GroupView,
    OutboundSend,
    Sender,
)
from agentconnect.backoff import Backoff
from agentconnect.clock import Clock
from agentconnect.payloads import event_payload, message_payload
from agentconnect.tasks import cancel_and_wait

LOG = log.get("agentconnect.callback")

DEFAULT_TIMEOUT = 120.0  # seconds a callback may run; agent turns call models
GRACE_SECS = 5.0  # after the timeout's cancellation, before a handler is abandoned
STOP_GRACE_SECS = 1.0  # real seconds a stopping runtime waits for a cancelled handler

# One payload in; returning means handled, raising means try again later.
PayloadCallback = Callable[[dict[str, Any]], Awaitable[None]]


class EventQueue(Protocol):
    """Where the adapter keeps events until a callback took them (the store)."""

    def adapter_event_add(self, adapter: str, event_id: str, payload: dict[str, Any]) -> bool: ...
    def adapter_events(
        self, adapter: str, group_id: str | None = None, limit: int = 100
    ) -> list[tuple[int, dict[str, Any]]]: ...
    def adapter_event_groups(self, adapter: str) -> list[str | None]: ...
    def adapter_event_done(self, seq: int) -> None: ...


class HandlerCancelledError(Exception):
    """A handler ended with ``CancelledError`` although nothing cancelled it
    (it awaited a task or future something else cancelled): a failure of
    that handler, retried like any other, not the end of the delivery."""


def _group_of(payload: dict[str, Any]) -> str | None:
    group = payload.get("group")
    return str(group["id"]) if isinstance(group, dict) and "id" in group else None


class CallbackAdapter:
    """Implements :class:`agentconnect.adapter.Adapter` with two callbacks."""

    def __init__(  # noqa: PLR0913
        self,
        on_message: PayloadCallback,
        on_event: PayloadCallback,
        clock: Clock,
        *,
        name: str = "sdk",
        timeout: float = DEFAULT_TIMEOUT,
        rng: random.Random | None = None,
        on_abandon: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.name = name
        self._on_abandon = on_abandon
        # At most one handler per group that ignored its cancellation and
        # was left running.
        self._abandoned: dict[str | None, asyncio.Future[None]] = {}
        self._on_message, self._on_event = on_message, on_event
        self._clock = clock
        self._timeout = timeout
        self._rng = rng
        self._queue: EventQueue | None = None
        self._open = asyncio.Event()
        self._wake = asyncio.Event()
        self._worker: asyncio.Task[None] | None = None
        self._groups: dict[str | None, asyncio.Task[None]] = {}
        self._handlers: set[asyncio.Future[None]] = set()
        self._idle = asyncio.Event()
        self._idle.set()

    def capabilities(self) -> Capabilities:
        # Sends go through the runtime's AgentApi, not through on_outbound.
        return Capabilities(accepts=["text", "data"], originates=False)

    def bind_store(self, queue: EventQueue) -> None:
        """Called by the runtime at start with its store."""
        self._queue = queue

    async def on_outbound(self, send: OutboundSend) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.get_running_loop().create_task(self._run_events())

    def open(self) -> None:
        """Start handing deliveries and events to the callbacks."""
        self._open.set()
        self._wake.set()

    def pause(self) -> None:
        """Stop handing new ones over; they wait, nothing is lost. Callbacks
        already running go on (:meth:`drain` waits for them)."""
        self._open.clear()

    @property
    def is_open(self) -> bool:
        return self._open.is_set()

    def in_handler(self) -> bool:
        """Whether the calling task is one of this adapter's callbacks."""
        try:
            task = asyncio.current_task()
        except RuntimeError:
            return False
        return task is not None and task in self._handlers

    def busy(self) -> bool:
        """Whether any callback is running now."""
        return bool(self._handlers)

    async def drain(self, within: float) -> bool:
        """Wait (real time, at most ``within`` seconds) until no callback runs;
        whether none does."""
        if not self._idle.is_set() and within > 0:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._idle.wait(), within)
        return self._idle.is_set()

    def _track(self, task: asyncio.Future[None]) -> None:
        self._handlers.add(task)
        self._idle.clear()

        def finished(done: asyncio.Future[None]) -> None:
            self._handlers.discard(done)
            if not self._handlers:
                self._idle.set()
            if not done.cancelled():
                done.exception()  # retrieved: an abandoned one has no awaiter

        task.add_done_callback(finished)

    async def _call(self, callback: PayloadCallback, payload: dict[str, Any]) -> None:
        """Run ``callback`` in a task of its own, bounded by the timeout on the
        runtime's clock.

        * It returns: done. It raises: that error. It ends with
          ``CancelledError`` while this caller isn't being cancelled:
          :class:`HandlerCancelledError`.
        * Past the timeout it is cancelled and gets :data:`GRACE_SECS` to
          stop (``TimeoutError``). One that ignores the cancellation is left
          running (logged ``handler_ignored_cancel``), and ``on_abandon`` is
          told, so the redelivery isn't refused as a duplicate in progress;
          a group keeps at most one such handler and otherwise waits for it.
        * If this caller is cancelled (the runtime stops), the handler is
          cancelled too and waited for, at most :data:`STOP_GRACE_SECS`.
        """
        group = _group_of(payload)
        task: asyncio.Future[None] = asyncio.ensure_future(callback(payload))
        self._track(task)
        timer = asyncio.ensure_future(self._clock.sleep(self._timeout, deadline=True))
        settled = False
        try:
            done, _ = await asyncio.wait({task, timer}, return_when=asyncio.FIRST_COMPLETED)
            if task in done:
                settled = True
                if task.cancelled():
                    current = asyncio.current_task()
                    if current is not None and current.cancelling():
                        raise asyncio.CancelledError
                    raise HandlerCancelledError
                task.result()
                return
            task.cancel()
            grace = asyncio.ensure_future(self._clock.sleep(GRACE_SECS, deadline=True))
            try:
                await asyncio.wait({task, grace}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                grace.cancel()
            if not task.done():
                held = self._abandoned.get(group)
                if held is not None and not held.done():
                    LOG.warning("handler_ignores_cancel", group=log.hid(group), waiting=True)
                    await asyncio.wait({task})
                else:
                    self._abandoned[group] = task
                    LOG.warning("handler_ignored_cancel", group=log.hid(group))
                    if self._on_abandon is not None:
                        self._on_abandon(payload)
            settled = True
            raise TimeoutError
        finally:
            timer.cancel()
            if not settled and not task.done():
                # This caller is cancelled: the handler goes too.
                task.cancel()
                await asyncio.wait({task}, timeout=STOP_GRACE_SECS)

    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        await self._open.wait()
        try:
            await self._call(self._on_message, message_payload(group, inner))
        except Exception as e:
            LOG.warning("callback_failed", kind="message", error=type(e).__name__)
            return DeliveryResult.RETRY
        return DeliveryResult.ACK

    async def on_event(self, group: GroupView | None, event: Event) -> None:
        """Queue the event durably; a worker hands it over. Raises (so the
        runtime keeps the event and sends it again) only without a store."""
        if self._queue is None:
            msg = "the callback adapter has no store yet"
            raise RuntimeError(msg)
        self._queue.adapter_event_add(self.name, event.event_id, event_payload(group, event))
        self._wake.set()

    def _queued(self, group: str | None) -> list[tuple[int, dict[str, Any]]]:
        if self._queue is None:
            return []
        return self._queue.adapter_events(self.name, group_id=group)

    async def _run_events(self) -> None:
        """Start a worker for every group with queued events."""
        try:
            while True:
                self._wake.clear()
                await self._open.wait()
                groups = [] if self._queue is None else self._queue.adapter_event_groups(self.name)
                for group in groups:
                    running = self._groups.get(group)
                    if running is None or running.done():
                        worker = asyncio.ensure_future(self._run_group(group))
                        worker.add_done_callback(self._group_done)
                        self._groups[group] = worker
                await self._wake.wait()
        finally:
            workers, self._groups = list(self._groups.values()), {}
            await cancel_and_wait(*workers)

    def _group_done(self, worker: asyncio.Future[None]) -> None:
        """A group's event worker that ended by surprise is logged, and the
        next wake starts a new one."""
        if worker.cancelled():
            return
        error = worker.exception()
        if error is not None:
            LOG.error("event_worker_died", reason=type(error).__name__)
            self._wake.set()

    async def _run_group(self, group: str | None) -> None:
        """One group's events, in order, until none is queued."""
        backoff = Backoff(base=1.0, cap=300.0, rng=self._rng)
        while True:
            rows = self._queued(group)
            if not rows:
                return
            for seq, payload in rows:
                await self._open.wait()
                try:
                    await self._call(self._on_event, payload)
                except Exception as e:
                    LOG.warning("callback_failed", kind="event", error=type(e).__name__)
                    await self._clock.sleep(backoff.next())
                    break  # retry from the head, in order
                backoff.reset()
                if self._queue is not None:
                    self._queue.adapter_event_done(seq)

    async def close(self) -> None:
        """Called by the runtime when it stops."""
        self._open.clear()
        if self._worker is not None:
            worker, self._worker = self._worker, None
            await cancel_and_wait(worker)
