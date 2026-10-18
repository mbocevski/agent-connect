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

# One payload in; returning means handled, raising means try again later.
PayloadCallback = Callable[[dict[str, Any]], Awaitable[None]]


class EventQueue(Protocol):
    """Where the adapter keeps events until a callback took them (the store)."""

    def adapter_event_add(self, adapter: str, event_id: str, payload: dict[str, Any]) -> bool: ...
    def adapter_events(self, adapter: str) -> list[tuple[int, dict[str, Any]]]: ...
    def adapter_event_done(self, seq: int) -> None: ...


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
    ) -> None:
        self.name = name
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

    async def _call(self, callback: PayloadCallback, payload: dict[str, Any]) -> None:
        """Run ``callback`` in a task of its own, bounded by the timeout on the
        runtime's clock (``TimeoutError``). If the caller is cancelled, the
        callback is cancelled too and waited for."""
        task: asyncio.Future[None] = asyncio.ensure_future(callback(payload))
        self._handlers.add(task)
        self._idle.clear()
        timer = asyncio.ensure_future(self._clock.sleep(self._timeout, deadline=True))
        try:
            done, _ = await asyncio.wait({task, timer}, return_when=asyncio.FIRST_COMPLETED)
            if task not in done:
                raise TimeoutError
            task.result()
        finally:
            try:
                await cancel_and_wait(timer)
            finally:
                if not task.done():
                    await cancel_and_wait(task, ignore=(Exception,))
                self._handlers.discard(task)
                if not self._handlers:
                    self._idle.set()

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
        rows = [] if self._queue is None else self._queue.adapter_events(self.name)
        return [(seq, p) for seq, p in rows if _group_of(p) == group]

    async def _run_events(self) -> None:
        """Start a worker for every group with queued events."""
        try:
            while True:
                self._wake.clear()
                await self._open.wait()
                rows = [] if self._queue is None else self._queue.adapter_events(self.name)
                for group in dict.fromkeys(_group_of(p) for _, p in rows):
                    running = self._groups.get(group)
                    if running is None or running.done():
                        self._groups[group] = asyncio.ensure_future(self._run_group(group))
                await self._wake.wait()
        finally:
            workers, self._groups = list(self._groups.values()), {}
            await cancel_and_wait(*workers)

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
