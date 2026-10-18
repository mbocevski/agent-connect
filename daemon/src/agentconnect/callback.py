"""The in-process adapter: deliveries and events go to Python callbacks.

The embedded SDK registers it, so an agent running the runtime in its own
process gets messages without a webhook or a socket. The callbacks receive
the same JSON payloads the webhook and SSE adapters send
(:mod:`agentconnect.payloads`), so the SDK parses one shape in every mode.

Semantics match the webhook adapter (``docs/adapters/webhook.md``):

* **Messages** are handed over in the runtime's delivery loop, in order. A
  callback that returns is an ack. One that raises is ``RETRY``: the runtime
  retries with exponential backoff on its clock and delivers nothing later
  before it, as for a webhook that answers 500. Nothing is dead-lettered.
* **Events** are queued in the runtime's encrypted database and handed over
  in order by a worker of their own, so a slow handler never holds up the
  runtime. A callback that raises is retried with backoff; the queue keeps
  the newest 10 000 per adapter. A crash before the callback returned
  hands the event over again after the restart.
* Until :meth:`CallbackAdapter.open` is called (the SDK's ``serve()``),
  nothing is handed over: messages wait in the inbox, events in the queue.

A callback failure is logged with the exception type only, never the
message or its body.
"""

from __future__ import annotations

import asyncio
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

# One payload in; returning means handled, raising means try again later.
PayloadCallback = Callable[[dict[str, Any]], Awaitable[None]]


class EventQueue(Protocol):
    """Where the adapter keeps events until a callback took them (the store)."""

    def adapter_event_add(self, adapter: str, event_id: str, payload: dict[str, Any]) -> bool: ...
    def adapter_events(self, adapter: str) -> list[tuple[int, dict[str, Any]]]: ...
    def adapter_event_done(self, seq: int) -> None: ...


class CallbackAdapter:
    """Implements :class:`agentconnect.adapter.Adapter` with two callbacks."""

    def __init__(
        self,
        on_message: PayloadCallback,
        on_event: PayloadCallback,
        clock: Clock,
        *,
        name: str = "sdk",
        backoff: Backoff | None = None,
    ) -> None:
        self.name = name
        self._on_message, self._on_event = on_message, on_event
        self._clock = clock
        self._backoff = backoff or Backoff(base=1.0, cap=300.0)
        self._queue: EventQueue | None = None
        self._open = asyncio.Event()
        self._wake = asyncio.Event()
        self._worker: asyncio.Task[None] | None = None

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
        """Stop handing them over; they wait, nothing is lost."""
        self._open.clear()

    @property
    def is_open(self) -> bool:
        return self._open.is_set()

    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        await self._open.wait()
        try:
            await self._on_message(message_payload(group, inner))
        except Exception as e:
            LOG.warning("callback_failed", kind="message", error=type(e).__name__)
            return DeliveryResult.RETRY
        return DeliveryResult.ACK

    async def on_event(self, group: GroupView | None, event: Event) -> None:
        """Queue the event durably; the worker hands it over. Raises (so the
        runtime keeps the event and sends it again) only without a store."""
        if self._queue is None:
            msg = "the callback adapter has no store yet"
            raise RuntimeError(msg)
        self._queue.adapter_event_add(self.name, event.event_id, event_payload(group, event))
        self._wake.set()

    async def _run_events(self) -> None:
        while True:
            self._wake.clear()
            await self._open.wait()
            rows = [] if self._queue is None else self._queue.adapter_events(self.name)
            if not rows:
                await self._wake.wait()
                continue
            for seq, payload in rows:
                await self._open.wait()
                try:
                    await self._on_event(payload)
                except Exception as e:
                    LOG.warning("callback_failed", kind="event", error=type(e).__name__)
                    await self._clock.sleep(self._backoff.next())
                    break  # retry from the head, in order
                self._backoff.reset()
                if self._queue is not None:
                    self._queue.adapter_event_done(seq)

    async def close(self) -> None:
        """Called by the runtime when it stops."""
        self._open.clear()
        if self._worker is not None:
            worker, self._worker = self._worker, None
            await cancel_and_wait(worker)
