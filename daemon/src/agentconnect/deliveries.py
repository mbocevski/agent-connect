"""The delivery queue: messages kept until an agent tool takes them.

The MCP host (``agentconnect mcp``, ADR-005) registers it as the ``mcp``
adapter. An MCP client pulls: the model calls a tool that waits for
messages. So the adapter doesn't push anything. It keeps each delivery in
the runtime's encrypted database until a tool call has returned it, and
answers the runtime ``ACK`` at once, so the relay can drop its copy.

* **Durable.** A queued message survives a restart; one that no tool call
  returned before the session ended is returned by the next one. The queue
  keeps the newest 10 000.
* **At least once, deduplicated.** A delivery the runtime hands over again
  after a crash has the same key (``["msg", group, sender, msg_id]``, the
  embedded SDK's key): it isn't queued twice, and once a tool call returned
  it, the key is in the runtime's handled ids (:attr:`Runtime.handled`'s
  table), so a later repeat is dropped.
* **Leases.** :meth:`DeliveryQueue.take` leases what it returns for
  :data:`LEASE_SECS`; :meth:`DeliveryQueue.ack` takes it off the queue.
  Another waiter (a second session attached through the local API) doesn't
  see a leased message. A lease that runs out without an ack (the caller
  went away) puts the message back.
* **Content only.** Text and task messages are queued. Agent Cards and
  ``control.*`` messages carry no text for the model: they are acknowledged
  and not queued (the runtime keeps the card). Events are not queued
  either: they are in the agent's event log (``GET /v0/events``).

Every queued message keeps its SPEC 10.1 framing (``untrusted``,
``notice``, ``scope``, ``addressed_to_me``) in the payload shape of the
webhook adapter (:mod:`agentconnect.payloads`).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from agentconnect.adapter import (
    Capabilities,
    Delivery,
    DeliveryResult,
    Event,
    GroupView,
    OutboundSend,
    Sender,
)
from agentconnect.clock import Clock
from agentconnect.payloads import message_payload

ADAPTER_NAME = "mcp"
CONTENT_KINDS = frozenset(
    {"a2a.message", "a2a.task_status", "a2a.task_artifact", "a2a.task_cancel"}
)
QUEUE_KEEP = 10_000  # queued messages kept per runtime, the newest
MAX_BATCH = 50  # messages one take returns at most
LEASE_SECS = 120.0  # how long a taken, unacknowledged message stays hidden
MAX_WAIT_SECS = 300.0  # the longest one take waits


class QueueStore(Protocol):
    """The part of the runtime's store the queue uses."""

    def adapter_event_add(
        self, adapter: str, event_id: str, payload: dict[str, Any], keep: int = ...
    ) -> bool: ...
    def adapter_events(
        self, adapter: str, group_id: str | None = None, limit: int = 100
    ) -> list[tuple[int, dict[str, Any]]]: ...
    def adapter_event_groups(self, adapter: str) -> list[str | None]: ...
    def adapter_event_finish(self, adapter: str, seq: int) -> bool: ...
    def handled_has(self, key: str) -> bool: ...


def delivery_key(payload: dict[str, Any]) -> str:
    """``["msg", group, sender, msg_id]``: each sender picks its own
    ``msg_id`` (SPEC 8.3), so the key names the sender too, and a peer can't
    pick an id that hides another sender's message."""
    group, sender = payload.get("group"), payload.get("sender")
    group_id = group.get("id") if isinstance(group, dict) else None
    identity = sender.get("identity") if isinstance(sender, dict) else None
    return json.dumps(["msg", group_id, identity, payload.get("msg_id")], separators=(",", ":"))


@dataclass(frozen=True)
class Taken:
    """One leased message: ``delivery_id`` acknowledges it."""

    delivery_id: int
    payload: dict[str, Any]


class DeliveryQueue:
    """Implements :class:`agentconnect.adapter.Adapter`; the agent pulls with
    :meth:`take` and confirms with :meth:`ack`."""

    def __init__(self, clock: Clock, *, name: str = ADAPTER_NAME) -> None:
        self.name = name
        self._clock = clock
        self._store: QueueStore | None = None
        self._leases: dict[int, float] = {}  # delivery_id -> when the lease ends
        self._changed = asyncio.Event()
        self._closed = False
        self.waiting = 0  # takes waiting now (status and tests)

    def capabilities(self) -> Capabilities:
        # The agent sends through the runtime's AgentApi, not on_outbound.
        return Capabilities(accepts=["text", "data"], originates=False)

    def bind_store(self, store: QueueStore) -> None:
        """Called by the runtime at start with its store."""
        self._store = store
        self._closed = False

    async def on_outbound(self, send: OutboundSend) -> None:
        return None

    def _queue(self) -> QueueStore:
        if self._store is None:
            msg = "the delivery queue has no store yet"
            raise RuntimeError(msg)
        return self._store

    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        if inner.kind not in CONTENT_KINDS:
            return DeliveryResult.ACK
        store = self._queue()  # raises without a store: the runtime retries
        payload = message_payload(group, inner)
        key = delivery_key(payload)
        if not store.handled_has(key) and store.adapter_event_add(
            self.name, key, payload, QUEUE_KEEP
        ):
            self._changed.set()
        return DeliveryResult.ACK

    async def on_event(self, group: GroupView | None, event: Event) -> None:
        """Events are read from the agent's event log, not queued here."""
        return None

    async def close(self) -> None:
        """Called by the runtime when it stops: waiting takes return."""
        self._closed = True
        self._changed.set()

    def _now(self) -> float:
        return self._clock.now().timestamp()

    def _available(self, group: str | None, limit: int) -> list[tuple[int, dict[str, Any]]]:
        """Queued, unleased messages of ``group`` (any group: ``None``),
        oldest first; at most ``limit`` + 1, to tell whether there are more."""
        now = self._now()
        self._leases = {d: end for d, end in self._leases.items() if end > now}
        store = self._queue()
        groups = (
            [group]
            if group is not None
            else [g for g in store.adapter_event_groups(self.name) if g is not None]
        )
        rows: list[tuple[int, dict[str, Any]]] = []
        for g in groups:
            fetched = store.adapter_events(self.name, g, limit=limit + 1 + len(self._leases))
            rows.extend(r for r in fetched if r[0] not in self._leases)
        rows.sort(key=lambda r: r[0])
        return rows[: limit + 1]

    async def take(
        self,
        group: str | None = None,
        *,
        addressed_only: bool = False,
        wait_secs: float = 0.0,
        limit: int = MAX_BATCH,
        stop: asyncio.Event | None = None,
    ) -> tuple[list[Taken], bool]:
        """Wait (on the runtime's clock, at most ``wait_secs`` seconds, capped
        at :data:`MAX_WAIT_SECS`) until a message of ``group`` (any group:
        ``None``) is queued, or with ``addressed_only`` one that addresses
        this agent; then lease and return the queued messages of ``group``
        (addressed or not, oldest first, at most ``limit``) and whether more
        are queued. Nothing is leased if the caller is cancelled, the runtime
        stops or ``stop`` is set: the answer is then empty."""
        limit = max(1, min(limit, MAX_BATCH))
        deadline = self._now() + max(0.0, min(wait_secs, MAX_WAIT_SECS))
        while True:
            self._changed.clear()  # before checking: no change is missed
            if self._closed:
                return [], False
            rows = self._available(group, limit)
            if rows and (
                not addressed_only or any(p.get("addressed_to_me") is True for _, p in rows)
            ):
                picked = rows[:limit]
                ends = self._now() + LEASE_SECS
                for delivery_id, _ in picked:
                    self._leases[delivery_id] = ends
                return [Taken(d, p) for d, p in picked], len(rows) > limit
            now = self._now()
            if now >= deadline or (stop is not None and stop.is_set()):
                return [], False
            await self._nap(min([deadline, *self._leases.values()]), stop)

    async def _nap(self, until: float, stop: asyncio.Event | None) -> None:
        """Until something changes, ``until`` (Unix seconds on the runtime's
        clock: the deadline or the end of a lease) or ``stop``."""
        waits = [
            asyncio.ensure_future(self._changed.wait()),
            asyncio.ensure_future(self._clock.sleep_until(until, deadline=True)),
        ]
        if stop is not None:
            waits.append(asyncio.ensure_future(stop.wait()))
        self.waiting += 1
        try:
            await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
        finally:
            self.waiting -= 1
            for w in waits:
                w.cancel()

    def ack(self, delivery_ids: Iterable[int]) -> int:
        """Take messages off the queue (a tool call returned them) and
        remember their keys as handled; how many were still queued."""
        store = self._queue()
        done = 0
        for delivery_id in delivery_ids:
            self._leases.pop(delivery_id, None)
            done += store.adapter_event_finish(self.name, delivery_id)
        return done

    def release(self, delivery_ids: Iterable[int]) -> None:
        """End leases early: the messages are queued again for any waiter."""
        for delivery_id in delivery_ids:
            self._leases.pop(delivery_id, None)
        self._changed.set()
