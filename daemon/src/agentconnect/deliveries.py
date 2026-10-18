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
  :data:`LEASE_SECS` under a lease token; :meth:`DeliveryQueue.ack` with
  that token takes it off the queue, and no other token can. Another waiter
  (a second session attached through the local API) doesn't see a leased
  message. A lease that runs out without an ack (the caller went away) puts
  the message back; its holder may still ack it until another take leases it.
* **Addressed first.** Each row records whether it addresses this agent, so
  a take with ``addressed_only`` finds the oldest such row directly, however
  many others are queued before it.
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
import secrets
from collections.abc import Iterable, Sequence
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
HOLDER_KEEP_SECS = 3600.0  # how long a lease's holder may still ack after it ran out


class QueueStore(Protocol):
    """The part of the runtime's store the queue uses."""

    def adapter_event_add(
        self,
        adapter: str,
        event_id: str,
        payload: dict[str, Any],
        keep: int = ...,
        *,
        addressed: bool = ...,
    ) -> bool: ...
    def queue_rows(  # noqa: PLR0913
        self,
        adapter: str,
        *,
        group_id: str | None,
        skip: Sequence[int],
        limit: int,
        addressed: bool = ...,
        before: int | None = ...,
    ) -> list[tuple[int, dict[str, Any]]]: ...
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
class _Holder:
    token: str
    ends: float  # Unix seconds on the runtime's clock


@dataclass(frozen=True)
class Batch:
    """What one take leased: ``lease`` acknowledges or releases it."""

    lease: str
    items: list[Taken]
    more: bool


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
        self._holders: dict[int, _Holder] = {}  # delivery_id -> its lease
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
            self.name, key, payload, QUEUE_KEEP, addressed=inner.addressed_to_me
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

    def _leased(self) -> list[int]:
        """The seqs under a lease that hasn't run out. A record outlives its
        lease (it names the last holder, who may still ack) until another
        take leases the message again; old ones are pruned."""
        now = self._now()
        self._holders = {d: h for d, h in self._holders.items() if h.ends > now - HOLDER_KEEP_SECS}
        return [d for d, h in self._holders.items() if h.ends > now]

    def _pick(
        self, group: str | None, limit: int, addressed_only: bool
    ) -> tuple[list[tuple[int, dict[str, Any]]], bool] | None:
        """What a take returns now (the rows and whether more are queued),
        or ``None`` when it has to wait.

        Without ``addressed_only``: the oldest ``limit`` unleased rows.
        With it, the oldest unleased row that addresses this agent is found
        directly, however many others are queued before it: the batch is the
        oldest ``limit`` rows if it is among them, else that row and the
        ``limit - 1`` rows right before it."""
        store, skip = self._queue(), self._leased()
        head = store.queue_rows(self.name, group_id=group, skip=skip, limit=limit + 1)
        if not head:
            return None
        if not addressed_only:
            return head[:limit], len(head) > limit
        first = store.queue_rows(self.name, group_id=group, skip=skip, limit=1, addressed=True)
        if not first:
            return None
        if any(seq == first[0][0] for seq, _ in head[:limit]):
            return head[:limit], len(head) > limit
        before = store.queue_rows(
            self.name, group_id=group, skip=skip, limit=limit - 1, before=first[0][0]
        )
        return [*before, first[0]], True

    async def take(
        self,
        group: str | None = None,
        *,
        addressed_only: bool = False,
        wait_secs: float = 0.0,
        limit: int = MAX_BATCH,
        stop: asyncio.Event | None = None,
    ) -> Batch:
        """Wait (on the runtime's clock, at most ``wait_secs`` seconds, capped
        at :data:`MAX_WAIT_SECS`) until a message of ``group`` (any group:
        ``None``) is queued, or with ``addressed_only`` one that addresses
        this agent; then lease what :meth:`_pick` chose under a new lease
        token and return it. Nothing is leased if the caller is cancelled,
        the runtime stops or ``stop`` is set: the batch is then empty."""
        limit = max(1, min(limit, MAX_BATCH))
        deadline = self._now() + max(0.0, min(wait_secs, MAX_WAIT_SECS))
        while True:
            self._changed.clear()  # before checking: no change is missed
            if self._closed:
                return Batch("", [], more=False)
            picked = self._pick(group, limit, addressed_only)
            if picked is not None:
                rows, more = picked
                holder = _Holder(secrets.token_urlsafe(16), self._now() + LEASE_SECS)
                for seq, _ in rows:
                    self._holders[seq] = holder
                return Batch(holder.token, [Taken(d, p) for d, p in rows], more=more)
            now = self._now()
            if now >= deadline or (stop is not None and stop.is_set()):
                return Batch("", [], more=False)
            ends = [h.ends for h in self._holders.values() if h.ends > now]
            await self._nap(min([deadline, *ends]), stop)

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

    def _held(self, lease: str, delivery_ids: Iterable[int]) -> list[int]:
        return [
            d
            for d in delivery_ids
            if lease and (h := self._holders.get(d)) is not None and h.token == lease
        ]

    def ack(self, lease: str, delivery_ids: Iterable[int]) -> list[int]:
        """Take messages off the queue (a tool call returned them) and
        remember their keys as handled. Only the ids ``lease`` holds, or
        held last if nobody leased them since: an id never leased, or leased
        again by another caller, is refused. The ids acknowledged."""
        store = self._queue()
        done = []
        for delivery_id in self._held(lease, delivery_ids):
            del self._holders[delivery_id]
            if store.adapter_event_finish(self.name, delivery_id):
                done.append(delivery_id)
        return done

    def release(self, lease: str, delivery_ids: Iterable[int]) -> None:
        """End ``lease``'s hold early: the messages are queued again for any
        waiter. Ids it doesn't hold are left alone."""
        for delivery_id in self._held(lease, delivery_ids):
            del self._holders[delivery_id]
        self._changed.set()
