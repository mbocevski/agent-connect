"""The SSE adapter: a hub behind ``GET /v0/events`` (Accept: text/event-stream).

Same payloads as the webhook adapter (:mod:`agentconnect.payloads`), pulled
instead of pushed. Every message and event is appended to a **durable feed**
in the daemon's encrypted database; the SSE ``id`` is the feed's sequence
number. A consumer that reconnects with ``Last-Event-ID`` gets everything after
that id first, whether the daemon restarted meanwhile or not.

Delivery is **at least once**:

* With no consumer connected for a message's group, ``deliver`` returns
  ``RETRY``: the daemon keeps the message in its durable inbound queue, in
  order, and retries with backoff. Nothing is lost while nobody listens.
* Once a consumer is connected, the message is appended to the feed and acked.
  If the consumer dies before handling it, resuming with ``Last-Event-ID``
  replays it from the feed.
* A message or event the daemon hands over again after a crash (same
  ``msg_id`` / ``event_id``) is already in the feed and is not appended twice.
* The feed keeps the last :data:`FEED_KEEP` items. A consumer that is away
  longer than that misses the oldest ones.
* A connection without ``Last-Event-ID`` starts live.

The feed holds message payloads (the plaintext the adapter was given) for as
long as they stay in that window. It lives in ``daemon.sqlite3``, which is
encrypted at rest (ADR-003).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
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
from agentconnect.clock import Clock, SystemClock, unix_seconds
from agentconnect.payloads import event_payload, message_payload
from agentconnect.tasks import cancel_and_wait

FEED_KEEP = 10_000
RETENTION_SECS = 3600
GAP_EVENT = "sse_gap"
MAX_PURGE_INTERVAL = 60.0
SUBSCRIBER_QUEUE = 1024


class Feed(Protocol):
    """The durable feed (``Store`` implements it)."""

    def feed_add(
        self, key: str, group_id: str | None, payload: dict[str, Any], now: int
    ) -> int | None: ...

    def feed_purge(self, before: int) -> int: ...

    def feed_purged(self) -> int: ...

    def feed_since(
        self, after: int, group_id: str | None = None, limit: int = ...
    ) -> list[tuple[int, str | None, dict[str, Any]]]: ...

    def feed_last(self) -> int: ...


@dataclass(frozen=True)
class Item:
    seq: int
    group_id: str | None
    payload: dict[str, Any]

    @property
    def id(self) -> str:
        return str(self.seq)

    def frame(self) -> bytes:
        """One SSE frame (the JSON is on a single ``data:`` line)."""
        data = json.dumps(self.payload, sort_keys=True, separators=(",", ":"))
        return f"id: {self.id}\nevent: {self.payload['event']}\ndata: {data}\n\n".encode()


@dataclass(eq=False)
class Subscription:
    """One connected consumer. ``queue`` gets the replay first, then live items."""

    group_id: str | None
    queue: asyncio.Queue[Item] = field(default_factory=lambda: asyncio.Queue(SUBSCRIBER_QUEUE))
    overflowed: bool = False

    def wants(self, item: Item) -> bool:
        return self.group_id is None or item.group_id == self.group_id


class SseAdapter:
    """Implements :class:`agentconnect.adapter.Adapter` for stream consumers."""

    name = "sse"

    def __init__(
        self,
        clock: Clock | None = None,
        retention: int = RETENTION_SECS,
        feed: Feed | None = None,
    ) -> None:
        self._clock: Clock = clock or SystemClock()
        self._retention = retention
        self._feed = feed
        self._purger: asyncio.Task[None] | None = None
        self._subs: set[Subscription] = set()
        self._changed = asyncio.Event()

    def bind_store(self, feed: Feed) -> None:
        """Called by the daemon at start with its store."""
        self._feed = feed

    @property
    def feed(self) -> Feed:
        if self._feed is None:
            msg = "the SSE adapter has no feed: the daemon binds its store at start"
            raise RuntimeError(msg)
        return self._feed

    def capabilities(self) -> Capabilities:
        return Capabilities(accepts=["text", "data"], originates=False)

    async def on_outbound(self, send: OutboundSend) -> None:
        self.purge()  # whatever expired while the daemon was down
        if self._purger is None or self._purger.done():
            self._purger = asyncio.get_running_loop().create_task(self._run_purger())

    def purge(self) -> int:
        """Delete feed items older than the retention window."""
        return self.feed.feed_purge(unix_seconds(self._clock) - self._retention)

    async def _run_purger(self) -> None:
        interval = min(float(self._retention), MAX_PURGE_INTERVAL)
        while True:
            await self._clock.sleep(interval)
            self.purge()

    async def close(self) -> None:
        if self._purger is not None:
            await cancel_and_wait(self._purger)
            self._purger = None

    def _publish(self, key: str, group_id: str | None, payload: dict[str, Any]) -> None:
        self.purge()
        seq = self.feed.feed_add(key, group_id, payload, unix_seconds(self._clock))
        if seq is None:
            return  # handed over again after a crash: already in the feed
        item = Item(seq, group_id, payload)
        for sub in list(self._subs):
            if not sub.wants(item):
                continue
            try:
                sub.queue.put_nowait(item)
            except asyncio.QueueFull:
                # Too slow: drop it. It resumes with Last-Event-ID.
                sub.overflowed = True
                self._subs.discard(sub)

    def has_listener(self, group_id: str) -> bool:
        return any(s.group_id in (None, group_id) for s in self._subs)

    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        if not self.has_listener(group.group_id):
            return DeliveryResult.RETRY
        self._publish(inner.msg_id, group.group_id, message_payload(group, inner))
        return DeliveryResult.ACK

    async def on_event(self, group: GroupView | None, event: Event) -> None:
        self._publish(event.event_id, event.group_id, event_payload(group, event))

    def subscribe(self, group_id: str | None, last_event_id: str | None) -> Subscription:
        """Register a consumer, queueing the replay after ``last_event_id``.

        Synchronous on purpose: no item can slip between the replay and the
        live feed.
        """
        self.purge()
        after = self._resume_point(last_event_id)
        rows = self.feed.feed_since(after, group_id, FEED_KEEP)
        gap = self._gap(last_event_id, after)
        sub = Subscription(group_id, asyncio.Queue(SUBSCRIBER_QUEUE + len(rows) + 1))
        if gap is not None:
            sub.queue.put_nowait(gap)
        for seq, gid, payload in rows:
            sub.queue.put_nowait(Item(seq, gid, payload))
        self._subs.add(sub)
        self._changed.set()
        return sub

    def _gap(self, last_event_id: str | None, after: int) -> Item | None:
        """The ``sse_gap`` item for a consumer that resumed from before the
        retention window: items up to ``missed_through`` are gone. Its ``id``
        is ``missed_through``, so the consumer's resume point moves past the
        hole and it should re-sync from the source of truth."""
        purged = self.feed.feed_purged()
        if last_event_id is None or after >= purged:
            return None
        payload = {
            "event": GAP_EVENT,
            "event_id": f"{GAP_EVENT}-{purged}",
            "group": None,
            "untrusted": True,
            "data": {"missed_through": purged, "resumed_from": after},
        }
        return Item(purged, None, payload)

    def unsubscribe(self, sub: Subscription) -> None:
        self._subs.discard(sub)
        self._changed.set()

    async def wait_listeners(self, count: int) -> None:
        """Wait until exactly ``count`` consumers are connected (for tests)."""
        while len(self._subs) != count:
            self._changed.clear()
            await self._changed.wait()

    def _resume_point(self, last_event_id: str | None) -> int:
        """The feed ``seq`` to resume after. No (or a malformed) id starts
        live, with no replay."""
        if last_event_id is None or not last_event_id.isascii() or not last_event_id.isdigit():
            return self.feed.feed_last()
        return int(last_event_id)
