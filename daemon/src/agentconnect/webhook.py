"""The webhook adapter: POST every message and event to a callback URL.

Delivery is **at least once**:

* Messages go through the daemon's delivery loop, which keeps them in order
  and in its durable inbound queue until :meth:`WebhookAdapter.deliver`
  returns ``ACK``. A 2xx response is an ack; any other response, a timeout
  or a connection error is ``RETRY``, and the daemon retries with
  exponential backoff on its clock. Nothing later is delivered before it.
* Events (``member_joined``, ``epoch_changed``, ``loop_guard``, ...) are
  posted at once. If that fails, they wait in a bounded in-memory queue with
  the same retry rule, and ``on_event`` raises, so the daemon keeps the event
  unnotified and sends it again after a reconnect or restart (ADR-004). The
  repeat carries the same ``event_id``.

A receiver can therefore see a payload twice (the ack was lost) and must
treat ``msg_id`` / ``event_id`` as idempotency keys. The Python SDK does.

Every request is signed: ``X-AgentConnect-Signature: v0=<hex>`` is
HMAC-SHA256 over ``<timestamp>.<body>`` with the adapter's secret, and
``X-AgentConnect-Timestamp`` is the Unix time in seconds. Each attempt is
signed afresh, so a captured request stops verifying after the receiver's
skew window (5 minutes in the SDK).

The callback is loopback unless the config opts in (``webhook.allow_remote``)
and then it must be ``https``; redirects are never followed. With
``webhook.callback_socket`` it is a Unix socket instead, and the receiver's
server must run as the expected user before a byte is written
(:func:`agentconnect.sockets.receiver_async_transport`): anything else is a
``RETRY``, so another local user can neither read a delivery nor ack it
away.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections import deque
from typing import Any, override
from urllib.parse import urlsplit

import httpx

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
from agentconnect.clock import Clock, unix_seconds
from agentconnect.payloads import encode, event_payload, message_payload
from agentconnect.sockets import PeerMismatchError
from agentconnect.tasks import cancel_and_wait

LOG = log.get("agentconnect.webhook")

SIGNATURE_HEADER = "X-AgentConnect-Signature"
TIMESTAMP_HEADER = "X-AgentConnect-Timestamp"
SIGNATURE_VERSION = "v0"
SECRET_FILE = "webhook-secret"  # noqa: S105 - a file name
# The URL a socket receiver is sent to when no callback_url names its path.
SOCKET_URL = "http://localhost/"
EVENT_QUEUE_LIMIT = 1000


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """``v0=<hex>``: HMAC-SHA256 over ``<timestamp>.<body>``."""
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return f"{SIGNATURE_VERSION}={mac.hexdigest()}"


class WebhookAdapter:
    """Implements :class:`agentconnect.adapter.Adapter` over HTTP POST."""

    name = "webhook"

    def __init__(  # noqa: PLR0913
        self,
        url: str,
        secret: str,
        clock: Clock,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 10.0,
        backoff: Backoff | None = None,
    ) -> None:
        self.url = url
        self._secret = secret
        self._clock = clock
        self._transport, self._timeout = transport, timeout
        self._client: httpx.AsyncClient | None = None
        self._backoff = backoff or Backoff(base=1.0, cap=300.0)
        self._events: deque[dict[str, Any]] = deque()
        self._wake = asyncio.Event()
        self._worker: asyncio.Task[None] | None = None
        self._inflight = 0
        self._quiet = asyncio.Event()
        self._quiet.set()

    @property
    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=self._transport,
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
            )
        return self._client

    @override
    def __repr__(self) -> str:
        host = urlsplit(self.url).netloc
        return f"WebhookAdapter(host={host!r})"

    def capabilities(self) -> Capabilities:
        return Capabilities(accepts=["text", "data"], originates=False)

    async def on_outbound(self, send: OutboundSend) -> None:
        # Outbound messages go through the local API; start the event worker.
        self._ensure_worker()

    def _ensure_worker(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.get_running_loop().create_task(self._run_events())

    async def drain(self) -> None:
        """Wait until no request is in flight (for orderly shutdown in tests)."""
        await self._quiet.wait()

    async def close(self) -> None:
        try:
            if self._worker is not None:
                await cancel_and_wait(self._worker)
                self._worker = None
        finally:
            if self._client is not None:
                await self._client.aclose()
                self._client = None

    async def _post(self, payload: dict[str, Any]) -> bool:
        body = encode(payload)
        stamp = str(unix_seconds(self._clock))
        headers = {
            "content-type": "application/json",
            TIMESTAMP_HEADER: stamp,
            SIGNATURE_HEADER: sign(self._secret, stamp, body),
        }
        self._inflight += 1
        self._quiet.clear()
        try:
            resp = await self._http.post(self.url, content=body, headers=headers)
        except PeerMismatchError as e:
            # Not the agent's receiver: nothing was sent; the path and both
            # UIDs, never the delivery.
            LOG.warning("webhook_receiver_refused", reason=str(e))
            return False
        except httpx.HTTPError as e:
            LOG.warning("webhook_unreachable", error=type(e).__name__)
            return False
        finally:
            self._inflight -= 1
            if self._inflight == 0:
                self._quiet.set()
        if 200 <= resp.status_code < 300:  # noqa: PLR2004
            return True
        LOG.warning("webhook_rejected", status=resp.status_code)
        return False

    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        ok = await self._post(message_payload(group, inner))
        return DeliveryResult.ACK if ok else DeliveryResult.RETRY

    async def on_event(self, group: GroupView | None, event: Event) -> None:
        """Send the event now when nothing is waiting ahead of it. If that
        fails, or earlier events are still queued (order), queue it for the
        retry worker and raise: the daemon then keeps the event unnotified
        and sends it again after a reconnect or restart. The receiver dedupes
        by ``event_id``, so the repeat is harmless."""
        payload = event_payload(group, event)
        if not self._events and await self._post(payload):
            return
        if all(p["event_id"] != event.event_id for p in self._events):
            if len(self._events) >= EVENT_QUEUE_LIMIT:
                self._events.popleft()
                LOG.warning("webhook_event_dropped")
            self._events.append(payload)
        self._wake.set()
        self._ensure_worker()
        msg = "webhook not reachable"
        raise ConnectionError(msg)

    async def _run_events(self) -> None:
        while True:
            self._wake.clear()
            while self._events:
                head = self._events[0]
                if await self._post(head):
                    if self._events and self._events[0] is head:
                        self._events.popleft()
                    self._backoff.reset()
                else:
                    await self._clock.sleep(self._backoff.next())
            await self._wake.wait()
