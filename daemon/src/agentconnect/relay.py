"""The relay link: a persistent WebSocket (SPEC §8.2) and signed REST (§8.1.1).

The WebSocket authenticates with the instance key, reconnects with
exponential backoff and jitter (timed by the injectable clock), and hands
every server frame to the daemon. Replies (``accepted``/``error``) are
matched to requests by ``msg_id``. Nothing polls: the relay pushes queued
``deliver`` frames on (re)connect and as they arrive.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

import httpx
import websockets
from websockets.asyncio.client import ClientConnection, connect

import agentconnect_core as ac
from agentconnect import log
from agentconnect.backoff import Backoff
from agentconnect.clock import Clock, unix_seconds

LOG = log.get("agentconnect.relay")

# The relay's frame limit is 2 MiB of JSON; leave headroom.
MAX_FRAME = 4 << 20
REQUEST_TIMEOUT = 30.0
NONCE_LEN = 32  # SPEC 8.2
DRAIN_KEY = "_drain"  # set on every frame handed to the daemon


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class NotConnectedError(ConnectionError):
    """The relay link is down; the request will be retried after reconnect."""


class RelayError(Exception):
    """An ``error`` frame or REST error from the relay (SPEC §8.4)."""

    def __init__(self, code: str, detail: str = "", current_epoch: int | None = None) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.current_epoch = current_epoch


FrameHandler = Callable[[dict[str, Any]], Awaitable[None]]


class RelayLink:
    """One authenticated WebSocket to the relay, kept up until :meth:`stop`."""

    def __init__(  # noqa: PLR0913
        self,
        url: str,
        relay_host: str,
        instance: ac.Instance,
        clock: Clock,
        on_frame: FrameHandler,
        *,
        backoff: Backoff | None = None,
        on_connected: Callable[[], Coroutine[Any, Any, None]] | None = None,
        on_state: Callable[[], None] | None = None,
    ) -> None:
        self._url = url
        self._host = relay_host
        self._instance = instance
        self._clock = clock
        self._on_frame = on_frame
        self._on_connected = on_connected
        self._on_state = on_state or (lambda: None)
        self.backoff = backoff or Backoff()
        self._ws: ClientConnection | None = None
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._connected = asyncio.Event()
        self._stop = asyncio.Event()
        self.connections = 0
        self.draining = False

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    async def wait_connected(self) -> None:
        await self._connected.wait()

    async def run(self) -> None:
        """Connect, serve, and reconnect forever (until :meth:`stop`)."""
        while not self._stop.is_set():
            try:
                async with connect(
                    self._url, max_size=MAX_FRAME, open_timeout=10, compression=None
                ) as ws:
                    await self._authenticate(ws)
                    self._ws = ws
                    # Until the relay's ``drained`` frame: the reconnect drain.
                    self.draining = True
                    self.connections += 1
                    self.backoff.reset()
                    self._connected.set()
                    LOG.info("relay_connected", connections=self.connections)
                    if self._on_connected is not None:
                        asyncio.get_running_loop().create_task(self._on_connected())
                    async for raw in ws:
                        await self._dispatch(raw)
            except (OSError, websockets.WebSocketException, TimeoutError, ValueError) as e:
                LOG.info("relay_disconnected", reason=type(e).__name__)
            except Exception as e:
                # Anything else a relay frame can provoke (a bug included) must
                # not end the link for good: log the type only and reconnect.
                LOG.warning("relay_link_error", reason=type(e).__name__)
            finally:
                self._down()
            if self._stop.is_set():
                break
            delay = self.backoff.next()
            LOG.info("relay_reconnect_scheduled", delay=round(delay, 3))
            sleeping = asyncio.ensure_future(self._clock.sleep(delay))
            await asyncio.sleep(0)  # let the sleep register before announcing it
            self._on_state()
            await sleeping

    def _down(self) -> None:
        self._ws = None
        self._connected.clear()
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(NotConnectedError("relay connection lost"))
        self._pending.clear()
        self._on_state()

    async def _authenticate(self, ws: ClientConnection) -> None:
        """SPEC 8.2. Every malformed frame raises ``ValueError`` (reconnect)."""
        challenge = json.loads(await asyncio.wait_for(ws.recv(), REQUEST_TIMEOUT))
        if not isinstance(challenge, dict) or challenge.get("t") != "challenge":
            msg = "expected a challenge"
            raise ValueError(msg)
        nonce_text = challenge.get("nonce")
        if not isinstance(nonce_text, str):
            msg = "challenge without a nonce"
            raise ValueError(msg)
        try:
            nonce = unb64(nonce_text)
        except (ValueError, TypeError):
            msg = "challenge nonce is not base64url"
            raise ValueError(msg) from None
        if len(nonce) != NONCE_LEN:
            msg = "challenge nonce is not 32 bytes"
            raise ValueError(msg)
        sig = self._instance.sign_relay_challenge(nonce, self._host)
        await ws.send(
            json.dumps({"t": "auth", "sig_key": b64(self._instance.public_key), "sig": b64(sig)})
        )
        ready = json.loads(await asyncio.wait_for(ws.recv(), REQUEST_TIMEOUT))
        if (
            not isinstance(ready, dict)
            or ready.get("t") != "ready"
            or ready.get("mailbox_id") != self._instance.mailbox_id
        ):
            msg = "relay authentication failed"
            raise ValueError(msg)

    async def _dispatch(self, raw: str | bytes) -> None:
        try:
            frame = json.loads(raw)
        except ValueError:
            LOG.warning("relay_frame_unparsable")
            return
        if not isinstance(frame, dict):
            return
        t = frame.get("t")
        if t == "drained":
            self.draining = False
            return
        # Ours, never the relay's: was this frame queued before we connected?
        frame[DRAIN_KEY] = self.draining
        if t in ("accepted", "error"):
            fut = self._pending.pop(str(frame.get("msg_id")), None)
            if fut is not None and not fut.done():
                fut.set_result(frame)
                return
        await self._on_frame(frame)

    async def send(self, frame: dict[str, Any]) -> None:
        """Send without waiting for a reply (acks)."""
        ws = self._ws
        if ws is None:
            raise NotConnectedError("relay link is down")
        try:
            await ws.send(json.dumps(frame, separators=(",", ":")))
        except websockets.WebSocketException as e:
            # The socket is gone, but run() may not have noticed yet. Mark
            # the link down now: a caller that retries after
            # NotConnectedError then waits in wait_connected() instead of
            # failing again without yielding, which would starve the loop
            # (run() included) for good.
            if self._ws is ws:
                self._down()
            raise NotConnectedError(str(e)) from None

    async def request(self, frame: dict[str, Any], msg_id: str) -> dict[str, Any]:
        """Send a frame and wait for the ``accepted``/``error`` with ``msg_id``.

        Raises :class:`NotConnectedError` if the link drops first (the caller
        resends the same frame after reconnecting) and :class:`RelayError`
        for an ``error`` reply.
        """
        if self._ws is None:
            raise NotConnectedError("relay link is down")
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[msg_id] = fut
        try:
            await self.send(frame)
            reply = await asyncio.wait_for(fut, REQUEST_TIMEOUT)
        except TimeoutError:
            raise NotConnectedError("no reply from relay") from None
        finally:
            self._pending.pop(msg_id, None)
        if reply.get("t") == "error":
            raise RelayError(
                str(reply.get("code")), str(reply.get("detail", "")), reply.get("current_epoch")
            )
        return reply

    async def kick(self) -> None:
        """Drop the current connection (it reconnects); used on shutdown."""
        ws = self._ws
        if ws is not None:
            await ws.close()

    async def stop(self) -> None:
        """Go down at once (pending requests fail, nothing new is sent),
        then close the socket."""
        self._stop.set()
        ws = self._ws
        if ws is not None:
            self._down()
            await ws.close()


class RelayRest:
    """Signed REST calls (SPEC §8.1.1): a fresh ``ts`` for every request."""

    def __init__(
        self,
        base_url: str,
        relay_host: str,
        instance: ac.Instance,
        clock: Clock,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._host = relay_host
        self._instance = instance
        self._clock = clock
        self._transport = transport
        self._last_ts = 0

    def _ts(self) -> int:
        # Strictly increasing, so two requests in one second never share a
        # signature (each signed request is single use at the relay).
        ts = max(unix_seconds(self._clock), self._last_ts + 1)
        self._last_ts = ts
        return ts

    def authorization(self, method: str, path: str, body: bytes) -> str:
        ts = self._ts()
        sig = self._instance.sign_relay_request(method, path, ts, body, self._host)
        return f"AgentConnect-Ed25519 {b64(self._instance.public_key)}.{ts}.{b64(sig)}"

    async def _call(self, method: str, path: str, body: bytes = b"", signed: bool = True) -> Any:
        headers = {"content-type": "application/json"}
        if signed:
            headers["authorization"] = self.authorization(method, path, body)
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=REQUEST_TIMEOUT
            ) as http:
                resp = await http.request(method, self._base + path, content=body, headers=headers)
        except httpx.HTTPError as e:
            # Connection refused, DNS, timeouts: all "relay unreachable".
            raise RelayError("relay_unreachable", type(e).__name__) from None
        LOG.debug(
            "relay_rest",
            method=method,
            status=resp.status_code,
            ms=round((time.monotonic() - started) * 1000),
        )
        try:
            data = resp.json() if resp.content else {}
        except ValueError:
            data = None
        if not isinstance(data, dict):
            # A proxy's HTML error page, or a non-object body.
            code = "internal" if resp.status_code >= 400 else "bad_response"  # noqa: PLR2004
            raise RelayError(code, f"HTTP {resp.status_code} without a JSON object")
        if resp.status_code >= 400:  # noqa: PLR2004
            raise RelayError(str(data.get("code", "internal")), str(data.get("detail", "")))
        return data

    async def create_invite(self, meta: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(
            {**meta, "inviter_mailbox": self._instance.mailbox_id}, separators=(",", ":")
        ).encode()
        return await self._call("POST", "/v0/invites", body)

    async def revoke_invite(self, invite_id: str) -> None:
        await self._call("DELETE", f"/v0/invites/{invite_id}")

    async def invite_meta(self, invite_id: str) -> dict[str, Any]:
        return await self._call("GET", f"/v0/invites/{invite_id}", signed=False)
