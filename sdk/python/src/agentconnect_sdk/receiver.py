"""Receiving deliveries: a small webhook HTTP server and an SSE line parser.

The server speaks just enough HTTP/1.1 for the daemon's POST (one request per
connection, ``Content-Length`` bodies, at most 1 MiB). It binds to loopback by
default. Put a real web framework in front instead if you need TLS or other
routes: call :meth:`agentconnect_sdk.AgentConnect.receive` from your handler.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import stat
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentconnect.limits import MAX_PAYLOAD_DEPTH, loads
from agentconnect_sdk import _log
from agentconnect_sdk.errors import AgentConnectError, PayloadError, SignatureError
from agentconnect_sdk.signature import WebhookVerifier

MAX_BODY = 1 << 20
MAX_HEADER = 16 << 10
READ_TIMEOUT = 15.0  # seconds to send a whole request

STATUS_TEXT = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    405: "Method Not Allowed",
    408: "Request Timeout",
    413: "Payload Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
}

# (payload) -> "handled" | "duplicate" | "busy"
Dispatch = Callable[[dict[str, Any]], Awaitable[str]]


class WebhookReceiver:
    """Serves one webhook endpoint for an :class:`~agentconnect_sdk.AgentConnect`.

    The status it answers with is the ack: 200 for a handled or already
    handled payload, 503 when the same id is still being handled, 500 when
    the handler raised (the daemon redelivers), 401 for a request that is not
    authentic, 400 for a malformed body.

    With ``path`` it listens on a Unix socket there instead (mode 0660, so
    the daemon's user can connect through the group of a setgid directory in
    the separate-OS-user mode). The daemon checks the user serving it before
    it sends a delivery (``webhook.callback_socket``).
    """

    def __init__(
        self,
        dispatch: Dispatch,
        verifier: WebhookVerifier,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        path: Path | None = None,
    ) -> None:
        self._dispatch = dispatch
        self._verifier = verifier
        self._host, self._port = host, port
        self.path = path
        self._server: asyncio.Server | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None or not self._server.sockets:
            msg = "the receiver is not started"
            raise RuntimeError(msg)
        host, port = self._server.sockets[0].getsockname()[:2]
        return str(host), int(port)

    async def start(self) -> None:
        if self.path is None:
            self._server = await asyncio.start_server(
                self._serve, self._host, self._port, limit=MAX_HEADER
            )
            return
        with contextlib.suppress(FileNotFoundError):
            if not stat.S_ISSOCK(self.path.lstat().st_mode):
                msg = f"{self.path} exists and is not a socket; refusing to replace it"
                raise AgentConnectError("bad_config", msg)
            self.path.unlink()  # left behind by an earlier run
        old = os.umask(0o007)  # never connectable by others, not even briefly
        try:
            self._server = await asyncio.start_unix_server(self._serve, self.path, limit=MAX_HEADER)
        finally:
            os.umask(old)
        self.path.chmod(0o660)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            close_clients = getattr(self._server, "close_clients", None)  # Python 3.13+
            if close_clients is not None:
                close_clients()  # connections accepted but not yet served
            await self._server.wait_closed()
            self._server = None
            if self.path is not None:
                self.path.unlink(missing_ok=True)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._respond(reader, writer)
        finally:
            writer.close()  # also when the handler is cancelled mid-request

    async def _respond(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            status, payload = await self._handle(reader)
        except Exception as e:
            _log.LOG.error("webhook_failed: %s", type(e).__name__)
            status, payload = 500, {"status": "error"}
        data = json.dumps(payload).encode()
        writer.write(
            f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'Error')}\r\n"
            f"content-type: application/json\r\ncontent-length: {len(data)}\r\n"
            "connection: close\r\n\r\n".encode()
            + data
        )
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await writer.wait_closed()

    async def _handle(  # noqa: PLR0911
        self, reader: asyncio.StreamReader
    ) -> tuple[int, dict[str, Any]]:
        try:
            async with asyncio.timeout(READ_TIMEOUT):
                method, headers, body = await _read_request(reader)
        except TimeoutError:
            return 408, {"status": "timeout"}
        except _TooLargeError:
            return 413, {"status": "too_large"}
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            return 400, {"status": "bad_request"}
        if method != "POST":
            return 405, {"status": "method_not_allowed"}
        try:
            self._verifier.verify(headers, body)
        except SignatureError as e:
            return 401, {"status": "unauthorized", "reason": type(e).__name__}
        try:
            payload = loads(body, MAX_PAYLOAD_DEPTH)
            if not isinstance(payload, dict):
                raise PayloadError("body must be an object")
            result = await self._dispatch(payload)
        except (ValueError, PayloadError):
            return 400, {"status": "bad_request"}
        except Exception as e:
            # The handler failed: not an ack, so the daemon redelivers. The
            # type only: its text may quote the message it was handling.
            _log.LOG.error("handler_failed: %s", type(e).__name__)
            return 500, {"status": "handler_error"}
        return (503, {"status": "busy"}) if result == "busy" else (200, {"status": result})


class _TooLargeError(Exception):
    pass


async def _read_request(reader: asyncio.StreamReader) -> tuple[str, dict[str, str], bytes]:
    head = await reader.readuntil(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    method = lines[0].split(" ", 1)[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0") or 0)
    if length < 0 or length > MAX_BODY:
        raise _TooLargeError
    return method, headers, await reader.readexactly(length) if length else b""


@dataclass(frozen=True)
class SseFrame:
    id: str | None
    event: str
    data: str


async def iter_sse(lines: AsyncIterator[str]) -> AsyncIterator[SseFrame]:
    """Parse ``text/event-stream`` lines into frames. Comments (``:``) are
    skipped; a blank line ends a frame; a frame without data is dropped."""
    event_id: str | None = None
    event = "message"
    data: list[str] = []
    async for line in lines:
        if line == "":
            if data:
                yield SseFrame(event_id, event, "\n".join(data))
            event_id, event = None, "message"
            data = []
        elif line.startswith(":"):
            continue
        else:
            name, _, value = line.partition(":")
            value = value.removeprefix(" ")
            if name == "id":
                event_id = value
            elif name == "event":
                event = value
            elif name == "data":
                data.append(value)
