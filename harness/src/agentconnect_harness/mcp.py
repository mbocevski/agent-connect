"""A stdio MCP client, and ``agentconnect mcp`` servers for it to drive.

* :class:`McpClient` is a minimal JSON-RPC 2.0 client over two pipes, the
  way an agent tool talks to the MCP server it spawned: one JSON message per
  line, ``initialize`` and ``notifications/initialized``, ``tools/list``,
  ``tools/call`` and ``notifications/cancelled``. It drives a subprocess
  (``agentconnect mcp``) or a server in this process the same way.
* :class:`McpInstance` runs :class:`~agentconnect.mcp.McpServer` (what the
  command runs) in this process over real OS pipes, on the cluster's fake
  clock and seeded randomness, so a scenario can stop it with stdin EOF and
  start it again on the same data directory.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentconnect.clock import FakeClock
from agentconnect.config import Config
from agentconnect.deliveries import DeliveryQueue
from agentconnect.identity import Seeded
from agentconnect.keystore import FileKeystore
from agentconnect.mcp import McpServer
from agentconnect.mcp.backend import HostBackend
from agentconnect.runtime.engine import Engine, Options

WAIT = 8.0  # real-time guard for every wait; nothing sleeps
PROTOCOL = "2025-11-25"


class McpError(Exception):
    """A JSON-RPC error answer."""

    def __init__(self, error: dict[str, Any]) -> None:
        super().__init__(str(error.get("message", "")))
        self.code = error.get("code")


@dataclass
class ToolResult:
    data: dict[str, Any]
    is_error: bool
    text: str


class McpClient:
    """JSON-RPC over a reader (the server's stdout) and a writer (its stdin)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.WriteTransport) -> None:
        self._reader, self._writer = reader, writer
        self._ids = itertools.count(1)
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.answered: set[int] = set()
        self.notifications: list[dict[str, Any]] = []
        self._task = asyncio.ensure_future(self._read())

    @classmethod
    async def over(cls, read_fd: int, write_fd: int) -> McpClient:
        """A client reading the server's output from ``read_fd`` and writing
        its input to ``write_fd`` (both pipe ends; closing the client closes
        them)."""
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=4 << 20)
        await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(read_fd, "rb", buffering=0)
        )
        writer, _ = await loop.connect_write_pipe(
            asyncio.BaseProtocol, os.fdopen(write_fd, "wb", buffering=0)
        )
        return cls(reader, writer)

    async def _read(self) -> None:
        while line := await self._reader.readline():
            msg = json.loads(line)
            if "id" in msg and ("result" in msg or "error" in msg):
                self.answered.add(int(msg["id"]))
                future = self._pending.pop(int(msg["id"]), None)
                if future is not None and not future.done():
                    future.set_result(msg)
            else:
                self.notifications.append(msg)
        for future in self._pending.values():
            if not future.done():
                future.set_exception(ConnectionError("the server closed its output"))

    def _send(self, msg: dict[str, Any]) -> None:
        self._writer.write(json.dumps({"jsonrpc": "2.0", **msg}).encode() + b"\n")

    def send_raw(self, line: bytes) -> None:
        self._writer.write(line)

    def start_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> tuple[int, asyncio.Future[dict[str, Any]]]:
        request_id = next(self._ids)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        msg: dict[str, Any] = {"id": request_id, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)
        return request_id, future

    async def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        _, future = self.start_request(method, params)
        reply = await asyncio.wait_for(future, WAIT)
        if "error" in reply:
            raise McpError(reply["error"])
        result: dict[str, Any] = reply["result"]
        return result

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def cancel(self, request_id: int) -> None:
        self.notify("notifications/cancelled", {"requestId": request_id, "reason": "test"})

    async def initialize(self) -> dict[str, Any]:
        info = await self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "harness", "version": "0"},
            },
        )
        self.notify("notifications/initialized")
        return info

    async def tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = (await self.request("tools/list"))["tools"]
        return tools

    @staticmethod
    def result(raw: dict[str, Any]) -> ToolResult:
        text = "".join(c.get("text", "") for c in raw.get("content", []))
        data = raw.get("structuredContent")
        return ToolResult(data if isinstance(data, dict) else {}, bool(raw.get("isError")), text)

    async def call(self, name: str, args: dict[str, Any] | None = None) -> ToolResult:
        raw = await self.request("tools/call", {"name": name, "arguments": args or {}})
        return self.result(raw)

    async def ok(self, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """A tool call that must succeed; its structured result."""
        result = await self.call(name, args)
        if result.is_error or json.loads(result.text) != result.data:
            msg = f"{name}: {result.text}"
            raise AssertionError(msg)
        return result.data

    def close(self) -> None:
        """EOF on the server's stdin: the server stops."""
        self._writer.close()

    async def finished(self) -> None:
        """Wait until the server's output ends."""
        await asyncio.wait_for(asyncio.shield(self._task), WAIT)


@dataclass
class McpInstance:
    """``agentconnect mcp`` in this process, over OS pipes."""

    name: str
    config: Config
    clock: FakeClock
    seed: int
    starts: int = 0
    server: McpServer = field(init=False)
    client: McpClient = field(init=False)
    _task: asyncio.Task[None] | None = None
    _fds: list[int] = field(default_factory=list)

    def _options(self) -> Options:
        self.starts += 1
        seed = self.seed + self.starts
        return Options(testing=Seeded(seed), backoff_rng=random.Random(seed))  # noqa: S311

    async def start(self) -> McpClient:
        to_server_r, to_server_w = os.pipe()
        from_server_r, from_server_w = os.pipe()
        self._fds = [to_server_r, from_server_w]
        self.server = McpServer(
            self.config,
            clock=self.clock,
            keystore=FileKeystore(self.config.data_dir / "keys"),
            options=self._options(),
            stdin=to_server_r,
            stdout=from_server_w,
        )
        ready = asyncio.Event()
        self._task = asyncio.ensure_future(self.server.run(ready))
        waiting = asyncio.ensure_future(ready.wait())
        await asyncio.wait({waiting, self._task}, timeout=WAIT, return_when=asyncio.FIRST_COMPLETED)
        if not ready.is_set():
            waiting.cancel()
            await self._task  # raises what stopped it
        self.client = await McpClient.over(from_server_r, to_server_w)
        await self.client.initialize()
        return self.client

    @property
    def mode(self) -> str:
        return self.server.session.mode

    @property
    def host(self) -> HostBackend:
        backend = self.server.session.backend
        if not isinstance(backend, HostBackend):
            msg = f"{self.name} doesn't host the runtime"
            raise TypeError(msg)
        return backend

    @property
    def engine(self) -> Engine:
        return self.host.runtime._engine

    @property
    def queue(self) -> DeliveryQueue:
        return self.host.queue

    @property
    def data_dir(self) -> Path:
        return self.config.data_dir

    async def wait(self, predicate: Any, within: float = WAIT) -> None:
        await self.engine.wait_until(predicate, within)

    async def stop(self) -> None:
        """Stdin EOF, as when the agent tool ends the session."""
        if self._task is None:
            return
        task, self._task = self._task, None
        self.client.close()
        try:
            await asyncio.wait_for(task, WAIT)
        finally:
            for fd in self._fds:
                with contextlib.suppress(OSError):
                    os.close(fd)
            self._fds = []
        await self.client.finished()

    async def restart(self) -> McpClient:
        await self.stop()
        return await self.start()
