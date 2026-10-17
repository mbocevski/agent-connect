"""A small ASGI server on loopback (uvicorn), started and stopped in-process.

uvicorn's own ``serve()`` installs signal handlers (the daemon owns those)
and polls; this runs only its startup, and stops by closing the listener
and cancelling the connections' tasks.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import uvicorn

LOOPBACK = "127.0.0.1"


class LoopbackServer:
    def __init__(self, app: Any, port: int = 0) -> None:
        self._app = app
        self._port = port
        self._server: uvicorn.Server | None = None
        self.port = 0

    async def start(self) -> int:
        """Listen on ``127.0.0.1:<port>`` (0: any free port); returns it."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((LOOPBACK, self._port))
        except OSError:
            sock.close()
            raise
        config = uvicorn.Config(
            self._app, lifespan="off", access_log=False, log_level="warning", log_config=None
        )
        config.load()
        server = uvicorn.Server(config)
        server.lifespan = config.lifespan_class(config)
        await server.startup(sockets=[sock])
        self._server = server
        self.port = int(sock.getsockname()[1])
        return self.port

    def addresses(self) -> list[tuple[str, int]]:
        """Where it listens (host, port)."""
        if self._server is None:
            return []
        return [
            (str(s.getsockname()[0]), int(s.getsockname()[1]))
            for listener in self._server.servers
            for s in listener.sockets
        ]

    async def stop(self) -> None:
        server, self._server = self._server, None
        if server is None:
            return
        for listener in server.servers:
            listener.close()
        for connection in list(server.server_state.connections):
            connection.shutdown()
        tasks = list(server.server_state.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
