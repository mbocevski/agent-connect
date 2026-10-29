"""A small ASGI server on loopback (uvicorn), started and stopped in-process.

uvicorn's own ``serve()`` installs signal handlers (the daemon owns those)
and polls; this runs only its startup, and stops by closing the listener
and cancelling the connections' tasks. :class:`UnixServer` serves a Unix
socket instead, and accepts a connection only from an admitted user: one
from anyone else is closed at ``accept()``, before a byte is read.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, override

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
        await self._serve_on(sock)
        self.port = int(sock.getsockname()[1])
        return self.port

    async def _serve_on(self, sock: socket.socket) -> None:
        config = uvicorn.Config(
            self._app, lifespan="off", access_log=False, log_level="warning", log_config=None
        )
        config.load()
        server = uvicorn.Server(config)
        server.lifespan = config.lifespan_class(config)
        await server.startup(sockets=[sock])
        self._server = server

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


class _AdmittingSocket(socket.socket):
    """A listening socket whose ``accept()`` closes a connection that
    ``admit`` refuses: asyncio drops it as aborted, and nothing it sent is
    ever read."""

    admit: Callable[[socket.socket], bool]

    @override
    def accept(self) -> tuple[socket.socket, Any]:
        conn, addr = super().accept()
        if not self.admit(conn):
            conn.close()
            msg = "connection refused: its user is not admitted"
            raise ConnectionAbortedError(msg)
        return conn, addr


class UnixServer(LoopbackServer):
    """The ASGI app on a Unix socket at ``path``, created 0600 (0660 with
    the group ``gid`` when given). ``admit`` sees each connected socket
    before anything is read from it."""

    def __init__(
        self,
        app: Any,
        path: Path,
        admit: Callable[[socket.socket], bool],
        gid: int | None = None,
    ) -> None:
        super().__init__(app)
        self.path, self._admit, self._gid = path, admit, gid

    @override
    async def start(self) -> int:
        with contextlib.suppress(FileNotFoundError):
            if not stat.S_ISSOCK(self.path.lstat().st_mode):
                msg = f"{self.path} exists and is not a socket; refusing to replace it"
                raise FileExistsError(msg)
            self.path.unlink()  # left behind by an earlier run
        sock = _AdmittingSocket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.admit = self._admit
        old = os.umask(0o077)  # never connectable by others, not even briefly
        try:
            sock.bind(str(self.path))
        except OSError:
            sock.close()
            raise
        finally:
            os.umask(old)
        if self._gid is not None:
            os.chown(self.path, -1, self._gid)
            self.path.chmod(0o660)
        else:
            self.path.chmod(0o600)
        await self._serve_on(sock)
        return 0

    @override
    async def stop(self) -> None:
        await super().stop()
        self.path.unlink(missing_ok=True)
