"""A small ASGI server on loopback (uvicorn), started and stopped in-process.

uvicorn's own ``serve()`` installs signal handlers (the daemon owns those)
and polls; this runs only its startup, and stops by closing the listener
and cancelling the connections' tasks. :class:`UnixServer` serves a Unix
socket instead, and serves a connection only from an admitted user: one
from anyone else is aborted as the protocol is told of it, before any data
is handed to it. That holds on any event loop (asyncio, uvloop).
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
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

    async def _serve_on(
        self, sock: socket.socket, admit: Callable[[Any], bool] | None = None
    ) -> None:
        config = uvicorn.Config(
            self._app, lifespan="off", access_log=False, log_level="warning", log_config=None
        )
        config.load()
        if admit is not None:
            config.http_protocol_class = _admitting(config.http_protocol_class, admit)
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


def _admitting(base: Any, admit: Callable[[Any], bool]) -> Any:
    """uvicorn's HTTP protocol, checking each connection with ``admit``
    (given the connection's socket) when it is made. A refused one is
    aborted there, and the protocol never sees data from it. This is the
    protocol, not the listening socket's ``accept()``, so every event loop
    goes through it (uvloop accepts in C)."""

    class Admitting(base):
        _refused = False

        def connection_made(self, transport: Any) -> None:
            if not admit(transport.get_extra_info("socket")):
                self._refused = True
                transport.abort()
                return
            super().connection_made(transport)

        def data_received(self, data: bytes) -> None:
            if not self._refused:
                super().data_received(data)

        def eof_received(self) -> None:
            if not self._refused:
                super().eof_received()

        def connection_lost(self, exc: Exception | None) -> None:
            if not self._refused:
                super().connection_lost(exc)

    return Admitting


def _private_parent(path: Path) -> None:
    """The socket's directory must be a real directory of this user that
    nobody else can write to: otherwise another user could replace the
    socket, or swap it for a link, after it is bound."""
    st = path.parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
        msg = f"{path.parent} must be a directory owned by this user that only it can write to"
        raise PermissionError(msg)


def _in_use(path: Path) -> bool:
    """Whether a server is listening on the socket at ``path``. The probe
    never blocks: a listener whose queue is full is in use, and only a
    refused connection (or no socket) is stale. macOS answers a full queue
    with a refusal too, so there such a listener reads as stale."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.setblocking(False)
        code = probe.connect_ex(str(path))
    return code not in (errno.ECONNREFUSED, errno.ENOENT)


class UnixServer(LoopbackServer):
    """The ASGI app on a Unix socket at ``path``, 0600 (0660 with the group
    ``gid`` when given), in a directory only this user can write to.
    ``admit`` sees each connection's socket before anything is read from
    it."""

    def __init__(
        self,
        app: Any,
        path: Path,
        admit: Callable[[Any], bool],
        gid: int | None = None,
    ) -> None:
        super().__init__(app)
        self.path, self._admit, self._gid = path, admit, gid

    @override
    async def start(self) -> int:
        _private_parent(self.path)
        with contextlib.suppress(FileNotFoundError):
            if not stat.S_ISSOCK(self.path.lstat().st_mode):
                msg = f"{self.path} exists and is not a socket; refusing to replace it"
                raise FileExistsError(msg)
            if _in_use(self.path):
                msg = f"{self.path} is in use by a running server; refusing to replace it"
                raise FileExistsError(msg)
            self.path.unlink()  # left behind by an earlier run
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # The umask is process-wide, so it is left alone: the mode is set
        # right after bind, in a directory only this user can write to (so
        # the path is still the socket). Until then, as after, the peer check
        # decides who is served.
        try:
            sock.bind(str(self.path))
            if not stat.S_ISSOCK(self.path.lstat().st_mode):
                msg = f"{self.path} was replaced while it was bound; refusing to use it"
                raise FileExistsError(msg)
        except OSError:
            sock.close()
            raise
        if self._gid is not None:
            os.chown(self.path, -1, self._gid, follow_symlinks=False)
            self.path.chmod(0o660)
        else:
            self.path.chmod(0o600)
        await self._serve_on(sock, self._admit)
        return 0

    @override
    async def stop(self) -> None:
        await super().stop()
        self.path.unlink(missing_ok=True)
