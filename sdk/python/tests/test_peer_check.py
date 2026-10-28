"""Attach mode checks the daemon's socket before sending the token (SR-09).

The server's credentials are injected; ``daemon/tests/test_local_transport.py``
covers the transport itself.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentconnect.api_tls import CERT_FILE, KEY_FILE, ensure_certificate
from agentconnect.clock import SystemClock
from agentconnect.isolation import PeerCred
from agentconnect_sdk import AgentConnect, AgentConnectError

OTHER_UID = os.geteuid() + 1


class Server:
    """A Unix socket server on a thread that records what each of its
    connections sent before the client closed."""

    def __init__(self, path: Path, connections: int) -> None:
        self.path = path
        self.received: list[bytes] = []
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(path))
        self._sock.listen(connections)
        self._thread = threading.Thread(target=self._serve, args=(connections,), daemon=True)
        self._thread.start()

    def _serve(self, connections: int) -> None:
        for _ in range(connections):
            conn, _ = self._sock.accept()
            with conn:
                data = b""
                while chunk := conn.recv(65536):
                    data += chunk
                self.received.append(data)

    def done(self) -> list[bytes]:
        self._thread.join(timeout=5)
        assert not self._thread.is_alive(), "the client never connected or closed"
        self._sock.close()
        return self.received


@pytest.fixture
def short_dir() -> Iterator[Path]:
    # /tmp, not $TMPDIR: socket paths are limited to about 100 bytes.
    d = Path(tempfile.mkdtemp(prefix="ac-sdk-", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def test_attach_refuses_another_users_socket(
    isolated_env: None, data_dir: Path, short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "agentconnect.isolation.peer_credentials",
        lambda _sock: PeerCred(uid=OTHER_UID, gid=OTHER_UID),
    )
    server = Server(short_dir / "s.sock", connections=2)
    async with AgentConnect(data_dir=data_dir, socket=server.path) as ac:
        with pytest.raises(AgentConnectError) as e:
            await ac.status()
        assert e.value.code == "peer_mismatch"
        with pytest.raises(AgentConnectError) as e:
            await ac.stream()
        assert e.value.code == "peer_mismatch"
    assert server.done() == [b"", b""]


async def test_attach_over_tcp_refuses_a_server_without_the_pinned_certificate(
    isolated_env: None, data_dir: Path, short_dir: Path
) -> None:
    # The daemon's certificate is pinned in the data directory; a squatter
    # on the port presents another one and gets nothing.
    ensure_certificate(data_dir, SystemClock().now())
    ensure_certificate(short_dir, SystemClock().now())
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    got: list[bytes] = []

    def serve() -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(short_dir / CERT_FILE, short_dir / KEY_FILE)
        for _ in range(2):
            raw, _ = listener.accept()
            try:
                with ctx.wrap_socket(raw, server_side=True) as conn:
                    got.append(conn.recv(65536))
            except (ssl.SSLError, OSError):
                got.append(b"")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    async with AgentConnect(data_dir=data_dir, tcp_port=port) as ac:
        with pytest.raises(AgentConnectError) as e:
            await ac.status()
        assert e.value.code == "peer_mismatch"
        with pytest.raises(AgentConnectError) as e:
            await ac.stream()
        assert e.value.code == "peer_mismatch"
    thread.join(timeout=5)
    listener.close()
    assert got == [b"", b""]
