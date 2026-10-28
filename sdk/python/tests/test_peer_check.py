"""Attach mode checks the daemon's socket before sending the token (SR-09).

The server's credentials are injected; ``daemon/tests/test_local_transport.py``
covers the transport itself.
"""

from __future__ import annotations

import os
import shutil
import socket
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

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
    d = Path(tempfile.mkdtemp(prefix="ac-sdk-"))
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
