"""Local-API clients check the daemon before sending a byte (SR-09).

The transport refuses a socket server whose UID isn't the owner of the
directory the token came from, and a short socket directory that isn't
private. The server's credentials are injected, as in ``test_isolation.py``,
so no second OS user is needed; ``test_local_transport_multiuser.py`` runs
the same refusal with a real one.
"""

from __future__ import annotations

import os
import random
import shutil
import socket
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.cli_support import EXIT_REFUSED, map_api_error
from agentconnect.config import Config
from agentconnect.isolation import PeerCred
from agentconnect.mcp.backend import AttachBackend, ToolError
from agentconnect.sockets import (
    MAX_SOCKET_PATH,
    PeerMismatchError,
    bind_path,
    local_async_transport,
    local_transport,
    token_owner,
)
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE

EUID = os.geteuid()
OK = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}"


class Server:
    """A Unix socket server on a thread. It records what its one connection
    sent before the client closed or finished its headers, and answers 200."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.received: list[bytes] = []
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(path))
        self._sock.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        conn, _ = self._sock.accept()
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            self.received.append(data)
            if data:
                conn.sendall(OK)

    def done(self) -> list[bytes]:
        """What the connection sent, once the server has finished with it."""
        self._thread.join(timeout=5)
        assert not self._thread.is_alive(), "the client never connected or closed"
        self._sock.close()
        return self.received


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A short path: Unix socket paths are limited to about 100 bytes."""
    # /tmp, not $TMPDIR: macOS gives long ones, and the short-root tests nest
    # a socket two levels down.
    d = Path(tempfile.mkdtemp(prefix="ac-lt-", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _uid(rng: random.Random) -> int:
    """A UID nobody here runs as."""
    while True:
        uid = rng.randrange(20_000, 60_000)
        if uid != EUID:
            return uid


def as_uid(uid: int) -> Any:
    return lambda _sock: PeerCred(uid=uid, gid=uid)


def token(rng: random.Random) -> str:
    return rng.randbytes(16).hex()


def get(transport: httpx.BaseTransport, secret: str) -> httpx.Response:
    with httpx.Client(transport=transport, base_url="http://agentconnectd") as c:
        return c.get("/v0/status", headers={"authorization": f"Bearer {secret}"})


async def aget(transport: httpx.AsyncBaseTransport, secret: str) -> httpx.Response:
    async with httpx.AsyncClient(transport=transport, base_url="http://agentconnectd") as c:
        return await c.get("/v0/status", headers={"authorization": f"Bearer {secret}"})


# -- the peer check ------------------------------------------------------------


def test_the_token_directory_owner_is_accepted(short_dir: Path, rng: random.Random) -> None:
    server = Server(short_dir / "s.sock")
    secret = token(rng)
    resp = get(local_transport(server.path, short_dir, credentials=as_uid(EUID)), secret)
    assert resp.status_code == 200
    assert secret.encode() in server.done()[0]


async def test_the_token_directory_owner_is_accepted_async(
    short_dir: Path, rng: random.Random
) -> None:
    server = Server(short_dir / "s.sock")
    secret = token(rng)
    transport = local_async_transport(server.path, short_dir, credentials=as_uid(EUID))
    resp = await aget(transport, secret)
    assert resp.status_code == 200
    assert secret.encode() in server.done()[0]


def test_the_real_credentials_accept_our_own_server(short_dir: Path, rng: random.Random) -> None:
    server = Server(short_dir / "s.sock")
    assert get(local_transport(server.path, short_dir), token(rng)).status_code == 200
    server.done()


def test_another_uid_is_refused_before_a_byte_is_sent(short_dir: Path, rng: random.Random) -> None:
    server = Server(short_dir / "s.sock")
    other, secret = _uid(rng), token(rng)
    with pytest.raises(PeerMismatchError) as e:
        get(local_transport(server.path, short_dir, credentials=as_uid(other)), secret)
    assert server.done() == [b""]
    message = str(e.value)
    assert str(other) in message
    assert str(EUID) in message
    assert str(server.path) in message
    assert secret not in message
    assert e.value.code == "peer_mismatch"


async def test_another_uid_is_refused_before_a_byte_is_sent_async(
    short_dir: Path, rng: random.Random
) -> None:
    server = Server(short_dir / "s.sock")
    other, secret = _uid(rng), token(rng)
    transport = local_async_transport(server.path, short_dir, credentials=as_uid(other))
    with pytest.raises(PeerMismatchError) as e:
        await aget(transport, secret)
    assert server.done() == [b""]
    assert str(other) in str(e.value)
    assert secret not in str(e.value)


def test_the_expected_uid_is_the_owner_of_the_token_directory(
    short_dir: Path, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Separate-OS-user mode: the agent's token directory belongs to the
    # daemon's user, so that user's socket is the one accepted.
    daemon_uid = _uid(rng)
    monkeypatch.setattr(
        "agentconnect.sockets.token_owner", lambda d: daemon_uid if d == short_dir else -1
    )
    server = Server(short_dir / "s.sock")
    transport = local_transport(server.path, short_dir, credentials=as_uid(daemon_uid))
    assert get(transport, token(rng)).status_code == 200
    server.done()
    server = Server(short_dir / "t.sock")
    with pytest.raises(PeerMismatchError):
        get(local_transport(server.path, short_dir, credentials=as_uid(EUID)), token(rng))
    assert server.done() == [b""]


def test_unreadable_credentials_are_refused(short_dir: Path, rng: random.Random) -> None:
    def broken(_sock: Any) -> PeerCred:
        raise OSError("no credentials")

    server = Server(short_dir / "s.sock")
    with pytest.raises(PeerMismatchError, match="credentials"):
        get(local_transport(server.path, short_dir, credentials=broken), token(rng))
    assert server.done() == [b""]


def test_no_server_is_a_plain_connect_error(short_dir: Path, rng: random.Random) -> None:
    transport = local_transport(short_dir / "absent.sock", short_dir)
    with pytest.raises(httpx.ConnectError) as e:
        get(transport, token(rng))
    assert not isinstance(e.value, PeerMismatchError)


# -- the short socket directory -----------------------------------------------


def long_socket(tmp_path: Path) -> Path:
    path = tmp_path / ("x" * 80) / ("y" * 40) / "agentconnectd.sock"
    assert len(os.fsencode(path)) > MAX_SOCKET_PATH
    return path


@pytest.fixture
def short_root(short_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = short_dir / "root"
    root.mkdir()
    monkeypatch.setattr("agentconnect.sockets.SHORT_ROOT", root)
    return root


def test_a_private_short_directory_is_used(
    short_root: Path, tmp_path: Path, rng: random.Random
) -> None:
    configured = long_socket(tmp_path)
    mapped = bind_path(configured)
    mapped.parent.mkdir(mode=0o700)
    server = Server(mapped)
    assert get(local_transport(configured, tmp_path), token(rng)).status_code == 200
    server.done()


@pytest.mark.parametrize("mode", [0o777, 0o755, 0o1777])
def test_a_shared_short_directory_is_refused(
    short_root: Path, tmp_path: Path, rng: random.Random, mode: int
) -> None:
    configured = long_socket(tmp_path)
    mapped = bind_path(configured)
    mapped.parent.mkdir()
    mapped.parent.chmod(mode)
    server = Server(mapped)
    with pytest.raises(PeerMismatchError, match="0700"):
        get(local_transport(configured, tmp_path), token(rng))
    # Refused before connecting: unblock the server's accept.
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(str(mapped))
    assert server.done() == [b""]


def test_a_symlinked_short_directory_is_refused(
    short_root: Path, tmp_path: Path, rng: random.Random
) -> None:
    configured = long_socket(tmp_path)
    mapped = bind_path(configured)
    target = short_root / "elsewhere"
    target.mkdir(mode=0o700)
    mapped.parent.symlink_to(target)
    with pytest.raises(PeerMismatchError, match="symlink"):
        get(local_transport(configured, tmp_path), token(rng))


def test_a_short_directory_of_another_owner_is_refused(
    short_root: Path, tmp_path: Path, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = long_socket(tmp_path)
    mapped = bind_path(configured)
    mapped.parent.mkdir(mode=0o700)
    other = _uid(rng)
    monkeypatch.setattr(os, "geteuid", lambda: other)
    monkeypatch.setattr("agentconnect.sockets.bind_path", lambda _p: mapped)
    with pytest.raises(PeerMismatchError, match="owned"):
        get(local_transport(configured, tmp_path), token(rng))


def test_a_non_socket_at_the_short_path_is_refused(
    short_root: Path, tmp_path: Path, rng: random.Random
) -> None:
    configured = long_socket(tmp_path)
    mapped = bind_path(configured)
    mapped.parent.mkdir(mode=0o700)
    mapped.write_bytes(b"")
    with pytest.raises(PeerMismatchError, match="not a socket"):
        get(local_transport(configured, tmp_path), token(rng))


def test_a_missing_short_directory_is_not_running(
    short_root: Path, tmp_path: Path, rng: random.Random
) -> None:
    with pytest.raises(httpx.ConnectError) as e:
        get(local_transport(long_socket(tmp_path), tmp_path), token(rng))
    assert not isinstance(e.value, PeerMismatchError)


# -- the clients use it -------------------------------------------------------


@pytest.fixture
def foreign_server(short_dir: Path, rng: random.Random, monkeypatch: pytest.MonkeyPatch) -> Server:
    """A socket at the data directory's path whose server is another user."""
    other = _uid(rng)
    monkeypatch.setattr("agentconnect.isolation.peer_credentials", as_uid(other))
    for name in (API_TOKEN_FILE, HUMAN_TOKEN_FILE):
        (short_dir / name).write_text(token(rng), encoding="ascii")
    return Server(short_dir / "agentconnectd.sock")


def test_the_cli_client_refuses_a_foreign_server(short_dir: Path, foreign_server: Server) -> None:
    client = ApiClient(Config(relay_url="", relay_host="", data_dir=short_dir), human=True)
    with pytest.raises(ApiClientError) as e:
        client.request("GET", "/v0/status")
    assert e.value.code == "peer_mismatch"
    assert foreign_server.done() == [b""]
    err = map_api_error(e.value)
    assert (err.code, err.exit_code) == ("peer_mismatch", EXIT_REFUSED)
    assert str(foreign_server.path) in err.message


def test_a_configured_socket_is_checked_too(
    foreign_server: Server, tmp_path: Path, rng: random.Random
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / API_TOKEN_FILE).write_text(token(rng), encoding="ascii")
    cfg = Config(relay_url="", relay_host="", data_dir=data, api_socket=foreign_server.path)
    with pytest.raises(ApiClientError) as e:
        ApiClient(cfg).request("GET", "/v0/status")
    assert e.value.code == "peer_mismatch"
    assert foreign_server.done() == [b""]


async def test_mcp_attach_refuses_a_foreign_server(short_dir: Path, foreign_server: Server) -> None:
    backend = AttachBackend(Config(relay_url="", relay_host="", data_dir=short_dir), "daemon")
    with pytest.raises(ToolError) as e:
        await backend.groups()
    assert e.value.code == "peer_mismatch"
    assert foreign_server.done() == [b""]
    await backend.close()


def test_a_token_passed_in_directly_expects_this_user(tmp_path: Path) -> None:
    assert token_owner(tmp_path / "absent") == EUID
    assert token_owner(tmp_path) == tmp_path.stat().st_uid
