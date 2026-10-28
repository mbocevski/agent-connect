"""The local API on loopback TCP is TLS with a pinned certificate (SR-08).

The daemon keeps a self-signed certificate in its data directory; clients
trust only that certificate, read from the directory they read the token
from, and refuse any other server before a request byte is sent.

Certificate management runs on a fixed time. The TLS tests make their
certificates on the system clock, because OpenSSL checks a certificate's
dates against it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import random
import shutil
import socket
import ssl
import tempfile
import threading
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from agentconnect.api_tls import (
    CERT_FILE,
    FINGERPRINT_FILE,
    KEY_FILE,
    LIFETIME,
    RENEW_BEFORE,
    ensure_certificate,
    server_context,
)
from agentconnect.apiclient import ApiClient, ApiClientError
from agentconnect.clock import DEFAULT_FAKE_START, SystemClock
from agentconnect.config import Config
from agentconnect.mcp.backend import AttachBackend, ToolError
from agentconnect.sockets import (
    PeerMismatchError,
    local_async_tcp_transport,
    local_tcp_transport,
)
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE

NOW = DEFAULT_FAKE_START
OK = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n"
OK += b"connection: close\r\n\r\n{}"


@pytest.fixture
def data_dir() -> Iterator[Path]:
    d = Path(tempfile.mkdtemp(prefix="ac-tls-"))
    d.chmod(0o700)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def real_now() -> Any:
    return SystemClock().now()


def fingerprint_of(cert_file: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert_file.read_text(encoding="ascii"))
    return hashlib.sha256(der).hexdigest()


def token(rng: random.Random) -> str:
    return rng.randbytes(16).hex()


# -- the daemon's certificate -------------------------------------------------


def test_the_first_start_creates_a_private_pinned_certificate(data_dir: Path) -> None:
    made = ensure_certificate(data_dir, NOW)
    for name in (CERT_FILE, KEY_FILE, FINGERPRINT_FILE):
        st = (data_dir / name).stat()
        assert st.st_mode & 0o777 == 0o600, name
        assert st.st_uid == os.geteuid()
    fp = (data_dir / FINGERPRINT_FILE).read_text(encoding="ascii").strip()
    assert fp == fingerprint_of(data_dir / CERT_FILE) == made.fingerprint
    cert = x509.load_pem_x509_certificate((data_dir / CERT_FILE).read_bytes())
    assert cert.not_valid_after_utc == NOW + LIFETIME
    assert cert.not_valid_before_utc <= NOW
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address("127.0.0.1") in san.get_values_for_type(x509.IPAddress)
    assert made.not_after == NOW + LIFETIME
    assert made.renew_at == NOW + LIFETIME - RENEW_BEFORE


def test_a_valid_certificate_is_kept(data_dir: Path) -> None:
    first = ensure_certificate(data_dir, NOW)
    assert ensure_certificate(data_dir, first.renew_at - timedelta(seconds=1)) == first


def test_the_certificate_is_renewed_ahead_of_its_expiry(data_dir: Path) -> None:
    first = ensure_certificate(data_dir, NOW)
    renewed = ensure_certificate(data_dir, first.renew_at)
    assert renewed.fingerprint != first.fingerprint
    assert renewed.not_after == first.renew_at + LIFETIME


def test_an_expired_certificate_is_replaced(data_dir: Path) -> None:
    first = ensure_certificate(data_dir, NOW)
    later = first.not_after + timedelta(days=1)
    assert ensure_certificate(data_dir, later).fingerprint != first.fingerprint


def _other_key_pem() -> bytes:
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )


@pytest.mark.parametrize(
    "damage",
    ["garbage certificate", "another key", "wrong fingerprint", "no key", "no fingerprint"],
)
def test_a_damaged_or_mismatched_certificate_is_replaced(data_dir: Path, damage: str) -> None:
    first = ensure_certificate(data_dir, NOW)
    if damage == "garbage certificate":
        (data_dir / CERT_FILE).write_text("not a certificate", encoding="ascii")
    elif damage == "another key":
        (data_dir / KEY_FILE).write_bytes(_other_key_pem())
    elif damage == "wrong fingerprint":
        (data_dir / FINGERPRINT_FILE).write_text("00" * 32, encoding="ascii")
    elif damage == "no key":
        (data_dir / KEY_FILE).unlink()
    else:
        (data_dir / FINGERPRINT_FILE).unlink()
    again = ensure_certificate(data_dir, NOW)
    assert again.fingerprint != first.fingerprint
    assert (data_dir / FINGERPRINT_FILE).read_text(encoding="ascii").strip() == again.fingerprint
    assert fingerprint_of(data_dir / CERT_FILE) == again.fingerprint


@pytest.mark.parametrize("name", [KEY_FILE, FINGERPRINT_FILE, CERT_FILE])
def test_loose_permissions_stop_the_start(data_dir: Path, name: str) -> None:
    ensure_certificate(data_dir, NOW)
    (data_dir / name).chmod(0o644)
    with pytest.raises(PermissionError, match=name):
        ensure_certificate(data_dir, NOW)


# -- servers on a loopback port ------------------------------------------------


class Server:
    """A loopback TCP server on a thread, for ``connections`` connections.
    With ``tls``, each connection does a TLS handshake with the certificate
    in ``cert_dir`` as it is at that moment, records the decrypted bytes and
    answers 200; without, it records the raw bytes and closes."""

    def __init__(self, cert_dir: Path | None, connections: int = 1) -> None:
        self.cert_dir = cert_dir
        self.received: list[bytes] = []
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, args=(connections,), daemon=True)
        self._thread.start()

    def _serve(self, connections: int) -> None:
        for _ in range(connections):
            raw, _ = self._sock.accept()
            raw.settimeout(5)
            if self.cert_dir is None:
                with raw:
                    self.received.append(raw.recv(65536))
                continue
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(self.cert_dir / CERT_FILE, self.cert_dir / KEY_FILE)
            try:
                conn = ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                raw.close()
                self.received.append(b"")  # the handshake failed: nothing arrived
                continue
            with conn:
                data = b""
                try:
                    while b"\r\n\r\n" not in data and (chunk := conn.recv(65536)):
                        data += chunk
                except (ssl.SSLError, OSError):
                    pass
                self.received.append(data)
                if data:
                    conn.sendall(OK)

    def done(self) -> list[bytes]:
        self._thread.join(timeout=5)
        assert not self._thread.is_alive(), "the client never connected or closed"
        self._sock.close()
        return self.received


def get(transport: httpx.BaseTransport, port: int, secret: str, scheme: str = "https") -> int:
    with httpx.Client(transport=transport, base_url=f"{scheme}://127.0.0.1:{port}") as c:
        return c.get("/v0/status", headers={"authorization": f"Bearer {secret}"}).status_code


async def aget(transport: httpx.AsyncBaseTransport, port: int, secret: str) -> int:
    async with httpx.AsyncClient(transport=transport, base_url=f"https://127.0.0.1:{port}") as c:
        resp = await c.get("/v0/status", headers={"authorization": f"Bearer {secret}"})
        return resp.status_code


@pytest.fixture
def pinned(data_dir: Path) -> Path:
    """A data directory holding a certificate valid now."""
    ensure_certificate(data_dir, real_now())
    return data_dir


@pytest.fixture
def stranger() -> Iterator[Path]:
    """Another certificate and key, valid now: a squatter's."""
    d = Path(tempfile.mkdtemp(prefix="ac-tls-other-"))
    d.chmod(0o700)
    ensure_certificate(d, real_now())
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_the_pinned_certificate_is_accepted(pinned: Path, rng: random.Random) -> None:
    server, secret = Server(pinned), token(rng)
    assert get(local_tcp_transport(server.port, pinned), server.port, secret) == 200
    assert secret.encode() in server.done()[0]


async def test_the_pinned_certificate_is_accepted_async(pinned: Path, rng: random.Random) -> None:
    server, secret = Server(pinned), token(rng)
    assert await aget(local_async_tcp_transport(server.port, pinned), server.port, secret) == 200
    assert secret.encode() in server.done()[0]


def test_the_server_context_serves_the_pinned_certificate(pinned: Path) -> None:
    ctx = server_context(ensure_certificate(pinned, real_now()))
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_a_plain_squatter_gets_no_request(pinned: Path, rng: random.Random) -> None:
    server, secret = Server(None), token(rng)
    with pytest.raises(PeerMismatchError) as e:
        get(local_tcp_transport(server.port, pinned), server.port, secret)
    (got,) = server.done()
    assert got[:1] == b"\x16"  # a TLS handshake record, nothing else
    assert secret.encode() not in got
    assert b"HTTP/" not in got
    assert e.value.code == "peer_mismatch"
    assert str(server.port) in str(e.value)


async def test_a_plain_squatter_gets_no_request_async(pinned: Path, rng: random.Random) -> None:
    server, secret = Server(None), token(rng)
    with pytest.raises(PeerMismatchError):
        await aget(local_async_tcp_transport(server.port, pinned), server.port, secret)
    (got,) = server.done()
    assert secret.encode() not in got
    assert b"HTTP/" not in got


def test_a_squatter_with_another_certificate_gets_nothing(
    pinned: Path, stranger: Path, rng: random.Random
) -> None:
    server, secret = Server(stranger), token(rng)
    with pytest.raises(PeerMismatchError) as e:
        get(local_tcp_transport(server.port, pinned), server.port, secret)
    assert server.done() == [b""]
    assert secret not in str(e.value)


async def test_a_squatter_with_another_certificate_gets_nothing_async(
    pinned: Path, stranger: Path, rng: random.Random
) -> None:
    server = Server(stranger)
    with pytest.raises(PeerMismatchError):
        await aget(local_async_tcp_transport(server.port, pinned), server.port, token(rng))
    assert server.done() == [b""]


def test_an_expired_certificate_is_refused(data_dir: Path, rng: random.Random) -> None:
    # A daemon replaces an expired certificate when it starts or renews; a
    # client still refuses one that is presented.
    ensure_certificate(data_dir, real_now() - LIFETIME - timedelta(days=1))
    server = Server(data_dir)
    with pytest.raises(PeerMismatchError, match="expired"):
        get(local_tcp_transport(server.port, data_dir), server.port, token(rng))
    assert server.done() == [b""]


def test_a_rotated_certificate_needs_no_new_client(pinned: Path, rng: random.Random) -> None:
    server = Server(pinned, connections=2)
    transport = local_tcp_transport(server.port, pinned)
    with httpx.Client(transport=transport, base_url=f"https://127.0.0.1:{server.port}") as c:
        assert c.get("/v0/status").status_code == 200
        first = ensure_certificate(pinned, real_now())
        (pinned / FINGERPRINT_FILE).unlink()
        ensure_certificate(pinned, real_now())  # rotated under the client
        assert fingerprint_of(pinned / CERT_FILE) != first.fingerprint
        assert c.get("/v0/status").status_code == 200
    assert len(server.done()) == 2


@pytest.mark.parametrize("damage", ["fingerprint", "certificate"])
def test_a_pin_that_doesnt_match_its_certificate_sends_nothing(
    pinned: Path, rng: random.Random, damage: str
) -> None:
    if damage == "fingerprint":
        (pinned / FINGERPRINT_FILE).write_text("00" * 32, encoding="ascii")
    else:
        (pinned / CERT_FILE).write_text("not a certificate", encoding="ascii")
    server = Server(None)
    with pytest.raises(PeerMismatchError, match="nothing was sent"):
        get(local_tcp_transport(server.port, pinned), server.port, token(rng))
    with socket.create_connection(("127.0.0.1", server.port)):
        pass  # unblock the server's accept
    assert server.done() == [b""]


def test_no_certificate_is_a_plain_connect_error(data_dir: Path, rng: random.Random) -> None:
    server = Server(None)
    with pytest.raises(httpx.ConnectError) as e:
        get(local_tcp_transport(server.port, data_dir), server.port, token(rng))
    assert not isinstance(e.value, PeerMismatchError)
    assert CERT_FILE in str(e.value)
    with socket.create_connection(("127.0.0.1", server.port)):
        pass  # unblock the server's accept
    assert server.done() == [b""]


def test_plain_http_is_never_sent(pinned: Path, rng: random.Random) -> None:
    server, secret = Server(None), token(rng)
    with pytest.raises(httpx.ConnectError):
        get(local_tcp_transport(server.port, pinned), server.port, secret, scheme="http")
    with socket.create_connection(("127.0.0.1", server.port)):
        pass
    assert server.done() == [b""]


def test_only_the_configured_port_is_dialled(pinned: Path, rng: random.Random) -> None:
    server = Server(None)
    with pytest.raises(httpx.ConnectError):
        get(local_tcp_transport(server.port + 1, pinned), server.port, token(rng))
    with socket.create_connection(("127.0.0.1", server.port)):
        pass
    assert server.done() == [b""]


# -- the clients use it -------------------------------------------------------


@pytest.fixture
def squatted(pinned: Path, stranger: Path, rng: random.Random) -> tuple[Config, Server]:
    for name in (API_TOKEN_FILE, HUMAN_TOKEN_FILE):
        (pinned / name).write_text(token(rng), encoding="ascii")
    server = Server(stranger)
    cfg = Config(relay_url="", relay_host="", data_dir=pinned, api_tcp_port=server.port)
    return cfg, server


def test_the_cli_client_refuses_a_squatter(squatted: tuple[Config, Server]) -> None:
    cfg, server = squatted
    with pytest.raises(ApiClientError) as e:
        ApiClient(cfg, human=True).request("GET", "/v0/status")
    assert e.value.code == "peer_mismatch"
    assert server.done() == [b""]


async def test_mcp_attach_refuses_a_squatter(squatted: tuple[Config, Server]) -> None:
    cfg, server = squatted
    backend = AttachBackend(cfg, "daemon")
    with pytest.raises(ToolError) as e:
        await backend.groups()
    assert e.value.code == "peer_mismatch"
    assert server.done() == [b""]
    await backend.close()
