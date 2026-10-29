"""Receivers on Unix sockets, checked by their server's UID (SR-10).

The daemon writes a delivery only to a receiver run by the expected user:
its own outside the separate-OS-user mode, one of ``isolation.agent_users``
in it. Anything else is a ``RETRY`` with nothing written, so a squatter
neither reads a delivery nor acks it away. The server's credentials are
injected; ``test_receivers_multiuser.py`` uses a real second user.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import socket
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agentconnect.adapter import Delivery, DeliveryResult, GroupView, Sender
from agentconnect.adapters import build_adapters
from agentconnect.clock import FakeClock
from agentconnect.config import Config, ConfigError, load_config
from agentconnect.isolation import (
    IsolationError,
    PeerCred,
    check_config,
    facade_uids,
    receiver_uids,
)
from agentconnect.sockets import receiver_async_transport
from agentconnect.webhook import SIGNATURE_HEADER, WebhookAdapter

EUID = os.geteuid()
GROUP = GroupView("g1", "Ops", "Deploys", 3, "free")
SENDER = Sender("ac:v0:peer", "i1", "peer-bot", False)
DELIVERY_TEXT = "the plaintext of a delivery"
NO_CONTENT = b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"


def delivery(msg_id: str = "m1") -> Delivery:
    body = {"text": DELIVERY_TEXT}
    return Delivery(
        "g1",
        msg_id,
        "a2a.message",
        body,
        SENDER,
        ["*"],
        True,
        "Deploys",
        {"self": "unverified", "verified_members": 0, "members": 2},
        "agent",
        1,
        {"kind": "a2a.message", "body": body},
    )


class Receiver:
    """A Unix socket server on a thread for one connection: records what
    arrived before the client closed or finished its request, answers 204."""

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
            while b"\r\n\r\n" not in data and (chunk := conn.recv(65536)):
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            length = next(
                (
                    int(line.split(b":", 1)[1])
                    for line in head.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                ),
                0,
            )
            while len(rest) < length and (chunk := conn.recv(65536)):
                rest += chunk
            self.received.append(head + (b"\r\n\r\n" + rest if data else b""))
            if data:
                conn.sendall(NO_CONTENT)

    def done(self) -> list[bytes]:
        self._thread.join(timeout=5)
        assert not self._thread.is_alive(), "the daemon never connected or closed"
        self._sock.close()
        return self.received


@pytest.fixture
def short_dir() -> Iterator[Path]:
    # /tmp, not $TMPDIR: socket paths are limited to about 100 bytes.
    d = Path(tempfile.mkdtemp(prefix="ac-recv-", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _uid(rng: random.Random) -> int:
    while True:
        uid = rng.randrange(20_000, 60_000)
        if uid != EUID:
            return uid


def as_uid(uid: int) -> Any:
    return lambda _sock: PeerCred(uid=uid, gid=uid)


def adapter_for(path: Path, uids: set[int], served_by: int) -> WebhookAdapter:
    transport = receiver_async_transport(path, uids, credentials=as_uid(served_by))
    return WebhookAdapter(
        "http://localhost/hook", "s" * 32, FakeClock(), transport=transport, timeout=5
    )


def log_events(err: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in err.splitlines() if line.startswith("{")]


# -- the webhook adapter --------------------------------------------------------


async def test_the_receivers_own_user_gets_the_delivery(short_dir: Path) -> None:
    receiver = Receiver(short_dir / "hook.sock")
    adapter = adapter_for(receiver.path, {EUID}, EUID)
    assert await adapter.deliver(GROUP, SENDER, ["*"], delivery()) is DeliveryResult.ACK
    (got,) = receiver.done()
    assert got.startswith(b"POST /hook HTTP/1.1")
    assert SIGNATURE_HEADER.lower().encode() in got.lower()
    assert DELIVERY_TEXT.encode() in got
    await adapter.close()


async def test_another_user_is_a_retry_with_nothing_written(
    short_dir: Path, rng: random.Random, capsys: pytest.CaptureFixture[str]
) -> None:
    receiver = Receiver(short_dir / "hook.sock")
    other = _uid(rng)
    adapter = adapter_for(receiver.path, {EUID}, other)
    assert await adapter.deliver(GROUP, SENDER, ["*"], delivery()) is DeliveryResult.RETRY
    assert receiver.done() == [b""]
    err = capsys.readouterr().err
    (refused,) = [e for e in log_events(err) if e["event"] == "webhook_receiver_refused"]
    assert str(other) in refused["reason"]
    assert str(EUID) in refused["reason"]
    assert str(receiver.path) in refused["reason"]
    assert DELIVERY_TEXT not in err
    await adapter.close()


async def test_any_listed_agent_user_may_receive(short_dir: Path, rng: random.Random) -> None:
    first, second = _uid(rng), _uid(rng)
    receiver = Receiver(short_dir / "hook.sock")
    adapter = adapter_for(receiver.path, {first, second}, second)
    assert await adapter.deliver(GROUP, SENDER, ["*"], delivery()) is DeliveryResult.ACK
    assert DELIVERY_TEXT.encode() in receiver.done()[0]
    await adapter.close()


async def test_a_missing_receiver_is_a_retry(short_dir: Path) -> None:
    adapter = adapter_for(short_dir / "absent.sock", {EUID}, EUID)
    assert await adapter.deliver(GROUP, SENDER, ["*"], delivery()) is DeliveryResult.RETRY
    await adapter.close()


def _config(short_dir: Path, **kw: Any) -> Config:
    return Config(relay_url="", relay_host="", data_dir=short_dir / "data", **kw)


async def test_the_daemon_delivers_to_the_configured_socket(short_dir: Path) -> None:
    receiver = Receiver(short_dir / "hook.sock")
    cfg = _config(short_dir, adapters=("webhook",), webhook_socket=receiver.path)
    (adapter,) = build_adapters(cfg, FakeClock())
    assert isinstance(adapter, WebhookAdapter)
    assert await adapter.deliver(GROUP, SENDER, ["*"], delivery()) is DeliveryResult.ACK
    assert DELIVERY_TEXT.encode() in receiver.done()[0]
    await adapter.close()


async def test_the_configured_socket_is_checked(
    short_dir: Path, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentconnect.isolation.peer_credentials", as_uid(_uid(rng)))
    receiver = Receiver(short_dir / "hook.sock")
    cfg = _config(
        short_dir,
        adapters=("webhook",),
        webhook_url="http://127.0.0.1:1/hook",
        webhook_socket=receiver.path,
    )
    (adapter,) = build_adapters(cfg, FakeClock())
    assert isinstance(adapter, WebhookAdapter)
    assert await adapter.deliver(GROUP, SENDER, ["*"], delivery()) is DeliveryResult.RETRY
    assert receiver.done() == [b""]
    await adapter.close()


# -- who may receive ------------------------------------------------------------


def test_outside_isolation_only_the_daemons_user_receives(short_dir: Path) -> None:
    assert receiver_uids(_config(short_dir)) == frozenset({EUID})


def test_in_isolation_the_agent_users_receive(short_dir: Path, rng: random.Random) -> None:
    a, b = _uid(rng), _uid(rng)
    cfg = _config(short_dir, isolation=True, isolation_agent_users=(str(a), str(b)))
    assert receiver_uids(cfg) == frozenset({a, b})


# -- configuration ---------------------------------------------------------------


def load(tmp_path: Path, text: str) -> Config:
    path = tmp_path / "config.toml"
    path.write_text(f'[relay]\nurl = "wss://relay.example.org"\n{text}', encoding="utf-8")
    return load_config(path, environ={"AC_DATA_DIR": str(tmp_path / "data")})


def test_the_receiver_sockets_are_configured(tmp_path: Path) -> None:
    cfg = load(
        tmp_path,
        '[daemon]\nadapters = ["webhook"]\n'
        '[webhook]\ncallback_socket = "/run/agent/hook.sock"\n'
        '[a2a]\nlocal_agent_url = "http://localhost/"\n'
        'local_agent_socket = "/run/agent/a2a.sock"\n',
    )
    assert cfg.webhook_socket == Path("/run/agent/hook.sock")
    assert cfg.webhook_url is None  # the socket alone is enough
    assert cfg.a2a_local_agent_socket == Path("/run/agent/a2a.sock")


def test_a_local_agent_socket_needs_the_url(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="local_agent_url"):
        load(tmp_path, '[a2a]\nlocal_agent_socket = "/run/agent/a2a.sock"\n')


@pytest.mark.parametrize(
    "url",
    [
        "http://agent.example.org/",
        "https://10.0.0.5:9999/",
        "http://user:pw@127.0.0.1:9999/",
        "ftp://127.0.0.1/",
    ],
)
def test_the_local_agent_url_must_be_loopback(tmp_path: Path, url: str) -> None:
    with pytest.raises(ConfigError, match=r"a2a\.local_agent_url"):
        load(tmp_path, f'[a2a]\nlocal_agent_url = "{url}"\n')


@pytest.mark.parametrize("url", ["http://127.0.0.1:99999/", "http://127.0.0.1:abc/"])
def test_the_local_agent_url_needs_a_valid_port(tmp_path: Path, url: str) -> None:
    with pytest.raises(ConfigError, match=r"a2a\.local_agent_url"):
        load(tmp_path, f'[a2a]\nlocal_agent_url = "{url}"\n')


def test_a_local_agent_socket_carries_plain_http(tmp_path: Path) -> None:
    # TLS over the socket would fail every delivery; the server's user is
    # what authenticates the agent there.
    with pytest.raises(ConfigError, match="https"):
        load(
            tmp_path,
            '[a2a]\nlocal_agent_url = "https://localhost/"\n'
            'local_agent_socket = "/run/agent/a2a.sock"\n',
        )


@pytest.mark.parametrize("url", ["http://127.0.0.1:9999/", "https://localhost/", "http://[::1]:1/"])
def test_a_loopback_local_agent_url_is_accepted(tmp_path: Path, url: str) -> None:
    assert load(tmp_path, f'[a2a]\nlocal_agent_url = "{url}"\n').a2a_local_agent_url == url


def _isolated(short_dir: Path, **kw: Any) -> Config:
    return _config(
        short_dir,
        isolation=True,
        isolation_agent_dir=short_dir / "agents",
        isolation_agent_users=(str(EUID + 1),),
        **kw,
    )


@pytest.mark.parametrize(
    ("receiver", "message"),
    [
        ({"webhook_url": "http://127.0.0.1:8808/"}, "webhook.callback_socket"),
        ({"a2a_local_agent_url": "http://127.0.0.1:9999/"}, "a2a.local_agent_socket"),
    ],
)
def test_isolation_refuses_tcp_receivers(
    short_dir: Path, receiver: dict[str, Any], message: str
) -> None:
    with pytest.raises(IsolationError, match=message):
        check_config(_isolated(short_dir, **receiver), EUID + 2, {EUID + 1}, set())


def test_isolation_needs_an_agent_user_to_deliver_to(short_dir: Path) -> None:
    cfg = _config(
        short_dir,
        isolation=True,
        isolation_agent_dir=short_dir / "agents",
        webhook_socket=short_dir / "hook.sock",
    )
    with pytest.raises(IsolationError, match="agent_users"):
        check_config(cfg, EUID + 2, set(), set())


def test_isolation_accepts_socket_receivers(short_dir: Path) -> None:
    cfg = _isolated(
        short_dir,
        webhook_url="http://127.0.0.1:8808/",
        webhook_socket=short_dir / "hook.sock",
        a2a_local_agent_url="http://localhost/",
        a2a_local_agent_socket=short_dir / "a2a.sock",
    )
    check_config(cfg, EUID + 2, {EUID + 1}, set())


# -- the A2A facade on a socket ---------------------------------------------------


def test_the_facade_socket_is_configured(tmp_path: Path) -> None:
    cfg = load(tmp_path, '[a2a]\nfacade_socket = "/run/agentconnect/facade.sock"\n')
    assert cfg.a2a_facade_socket == Path("/run/agentconnect/facade.sock")
    assert cfg.a2a_facade_port == 0
    assert cfg.a2a_enabled


def test_the_facade_is_on_a_port_or_a_socket_not_both(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="facade_socket"):
        load(tmp_path, '[a2a]\nfacade_port = 8765\nfacade_socket = "/run/f.sock"\n')


def test_isolation_refuses_a_facade_on_a_port(short_dir: Path) -> None:
    with pytest.raises(IsolationError, match=r"a2a\.facade_socket"):
        check_config(_isolated(short_dir, a2a_facade_port=8765), EUID + 2, {EUID + 1}, set())
    check_config(
        _isolated(short_dir, a2a_facade_socket=short_dir / "agents" / "facade.sock"),
        EUID + 2,
        {EUID + 1},
        set(),
    )


def test_the_facade_admits_the_daemons_user_and_the_agent_users(
    short_dir: Path, rng: random.Random
) -> None:
    a, b = _uid(rng), _uid(rng)
    assert facade_uids(_config(short_dir)) == frozenset({EUID})
    cfg = _config(short_dir, isolation=True, isolation_agent_users=(str(a), str(b)))
    assert facade_uids(cfg) == frozenset({EUID, a, b})
