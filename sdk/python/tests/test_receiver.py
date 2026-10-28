"""The built-in webhook server, driven with raw HTTP."""

from __future__ import annotations

import asyncio
import json
import shutil
import stat
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from agentconnect_sdk import AgentConnect, AgentConnectError, Group, Message, sign
from agentconnect_sdk.receiver import WebhookReceiver

Payload = Callable[..., dict[str, Any]]


@pytest_asyncio.fixture
async def receiver(agent: AgentConnect) -> AsyncIterator[WebhookReceiver]:
    server = agent.webhook_receiver(port=0)
    await server.start()
    yield server
    await server.close()


def signed(secret: str, body: bytes, at: int | None = None) -> dict[str, str]:
    stamp = str(int(time.time()) if at is None else at)
    return {
        "X-AgentConnect-Timestamp": stamp,
        "X-AgentConnect-Signature": sign(secret, stamp, body),
    }


async def http(
    server: WebhookReceiver,
    body: bytes,
    headers: dict[str, str] | None = None,
    method: str = "POST",
    length: int | None = None,
) -> tuple[int, dict[str, Any]]:
    reader, writer = await asyncio.open_connection(*server.address)
    lines = [
        f"{method} /hook HTTP/1.1",
        "host: localhost",
        f"content-length: {len(body) if length is None else length}",
    ]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    writer.write("\r\n".join(lines).encode() + b"\r\n\r\n" + body)
    await writer.drain()
    writer.write_eof()
    raw = await reader.read()
    writer.close()
    head, _, rest = raw.partition(b"\r\n\r\n")
    return int(head.split()[1]), json.loads(rest)


async def test_a_signed_message_reaches_the_handler_once(
    agent: AgentConnect, receiver: WebhookReceiver, secret: str, make_payload: Payload
) -> None:
    got: list[tuple[str, str]] = []

    @agent.on_message
    async def handle(msg: Message, group: Group) -> None:
        got.append((msg.raw_text, group.id))

    body = json.dumps(make_payload(msg_id="m1")).encode()
    assert await http(receiver, body, signed(secret, body)) == (200, {"status": "handled"})
    # The daemon redelivers with a fresh signature: acked, not handled again.
    assert await http(receiver, body, signed(secret, body, int(time.time()) + 1)) == (
        200,
        {"status": "duplicate"},
    )
    assert got == [("hello", "g1")]


async def test_unauthentic_requests_are_refused_and_never_dispatched(
    agent: AgentConnect, receiver: WebhookReceiver, secret: str, make_payload: Payload
) -> None:
    got: list[str] = []

    @agent.on_message
    async def handle(msg: Message, _group: Group) -> None:
        got.append(msg.msg_id)

    body = json.dumps(make_payload(msg_id="m1")).encode()
    good = signed(secret, body)
    cases = {
        "unsigned": {},
        "tampered": good,
        "skewed": signed(secret, body, int(time.time()) - 3600),
        "wrong secret": signed(secret + "x", body),
    }
    for name, headers in cases.items():
        sent = body.replace(b"hello", b"HELLO") if name == "tampered" else body
        status, reply = await http(receiver, sent, headers)
        assert status == 401, name
        assert reply["status"] == "unauthorized"
    assert got == []
    assert await http(receiver, body, good) == (200, {"status": "handled"})
    status, reply = await http(receiver, body, good)  # a captured request, replayed
    assert (status, reply["reason"]) == (401, "ReplayError")
    assert got == ["m1"]


async def test_malformed_bodies_are_400(
    receiver: WebhookReceiver, secret: str, make_payload: Payload
) -> None:
    deep = b'{"event": "message", "a2a": ' + b"[" * 200 + b"]" * 200 + b"}"
    for body in (b"not json", b"[]", json.dumps({"event": "message"}).encode(), deep):
        status, _ = await http(receiver, body, signed(secret, body))
        assert status == 400, body
    bad = json.dumps(make_payload(group=None)).encode()
    assert (await http(receiver, bad, signed(secret, bad)))[0] == 400


async def test_only_post_is_served(receiver: WebhookReceiver, secret: str) -> None:
    status, _ = await http(receiver, b"", signed(secret, b""), method="GET")
    assert status == 405


async def test_oversized_and_truncated_requests_are_refused(
    receiver: WebhookReceiver, secret: str
) -> None:
    assert (await http(receiver, b"", signed(secret, b""), length=2 << 20))[0] == 413
    status, _ = await http(receiver, b"", signed(secret, b""), length=-1)
    assert status == 413
    status, _ = await http(receiver, b"abc", signed(secret, b"abc"), length=50)
    assert status == 400
    reader, writer = await asyncio.open_connection(*receiver.address)
    writer.write(b"POST / HTTP/1.1\r\ncontent-length: nope\r\n\r\n")
    await writer.drain()
    assert b" 400 " in await reader.read()
    writer.close()


async def test_a_slow_request_times_out(
    receiver: WebhookReceiver, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentconnect_sdk.receiver.READ_TIMEOUT", 0.05)
    reader, writer = await asyncio.open_connection(*receiver.address)
    writer.write(b"POST / HTTP/1.1\r\n")  # never finishes the head
    await writer.drain()
    assert b" 408 " in await reader.read()
    writer.close()


async def test_a_failing_handler_is_not_an_ack_and_runs_again(
    agent: AgentConnect, receiver: WebhookReceiver, secret: str, make_payload: Payload
) -> None:
    attempts: list[str] = []

    @agent.on_message
    async def flaky(msg: Message, _group: Group) -> None:
        attempts.append(msg.msg_id)
        if len(attempts) == 1:
            raise RuntimeError("model unavailable")

    body = json.dumps(make_payload(msg_id="m1")).encode()
    assert (await http(receiver, body, signed(secret, body)))[0] == 500
    assert await http(receiver, body, signed(secret, body, int(time.time()) + 1)) == (
        200,
        {"status": "handled"},
    )
    assert attempts == ["m1", "m1"]


async def test_the_same_id_while_in_flight_is_503(
    agent: AgentConnect, receiver: WebhookReceiver, secret: str, make_payload: Payload
) -> None:
    started, release = asyncio.Event(), asyncio.Event()

    @agent.on_message
    async def slow(_msg: Message, _group: Group) -> None:
        started.set()
        await release.wait()

    body = json.dumps(make_payload(msg_id="m1")).encode()
    first = asyncio.create_task(http(receiver, body, signed(secret, body)))
    await started.wait()
    assert (await http(receiver, body, signed(secret, body, int(time.time()) + 1)))[0] == 503
    release.set()
    assert await first == (200, {"status": "handled"})


async def test_an_unexpected_server_error_is_500(
    agent: AgentConnect, secret: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = agent.webhook_receiver(port=0)
    await server.start()

    async def explode(reader: asyncio.StreamReader) -> tuple[int, dict[str, Any]]:
        await reader.readuntil(b"\r\n\r\n")
        raise RuntimeError("bug")

    monkeypatch.setattr(server, "_handle", explode)
    try:
        assert (await http(server, b"", signed(secret, b"")))[0] == 500
    finally:
        await server.close()


def test_address_needs_a_started_server(agent: AgentConnect) -> None:
    with pytest.raises(RuntimeError, match="not started"):
        _ = agent.webhook_receiver(port=0).address


# -- on a Unix socket (SR-10) ---------------------------------------------------


@pytest.fixture
def sockdir() -> Iterator[Path]:
    # /tmp, not $TMPDIR: socket paths are limited to about 100 bytes.
    d = Path(tempfile.mkdtemp(prefix="ac-hook-", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def post_unix(path: Path, body: bytes, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    reader, writer = await asyncio.open_unix_connection(str(path))
    lines = ["POST /hook HTTP/1.1", "host: localhost", f"content-length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    writer.write("\r\n".join(lines).encode() + b"\r\n\r\n" + body)
    await writer.drain()
    writer.write_eof()
    raw = await reader.read()
    writer.close()
    head, _, rest = raw.partition(b"\r\n\r\n")
    return int(head.split()[1]), json.loads(rest)


async def test_the_receiver_serves_a_unix_socket(
    agent: AgentConnect, sockdir: Path, secret: str, make_payload: Payload
) -> None:
    got: list[str] = []

    @agent.on_message
    async def handle(msg: Message, _group: Group) -> None:
        got.append(msg.raw_text)

    path = sockdir / "hook.sock"
    path.touch()  # a stale file from an earlier run is not replaced...
    with pytest.raises(AgentConnectError, match="not a socket"):
        await agent.webhook_receiver(path=path).start()
    path.unlink()
    server = agent.webhook_receiver(path=path)
    await server.start()
    try:
        # The daemon's user (the group, in the separate-OS-user mode) connects.
        assert stat.S_IMODE(path.stat().st_mode) == 0o660
        assert server.path == path
        body = json.dumps(make_payload(msg_id="m1")).encode()
        assert await post_unix(path, body, signed(secret, body)) == (200, {"status": "handled"})
        assert got == ["hello"]
    finally:
        await server.close()
    # ...but a socket left behind is.
    stale = agent.webhook_receiver(path=path)
    await stale.start()
    await stale.close()
    assert not path.exists()


async def test_serve_listens_on_the_configured_socket(  # noqa: PLR0913, PLR0917
    isolated_env: None,
    data_dir: Path,
    sockdir: Path,
    tmp_path: Path,
    secret: str,
    make_payload: Payload,
) -> None:
    path = sockdir / "hook.sock"
    config = tmp_path / "daemon.toml"
    config.write_text(f'[webhook]\ncallback_socket = "{path}"\n', encoding="utf-8")
    agent = AgentConnect(data_dir=data_dir, config_path=config)
    got: list[str] = []

    @agent.on_message
    async def handle(msg: Message, _group: Group) -> None:
        got.append(msg.raw_text)

    ready = asyncio.Event()
    task = asyncio.create_task(agent.serve(ready=ready))
    await asyncio.wait_for(ready.wait(), 5)
    body = json.dumps(make_payload(msg_id="m2")).encode()
    assert await post_unix(path, body, signed(secret, body)) == (200, {"status": "handled"})
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await agent.aclose()
    assert got == ["hello"]
