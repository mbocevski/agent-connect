"""The relay link against a scripted loopback WebSocket server, and the
signed REST client against an in-memory transport."""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from http import HTTPStatus
from typing import Any

import httpx
import pytest
import pytest_asyncio
from websockets.asyncio.server import ServerConnection, serve
from websockets.http11 import Request, Response

import agentconnect_core as ac
from agentconnect.backoff import Backoff
from agentconnect.clock import FakeClock
from agentconnect.limits import MAX_PAYLOAD_DEPTH
from agentconnect.relay import (
    CAUGHT_UP,
    NotConnectedError,
    RelayError,
    RelayLink,
    RelayRest,
    b64,
    unb64,
)

Script = Callable[[ServerConnection], Awaitable[None]]


def instance(rng: random.Random) -> ac.Instance:
    ident = ac.Identity._generate_for_testing(rng.getrandbits(64))
    return ident._create_instance_for_testing(seed=rng.getrandbits(64))


class FakeRelay:
    def __init__(self) -> None:
        self.script: Script | None = None
        self.port = 0
        # Upgrades to refuse with 503, as the relay does at its connection cap.
        self.refuse_upgrades = 0
        self.upgrades = 0

    async def handler(self, ws: ServerConnection) -> None:
        if self.script is not None:
            await self.script(ws)

    def process_request(self, ws: ServerConnection, _request: Request) -> Response | None:
        self.upgrades += 1
        if self.refuse_upgrades > 0:
            self.refuse_upgrades -= 1
            return ws.respond(HTTPStatus.SERVICE_UNAVAILABLE, "too many connections\n")
        return None


@pytest_asyncio.fixture
async def fake_relay() -> AsyncIterator[FakeRelay]:
    relay = FakeRelay()
    async with serve(
        relay.handler, "127.0.0.1", 0, process_request=relay.process_request
    ) as server:
        relay.port = int(next(iter(server.sockets)).getsockname()[1])
        yield relay


async def handshake(ws: ServerConnection, inst: ac.Instance, nonce: bytes, host: str) -> bool:
    await ws.send(json.dumps({"t": "challenge", "nonce": b64(nonce)}))
    auth = json.loads(await ws.recv())
    ok = auth["sig"] == b64(inst.sign_relay_challenge(nonce, host))
    await ws.send(json.dumps({"t": "ready", "mailbox_id": inst.mailbox_id if ok else "x"}))
    return bool(ok)


class Watch:
    """Wakes on every link state change (``on_state``); no polling."""

    def __init__(self) -> None:
        self.event = asyncio.Event()

    def poke(self) -> None:
        self.event.set()

    async def until(self, predicate: Callable[[], bool]) -> None:
        async def loop() -> None:
            while not predicate():
                self.event.clear()
                await self.event.wait()

        await asyncio.wait_for(loop(), 5)


async def test_a_frame_nested_too_deep_to_parse_is_dropped(rng: random.Random) -> None:
    """JSON past the parser's own recursion limit is an unparsable frame,
    not an error that ends the link (SR-11)."""
    frames: list[dict[str, Any]] = []

    async def on_frame(frame: dict[str, Any]) -> None:
        frames.append(frame)

    link = RelayLink("ws://127.0.0.1:1", "relay.test", instance(rng), FakeClock(), on_frame)
    depth = 200_000
    await link._dispatch("[" * depth + "]" * depth)
    await link._dispatch(json.dumps({"t": "deliver", "env": {}}))
    assert [f["t"] for f in frames] == ["deliver"]


async def test_a_deep_frame_is_dropped_before_it_is_parsed(
    rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Python 3.12 and 3.13 crash in ``json.loads`` on a small thread stack
    before ``RecursionError``: depth is counted on the text first."""
    frames: list[dict[str, Any]] = []

    async def on_frame(frame: dict[str, Any]) -> None:
        frames.append(frame)

    link = RelayLink("ws://127.0.0.1:1", "relay.test", instance(rng), FakeClock(), on_frame)
    parsed: list[int] = []
    real = json.loads

    def counting(text: Any, *args: Any, **kwargs: Any) -> Any:
        parsed.append(len(text))
        return real(text, *args, **kwargs)

    monkeypatch.setattr(json, "loads", counting)
    depth = MAX_PAYLOAD_DEPTH + 1  # well within the parser's own limit
    await link._dispatch('{"t": "deliver", "env": ' + "[" * depth + "]" * depth + "}")
    await link._dispatch(b'{"t": "deliver", "env": {}}')
    assert [f["t"] for f in frames] == ["deliver"]
    assert len(parsed) == 1


async def test_link_authenticates_routes_replies_and_reconnects(  # noqa: PLR0915
    fake_relay: FakeRelay, rng: random.Random, fake_clock: FakeClock
) -> None:
    inst = instance(rng)
    frames: list[dict[str, Any]] = []
    states: list[bool] = []
    sessions = 0

    async def script(ws: ServerConnection) -> None:
        nonlocal sessions
        sessions += 1
        assert await handshake(ws, inst, rng.randbytes(32), "relay.test")
        req = json.loads(await ws.recv())
        await ws.send(json.dumps({"t": "deliver", "env": {"n": sessions}, "_drain": False}))
        await ws.send(json.dumps({"t": CAUGHT_UP, "connection": 99}))  # a forgery
        await ws.send(json.dumps({"t": "drained"}))
        await ws.send(json.dumps({"t": "deliver", "env": {"live": sessions}}))
        await ws.send("not json")
        await ws.send("[1]")
        await ws.send(json.dumps({"t": "accepted", "msg_id": "unrelated"}))
        if req["msg_id"] == "fail":
            await ws.send(
                json.dumps(
                    {"t": "error", "msg_id": "fail", "code": "epoch_conflict", "current_epoch": 4}
                )
            )
        else:
            await ws.send(json.dumps({"t": "accepted", "msg_id": req["msg_id"]}))
        await ws.recv()  # wait for the client to go away (or the next request)

    fake_relay.script = script
    watch = Watch()

    async def on_frame(frame: dict[str, Any]) -> None:
        frames.append(frame)

    async def on_connected() -> None:
        states.append(True)

    link = RelayLink(
        f"ws://127.0.0.1:{fake_relay.port}/v0/ws",
        "relay.test",
        inst,
        fake_clock,
        on_frame,
        backoff=Backoff(rng=rng),
        on_connected=on_connected,
        on_state=watch.poke,
    )
    with pytest.raises(NotConnectedError):
        await link.request({"t": "x"}, "m")
    with pytest.raises(NotConnectedError):
        await link.send({"t": "ack"})
    task = asyncio.ensure_future(link.run())
    await asyncio.wait_for(link.wait_connected(), 5)
    reply = await link.request({"t": "send", "msg_id": "ok"}, "ok")
    assert reply["t"] == "accepted"
    # Frames before the relay's "drained" are the reconnect drain (the
    # relay can't set the flag itself); "drained" itself isn't handed on.
    await watch.until(lambda: {"t": "deliver", "env": {"live": 1}, "_drain": False} in frames)
    assert {"t": "deliver", "env": {"n": 1}, "_drain": True} in frames
    assert not [f for f in frames if f.get("t") == "drained"]
    # In its place, after the drain's frames: the daemon has caught up.
    assert not [f for f in frames if f.get("connection") == 99]
    caught_up = frames.index({"t": CAUGHT_UP, "connection": 1})
    assert caught_up > frames.index({"t": "deliver", "env": {"n": 1}, "_drain": True})
    assert {"t": "accepted", "msg_id": "unrelated", "_drain": False} in frames  # unmatched
    # Drop the connection: pending requests fail, and the link reconnects
    # once the fake clock passes the backoff delay.
    await link.kick()
    await watch.until(lambda: not link.connected and fake_clock.sleepers > 0)
    fake_clock.advance(60)
    await asyncio.wait_for(link.wait_connected(), 5)
    with pytest.raises(RelayError) as err:
        await link.request({"t": "send", "msg_id": "fail"}, "fail")
    assert err.value.code == "epoch_conflict"
    assert err.value.current_epoch == 4
    assert link.connections == 2
    assert states == [True, True]
    await link.stop()
    await asyncio.wait_for(task, 5)


async def test_a_send_on_a_closed_socket_takes_the_link_down(
    fake_relay: FakeRelay, rng: random.Random, fake_clock: FakeClock
) -> None:
    """Regression: the relay closed the socket while run() was busy with a
    frame, so the link still looked connected. A failed send must take it
    down itself: the outbox retries on NotConnectedError via
    wait_connected(), and if that returned at once the retry would fail
    again without ever yielding, starving the event loop (and shutdown)."""
    inst = instance(rng)
    busy = asyncio.Event()
    release = asyncio.Event()
    closed = asyncio.Event()

    async def script(ws: ServerConnection) -> None:
        assert await handshake(ws, inst, rng.randbytes(32), "relay.test")
        await ws.send(json.dumps({"t": "deliver", "env": {}}))
        await ws.close()
        closed.set()

    fake_relay.script = script

    async def on_frame(_frame: dict[str, Any]) -> None:
        busy.set()
        await release.wait()

    link = RelayLink(
        f"ws://127.0.0.1:{fake_relay.port}/v0/ws",
        "relay.test",
        inst,
        fake_clock,
        on_frame,
        backoff=Backoff(rng=rng),
    )
    task = asyncio.ensure_future(link.run())
    await asyncio.wait_for(asyncio.gather(busy.wait(), closed.wait()), 5)
    assert link.connected  # run() hasn't seen the close yet
    with pytest.raises(NotConnectedError):
        await link.send({"t": "ack"})
    assert not link.connected
    with pytest.raises(NotConnectedError):
        await link.request({"t": "send", "msg_id": "m"}, "m")
    release.set()
    await link.stop()
    await asyncio.wait_for(task, 5)
    assert link.connections == 1


@pytest.mark.parametrize(
    "mode",
    [
        "no_challenge",
        "bad_ready",
        "close",
        "missing_nonce",
        "nonce_not_str",
        "nonce_not_b64",
        "short_nonce",
        "long_nonce",
        "challenge_array",
        "ready_array",
    ],
)
async def test_link_retries_on_failed_authentication(
    fake_relay: FakeRelay, rng: random.Random, fake_clock: FakeClock, mode: str
) -> None:
    inst = instance(rng)
    attempts = 0

    async def script(ws: ServerConnection) -> None:
        nonlocal attempts
        attempts += 1
        if mode == "no_challenge":
            await ws.send(json.dumps({"t": "ready"}))
        elif mode == "bad_ready":
            await handshake(ws, inst, rng.randbytes(32), "other.host")
        elif mode == "ready_array":
            await ws.send(json.dumps({"t": "challenge", "nonce": b64(rng.randbytes(32))}))
            await ws.recv()
            await ws.send("[1]")
        else:
            # Malformed challenges (SPEC 8.2): each must cause a reconnect,
            # never end the link task.
            challenge: Any = {
                "missing_nonce": {"t": "challenge"},
                "nonce_not_str": {"t": "challenge", "nonce": 7},
                "nonce_not_b64": {"t": "challenge", "nonce": "!!!"},
                "short_nonce": {"t": "challenge", "nonce": b64(rng.randbytes(31))},
                "long_nonce": {"t": "challenge", "nonce": b64(rng.randbytes(32) + b"x.")},
                "challenge_array": ["challenge"],
            }.get(mode)
            if challenge is not None:
                await ws.send(json.dumps(challenge))
        await ws.close()

    fake_relay.script = script
    watch = Watch()

    async def ignore(_frame: dict[str, Any]) -> None:
        return None

    link = RelayLink(
        f"ws://127.0.0.1:{fake_relay.port}/v0/ws",
        "relay.test",
        inst,
        fake_clock,
        ignore,
        backoff=Backoff(rng=rng),
        on_state=watch.poke,
    )
    task = asyncio.ensure_future(link.run())
    await watch.until(lambda: fake_clock.sleepers > 0)
    assert not link.connected
    assert attempts == 1
    assert not task.done(), "the link keeps retrying"
    # It does retry: a second attempt after the backoff.
    fake_clock.advance(60)
    await watch.until(lambda: attempts == 2 and fake_clock.sleepers > 0)
    assert not task.done()
    await link.stop()
    fake_clock.advance(60)
    await asyncio.wait_for(task, 5)
    assert link.connections == 0


async def test_link_answers_relay_pings_while_its_handler_is_busy(
    fake_relay: FakeRelay, rng: random.Random, fake_clock: FakeClock
) -> None:
    """The relay pings every connection and closes one that stays silent
    (relay/README.md, "Connection limits"). The link answers pings on its
    own, also while the daemon is still handling an earlier frame."""
    inst = instance(rng)
    busy = asyncio.Event()
    release = asyncio.Event()
    ponged: list[bool] = []

    async def script(ws: ServerConnection) -> None:
        assert await handshake(ws, inst, rng.randbytes(32), "relay.test")
        await ws.send(json.dumps({"t": "deliver", "env": {}}))
        await busy.wait()
        for _ in range(3):
            waiter = await ws.ping()
            await asyncio.wait_for(waiter, 5)
            ponged.append(True)
        release.set()
        await ws.recv()

    fake_relay.script = script

    async def on_frame(_frame: dict[str, Any]) -> None:
        busy.set()
        await release.wait()

    link = RelayLink(
        f"ws://127.0.0.1:{fake_relay.port}/v0/ws",
        "relay.test",
        inst,
        fake_clock,
        on_frame,
        backoff=Backoff(rng=rng),
    )
    task = asyncio.ensure_future(link.run())
    await asyncio.wait_for(release.wait(), 5)
    assert ponged == [True, True, True]
    assert link.connected
    await link.stop()
    await asyncio.wait_for(task, 5)
    assert link.connections == 1


@pytest.mark.parametrize("cap", ["total", "mailbox"])
async def test_link_retries_after_the_relay_refuses_a_connection_at_a_cap(
    fake_relay: FakeRelay, rng: random.Random, fake_clock: FakeClock, cap: str
) -> None:
    """The relay's connection caps: past the total an upgrade gets HTTP 503,
    past the per-mailbox cap the authenticated connection gets
    `rate_limited` and close code 1013. Either way the link backs off and
    tries again."""
    inst = instance(rng)
    sessions = 0
    if cap == "total":
        fake_relay.refuse_upgrades = 1

    async def script(ws: ServerConnection) -> None:
        nonlocal sessions
        sessions += 1
        if cap == "mailbox" and sessions == 1:
            await ws.send(json.dumps({"t": "challenge", "nonce": b64(rng.randbytes(32))}))
            await ws.recv()
            error = {"t": "error", "code": "rate_limited", "detail": "too many connections"}
            await ws.send(json.dumps(error))
            await ws.close(1013, "too_many_connections")
            return
        assert await handshake(ws, inst, rng.randbytes(32), "relay.test")
        await ws.recv()

    fake_relay.script = script
    watch = Watch()

    async def ignore(_frame: dict[str, Any]) -> None:
        return None

    link = RelayLink(
        f"ws://127.0.0.1:{fake_relay.port}/v0/ws",
        "relay.test",
        inst,
        fake_clock,
        ignore,
        backoff=Backoff(rng=rng),
        on_state=watch.poke,
    )
    task = asyncio.ensure_future(link.run())
    await watch.until(lambda: fake_clock.sleepers > 0)
    assert not link.connected
    assert not task.done()
    fake_clock.advance(60)
    await asyncio.wait_for(link.wait_connected(), 5)
    assert fake_relay.upgrades == 2
    assert link.connections == 1
    await link.stop()
    await asyncio.wait_for(task, 5)


async def test_rest_signs_every_request_with_a_fresh_ts(
    rng: random.Random, fake_clock: FakeClock
) -> None:
    inst = instance(rng)
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "GET" and request.url.path.endswith("/gone"):
            return httpx.Response(404, json={"code": "invite_not_open", "detail": "x"})
        if request.method == "DELETE":
            return httpx.Response(204)
        if request.method == "POST":
            return httpx.Response(201, json=json.loads(request.content))
        return httpx.Response(200, json={"status": "open"})

    rest = RelayRest(
        "http://relay.test/", "relay.test", inst, fake_clock, httpx.MockTransport(handle)
    )
    created = await rest.create_invite({"invite_id": "i"})
    assert created["inviter_mailbox"] == inst.mailbox_id
    await rest.create_invite({"invite_id": "j"})
    await rest.revoke_invite("i")
    assert (await rest.invite_meta("i"))["status"] == "open"
    with pytest.raises(RelayError, match="invite_not_open"):
        await rest.invite_meta("gone")
    signed = [r for r in seen if "authorization" in r.headers]
    assert len(signed) == 3
    stamps = [int(r.headers["authorization"].split(" ")[1].split(".")[1]) for r in signed]
    assert stamps == sorted(set(stamps))  # strictly increasing, never reused
    assert stamps[0] == fake_clock.unix_millis() // 1000
    key, ts, sig = signed[0].headers["authorization"].split(" ")[1].split(".")
    assert unb64(key) == inst.public_key
    expected = inst.sign_relay_request(
        "POST", "/v0/invites", int(ts), signed[0].content, "relay.test"
    )
    assert unb64(sig) == expected
    assert "authorization" not in seen[-1].headers  # GET is public


async def test_rest_maps_transport_and_body_errors(
    rng: random.Random, fake_clock: FakeClock
) -> None:
    inst = instance(rng)

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/down"):
            raise httpx.ConnectError("refused", request=request)
        if request.url.path.endswith("/html"):
            return httpx.Response(502, text="<html>bad gateway</html>")
        return httpx.Response(200, json=[1])

    rest = RelayRest(
        "http://relay.test/", "relay.test", inst, fake_clock, httpx.MockTransport(handle)
    )
    for path, code in (
        ("down", "relay_unreachable"),
        ("html", "internal"),
        ("list", "bad_response"),
    ):
        with pytest.raises(RelayError) as err:
            await rest.invite_meta(path)
        assert err.value.code == code


async def test_rest_signs_again_once_when_a_restarted_relay_says_when(
    rng: random.Random, fake_clock: FakeClock
) -> None:
    # A relay that just restarted answers rate_limited with retry_after
    # (SPEC 8.1.1): the request is signed again once, after that wait.
    inst = instance(rng)
    seen: list[httpx.Request] = []
    refusals = [{"code": "rate_limited", "detail": "restarted", "retry_after": 7}]

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if refusals:
            return httpx.Response(429, json=refusals.pop())
        return httpx.Response(204)

    rest = RelayRest(
        "http://relay.test/", "relay.test", inst, fake_clock, httpx.MockTransport(handle)
    )
    task = asyncio.ensure_future(rest.revoke_invite("i"))
    for _ in range(100):
        if fake_clock.sleepers:
            break
        await asyncio.sleep(0)
    assert len(seen) == 1
    fake_clock.advance(7)
    await asyncio.wait_for(task, 5)
    assert len(seen) == 2
    stamps = [int(r.headers["authorization"].split(" ")[1].split(".")[1]) for r in seen]
    assert stamps[1] > stamps[0]

    # Only once, only for that hint, and never for a long one.
    for refusal in (
        [{"code": "rate_limited", "detail": "x", "retry_after": 1}] * 2,
        [{"code": "rate_limited", "detail": "a mailbox's rate"}],
        [{"code": "rate_limited", "detail": "x", "retry_after": 3600}],
        [{"code": "quota_exceeded", "detail": "x", "retry_after": 1}],
    ):
        refusals[:] = refusal
        task = asyncio.ensure_future(rest.revoke_invite("i"))
        for _ in range(50):
            if task.done():
                break
            if fake_clock.sleepers:
                fake_clock.advance(1)
            await asyncio.sleep(0)
        with pytest.raises(RelayError) as err:
            await asyncio.wait_for(task, 5)
        assert err.value.code == refusal[0]["code"]


# -- proxies: a loopback relay is always reached directly (MAR-299 / SR-30 class)


class _Recorder:
    """A loopback server on a thread: records each connection's first bytes
    and answers ``answer``."""

    def __init__(self, answer: bytes) -> None:
        import socket  # noqa: PLC0415

        self._sock = socket.create_server(("127.0.0.1", 0))
        self._sock.settimeout(0.05)
        self.port = self._sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.received: list[bytes] = []
        self.got = threading.Event()
        self._answer, self._open = answer, True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while self._open:
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(2)
                try:
                    self.received.append(conn.recv(65536))
                    self.got.set()
                    conn.sendall(self._answer)
                except OSError:
                    pass

    def close(self) -> list[bytes]:
        self._open = False
        self._thread.join(timeout=5)
        self._sock.close()
        return self.received


PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


@pytest.fixture
def proxy(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Recorder]:
    """Every proxy variable points at a recorder, and nothing bypasses it."""
    recorder = _Recorder(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
    for var in PROXY_VARS:
        monkeypatch.setenv(var, recorder.url)
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    yield recorder
    recorder.close()


async def test_rest_to_a_loopback_relay_goes_direct(proxy: _Recorder, rng: random.Random) -> None:
    body = json.dumps({"group_name": "Ops"}).encode()
    relay = _Recorder(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
        + f"content-length: {len(body)}\r\nconnection: close\r\n\r\n".encode()
        + body
    )
    try:
        rest = RelayRest(relay.url, "relay.test", instance(rng), FakeClock())
        assert await rest.invite_meta("inv1") == {"group_name": "Ops"}
    finally:
        got = relay.close()
    assert len(got) == 1
    assert got[0].startswith(b"GET /v0/invites/inv1 ")
    assert proxy.close() == []


async def test_rest_to_a_remote_relay_honours_the_proxy(
    proxy: _Recorder, rng: random.Random
) -> None:
    # An operator may need a proxy to reach a relay elsewhere.
    rest = RelayRest(
        "http://relay.example.org:8443", "relay.example.org", instance(rng), FakeClock()
    )
    with pytest.raises(RelayError):
        await rest.invite_meta("inv1")
    (seen,) = proxy.close()
    assert seen.startswith(b"GET http://relay.example.org:8443/v0/invites/inv1 ")


async def test_the_websocket_to_a_loopback_relay_goes_direct(
    fake_relay: FakeRelay, proxy: _Recorder, rng: random.Random, fake_clock: FakeClock
) -> None:
    inst = instance(rng)

    async def script(ws: ServerConnection) -> None:
        await handshake(ws, inst, b"\x01" * 32, "relay.test")
        await ws.wait_closed()

    fake_relay.script = script

    async def on_frame(_frame: dict[str, Any]) -> None:
        return None

    link = RelayLink(
        f"ws://127.0.0.1:{fake_relay.port}/v0/ws", "relay.test", inst, fake_clock, on_frame
    )
    task = asyncio.ensure_future(link.run())
    try:
        await asyncio.wait_for(link.wait_connected(), 5)
    finally:
        await link.stop()
        await asyncio.wait_for(task, 5)
    assert proxy.close() == []


async def test_the_websocket_to_a_remote_relay_honours_the_proxy(
    proxy: _Recorder, rng: random.Random, fake_clock: FakeClock
) -> None:
    async def on_frame(_frame: dict[str, Any]) -> None:
        return None

    link = RelayLink(
        "ws://relay.example.org:8080/v0/ws",
        "relay.example.org",
        instance(rng),
        fake_clock,
        on_frame,
    )
    task = asyncio.ensure_future(link.run())

    try:
        assert await asyncio.to_thread(proxy.got.wait, 5)
    finally:
        # After the proxy's 502 the link backs off on the fake clock: cancel.
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    assert proxy.close()[0].startswith(b"CONNECT relay.example.org:8080 ")
