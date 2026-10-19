"""Separate-OS-user mode through the real API server and socket.

The peer's UID is injected (no second OS user in the fast tier); everything
else is the server the daemon runs: the accept-time UID check, the human-UID
gate on top of the human token, and the socket and agent directory modes.
"""

from __future__ import annotations

import asyncio
import os
import random
import shutil
import socket
import stat
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentconnect.isolation import AGENT_DIR_MODE, PeerCred, PeerGate
from agentconnect.runtime.api import (
    MAX_AGENT_REQUESTS,
    MAX_PENDING,
    MAX_PENDING_PER_PEER_HARD,
    MAX_STREAMS_PER_PEER,
    ApiServer,
)
from agentconnect.sse import SseAdapter
from agentconnect_harness.cluster import WAIT, Cluster, api_token

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="the mode refuses to run as root")


@pytest.fixture
def agent_dir() -> Iterator[Path]:
    # Unix socket paths are limited to ~100 bytes; pytest's tmp paths can be longer.
    d = Path(tempfile.mkdtemp(prefix="ac-"))
    d.chmod(AGENT_DIR_MODE)
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def until(predicate: Callable[[], bool]) -> None:
    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - the server announces nothing
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


def _uid(rng: random.Random) -> int:
    while (uid := rng.randrange(20_000, 60_000)) == os.geteuid():
        pass
    return uid


async def test_peer_uid_and_human_uid_gates(
    cluster: Cluster, agent_dir: Path, rng: random.Random
) -> None:
    node = await cluster.node("iso")
    agent_uid, stranger = _uid(rng), _uid(rng)
    while stranger == agent_uid:
        stranger = _uid(rng)
    cfg = node.config.with_overrides(
        isolation=True,
        isolation_agent_dir=agent_dir,
        isolation_group=str(os.getgid()),
        isolation_agent_users=(str(agent_uid),),
    )
    node.config = node.daemon.config = cfg
    peer = {"uid": agent_uid}
    gate = PeerGate.from_config(cfg, credentials=lambda _s: PeerCred(peer["uid"], os.getgid()))
    server = ApiServer(node.daemon, gate)
    await server.start()
    try:
        sock = Path(str(server.address))
        assert sock.parent == agent_dir
        assert stat.S_IMODE(os.stat(str(sock)).st_mode) == 0o660
        # Agents read the agent token from the agent directory; never the human token.
        assert (agent_dir / "api-token").read_text() == api_token(server, "agent")
        assert not (agent_dir / "human-token").exists()
        transport = httpx.AsyncHTTPTransport(uds=str(sock))

        async def call(uid: int, scope: str, method: str, path: str) -> tuple[int, Any]:
            peer["uid"] = uid
            headers = {"authorization": f"Bearer {api_token(server, scope)}"}
            async with httpx.AsyncClient(transport=transport, base_url="http://ac") as c:
                resp = await c.request(method, path, headers=headers, json={})
            return resp.status_code, resp.json()

        me = os.geteuid()
        # The agent user uses agent routes...
        assert (await call(agent_uid, "agent", "GET", "/v0/status"))[0] == 200
        # ...but not the human-only ones, with either token.
        status, err = await call(agent_uid, "agent", "POST", "/v0/approvals/nope/approve")
        assert (status, err["code"]) == (403, "human_only")
        status, err = await call(agent_uid, "human", "POST", "/v0/approvals/nope/approve")
        assert (status, err["code"]) == (403, "peer_refused")
        status, err = await call(agent_uid, "human", "POST", "/v0/groups/g/sas/mismatch")
        assert (status, err["code"]) == (403, "peer_refused")
        status, err = await call(agent_uid, "human", "POST", "/v0/groups/g/members/m/verify")
        assert (status, err["code"]) == (403, "peer_refused")
        # The human token from the daemon's own user passes both gates
        # (an unknown request id is then the handler's answer).
        status, err = await call(me, "human", "POST", "/v0/approvals/nope/approve")
        assert err["code"] not in ("peer_refused", "human_only", "auth_failed")
        # The agent token alone is still refused there, whoever sends it.
        status, err = await call(me, "agent", "POST", "/v0/approvals/nope/approve")
        assert (status, err["code"]) == (403, "human_only")
        # Any other user is refused before the request is read.
        status, err = await call(stranger, "agent", "GET", "/v0/status")
        assert (status, err["code"]) == (403, "peer_refused")
    finally:
        await server.stop()


async def test_an_agent_user_cant_crowd_out_the_human_user(
    cluster: Cluster, agent_dir: Path, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Connections still sending their request are limited per peer UID: an
    agent user that opens far more of them than that closes only its own
    oldest, so the human user's unfinished request survives and completes.
    (Each has waited long enough to give way.)"""
    monkeypatch.setattr("agentconnect.runtime.api.EVICT_AFTER", 0)
    node = await cluster.node("iso-flood")
    agent_uid = _uid(rng)
    cfg = node.config.with_overrides(
        isolation=True,
        isolation_agent_dir=agent_dir,
        isolation_group=str(os.getgid()),
        isolation_agent_users=(str(agent_uid),),
    )
    node.config = node.daemon.config = cfg
    peer = {"uid": os.geteuid()}
    admitted: list[int] = []

    def credentials(_sock: object) -> PeerCred:
        admitted.append(peer["uid"])
        return PeerCred(peer["uid"], os.getgid())

    gate = PeerGate.from_config(cfg, credentials=credentials)
    server = ApiServer(node.daemon, gate)
    await server.start()
    sock = str(server.address)
    held: list[asyncio.StreamWriter] = []

    async def half_sent() -> asyncio.StreamReader:
        before = len(admitted)
        reader, writer = await asyncio.open_unix_connection(sock)
        writer.write(b"GET /v0/status HTTP/1.1\r\nhost: ac\r\n")
        await writer.drain()
        held.append(writer)
        # Admitted (its UID read) before the next one changes it.
        await until(lambda: len(admitted) > before)
        return reader

    try:
        human = await half_sent()
        peer["uid"] = agent_uid
        first = await half_sent()
        for _ in range(3 * MAX_PENDING):
            await half_sent()
        assert b" 503 " in await first.read()
        # The human's request was never closed: it finishes now.
        token = api_token(server, "human")
        held[0].write(f"authorization: Bearer {token}\r\n\r\n".encode())
        await held[0].drain()
        assert b" 200 " in await human.read()
    finally:
        for writer in held:
            writer.close()
        await server.stop()


async def status_of(sock: socket.socket) -> bytes:
    """The status code the server answered on ``sock``, once it closed."""
    loop = asyncio.get_running_loop()
    sock.setblocking(False)
    data = b""
    try:
        while chunk := await asyncio.wait_for(loop.sock_recv(sock, 65536), WAIT):
            data += chunk
    except ConnectionResetError:
        return b"reset"
    finally:
        sock.close()
    return data.split(b" ", 2)[1] if data else b"closed"


async def isolated(
    cluster: Cluster, agent_dir: Path, users: tuple[int, ...], **node: Any
) -> tuple[ApiServer, dict[str, int]]:
    """An API server in the separate-OS-user mode with ``users`` as agent
    users, and the peer UID its next connection reports (``peer["uid"]``)."""
    n = await cluster.node("iso-" + str(users[0]), **node)
    cfg = n.config.with_overrides(
        isolation=True,
        isolation_agent_dir=agent_dir,
        isolation_group=str(os.getgid()),
        isolation_agent_users=tuple(str(u) for u in users),
    )
    n.config = n.daemon.config = cfg
    peer = {"uid": users[0]}
    gate = PeerGate.from_config(cfg, credentials=lambda _s: PeerCred(peer["uid"], os.getgid()))
    server = ApiServer(n.daemon, gate)
    await server.start()
    return server, peer


def connect(server: ApiServer) -> socket.socket:
    s = socket.socket(socket.AF_UNIX)
    s.connect(str(server.address))
    return s


def whole_request(token: str, path: str = "/v0/status", accept: str = "") -> bytes:
    extra = f"accept: {accept}\r\n" if accept else ""
    return (
        f"GET {path} HTTP/1.1\r\nhost: ac\r\n{extra}authorization: Bearer {token}\r\n\r\n".encode()
    )


@pytest.mark.parametrize("n", [12, 24, 40, 60])
async def test_one_users_requests_that_arrive_together_all_get_through(
    cluster: Cluster, agent_dir: Path, rng: random.Random, n: int
) -> None:
    """Whole requests from one agent user that arrive together, as an SDK's
    parallel calls do, are all answered, though there are more of them
    than that user may have unfinished at once."""
    server, _peer = await isolated(cluster, agent_dir, (_uid(rng),))
    token = api_token(server, "agent")
    socks = []
    try:
        for _ in range(n):  # blocking: all of them are in before the loop runs
            s = connect(server)
            s.sendall(whole_request(token))
            socks.append(s)
        assert await asyncio.gather(*(status_of(s) for s in socks)) == [b"200"] * n
    finally:
        for s in socks:
            s.close()
        await server.stop()


async def test_one_user_past_the_hard_limit_closes_its_own_quiet_ones(
    cluster: Cluster, agent_dir: Path, rng: random.Random
) -> None:
    """Past the hard limit, waiting doesn't protect an unfinished
    connection: the user's oldest that sent nothing goes, at once."""
    server, _peer = await isolated(cluster, agent_dir, (_uid(rng),))
    held = []
    try:
        partial = connect(server)
        partial.sendall(b"GET /v0/status HTTP/1.1\r\n")
        held.append(partial)
        await until(lambda: len(server._pending) == 1 and server._pending[0].started)
        for _ in range(MAX_PENDING_PER_PEER_HARD - 1):
            held.append(connect(server))
        await until(lambda: len(server._pending) == MAX_PENDING_PER_PEER_HARD)
        held.append(connect(server))
        assert await status_of(held[1]) == b"503"
        await until(lambda: len(server._pending) == MAX_PENDING_PER_PEER_HARD)
        assert server._pending[0].started  # the one that sent part of its request stays
    finally:
        for s in held:
            s.close()
        await server.stop()


async def test_one_agent_user_cant_hold_every_agent_request(
    cluster: Cluster, agent_dir: Path, rng: random.Random
) -> None:
    """Event streams are limited per agent user, so one agent user holding
    as many as it may doesn't leave another agent user's requests `503`."""
    x, y = _uid(rng), _uid(rng)
    while y == x:
        y = _uid(rng)
    server, peer = await isolated(
        cluster,
        agent_dir,
        (x, y),
        default_adapter="sse",
        make_adapters=lambda cfg, clock: [SseAdapter(clock, cfg.sse_retention)],
    )
    token = api_token(server, "agent")
    held = []
    try:
        refused = None
        for _ in range(MAX_AGENT_REQUESTS):
            s = connect(server)
            s.sendall(whole_request(token, "/v0/events", accept="text/event-stream"))
            held.append(s)
            s.setblocking(False)
            first = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(s, 64), WAIT)
            if b" 503 " in first:
                refused = len(held)
                break
        assert refused == MAX_STREAMS_PER_PEER + 1
        peer["uid"] = y
        s = connect(server)
        s.sendall(whole_request(token))
        assert await status_of(s) == b"200"
        s = connect(server)
        s.sendall(whole_request(token, "/v0/events", accept="text/event-stream"))
        held.append(s)
        s.setblocking(False)
        first = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(s, 64), WAIT)
        assert first.startswith(b"HTTP/1.1 200 ")
    finally:
        for s in held:
            s.close()
        await server.stop()
