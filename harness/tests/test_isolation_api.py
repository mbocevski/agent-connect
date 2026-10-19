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
import stat
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentconnect.isolation import AGENT_DIR_MODE, PeerCred, PeerGate
from agentconnect.runtime.api import MAX_PENDING, ApiServer
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
    cluster: Cluster, agent_dir: Path, rng: random.Random
) -> None:
    """Connections still sending their request are limited per peer UID: an
    agent user that opens far more of them than that closes only its own
    oldest, so the human user's unfinished request survives and completes."""
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
