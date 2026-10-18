"""``GET /v0/deliveries`` and ``POST /v0/deliveries/ack``: what an attached
MCP session pulls from the runtime that holds the data directory."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from agentconnect.deliveries import DeliveryQueue
from agentconnect.runtime.agent import a2a_text
from agentconnect.runtime.api import ROUTE_SPECS
from agentconnect.shapes import conforms
from agentconnect.sockets import bind_path
from agentconnect.tokens import API_TOKEN_FILE
from agentconnect_harness.cluster import WAIT, Cluster, Node

pytestmark = pytest.mark.hosts("daemon")

SPECS = {f"{s.method} {s.path}": s for s in ROUTE_SPECS}


def client(node: Node) -> httpx.AsyncClient:
    token = (node.config.data_dir / API_TOKEN_FILE).read_text(encoding="ascii").strip()
    transport = httpx.AsyncHTTPTransport(uds=str(bind_path(node.config.socket_path)))
    return httpx.AsyncClient(
        transport=transport,
        base_url="http://ac",
        headers={"authorization": f"Bearer {token}"},
        timeout=WAIT,
    )


async def owner_and_peer(cluster: Cluster) -> tuple[Node, Node, str, DeliveryQueue]:
    queues: list[DeliveryQueue] = []

    def make(_cfg: Any, clock: Any) -> list[Any]:
        queues.append(DeliveryQueue(clock))
        return queues[-1:]

    owner = await cluster.node("owner", default_adapter="mcp", make_adapters=make, serve_api=True)
    peer = await cluster.node("peer")
    gid = owner.daemon.create_group("Ops", "Deploys")
    await owner.idle()
    await cluster.invite(owner, peer, gid)
    return owner, peer, gid, queues[-1]


async def until(predicate: Callable[[], bool]) -> None:
    """Poll state that has no pulse (TESTING.md: under asyncio.wait_for)."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


def send(peer: Node, gid: str, text: str) -> None:
    peer.daemon.queue_message(
        gid, a2a_text(gid, text, human=False), to=["*"], kind="a2a.message", origin="agent"
    )


async def test_a_long_poll_returns_leases_and_acks(cluster: Cluster) -> None:
    owner, peer, gid, queue = await owner_and_peer(cluster)
    async with client(owner) as api:
        polling = asyncio.ensure_future(
            api.get("/v0/deliveries", params={"timeout": 60, "addressed_only": 1})
        )
        await until(lambda: queue.waiting == 1)
        send(peer, gid, "hello")
        resp = await asyncio.wait_for(polling, WAIT)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert conforms(data, SPECS["GET /v0/deliveries"].response)
        (item,) = data["deliveries"]
        assert item["message"]["untrusted"] is True
        assert item["message"]["a2a"]["parts"] == [{"text": "hello"}]
        # Leased: another caller doesn't get it.
        again = await api.get("/v0/deliveries", params={"group": gid})
        assert again.json()["deliveries"] == []
        body = {"ids": [item["delivery_id"]]}
        assert conforms(body, SPECS["POST /v0/deliveries/ack"].request)
        acked = await api.post("/v0/deliveries/ack", json=body)
        assert acked.json() == {"acked": 1}
        assert (await api.post("/v0/deliveries/ack", json=body)).json() == {"acked": 0}

        for params in ({"timeout": 61}, {"addressed_only": "yes"}, {"timeout": "-1"}):
            refused = await api.get("/v0/deliveries", params=params)
            assert (refused.status_code, refused.json()["code"]) == (400, "bad_request")
        for bad in ({"ids": "1"}, {"ids": ["x"]}, {}):
            refused = await api.post("/v0/deliveries/ack", json=bad)
            assert refused.status_code == 400


async def test_a_caller_that_leaves_leases_nothing(cluster: Cluster) -> None:
    owner, peer, gid, queue = await owner_and_peer(cluster)
    async with client(owner) as api:
        polling = asyncio.ensure_future(api.get("/v0/deliveries", params={"timeout": 60}))
        await until(lambda: queue.waiting == 1)
        polling.cancel()
        with pytest.raises(asyncio.CancelledError):
            await polling
        await until(lambda: queue.waiting == 0)
        send(peer, gid, "after")
        got = await api.get("/v0/deliveries", params={"timeout": 60})
        assert [d["message"]["a2a"]["parts"] for d in got.json()["deliveries"]] == [
            [{"text": "after"}]
        ]


async def test_a_stopping_server_ends_waiting_polls(cluster: Cluster) -> None:
    """A long poll doesn't hold up the runtime's stop: the poll ends at
    once (the connection closes), and the caller attaches again."""
    owner, _peer, _gid, queue = await owner_and_peer(cluster)
    async with client(owner) as api:
        polling = asyncio.ensure_future(api.get("/v0/deliveries", params={"timeout": 60}))
        await until(lambda: queue.waiting == 1)
        await asyncio.wait_for(owner.runtime.stop(flush=0), WAIT)
        with pytest.raises(httpx.TransportError):
            await asyncio.wait_for(polling, WAIT)
        assert queue.waiting == 0


async def test_without_a_queue_the_routes_say_so(cluster: Cluster) -> None:
    node = await cluster.node("plain", serve_api=True)
    async with client(node) as api:
        for method, path in (("GET", "/v0/deliveries"), ("POST", "/v0/deliveries/ack")):
            resp = await api.request(method, path, json={"ids": []} if method == "POST" else None)
            assert (resp.status_code, resp.json()["code"]) == (409, "no_deliveries")
