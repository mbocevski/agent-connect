"""The request and response shapes in ``api.ROUTE_SPECS`` (which generate
docs/api.md) against a real daemon."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest_asyncio

from agentconnect.api import ROUTE_SPECS, ApiServer, RouteSpec
from agentconnect.shapes import conforms
from agentconnect_harness.cluster import Cluster, Node


class Recorder:
    """Calls the API and checks every 200 answer, and every JSON body sent,
    against the route's declared shapes."""

    def __init__(self, node: Node, server: ApiServer) -> None:
        self.node, self.server = node, server
        self.transport = httpx.AsyncHTTPTransport(uds=str(server.address))
        self.seen: set[str] = set()

    def spec_for(self, method: str, path: str) -> RouteSpec:
        bare = path.partition("?")[0]
        for route, spec in zip(self.server.routes, ROUTE_SPECS, strict=True):
            if route.method == method and route.regex.match(bare):
                return spec
        raise AssertionError(f"no route for {method} {path}")

    async def call(
        self, method: str, path: str, body: Any = None, scope: str = "agent"
    ) -> dict[str, Any]:
        spec = self.spec_for(method, path)
        if body is not None:
            assert conforms(body, spec.request), (spec.path, body)
        headers = {"authorization": f"Bearer {self.server.tokens[scope]}"}
        async with httpx.AsyncClient(transport=self.transport, base_url="http://ac") as c:
            resp = await c.request(method, path, json=body, headers=headers)
        assert resp.status_code == 200, resp.text
        data: dict[str, Any] = resp.json()
        assert conforms(data, spec.response), (spec.path, str(data))
        self.seen.add(f"{spec.method} {spec.path}")
        return data


@pytest_asyncio.fixture
async def sockdir() -> AsyncIterator[Path]:
    d = Path(tempfile.mkdtemp(prefix="ac-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def serve(cluster: Cluster, name: str, sockdir: Path, auto_approve: bool) -> Recorder:
    node = await cluster.node(name, auto_approve=auto_approve)
    node.config = node.config.with_overrides(api_socket=sockdir / f"{name}.sock")
    node.daemon.config = node.config
    server = ApiServer(node.daemon)
    await server.start()
    return Recorder(node, server)


async def test_responses_and_requests_match_the_declared_shapes(
    cluster: Cluster, sockdir: Path
) -> None:
    alice = await serve(cluster, "alice", sockdir, auto_approve=False)
    bob = await serve(cluster, "bob", sockdir, auto_approve=True)
    await alice.call("GET", "/v0/status")
    gid = (await alice.call("POST", "/v0/groups", {"name": "Ops", "purpose": "Deploys"}))[
        "group_id"
    ]
    await alice.node.idle()
    await alice.call("POST", f"/v0/groups/{gid}/policy", {"require_verified": True})
    invite = await alice.call("POST", f"/v0/groups/{gid}/invites", {"ttl_secs": 3600})
    await bob.call("POST", "/v0/invites/inspect", {"url": invite["url"]})
    await bob.call("POST", "/v0/invites/accept", {"url": invite["url"], "display_name": "bob"})
    await alice.node.wait(lambda: len(alice.node.daemon.approvals()) == 1)
    (req,) = (await alice.call("GET", "/v0/approvals"))["approvals"]
    await alice.call("POST", f"/v0/approvals/{req['request_id']}/approve", scope="human")
    await bob.node.wait(lambda: bob.node.daemon.store.group(gid) is not None)
    await cluster.settle(gid, 1)

    await alice.call("GET", "/v0/groups")
    await alice.call("GET", f"/v0/groups/{gid}")
    await bob.call("GET", f"/v0/groups/{gid}")
    await alice.call(
        "POST", f"/v0/groups/{gid}/members/{bob.node.me}/verify", {"verified": True}, "human"
    )
    await alice.call("POST", f"/v0/groups/{gid}/messages", {"text": "hello", "to": ["*"]})
    await alice.call("GET", "/v0/events?after=0")
    other = await alice.call("POST", f"/v0/groups/{gid}/invites", {})
    await alice.call("DELETE", f"/v0/invites/{other['invite_id']}")
    await bob.call("POST", f"/v0/groups/{gid}/leave")

    assert len(alice.seen | bob.seen) >= 13
    await alice.server.stop()
    await bob.server.stop()


async def test_safety_routes_match_the_declared_shapes(cluster: Cluster, sockdir: Path) -> None:
    alice = await serve(cluster, "alice", sockdir, auto_approve=True)
    bob = await serve(cluster, "bob", sockdir, auto_approve=True)
    gid = (await alice.call("POST", "/v0/groups", {"name": "Ops"}))["group_id"]
    await alice.node.idle()
    await cluster.invite(alice.node, bob.node, gid)
    await alice.call("GET", f"/v0/groups/{gid}/safety")
    changes = {"set": {"require_approval": "both", "transcript": True}}
    await alice.call("POST", f"/v0/groups/{gid}/safety", changes, "human")
    limit = {"set": {"sender_per_minute": 10}, "sender": bob.node.me}
    await alice.call("POST", f"/v0/groups/{gid}/safety", limit, "human")
    sent = await alice.call("POST", f"/v0/groups/{gid}/messages", {"text": "out"})
    assert sent["status"] == "held"
    bob.node.daemon.send_message(gid, {"text": "in"})
    await alice.node.wait(lambda: len(alice.node.daemon.held_messages()) == 2)
    held = (await alice.call("GET", "/v0/approvals"))["messages"]
    first, second = (item["hold_id"] for item in held)
    for hold_id in (first, second):
        await alice.call("GET", f"/v0/approvals/messages/{hold_id}", scope="human")
    await alice.call("POST", f"/v0/approvals/messages/{first}/approve", scope="human")
    await alice.call("POST", f"/v0/approvals/messages/{second}/reject", scope="human")
    await alice.call("GET", f"/v0/audit?group={gid}&after=0", scope="human")
    await alice.call("GET", f"/v0/groups/{gid}/transcript", scope="human")
    await alice.call("POST", f"/v0/groups/{gid}/members/{bob.node.me}/remove", scope="human")
    assert len(alice.seen) == 11
    await alice.server.stop()
    await bob.server.stop()
