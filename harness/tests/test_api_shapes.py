"""The request and response shapes in ``api.ROUTE_SPECS`` (which generate
docs/api.md) against a real daemon."""

from __future__ import annotations

import base64
import shutil
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest_asyncio

from agentconnect.runtime.api import ROUTE_SPECS, ApiServer, RouteSpec
from agentconnect.shapes import conforms
from agentconnect_harness.cluster import Cluster, Node, api_token


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
        headers = {"authorization": f"Bearer {api_token(self.server, scope)}"}
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
    (req,) = (await alice.call("GET", "/v0/approvals", scope="human"))["approvals"]
    await alice.call("POST", f"/v0/approvals/{req['request_id']}/approve", scope="human")
    await bob.node.wait(lambda: bob.node.daemon.store.group(gid) is not None)
    await cluster.settle(gid, 1)

    await alice.call("GET", "/v0/groups")
    await alice.call("GET", f"/v0/groups/{gid}")
    await bob.call("GET", f"/v0/groups/{gid}")
    await alice.call(
        "POST",
        f"/v0/groups/{gid}/members/{bob.node.me}/verify",
        {"verified": True, "epoch": alice.node.epoch(gid)},
        "human",
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
    held = (await alice.call("GET", "/v0/approvals", scope="human"))["messages"]
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


async def test_membership_routes_match_the_declared_shapes(cluster: Cluster, sockdir: Path) -> None:
    alice = await serve(cluster, "alice", sockdir, auto_approve=True)
    bob = await serve(cluster, "bob", sockdir, auto_approve=True)
    gid = (await alice.call("POST", "/v0/groups", {"name": "Ops"}))["group_id"]
    await alice.node.idle()
    await cluster.invite(alice.node, bob.node, gid)
    replica = await cluster.node("bob2", identity_of=bob.node)
    await cluster.invite(alice.node, replica, gid)
    info = await bob.call("GET", f"/v0/groups/{gid}")
    (mine,) = [m for m in info["members"] if m["self"]]
    other = next(i["instance_id"] for i in mine["instances"] if not i["self"])
    path = f"/v0/groups/{gid}/members/{bob.node.me}/remove"
    for body, answer in (
        ({"instances": "x"}, (400, "bad_request")),
        ({"instances": []}, (400, "bad_request")),
        ({}, (404, "not_found")),  # one's own identity needs instances
    ):
        assert await refused(bob, "POST", path, body) == answer
    nobody = f"/v0/groups/{gid}/members/ac:v0:nobody/remove"
    assert await refused(bob, "POST", nobody, {"instances": [other]}) == (404, "not_found")
    await bob.call("POST", path, {"instances": [other]}, "human")
    await bob.node.wait(lambda: len(bob.node.daemon.client.members(_raw(gid))) == 2)
    await bob.call("POST", f"/v0/groups/{gid}/leave")
    info = await bob.call("GET", f"/v0/groups/{gid}")
    assert info["leaving"] is None or info["leaving"]["blocked"] is False
    await alice.server.stop()
    await bob.server.stop()


async def test_role_and_policy_routes_match_the_declared_shapes(
    cluster: Cluster, sockdir: Path
) -> None:
    """The routes of roles and the policy: what each token may do, the
    core's dry run as `403 not_permitted`, and the answers' shapes."""
    alice = await serve(cluster, "alice", sockdir, auto_approve=True)
    bob = await serve(cluster, "bob", sockdir, auto_approve=True)
    made = {"name": "Ops", "policy": {"floor": "moderated", "max_members": 10}}
    for scope, answer in (("agent", (403, "human_only")),):
        assert await refused(alice, "POST", "/v0/groups", made, scope) == answer
    assert await refused(alice, "POST", "/v0/groups", {"name": "x", "policy": 1}) == (
        400,
        "bad_request",
    )
    assert await refused(
        alice, "POST", "/v0/groups", {"name": "x", "policy": {"require_verified": 1}}, "agent"
    ) == (400, "bad_request")
    for bad in ({"max_members": 0}, {"owner": bob.node.me}):
        assert await refused(alice, "POST", "/v0/groups", {"name": "x", "policy": bad}) == (
            400,
            "bad_request",
        )
    agent_made = {"name": "Mine", "policy": {"require_verified": True}}
    mine = (await alice.call("POST", "/v0/groups", agent_made))["group_id"]
    assert alice.node.daemon.group_info(mine)["policy"]["require_verified"] is True
    gid = (await alice.call("POST", "/v0/groups", made, "human"))["group_id"]
    assert alice.node.daemon.group_info(gid)["floor"] == {
        "mode": "moderated",
        "pinned": True,
        "moderator": None,
    }
    await alice.node.idle()
    await cluster.invite(alice.node, bob.node, gid)

    path = f"/v0/groups/{gid}/policy"
    for body in ({"invite": "members"}, {"require_verified": False}, {}):
        assert await refused(alice, "POST", path, body, "agent") == (403, "human_only")
    assert await refused(alice, "POST", path, {"require_verified": "yes"}, "agent") == (
        400,
        "bad_request",
    )
    for body in ({"owner": bob.node.me}, {}, {"max_members": 0}, {"invite": "anyone"}):
        assert await refused(alice, "POST", path, body) == (400, "bad_request")
    assert await refused(bob, "POST", path, {"require_verified": True}, "agent") == (
        403,
        "not_permitted",
    )
    answer = await alice.call("POST", path, {"invite": "members", "max_agent_turns": 5}, "human")
    assert answer == {"status": "committing"}
    await alice.node.wait(lambda: alice.node.daemon.store.outbox() == [])
    assert await alice.call("POST", path, {"invite": "members"}, "human") == {"status": "unchanged"}
    assert await alice.call("POST", path, {"require_verified": True}) == {"status": "committing"}

    role = f"/v0/groups/{gid}/members/{bob.node.me}/role"
    assert await refused(alice, "POST", role, {"role": "admin"}, "agent") == (403, "human_only")
    assert await refused(alice, "POST", role, {"role": "owner"}) == (400, "bad_request")
    assert await refused(
        bob, "POST", f"/v0/groups/{gid}/members/{alice.node.me}/role", {"role": "admin"}
    ) == (400, "bad_request")
    nobody = f"/v0/groups/{gid}/members/ac:v0:nobody/role"
    assert await refused(alice, "POST", nobody, {"role": "admin"}) == (404, "not_found")
    await alice.call("POST", role, {"role": "admin"}, "human")

    owner = f"/v0/groups/{gid}/owner"
    hand_over = {"identity": bob.node.me, "keep_admin": False}
    assert await refused(alice, "POST", owner, hand_over, "agent") == (403, "human_only")
    assert await refused(alice, "POST", owner, {"identity": bob.node.me, "keep_admin": 1}) == (
        400,
        "bad_request",
    )
    await alice.node.wait(lambda: alice.node.daemon.store.outbox() == [])
    await alice.call("POST", owner, hand_over, "human")
    await alice.node.wait(
        lambda: alice.node.daemon.group_info(gid)["policy"]["owner"] == bob.node.me
    )
    info = await alice.call("GET", f"/v0/groups/{gid}")
    assert info["policy_summary"]["invite"] == "members"
    assert info["policy_summary"]["max_agent_turns"] == 5
    assert {"POST /v0/groups/{gid}/owner", "POST /v0/groups/{gid}/members/{identity}/role"} <= (
        alice.seen
    )
    await alice.server.stop()
    await bob.server.stop()


async def refused(
    rec: Recorder, method: str, path: str, body: Any, scope: str = "human"
) -> tuple[int, str]:
    """The status and error code of a request the API refuses."""
    headers = {"authorization": f"Bearer {api_token(rec.server, scope)}"}
    async with httpx.AsyncClient(transport=rec.transport, base_url="http://ac") as c:
        resp = await c.request(method, path, json=body, headers=headers)
    return resp.status_code, str(resp.json()["code"])


def _raw(gid: str) -> bytes:
    return base64.urlsafe_b64decode(gid + "=" * (-len(gid) % 4))
