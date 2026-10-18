"""Publishing, renewing and withdrawing a listing against the real relay and
the real directory, on both hosts (docs/discovery.md).

The relay and the directory use the system clock and the nodes the
cluster's fake clock, which starts at the real time: a scenario moves it by
less than the 300 s the signed requests may be off.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import httpx
import pytest

import agentconnect_core as ac
from agentconnect.failpoints import SimulatedCrash
from agentconnect.relay import RelayError, b64
from agentconnect.runtime.api import ROUTE_SPECS
from agentconnect.shapes import conforms
from agentconnect_harness.cluster import Cluster, Node, api_token, serve_api
from agentconnect_harness.directory import DirectoryProcess

CARD: dict[str, Any] = {
    "name": "Release planner",
    "description": "Plans release trains.",
    "version": "1.0.0",
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "plan", "name": "Planning", "description": "Plans.", "tags": ["planning"]}],
}


def unique_name(rng: random.Random) -> str:
    """A listing name of this scenario's own: the directory is shared."""
    return f"h{rng.getrandbits(48):012x}"


async def owner(cluster: Cluster, directory: DirectoryProcess, **kw: Any) -> Node:
    return await cluster.node("owner", directories=(directory.config,), **kw)


def body(node: Node, directory: DirectoryProcess, name: str) -> dict[str, Any]:
    token = directory.token(name, node.me, node.daemon.now())
    return {"directory": directory.host, "card": CARD, "token": json.loads(token)}


async def publish(node: Node, request: dict[str, Any]) -> dict[str, Any]:
    shown = await node.daemon.listings.preview(request)
    return await node.daemon.listings.publish(
        {**request, "content_sha256": shown["content_sha256"]}
    )


async def fetch(directory: DirectoryProcess, name: str) -> httpx.Response:
    async with httpx.AsyncClient(trust_env=False) as http:
        return await http.get(f"{directory.url}/a/{name}.json")


async def registered(node: Node, door_id: str, expires_at: int) -> bool:
    """Whether the relay holds this door id (it refuses a second registration)."""
    try:
        await node.daemon.rest.create_door(door_id, expires_at)
    except RelayError as e:
        return e.code == "bad_request" and "already exists" in e.detail
    return False


def listed_door(listing: ac.Listing) -> tuple[str, int]:
    door = listing.door
    assert door is not None
    return b64(door["id"]), int(door["expires_at"])


async def test_publish_then_withdraw_with_the_agent_token(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    node = await owner(cluster, directory)
    name = unique_name(rng)
    out = await publish(node, body(node, directory, name))
    assert out["state"] == "published"
    resp = await fetch(directory, name)
    assert resp.status_code == 200
    listing = ac.verify_listing(resp.content)
    listing.check_token(directory.host, [directory.key.public_key], node.daemon.now())
    assert listing.identity == node.me
    assert listing.relay == cluster.relay.host
    door_id, expires_at = listed_door(listing)
    assert await registered(node, door_id, expires_at)
    assert node.daemon.listings.door(door_id) is not None

    gone = await node.runtime.agent.withdraw_listing()
    assert (gone["state"], gone["doors_closed"], gone["doors_close_pending"]) == ("withdrawn", 1, 0)
    assert (await fetch(directory, name)).status_code == 410
    assert node.daemon.listings.door(door_id) is None
    # Published again later, it signs above the withdrawn seq.
    again = await publish(node, body(node, directory, name))
    assert again["seq"] > out["seq"]
    assert (await fetch(directory, name)).status_code == 200


async def test_the_local_api_keeps_publish_for_the_human(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random, sockdir: Path
) -> None:
    node = await owner(cluster, directory)
    server = await serve_api(node, sockdir)
    specs = {(s.method, s.path): s for s in ROUTE_SPECS}
    transport = httpx.AsyncHTTPTransport(uds=str(server.address))

    async def call(method: str, path: str, scope: str, payload: Any = None) -> httpx.Response:
        headers = {"authorization": f"Bearer {api_token(server, scope)}"}
        async with httpx.AsyncClient(transport=transport, base_url="http://ac") as http:
            resp = await http.request(method, path, json=payload, headers=headers)
        if resp.status_code == 200:
            spec = specs[(method, path)]
            assert conforms(resp.json(), spec.response), (path, resp.text)
        return resp

    request = body(node, directory, unique_name(rng))
    for path in ("/v0/listing/preview", "/v0/listing/publish"):
        refused = await call("POST", path, "agent", request)
        assert (refused.status_code, refused.json()["code"]) == (403, "human_only")
    shown = (await call("POST", "/v0/listing/preview", "human", request)).json()
    published = await call(
        "POST",
        "/v0/listing/publish",
        "human",
        {**request, "content_sha256": shown["content_sha256"]},
    )
    assert published.json()["state"] == "published"
    status = (await call("GET", "/v0/listing", "agent")).json()["listing"]
    assert status["state"] == "published"
    gone = await call("POST", "/v0/listing/withdraw", "agent")
    assert gone.json()["state"] == "withdrawn"
    await server.stop()


async def test_renewal_registers_a_second_door_and_the_old_one_stays(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    node = await owner(cluster, directory, options={"door_lifetime_secs": 240})
    name = unique_name(rng)
    await publish(node, body(node, directory, name))
    first = ac.verify_listing((await fetch(directory, name)).content)
    old_door, old_expiry = listed_door(first)
    events = node.daemon.store.events

    def renewed() -> bool:
        return any(e["type"] == "listing_renewed" for e in events(limit=1000))

    await cluster.advance(120)  # half the door's life
    await node.wait(renewed)
    second = ac.verify_listing((await fetch(directory, name)).content)
    new_door, new_expiry = listed_door(second)
    assert second.seq > first.seq
    assert second.content == first.content
    assert new_door != old_door
    assert await registered(node, new_door, new_expiry)
    assert await registered(node, old_door, old_expiry)
    states = {d["door_id"]: d["state"] for d in node.daemon.store.doors()}
    assert states == {old_door: "retiring", new_door: "current"}
    await node.runtime.agent.withdraw_listing()


@pytest.mark.parametrize(
    "point", ["door.after_register", "listing.after_sign", "listing.after_post"]
)
async def test_a_crash_while_publishing_converges_after_a_restart(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random, point: str
) -> None:
    node = await owner(cluster, directory)
    name = unique_name(rng)
    node.daemon.failpoints.arm(point, "crash")
    with pytest.raises(SimulatedCrash):
        await publish(node, body(node, directory, name))
    await node.restart()
    # No time passes: the requests signed again after the restart carry a
    # later ts than those before it, so the relay never sees a replay.
    store = node.daemon.store

    def published() -> bool:
        row = store.listing(directory.host, name)
        return row is not None and str(row["state"]) == "published"

    await node.wait(published)
    listing = ac.verify_listing((await fetch(directory, name)).content)
    door_id, _ = listed_door(listing)
    assert [d["door_id"] for d in store.doors()] == [door_id]
    events = [e for e in store.events(limit=1000) if e["type"] == "listing_published"]
    assert len(events) == 1
    await node.runtime.agent.withdraw_listing()
