"""Knocking on a listing and approving the knock, against the real relay and
the real directory, on both hosts (docs/discovery.md, SPEC 6.6).

The relay and the directory use the system clock and the nodes the
cluster's fake clock, which starts at the real time. A knock's lapse (an
hour) is reached by moving the fake clock: the WebSocket and the knock's own
checks follow it, and no signed REST request is made after that.

The crash scenarios at the end follow ``test_crash_consistency.py``: a
failure or a crash at every new step boundary, on the knocker and on the
owner, loses nothing and duplicates nothing. At most one approval is made,
one Welcome sent and one group joined, and the replay ledger keeps its
entries.
"""

from __future__ import annotations

import asyncio
import json
import random
from collections.abc import Callable
from typing import Any

import httpx
import pytest

import agentconnect_core as ac
from agentconnect.failpoints import FailpointError, SimulatedCrash
from agentconnect.relay import b64, unb64
from agentconnect.runtime import ApiError
from agentconnect.runtime.engine import DaemonError
from agentconnect.runtime.knocks import GIVE_UP_SECS, LAPSE_SECS
from agentconnect_harness.cluster import WAIT, Cluster, Node
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
    return f"k{rng.getrandbits(48):012x}"


def fresh_id(rng: random.Random) -> str:
    return b64(rng.randbytes(16))


async def publish(node: Node, directory: DirectoryProcess, name: str) -> None:
    token = json.loads(directory.token(name, node.me, node.daemon.now()))
    request = {"directory": directory.host, "card": CARD, "token": token}
    shown = await node.daemon.listings.preview(request)
    out = await node.daemon.listings.publish({**request, "content_sha256": shown["content_sha256"]})
    assert out["state"] == "published"


async def listed(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random, **kw: Any
) -> tuple[Node, str]:
    """An owner node with a published listing, and the listing's reference."""
    node = await cluster.node("owner", directories=(directory.config,), **kw)
    name = unique_name(rng)
    await publish(node, directory, name)
    return node, f"{directory.host}/a/{name}"


async def knocker(
    cluster: Cluster, directory: DirectoryProcess, name: str = "knocker", **kw: Any
) -> Node:
    return await cluster.node(name, directories=(directory.config,), **kw)


def events(node: Node, kind: str) -> list[dict[str, Any]]:
    return [e for e in node.daemon.store.events(limit=10_000) if e["type"] == kind]


def knock_event(node: Node, kind: str, knock_id: str) -> dict[str, Any] | None:
    return next((e for e in events(node, kind) if e["data"].get("knock_id") == knock_id), None)


async def pending(owner: Node, n: int = 1) -> list[dict[str, Any]]:
    await owner.wait(lambda: len(owner.daemon.knocks.approvals()) >= n)
    return owner.daemon.knocks.approvals()


async def joined(node: Node, knock_id: str) -> str:
    await node.wait(lambda: knock_event(node, "joined", knock_id) is not None)
    event = knock_event(node, "joined", knock_id)
    assert event is not None
    return str(event["group_id"])


async def handled(node: Node, sender: str, msg_id: str) -> None:
    """Wait until the inbound worker recorded this envelope."""
    await node.wait(lambda: node.daemon.store.inbox_state(sender, msg_id) is not None)


def knock_audit(node: Node) -> list[str]:
    return [r["reason"] for r in node.daemon.store.audit(limit=1000) if r["kind"] == "knock"]


async def agent_sees_the_group_once_the_knocker_is_in(owner: Node, k: Node, gid: str) -> None:
    """The owner's agent: a gap-free sequence, the group first seen through
    its ``member_joined``, and no claimed name on the knocker."""
    seen = (await owner.runtime.agent.events())["events"]
    assert [e["seq"] for e in seen] == list(range(1, len(seen) + 1))
    first = next(e for e in seen if e["group_id"] == gid)
    assert first["type"] == "member_joined"
    # The knocker's claimed name is the human's to read, not the agent's.
    agent_view = await owner.runtime.agent.group_info(gid)
    (knocker_member,) = [m for m in agent_view["members"] if m["identity"] == k.me]
    assert knocker_member["display_name"] is None


async def test_knock_approve_and_talk(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    # auto_approve (joins) is on for cluster nodes: it never applies to knocks.
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    shown = await k.runtime.agent.knock_inspect(ref)
    assert shown["untrusted"] is True
    assert shown["listing"]["identity"] == owner.me
    assert shown["owner"] == {
        "domain": None,
        "state": "unclaimed",
        "fetch": None,
        "checked_at": None,
    }
    sent = await k.runtime.agent.knock(ref, listing_sha256=shown["listing"]["sha256"])
    assert sent["status"] == "queued"
    knock_id = sent["knock_id"]
    (request,) = await pending(owner)
    assert (request["kind"], request["identity"], request["display_name"]) == (
        "knock",
        k.me,
        "knocker",
    )
    assert request["known"] == {"groups": 0, "verified_in": []}
    assert request["request_id"].startswith("kn-")
    # Nothing reached the owner's agent: knocks are the human's.
    assert not [e for e in owner.adapter.events if e.type.startswith("knock_")]

    approved = owner.daemon.approve(request["request_id"])
    gid = approved["group_id"]
    assert await joined(k, knock_id) == gid
    await cluster.settle(gid, 1)
    assert owner.sas(gid) == k.sas(gid)
    name = ref.rsplit("/", 1)[1]
    info = k.daemon.group_info(gid)
    assert info["origin"] == {"kind": "knock", "directory": directory.host, "name": name}
    assert info["name"] == name
    assert info["purpose"] == CARD["description"]
    (listed_member,) = [m for m in info["members"] if "listed_as" in m]
    assert listed_member["identity"] == owner.me
    assert listed_member["display_name"] == CARD["name"]
    assert not listed_member["verified"]
    assert info["trust_state"]["self"] == "unverified"
    owner_info = owner.daemon.group_info(gid)
    assert owner_info["origin"]["kind"] == "knock"
    assert owner_info["trust_state"]["self"] == "unverified"

    owner.daemon.send_message(gid, {"text": "hello knocker"})
    assert await k.wait_texts(gid, 1) == ["hello knocker"]
    k.daemon.send_message(gid, {"text": "hello owner"})
    assert await owner.wait_texts(gid, 1) == ["hello owner"]
    # The owner's agent hears of the group once the knocker is in, once, and
    # nothing of the group before that (its events of the Add are the human's).
    assert [e.data["identity"] for e in owner.adapter.of_type("member_joined")] == [k.me]
    await agent_sees_the_group_once_the_knocker_is_in(owner, k, gid)
    row = owner.daemon.store.knock_request(request["request_id"])
    assert row is not None
    assert (row["status"], row["note"]) == ("approved", None)
    assert owner.daemon.store.knock_request_secret(request["request_id"]) is None
    assert k.daemon.store.knock_secret(knock_id) is None
    assert [x["status"] for x in k.daemon.knocks.knocks()] == ["joined"]
    event = knock_event(k, "joined", knock_id)
    assert event is not None
    assert event["data"]["listing"]["identity"] == owner.me


async def test_a_rejected_knock_sends_nothing_and_lapses_as_no_answer(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    seen = len(k.proxy.delivered)
    assert owner.daemon.reject(request["request_id"]) == {"status": "rejected"}
    await owner.idle()
    await cluster.advance(GIVE_UP_SECS)
    await k.wait(lambda: knock_event(k, "knock_lapsed", sent["knock_id"]) is not None)
    # Nothing from the owner reached the knocker's mailbox.
    assert all(f["env"].get("sender") != owner.daemon.mailbox for f in k.proxy.delivered[seen:])
    assert k.daemon.store.knock_secret(sent["knock_id"]) is None
    assert [x["status"] for x in k.daemon.knocks.knocks()] == ["lapsed"]
    row = owner.daemon.store.knock_request(request["request_id"])
    assert row is not None
    assert (row["display_name"], row["note"]) == (None, None)


async def test_an_approval_after_the_lapse_is_refused(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    await k.runtime.agent.knock(ref, note="About the 1.4 release")
    (request,) = await pending(owner)
    assert request["note"] == "About the 1.4 release"
    await cluster.advance(LAPSE_SECS)
    await owner.wait(lambda: bool(events(owner, "knock_expired")))
    with pytest.raises(DaemonError) as e:
        owner.daemon.approve(request["request_id"])
    assert e.value.code == "not_found"
    assert owner.daemon.store.knock_request_secret(request["request_id"]) is None
    assert not [g for g in owner.daemon.store.groups() if g.status == "active"]


async def test_the_agent_token_cant_approve_or_see_knocks(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    await k.runtime.agent.knock(ref)
    await pending(owner)
    agent = owner.runtime.agent
    assert (await agent.approvals())["approvals"] == []
    assert (await agent.status())["pending_approvals"] == 0
    assert owner.runtime.status()["pending_approvals"] == 0
    assert owner.daemon.status()["pending_approvals"] == 1
    assert not [e for e in (await agent.events())["events"] if e["type"].startswith("knock_")]
    assert not [n for n in dir(agent) if "approve" in n or "reject" in n]


async def test_after_a_withdrawal_a_knock_gets_door_not_open(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    first = await knocker(cluster, directory, "first")
    late = await knocker(cluster, directory, "late")
    shown = await late.runtime.agent.knock_inspect(ref)  # an older copy of the listing
    await first.runtime.agent.knock(ref)
    await pending(owner)
    gone = await owner.runtime.agent.withdraw_listing()
    assert gone["state"] == "withdrawn"
    # A pending approval survives the withdrawal: dropping it is the human's.
    assert len(owner.daemon.knocks.approvals()) == 1
    with pytest.raises(ApiError) as e:
        await late.runtime.agent.knock_inspect(ref)
    assert (e.value.status, e.value.code) == (410, "listing_withdrawn")
    sent = await late.runtime.agent.knock(ref, listing_sha256=shown["listing"]["sha256"])
    await late.wait(lambda: knock_event(late, "knock_failed", sent["knock_id"]) is not None)
    failed = knock_event(late, "knock_failed", sent["knock_id"])
    assert failed is not None
    assert failed["data"]["code"] == "door_not_open"
    assert late.daemon.store.knock_secret(sent["knock_id"]) is None


async def test_a_replayed_knock_is_dropped(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    frame = owner.proxy.last_delivered("knock")

    async def replay() -> None:
        again = json.loads(json.dumps(frame))
        again["env"]["msg_id"] = fresh_id(rng)  # the relay can re-send under any msg_id
        await owner.proxy.inject(again)
        await handled(owner, again["env"]["sender"], again["env"]["msg_id"])

    await replay()  # while the approval waits
    assert len(owner.daemon.knocks.approvals()) == 1
    owner.daemon.reject(request["request_id"])
    await replay()  # after the human rejected it
    await owner.restart()
    await replay()  # after a restart: the ledger is persisted
    assert owner.daemon.knocks.approvals() == []
    assert knock_audit(owner).count("knock_replay") == 3


async def test_one_identity_waits_once_on_a_listing(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    replica = await cluster.node("replica", identity_of=k, directories=(directory.config,))
    await k.runtime.agent.knock(ref)
    await pending(owner)
    await replica.runtime.agent.knock(ref)
    await owner.wait(lambda: "knock_identity_pending" in knock_audit(owner))
    assert len(owner.daemon.knocks.approvals()) == 1
    with pytest.raises(ApiError) as e:
        await k.runtime.agent.knock(ref)
    assert (e.value.status, e.value.code) == (409, "already_pending")


async def test_a_malicious_relay_cant_get_a_knock_through(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    await k.runtime.agent.knock(ref)
    await pending(owner)
    frame = owner.proxy.last_delivered("knock")
    changes = {
        "door": lambda env: env.update(door_id=b64(bytes(16))),
        "truncated": lambda env: env.update(ct=b64(unb64(env["ct"])[:1100])),
        "bit_flip": lambda env: env.update(
            ct=b64(unb64(env["ct"])[:-1] + bytes([unb64(env["ct"])[-1] ^ 1]))
        ),
        "kind": lambda env: env.update(kind="join_request"),
        "group": lambda env: env.update(group_id="x" * 22),
        "door_shape": lambda env: env.update(door_id=env["door_id"] + "A"),
    }
    for change in changes.values():
        bad = json.loads(json.dumps(frame))
        bad["env"]["msg_id"] = fresh_id(rng)
        change(bad["env"])
        await owner.proxy.inject(bad)
    # Frames are handled in order: once this one is, so are those before it.
    last = json.loads(json.dumps(frame))
    last["env"]["msg_id"] = fresh_id(rng)
    await owner.proxy.inject(last)
    await handled(owner, last["env"]["sender"], last["env"]["msg_id"])
    assert len(owner.daemon.knocks.approvals()) == 1
    reasons = knock_audit(owner)
    assert "knock_check:unknown_door" in reasons
    assert "knock_check:malformed" in reasons
    assert "knock_check:authentication" in reasons
    # A knock has no group: nothing is raised to anyone, nothing sent back.
    assert not events(owner, "relay_misbehaviour")


async def test_a_welcome_for_the_wrong_group_ends_the_knock(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    # A broken (or malicious) owner names the group after another listing.
    owner.daemon.store._db.execute(
        "UPDATE knock_requests SET name = 'another-name' WHERE request_id = ?",
        (request["request_id"],),
    )
    owner.daemon.approve(request["request_id"])
    await k.wait(lambda: knock_event(k, "knock_failed", sent["knock_id"]) is not None)
    failed = knock_event(k, "knock_failed", sent["knock_id"])
    assert failed is not None
    assert failed["data"]["code"] == "welcome_invalid"
    assert [e["data"]["reason"] for e in events(k, "relay_misbehaviour")] == [
        "knock_welcome_mismatch"
    ]
    assert k.daemon.store.knock_secret(sent["knock_id"]) is None
    assert not [g for g in k.daemon.store.groups() if g.status == "active"]


async def test_the_human_chooses_the_purpose(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    with pytest.raises(DaemonError):
        owner.daemon.approve(request["request_id"], "two\nlines")
    owner.daemon.approve(request["request_id"], "Plan the 1.4 release")
    gid = await joined(k, sent["knock_id"])
    await cluster.settle(gid, 1)
    owner.daemon.send_message(gid, {"text": "hi"})
    await k.wait_texts(gid, 1)
    assert k.adapter.deliveries[-1].scope == "Plan the 1.4 release"


async def test_a_knock_on_the_old_door_lands_after_a_renewal(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng, options={"door_lifetime_secs": 240})
    k = await knocker(cluster, directory)
    old = await k.runtime.agent.knock_inspect(ref)
    await cluster.advance(120)  # half the door's life
    await owner.wait(lambda: bool(events(owner, "listing_renewed")))
    async with httpx.AsyncClient(trust_env=False) as http:
        served = await http.get(f"{directory.url}/a/{ref.rsplit('/', 1)[1]}.json")
    assert ac.verify_listing(served.content).sha256.hex() != old["listing"]["sha256"]
    # The knocker knocks with the copy it saw first: the old door still opens.
    sent = await k.runtime.agent.knock(ref, listing_sha256=old["listing"]["sha256"])
    (request,) = await pending(owner)
    owner.daemon.approve(request["request_id"])
    await joined(k, sent["knock_id"])


# -- crashes (ADR-004) ------------------------------------------------------------

MODES = ("raise", "crash")
STEPS = ("before_core", "after_core", "in_tx", "after_tx", "after_consume")


async def until(predicate: Callable[[], bool]) -> None:
    """Poll (yielding to the loop): a crashed worker announces nothing."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing to wait on after a crash
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


def arm(node: Node, point: str, mode: str) -> Callable[[], bool]:
    node.daemon.failpoints.arm(point, "crash" if mode == "crash" else "raise")
    return lambda: point in node.daemon.failpoints.fired


async def recover(cluster: Cluster, node: Node, mode: str, fired: Callable[[], bool]) -> None:
    await until(fired)
    if mode == "crash":
        await node.restart()
        return
    await until(lambda: node.clock.sleepers > 0)
    await cluster.advance(300)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("point", ["knock.in_tx", "knock.after_tx"])
async def test_a_received_knock_is_recorded_once(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random, point: str, mode: str
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    fired = arm(owner, point, mode)
    await k.runtime.agent.knock(ref)
    await recover(cluster, owner, mode, fired)
    (request,) = await pending(owner)
    await owner.idle()
    assert len(owner.daemon.store.ledger_rows(owner.daemon.now())) == 1
    assert len(events(owner, "knock_received")) == 1
    owner.daemon.approve(request["request_id"])
    await joined(k, k.daemon.knocks.knocks()[0]["knock_id"])


@pytest.mark.parametrize("mode", MODES)
async def test_a_knock_whose_record_failed_leaves_nothing_and_can_be_sent_again(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random, mode: str
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    arm(k, "knock_send.after_core", mode)
    with pytest.raises(SimulatedCrash if mode == "crash" else FailpointError):
        await k.runtime.agent.knock(ref)
    if mode == "crash":
        await k.restart()
    assert k.daemon.knocks.knocks() == []
    assert k.daemon.store.outbox() == []
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    owner.daemon.approve(request["request_id"])
    await joined(k, sent["knock_id"])


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("step", STEPS)
async def test_a_knock_welcome_joins_once(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random, step: str, mode: str
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    fired = arm(k, f"knock_welcome.{step}", mode)
    owner.daemon.approve(request["request_id"])
    await recover(cluster, k, mode, fired)
    gid = await joined(k, sent["knock_id"])
    await cluster.settle(gid, 1)
    assert [g.group_id for g in k.daemon.store.groups() if g.status == "active"] == [gid]
    assert len(events(k, "joined")) == 1
    assert k.daemon.client.journal_pending() == []
    assert k.daemon.store.knock_secret(sent["knock_id"]) is None
    assert owner.sas(gid) == k.sas(gid)


@pytest.mark.parametrize("mode", MODES)
async def test_an_approval_whose_group_wasnt_recorded_can_be_made_again(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random, mode: str
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    arm(owner, "knock_approve.after_group", mode)
    with pytest.raises(SimulatedCrash if mode == "crash" else FailpointError):
        owner.daemon.approve(request["request_id"])
    if mode == "crash":
        await owner.restart()
    # Still the human's to decide: the request waits, with its secret.
    (again,) = owner.daemon.knocks.approvals()
    assert again["request_id"] == request["request_id"]
    assert not [g for g in owner.daemon.store.groups() if g.status == "active"]
    gid = owner.daemon.approve(request["request_id"])["group_id"]
    assert await joined(k, sent["knock_id"]) == gid
    assert len(events(owner, "knock_approved")) == 1


@pytest.mark.parametrize("mode", MODES)
async def test_the_welcome_of_an_approval_goes_once(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random, mode: str
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    fired = arm(owner, "knock_add.after_welcome", mode)
    gid = owner.daemon.approve(request["request_id"])["group_id"]
    await recover(cluster, owner, mode, fired)
    assert await joined(k, sent["knock_id"]) == gid
    await owner.wait(
        lambda: (
            (r := owner.daemon.store.knock_request(request["request_id"])) is not None
            and r["status"] == "approved"
        )
    )
    await cluster.settle(gid, 1)
    welcomes = [f for f in k.proxy.delivered if f["env"].get("kind") == "welcome_wrapped"]
    assert len({f["env"]["msg_id"] for f in welcomes}) == 1
    assert owner.daemon.store.knock_request_secret(request["request_id"]) is None
    assert len(events(k, "joined")) == 1


async def test_an_approved_knock_finishes_after_a_restart(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    await owner.proxy.cut()
    await owner.wait(lambda: not owner.daemon.link.connected)
    gid = owner.daemon.approve(request["request_id"])["group_id"]
    owner.proxy.heal()
    await owner.restart()
    assert await joined(k, sent["knock_id"]) == gid
    assert knock_event(k, "joined", sent["knock_id"]) is not None


async def test_a_message_in_the_hidden_window_waits_for_the_agent(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    """N1: the Welcome went out but the approval isn't recorded done yet (the
    failpoint raises, the outbox waits out its backoff). A message the
    knocker sends meanwhile waits in the owner's inbox, and reaches the agent
    once the group is the agent's, after its events."""
    owner, ref = await listed(cluster, directory, rng)
    k = await knocker(cluster, directory)
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    fired = arm(owner, "knock_add.after_welcome", "raise")
    gid = owner.daemon.approve(request["request_id"])["group_id"]
    await until(fired)
    assert await joined(k, sent["knock_id"]) == gid
    k.daemon.send_message(gid, {"text": "early"})
    store = owner.daemon.store
    await owner.wait(lambda: any(r.group_id == gid for r in store.pending_deliveries()))
    assert owner.daemon.hidden_from_agent(gid)
    assert owner.adapter.texts(gid) == []
    assert not [e for e in (await owner.runtime.agent.events())["events"] if e["group_id"] == gid]
    await until(lambda: owner.clock.sleepers > 0)
    await cluster.advance(300)
    assert await owner.wait_texts(gid, 1) == ["early"]
    assert not owner.daemon.hidden_from_agent(gid)
    seen = (await owner.runtime.agent.events())["events"]
    assert [e["seq"] for e in seen] == list(range(1, len(seen) + 1))
    mine = [e["type"] for e in seen if e["group_id"] == gid]
    assert mine[0] == "member_joined"
    assert mine.count("member_joined") == 1


# -- a Welcome the relay refuses for now (N5) ------------------------------------


def refuse_welcomes(node: Node, times: int) -> list[str]:
    """Have the relay answer the node's next ``times`` Welcomes
    `rate_limited`. Returns the msg_id of every Welcome the node sends,
    refused or not."""
    tried: list[str] = []

    def count(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if frame.get("t") == "send" and env.get("kind") == "welcome_wrapped":
            tried.append(str(env["msg_id"]))
        return [frame]

    node.proxy.client_filters.append(count)
    node.proxy.fail_next("send", "rate_limited", kind="welcome_wrapped", times=times)
    return tried


async def team(cluster: Cluster, owner: Node) -> tuple[Node, str]:
    """A group of the owner and bob, besides the one an approval creates."""
    bob = await cluster.node("bob")
    gid = owner.daemon.create_group("Team", "Plan the release")
    await owner.idle()
    await cluster.invite(owner, bob, gid)
    return bob, gid


async def approve_with_refused_welcome(
    cluster: Cluster, directory: DirectoryProcess, owner: Node, ref: str, refusals: int
) -> tuple[Node, str, str, str, list[str]]:
    """Approve a knock whose Welcome the relay refuses ``refusals`` times
    (`rate_limited`), and wait until the first refusal is waiting out its
    backoff."""
    k = await knocker(cluster, directory)
    sent = await k.runtime.agent.knock(ref)
    (request,) = await pending(owner)
    tried = refuse_welcomes(owner, refusals)
    kid = owner.daemon.approve(request["request_id"])["group_id"]
    await until(lambda: len(tried) == 1 and owner.clock.sleepers > 0)
    return k, str(sent["knock_id"]), str(request["request_id"]), str(kid), tried


async def welcome_goes_out(cluster: Cluster, owner: Node, k: Node, knock_id: str, kid: str) -> None:
    """Let the backoff run out until the Welcome is taken, and check it went
    once and the knocker joined once."""
    for _ in range(10):
        if knock_event(k, "joined", knock_id) is not None:
            break
        await until(
            lambda: owner.clock.sleepers > 0 or knock_event(k, "joined", knock_id) is not None
        )
        await cluster.advance(60)
    assert await joined(k, knock_id) == kid
    await cluster.settle(kid, 1)
    welcomes = [f for f in k.proxy.delivered if f["env"].get("kind") == "welcome_wrapped"]
    assert len({f["env"]["msg_id"] for f in welcomes}) == 1
    assert len(events(k, "joined")) == 1


async def test_a_welcome_the_relay_refuses_for_now_holds_up_no_other_group(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    """N5: an approved knock's Welcome waits out its backoff on its own. The
    owner's other groups don't wait behind it: their messages and commits go
    out meanwhile, in the order they were queued."""
    owner, ref = await listed(cluster, directory, rng)
    bob, gid = await team(cluster, owner)
    k, knock_id, request_id, kid, tried = await approve_with_refused_welcome(
        cluster, directory, owner, ref, refusals=3
    )
    epoch = owner.epoch(gid)
    owner.daemon.send_message(gid, {"text": "one"})
    owner.daemon.update(gid)
    owner.daemon.send_message(gid, {"text": "two"})
    owner.daemon.send_message(gid, {"text": "three"})
    # No time passes: the Welcome is still waiting, and nothing else is.
    assert await bob.wait_texts(gid, 3) == ["one", "two", "three"]
    await bob.wait(lambda: bob.epoch(gid) == epoch + 1)
    kinds = [
        f["env"]["kind"]
        for f in bob.proxy.delivered
        if f["env"].get("group_id") == gid and f["env"].get("kind") in ("application", "commit")
    ]
    assert kinds[-4:] == ["application", "commit", "application", "application"]
    assert len(tried) == 1
    req = owner.daemon.store.knock_request(request_id)
    assert req is not None
    assert req["status"] == "approving"
    assert knock_event(k, "joined", knock_id) is None
    await welcome_goes_out(cluster, owner, k, knock_id, kid)
    assert len(tried) == 4  # three refused, then taken
    assert len(set(tried)) == 1
    assert bob.adapter.texts(gid) == ["one", "two", "three"]


async def test_a_welcome_refused_for_now_goes_once_after_a_restart(
    cluster: Cluster, directory: DirectoryProcess, rng: random.Random
) -> None:
    """N5, crash consistency: the owner dies while the Welcome waits out its
    backoff and other groups' messages wait behind a cut connection. After
    the restart the Welcome is tried again under the same msg_id, and the
    messages go out once each, in order, while it waits again."""
    owner, ref = await listed(cluster, directory, rng)
    bob, gid = await team(cluster, owner)
    k, knock_id, request_id, kid, tried = await approve_with_refused_welcome(
        cluster, directory, owner, ref, refusals=2
    )
    await owner.proxy.cut()
    await owner.wait(lambda: not owner.daemon.link.connected)
    for text in ("one", "two", "three"):
        owner.daemon.send_message(gid, {"text": text})
    owner.proxy.heal()
    await owner.restart()
    assert await bob.wait_texts(gid, 3) == ["one", "two", "three"]
    await until(lambda: len(tried) == 2)
    owner.daemon.send_message(gid, {"text": "four"})
    assert await bob.wait_texts(gid, 4) == ["one", "two", "three", "four"]
    await welcome_goes_out(cluster, owner, k, knock_id, kid)
    req = owner.daemon.store.knock_request(request_id)
    assert req is not None
    assert req["status"] == "approved"
    assert len(tried) == 3  # once before the restart, once after, then taken
    assert len(set(tried)) == 1
    assert bob.adapter.texts(gid) == ["one", "two", "three", "four"]
