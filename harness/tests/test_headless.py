"""The headless adapter and the Python SDK against real daemons.

The webhook adapter POSTs to the SDK's receiver; the SSE hub feeds the SDK's
stream consumer. Replies go back through the local API with the agent token.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentconnect.adapter import Delivery
from agentconnect_harness.cluster import WAIT, Cluster, Node, serve_api
from agentconnect_harness.headless import Headless, headless
from agentconnect_sdk import AgentConnect, AgentConnectError, Event, Group, Message, TaskState


async def pair(cluster: Cluster, sockdir: Path, **kw: Any) -> tuple[Node, Headless, str]:
    """Alice (plain daemon) and Bob (headless), joined in one group."""
    alice = await cluster.node("alice")
    gid = alice.daemon.create_group("Ops", "Plan the offsite")
    await alice.idle()
    bob = await headless(cluster, "bob", sockdir, **kw)
    await cluster.invite(alice, bob.node, gid)
    return alice, bob, gid


async def pump(cluster: Cluster, h: Headless, done: Callable[[], bool]) -> None:
    """Advance daemon time through delivery retries until ``done``."""
    for _ in range(40):
        if done():
            return
        await h.node.wait(lambda: done() or h.node.clock.sleepers > 0)
        if done():
            return
        await cluster.advance(300)
    msg = "not delivered"
    raise AssertionError(msg)


def say(alice: Node, gid: str, text: str) -> str:
    return alice.daemon.send_message(gid, {"text": text})


def received(node: Node, kind: str = "a2a.message") -> list[Delivery]:
    return [d for d in node.adapter.deliveries if d.kind == kind]


async def test_a_message_triggers_the_handler_and_the_reply_carries_hop(
    cluster: Cluster, sockdir: Path
) -> None:
    alice, bob, gid = await pair(cluster, sockdir)
    seen: list[Message] = []

    @bob.sdk.on_message
    async def handle(msg: Message, group: Group) -> None:
        seen.append(msg)
        if msg.addressed_to_me:
            await group.reply(msg, f"echo {msg.raw_text}")

    sent = say(alice, gid, "ping")
    await alice.adapter.wait_for(lambda: bool(received(alice)), WAIT)
    (msg,) = seen
    assert msg.msg_id == sent
    assert msg.untrusted
    assert msg.scope == "Plan the offsite"
    assert msg.sender.identity == alice.me
    assert msg.addressed_to_me
    assert msg.group.id == gid
    assert msg.trust_state.members == 2
    assert msg.raw_text == "ping"
    (answer,) = received(alice)
    assert answer.body["parts"] == [{"text": "echo ping"}]
    assert answer.inner["reply_to"] == [sent]
    assert answer.hop == 2  # SPEC 10.3: one more than the message replied to
    # SPEC 9.3: to the whole group, addressed to the requester.
    assert (answer.to, answer.inner["addressee"], answer.addressed_to_me) == (
        ["*"],
        [alice.me],
        True,
    )
    await bob.close()


async def test_addressee_reaches_the_sdk_and_triggers_only_who_it_names(
    cluster: Cluster, sockdir: Path
) -> None:
    alice, bob, gid = await pair(cluster, sockdir)
    carol = await cluster.node("carol")
    await cluster.invite(alice, carol, gid)
    seen: list[Message] = []

    @bob.sdk.on_message
    async def handle(msg: Message, group: Group) -> None:
        seen.append(msg)
        if msg.addressed_to_me:
            await group.reply(msg, "for alice")

    # Alice's agent names Bob as the addressee of a message to everyone.
    sent = alice.daemon.send_message(gid, {"text": "bob, you"}, addressee=[bob.node.me])
    await carol.adapter.wait_for(lambda: bool(received(carol)), WAIT)
    assert not received(carol)[0].addressed_to_me
    await alice.adapter.wait_for(lambda: bool(received(alice)), WAIT)
    (msg,) = [m for m in seen if m.msg_id == sent]
    assert msg.addressee == (bob.node.me,)
    assert msg.addressed_to_me
    # Bob's answer reaches Carol as context only.
    await carol.adapter.wait_for(lambda: len(received(carol)) == 2, WAIT)
    answer = received(carol)[1]
    assert answer.sender.identity == bob.node.me
    assert not answer.addressed_to_me
    await bob.close()


async def test_task_status_and_artifact_replies(cluster: Cluster, sockdir: Path) -> None:
    alice, bob, gid = await pair(cluster, sockdir)

    @bob.sdk.on_message
    async def handle(msg: Message, group: Group) -> None:
        await group.reply_status(msg, TaskState.WORKING, "on it", task_id="t1")
        await group.reply_artifact(msg, "the plan", name="plan", task_id="t1")
        await group.reply_status(msg, TaskState.COMPLETED, task_id="t1")

    say(alice, gid, "make a plan")
    await alice.adapter.wait_for(lambda: len(received(alice, "a2a.task_status")) == 2, WAIT)
    await alice.adapter.wait_for(lambda: bool(received(alice, "a2a.task_artifact")), WAIT)
    states = [d.body["status"]["state"] for d in received(alice, "a2a.task_status")]
    assert states == ["TASK_STATE_WORKING", "TASK_STATE_COMPLETED"]
    (artifact,) = received(alice, "a2a.task_artifact")
    assert artifact.body["artifact"]["parts"] == [{"text": "the plan"}]
    assert {d.hop for d in received(alice, "a2a.task_status")} == {2}
    await bob.close()


async def test_messages_queue_while_the_webhook_is_down_and_arrive_in_order(
    cluster: Cluster, sockdir: Path
) -> None:
    alice, bob, gid = await pair(cluster, sockdir, started=False)
    handled: list[str] = []
    done = asyncio.Event()

    @bob.sdk.on_message
    async def handle(msg: Message, _group: Group) -> None:
        handled.append(msg.raw_text)
        if len(handled) == 3:
            done.set()

    for text in ("one", "two", "three"):
        say(alice, gid, text)
    await bob.node.wait(lambda: len(bob.node.daemon.store.pending_deliveries()) == 3)
    assert handled == []

    # The first ack is lost: the handler ran, the daemon got a 500.
    await bob.up()
    assert bob.receiver is not None
    real = bob.sdk.dispatch
    lost: list[str] = []

    async def lossy(payload: dict[str, Any]) -> str:
        result = await real(payload)
        if not lost:
            lost.append(str(payload["msg_id"]))
            msg = "ack lost"
            raise RuntimeError(msg)
        return result

    bob.receiver._dispatch = lossy
    await pump(cluster, bob, done.is_set)
    assert handled == ["one", "two", "three"]  # in order, none twice
    assert len(lost) == 1
    await bob.node.wait(lambda: not bob.node.daemon.store.pending_deliveries())
    await bob.close()


async def test_events_reach_the_sdk_once_with_their_ids(cluster: Cluster, sockdir: Path) -> None:
    alice, bob, gid = await pair(cluster, sockdir)
    events: list[Event] = []

    @bob.sdk.on_event
    async def on_event(event: Event, group: Group | None) -> None:
        events.append(event)

    carol = await cluster.node("carol")
    await cluster.invite(alice, carol, gid)
    await bob.node.wait(lambda: any(e.type == "member_joined" for e in events))
    ids = [e.event_id for e in events]
    assert len(ids) == len(set(ids))
    assert all(e.untrusted and e.event_id for e in events)
    joined = next(e for e in events if e.type == "member_joined")
    assert joined.group is not None
    assert joined.group.id == gid
    await bob.close()


async def test_sse_streams_resume_after_a_disconnect(cluster: Cluster, sockdir: Path) -> None:
    alice, bob, gid = await pair(cluster, sockdir, mode="sse")
    handled: list[str] = []
    changed = asyncio.Event()

    @bob.sdk.on_message
    async def handle(msg: Message, _group: Group) -> None:
        handled.append(msg.raw_text)
        changed.set()

    async def until(n: int) -> None:
        while len(handled) < n:
            changed.clear()
            await asyncio.wait_for(changed.wait(), WAIT)

    stream = asyncio.create_task(bob.sdk.stream())
    await bob.hub.wait_listeners(1)
    say(alice, gid, "m1")
    say(alice, gid, "m2")
    await until(2)
    stream.cancel()
    await asyncio.gather(stream, return_exceptions=True)
    await bob.hub.wait_listeners(0)

    # Nobody listens: the daemon keeps m3 in its queue and retries.
    say(alice, gid, "m3")
    await bob.node.wait(lambda: len(bob.node.daemon.store.pending_deliveries()) == 1)
    stream = asyncio.create_task(bob.sdk.stream())  # resumes with Last-Event-ID
    await bob.hub.wait_listeners(1)
    daemon = bob.node.daemon
    for _ in range(40):
        await bob.node.wait(
            lambda: not daemon.store.pending_deliveries() or bob.node.clock.sleepers > 0
        )
        if not daemon.store.pending_deliveries():
            break
        await cluster.advance(300)
    await until(3)
    assert handled == ["m1", "m2", "m3"]

    # A second consumer that only got as far as m1 resumes from there.
    feed = bob.node.daemon.store.feed_since(0)
    ids = [str(seq) for seq, _gid, payload in feed if "msg_id" in payload]
    other = AgentConnect(
        data_dir=bob.node.config.data_dir,
        socket=Path(str(bob.server.address)),
    )
    replayed: list[str] = []
    again = asyncio.Event()

    @other.on_message
    async def collect(msg: Message, _group: Group) -> None:
        replayed.append(msg.raw_text)
        again.set()

    second = asyncio.create_task(other.stream(last_event_id=ids[0]))
    while len(replayed) < 2:
        again.clear()
        await asyncio.wait_for(again.wait(), WAIT)
    assert replayed == ["m2", "m3"]
    for task in (stream, second):
        task.cancel()
    await asyncio.gather(stream, second, return_exceptions=True)
    await other.aclose()
    await bob.close()


async def test_sse_resume_survives_a_daemon_restart(cluster: Cluster, sockdir: Path) -> None:
    alice, bob, gid = await pair(cluster, sockdir, mode="sse")
    handled: list[str] = []
    changed = asyncio.Event()

    @bob.sdk.on_message
    async def handle(msg: Message, _group: Group) -> None:
        handled.append(msg.raw_text)
        changed.set()

    stream = asyncio.create_task(bob.sdk.stream())
    await bob.hub.wait_listeners(1)
    say(alice, gid, "m1")
    say(alice, gid, "m2")
    while len(handled) < 2:
        changed.clear()
        await asyncio.wait_for(changed.wait(), WAIT)
    first_id = next(seq for seq, _g, p in bob.node.daemon.store.feed_since(0) if "msg_id" in p)
    stream.cancel()
    await asyncio.gather(stream, return_exceptions=True)
    await bob.hub.wait_listeners(0)

    # The daemon goes down and comes back; the feed is in its database.
    await bob.server.stop()
    await bob.node.restart()
    bob.server = await serve_api(bob.node, sockdir)

    resumed = AgentConnect(data_dir=bob.node.config.data_dir, socket=Path(str(bob.server.address)))
    replayed: list[str] = []
    again = asyncio.Event()

    @resumed.on_message
    async def collect(msg: Message, _group: Group) -> None:
        replayed.append(msg.raw_text)
        again.set()

    task = asyncio.create_task(resumed.stream(last_event_id=str(first_id)))
    while not replayed:
        again.clear()
        await asyncio.wait_for(again.wait(), WAIT)
    assert replayed == ["m2"]
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await resumed.aclose()
    await bob.close()


async def test_sse_filters_by_group_and_refuses_without_the_adapter(
    cluster: Cluster, sockdir: Path
) -> None:
    alice, bob, gid = await pair(cluster, sockdir, mode="sse")
    with pytest.raises(AgentConnectError) as info:
        await bob.sdk.stream("no-such-group")
    assert (info.value.status, info.value.code) == (404, "not_found")

    other = alice.daemon.create_group("Other", "Elsewhere")
    await alice.idle()
    seen: list[str] = []
    got = asyncio.Event()

    @bob.sdk.on_message
    async def handle(msg: Message, _group: Group) -> None:
        seen.append(msg.raw_text)
        got.set()

    stream = asyncio.create_task(bob.sdk.stream(gid))
    await bob.hub.wait_listeners(1)
    say(alice, gid, "for the stream")
    await asyncio.wait_for(got.wait(), WAIT)
    assert seen == ["for the stream"]
    stream.cancel()
    await asyncio.gather(stream, return_exceptions=True)
    assert other != gid
    await bob.close()

    plain = await cluster.node("plain")
    server_sdk = await headless(cluster, "hook", sockdir)
    with pytest.raises(AgentConnectError) as info:
        await server_sdk.sdk.stream()
    assert (info.value.status, info.value.code) == (409, "no_sse_adapter")
    assert plain.me != alice.me
    await server_sdk.close()


async def test_the_json_events_log_filters_by_group_and_carries_event_ids(
    cluster: Cluster, sockdir: Path
) -> None:
    _alice, bob, gid = await pair(cluster, sockdir)
    other = bob.node.daemon.create_group("Other", "Elsewhere")
    await bob.node.idle()
    everything = (await bob.sdk._request("GET", "/v0/events"))["events"]
    mine = (await bob.sdk._request("GET", f"/v0/events?group={gid}"))["events"]
    assert mine
    assert {e["group_id"] for e in mine} == {gid}
    assert len(mine) < len(everything) or other not in {e["group_id"] for e in everything}
    assert all(e["event_id"] for e in everything)
    await bob.close()


async def test_the_sdk_cannot_do_human_only_things(cluster: Cluster, sockdir: Path) -> None:
    alice, bob, gid = await pair(cluster, sockdir)
    with pytest.raises(AgentConnectError) as info:
        await bob.sdk._request("POST", f"/v0/groups/{gid}/members/{alice.me}/verify", {})
    assert (info.value.status, info.value.code) == (403, "human_only")
    with pytest.raises(AgentConnectError) as info:
        await bob.sdk._request("POST", "/v0/approvals/x/approve", {})
    assert info.value.code == "human_only"
    await bob.sdk.group(gid).send("allowed", to=["*"])
    with pytest.raises(AgentConnectError) as info:
        await bob.sdk._request(
            "POST", f"/v0/groups/{gid}/messages", {"kind": "control.resume", "body": {}}
        )
    assert info.value.code == "human_only"
    await bob.close()


async def test_a_wrong_token_is_refused(cluster: Cluster, sockdir: Path) -> None:
    alice, bob, _gid = await pair(cluster, sockdir)
    bad = AgentConnect(
        data_dir=bob.node.config.data_dir,
        socket=Path(str(bob.server.address)),
        token=secrets.token_urlsafe(8),
    )
    with pytest.raises(AgentConnectError) as info:
        await bad.status()
    assert info.value.status == 401
    await bad.aclose()
    async with httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(uds=str(bob.server.address)), base_url="http://x"
    ) as c:
        resp = await c.get("/v0/events", headers={"accept": "text/event-stream"})
    assert resp.status_code == 401
    assert alice.me != ""
    await bob.close()


async def test_the_text_shorthand_is_an_a2a_message(cluster: Cluster, sockdir: Path) -> None:
    """``agentconnect send`` posts ``text``; the daemon wraps it (SPEC 7.2)."""
    alice, bob, gid = await pair(cluster, sockdir)
    await bob.sdk._request("POST", f"/v0/groups/{gid}/messages", {"text": "hello"})
    await alice.adapter.wait_for(lambda: bool(received(alice)), WAIT)
    (agent_msg,) = received(alice)
    assert agent_msg.body["role"] == "ROLE_AGENT"
    assert agent_msg.body["parts"] == [{"text": "hello"}]
    assert agent_msg.body["contextId"] == gid
    assert agent_msg.body["messageId"]
    assert alice.adapter.texts(gid) == ["hello"]

    human_token = (bob.node.config.data_dir / "human-token").read_text().strip()
    async with httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(uds=str(bob.server.address)), base_url="http://x"
    ) as c:
        resp = await c.post(
            f"/v0/groups/{gid}/messages",
            json={"text": "from the human"},
            headers={"authorization": f"Bearer {human_token}"},
        )
    assert resp.status_code == 200
    await alice.adapter.wait_for(lambda: len(received(alice)) == 2, WAIT)
    assert received(alice)[1].body["role"] == "ROLE_USER"
    assert received(alice)[1].origin == "human"
    await bob.close()


async def test_nothing_is_written_to_the_feed_without_the_sse_adapter(
    cluster: Cluster, sockdir: Path
) -> None:
    alice, bob, gid = await pair(cluster, sockdir)  # webhook
    handled = asyncio.Event()

    @bob.sdk.on_message
    async def handle(_msg: Message, _group: Group) -> None:
        handled.set()

    say(alice, gid, "hello")
    await asyncio.wait_for(handled.wait(), WAIT)
    assert bob.node.daemon.store.feed_since(0) == []
    assert bob.node.daemon.store.feed_last() == 0
    assert alice.daemon.store.feed_last() == 0
    await bob.close()


async def test_sse_resume_past_the_retention_window_gets_a_gap_event(
    cluster: Cluster, sockdir: Path
) -> None:
    alice, bob, gid = await pair(cluster, sockdir, mode="sse", sse_retention=60)
    handled: list[str] = []
    changed = asyncio.Event()

    @bob.sdk.on_message
    async def handle(msg: Message, _group: Group) -> None:
        handled.append(msg.raw_text)
        changed.set()

    stream = asyncio.create_task(bob.sdk.stream())
    await bob.hub.wait_listeners(1)
    say(alice, gid, "m1")
    while not handled:
        changed.clear()
        await asyncio.wait_for(changed.wait(), WAIT)
    first_id = next(s for s, _g, p in bob.node.daemon.store.feed_since(0) if "msg_id" in p)
    stream.cancel()
    await asyncio.gather(stream, return_exceptions=True)
    await bob.hub.wait_listeners(0)

    # Inside the window the items survive a restart.
    await bob.server.stop()
    await bob.node.restart()
    bob.server = await serve_api(bob.node, sockdir)
    assert [s for s, _g, p in bob.node.daemon.store.feed_since(0) if "msg_id" in p] == [first_id]

    # Past the window they are purged when the daemon comes back.
    await bob.server.stop()
    await bob.node.daemon.stop()
    await cluster.advance(bob.node.config.sse_retention + 1)
    await bob.node.start()
    bob.server = await serve_api(bob.node, sockdir)
    assert bob.node.daemon.store.feed_since(0) == []

    resumed = AgentConnect(data_dir=bob.node.config.data_dir, socket=Path(str(bob.server.address)))
    gaps: list[Event] = []
    got = asyncio.Event()

    @resumed.on_event
    async def on_event(event: Event, _group: Group | None) -> None:
        if event.type == "sse_gap":
            gaps.append(event)
            got.set()

    task = asyncio.create_task(resumed.stream(last_event_id=str(first_id - 1)))
    await asyncio.wait_for(got.wait(), WAIT)
    assert gaps[0].data["missed_through"] >= first_id
    assert gaps[0].group is None
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await resumed.aclose()
    await bob.close()
