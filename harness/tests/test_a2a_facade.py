"""Direction 2 of the A2A adapter: a local A2A client (a2a-sdk) talks to a
group through the facade on 127.0.0.1."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from a2a.client import A2ACardResolver, Client, ClientConfig, ClientFactory
from a2a.types import (
    AgentCard,
    CancelTaskRequest,
    GetTaskPushNotificationConfigRequest,
    GetTaskRequest,
    Message,
    Part,
    Role,
    SendMessageRequest,
    StreamResponse,
    SubscribeToTaskRequest,
    TaskPushNotificationConfig,
    TaskState,
)
from a2a.utils.errors import A2AError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from agentconnect.a2a_adapter import A2AAdapter
from agentconnect.a2a_adapter.serve import LoopbackServer
from agentconnect.runtime.engine import DaemonError
from agentconnect_harness.a2a_agents import (
    AgentServer,
    HelloWorldExecutor,
    ScriptedExecutor,
    a2a_node,
    a2a_of,
)
from agentconnect_harness.cluster import WAIT, Cluster, Node


def adapter_of(node: Node) -> A2AAdapter:
    return a2a_of(node)


@dataclass
class Facade:
    url: str
    http: httpx.AsyncClient
    card: AgentCard
    client: Client
    plain: Client


async def open_facade(node: Node, group_id: str, member: str | None = None) -> Facade:
    adapter = adapter_of(node)
    assert adapter.facade is not None
    assert adapter.facade_token is not None
    url = adapter.facade.url(group_id, member)
    # A facade on a Unix socket: an httpx uds transport, as a2a-sdk clients use.
    path = adapter.facade.path
    http = httpx.AsyncClient(
        headers={"Authorization": f"Bearer {adapter.facade_token}"},
        timeout=WAIT,
        transport=None if path is None else httpx.AsyncHTTPTransport(uds=str(path)),
    )
    card = await A2ACardResolver(http, url).get_agent_card()
    client = ClientFactory(ClientConfig(httpx_client=http)).create(card)
    plain = ClientFactory(ClientConfig(httpx_client=http, streaming=False)).create(card)
    return Facade(url, http, card, client, plain)


def user(text: str, task_id: str = "", **metadata: Any) -> SendMessageRequest:
    msg = Message(role=Role.ROLE_USER, message_id=f"u-{text}", parts=[Part(text=text)])
    if task_id:
        msg.task_id = task_id
    if metadata:
        msg.metadata.update(metadata)
    return SendMessageRequest(message=msg)


async def collect(stream: AsyncIterator[StreamResponse]) -> list[StreamResponse]:
    return [r async for r in stream]


def states(events: list[StreamResponse]) -> list[str]:
    out: list[str] = []
    for r in events:
        if r.HasField("task"):
            out.append(str(TaskState.Name(r.task.status.state)))
        elif r.HasField("status_update"):
            out.append(str(TaskState.Name(r.status_update.status.state)))
        elif r.HasField("artifact_update"):
            out.append("artifact")
        else:
            out.append("message")
    return out


@pytest_asyncio.fixture
async def scripted() -> AsyncIterator[AgentServer]:
    agent = AgentServer(ScriptedExecutor(), "scripted", skills=["stream", "ask"])
    await agent.start()
    yield agent
    await agent.stop()


async def pair(
    cluster: Cluster, agent: AgentServer, facade_socket: Path | None = None
) -> tuple[Node, Node, str]:
    a = await a2a_node(cluster, "a", facade=True, facade_socket=facade_socket)
    b = await a2a_node(cluster, "b", agent)
    gid = a.daemon.create_group("Pair", "Ask the other agent")
    await a.idle()
    await cluster.invite(a, b, gid)
    await a.wait(lambda: b.me in adapter_of(a).peer_cards(gid))
    return a, b, gid


@pytest.mark.parametrize("over", ["tcp", "socket"])
async def test_one_to_one_facade(
    cluster: Cluster, scripted: AgentServer, sockdir: Path, over: str
) -> None:
    a, b, gid = await pair(cluster, scripted, sockdir / "facade.sock" if over == "socket" else None)
    f = await open_facade(a, gid)
    try:
        # 1:1: the card mirrors the peer's, with the facade's interface and auth.
        assert f.card.name == "scripted"
        assert [s.id for s in f.card.skills] == ["stream", "ask"]
        assert f.card.supported_interfaces[0].url == f.url
        assert f.card.capabilities.streaming
        assert "agentconnectBearer" in f.card.security_schemes

        # A plain message answer comes back as a message.
        (reply,) = await collect(f.plain.send_message(user("echo hello")))
        assert reply.HasField("message")
        assert reply.message.parts[0].text.endswith("echo hello")
        assert reply.message.context_id == gid
        assert reply.message.metadata["sender"] == b.me
        assert reply.message.metadata["untrusted"] is True

        # Streaming: the peer's task, its artifacts, and its end state.
        events = await collect(f.client.send_message(user("stream it")))
        assert states(events) == [
            "TASK_STATE_SUBMITTED",
            "TASK_STATE_SUBMITTED",
            "TASK_STATE_WORKING",
            "artifact",
            "artifact",
            "TASK_STATE_COMPLETED",
        ]
        task_id = events[0].task.id
        assert all(e.task.id == task_id for e in events if e.HasField("task"))
        remote = events[-1].status_update.metadata["remote_task_id"]
        assert remote
        assert remote != task_id

        task = await f.client.get_task(GetTaskRequest(id=task_id))
        assert task.status.state == TaskState.TASK_STATE_COMPLETED
        assert task.context_id == gid
        assert [p.text for p in task.artifacts[0].parts] == ["part one", "part two"]
    finally:
        await f.http.aclose()


async def test_facade_input_required_and_cancel(cluster: Cluster, scripted: AgentServer) -> None:
    a, _b, gid = await pair(cluster, scripted)
    f = await open_facade(a, gid)
    executor = scripted.executor
    assert isinstance(executor, ScriptedExecutor)
    try:
        events = await collect(f.client.send_message(user("ask something")))
        assert states(events)[-1] == "TASK_STATE_INPUT_REQUIRED"
        task_id = events[0].task.id
        remote = events[-1].status_update.metadata["remote_task_id"]
        # The follow-up names the facade's task; the peer sees its own.
        events = await collect(f.client.send_message(user("this one", task_id=task_id)))
        assert states(events)[-1] == "TASK_STATE_COMPLETED"
        seen = await executor.wait_for(2)
        assert seen[1].continued
        assert seen[1].task_id == remote

        # Cancel: the facade cancels its task and the peer's.
        stream = aiter(f.client.send_message(user("wait here")))
        first = await anext(stream)
        task_id = first.task.id
        working = await anext(stream)  # the peer's task, submitted
        assert working.status_update.status.state == TaskState.TASK_STATE_SUBMITTED
        working = await anext(stream)
        assert working.status_update.status.state == TaskState.TASK_STATE_WORKING
        sub = aiter(f.client.subscribe(SubscribeToTaskRequest(id=task_id)))
        assert (await anext(sub)).task.id == task_id
        canceled = await f.client.cancel_task(CancelTaskRequest(id=task_id))
        assert canceled.status.state == TaskState.TASK_STATE_CANCELED
        await asyncio.wait_for(_until(lambda: bool(executor.canceled), executor), WAIT)
        assert executor.canceled == [working.status_update.metadata["remote_task_id"]]
    finally:
        await f.http.aclose()


async def _until(predicate: Any, executor: ScriptedExecutor) -> None:
    while not predicate():
        executor.changed.clear()
        await executor.changed.wait()


async def test_facade_push_notifications(cluster: Cluster, scripted: AgentServer) -> None:
    a, _b, gid = await pair(cluster, scripted)
    f = await open_facade(a, gid)
    got: list[dict[str, Any]] = []
    changed = asyncio.Event()

    async def hook(request: Request) -> Response:
        got.append(await request.json())
        changed.set()
        return JSONResponse({})

    receiver = LoopbackServer(Starlette(routes=[Route("/hook", hook, methods=["POST"])]))
    port = await receiver.start()
    try:
        stream = aiter(f.client.send_message(user("ask first")))
        task_id = (await anext(stream)).task.id
        async for _ in stream:
            pass
        config = TaskPushNotificationConfig(
            task_id=task_id,
            id="cfg",
            url=f"http://127.0.0.1:{port}/hook",
            token=secrets.token_hex(8),
        )
        await f.client.create_task_push_notification_config(config)
        stored = await f.client.get_task_push_notification_config(
            GetTaskPushNotificationConfigRequest(task_id=task_id, id="cfg")
        )
        assert stored.url == config.url
        await collect(f.client.send_message(user("answer", task_id=task_id)))

        async def pushed() -> None:
            while not any("COMPLETED" in str(p) for p in got):
                changed.clear()
                await changed.wait()

        await asyncio.wait_for(pushed(), WAIT)
    finally:
        await receiver.stop()
        await f.http.aclose()


async def test_facade_refuses_another_context(cluster: Cluster, scripted: AgentServer) -> None:
    a, _b, gid = await pair(cluster, scripted)
    f = await open_facade(a, gid)
    try:
        request = user("echo x")
        request.message.context_id = "some-other-context"
        with pytest.raises(A2AError):
            await collect(f.plain.send_message(request))
    finally:
        await f.http.aclose()


async def test_group_facade_composite_and_member_paths(
    cluster: Cluster, scripted: AgentServer
) -> None:
    hello = AgentServer(HelloWorldExecutor(), "helloworld", skills=["greet"])
    await hello.start()
    try:
        a, b, gid = await pair(cluster, scripted)
        c = await a2a_node(cluster, "c", hello)
        await cluster.invite(a, c, gid)
        await a.wait(lambda: c.me in adapter_of(a).peer_cards(gid))
        f = await open_facade(a, gid)
        try:
            # A composite card: every member's skills, prefixed by the member.
            assert f.card.name == "Pair"
            ids = sorted(s.id for s in f.card.skills)
            assert ids == sorted([f"{b.me}/stream", f"{b.me}/ask", f"{c.me}/greet"])
            # Mention mode: metadata.to picks the member.
            (reply,) = await collect(f.plain.send_message(user("echo to b", to=[b.me])))
            assert reply.message.metadata["sender"] == b.me
            (reply,) = await collect(f.plain.send_message(user("hi c", to=[c.me])))
            assert reply.message.parts[0].text == "Hello World"
        finally:
            await f.http.aclose()

        m = await open_facade(a, gid, member=c.me)
        try:
            assert m.card.name == "helloworld"
            assert m.url.endswith(f"/m/{c.me}/")
            (reply,) = await collect(m.plain.send_message(user("hello")))
            assert reply.message.metadata["sender"] == c.me
        finally:
            await m.http.aclose()
    finally:
        await hello.stop()


async def test_facade_auth_and_loopback(cluster: Cluster) -> None:
    a = await a2a_node(cluster, "a", facade=True)
    gid = a.daemon.create_group("Solo", "Nobody else")
    adapter = adapter_of(a)
    assert adapter.facade is not None
    url = adapter.facade.url(gid) + ".well-known/agent-card.json"
    good = {"Authorization": f"Bearer {adapter.facade_token}"}
    async with httpx.AsyncClient() as http:
        assert (await http.get(url)).status_code == 401
        bad = {"Authorization": "Bearer " + "x" * 43}
        assert (await http.get(url, headers=bad)).status_code == 401
        assert (await http.get(url, headers={"Authorization": "Basic abc"})).status_code == 401
        origin = good | {"Origin": "http://evil.example"}
        assert (await http.get(url, headers=origin)).status_code == 403
        host = good | {"Host": "evil.example"}
        assert (await http.get(url, headers=host)).status_code == 403
        root = f"http://127.0.0.1:{adapter.facade.port}/"
        assert (await http.get(root, headers=good)).status_code == 404
        assert (await http.get(root + "g/not!valid/", headers=good)).status_code == 404
        ok = await http.get(url, headers=good)
        assert ok.status_code == 200
        assert ok.json()["supportedInterfaces"][0]["url"].startswith("http://127.0.0.1:")
    # The facade listens on loopback only.
    server = adapter.facade.listening()
    assert server == [("127.0.0.1", adapter.facade.port)]


async def test_a_held_send_is_reported_not_timed_out(
    cluster: Cluster, scripted: AgentServer
) -> None:
    a, _b, gid = await pair(cluster, scripted)
    a.daemon.update_safety(gid, {"require_approval": "outbound"})
    f = await open_facade(a, gid)
    try:
        # The stream says so at once (and stays open until the human decides).
        events: list[StreamResponse] = []
        async for event in f.client.send_message(user("echo hello")):
            events.append(event)
            if states(events)[-1] == "TASK_STATE_INPUT_REQUIRED":
                break
        note = events[-1].status_update.status.message.parts[0].text
        assert "approval" in note
        (held,) = a.daemon.held_messages()
        assert held["direction"] == "out"
    finally:
        await f.http.aclose()


async def poll_task(f: Facade, task_id: str, state: int) -> Any:
    """The facade task once it reaches ``state`` (each poll is a request,
    so the loop yields to the daemon and the agents; WAIT bounds it)."""

    async def loop() -> Any:
        while True:
            task = await f.client.get_task(GetTaskRequest(id=task_id))
            if task.status.state == state:
                return task
            await asyncio.sleep(0)

    return await asyncio.wait_for(loop(), WAIT)


def seen_texts(agent: AgentServer) -> list[str]:
    received = getattr(agent.executor, "received", [])
    return [p.text for s in received for p in s.message.parts]


async def test_an_approved_held_send_goes_out_and_its_reply_reaches_the_task(
    cluster: Cluster, scripted: AgentServer
) -> None:
    a, _b, gid = await pair(cluster, scripted)
    a.daemon.update_safety(gid, {"require_approval": "outbound"})
    f = await open_facade(a, gid)
    try:
        (first,) = await collect(f.plain.send_message(user("echo held")))
        task_id = first.task.id
        assert first.task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
        (held,) = a.daemon.held_messages()
        a.daemon.approve_message(held["hold_id"])
        task = await poll_task(f, task_id, TaskState.TASK_STATE_COMPLETED)
        replies = [p.text for m in task.history for p in m.parts]
        assert any(t.endswith("echo held") for t in replies), replies
        # It reached b's agent once, as the request it is.
        assert sum("echo held" in t for t in seen_texts(scripted)) == 1
    finally:
        await f.http.aclose()


@pytest.mark.parametrize(("decide", "state"), [("reject", "REJECTED"), ("expire", "FAILED")])
async def test_a_rejected_or_expired_held_send_ends_the_task(
    cluster: Cluster, scripted: AgentServer, decide: str, state: str
) -> None:
    a, _b, gid = await pair(cluster, scripted)
    a.daemon.update_safety(gid, {"require_approval": "outbound", "approval_ttl_secs": 60})
    f = await open_facade(a, gid)
    try:
        (first,) = await collect(f.plain.send_message(user("echo never")))
        (held,) = a.daemon.held_messages()
        if decide == "reject":
            await a.daemon.reject_message(held["hold_id"])
        else:
            await cluster.advance(61)
        await poll_task(f, first.task.id, getattr(TaskState, f"TASK_STATE_{state}"))
        assert not any("echo never" in t for t in seen_texts(scripted))
    finally:
        await f.http.aclose()


async def test_cancelling_a_held_facade_request_withdraws_the_send(
    cluster: Cluster, scripted: AgentServer
) -> None:
    a, _b, gid = await pair(cluster, scripted)
    a.daemon.update_safety(gid, {"require_approval": "outbound"})
    f = await open_facade(a, gid)
    facade = adapter_of(a).facade
    assert facade is not None
    try:
        (first,) = await collect(f.plain.send_message(user("echo cancel me")))
        (held,) = a.daemon.held_messages()
        await f.plain.cancel_task(CancelTaskRequest(id=first.task.id))
        await a.wait(lambda: a.daemon.held_messages() == [])
        await a.wait(lambda: not facade.waiters)
        failed = [
            e["data"] for e in a.daemon.store.events(limit=10_000) if e["type"] == "send_failed"
        ]
        assert [(e["msg_id"], e["code"]) for e in failed] == [(held["msg_id"], "cancelled")]
        decisions = [
            r["decision"] for r in a.daemon.store.audit(gid) if r["msg_id"] == held["msg_id"]
        ]
        assert decisions == ["hold_for_approval", "cancelled"]
        with pytest.raises(DaemonError):
            a.daemon.approve_message(held["hold_id"])
    finally:
        await f.http.aclose()
