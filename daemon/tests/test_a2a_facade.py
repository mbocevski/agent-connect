"""The A2A facade without a daemon: a fake group sender, and replies handed
to the adapter as deliveries that name the facade's message in
``reply_to``."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from a2a.client import Client, ClientConfig, ClientFactory
from a2a.types import (
    AgentCard,
    CancelTaskRequest,
    Message,
    Part,
    Role,
    SendMessageRequest,
    StreamResponse,
    Task,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
)

from agentconnect.a2a_adapter import A2AAdapter, A2AOptions, convert
from agentconnect.a2a_adapter import facade as facade_module
from agentconnect.a2a_adapter.serve import LoopbackServer
from agentconnect.adapter import Delivery, Event, GroupView, Sender
from agentconnect.daemon import DaemonError

GID = "Z3JvdXA"
OTHER = "b3RoZXI"
PEER = "ac:v0:peer"


class Group:
    """Records what the facade sends; fails on demand."""

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.fail: str | None = None
        self.changed = asyncio.Event()

    async def __call__(self, group_id: str, body: dict[str, Any], **kw: Any) -> str:
        if self.fail is not None:
            raise DaemonError(self.fail, "refused")
        self.sent.append({"group_id": group_id, "body": body, **kw})
        self.changed.set()
        return f"sent-{len(self.sent)}"

    async def wait_for(self, n: int) -> list[dict[str, Any]]:
        async def loop() -> None:
            while len(self.sent) < n:
                self.changed.clear()
                await self.changed.wait()

        await asyncio.wait_for(loop(), 5)
        return self.sent


def reply(
    reply_to: str | None, kind: str, body: dict[str, Any], sender: str = PEER, n: int = 0
) -> Delivery:
    inner: dict[str, Any] = {"kind": kind, "body": body}
    if reply_to is not None:
        inner["reply_to"] = [reply_to]
    return Delivery(
        group_id=GID,
        msg_id=f"r-{sender}-{kind}-{n}-{reply_to}",
        kind=kind,
        body=body,
        sender=Sender(sender, "00" * 16, "peer", True),
        to=["*"],
        addressed_to_me=True,
        scope="Testing",
        trust_state={"self": "verified", "verified_members": 1, "members": 2},
        origin="agent",
        hop=1,
        inner=inner,
    )


def status(task_id: str, state: TaskState, text: str = "") -> dict[str, Any]:
    event = TaskStatusUpdateEvent(task_id=task_id, context_id=GID)
    event.status.state = state
    if text:
        event.status.message.CopyFrom(convert.agent_text(text, GID))
    return convert.to_json(event)


def user(text: str, **metadata: Any) -> SendMessageRequest:
    msg = Message(role=Role.ROLE_USER, message_id=f"u-{text}", parts=[Part(text=text)])
    if metadata:
        msg.metadata.update(metadata)
    return SendMessageRequest(message=msg)


VIEW = GroupView(GID, "Group", "Testing", 1, "free")


@pytest_asyncio.fixture
async def setup(tmp_path: Path) -> AsyncIterator[tuple[A2AAdapter, Group, Client]]:
    adapter = A2AAdapter(A2AOptions(facade_port=0, data_dir=tmp_path))
    group = Group()
    await adapter.on_outbound(group)
    assert adapter.facade is not None
    http = httpx.AsyncClient(headers={"Authorization": f"Bearer {adapter.facade_token}"})
    card = AgentCard(name="x")
    card.supported_interfaces.add(
        url=adapter.facade.url(GID), protocol_binding="JSONRPC", protocol_version="1.0"
    )
    card.capabilities.streaming = True
    client = ClientFactory(ClientConfig(httpx_client=http)).create(card)
    yield adapter, group, client
    await http.aclose()
    await adapter.aclose()


async def collect(stream: AsyncIterator[StreamResponse]) -> list[StreamResponse]:
    return [e async for e in stream]


async def answer(adapter: A2AAdapter, *deliveries: Delivery) -> None:
    for d in deliveries:
        await adapter.deliver(VIEW, d.sender, d.to, d)


async def test_a_failed_send_fails_the_task(setup: Any) -> None:
    _adapter, group, client = setup
    group.fail = "rate_limited"
    events = [e async for e in client.send_message(user("hi"))]
    last = events[-1].status_update
    assert last.status.state == TaskState.TASK_STATE_FAILED
    assert last.status.message.parts[0].text == "not sent: rate_limited"


async def test_task_events_and_a_closing_message(setup: Any) -> None:
    adapter, group, client = setup
    running = asyncio.ensure_future(collect(client.send_message(user("go", to="ac:v0:one"))))
    (sent,) = await group.wait_for(1)
    assert sent["to"] == ["ac:v0:one"]  # metadata.to as a single identity
    await answer(
        adapter,
        reply("sent-1", "a2a.task_status", {"taskId": {"not": "a string"}}, n=1),
        reply("sent-1", "a2a.task_status", status("remote", TaskState.TASK_STATE_WORKING), n=2),
        # Another member answering the same request is ignored.
        reply(
            "sent-1",
            "a2a.task_status",
            status("theirs", TaskState.TASK_STATE_COMPLETED),
            sender="ac:v0:other",
        ),
        reply("sent-1", "a2a.task_artifact", {"taskId": {"bad": 1}}, n=3),
        reply(
            "sent-1",
            "a2a.task_artifact",
            convert.to_json(
                TaskArtifactUpdateEvent(
                    task_id="remote", artifact={"artifact_id": "a", "parts": [{"text": "x"}]}
                )
            ),
            n=4,
        ),
        reply("sent-1", "control.pause", {"reason": "human"}, n=5),
        reply("sent-1", "a2a.message", convert.to_json(convert.agent_text("done", GID)), n=6),
    )
    events = await asyncio.wait_for(running, 5)
    kinds = [e.WhichOneof("payload") for e in events]
    assert kinds == ["task", "status_update", "artifact_update", "status_update"]
    final = events[-1].status_update
    assert final.status.state == TaskState.TASK_STATE_COMPLETED
    assert final.status.message.parts[0].text == "done"
    assert final.metadata["sender"] == PEER


async def test_cancel_before_any_reply_and_when_the_cancel_cannot_be_sent(setup: Any) -> None:
    adapter, group, client = setup
    stream = aiter(client.send_message(user("long", to=5)))  # a bad `to` means "*"
    first_event = asyncio.ensure_future(anext(stream))
    (sent,) = await group.wait_for(1)
    assert sent["to"] == ["*"]
    await answer(
        adapter,
        reply("sent-1", "a2a.task_status", status("remote", TaskState.TASK_STATE_SUBMITTED)),
    )
    first = await asyncio.wait_for(first_event, 5)
    task_id = first.task.id
    group.fail = "not_found"
    canceled = await client.cancel_task(CancelTaskRequest(id=task_id))
    assert canceled.status.state == TaskState.TASK_STATE_CANCELED


async def test_no_reply_in_time_fails_the_task(tmp_path: Path) -> None:
    adapter = A2AAdapter(A2AOptions(facade_port=0, data_dir=tmp_path, reply_timeout=0.0))
    await adapter.on_outbound(Group())
    assert adapter.facade is not None
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {adapter.facade_token}"}
    ) as http:
        card = AgentCard(name="x")
        card.supported_interfaces.add(url=adapter.facade.url(GID), protocol_binding="JSONRPC")
        client = ClientFactory(ClientConfig(httpx_client=http, streaming=False)).create(card)
        (result,) = [e async for e in client.send_message(user("anyone"))]
        assert result.task.status.state == TaskState.TASK_STATE_FAILED
        # A cancel of a task that has no peer side stays local.
    await adapter.aclose()


async def test_replies_without_reply_to_are_not_routed(setup: Any) -> None:
    adapter, _group, _client = setup
    assert adapter.facade is not None
    assert not adapter.facade.route_reply(reply(None, "a2a.message", {"text": "x"}))


async def test_facade_asgi_edges(setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, _group, _client = setup
    facade = adapter.facade
    assert facade is not None
    # Not HTTP: ignored.
    await facade({"type": "lifespan"}, None, None)
    # A non-loopback client is refused.
    transport = httpx.ASGITransport(app=facade, client=("10.0.0.1", 1234))
    host = f"127.0.0.1:{facade.port}"
    async with httpx.AsyncClient(transport=transport, base_url=f"http://{host}") as http:
        assert (await http.get(f"/g/{GID}/")).status_code == 403
    # Group apps are bounded.
    monkeypatch.setattr(facade_module, "MAX_GROUPS", 1)
    facade.card(GID, None)
    first = facade._app(GID, None)
    facade._app(OTHER, None)
    assert facade._app(GID, None) is not first


def test_convert_edges() -> None:
    task = Task(
        id="t", context_id="elsewhere", status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED)
    )
    task.artifacts.add(artifact_id="a", parts=[Part(text="x")])
    out = convert.stream_to_inner(StreamResponse(task=task), GID)
    assert [k for k, _ in out] == ["a2a.task_status", "a2a.task_artifact"]
    assert all(b["contextId"] == GID for _, b in out)
    assert convert.stream_to_inner(StreamResponse(), GID) == []
    assert convert.task_id_of(StreamResponse()) == ""
    assert not convert.is_final(StreamResponse())


async def test_loopback_server_edges() -> None:
    server = LoopbackServer(lambda *_: None)
    assert server.addresses() == []
    await server.stop()  # not started: nothing to do
    port = await server.start()
    taken = LoopbackServer(lambda *_: None, port)
    with pytest.raises(OSError, match="in use"):
        await taken.start()
    await server.stop()


async def test_a_decision_before_the_wait_is_kept(setup: Any) -> None:
    adapter, _group, _client = setup
    facade = adapter.facade
    assert facade is not None
    await adapter.on_event(VIEW, Event("send_failed", GID, {"msg_id": "m1", "code": "rejected"}))
    assert await facade.hold("m1") == "rejected"
    waiting = facade.hold("m2")
    facade.decided("m2", "approved")
    facade.decided("m2", "expired")  # a second word changes nothing
    assert await waiting == "approved"
