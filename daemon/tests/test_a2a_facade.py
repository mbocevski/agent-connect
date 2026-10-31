"""The A2A facade without a daemon: a fake group sender, and replies handed
to the adapter as deliveries that name the facade's message in
``reply_to``."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import os
import random
import shutil
import socket
import stat
import tempfile
import types
from collections.abc import AsyncIterator, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, override

import httpx
import pytest
import pytest_asyncio
from a2a.client import Client, ClientConfig, ClientFactory
from a2a.server.context import ServerCallContext
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
    TaskPushNotificationConfig,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
)
from a2a.utils.errors import A2AError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from agentconnect.a2a_adapter import A2AAdapter, A2AOptions, convert
from agentconnect.a2a_adapter import facade as facade_module
from agentconnect.a2a_adapter import serve as serve_module
from agentconnect.a2a_adapter.serve import LoopbackServer
from agentconnect.adapter import Delivery, Event, GroupView, Sender
from agentconnect.isolation import PeerCred
from agentconnect.runtime.engine import DaemonError
from agentconnect_harness.a2a_agents import AgentServer, HelloWorldExecutor

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


def reply(  # noqa: PLR0913, PLR0917
    reply_to: str | None,
    kind: str,
    body: dict[str, Any],
    sender: str = PEER,
    n: int = 0,
    instance: str = "00" * 8,
) -> Delivery:
    inner: dict[str, Any] = {"kind": kind, "body": body}
    if reply_to is not None:
        inner["reply_to"] = [reply_to]
    return Delivery(
        group_id=GID,
        msg_id=f"r-{sender}-{instance}-{kind}-{n}-{reply_to}",
        kind=kind,
        body=body,
        sender=Sender(sender, instance, "peer", True),
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


async def test_a_member_addressed_request_takes_only_that_members_reply(setup: Any) -> None:
    """SR-37: a request on a member's path (`/g/<gid>/m/<X>/`) goes to X
    alone; in a `free` group every member reads it, but a reply from anyone
    else can't stand in for X's."""
    adapter, group, _client = setup
    card = AgentCard(name="x")
    card.supported_interfaces.add(
        url=adapter.facade.url(GID, PEER), protocol_binding="JSONRPC", protocol_version="1.0"
    )
    http = httpx.AsyncClient(headers={"Authorization": f"Bearer {adapter.facade_token}"})
    member = ClientFactory(ClientConfig(httpx_client=http)).create(card)
    running = asyncio.ensure_future(collect(member.send_message(user("just you"))))
    (sent,) = await group.wait_for(1)
    assert sent["to"] == [PEER]
    await answer(
        adapter,
        reply(
            "sent-1",
            "a2a.message",
            convert.to_json(convert.agent_text("not you", GID)),
            sender="ac:v0:other",
        ),
        reply("sent-1", "a2a.message", convert.to_json(convert.agent_text("me", GID)), n=1),
    )
    (event,) = await asyncio.wait_for(running, 5)
    assert event.message.parts[0].text == "me"
    assert event.message.metadata["sender"] == PEER
    await http.aclose()


async def test_another_members_reply_to_a_member_request_is_context(tmp_path: Path) -> None:
    """SR-37: the facade doesn't take another member's reply to a request
    on a member's path, so the adapter handles it as any other message: the
    local agent gets it as context, not nothing."""
    agent = AgentServer(HelloWorldExecutor(), "hello")
    await agent.start()
    options = A2AOptions(
        facade_port=0, data_dir=tmp_path, local_agent_url=agent.url, context_messages=3
    )
    adapter = A2AAdapter(options)
    group = Group()
    await adapter.on_outbound(group)
    assert adapter.facade is not None
    card = AgentCard(name="x")
    card.supported_interfaces.add(
        url=adapter.facade.url(GID, PEER), protocol_binding="JSONRPC", protocol_version="1.0"
    )
    http = httpx.AsyncClient(headers={"Authorization": f"Bearer {adapter.facade_token}"})
    member = ClientFactory(ClientConfig(httpx_client=http)).create(card)
    running = asyncio.ensure_future(collect(member.send_message(user("just you"))))
    try:
        await group.wait_for(1)
        other = "ac:v0:other"
        body = convert.to_json(convert.agent_text("not you", GID))
        stray = replace(reply("sent-1", "a2a.message", body, other), addressed_to_me=False)
        await answer(adapter, stray)
        body = convert.to_json(convert.agent_text("now you", GID))
        await answer(adapter, reply(None, "a2a.message", body, other))
        await group.wait_for(2)  # the local agent answered
        executor = agent.executor
        assert isinstance(executor, HelloWorldExecutor)
        meta = convert.to_json(executor.received[0].message)["metadata"]
        assert [m["msg_id"] for m in meta.get("context_messages", [])] == [stray.msg_id]
        body = convert.to_json(convert.agent_text("me", GID))
        await answer(adapter, reply("sent-1", "a2a.message", body, n=1))
        (event,) = await asyncio.wait_for(running, 5)
        assert event.message.parts[0].text == "me"
    finally:
        running.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await running
        await http.aclose()
        await adapter.aclose()
        await agent.stop()


async def test_a_task_is_bound_to_the_instance_that_answered(
    setup: Any, rng: random.Random
) -> None:
    """Replicas of one member each run their own task (SPEC 9.4): the
    facade's task follows the instance that answered first, and its
    follow-ups and cancel name that instance."""
    adapter, group, client = setup
    first, second = (f"{rng.getrandbits(64):016x}" for _ in range(2))
    stream = aiter(client.send_message(user("ask", to=PEER)))
    created = asyncio.ensure_future(anext(stream))
    (sent,) = await group.wait_for(1)
    assert (sent["to"], sent["instance"]) == ([PEER], None)  # both may answer
    working = status("mine", TaskState.TASK_STATE_WORKING)
    await answer(adapter, reply("sent-1", "a2a.task_status", working, instance=first))
    task_id = (await asyncio.wait_for(created, 5)).task.id
    assert (await asyncio.wait_for(anext(stream), 5)).status_update.metadata[
        "remote_task_id"
    ] == "mine"
    # The other replica's task, and anything else from it, isn't this task.
    await answer(
        adapter,
        reply(
            "sent-1",
            "a2a.task_status",
            status("theirs", TaskState.TASK_STATE_COMPLETED),
            instance=second,
        ),
        reply(
            "sent-1", "a2a.message", convert.to_json(convert.agent_text("x", GID)), instance=second
        ),
        reply(
            "sent-1",
            "a2a.task_status",
            status("mine", TaskState.TASK_STATE_INPUT_REQUIRED),
            n=1,
            instance=first,
        ),
    )
    last = await asyncio.wait_for(anext(stream), 5)
    assert last.status_update.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    assert last.status_update.metadata["remote_task_id"] == "mine"

    # The follow-up goes to the bound instance only.
    follow = Message(role=Role.ROLE_USER, message_id="u-more", parts=[Part(text="more")])
    follow.task_id = task_id
    more = asyncio.ensure_future(collect(client.send_message(SendMessageRequest(message=follow))))
    sent = (await group.wait_for(2))[1]
    assert (sent["to"], sent["instance"], sent["body"]["taskId"]) == ([PEER], first, "mine")
    done = status("mine", TaskState.TASK_STATE_COMPLETED)
    await answer(adapter, reply("sent-2", "a2a.task_status", done, n=2, instance=first))
    assert (await asyncio.wait_for(more, 5))[-1].status_update.status.state == (
        TaskState.TASK_STATE_COMPLETED
    )


async def test_a_cancel_names_the_bound_instance(setup: Any, rng: random.Random) -> None:
    adapter, group, client = setup
    bound = f"{rng.getrandbits(64):016x}"
    stream = aiter(client.send_message(user("long", to=PEER)))
    first_event = asyncio.ensure_future(anext(stream))
    await group.wait_for(1)
    submitted = status("remote", TaskState.TASK_STATE_SUBMITTED)
    await answer(adapter, reply("sent-1", "a2a.task_status", submitted, instance=bound))
    task_id = (await asyncio.wait_for(first_event, 5)).task.id
    await asyncio.wait_for(anext(stream), 5)
    await client.cancel_task(CancelTaskRequest(id=task_id))
    cancel = (await group.wait_for(2))[1]
    assert (cancel["kind"], cancel["to"], cancel["instance"]) == (
        "a2a.task_cancel",
        [PEER],
        bound,
    )
    assert cancel["body"] == {"id": "remote"}


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
    facade.track("h1")
    data = {"msg_id": "m1", "hold_id": "h1", "code": "rejected"}
    await adapter.on_event(VIEW, Event("send_failed", GID, data))
    assert await facade.hold("h1") == "rejected"
    waiting = facade.hold("m2")
    facade.decided("m2", "approved")
    facade.decided("m2", "expired")  # a second word changes nothing
    assert await waiting == "approved"


async def test_the_early_decision_buffer_keeps_only_own_holds_for_a_while(setup: Any) -> None:
    adapter, _group, _client = setup
    facade = adapter.facade
    assert facade is not None
    now = [1000.0]
    facade.now = lambda: now[0]
    # A decision on a send the facade never made is not kept.
    facade.decided("someone-elses", "approved")
    assert facade.early() == 0
    facade.track("mine")
    facade.decided("mine", "rejected")
    assert facade.early() == 1
    assert await facade.hold("mine") == "rejected"
    assert facade.early() == 0, "consumed"
    facade.track("late")
    facade.decided("late", "approved")
    now[0] += 3601
    facade.decided("late-too", "approved")  # sweeps
    assert facade.early() == 0, "expired"


async def test_the_early_decision_buffer_is_bounded(
    setup: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A flood of the facade's own held sends, decided before anyone waits,
    # keeps only the newest MAX_EARLY: memory stays bounded.
    adapter, _group, _client = setup
    facade = adapter.facade
    assert facade is not None
    monkeypatch.setattr(facade_module, "MAX_EARLY", 3)
    for i in range(5):
        facade.track(f"h{i}")
    for i in range(5):
        facade.decided(f"h{i}", "approved")
    assert facade.early() == 3
    assert await asyncio.wait_for(facade.hold("h4"), 1) == "approved"
    assert facade.early() == 2


# -- the push client goes straight to the push URL (SR-30) ---------------------


class _Recorder:
    """A loopback server on a thread: records every connection's first bytes
    and answers with ``answer``."""

    def __init__(self, answer: bytes) -> None:
        import socket  # noqa: PLC0415
        import threading  # noqa: PLC0415

        self._sock = socket.create_server(("127.0.0.1", 0))
        self._sock.settimeout(0.05)
        self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}"
        self.received: list[bytes] = []
        self._answer, self._open = answer, True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while self._open:
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            with conn:
                self.received.append(conn.recv(65536))
                conn.sendall(self._answer)

    def close(self) -> list[bytes]:
        self._open = False
        self._thread.join(timeout=5)
        self._sock.close()
        return self.received


async def test_the_push_client_ignores_proxies_and_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy = _Recorder(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
    elsewhere = _Recorder(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
    hook = _Recorder(
        b"HTTP/1.1 307 Temporary Redirect\r\n"
        + f"location: {elsewhere.url}/stolen\r\n".encode()
        + b"content-length: 0\r\n\r\n"
    )
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(var, proxy.url)
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    # The client the facade's push sender uses (_GroupApps), built as the
    # adapter builds it, with the environment above.
    facade = facade_module.Facade(A2AAdapter(A2AOptions()), "t", 0)
    try:
        resp = await facade._http.post(f"{hook.url}/hook", json={"task": "update"})
        assert resp.status_code == 307  # not followed
    finally:
        await facade._http.aclose()
    assert len(hook.close()) == 1
    assert elsewhere.close() == []
    assert proxy.close() == []


# -- the facade on a Unix socket, checked by its client's user (SR-10 class) --


@pytest.fixture
def sockdir() -> Iterator[Path]:
    # /tmp, not $TMPDIR: socket paths are limited to about 100 bytes.
    d = Path(tempfile.mkdtemp(prefix="ac-facade-", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def socket_facade(sockdir: Path, tmp_path: Path) -> A2AAdapter:
    adapter = A2AAdapter(
        A2AOptions(
            facade_socket=sockdir / "facade.sock",
            facade_uids=frozenset({os.geteuid()}),
            data_dir=tmp_path,
        )
    )
    await adapter.on_outbound(Group())
    return adapter


async def test_the_facade_on_a_socket_serves_its_own_user(sockdir: Path, tmp_path: Path) -> None:
    adapter = await socket_facade(sockdir, tmp_path)
    try:
        assert adapter.facade is not None
        path = sockdir / "facade.sock"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        url = adapter.facade.url(GID)
        assert url.startswith("http://localhost/")
        transport = httpx.AsyncHTTPTransport(uds=str(path))
        auth = {"Authorization": f"Bearer {adapter.facade_token}"}
        async with httpx.AsyncClient(transport=transport, headers=auth) as http:
            card = await http.get(f"{url}.well-known/agent-card.json")
            assert card.status_code == 200, card.text
            assert card.json()["supportedInterfaces"][0]["url"] == url
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(path))) as http:
            assert (await http.get(f"{url}.well-known/agent-card.json")).status_code == 401
    finally:
        await adapter.aclose()
    assert not (sockdir / "facade.sock").exists()


async def test_another_users_connection_is_closed_before_it_is_read(
    sockdir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    other = os.geteuid() + 1
    monkeypatch.setattr(
        "agentconnect.isolation.peer_credentials", lambda _s: PeerCred(uid=other, gid=other)
    )
    adapter = await socket_facade(sockdir, tmp_path)
    try:
        reader, writer = await asyncio.open_unix_connection(str(sockdir / "facade.sock"))
        answer = b"(reset)"
        with contextlib.suppress(ConnectionError):
            writer.write(f"GET /g/{GID}/.well-known/agent-card.json HTTP/1.1\r\n".encode())
            writer.write(b"host: localhost\r\nauthorization: Bearer x\r\n\r\n")
            await writer.drain()
            answer = await asyncio.wait_for(reader.read(), 5)
        assert answer in (b"", b"(reset)")  # closed at accept: no answer, nothing read
        writer.close()
    finally:
        await adapter.aclose()
    events = [
        json.loads(line) for line in capsys.readouterr().err.splitlines() if line.startswith("{")
    ]
    (refused,) = [e for e in events if e["event"] == "a2a_facade_peer_refused"]
    assert refused["uid"] == other


async def test_a_connection_whose_user_cant_be_read_is_closed_too(
    sockdir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def unreadable(_sock: object) -> PeerCred:
        raise OSError("no peer credentials")

    monkeypatch.setattr("agentconnect.isolation.peer_credentials", unreadable)
    adapter = await socket_facade(sockdir, tmp_path)
    try:
        reader, writer = await asyncio.open_unix_connection(str(sockdir / "facade.sock"))
        answer = b"(reset)"
        with contextlib.suppress(ConnectionError):
            writer.write(f"GET /g/{GID}/.well-known/agent-card.json HTTP/1.1\r\n".encode())
            writer.write(b"host: localhost\r\n\r\n")
            await writer.drain()
            answer = await asyncio.wait_for(reader.read(), 5)
        assert answer in (b"", b"(reset)")  # refused, not answered
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()
    finally:
        await adapter.aclose()
    events = [
        json.loads(line) for line in capsys.readouterr().err.splitlines() if line.startswith("{")
    ]
    assert [e for e in events if e["event"] == "a2a_facade_peer_unknown"]


async def test_the_facade_socket_replaces_a_stale_one_only(sockdir: Path, tmp_path: Path) -> None:
    path = sockdir / "facade.sock"
    path.write_text("not a socket")
    with pytest.raises(FileExistsError, match="not a socket"):
        await socket_facade(sockdir, tmp_path)
    path.unlink()
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(str(path))
    stale.close()  # left behind by an earlier run
    adapter = await socket_facade(sockdir, tmp_path)
    await adapter.aclose()


# -- the socket server itself (serve.UnixServer) ------------------------------


async def _reached_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    if scope["type"] == "http":
        REACHED.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


REACHED: list[str] = []


def _ask(path: Path) -> bytes:
    with socket.socket(socket.AF_UNIX) as c:
        c.settimeout(5)
        c.connect(str(path))
        try:
            c.sendall(b"GET /secret HTTP/1.1\r\nhost: localhost\r\n\r\n")
            return c.recv(4096)
        except OSError:
            return b""


def _loops() -> list[Any]:
    loops: list[Any] = [pytest.param(asyncio.new_event_loop, id="asyncio")]
    try:
        uvloop = importlib.import_module("uvloop")  # optional: not a dependency
    except ImportError:
        loops.append(pytest.param(None, id="uvloop", marks=pytest.mark.skip("no uvloop")))
    else:
        loops.append(pytest.param(uvloop.new_event_loop, id="uvloop"))
    return loops


@pytest.mark.parametrize("loop_factory", _loops())
def test_the_peer_check_holds_on_every_event_loop(sockdir: Path, loop_factory: Any) -> None:
    # The check is in the protocol, not in the listening socket's accept(),
    # which uvloop doesn't call from Python.
    seen: list[object] = []

    def refuse(sock: object) -> bool:
        seen.append(sock)
        return False

    async def run() -> bytes:
        server = serve_module.UnixServer(_reached_app, sockdir / "f.sock", refuse)
        await server.start()
        try:
            return await asyncio.to_thread(_ask, sockdir / "f.sock")
        finally:
            await server.stop()

    REACHED.clear()
    with asyncio.Runner(loop_factory=loop_factory) as runner:
        answer = runner.run(run())
    assert answer == b""
    assert REACHED == []
    assert len(seen) == 1


async def test_the_socket_directory_must_be_private(
    sockdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A directory others can write to: its lstat reports group write (no
    # chmod, so the test never makes anything writable for real).
    real_lstat = Path.lstat

    def lstat(self: Path) -> os.stat_result:
        st = real_lstat(self)
        if self != sockdir:
            return st
        fields = list(st)
        fields[0] = stat.S_IFDIR | 0o770
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "lstat", lstat)
    server = serve_module.UnixServer(_reached_app, sockdir / "f.sock", lambda _s: True)
    with pytest.raises(PermissionError, match="only it can write"):
        await server.start()


async def test_a_symlinked_socket_directory_is_refused(sockdir: Path) -> None:
    real = sockdir / "real"
    real.mkdir(mode=0o700)
    (sockdir / "link").symlink_to(real)
    server = serve_module.UnixServer(_reached_app, sockdir / "link" / "f.sock", lambda _s: True)
    with pytest.raises(PermissionError, match="only it can write"):
        await server.start()


async def test_a_running_server_at_the_path_is_not_replaced(sockdir: Path) -> None:
    first = serve_module.UnixServer(_reached_app, sockdir / "f.sock", lambda _s: True)
    await first.start()
    try:
        second = serve_module.UnixServer(_reached_app, sockdir / "f.sock", lambda _s: True)
        with pytest.raises(FileExistsError, match="in use"):
            await second.start()
        assert (await asyncio.to_thread(_ask, sockdir / "f.sock")).startswith(b"HTTP/1.1 200")
    finally:
        await first.stop()


@pytest.mark.parametrize(("gid", "mode"), [(None, 0o600), (os.getgid(), 0o660)])
async def test_the_mode_is_set_at_bind_and_no_link_is_followed(
    sockdir: Path, monkeypatch: pytest.MonkeyPatch, gid: int | None, mode: int
) -> None:
    path = sockdir / "f.sock"
    server = serve_module.UnixServer(_reached_app, path, lambda _s: True, gid)
    await server.start()
    assert stat.S_IMODE(path.lstat().st_mode) == mode
    await server.stop()
    # Someone who could write to the directory swaps the socket for a link
    # right after bind(): nothing done through the path afterwards reaches
    # the link's target.
    victim = sockdir / "victim"
    victim.write_text("secret")
    victim.chmod(0o600)

    class Racing(socket.socket):
        @override
        def bind(self, address: Any) -> None:
            super().bind(address)
            if self.family == socket.AF_UNIX:
                os.unlink(address)
                os.symlink(victim, address)

    fake = types.SimpleNamespace(
        socket=Racing, AF_UNIX=socket.AF_UNIX, SOCK_STREAM=socket.SOCK_STREAM
    )
    monkeypatch.setattr(serve_module, "socket", fake)
    racing = serve_module.UnixServer(_reached_app, path, lambda _s: True, gid)
    with pytest.raises(FileExistsError, match="replaced"):
        await racing.start()
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600
    assert victim.read_text() == "secret"


async def test_a_listener_with_a_full_backlog_counts_as_in_use(sockdir: Path) -> None:
    # The probe for a live server mustn't block the event loop: a listener
    # that accepts nothing, its queue full, is in use, not stale.
    path = sockdir / "f.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(0)
    queued: list[socket.socket] = []
    try:
        while True:  # fill the queue until a connect would block
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.setblocking(False)
            try:
                c.connect(str(path))
            except BlockingIOError:
                c.close()
                break
            except ConnectionRefusedError:
                # macOS refuses a full queue with ECONNREFUSED, the same
                # answer as a stale socket: there the two can't be told
                # apart by connecting (serve._in_use).
                c.close()
                pytest.skip("a full accept queue reads as refused on this platform")
            queued.append(c)
        server = serve_module.UnixServer(_reached_app, path, lambda _s: True)
        with pytest.raises(FileExistsError, match="in use"):
            await server.start()
    finally:
        for c in queued:
            c.close()
        listener.close()


async def test_binding_the_socket_leaves_the_process_umask_alone(
    sockdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The umask is process-wide: a file another thread creates while the
    # socket is bound must get the process's usual mode.
    seen: list[int] = []
    usual = os.umask(0o022)
    os.umask(usual)

    class Watching(socket.socket):
        @override
        def bind(self, address: Any) -> None:
            super().bind(address)
            if self.family == socket.AF_UNIX:
                other = sockdir / "other-thread-file"
                other.write_text("x")
                seen.append(stat.S_IMODE(other.stat().st_mode))

    fake = types.SimpleNamespace(
        socket=Watching, AF_UNIX=socket.AF_UNIX, SOCK_STREAM=socket.SOCK_STREAM
    )
    monkeypatch.setattr(serve_module, "socket", fake)
    server = serve_module.UnixServer(_reached_app, sockdir / "f.sock", lambda _s: True, os.getgid())
    await server.start()
    try:
        assert stat.S_IMODE((sockdir / "f.sock").lstat().st_mode) == 0o660
    finally:
        await server.stop()
    assert seen == [0o666 & ~usual]


# -- push URLs: literal loopback only (SR-31) ------------------------------------


@pytest.mark.parametrize(
    ("url", "accepted"),
    [
        ("http://127.0.0.1:8080/hook", True),
        ("https://127.5.5.5/hook", True),
        ("http://[::1]:9000/hook", True),
        ("http://10.1.2.3/hook", False),
        ("http://192.168.1.20:8080/hook", False),
        ("http://localhost:8080/hook", False),  # a name: no lookup, no rebinding
        ("http://agent.example.org/hook", False),
        ("http://[::ffff:127.0.0.1]/hook", False),
        ("ftp://127.0.0.1/hook", False),
        ("http://127.0.0.1:99999/hook", False),
        ("http://user@127.0.0.1/hook", False),
        # urlsplit and httpx disagree on the host of these: the "@" rule
        # refuses them all.
        ("http://127.0.0.1\\@evil.example/h", False),
        ("http://127.0.0.1:80@evil.example/h", False),
        ("http://127.0.0.1%2f@evil.example/h", False),
        ("http:///hook", False),
        ("not a url", False),
    ],
)
async def test_only_literal_loopback_push_urls_are_accepted(url: str, accepted: bool) -> None:
    assert await facade_module.loopback_push_url(url) is accepted


async def test_a_push_config_off_loopback_is_refused_when_it_is_set(setup: Any) -> None:
    _adapter, group, client = setup
    group.fail = "rate_limited"  # a task, finished at once
    events = [e async for e in client.send_message(user("hi"))]
    task_id = events[0].task.id
    for url in ("http://10.1.2.3/hook", "http://localhost:8080/hook", "ftp://127.0.0.1/hook"):
        config = TaskPushNotificationConfig(task_id=task_id, id="bad", url=url)
        with pytest.raises(A2AError):
            await client.create_task_push_notification_config(config)
    ok = TaskPushNotificationConfig(task_id=task_id, id="ok", url="http://127.0.0.1:1/hook")
    assert (await client.create_task_push_notification_config(ok)).url == ok.url


async def test_a_stored_push_url_off_loopback_is_refused_at_send_time(
    setup: Any, rng: random.Random
) -> None:
    adapter, _group, _client = setup
    assert adapter.facade is not None
    # Listens on 127.0.0.1, so "localhost" would reach it if it were looked up.
    receiver = LoopbackServer(Starlette(routes=[Route("/hook", _record, methods=["POST"])]))
    port = await receiver.start()
    try:
        adapter.facade._app(GID, None)  # the group's stores and sender
        apps = adapter.facade._groups[GID]
        context = ServerCallContext()
        for name, host in (("bad", "localhost"), ("good", "127.0.0.1")):
            config = TaskPushNotificationConfig(
                task_id="t1", id=name, url=f"http://{host}:{port}/hook", token=str(rng.random())
            )
            await apps.push.set_info("t1", config, context)
        task = Task(id="t1", context_id=GID, status=TaskStatus(state=TaskState.TASK_STATE_WORKING))
        RECORDED.clear()
        await apps.sender.send_notification("t1", task)
        assert len(RECORDED) == 1  # the loopback one; the named one was refused
    finally:
        await receiver.stop()


RECORDED: list[bytes] = []


async def _record(request: Request) -> Response:
    RECORDED.append(await request.body())
    return JSONResponse({})


async def test_a_failed_push_logs_no_url(
    setup: Any,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    rng: random.Random,
) -> None:
    # a2a-sdk logs a failed push with its URL (query secrets included) and a
    # traceback; the facade logs its own event with ids only.
    adapter, _group, _client = setup
    assert adapter.facade is not None
    adapter.facade._app(GID, None)
    apps = adapter.facade._groups[GID]
    with socket.socket() as probe:  # a loopback port nothing listens on
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    secret = f"{rng.getrandbits(64):016x}"
    config = TaskPushNotificationConfig(
        task_id="t1", id="cfg", url=f"http://127.0.0.1:{port}/hook?key={secret}"
    )
    await apps.push.set_info("t1", config, ServerCallContext())
    task = Task(id="t1", context_id=GID, status=TaskStatus(state=TaskState.TASK_STATE_WORKING))
    await apps.sender.send_notification("t1", task)
    err = capsys.readouterr().err
    assert secret not in caplog.text
    assert secret not in err
    events = [json.loads(line) for line in err.splitlines() if line.startswith("{")]
    (failed,) = [e for e in events if e["event"] == "a2a_facade_push_failed"]
    assert failed["task"] == "t1"
