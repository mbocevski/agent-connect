"""The A2A facade without a daemon: a fake group sender, and replies handed
to the adapter as deliveries that name the facade's message in
``reply_to``."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import random
import shutil
import socket
import stat
import tempfile
from collections.abc import AsyncIterator, Iterator
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
from agentconnect.isolation import PeerCred
from agentconnect.runtime.engine import DaemonError

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
