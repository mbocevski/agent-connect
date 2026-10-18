"""The client against a fake daemon (httpx.MockTransport)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

import agentconnect_sdk
from agentconnect_sdk import (
    AgentConnect,
    AgentConnectError,
    Event,
    Group,
    Message,
    SignatureError,
    TaskState,
    sign,
)

Payload = Callable[..., dict[str, Any]]
SRC = Path(agentconnect_sdk.__file__).parent


class FakeDaemon:
    """Records requests and answers from a table of canned replies."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.replies: dict[tuple[str, str], tuple[int, Any]] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, body = self.replies.get(
            (request.method, request.url.path), (404, {"code": "not_found", "message": "no"})
        )
        if isinstance(body, bytes):
            return httpx.Response(status, content=body)
        return httpx.Response(status, json=body)

    def last_body(self) -> dict[str, Any]:
        return json.loads(self.requests[-1].content)


@pytest.fixture
def daemon() -> FakeDaemon:
    return FakeDaemon()


@pytest.fixture
def client(isolated_env: None, data_dir: Path, daemon: FakeDaemon) -> AgentConnect:
    return AgentConnect(data_dir=data_dir, transport=httpx.MockTransport(daemon))


def make_message(make_payload: Payload, **overrides: Any) -> Message:
    parsed = agentconnect_sdk.parse_payload(make_payload(**overrides))
    assert isinstance(parsed, Message)
    return parsed


async def test_requests_carry_only_the_api_token(
    client: AgentConnect, daemon: FakeDaemon, api_token: str, human_token: str
) -> None:
    daemon.replies[("POST", "/v0/groups")] = (200, {"group_id": "g1"})
    daemon.replies[("GET", "/v0/status")] = (200, {"identity": "x"})
    group = await client.create_group(purpose="plan the offsite")
    await client.status()
    assert group.id == "g1"
    assert daemon.requests[0].headers["authorization"] == f"Bearer {api_token}"
    for request in daemon.requests:
        assert human_token not in str(request.headers)
        assert human_token not in request.content.decode()


def test_the_package_never_names_the_human_token() -> None:
    for path in SRC.glob("*.py"):
        assert "human-token" not in path.read_text(), path.name


async def test_create_group_names_it_after_the_purpose(
    client: AgentConnect, daemon: FakeDaemon
) -> None:
    daemon.replies[("POST", "/v0/groups")] = (200, {"group_id": "g1"})
    await client.create_group(purpose="p" * 100)
    assert daemon.last_body() == {"name": "p" * 80, "purpose": "p" * 100}
    await client.create_group(name="Ops", purpose="x")
    assert daemon.last_body()["name"] == "Ops"
    await client.create_group()
    assert daemon.last_body() == {"name": "AgentConnect chat", "purpose": ""}


async def test_invite_and_group_calls(client: AgentConnect, daemon: FakeDaemon) -> None:
    daemon.replies[("POST", "/v0/groups/g1/invites")] = (200, {"url": "https://r/#x"})
    daemon.replies[("GET", "/v0/groups/g1")] = (200, {"group_id": "g1"})
    daemon.replies[("POST", "/v0/groups/g1/leave")] = (200, {"status": "leaving"})
    daemon.replies[("GET", "/v0/groups")] = (200, {"groups": [{"group_id": "g1"}, 5]})
    daemon.replies[("POST", "/v0/invites/accept")] = (200, {"status": "pending"})
    group = client.group("g1")
    assert await group.invite(max_uses=3) == "https://r/#x"
    assert daemon.last_body() == {"max_uses": 3, "ttl_secs": 86_400}
    assert (await group.info())["group_id"] == "g1"
    assert await group.leave() == "leaving"
    assert await client.groups() == [{"group_id": "g1"}]
    assert (await client.accept("https://r/#y", "bot"))["status"] == "pending"
    assert daemon.last_body() == {"url": "https://r/#y", "display_name": "bot"}
    await client.accept("https://r/#y")
    assert daemon.last_body() == {"url": "https://r/#y"}
    assert repr(group) == "Group('g1')"


async def test_send_and_reply_build_a2a_messages(
    client: AgentConnect, daemon: FakeDaemon, make_payload: Payload
) -> None:
    daemon.replies[("POST", "/v0/groups/g1/messages")] = (200, {"msg_id": "m9"})
    group = client.group("g1")
    assert await group.send("hello all") == "m9"
    sent = daemon.last_body()
    assert sent["kind"] == "a2a.message"
    assert sent["to"] == ["*"]
    assert "reply_to" not in sent
    assert sent["body"]["parts"] == [{"text": "hello all"}]
    assert sent["body"]["role"] == "ROLE_AGENT"
    assert sent["body"]["contextId"] == "g1"

    await group.send([{"data": {"k": 1}}], to=["ac:v0:a"], reply_to=["m1"])
    sent = daemon.last_body()
    assert sent["body"]["parts"] == [{"data": {"k": 1}}]
    assert sent["to"] == ["ac:v0:a"]
    assert sent["reply_to"] == ["m1"]

    msg = make_message(make_payload, msg_id="m5")
    await group.reply(msg, "answer")
    sent = daemon.last_body()
    # SPEC 9.3: to the group, addressed to the sender.
    assert (sent["to"], sent["addressee"]) == (["*"], ["ac:v0:peer"])
    assert sent["reply_to"] == ["m5"]
    assert sent["body"]["parts"] == [{"text": "answer"}]


async def test_task_replies(
    client: AgentConnect, daemon: FakeDaemon, make_payload: Payload
) -> None:
    daemon.replies[("POST", "/v0/groups/g1/messages")] = (200, {"msg_id": "m9"})
    group = client.group("g1")
    msg = make_message(make_payload, msg_id="m5", a2a={"taskId": "t1", "parts": []})

    await group.reply_status(msg, TaskState.WORKING, "on it")
    sent = daemon.last_body()
    assert sent["kind"] == "a2a.task_status"
    assert sent["reply_to"] == ["m5"]
    assert (sent["to"], sent["addressee"]) == (["*"], ["ac:v0:peer"])
    assert sent["body"]["taskId"] == "t1"
    assert sent["body"]["status"]["state"] == "TASK_STATE_WORKING"
    assert sent["body"]["status"]["message"]["parts"] == [{"text": "on it"}]

    await group.reply_status(make_message(make_payload), TaskState.COMPLETED, task_id="t2")
    sent = daemon.last_body()
    assert sent["body"]["taskId"] == "t2"
    assert "message" not in sent["body"]["status"]

    await group.reply_status(make_message(make_payload), TaskState.FAILED)
    assert daemon.last_body()["body"]["taskId"] != ""

    await group.reply_artifact(msg, "the plan", name="plan", last_chunk=False, append=True)
    sent = daemon.last_body()
    assert sent["kind"] == "a2a.task_artifact"
    assert sent["body"]["taskId"] == "t1"
    assert sent["body"]["artifact"]["name"] == "plan"
    assert sent["body"]["artifact"]["parts"] == [{"text": "the plan"}]
    assert sent["body"]["append"] is True
    assert sent["body"]["lastChunk"] is False

    await group.reply_artifact(make_message(make_payload), [{"data": 1}], artifact_id="a1")
    assert "name" not in daemon.last_body()["body"]["artifact"]
    assert daemon.last_body()["body"]["artifact"]["artifactId"] == "a1"


async def test_daemon_errors_become_exceptions(client: AgentConnect, daemon: FakeDaemon) -> None:
    daemon.replies[("POST", "/v0/groups/g1/leave")] = (
        403,
        {"code": "human_only", "message": "needs the human token"},
    )
    daemon.replies[("GET", "/v0/status")] = (500, b"not json")
    with pytest.raises(AgentConnectError) as info:
        await client.group("g1").leave()
    assert (info.value.code, info.value.status) == ("human_only", 403)
    with pytest.raises(AgentConnectError) as info:
        await client.status()
    assert info.value.code == "error"


async def test_an_unreachable_daemon_is_not_running(isolated_env: None, data_dir: Path) -> None:
    def refuse(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    async with AgentConnect(data_dir=data_dir, transport=httpx.MockTransport(refuse)) as ac:
        with pytest.raises(AgentConnectError) as info:
            await ac.status()
        assert info.value.code == "not_running"


def test_a_missing_token_means_the_daemon_never_ran(isolated_env: None, tmp_path: Path) -> None:
    with pytest.raises(AgentConnectError) as info:
        AgentConnect(data_dir=tmp_path)
    assert info.value.code == "not_running"


async def test_dispatch_runs_handlers_once_per_id(
    agent: AgentConnect, make_payload: Payload, make_event: Payload
) -> None:
    seen: list[tuple[str, str]] = []

    @agent.on_message
    async def on_message(msg: Message, group: Group) -> None:
        seen.append(("message", msg.msg_id))
        assert group.id == "g1"

    @agent.on_task
    async def on_task(msg: Message, _group: Group) -> None:
        seen.append((msg.event, msg.msg_id))

    @agent.on_event
    async def on_event(event: Event, group: Group | None) -> None:
        seen.append((event.type, event.event_id))
        assert group is None or group.id == "g1"

    first = make_payload(msg_id="m1")
    assert await agent.dispatch(first) == "handled"
    assert await agent.dispatch(first) == "duplicate"
    await agent.dispatch(make_payload(msg_id="m2", event="task_status"))
    await agent.dispatch(make_payload(msg_id="m3", event="agent_card"))
    await agent.dispatch(make_payload(msg_id="m4", event="control.pause"))
    await agent.dispatch(make_event(event_id="e1"))
    await agent.dispatch(make_event(event_id="e1"))
    await agent.dispatch(make_event(event_id="e2", group=None))
    assert seen == [
        ("message", "m1"),
        ("task_status", "m2"),
        ("member_joined", "e1"),
        ("member_joined", "e2"),
    ]


async def test_a_failing_handler_is_run_again_on_redelivery(
    agent: AgentConnect, make_payload: Payload
) -> None:
    calls: list[str] = []

    @agent.on_message
    async def flaky(msg: Message, _group: Group) -> None:
        calls.append(msg.msg_id)
        if len(calls) == 1:
            raise RuntimeError("model call failed")

    payload = make_payload(msg_id="m1")
    with pytest.raises(RuntimeError):
        await agent.dispatch(payload)
    assert await agent.dispatch(payload) == "handled"
    assert await agent.dispatch(payload) == "duplicate"
    assert calls == ["m1", "m1"]


async def test_a_duplicate_while_the_handler_runs_is_busy(
    agent: AgentConnect, make_payload: Payload
) -> None:
    started, release = asyncio.Event(), asyncio.Event()
    calls: list[str] = []

    @agent.on_message
    async def slow(msg: Message, _group: Group) -> None:
        calls.append(msg.msg_id)
        started.set()
        await release.wait()

    payload = make_payload(msg_id="m1")
    running = asyncio.create_task(agent.dispatch(payload))
    await started.wait()
    assert await agent.dispatch(payload) == "busy"
    release.set()
    assert await running == "handled"
    assert calls == ["m1"]


async def test_receive_verifies_before_dispatching(
    agent: AgentConnect, secret: str, make_payload: Payload
) -> None:
    calls: list[str] = []

    @agent.on_message
    async def handle(msg: Message, _group: Group) -> None:
        calls.append(msg.msg_id)

    body = json.dumps(make_payload(msg_id="m1")).encode()
    stamp = str(int(agent._clock()))
    headers = {
        "X-AgentConnect-Timestamp": stamp,
        "X-AgentConnect-Signature": sign(secret, stamp, body),
    }
    assert await agent.receive(headers, body) == "handled"
    with pytest.raises(SignatureError):  # the same request again is a replay
        await agent.receive(headers, body)
    bad = {**headers, "X-AgentConnect-Signature": "v0=" + "0" * 64}
    with pytest.raises(SignatureError):
        await agent.receive(bad, body)
    assert calls == ["m1"]
    list_body = b"[]"
    stamp2 = str(int(agent._clock()) + 1)
    with pytest.raises(ValueError, match="object"):
        await agent.receive(
            {
                "X-AgentConnect-Timestamp": stamp2,
                "X-AgentConnect-Signature": sign(secret, stamp2, list_body),
            },
            list_body,
        )


def sse(*frames: tuple[str, Any]) -> bytes:
    return (
        b"".join(
            f"id: {fid}\nevent: x\ndata: {json.dumps(data)}\n\n".encode() for fid, data in frames
        )
        + b": tail\n\n"
    )


async def test_stream_dispatches_frames_and_tracks_the_resume_point(
    client: AgentConnect, daemon: FakeDaemon, make_payload: Payload
) -> None:
    daemon.replies[("GET", "/v0/events")] = (
        200,
        sse(("1.1", make_payload(msg_id="m1")), ("1.2", make_payload(msg_id="m1")), ("1.3", [])),
    )
    texts: list[str] = []

    @client.on_message
    async def handle(msg: Message, _group: Group) -> None:
        texts.append(msg.msg_id)

    await client.stream("g1")
    assert texts == ["m1"]  # the replayed duplicate was dropped
    assert client.last_event_id == "1.3"
    request = daemon.requests[-1]
    assert request.headers["accept"] == "text/event-stream"
    assert "last-event-id" not in request.headers
    assert request.url.params["group"] == "g1"

    await client.stream()
    assert daemon.requests[-1].headers["last-event-id"] == "1.3"
    assert "group" not in daemon.requests[-1].url.params
    await client.stream(last_event_id="1.1")
    assert daemon.requests[-1].headers["last-event-id"] == "1.1"


async def test_stream_refused_raises_with_the_daemons_code(
    client: AgentConnect, daemon: FakeDaemon
) -> None:
    daemon.replies[("GET", "/v0/events")] = (409, {"code": "no_sse_adapter", "message": "set it"})
    with pytest.raises(AgentConnectError) as info:
        await client.stream()
    assert (info.value.code, info.value.status) == ("no_sse_adapter", 409)


async def test_stream_transport_errors_are_not_running(isolated_env: None, data_dir: Path) -> None:
    def refuse(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    ac = AgentConnect(data_dir=data_dir, transport=httpx.MockTransport(refuse))
    with pytest.raises(AgentConnectError) as info:
        await ac.stream()
    assert info.value.status == 0


class Sleeps:
    """A sleep that records its delays and stops the loop after ``limit``."""

    def __init__(self, limit: int) -> None:
        self.delays: list[float] = []
        self.limit = limit

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)
        if len(self.delays) >= self.limit:
            raise asyncio.CancelledError


async def test_serve_sse_reconnects_with_backoff_and_resumes(
    isolated_env: None, data_dir: Path, daemon: FakeDaemon, make_payload: Payload
) -> None:
    sleeps = Sleeps(limit=4)
    ac = AgentConnect(data_dir=data_dir, transport=httpx.MockTransport(daemon), sleep=sleeps)
    ready = asyncio.Event()
    daemon.replies[("GET", "/v0/events")] = (200, sse(("1.1", make_payload(msg_id="m1"))))
    calls: list[str] = []

    @ac.on_message
    async def boom(msg: Message, _group: Group) -> None:
        calls.append(msg.msg_id)
        raise RuntimeError("handler failed")

    with pytest.raises(asyncio.CancelledError):
        await ac.serve("sse", ready=ready)
    assert ready.is_set()
    # The failing message is redelivered after each backoff, not skipped.
    assert calls == ["m1"] * 4
    assert sleeps.delays == [2.0, 4.0, 8.0, 16.0]
    assert all("last-event-id" not in r.headers for r in daemon.requests)


async def test_serve_sse_resets_the_delay_after_progress(
    isolated_env: None, data_dir: Path, daemon: FakeDaemon, make_payload: Payload
) -> None:
    sleeps = Sleeps(limit=2)
    ac = AgentConnect(data_dir=data_dir, transport=httpx.MockTransport(daemon), sleep=sleeps)
    daemon.replies[("GET", "/v0/events")] = (200, sse(("1.1", make_payload(msg_id="m1"))))
    with pytest.raises(asyncio.CancelledError):
        await ac.serve("sse")
    assert ac.last_event_id == "1.1"
    assert sleeps.delays == [2.0, 4.0]
    assert daemon.requests[-1].headers["last-event-id"] == "1.1"


async def test_serve_sse_gives_up_on_a_refusal(client: AgentConnect, daemon: FakeDaemon) -> None:
    daemon.replies[("GET", "/v0/events")] = (401, {"code": "auth_failed", "message": "no"})
    with pytest.raises(AgentConnectError):
        await client.serve("sse")


async def test_serve_sse_survives_a_dropped_connection(isolated_env: None, data_dir: Path) -> None:
    sleeps = Sleeps(limit=2)

    def refuse(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    ac = AgentConnect(data_dir=data_dir, transport=httpx.MockTransport(refuse), sleep=sleeps)
    with pytest.raises(asyncio.CancelledError):
        await ac.serve("sse")
    assert sleeps.delays == [2.0, 4.0]


async def test_serve_picks_webhook_when_the_daemon_has_a_callback(
    isolated_env: None, data_dir: Path, tmp_path: Path
) -> None:
    config = tmp_path / "config.toml"
    config.write_text('[webhook]\ncallback_url = "http://127.0.0.1:0/"\n[api]\ntcp_port = 0\n')
    ac = AgentConnect(data_dir=data_dir, config_path=config)
    ready = asyncio.Event()
    task = asyncio.create_task(ac.serve(ready=ready))
    await ready.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_a_webhook_receiver_needs_a_port(agent: AgentConnect) -> None:
    with pytest.raises(AgentConnectError) as info:
        agent.webhook_receiver()
    assert info.value.code == "bad_config"


async def test_a_peer_chosen_msg_id_never_shadows_an_event_or_another_sender(
    agent: AgentConnect, make_payload: Payload, make_event: Payload
) -> None:
    """SPEC 8.3: senders choose their own msg_ids. A peer that sends a
    message whose msg_id equals the event_id of an event its commit will
    cause must not suppress that event, nor another sender's message."""
    seen: list[str] = []

    @agent.on_message
    async def on_message(msg: Message, _group: Group) -> None:
        seen.append(f"message from {msg.sender.identity}")

    @agent.on_event
    async def on_event(event: Event, _group: Group | None) -> None:
        seen.append(f"event {event.type}")

    other = {
        "identity": "ac:v0:other",
        "instance_id": "i2",
        "display_name": None,
        "verified": False,
    }
    assert await agent.dispatch(make_payload(msg_id="X")) == "handled"
    assert await agent.dispatch(make_event(event_id="X", event="member_joined")) == "handled"
    assert await agent.dispatch(make_payload(msg_id="X", sender=other)) == "handled"
    assert (
        await agent.dispatch(
            make_payload(msg_id="X", group={**make_payload()["group"], "id": "g2"})
        )
        == "handled"
    )
    assert await agent.dispatch(make_payload(msg_id="X")) == "duplicate"
    assert seen == [
        "message from ac:v0:peer",
        "event member_joined",
        "message from ac:v0:other",
        "message from ac:v0:peer",
    ]
