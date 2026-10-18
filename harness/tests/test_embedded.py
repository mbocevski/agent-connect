"""The embedded host (ADR-005): ``AgentConnect.embedded`` runs the runtime in
the agent's process, on the agent's loop, with in-process delivery.

What only this host has: the human runs the CLI against the embedded
instance's socket, agent code has no way to the human operations, the data
directory is locked against a daemon and a second embedded agent, start,
serve and shutdown are cancellation-safe, and a restart hands nothing to
user code twice. Every other scenario in the harness runs on this host too
(the ``cluster`` fixture)."""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, override

import httpx
import pytest
from typer.testing import CliRunner

from agentconnect import daemon as daemon_host
from agentconnect.adapter import OutboundSend, RecordingAdapter
from agentconnect.cli import app
from agentconnect.failpoints import SimulatedCrash
from agentconnect.keystore import DataDirLock
from agentconnect.keystore import DataDirLockedError as RuntimeLockedError
from agentconnect.runtime import AgentApi, ApiError, Runtime
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE, TokenDigest
from agentconnect_harness.cluster import WAIT, Cluster, Node
from agentconnect_harness.proxy import RelayProxy
from agentconnect_sdk import (
    AgentConnect,
    AgentConnectError,
    DataDirLockedError,
    Event,
    Group,
    Message,
)
from agentconnect_sdk.embedded import EmbeddedHost

pytestmark = pytest.mark.hosts("daemon")  # the peers; the agent here is always embedded

runner = CliRunner()
GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
# Substrings no agent-facing name may contain (SPEC 6.2, 10.4, 11).
HUMAN_ONLY = ("approve", "reject", "verif", "mismatch", "remove", "audit", "transcript", "human")
HUMAN_ROUTES = (
    ("POST", "/v0/approvals/r1/approve"),
    ("POST", "/v0/approvals/r1/reject"),
    ("POST", "/v0/approvals/messages/h1/approve"),
    ("POST", "/v0/approvals/messages/h1/reject"),
    ("POST", "/v0/groups/{gid}/members/{peer}/verify"),
    ("POST", "/v0/groups/{gid}/members/{peer}/remove"),
    ("POST", "/v0/groups/{gid}/safety"),
    ("POST", "/v0/groups/{gid}/sas/mismatch"),
    ("GET", "/v0/audit"),
    ("GET", "/v0/groups/{gid}/transcript"),
)


def cli(data_dir: Path, *args: str, input: str | None = None) -> tuple[int, str]:
    """``AC_DATA_DIR=<data_dir> agentconnect ...``, as the docs tell the human."""
    env = {"AC_DATA_DIR": str(data_dir), "AC_CONFIG": str(data_dir / "no-config.toml")}
    result = runner.invoke(app, list(args), input=input, env=env)
    if result.exception and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result.exit_code, result.stdout


async def embedded(cluster: Cluster, name: str, sockdir: Path, **kw: Any) -> Node:
    """An embedded agent that serves its local API in its data directory, as
    ``AgentConnect.embedded`` does (the socket path must be short)."""
    return await cluster.node(name, host="embedded", serve_api=True, data_dir=sockdir / name, **kw)


def sdk_of(node: Node) -> AgentConnect:
    assert node.sdk is not None
    return node.sdk


async def test_the_human_runs_the_cli_against_an_embedded_agent(
    cluster: Cluster, sockdir: Path
) -> None:
    agent = await embedded(cluster, "agent", sockdir, auto_approve=False)
    peer = await cluster.node("peer")
    sdk = sdk_of(agent)
    group = await sdk.create_group(purpose="plan the offsite")
    url = await group.invite()
    await agent.idle()
    before = agent.epoch(group.id)
    await peer.daemon.accept_invite(url)
    await agent.wait(lambda: len(agent.daemon.approvals()) == 1)
    # The agent hears nothing of the join request...
    assert (await agent.runtime.agent.approvals())["approvals"] == []
    # ...and the human approves it from a terminal.
    code, out = await asyncio.to_thread(cli, agent.config.data_dir, "approvals", "--json")
    assert code == 0, out
    (request,) = json.loads(out)["approvals"]
    code, out = await asyncio.to_thread(
        cli, agent.config.data_dir, "approvals", "approve", request["request_id"], "--yes"
    )
    assert code == 0, out
    await peer.wait(lambda: peer.daemon.store.group(group.id) is not None)
    await cluster.settle(group.id, before + 1)

    # The human compares the short code and confirms.
    code, out = await asyncio.to_thread(cli, agent.config.data_dir, "verify", group.id, input="y\n")
    assert code == 0, out
    members = {m.identity: m for m in agent.daemon.store.members(group.id)}
    assert members[peer.me].verified

    # The human changes the group's safety policy.
    code, out = await asyncio.to_thread(
        cli, agent.config.data_dir, "safety", "set", group.id, "sender_per_minute=5", "--json"
    )
    assert code == 0, out
    assert json.loads(out)["overrides"]["sender_per_minute"] == 5

    # A peer's message reaches the agent's handler in-process, framed.
    peer.daemon.send_message(group.id, {"text": "when is it?"})
    await agent.wait(lambda: any(isinstance(m, Message) for m in agent.handled))
    (msg,) = [m for m in agent.handled if isinstance(m, Message)]
    assert msg.raw_text == "when is it?"
    assert msg.text.startswith("Message from remote agent")
    assert msg.text.endswith("when is it?")
    assert msg.sender.identity == peer.me
    assert msg.sender.verified  # the human verified the peer above


async def test_agent_code_has_no_way_to_the_human_operations(
    cluster: Cluster, sockdir: Path
) -> None:
    agent = await embedded(cluster, "agent", sockdir)
    peer = await cluster.node("peer")
    gid = agent.daemon.create_group("Ops", "deploys")
    await agent.idle()
    await cluster.invite(agent, peer, gid)

    # No SDK or runtime surface names a human operation.
    for surface in (AgentConnect, Group, AgentApi, EmbeddedHost, Runtime):
        public = [n for n, _ in inspect.getmembers(surface) if not n.startswith("_")]
        assert not [n for n in public if any(w in n for w in HUMAN_ONLY)], surface

    # The agent-scope operations refuse what only the human may do.
    with pytest.raises(ApiError, match="human token"):
        await agent.runtime.agent.set_policy(gid, require_verified=False)
    with pytest.raises(ApiError, match="human token"):
        await agent.runtime.agent.send(gid, {}, kind="control.resume")

    # The agent token is refused on every human route of the embedded socket.
    data_dir = agent.config.data_dir
    token = (data_dir / API_TOKEN_FILE).read_text(encoding="ascii").strip()
    transport = httpx.AsyncHTTPTransport(uds=str(agent.runtime.api_address))
    async with httpx.AsyncClient(transport=transport, base_url="http://ac") as http:
        for method, path in HUMAN_ROUTES:
            url = path.format(gid=gid, peer=peer.me)
            resp = await http.request(
                method, url, json={"set": {}}, headers={"authorization": f"Bearer {token}"}
            )
            assert (resp.status_code, resp.json()["code"]) == (403, "human_only"), url
        resp = await http.post(
            f"/v0/groups/{gid}/policy",
            json={"require_verified": False},
            headers={"authorization": f"Bearer {token}"},
        )
        assert resp.json()["code"] == "human_only"

    # The runtime holds the human token's hash only, never its value.
    human = (data_dir / HUMAN_TOKEN_FILE).read_text(encoding="ascii").strip()
    server = agent.runtime._api
    assert server is not None
    held = [*vars(server).values(), *vars(agent.runtime).values()]
    assert human not in repr(held)
    assert all(isinstance(d, TokenDigest) for d in server._tokens.values())
    assert human not in repr(server._tokens)


async def test_one_runtime_per_data_directory(cluster: Cluster) -> None:
    daemon = await cluster.node("d")
    # An embedded agent can't take a running daemon's directory.
    second = AgentConnect.embedded(data_dir=daemon.config.data_dir, relay=daemon.config.relay_url)
    with pytest.raises(DataDirLockedError, match=r"a daemon, pid \d+"):
        await second.start()
    await second.aclose()
    assert daemon.daemon.running

    # Nor a second embedded agent an embedded one's.
    first = await cluster.node("e", host="embedded")
    again = AgentConnect.embedded(data_dir=first.config.data_dir, relay=first.config.relay_url)
    with pytest.raises(DataDirLockedError, match=r"an embedded agent, pid \d+") as e:
        await again.start()
    assert e.value.code == "locked"
    assert "another name or data_dir" in e.value.message

    # And a daemon can't start on an embedded agent's directory.
    with pytest.raises(RuntimeLockedError, match="an embedded agent"):
        await daemon_host.serve(first.config)
    assert first.daemon.running


class Blocker(RecordingAdapter):
    """An adapter whose start never finishes, to cancel a runtime mid-start."""

    def __init__(self) -> None:
        super().__init__("blocker")
        self.entered = asyncio.Event()

    @override
    async def on_outbound(self, send: OutboundSend) -> None:
        self.entered.set()
        await asyncio.Event().wait()


async def test_cancelling_during_startup_releases_everything(cluster: Cluster) -> None:
    seed = await cluster.node("seed")
    config = seed.config.with_overrides(data_dir=cluster.tmp / "starting")
    blocker = Blocker()
    host = EmbeddedHost(
        config, extra_adapters=[blocker], clock=cluster.clock, serve_api=False, flush=0
    )
    sdk = AgentConnect.hosted(host)
    starting = asyncio.ensure_future(sdk.start())
    await asyncio.wait_for(blocker.entered.wait(), WAIT)
    starting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await starting
    assert host.runtime is None
    DataDirLock(config.data_dir).release()  # the lock was released
    with pytest.raises(AgentConnectError, match="isn't running"):
        await sdk.status()
    await sdk.aclose()  # nothing left to close


async def test_cancelling_serve_pauses_and_the_context_stops(cluster: Cluster) -> None:
    peer = await cluster.node("peer")
    agent = await cluster.node("agent", host="embedded")
    gid = peer.daemon.create_group("Ops", "")
    await peer.idle()
    await cluster.invite(peer, agent, gid)
    sdk = sdk_of(agent)
    # Cancelling serve() stops deliveries, not the runtime.
    await agent._stop_serving()
    peer.daemon.send_message(gid, {"text": "while paused"})
    await agent.wait(lambda: agent.daemon.status()["inbox_pending"] == 1)
    assert not [m for m in agent.handled if isinstance(m, Message)]
    assert (await sdk.status())["relay"]["connected"]
    ready = asyncio.Event()
    serving = asyncio.ensure_future(sdk.serve(ready=ready))
    await agent.wait(lambda: any(isinstance(m, Message) for m in agent.handled))
    serving.cancel()
    with pytest.raises(asyncio.CancelledError):
        await serving

    # Cancelling the task that runs `async with ... serve()` stops the runtime.
    config = agent.config
    await sdk.aclose()
    host = EmbeddedHost(config, clock=cluster.clock, serve_api=False, flush=0)
    entered = asyncio.Event()

    async def run() -> None:
        async with AgentConnect.hosted(host) as ac:
            entered.set()
            await ac.serve()

    task = asyncio.ensure_future(run())
    await asyncio.wait_for(entered.wait(), WAIT)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert host.runtime is None
    DataDirLock(config.data_dir).release()


async def test_cancelling_during_shutdown_still_releases_the_lock(
    cluster: Cluster, malicious_relay: Callable[[Node], RelayProxy]
) -> None:
    peer = await cluster.node("peer")
    agent = await cluster.node("agent", host="embedded")
    gid = peer.daemon.create_group("Ops", "")
    await peer.idle()
    await cluster.invite(peer, agent, gid)
    sdk = sdk_of(agent)
    # The relay never sees the agent's sends, so stop()'s flush has to wait.
    malicious_relay(agent).client_filters.append(lambda f: [] if f.get("t") == "send" else [f])
    await sdk.group(gid).send("stuck")
    assert agent.daemon.store.outbox()
    host = sdk._host
    assert host is not None
    host._flush = WAIT
    closing = asyncio.ensure_future(sdk.aclose())
    for _ in range(20):
        await asyncio.sleep(0)
    assert not closing.done()
    closing.cancel()
    with pytest.raises(asyncio.CancelledError):
        await closing
    assert not agent.daemon.running
    DataDirLock(agent.config.data_dir).release()
    # The unsent message waits in the encrypted outbox for the next start.
    malicious_relay(agent).client_filters.clear()
    await agent.start()
    await peer.wait_texts(gid, 1)


async def pair(cluster: Cluster) -> tuple[Node, Node, str]:
    """A peer ``a`` and an embedded agent ``b`` in one group."""
    a = await cluster.node("a")
    gid = a.daemon.create_group("Ops", "")
    await a.idle()
    b = await cluster.node("b", host="embedded")
    await cluster.invite(a, b, gid)
    return a, b, gid


async def test_a_restart_hands_nothing_to_user_code_twice(cluster: Cluster) -> None:
    a, b, gid = await pair(cluster)

    # A crash after the handler ran but before the inbox recorded it: the
    # runtime hands the message over again, the SDK doesn't run the handler.
    b.daemon.failpoints.arm("delivery.after_adapter", "crash")
    msg_id = a.daemon.send_message(gid, {"text": "once"})
    await b.adapter.wait_for(lambda: len(b.adapter.deliveries) == 1, WAIT)
    await b.restart()
    await b.adapter.wait_for(lambda: len(b.adapter.deliveries) == 2, WAIT)
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 0)
    handled = [m for m in b.handled if isinstance(m, Message)]
    assert [m.msg_id for m in handled] == [msg_id]

    # A crash after the adapter heard of an event, before it was marked:
    # the event is sent again after the restart, the handler sees it once.
    b.daemon.failpoints.arm("event.after_notify", "crash")
    a.daemon.update(gid)
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("epoch_changed")), WAIT)
    (first,) = b.adapter.of_type("epoch_changed")
    await b.restart()
    await b.adapter.wait_for(
        lambda: len([e for e in b.adapter.events if e.event_id == first.event_id]) == 2, WAIT
    )
    await b.wait(lambda: any(getattr(e, "event_id", None) == first.event_id for e in b.handled))
    for _ in range(20):
        await asyncio.sleep(0)
    seen = [e for e in b.handled if isinstance(e, Event) and e.event_id == first.event_id]
    assert len(seen) == 1

    # While b is down, a's messages wait at the relay; b gets them on start.
    await b.stop()
    later = a.daemon.send_message(gid, {"text": "while you were away"})
    await a.idle()
    await b.start()
    await b.wait(lambda: any(getattr(m, "msg_id", None) == later for m in b.handled))
    texts = [m.raw_text for m in b.handled if isinstance(m, Message)]
    assert texts == ["once", "while you were away"]


async def test_a_failing_handler_is_retried_like_a_failing_webhook(
    cluster: Cluster, capfd: pytest.CaptureFixture[str]
) -> None:
    a, b, gid = await pair(cluster)
    sdk = sdk_of(b)
    calls: list[str] = []

    @sdk.on_message
    async def flaky(msg: Message, _group: Group) -> None:
        calls.append(msg.raw_text)
        if len(calls) == 1:
            raise RuntimeError(msg.raw_text)  # the body must not reach the log

    a.daemon.send_message(gid, {"text": "secret plans"})
    a.daemon.send_message(gid, {"text": "second"})
    await b.wait(lambda: len(calls) == 1 and b.clock.sleepers > 0)
    # The runtime keeps running, and nothing later is handed over before the
    # failed message (order), until the backoff ends.
    assert b.daemon.running
    assert calls == ["secret plans"]
    await cluster.advance(300)
    await b.wait(lambda: len(calls) == 3)
    assert calls == ["secret plans", "secret plans", "second"]
    logs = capfd.readouterr().err
    assert '"callback_failed"' in logs
    assert "RuntimeError" in logs
    assert "secret plans" not in logs


async def test_engine_crashes_propagate_out_of_the_embedded_host(cluster: Cluster) -> None:
    """A SimulatedCrash is a BaseException: the host never swallows one."""
    node = await cluster.node("n", host="embedded")
    node.daemon.failpoints.arm("event.after_record", "crash")
    with pytest.raises(SimulatedCrash):
        await node.daemon.emit(None, "custom")
