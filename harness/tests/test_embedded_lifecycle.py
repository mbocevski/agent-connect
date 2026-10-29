"""The embedded host's lifecycle against the real relay: shutting down from
inside a handler, handlers that finish during the stop flush, stuck
handlers, concurrent start and stop, and data directories whose socket
path is longer than the platform allows."""

from __future__ import annotations

import asyncio
import contextlib
import gc
import json
import logging
from collections.abc import Callable
from pathlib import Path

import pytest

from agentconnect.keystore import DataDirLock
from agentconnect.runtime import STOP_FLUSH_SECS
from agentconnect.sockets import MAX_SOCKET_PATH
from agentconnect_harness.cli import run_cli
from agentconnect_harness.cluster import WAIT, Cluster, Node
from agentconnect_sdk import AgentConnect, Group, Message
from agentconnect_sdk.embedded import EmbeddedHost

pytestmark = pytest.mark.hosts("daemon")  # the peers; the agent here is always embedded


async def pair(cluster: Cluster) -> tuple[Node, Node, str]:
    a = await cluster.node("a")
    gid = a.daemon.create_group("Ops", "")
    await a.idle()
    b = await cluster.node("b", host="embedded")
    await cluster.invite(a, b, gid)
    return a, b, gid


async def until(predicate: Callable[[], bool]) -> None:
    """Yield to the loop until ``predicate`` holds (for handler state, which
    no runtime event announces)."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing to wait on
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


def sdk_of(node: Node) -> AgentConnect:
    assert node.sdk is not None
    return node.sdk


def released(data_dir: Path) -> bool:
    try:
        DataDirLock(data_dir).release()
    except RuntimeError:
        return False
    return True


async def test_aclose_from_inside_a_handler_shuts_down_cleanly(
    cluster: Cluster, caplog: pytest.LogCaptureFixture
) -> None:
    a, b, gid = await pair(cluster)
    sdk = sdk_of(b)
    host = sdk._host
    assert host is not None
    host._flush = STOP_FLUSH_SECS
    outcome: list[str] = []

    @sdk.on_message
    async def quit_(msg: Message, group: Group) -> None:
        await group.reply(msg, "bye")
        await sdk.aclose()  # returns once the shutdown is scheduled
        outcome.append("returned")

    msg_id = a.daemon.send_message(gid, {"text": "quit"})
    serving = b._serving
    assert serving is not None
    await asyncio.wait_for(serving, WAIT)  # serve() returns once fully stopped
    assert outcome == ["returned"]
    assert not b.daemon.running
    assert released(b.config.data_dir)
    # The reply went out before the runtime stopped.
    await a.adapter.wait_for(lambda: a.adapter.texts(gid) == ["bye"], WAIT)
    gc.collect()
    problems = [r for r in caplog.records if r.name == "asyncio" and r.levelno >= logging.ERROR]
    assert problems == []
    # The handler's message was recorded as handled: a restart doesn't run it again.
    b._serving = None
    await b.start()
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 0)
    runs = [m for m in b.handled if isinstance(m, Message) and m.msg_id == msg_id]
    assert len(runs) == 1


async def test_aclose_from_an_event_handler(cluster: Cluster) -> None:
    a, b, gid = await pair(cluster)
    sdk = sdk_of(b)
    seen: list[str] = []

    @sdk.on_event
    async def on_change(event: object, _group: object) -> None:
        seen.append("event")
        await sdk.aclose()

    a.daemon.update(gid)
    serving = b._serving
    assert serving is not None
    await asyncio.wait_for(serving, WAIT)
    assert seen
    assert released(b.config.data_dir)
    b._serving = None


async def test_a_handler_finishing_during_the_stop_flush_runs_once(cluster: Cluster) -> None:
    a, b, gid = await pair(cluster)
    sdk = sdk_of(b)
    host = sdk._host
    assert host is not None
    host._flush = STOP_FLUSH_SECS
    calls: list[str] = []
    entered = asyncio.Event()
    gate = asyncio.Event()

    @sdk.on_message
    async def slow(msg: Message, group: Group) -> None:
        calls.append(msg.msg_id)
        entered.set()
        await gate.wait()
        await group.reply(msg, "done")  # a reply from inside the window

    msg_id = a.daemon.send_message(gid, {"text": "side effect"})
    await asyncio.wait_for(entered.wait(), WAIT)
    closing = asyncio.ensure_future(sdk.aclose())
    for _ in range(20):
        await asyncio.sleep(0)
    assert not closing.done()  # waiting for the handler
    gate.set()
    await asyncio.wait_for(closing, WAIT)
    assert released(b.config.data_dir)
    await a.adapter.wait_for(lambda: a.adapter.texts(gid) == ["done"], WAIT)
    b._serving = None
    await b.start()
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 0)
    for _ in range(20):
        await asyncio.sleep(0)
    assert calls == [msg_id]


async def test_a_stuck_handler_holds_up_its_group_only(cluster: Cluster) -> None:
    a, b, g1 = await pair(cluster)
    g2 = a.daemon.create_group("Other", "")
    await a.idle()
    await cluster.invite(a, b, g2)
    sdk = sdk_of(b)
    calls: list[tuple[str, str]] = []
    never = asyncio.Event()

    @sdk.on_message
    async def handle(msg: Message, group: Group) -> None:
        calls.append((group.id, msg.raw_text))
        if group.id == g1 and len([c for c in calls if c[0] == g1]) == 1:
            await never.wait()  # stuck, until the handler timeout

    a.daemon.send_message(g1, {"text": "stuck"})
    await until(lambda: (g1, "stuck") in calls)  # a handler's state: nothing pulses
    a.daemon.send_message(g1, {"text": "after, same group"})
    a.daemon.send_message(g2, {"text": "other group"})
    await until(lambda: (g2, "other group") in calls)
    assert (g1, "after, same group") not in calls  # strict order within a group
    # Past the handler timeout the stuck call is cancelled and retried.
    await cluster.advance(b.config.sdk_handler_timeout + 1)
    await until(lambda: b.clock.sleepers > 0 and calls.count((g1, "stuck")) == 1)
    await cluster.advance(300)
    await until(lambda: (g1, "after, same group") in calls)
    g1_calls = [t for g, t in calls if g == g1]
    assert g1_calls == ["stuck", "stuck", "after, same group"]


async def test_concurrent_start_and_stop_share_one_runtime(cluster: Cluster) -> None:
    seed = await cluster.node("seed")
    config = seed.config.with_overrides(data_dir=cluster.tmp / "both")
    host = EmbeddedHost(config, clock=cluster.clock, flush=0)
    sdk = AgentConnect.hosted(host)
    await asyncio.gather(sdk.start(), sdk.start())
    runtime = host.runtime
    assert runtime is not None
    assert runtime.running
    await asyncio.gather(sdk.aclose(), sdk.aclose())
    assert host.runtime is None
    assert released(config.data_dir)


async def test_a_data_dir_too_long_for_a_socket_path(cluster: Cluster) -> None:
    seed = await cluster.node("seed")
    deep = cluster.tmp / ("d" * 60) / ("e" * 60)
    assert len(str(deep / "agentconnectd.sock")) > MAX_SOCKET_PATH
    config = seed.config.with_overrides(data_dir=deep)
    host = EmbeddedHost(config, clock=cluster.clock, flush=0)
    sdk = AgentConnect.hosted(host)
    await sdk.start()
    try:
        runtime = host.runtime
        assert runtime is not None
        bound = Path(str(runtime.api_address))
        assert len(str(bound)) <= MAX_SOCKET_PATH
        assert (bound.parent.stat().st_mode & 0o777) == 0o700
        # The CLI finds the socket from the data directory alone.
        env = {"AC_DATA_DIR": str(deep), "AC_CONFIG": "/dev/null"}
        result = await asyncio.to_thread(run_cli, ["status", "--json"], env=env)
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["identity"] == runtime.status()["identity"]
    finally:
        await sdk.aclose()
    assert not await asyncio.to_thread(bound.exists)


async def test_the_cli_ignores_the_daemons_config_with_ac_config_dev_null(
    cluster: Cluster, sockdir: Path
) -> None:
    agent = await cluster.node("agent", host="embedded", serve_api=True, data_dir=sockdir / "x")
    home = sockdir / "cfg"
    (home / "agentconnect").mkdir(parents=True)
    (home / "agentconnect" / "config.toml").write_text("[api]\ntcp_port = 1\n", encoding="utf-8")
    base = {"AC_DATA_DIR": str(agent.config.data_dir), "XDG_CONFIG_HOME": str(home)}
    # The daemon's config points the CLI at its TCP port...
    wrong = await asyncio.to_thread(run_cli, ["status", "--json"], env=base)
    assert wrong.exit_code != 0
    # ...and AC_CONFIG=/dev/null, as docs/sdk.md says, reaches the embedded agent.
    env = {**base, "AC_CONFIG": "/dev/null"}
    right = await asyncio.to_thread(run_cli, ["status", "--json"], env=env)
    assert right.exit_code == 0, right.output


async def test_cancelling_aclose_while_a_handler_runs_still_stops_everything(
    cluster: Cluster,
) -> None:
    """A second Ctrl-C during shutdown, while a handler is mid-call: the
    runtime still stops and the lock is released, and a second caller of
    aclose() waits for the same shutdown without a cancellation of its own."""
    a, b, gid = await pair(cluster)
    sdk = sdk_of(b)
    host = sdk._host
    assert host is not None
    host._flush = STOP_FLUSH_SECS
    entered = asyncio.Event()

    @sdk.on_message
    async def slow(msg: Message, group: Group) -> None:
        entered.set()
        await asyncio.Event().wait()  # a model call that doesn't come back

    a.daemon.send_message(gid, {"text": "x"})
    await asyncio.wait_for(entered.wait(), WAIT)
    first = asyncio.ensure_future(sdk.aclose())
    second = asyncio.ensure_future(sdk.aclose())
    for _ in range(20):
        await asyncio.sleep(0)
    assert not first.done()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    await asyncio.wait_for(second, WAIT)  # no CancelledError: it didn't ask for one
    assert not b.daemon.running
    assert host.runtime is None
    assert released(b.config.data_dir)
    b._serving = None


async def two_groups(cluster: Cluster, handler_secs: int = 120) -> tuple[Node, Node, str, str]:
    a = await cluster.node("a")
    g1 = a.daemon.create_group("G1", "")
    g2 = a.daemon.create_group("G2", "")
    await a.idle()
    b = await cluster.node("b", host="embedded", sdk_handler_timeout=handler_secs)
    await cluster.invite(a, b, g1)
    await cluster.invite(a, b, g2)
    return a, b, g1, g2


async def test_a_handler_raising_cancelled_error_is_a_failure_not_the_end(
    cluster: Cluster, capfd: pytest.CaptureFixture[str]
) -> None:
    a, b, g1, g2 = await two_groups(cluster)
    sdk = sdk_of(b)
    seen: list[str] = []

    @sdk.on_message
    async def handle(msg: Message, _group: Group) -> None:
        seen.append(msg.raw_text)
        if msg.raw_text == "boom" and seen.count("boom") == 1:
            fut = asyncio.get_running_loop().create_future()
            fut.cancel()
            await fut  # a shared task something else cancelled

    a.daemon.send_message(g1, {"text": "boom"})
    await until(lambda: "boom" in seen)
    a.daemon.send_message(g2, {"text": "other group"})
    await until(lambda: "other group" in seen)  # delivery goes on elsewhere
    await b.wait(lambda: b.clock.sleepers > 0)  # g1 backs off, then retries
    await cluster.advance(300)
    await until(lambda: seen.count("boom") == 2)
    logs = capfd.readouterr().err
    assert "HandlerCancelledError" in logs


async def test_a_handler_ignoring_cancellation_is_abandoned_after_the_timeout(
    cluster: Cluster, capfd: pytest.CaptureFixture[str]
) -> None:
    a, b, g1, _ = await two_groups(cluster, handler_secs=10)
    sdk = sdk_of(b)
    seen: list[str] = []
    release = asyncio.Event()

    @sdk.on_message
    async def handle(msg: Message, _group: Group) -> None:
        seen.append(msg.raw_text)
        if msg.raw_text == "stubborn" and seen.count("stubborn") == 1:
            while not release.is_set():
                with contextlib.suppress(asyncio.CancelledError):  # ignores the timeout's
                    await release.wait()

    a.daemon.send_message(g1, {"text": "stubborn"})
    a.daemon.send_message(g1, {"text": "next"})
    await until(lambda: "stubborn" in seen)
    for _ in range(10):
        await asyncio.sleep(0)
    await cluster.advance(11)  # the timeout: cancelled, but it goes on
    for _ in range(10):
        await asyncio.sleep(0)
    await cluster.advance(10)  # the grace ends: abandoned, the claim released
    await b.wait(lambda: b.clock.sleepers > 0)
    await cluster.advance(300)  # the group's backoff: redelivered, not "busy"
    await until(lambda: seen == ["stubborn", "stubborn", "next"])
    assert "handler_ignored_cancel" in capfd.readouterr().err
    release.set()
    for _ in range(10):
        await asyncio.sleep(0)


async def test_a_stray_cancelled_error_restarts_a_supervised_worker(
    cluster: Cluster, capfd: pytest.CaptureFixture[str]
) -> None:
    node = await cluster.node("n")
    calls: list[int] = []

    async def worker() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise asyncio.CancelledError  # not a cancellation of the worker
        await asyncio.Event().wait()

    probe = asyncio.ensure_future(node.daemon._supervised("probe", worker))
    await node.wait(lambda: node.clock.sleepers > 0)
    await cluster.advance(120)
    await until(lambda: len(calls) == 2)
    probe.cancel()
    with pytest.raises(asyncio.CancelledError):
        await probe  # its own cancellation still ends it
    assert '"reason": "CancelledError"' in capfd.readouterr().err
