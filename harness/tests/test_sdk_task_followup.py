"""An SDK agent answers a peer agent's task, in both SDK modes: a reply to a
task status or artifact update continues that task (A2A: the follow-up
carries its ``taskId`` and ``contextId``), so an A2A agent's
``input-required`` gets its answer; a reply to a plain message names no
task."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from agentconnect_harness.a2a_agents import AgentServer, ScriptedExecutor, a2a_node
from agentconnect_harness.cluster import WAIT, Cluster, Node
from agentconnect_harness.headless import headless
from agentconnect_sdk import AgentConnect, AgentConnectError, Group, Message, TaskState

pytestmark = pytest.mark.hosts("daemon")  # the peers; the SDK modes are the parameter
MODES = ("embedded", "attach")


@asynccontextmanager
async def client(
    cluster: Cluster, sockdir: Path, mode: str
) -> AsyncGenerator[tuple[AgentConnect, Node]]:
    """``mode``'s SDK client for a fresh agent, delivering to handlers."""
    if mode == "embedded":
        node = await cluster.node("agent", host="embedded")
        assert node.sdk is not None
        yield node.sdk, node
        return
    attached = await headless(cluster, "agent", sockdir, mode="sse")
    serving = asyncio.ensure_future(attached.sdk.serve("sse"))
    try:
        yield attached.sdk, attached.node
    finally:
        serving.cancel()
        await attached.close()


async def until(predicate: Callable[[], bool]) -> None:
    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing announces it
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


@pytest.mark.parametrize("mode", MODES)
async def test_a_reply_to_input_required_continues_the_a2a_task(
    cluster: Cluster, sockdir: Path, mode: str
) -> None:
    executor = ScriptedExecutor()
    agent = AgentServer(executor, "asker")
    await agent.start()
    try:
        a = await a2a_node(cluster, "a", agent)
        gid = a.daemon.create_group("Pair", "Answer a task")
        await a.idle()
        async with client(cluster, sockdir, mode) as (ac, node):
            states: list[str] = []

            @ac.on_task
            async def answer(msg: Message, group: Group) -> None:
                state = str((msg.a2a.get("status") or {}).get("state", ""))
                states.append(state)
                if msg.addressed_to_me and state == TaskState.INPUT_REQUIRED:
                    await group.reply(msg, "the blue one")

            await cluster.invite(a, node, gid)
            await ac.group(gid).send("ask me")
            first, follow_up = await executor.wait_for(2)
            assert not first.continued
            assert follow_up.continued
            assert (follow_up.task_id, follow_up.context_id) == (first.task_id, gid)
            await until(lambda: TaskState.COMPLETED in states)
            assert states.index(TaskState.INPUT_REQUIRED) < states.index(TaskState.COMPLETED)
    finally:
        await agent.stop()


@pytest.mark.parametrize("mode", MODES)
async def test_which_replies_name_a_task(cluster: Cluster, sockdir: Path, mode: str) -> None:
    """A reply to an artifact update names its task; a reply to a plain
    message names none; ``send(task_id=)`` names the one given. Only an
    update answering the agent's own request triggers it (SPEC 9.3): a
    stray one is context, and the agent doesn't answer it."""
    peer = await cluster.node("peer")
    gid = peer.daemon.create_group("Pair", "Answer a task")
    await peer.idle()
    async with client(cluster, sockdir, mode) as (ac, node):

        @ac.on_message
        async def on_message(msg: Message, group: Group) -> None:
            if msg.addressed_to_me:
                await group.reply(msg, f"re {msg.raw_text}")

        @ac.on_task
        async def on_task(msg: Message, group: Group) -> None:
            if msg.addressed_to_me:
                await group.reply(msg, "re artifact")

        await cluster.invite(peer, node, gid)
        request = await ac.group(gid).send("run task-1", to=[peer.me])
        await peer.adapter.wait_for(lambda: len(peer.adapter.texts(gid)) == 1, WAIT)
        peer.daemon.send_message(gid, {"text": "plain"})

        def artifact(task: str) -> dict[str, Any]:
            return {
                "taskId": task,
                "contextId": gid,
                "artifact": {"artifactId": "a1", "parts": [{"text": "result"}]},
            }

        # (Sent as the human: an agent's send would reply to the request.)
        stray = peer.daemon.send_message(
            gid, artifact("task-0"), kind="a2a.task_artifact", origin="human"
        )
        peer.daemon.send_message(
            gid, artifact("task-1"), kind="a2a.task_artifact", reply_to=[request]
        )
        await peer.adapter.wait_for(lambda: len(peer.adapter.texts(gid)) == 3, WAIT)
        await node.wait(lambda: node.daemon.store.inbox_state(peer.daemon.mailbox, stray) == "done")
        bodies = {
            d.body["parts"][0]["text"]: d.body
            for d in peer.adapter.deliveries
            if d.kind != "control.capabilities"
        }
        assert "taskId" not in bodies["re plain"]
        assert bodies["re plain"]["contextId"] == gid
        assert (bodies["re artifact"]["taskId"], bodies["re artifact"]["contextId"]) == (
            "task-1",
            gid,
        )

        await ac.group(gid).send("more", task_id="task-1")
        await peer.adapter.wait_for(lambda: len(peer.adapter.texts(gid)) == 4, WAIT)
        assert peer.adapter.texts(gid).count("re artifact") == 1, "the stray one is context"
        assert peer.adapter.deliveries[-1].body["taskId"] == "task-1"
        with pytest.raises(AgentConnectError) as refused:
            await ac.group(gid).send("more", task_id="")
        assert refused.value.code == "bad_request"
