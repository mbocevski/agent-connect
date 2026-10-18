"""One SDK, two modes (ADR-005): the same script against an embedded
runtime and against a separate daemon (attach) gives the same answers, the
same errors and the same messages."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from agentconnect_harness.cluster import WAIT, Cluster, Node
from agentconnect_harness.headless import headless
from agentconnect_sdk import AgentConnect, AgentConnectError, Group, Message

pytestmark = pytest.mark.hosts("daemon")  # the peer; the modes are the parameter
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


@pytest.mark.parametrize("mode", MODES)
async def test_the_same_script_runs_in_both_modes(  # noqa: PLR0915
    cluster: Cluster, sockdir: Path, mode: str
) -> None:
    peer = await cluster.node("peer")
    async with client(cluster, sockdir, mode) as (ac, node):
        assert ac.mode == mode
        seen: list[Message] = []

        @ac.on_message
        async def handle(msg: Message, group: Group) -> None:
            seen.append(msg)
            if msg.addressed_to_me:
                await group.reply(msg, f"got {msg.raw_text}")

        status = await ac.status()
        assert status["identity"] == node.me
        assert status["held_messages"] == 0
        group = await ac.create_group(purpose="plan the offsite")
        assert repr(group) == f"Group({group.id!r})"
        url = await group.invite(max_uses=2)
        await node.idle()
        before = node.epoch(group.id)
        await peer.daemon.accept_invite(url)
        await peer.wait(lambda: peer.daemon.store.group(group.id) is not None)
        await cluster.settle(group.id, before + 1)

        (listed,) = await ac.groups()
        assert (listed["group_id"], listed["members"]) == (group.id, 2)
        info = await group.info()
        assert {m["identity"] for m in info["members"]} == {node.me, peer.me}
        assert "sas" in info

        peer.daemon.send_message(group.id, {"text": "hello"})
        await peer.adapter.wait_for(lambda: len(peer.adapter.texts(group.id)) == 1, WAIT)
        assert peer.adapter.texts(group.id) == ["got hello"]
        (msg,) = seen
        assert msg.raw_text == "hello"
        assert msg.text.startswith(msg.notice)
        assert msg.text.endswith("hello")
        assert msg.addressed_to_me
        assert msg.sender.identity == peer.me
        (answer,) = [d for d in peer.adapter.deliveries if d.group_id == group.id]
        assert answer.inner["reply_to"] == [msg.msg_id]
        assert answer.hop == msg.hop + 1  # SPEC 10.3

        msg_id = await group.send("to everyone", to=[peer.me])
        await peer.adapter.wait_for(lambda: len(peer.adapter.texts(group.id)) == 2, WAIT)
        assert peer.adapter.deliveries[-1].msg_id == msg_id

        # Errors look the same in both modes.
        with pytest.raises(AgentConnectError) as e:
            await ac.group("no-such-group").info()
        assert (e.value.code, e.value.status) == ("not_found", 404)
        with pytest.raises(AgentConnectError) as e:
            await ac.accept("https://example.org/not-an-invite")
        assert (e.value.code, e.value.status) == ("bad_request", 400)

        # The owner's last instance must hand over before leaving (SPEC 9.2).
        with pytest.raises(AgentConnectError) as e:
            await group.leave()
        assert (e.value.code, e.value.status) == ("forbidden", 403)
        joined = peer.daemon.create_group("Theirs", "")
        await peer.idle()
        invite = await peer.daemon.create_invite(joined)
        assert (await ac.accept(invite["url"], "agent-bot"))["status"]
        await node.wait(lambda: node.daemon.store.group(joined) is not None)
        assert await ac.group(joined).leave() in ("leaving", "left")
