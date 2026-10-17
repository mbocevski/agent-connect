"""The A2A adapter in a group of three: mention mode triggers only the
addressed agent, the rest arrives as context with its next call, and an
identity's replicas are all triggered (SPEC §9.3, §9.4)."""

from __future__ import annotations

from typing import Any

from a2a.types import Message, Part, Role

from agentconnect.a2a_adapter import convert
from agentconnect_harness.a2a_agents import (
    AgentServer,
    HelloWorldExecutor,
    ScriptedExecutor,
    a2a_node,
)
from agentconnect_harness.cluster import WAIT, Cluster, Node


def body(text: str, **metadata: Any) -> dict[str, Any]:
    msg = Message(role=Role.ROLE_USER, message_id=f"m-{text}", parts=[Part(text=text)])
    if metadata:
        msg.metadata.update(metadata)
    return convert.to_json(msg)


def sender(node: Node) -> Any:
    send = node.adapter.send
    assert send is not None
    return send


async def test_mention_mode_triggers_only_the_addressed_agent(cluster: Cluster) -> None:
    eb, ec = ScriptedExecutor(), HelloWorldExecutor()
    agent_b, agent_c = AgentServer(eb, "bee"), AgentServer(ec, "sea")
    await agent_b.start()
    await agent_c.start()
    try:
        a = await cluster.node("a")
        b = await a2a_node(cluster, "b", agent_b)
        c = await a2a_node(cluster, "c", agent_c)
        gid = a.daemon.create_group("Trio", "Three agents")
        await a.idle()
        await cluster.invite(a, b, gid)
        await cluster.invite(a, c, gid)
        group = a.daemon.store.group(gid)
        assert group is not None
        assert group.policy["floor"] == "mention"  # SPEC 9.1: switched at three

        send = sender(a)
        await send(gid, body("echo one"), to=[b.me])
        await eb.wait_for(1)
        await send(gid, body("for c only"), to=[c.me])
        await ec.wait_for(1)
        # An agent broadcast in mention mode triggers nobody.
        await send(gid, body("everyone, as context"))
        await send(gid, body("echo three"), to=[b.me])
        seen_b = await eb.wait_for(2)
        assert [r.message.parts[-1].text for r in seen_b] == ["echo one", "echo three"]
        assert [r.message.parts[-1].text for r in ec.received] == ["for c only"]
        # What b wasn't triggered by came with its next call, as context.
        meta = convert.to_json(seen_b[1].message)["metadata"]
        context = [m["parts"][-1].get("text") for m in meta["context_messages"]]
        assert "for c only" in context
        assert "everyone, as context" in context
        assert all(m["sender"] in (a.me, c.me) for m in meta["context_messages"])
        assert "context_messages" not in convert.to_json(seen_b[0].message)["metadata"]
        # Replies to an addressed message go to the requester only.
        await a.adapter.wait_for(
            lambda: any(
                d.sender.identity == c.me and d.kind == "a2a.message" for d in a.adapter.deliveries
            ),
            WAIT,
        )
        reply = next(
            d for d in a.adapter.deliveries if d.sender.identity == c.me and d.kind == "a2a.message"
        )
        assert reply.to == [a.me]
        assert reply.addressed_to_me
    finally:
        await agent_b.stop()
        await agent_c.stop()


async def test_replicas_are_all_triggered_unless_one_is_named(cluster: Cluster) -> None:
    e1, e2 = HelloWorldExecutor(), HelloWorldExecutor()
    r1, r2 = AgentServer(e1, "replica"), AgentServer(e2, "replica")
    await r1.start()
    await r2.start()
    try:
        a = await cluster.node("a")
        b1 = await a2a_node(cluster, "b1", r1)
        gid = a.daemon.create_group("Replicas", "One agent, two instances")
        await a.idle()
        await cluster.invite(a, b1, gid)
        b2 = await a2a_node(cluster, "b2", r2, identity_of=b1)
        await cluster.invite(a, b2, gid)
        assert b1.me == b2.me

        send = sender(a)
        await send(gid, body("both of you"), to=[b1.me])
        await e1.wait_for(1)
        await e2.wait_for(1)
        # metadata.instance narrows it to one instance (SPEC 9.4).
        instance = b2.daemon.instance.instance_id_hex
        await send(gid, body("just b2", instance=instance), to=[b1.me])
        await e2.wait_for(2)
        await send(gid, body("both again"), to=[b1.me])
        await e1.wait_for(2)
        assert [r.message.parts[-1].text for r in e1.received] == ["both of you", "both again"]
    finally:
        await r1.stop()
        await r2.stop()
