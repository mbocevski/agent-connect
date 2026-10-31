"""The instance hint between real daemons (SPEC 9.4, harness scenario 10,
docs/groups.md#addressing-one-instance): every instance of a member gets
every message once; ``instance`` narrows who is triggered to one instance,
and only narrows it: a hint that names no instance the floor triggers, a
malformed one, one naming another identity's instance or a moderated
group's non-holder triggers nobody, and the loop guard still holds."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.adapter import Delivery
from agentconnect.runtime.engine import DaemonError, new_msg_id
from agentconnect_harness.a2a_agents import AgentServer, HelloWorldExecutor, a2a_node
from agentconnect_harness.cluster import WAIT, Cluster, Node, converged
from agentconnect_sdk import AgentConnectError, Message

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]


async def until(predicate: Callable[[], bool]) -> None:
    """Poll (yielding to the loop) until ``predicate`` holds: what it reads
    (an adapter's recording, an SDK handler's list) has no change pulse."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing to wait on
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


def inst(node: Node) -> str:
    return node.daemon.instance.instance_id_hex


async def send(  # noqa: PLR0913
    node: Node,
    gid: str,
    text: str,
    *,
    to: list[str] | None = None,
    instance: str | None = None,
    reply_to: list[str] | None = None,
) -> str:
    """The node's agent sends ``text`` (``AgentApi.send``)."""
    answer = await node.runtime.agent.send(
        gid, text=text, to=to or ["*"], instance=instance, reply_to=reply_to
    )
    assert answer["status"] == "queued"
    return str(answer["msg_id"])


def got(node: Node, msg_id: str) -> Delivery | None:
    return next((d for d in node.adapter.deliveries if d.msg_id == msg_id), None)


def answering(node: Node, msg_id: str) -> Delivery | None:
    """The delivery that replies to ``msg_id``."""
    return next((d for d in node.adapter.deliveries if d.inner.get("reply_to") == [msg_id]), None)


def the(node: Node, msg_id: str) -> Delivery:
    d = got(node, msg_id)
    assert d is not None, (node.name, msg_id)
    return d


async def heard(nodes: list[Node], msg_id: str) -> dict[str, bool]:
    """Wait until every node has ``msg_id``; whether it triggered each one."""
    for n in nodes:
        await until(lambda n=n: got(n, msg_id) is not None)
    return {n.name: bool(d.addressed_to_me) for n in nodes if (d := got(n, msg_id)) is not None}


def from_(node: Node, sender: Node) -> list[str]:
    return [
        d.msg_id
        for d in node.adapter.deliveries
        if d.kind == "a2a.message" and d.sender.identity == sender.me
    ]


async def replicas(cluster: Cluster, *others: str, owner: Node | None = None) -> tuple[Any, ...]:
    """``a`` (or ``owner``), the nodes ``others``, then x1 and its replica x2."""
    a = owner or await cluster.node("a")
    gid = a.daemon.create_group("Replicas", "One agent, two instances")
    await a.idle()
    extra = []
    for name in others:
        n = await cluster.node(name)
        await cluster.invite(a, n, gid)
        extra.append(n)
    x1 = await cluster.node("x1")
    await cluster.invite(a, x1, gid)
    x2 = await cluster.node("x2", identity_of=x1)
    await cluster.invite(a, x2, gid)
    assert x1.me == x2.me
    assert inst(x1) != inst(x2)
    return (a, *extra, x1, x2, gid)


# -- scenario 10 --------------------------------------------------------------------------------


async def test_two_instance_agent_gets_each_message_once_per_instance(cluster: Cluster) -> None:
    executor = HelloWorldExecutor()
    agent = AgentServer(executor, "hello")
    await agent.start()
    try:
        a = await a2a_node(cluster, "a", agent)
        a, x1, x2, gid = await replicas(cluster, owner=a)
        # Two identities: the floor stays free (SPEC 9.1 counts identities).
        assert x1.daemon.store.group(gid).policy["floor"] == "free"

        sent = [await send(a, gid, f"m{i}", to=[x1.me]) for i in range(4)]
        await until(lambda: len(from_(x2, a)) == 4)
        await x2.wait(lambda: x2.daemon.status()["inbox_pending"] == 0)
        # x2 goes down mid-stream; what is sent meanwhile waits at the relay.
        await x2.stop()
        await asyncio.wait_for(x2.proxy.wait_no_sessions(), WAIT)
        sent += [await send(a, gid, f"m{i}", to=[x1.me]) for i in range(4, 7)]
        await a.idle()
        await x2.start()
        sent += [await send(a, gid, f"m{i}", to=[x1.me]) for i in range(7, 10)]
        for x in (x1, x2):
            await until(lambda x=x: len(from_(x, a)) >= 10)
            await x.wait(lambda x=x: x.daemon.status()["inbox_pending"] == 0)
            # Each instance gets each message once, in order, and is triggered.
            assert from_(x, a) == sent
            assert all(the(x, m).addressed_to_me for m in sent)
            if x.host == "embedded":
                handled = [m.msg_id for m in x.handled if isinstance(m, Message)]
                assert [m for m in handled if m in sent] == sent

        # With `instance`, only x1 is triggered; x2 gets it as context.
        hinted = await send(a, gid, "just x1", to=[x1.me], instance=inst(x1))
        assert await heard([x1, x2], hinted) == {"x1": True, "x2": False}
        assert the(x2, hinted).body["metadata"]["instance"] == inst(x1)

        # A task reply from a's A2A adapter goes to the instance that asked.
        ask = await send(x1, gid, "hello a", to=[a.me])
        await executor.wait_for(1)

        await until(lambda: answering(x1, ask) is not None)
        answer = answering(x1, ask)
        assert answer is not None
        assert answer.inner["addressee"] == [x1.me]
        assert answer.body["metadata"]["instance"] == inst(x1)
        assert await heard([x1, x2], answer.msg_id) == {"x1": True, "x2": False}
    finally:
        await agent.stop()


@pytest.mark.hosts("embedded")
async def test_an_sdk_reply_triggers_only_the_instance_that_asked(cluster: Cluster) -> None:
    a, x1, x2, gid = await replicas(cluster)
    ask = await send(x2, gid, "ping", to=[a.me])
    await until(lambda: any(isinstance(m, Message) and m.msg_id == ask for m in a.handled))
    (msg,) = [m for m in a.handled if isinstance(m, Message) and m.msg_id == ask]
    assert msg.sender.instance_id == inst(x2)
    assert a.sdk is not None
    group = a.sdk.group(gid)
    for answer in (
        await group.reply(msg, "pong"),
        await group.reply_status(msg, "TASK_STATE_INPUT_REQUIRED", "which one?"),
    ):
        assert await heard([x1, x2], answer) == {"x1": False, "x2": True}
    # Progress on the task is context for both (SPEC 9.3); its end triggers
    # the instance that asked only.
    progress = await group.reply_artifact(msg, "result")
    assert await heard([x1, x2], progress) == {"x1": False, "x2": False}
    done = await group.reply_status(msg, "TASK_STATE_COMPLETED")
    assert await heard([x1, x2], done) == {"x1": False, "x2": True}
    # Group.send takes the hint too, and refuses a malformed one.
    direct = await group.send("to x1", to=[x1.me], instance=inst(x1))
    assert await heard([x1, x2], direct) == {"x1": True, "x2": False}
    with pytest.raises(AgentConnectError) as e:
        await group.send("bad", to=[x1.me], instance="XYZ")
    assert (e.value.code, e.value.status) == ("bad_request", 400)


# -- a hint only narrows ------------------------------------------------------------------------


async def test_a_hint_naming_no_instance_of_the_recipients_triggers_nobody(
    cluster: Cluster, rng: random.Random
) -> None:
    a, b, x1, x2, gid = await replicas(cluster, "b")
    group = a.daemon.store.group(gid)
    assert group is not None
    assert group.policy["floor"] == "mention"  # three identities
    everyone = [b, x1, x2]

    # An instance id nobody in the group has: sent anyway, triggers nobody.
    unknown = f"{rng.getrandbits(64):016x}"
    assert unknown not in (inst(a), inst(b), inst(x1), inst(x2))
    msg = await send(a, gid, "nobody has it", to=[x1.me], instance=unknown)
    assert await heard(everyone, msg) == {"b": False, "x1": False, "x2": False}

    # Another identity's instance: b isn't in `to`, so b isn't triggered either.
    msg = await send(a, gid, "b's instance", to=[x1.me], instance=inst(b))
    assert await heard(everyone, msg) == {"b": False, "x1": False, "x2": False}

    # A human broadcast with b's instance triggers b alone.
    body = {"messageId": new_msg_id(), "role": "ROLE_USER", "parts": [{"text": "to all"}]}
    msg, status = a.daemon.queue_message(gid, body, origin="human", instance=inst(b))
    assert status == "queued"
    assert await heard(everyone, msg) == {"b": True, "x1": False, "x2": False}

    # An instance that left: the hint now names nobody.
    gone = inst(x2)
    x1.daemon.remove_instances(gid, x1.me, [gone])
    await converged([a, b, x1], gid)
    msg = await send(a, gid, "x2 has gone", to=[x1.me], instance=gone)
    assert await heard([b, x1], msg) == {"b": False, "x1": False}
    # Without the hint x1 is triggered as usual.
    msg = await send(a, gid, "plain", to=[x1.me])
    assert await heard([b, x1], msg) == {"b": False, "x1": True}


async def test_a_malformed_hint_is_refused_and_a_peers_one_triggers_nobody(
    cluster: Cluster,
) -> None:
    a, x1, x2, gid = await replicas(cluster)
    for bad in ("XYZ", "A" + inst(x1)[1:], inst(x1)[:15], inst(x1) + "0", x1.me):
        with pytest.raises(DaemonError) as e:
            await send(a, gid, "bad", to=[x1.me], instance=bad)
        assert e.value.code == "bad_request"
        body = {"messageId": new_msg_id(), "role": "ROLE_USER", "parts": [{"text": "bad"}]}
        with pytest.raises(DaemonError):
            a.daemon.queue_message(gid, body, origin="human", instance=bad)
    # Controls never trigger, so a hint on one is refused too.
    with pytest.raises(DaemonError) as e:
        await a.runtime.agent.send(
            gid, {"reason": "human"}, kind="control.pause", instance=inst(x1)
        )
    assert e.value.code == "bad_request"
    await a.idle()
    assert not a.daemon.store.outbox()

    # A modified daemon skips the check: the receivers treat the peer's hint
    # as untrusted, and a value that names no instance triggers nobody.
    for bad in ("XYZ", 7, [inst(x1)], {"id": inst(x1)}, "A" + inst(x1)[1:]):
        body = {"messageId": new_msg_id(), "parts": [{"text": "forged"}], "metadata": {}}
        body["metadata"]["instance"] = bad
        inner = a.daemon.inner("a2a.message", body, [x1.me], origin="agent", hop=1)
        msg = new_msg_id()
        a.daemon._enqueue("app", gid, {"inner": inner, "msg_id": msg})
        assert await heard([x1, x2], msg) == {"x1": False, "x2": False}


async def test_in_a_moderated_group_a_hint_narrows_within_the_moderator_and_the_holder(
    cluster: Cluster,
) -> None:
    a, b, x1, x2, gid = await replicas(cluster, "b")
    nodes = [a, b, x1, x2]
    assert a.daemon.change_policy(gid, {"floor": "moderated"}) == "committing"
    await converged(nodes, gid)
    a.daemon.grant_floor(gid, x1.me, origin="human")
    await a.wait(lambda: all(n.daemon.group_info(gid)["floor"]["holder"] == x1.me for n in nodes))

    # Without a hint: the moderator (the owner) and both holder instances.
    msg = await send(b, gid, "plain")
    assert await heard([a, x1, x2], msg) == {"a": True, "x1": True, "x2": True}
    # A hint naming a non-holder triggers nobody, b included.
    msg = await send(a, gid, "for b", to=[b.me], instance=inst(b))
    assert await heard([b, x1, x2], msg) == {"b": False, "x1": False, "x2": False}
    msg = await send(x1, gid, "for b too", to=[b.me], instance=inst(b))
    assert await heard([a, b, x2], msg) == {"a": False, "b": False, "x2": False}
    # A hint naming one holder instance: only it; the moderator is left out.
    msg = await send(b, gid, "x1 only", instance=inst(x1))
    assert await heard([a, x1, x2], msg) == {"a": False, "x1": True, "x2": False}
    # A hint naming the moderator's instance: only the moderator.
    msg = await send(b, gid, "a only", instance=inst(a))
    assert await heard([a, x1, x2], msg) == {"a": True, "x1": False, "x2": False}


async def test_the_loop_guard_holds_for_hinted_replies(cluster: Cluster) -> None:
    a, x1, x2, gid = await replicas(cluster)
    nodes = [a, x1, x2]
    a.daemon.set_policy(gid, loop_guard={"max_agent_turns": 3})
    await converged(nodes, gid)

    # a and x1 answer each other, each reply naming the other's instance.
    m1 = await send(a, gid, "t1", to=[x1.me], instance=inst(x1))
    assert await heard([x1, x2], m1) == {"x1": True, "x2": False}
    m2 = await send(x1, gid, "t2", to=[a.me], instance=inst(a), reply_to=[m1])
    assert await heard([a], m2) == {"a": True}
    m3 = await send(a, gid, "t3", to=[x1.me], instance=inst(x1), reply_to=[m2])
    assert await heard([x1, x2], m3) == {"x1": True, "x2": False}
    assert (the(x1, m3).hop, the(x2, m3).hop) == (3, 3)
    # hop 4 > 3: the hint names a, and a is still not triggered (SPEC 10.3).
    m4 = await send(x1, gid, "t4", to=[a.me], instance=inst(a), reply_to=[m3])
    assert await heard([a], m4) == {"a": False}
    assert the(a, m4).hop == 4
    await a.adapter.wait_for(lambda: bool(a.adapter.of_type("loop_guard")), WAIT)
    (event,) = a.adapter.of_type("loop_guard")
    assert (event.data["hop"], event.data["max_agent_turns"]) == (4, 3)
    # x2 decides on the hop alone too, though the hint left it out anyway.
    await x2.adapter.wait_for(lambda: bool(x2.adapter.of_type("loop_guard")), WAIT)
    # x2 was never triggered by the hinted exchange, so its own count is
    # untouched: its next agent message is a fresh turn.
    fresh = await send(x2, gid, "fresh", to=[a.me])
    await until(lambda: got(a, fresh) is not None)
    assert the(a, fresh).hop == 1


async def test_free_mode_doesnt_trigger_an_instance_on_its_siblings_messages(
    cluster: Cluster,
) -> None:
    """SR-35: SPEC 9.3 triggers "all members except the sender" in `free`
    mode, and a member is an identity: a replica's own broadcast doesn't
    trigger its sibling, which gets it as context. Addressed to its own
    identity on purpose, it does."""
    a, x1, x2, gid = await replicas(cluster)
    assert x1.daemon.store.group(gid).policy["floor"] == "free"
    said = await send(x1, gid, "thinking aloud")
    assert await heard([a, x2], said) == {"a": True, "x2": False}
    asked = await x1.runtime.agent.send(gid, text="over to you", addressee=[x1.me])
    assert await heard([x2], str(asked["msg_id"])) == {"x2": True}


async def test_moderated_mode_doesnt_trigger_an_instance_on_its_siblings_messages(
    cluster: Cluster,
) -> None:
    """SR-35, moderated: when the effective moderator (or the floor holder)
    has replicas, one replica's broadcast doesn't trigger its sibling, so
    the two can't ping-pong until the loop guard stops them."""
    a, x1, x2, gid = await replicas(cluster)
    a.daemon.change_policy(gid, {"floor": "moderated", "floor_moderator": x1.me})
    await until(
        lambda: all(
            n.daemon.store.group(gid).policy.get("floor") == "moderated"
            and n.daemon.store.group(gid).policy.get("floor_moderator") == x1.me
            for n in (x1, x2)
        )
    )
    said = await send(x1, gid, "the moderator's replica thinks aloud")
    assert await heard([a, x2], said) == {"a": False, "x2": False}
    # So x2 has nothing that triggered it to answer: no ping-pong.
    assert not x2.adapter.of_type("loop_guard")
