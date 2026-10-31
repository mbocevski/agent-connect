"""SPEC §10.3: agent replies carry ``hop``, a member past
``loop_guard.max_agent_turns`` is not triggered, pauses the group and tells
its human, and a human ``control.resume`` resets the counter."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from agentconnect.adapter import Delivery
from agentconnect.runtime.engine import new_msg_id
from agentconnect_harness.cluster import Node

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]


def max_turns(node: Node, gid: str) -> int | None:
    g = node.daemon.store.group(gid)
    return None if g is None else int(g.policy["loop_guard"]["max_agent_turns"])


def last(node: Node, kind: str = "a2a.message") -> Delivery:
    return [d for d in node.adapter.deliveries if d.kind == kind][-1]


async def reply(node: Node, gid: str, to: Delivery | None, text: str) -> None:
    send = node.adapter.send
    assert send is not None
    await send(gid, {"text": text}, reply_to=None if to is None else [to.msg_id])


async def test_replies_carry_hop_and_the_guard_pauses(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    a.daemon.set_policy(gid, loop_guard={"max_agent_turns": 3})
    await a.idle()
    await b.wait(lambda: max_turns(b, gid) == 3)

    # A fresh agent message is one agent turn.
    await reply(a, gid, None, "t1")
    await b.wait_texts(gid, 1)
    assert (last(b).hop, last(b).addressed_to_me) == (1, True)
    # Explicit replies: max(hop of the message replied to) + 1.
    await reply(b, gid, last(b), "t2")
    await a.wait_texts(gid, 1)
    assert last(a).hop == 2
    # Without reply_to, the last message that triggered this instance.
    await reply(a, gid, None, "t3")
    await b.wait_texts(gid, 2)
    assert (last(b).hop, last(b).addressed_to_me) == (3, True)
    await reply(b, gid, last(b), "t4")
    await a.wait_texts(gid, 2)
    # hop 4 > 3: delivered as context only, a pause goes out, the human hears.
    assert (last(a).hop, last(a).addressed_to_me) == (4, False)
    await a.adapter.wait_for(lambda: bool(a.adapter.of_type("loop_guard")))
    (event,) = a.adapter.of_type("loop_guard")
    assert event.data["hop"] == 4
    assert event.data["max_agent_turns"] == 3
    await b.adapter.wait_for(lambda: any(d.kind == "control.pause" for d in b.adapter.deliveries))
    pause = last(b, "control.pause")
    assert pause.body == {"reason": "loop_guard"}
    assert (pause.origin, pause.hop, pause.addressed_to_me) == ("agent", 5, False)
    # Only one pause and one event per episode.
    await reply(b, gid, last(b), "t5")
    await a.wait_texts(gid, 3)
    await a.idle()
    assert len(a.adapter.of_type("loop_guard")) == 1

    # The human resumes: hop 0, and the counter restarts on both sides.
    a.daemon.send_message(gid, {}, kind="control.resume", origin="human")
    await b.adapter.wait_for(lambda: any(d.kind == "control.resume" for d in b.adapter.deliveries))
    assert last(b, "control.resume").hop == 0
    await reply(a, gid, None, "after resume")
    await b.wait_texts(gid, 3)
    assert (last(b).hop, last(b).addressed_to_me) == (1, True)
    await reply(b, gid, None, "b after resume")
    await a.wait_texts(gid, 4)
    # b's last trigger was the resume (hop 0) then a's hop-1 message.
    assert (last(a).hop, last(a).addressed_to_me) == (2, True)
    # A human message is hop 0.
    b.daemon.send_message(gid, {"text": "from b's human"}, origin="human")
    await a.wait_texts(gid, 5)
    assert (last(a).hop, last(a).origin) == (0, "human")


async def test_an_agent_resume_is_ignored(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    a.daemon.set_policy(gid, loop_guard={"max_agent_turns": 0})
    await a.idle()
    await b.wait(lambda: max_turns(b, gid) == 0)
    await reply(a, gid, None, "x")
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("loop_guard")))
    # A peer daemon that claims an agent-originated resume is ignored: b
    # stays paused and nothing reaches its adapter.
    inner = a.daemon.inner("control.resume", {}, ["*"], origin="agent", hop=0)
    a.daemon._enqueue("app", gid, {"inner": inner, "msg_id": new_msg_id()})
    a.daemon.send_message(gid, {"text": "marker"})
    await b.wait_texts(gid, 2)
    assert not [d for d in b.adapter.deliveries if d.kind == "control.resume"]
    assert b.daemon.store.kv_get(f"loop_paused/{gid}") == "1"


async def test_replies_name_what_they_reply_to(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    await reply(a, gid, None, "first")
    await b.wait_texts(gid, 1)
    first = last(b)
    await reply(b, gid, first, "explicit")
    await a.wait_texts(gid, 1)
    assert last(a).inner["reply_to"] == [first.msg_id]
    # Without reply_to, the daemon names the last message that triggered it.
    await reply(a, gid, None, "implicit")
    await b.wait_texts(gid, 2)
    assert last(b).inner["reply_to"] == [last(a).msg_id]


async def test_a_hop_below_the_referenced_messages_is_raised(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    a.daemon.set_policy(gid, loop_guard={"max_agent_turns": 1})
    await a.idle()
    await b.wait(lambda: max_turns(b, gid) == 1)
    # b's agent speaks first (hop 1, below the limit)...
    await reply(b, gid, None, "from b")
    await a.wait_texts(gid, 1)
    from_b = last(a).msg_id
    # ...and a's daemon lies: hop 0 on a reply to b's hop-1 message.
    inner = a.daemon.inner("a2a.message", {"text": "forged"}, ["*"], hop=0, reply_to=[from_b])
    a.daemon._enqueue("app", gid, {"inner": inner, "msg_id": new_msg_id()})
    await b.wait_texts(gid, 1)
    # b knows its own message had hop 1, so this is at least hop 2 > 1.
    assert (last(b).hop, last(b).addressed_to_me) == (2, False)
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("loop_guard")))


async def test_naming_the_humans_message_does_not_reset_the_hop(group: GroupFixture) -> None:
    """SR-33: each human speaks once; then each agent keeps naming the other
    human's message in `reply_to` (hop 0), which would give every reply hop
    1 forever. An agent's hop is at least one more than the last message
    that triggered it, whatever `reply_to` names, so the two still reach
    `max_agent_turns` and the group pauses."""
    (a, b), gid = await group(2)
    a.daemon.set_policy(gid, loop_guard={"max_agent_turns": 3})
    await a.idle()
    await b.wait(lambda: max_turns(b, gid) == 3)
    a.daemon.send_message(gid, {"text": "from a's human"}, origin="human")
    await b.wait_texts(gid, 1)
    human_a = last(b)
    b.daemon.send_message(gid, {"text": "from b's human"}, origin="human")
    await a.wait_texts(gid, 1)
    human_b = last(a)
    assert human_a.hop == human_b.hop == 0
    hops = []
    for turn in range(2):
        await reply(a, gid, human_b, f"a{turn}")
        await b.wait_texts(gid, 2 + turn)
        hops.append(last(b).hop)
        await reply(b, gid, human_a, f"b{turn}")
        await a.wait_texts(gid, 2 + turn)
        hops.append(last(a).hop)
    assert hops == [1, 2, 3, 4]
    await a.adapter.wait_for(lambda: bool(a.adapter.of_type("loop_guard")))
