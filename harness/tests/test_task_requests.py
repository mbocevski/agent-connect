"""What a request grants (SPEC 9.3, 10.2), from the adversarial review of
the SR-12 fix: one task per member it asked, while that task is active and
for at most a capped lifetime; the trigger goes to the adapter that asked;
the A2A facade takes answers only from the members it asked; a follow-up
on a task asks only the member running it; an agent's task update without
``reply_to`` answers the request whose task it is; and a follow-up after
the peer's restart continues its task."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, override

import httpx
import pytest
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import Message, Part, Role, SendMessageRequest

from agentconnect.a2a_adapter import convert
from agentconnect.adapter import Delivery, RecordingAdapter
from agentconnect.runtime.engine import new_msg_id
from agentconnect_harness.a2a_agents import AgentServer, ScriptedExecutor, a2a_node, a2a_of
from agentconnect_harness.cluster import WAIT, Cluster, Node

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]


def raw_send(node: Node, gid: str, kind: str, body: dict[str, Any], **fields: Any) -> str:
    """Queue an inner message past the sender's own checks."""
    inner = node.daemon.inner(kind, body, ["*"]) | fields
    msg_id = new_msg_id()
    node.daemon._enqueue("app", gid, {"inner": inner, "msg_id": msg_id})
    return msg_id


def update(node: Node, gid: str, task: str, to: Node, refs: list[str]) -> str:
    body = {"taskId": task, "contextId": gid, "status": {"state": "TASK_STATE_WORKING"}}
    return raw_send(node, gid, "a2a.task_status", body, addressee=[to.me], reply_to=refs)


async def handled(receiver: Node, sender: Node, msg_id: str) -> str | None:
    await sender.idle()
    mailbox = sender.daemon.mailbox
    await receiver.wait(lambda: receiver.daemon.store.inbox_state(mailbox, msg_id) is not None)
    await receiver.wait(lambda: receiver.daemon.status()["inbox_pending"] == 0)
    return receiver.daemon.store.inbox_state(mailbox, msg_id)


def delivered(adapter: RecordingAdapter, msg_id: str) -> Delivery:
    (d,) = [d for d in adapter.deliveries if d.msg_id == msg_id]
    return d


async def triggers(receiver: Node, sender: Node, msg_id: str) -> bool:
    assert await handled(receiver, sender, msg_id) == "done"
    return delivered(receiver.adapter, msg_id).addressed_to_me


# -- F1: a request grants one task per member, while it is active ----------------------


async def test_an_answer_grants_one_task_to_the_member_it_answers(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    hello = a.daemon.send_message(gid, {"text": "hi"})
    assert await handled(b, a, hello) == "done"
    # b's agent answers as SDK `reply` does: that asks a.
    answer = b.daemon.send_message(
        gid, {"parts": [{"text": "hello"}]}, reply_to=[hello], addressee=[a.me]
    )
    assert await handled(a, b, answer) == "done"
    assert await triggers(b, a, update(a, gid, "t0", b, [answer]))
    # Another task against the same request is context: one task per member.
    for task in ("t1", "t2"):
        assert not await triggers(b, a, update(a, gid, task, b, [answer]))
    assert await triggers(b, a, update(a, gid, "t0", b, [answer]))


async def test_a_request_unanswered_for_its_window_grants_nothing(
    group: GroupFixture, advance: Advance
) -> None:
    (a, b), gid = await group(2)
    request = b.daemon.send_message(gid, {"text": "please"}, to=[a.me])
    assert await handled(a, b, request) == "done"
    await advance(601)  # task_request_window_secs: 600 by default
    assert not await triggers(b, a, update(a, gid, "t1", b, [request]))


async def test_each_update_renews_the_task_until_the_cap(
    group: GroupFixture, advance: Advance
) -> None:
    (a, b), gid = await group(2)
    b.daemon.update_safety(gid, {"task_request_max_secs": 3600})
    request = b.daemon.send_message(gid, {"text": "please"}, to=[a.me])
    assert await handled(a, b, request) == "done"
    assert await triggers(b, a, update(a, gid, "t1", b, [request]))
    # Every update renews the window (600 s), so a quiet gap shorter than it
    # never ends the task...
    for _ in range(6):
        await advance(500)
        assert await triggers(b, a, update(a, gid, "t1", b, [request]))
    # ...but a request lives at most task_request_max_secs (here an hour):
    # a longer task needs a new request.
    await advance(700)
    assert not await triggers(b, a, update(a, gid, "t1", b, [request]))
    # And a gap longer than the window ends it too.
    again = b.daemon.send_message(gid, {"text": "again"}, to=[a.me])
    assert await handled(a, b, again) == "done"
    assert await triggers(b, a, update(a, gid, "t2", b, [again]))
    await advance(601)
    assert not await triggers(b, a, update(a, gid, "t2", b, [again]))


async def test_the_task_is_bound_to_the_instance_that_opened_it(cluster: Cluster) -> None:
    """Replicas of the asked member can't open a task each, or answer for
    the instance running it."""
    a = await cluster.node("a")
    gid = a.daemon.create_group("Replicas", "One agent, two instances")
    await a.idle()
    x1 = await cluster.node("x1")
    await cluster.invite(a, x1, gid)
    x2 = await cluster.node("x2", identity_of=x1)
    await cluster.invite(a, x2, gid)
    request = a.daemon.send_message(gid, {"text": "please"}, to=[x1.me])
    assert await handled(x1, a, request) == "done"
    assert await triggers(a, x1, update(x1, gid, "t1", a, [request]))
    assert not await triggers(a, x2, update(x2, gid, "t1", a, [request]))
    assert not await triggers(a, x2, update(x2, gid, "t2", a, [request]))


async def test_a_held_request_counts_from_when_it_is_sent(
    group: GroupFixture, advance: Advance
) -> None:
    """A request held for the human's approval starts its window when the
    human lets it go, not when the agent queued it."""
    (a, b), gid = await group(2)
    b.daemon.update_safety(gid, {"require_approval": "outbound"})
    request = b.daemon.send_message(gid, {"text": "please"}, to=[a.me])
    await advance(900)
    (held,) = b.daemon.held_messages()
    b.daemon.approve_message(held["hold_id"])
    assert await handled(a, b, request) == "done"
    assert await triggers(b, a, update(a, gid, "t1", b, [request]))


# -- F2: the adapter that asked is the one triggered -----------------------------------


class Second(RecordingAdapter):
    pass


@pytest.mark.hosts("daemon")
async def test_the_adapter_whose_request_granted_the_update_is_triggered(
    cluster: Cluster,
) -> None:
    second = Second("second")
    a = await cluster.node(
        "a", adapters=("recording", "second"), make_adapters=lambda _c, _k: [second]
    )
    b = await cluster.node("b")
    c = await cluster.node("c")
    gid = a.daemon.create_group("Team", "two agents on one instance")
    await a.idle()
    await cluster.invite(a, b, gid)
    await cluster.invite(a, c, gid)
    assert a.adapter.send is not None
    assert second.send is not None
    to_c = str(await a.adapter.send(gid, {"text": "for c"}, to=[c.me]))
    to_b = str(await second.send(gid, {"text": "for b"}, to=[b.me]))
    assert await handled(b, a, to_c) == "done"
    assert await handled(b, a, to_b) == "done"
    # b names the first agent's message (which asked c) before the second
    # agent's request: the second agent, which asked b, is triggered.
    forged = update(b, gid, "t1", a, [to_c, to_b])
    assert await handled(a, b, forged) == "done"
    await second.wait_for(lambda: any(d.msg_id == forged for d in second.deliveries), WAIT)
    assert not delivered(a.adapter, forged).addressed_to_me
    assert delivered(second, forged).addressed_to_me


# -- F3: a follow-up after the peer's restart continues its task -----------------------


def a2a_body(text: str, gid: str, task_id: str = "") -> dict[str, Any]:
    msg = Message(role=Role.ROLE_USER, message_id=f"m-{text}", parts=[Part(text=text)])
    msg.context_id = gid
    if task_id:
        msg.task_id = task_id
    return convert.to_json(msg)


async def test_a_follow_up_after_the_peer_restarted_continues_its_task(
    cluster: Cluster,
) -> None:
    agent = AgentServer(ScriptedExecutor(), "asker")
    await agent.start()
    try:
        a = await cluster.node("a")
        b = await a2a_node(cluster, "b", agent)
        b.events_may_fail = True  # the card fetch can take more loop turns
        gid = a.daemon.create_group("Pair", "Exercise the A2A adapter")
        await a.idle()
        await cluster.invite(a, b, gid)
        send = a.adapter.send
        assert send is not None
        await send(gid, a2a_body("ask me", gid))

        def states(state: str) -> list[Delivery]:
            return [
                d
                for d in a.adapter.deliveries
                if d.kind == "a2a.task_status"
                and d.sender.identity == b.me
                and d.body["status"]["state"] == state
            ]

        await a.adapter.wait_for(lambda: bool(states("TASK_STATE_INPUT_REQUIRED")), WAIT)
        first = states("TASK_STATE_INPUT_REQUIRED")[0]
        assert first.addressed_to_me
        # b's daemon restarts; its adapter's task map is in its database.
        await b.restart()
        task = first.body["taskId"]
        follow_up = str(await send(gid, a2a_body("the blue one", gid, task)))
        await a.adapter.wait_for(lambda: bool(states("TASK_STATE_COMPLETED")), WAIT)
        done = states("TASK_STATE_COMPLETED")[0]
        assert done.body["taskId"] == task
        assert done.inner["reply_to"] == [follow_up]
        assert done.addressed_to_me
    finally:
        await agent.stop()


# -- F4: the facade takes answers only from the members it asked -----------------------


class Silent(AgentExecutor):
    """Never answers until released."""

    def __init__(self) -> None:
        self.release = asyncio.Event()

    @override
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        await self.release.wait()

    @override
    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        return None


async def test_a_member_facade_ignores_another_members_answer(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor = Silent()
    agent = AgentServer(executor, "slow-b")
    await agent.start()
    try:
        a = await a2a_node(cluster, "a", facade=True)
        b = await a2a_node(cluster, "b", agent)
        a.events_may_fail = b.events_may_fail = True
        c = await cluster.node("c")
        gid = a.daemon.create_group("Team", "ask b")
        await a.idle()
        await cluster.invite(a, b, gid)
        await cluster.invite(a, c, gid)
        await a.wait(lambda: b.me in a2a_of(a).peer_cards(gid))
        adapter = a2a_of(a)
        facade = adapter.facade
        assert facade is not None
        routed: dict[str, bool] = {}
        route = facade.route_reply

        def spy(d: Delivery) -> bool:
            routed[d.msg_id] = route(d)
            return routed[d.msg_id]

        monkeypatch.setattr(facade, "route_reply", spy)
        url = facade.url(gid, b.me)  # the facade for member b only
        http = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {adapter.facade_token}"}, timeout=WAIT
        )
        try:
            card = await A2ACardResolver(http, url).get_agent_card()
            plain = ClientFactory(ClientConfig(httpx_client=http, streaming=False)).create(card)
            msg = Message(role=Role.ROLE_USER, message_id="u-q", parts=[Part(text="for b")])
            pending = asyncio.ensure_future(
                anext(aiter(plain.send_message(SendMessageRequest(message=msg))))
            )

            def request() -> list[Delivery]:
                return [
                    d
                    for d in c.adapter.deliveries
                    if d.kind == "a2a.message" and d.sender.identity == a.me
                ]

            await c.adapter.wait_for(lambda: bool(request()), WAIT)
            req = request()[0]
            assert req.to == [b.me]
            forged = raw_send(
                c, gid, "a2a.message", {"parts": [{"text": "forged by c"}]}, reply_to=[req.msg_id]
            )
            assert await handled(a, c, forged) == "done"
            assert routed[forged] is False, "c's answer is not b's"
            assert not pending.done()
            pending.cancel()
        finally:
            await http.aclose()
    finally:
        executor.release.set()
        await agent.stop()


# -- F5: a follow-up on a task asks only the member running it -------------------------


def floor(node: Node, gid: str) -> str:
    row = node.daemon.store.group(gid)
    return "" if row is None else str(row.policy.get("floor"))


async def test_a_broadcast_follow_up_asks_only_the_task_owner(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    a.daemon.set_policy(gid, floor="free")
    await a.idle()
    for n in (b, c):
        await n.wait(lambda n=n: floor(n, gid) == "free")
    request = b.daemon.send_message(gid, {"text": "please"}, to=[a.me])
    assert await handled(a, b, request) == "done"
    assert await triggers(b, a, update(a, gid, "t1", b, [request]))
    # b continues a's task t1 the way SDK send(..., task_id="t1") does: to
    # ["*"], no addressee, which in a free group reaches everyone.
    follow_up = b.daemon.send_message(gid, {"parts": [{"text": "more"}], "taskId": "t1"})
    assert await handled(c, b, follow_up) == "done"
    # c, not running t1, can't answer it; a, which runs it, can.
    assert not await triggers(b, c, update(c, gid, "t1", b, [follow_up]))
    assert await triggers(b, a, update(a, gid, "t1", b, [follow_up]))


# -- F7: an agent's task update without reply_to answers its task's request ------------


async def test_a_task_update_without_reply_to_answers_its_request(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    from_a = a.daemon.send_message(gid, {"parts": [{"text": "task for b"}]}, to=[b.me])
    assert await handled(b, a, from_a) == "done"
    from_c = c.daemon.send_message(gid, {"parts": [{"text": "another"}]}, to=[b.me])
    assert await handled(b, c, from_c) == "done"
    # b's agent reports progress on a's task with the requester as addressee
    # and no reply_to: the runtime names a's request, not c's.
    status = {"taskId": "ta", "contextId": gid, "status": {"state": "TASK_STATE_WORKING"}}
    sent = b.daemon.send_message(gid, status, kind="a2a.task_status", addressee=[a.me])
    assert await handled(a, b, sent) == "done"
    d = delivered(a.adapter, sent)
    assert d.inner["reply_to"] == [from_a]
    assert d.addressed_to_me
    # a asks b something else; the next update of task ta still answers the
    # request whose task it is, not a's latest message.
    later = a.daemon.send_message(gid, {"parts": [{"text": "unrelated"}]}, to=[b.me])
    assert await handled(b, a, later) == "done"
    more = b.daemon.send_message(gid, status, kind="a2a.task_status", addressee=[a.me])
    assert await handled(a, b, more) == "done"
    assert delivered(a.adapter, more).inner["reply_to"] == [from_a]
    assert delivered(a.adapter, more).addressed_to_me
