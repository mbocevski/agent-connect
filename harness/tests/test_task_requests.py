"""What a request grants (SPEC 9.3), from the adversarial reviews of the
SR-12 fix: one task per instance it asked, which triggers only when it
enters a state the requester acts on (input or auth required, or an end),
once per state, however late or long the task; the trigger goes to the
adapter that asked;
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
from agentconnect.limits import SENDER_PER_MINUTE
from agentconnect.runtime.engine import DaemonError, new_msg_id
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


IR = "TASK_STATE_INPUT_REQUIRED"


def update(  # noqa: PLR0913, PLR0917
    node: Node, gid: str, task: str, to: Node, refs: list[str], state: str = IR
) -> str:
    """A task status update; by default one that asks the requester for
    input, which triggers it when the task is granted."""
    body = {"taskId": task, "contextId": gid, "status": {"state": state}}
    return raw_send(node, gid, "a2a.task_status", body, addressee=[to.me], reply_to=refs)


def artifact(  # noqa: PLR0913
    node: Node, gid: str, task: str, to: Node, refs: list[str], *, last: bool
) -> str:
    body = {
        "taskId": task,
        "contextId": gid,
        "artifact": {"artifactId": "a1", "parts": [{"text": "chunk"}]},
        "append": True,
        "lastChunk": last,
    }
    return raw_send(node, gid, "a2a.task_artifact", body, addressee=[to.me], reply_to=refs)


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


# -- F1 and V1-V3: what a granted task triggers ---------------------------------------


async def answers(a: Node, b: Node, gid: str, n: int) -> list[str]:
    """b's agent answers ``n`` messages of a as SDK `reply` does: each
    answer asks a, so each grants a one task."""
    out = []
    for i in range(n):
        hello = a.daemon.send_message(gid, {"text": f"hi {i}"})
        assert await handled(b, a, hello) == "done"
        answer = b.daemon.send_message(
            gid, {"parts": [{"text": "hello"}]}, reply_to=[hello], addressee=[a.me]
        )
        assert await handled(a, b, answer) == "done"
        out.append(answer)
    return out


async def test_an_answer_grants_one_task_to_the_member_it_answers(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    (answer,) = await answers(a, b, gid, 1)
    assert await triggers(b, a, update(a, gid, "t0", b, [answer]))
    # Another task against the same request is context: one task per member.
    for task in ("t1", "t2"):
        assert not await triggers(b, a, update(a, gid, task, b, [answer]))


async def test_replies_give_at_most_a_few_triggers_each(group: GroupFixture) -> None:
    """V1: however many updates a member sends on the tasks its answers
    granted, each request triggers at most once per state the requester acts
    on, and never after the task ended: no task budget of triggers."""
    (a, b), gid = await group(2)
    cycle = [
        "TASK_STATE_WORKING",
        IR,
        "TASK_STATE_WORKING",
        IR,
        "TASK_STATE_AUTH_REQUIRED",
        "TASK_STATE_COMPLETED",
        "TASK_STATE_COMPLETED",
        "TASK_STATE_FAILED",
        IR,
    ]
    sent: list[str] = []
    for k, answer in enumerate(await answers(a, b, gid, 3)):
        sent += [update(a, gid, f"t{k}", b, [answer], state) for state in cycle]
        sent.append(artifact(a, gid, f"t{k}", b, [answer], last=True))
    assert await handled(b, a, sent[-1]) == "done"
    fired = [m for m in sent if delivered(b.adapter, m).addressed_to_me]
    # Per request: input required, auth required, the end; three requests.
    assert len(fired) == 9
    states = [delivered(b.adapter, m).body["status"]["state"] for m in fired]
    assert states == [IR, "TASK_STATE_AUTH_REQUIRED", "TASK_STATE_COMPLETED"] * 3
    reasons = {
        r["reason"]
        for r in b.daemon.store.audit(gid)
        if r["msg_id"] in sent and r["msg_id"] not in fired
    }
    assert reasons == {"task_progress"}


async def test_a_long_task_with_gaps_triggers_once_at_its_end(
    group: GroupFixture, advance: Advance
) -> None:
    """V2: progress and artifacts are context, however long the gaps;
    the end triggers, with the artifacts already delivered before it."""
    (a, b), gid = await group(2)
    request = a.daemon.send_message(gid, {"parts": [{"text": "long job"}]}, to=[b.me])
    assert await handled(b, a, request) == "done"
    progress = [update(b, gid, "job", a, [request], "TASK_STATE_WORKING")]
    for last in (False, True):
        await advance(3 * 3600)  # hours without a word
        progress.append(artifact(b, gid, "job", a, [request], last=last))
    await advance(3 * 3600)
    done = update(b, gid, "job", a, [request], "TASK_STATE_COMPLETED")
    assert await triggers(a, b, done)
    assert not any(delivered(a.adapter, m).addressed_to_me for m in progress)
    order = [d.msg_id for d in a.adapter.deliveries]
    assert all(order.index(m) < order.index(done) for m in progress)
    # Anything after the end is context.
    late = update(b, gid, "job", a, [request], "TASK_STATE_COMPLETED")
    assert not await triggers(a, b, late)


async def test_a_late_first_answer_triggers(group: GroupFixture, advance: Advance) -> None:
    """V3: the relay held the request while the peer was away."""
    (a, b), gid = await group(2)
    request = a.daemon.send_message(gid, {"parts": [{"text": "when you can"}]}, to=[b.me])
    assert await handled(b, a, request) == "done"
    await advance(2 * 86_400)
    assert await triggers(a, b, update(b, gid, "job", a, [request], "TASK_STATE_COMPLETED"))


async def test_an_input_required_loop_triggers_once_per_entry(group: GroupFixture) -> None:
    """Each follow-up is a request of its own: the task asking again in
    answer to it triggers again, a repeat without one doesn't."""
    (a, b), gid = await group(2)
    request = a.daemon.send_message(gid, {"parts": [{"text": "plan it"}]}, to=[b.me])
    assert await handled(b, a, request) == "done"
    assert await triggers(a, b, update(b, gid, "job", a, [request]))
    assert not await triggers(a, b, update(b, gid, "job", a, [request]))
    for round_ in range(3):
        follow_up = a.daemon.send_message(
            gid, {"parts": [{"text": f"answer {round_}"}], "taskId": "job"}, to=[b.me]
        )
        assert await handled(b, a, follow_up) == "done"
        working = update(b, gid, "job", a, [follow_up], "TASK_STATE_WORKING")
        assert not await triggers(a, b, working)
        assert await triggers(a, b, update(b, gid, "job", a, [follow_up]))
    assert await triggers(a, b, update(b, gid, "job", a, [follow_up], "TASK_STATE_COMPLETED"))


async def test_a_late_joiner_counts_no_violations(group: GroupFixture, cluster: Cluster) -> None:
    """V4: c joins while b streams a task for a; c can't read a's request,
    and b's honest stream is never held against b."""
    (a, b), gid = await group(2)
    request = a.daemon.send_message(gid, {"parts": [{"text": "stream"}]}, to=[b.me])
    assert await handled(b, a, request) == "done"
    c = await cluster.node("late")
    await cluster.invite(a, c, gid)
    ids = [
        update(b, gid, "job", a, [request], "TASK_STATE_WORKING")
        for _ in range(SENDER_PER_MINUTE + 15)
    ]
    assert await handled(c, b, ids[-1]) == "dropped"
    reasons = {r["reason"] for r in c.daemon.store.audit(gid) if r["msg_id"] in ids}
    assert reasons == {"not_requested", "context_rate_limited"}
    assert c.daemon.safety.violations(gid, b.me) == 0
    assert "repeated_violations" not in [e["type"] for e in c.daemon.store.events(limit=10_000)]
    # The requester takes the whole stream, as context, on the task budget.
    assert await handled(a, b, ids[-1]) == "done"
    assert all(a.daemon.store.inbox_state(b.daemon.mailbox, m) == "done" for m in ids)


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


async def test_a_held_request_still_grants_once_approved(
    group: GroupFixture, advance: Advance
) -> None:
    """A request held for the human's approval grants its task when the
    peer answers it, however long the hold took."""
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
    # b's agent asks a for input on a's task with the requester as addressee
    # and no reply_to: the runtime names a's request, not c's.

    def status(state: str) -> dict[str, Any]:
        return {"taskId": "ta", "contextId": gid, "status": {"state": state}}

    sent = b.daemon.send_message(gid, status(IR), kind="a2a.task_status", addressee=[a.me])
    assert await handled(a, b, sent) == "done"
    d = delivered(a.adapter, sent)
    assert d.inner["reply_to"] == [from_a]
    assert d.addressed_to_me
    # a asks b something else; the next update of task ta still answers the
    # request whose task it is, not a's latest message.
    later = a.daemon.send_message(gid, {"parts": [{"text": "unrelated"}]}, to=[b.me])
    assert await handled(b, a, later) == "done"
    more = b.daemon.send_message(
        gid, status("TASK_STATE_COMPLETED"), kind="a2a.task_status", addressee=[a.me]
    )
    assert await handled(a, b, more) == "done"
    assert delivered(a.adapter, more).inner["reply_to"] == [from_a]
    assert delivered(a.adapter, more).addressed_to_me


# -- the final verification: no trick beats the bound, and an end is never lost --------


def max_turns(node: Node, gid: str) -> int:
    row = node.daemon.store.group(gid)
    return -1 if row is None else int(row.policy["loop_guard"]["max_agent_turns"])


def honest(  # noqa: PLR0913, PLR0917
    node: Node, gid: str, task: str, state: str, to: Node, refs: list[str]
) -> str:
    """A task status update through the runtime's own send path."""
    body = {"taskId": task, "contextId": gid, "status": {"state": state}}
    return node.daemon.send_message(
        gid, body, kind="a2a.task_status", reply_to=refs, addressee=[to.me]
    )


def fired(node: Node, ids: list[str]) -> list[str]:
    return [d.msg_id for d in node.adapter.deliveries if d.msg_id in ids and d.addressed_to_me]


async def test_every_trick_against_one_request_gives_three_triggers(cluster: Cluster) -> None:
    b = await cluster.node("b")  # asks
    a = await cluster.node("a")  # answers, and tries everything
    a2 = await cluster.node("a2", identity_of=a)  # and its replica
    gid = b.daemon.create_group("Pair", "One request")
    await b.idle()
    await cluster.invite(b, a, gid)
    await cluster.invite(b, a2, gid)
    request = b.daemon.send_message(gid, {"parts": [{"text": "do it"}]}, to=[a.me])
    assert await handled(a, b, request) == "done"
    assert await handled(a2, b, request) == "done"
    spellings = [IR, "TASK_STATE_WORKING", "input-required", "INPUT_REQUIRED"]
    spellings += ["TASK_STATE_AUTH_REQUIRED", "TASK_STATE_WORKING", "auth-required"]
    ids = [update(a, gid, "t1", b, [request], s) for s in spellings]
    ids.append(update(a, gid, "t2", b, [request]))  # a second task
    ids.append(update(a, gid, "t1", b, [request, request], "TASK_STATE_COMPLETED"))
    ids += [update(a, gid, "t1", b, [request], s) for s in ("failed", "TASK_STATE_REJECTED")]
    ids.append(update(a, gid, "t1", b, [request]))  # after the end
    ids.append(update(a, gid, "t3", b, [request]))  # a new task after the end
    assert await handled(b, a, ids[-1]) == "done"
    ids += [update(a2, gid, "t1", b, [request], s) for s in ("input-required", "completed")]
    ids.append(update(a2, gid, "t9", b, [request], "TASK_STATE_AUTH_REQUIRED"))
    assert await handled(b, a2, ids[-1]) == "done"
    states = [delivered(b.adapter, m).body["status"]["state"] for m in fired(b, ids)]
    assert states == [IR, "TASK_STATE_AUTH_REQUIRED", "TASK_STATE_COMPLETED"]


async def test_an_end_after_a_full_budget_of_progress_is_sent_and_triggers(
    group: GroupFixture,
) -> None:
    """X1: the end state is exempt from the task budget its progress used,
    on both sides, and is no violation."""
    (a, b), gid = await group(2)
    budget = 5
    for n in (a, b):
        n.daemon.update_safety(gid, {"task_per_minute": budget})
    request = a.daemon.send_message(gid, {"parts": [{"text": "stream"}]}, to=[b.me])
    assert await handled(b, a, request) == "done"
    ids = [honest(b, gid, "job", "TASK_STATE_WORKING", a, [request]) for _ in range(budget)]
    # The sender's budget is spent: more progress is refused...
    with pytest.raises(DaemonError) as refused:
        honest(b, gid, "job", "TASK_STATE_WORKING", a, [request])
    assert refused.value.code == "rate_limited"
    # ...but not the end, which the requester takes as its trigger.
    ids.append(honest(b, gid, "job", "TASK_STATE_COMPLETED", a, [request]))
    assert await handled(a, b, ids[-1]) == "done"
    assert fired(a, ids) == [ids[-1]]
    assert a.daemon.safety.violations(gid, b.me) == 0
    # The exemption is once per state: a repeated end has the budget again.
    with pytest.raises(DaemonError):
        honest(b, gid, "job", "TASK_STATE_COMPLETED", a, [request])


async def test_with_inbound_approval_a_quick_tasks_end_follows_the_decision(
    group: GroupFixture,
) -> None:
    """X2: the end that arrives while the task's first update waits is
    held behind it, and released with it."""
    (a, b), gid = await group(2)
    a.daemon.update_safety(gid, {"require_approval": "inbound"})
    request = a.daemon.send_message(gid, {"parts": [{"text": "quick"}]}, to=[b.me])
    assert await handled(b, a, request) == "done"
    working = honest(b, gid, "job", "TASK_STATE_WORKING", a, [request])
    done = honest(b, gid, "job", "TASK_STATE_COMPLETED", a, [request])
    assert await handled(a, b, done) == "held"
    held = {m["msg_id"]: m["hold_id"] for m in a.daemon.held_messages()}
    assert set(held) == {working, done}
    a.daemon.approve_message(held[working])
    await a.wait(lambda: all(any(d.msg_id == m for d in a.adapter.deliveries) for m in held))
    assert fired(a, [working, done]) == [done]
    assert a.daemon.held_messages() == []


async def test_rejecting_a_tasks_first_update_drops_its_end(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    a.daemon.update_safety(gid, {"require_approval": "inbound"})
    request = a.daemon.send_message(gid, {"parts": [{"text": "quick"}]}, to=[b.me])
    assert await handled(b, a, request) == "done"
    first = honest(b, gid, "job", IR, a, [request])
    done = honest(b, gid, "job", "TASK_STATE_COMPLETED", a, [request])
    assert await handled(a, b, done) == "held"
    held = {m["msg_id"]: m["hold_id"] for m in a.daemon.held_messages()}
    await a.daemon.reject_message(held[first])
    assert a.daemon.held_messages() == []
    for m in (first, done):
        assert a.daemon.store.inbox_state(b.daemon.mailbox, m) == "dropped"
    assert a.daemon.safety.violations(gid, b.me) == 0


async def test_approving_a_held_trigger_releases_the_end_behind_it(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    a.daemon.update_safety(gid, {"require_approval": "inbound"})
    request = a.daemon.send_message(gid, {"parts": [{"text": "ask me"}]}, to=[b.me])
    assert await handled(b, a, request) == "done"
    asking = honest(b, gid, "job", IR, a, [request])
    done = honest(b, gid, "job", "TASK_STATE_COMPLETED", a, [request])
    assert await handled(a, b, done) == "held"
    held = {m["msg_id"]: m["hold_id"] for m in a.daemon.held_messages()}
    a.daemon.approve_message(held[asking])
    await a.wait(lambda: all(any(d.msg_id == m for d in a.adapter.deliveries) for m in held))
    assert fired(a, [asking, done]) == [asking, done]


async def test_a_state_delivered_as_context_is_not_used_up(group: GroupFixture) -> None:
    """X3: past the loop guard the end is context and doesn't use the
    state; entered again once the guard allows it, it triggers, once."""
    (a, b), gid = await group(2)
    a.daemon.set_policy(gid, loop_guard={"max_agent_turns": 1})
    await a.idle()
    await a.wait(lambda: max_turns(a, gid) == 1)
    request = a.daemon.send_message(gid, {"parts": [{"text": "go"}]}, to=[b.me])
    assert await handled(b, a, request) == "done"
    late = update(b, gid, "job", a, [request], "TASK_STATE_COMPLETED")  # hop 2 > 1
    assert not await triggers(a, b, late)
    a.daemon.set_policy(gid, loop_guard={"max_agent_turns": 20})
    await a.idle()
    await a.wait(lambda: max_turns(a, gid) == 20)
    again = update(b, gid, "job", a, [request], "TASK_STATE_COMPLETED")
    assert await triggers(a, b, again)
    assert not await triggers(a, b, update(b, gid, "job", a, [request], "TASK_STATE_COMPLETED"))
