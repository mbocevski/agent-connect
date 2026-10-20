"""Task updates trigger only the instance that asked (SPEC 9.3, 10.2).

An ``a2a.task_status`` or ``a2a.task_artifact`` triggers the agent, and
counts against the task budget, only when its ``reply_to`` names a message
this instance sent, from a member that message asked, and about the task
that message named, if it named one. Any other task update is context only, held to the
ordinary message rates in windows of its own, and a drop there is no
violation: it may be an honest task for someone else (the security
review's SR-12)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from agentconnect.limits import SENDER_PER_MINUTE
from agentconnect.runtime.engine import new_msg_id
from agentconnect_harness.cluster import Node

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]


def raw_send(node: Node, gid: str, kind: str, body: dict[str, Any], **fields: Any) -> str:
    """Queue an inner message past the sender's own checks, with ``fields``
    replacing the inner message's own (a peer that doesn't enforce them)."""
    inner = node.daemon.inner(kind, body, ["*"]) | fields
    msg_id = new_msg_id()
    node.daemon._enqueue("app", gid, {"inner": inner, "msg_id": msg_id})
    return msg_id


def update(node: Node, gid: str, task: str, to: Node, refs: list[str] | None = None) -> str:
    """A task status update for ``task``, addressed to ``to`` (SPEC 7.2)."""
    body = {"taskId": task, "contextId": gid, "status": {"state": "TASK_STATE_WORKING"}}
    fields: dict[str, Any] = {"addressee": [to.me]}
    if refs is not None:
        fields["reply_to"] = refs
    return raw_send(node, gid, "a2a.task_status", body, **fields)


async def handled(receiver: Node, sender: Node, msg_id: str) -> str | None:
    await sender.idle()
    mailbox = sender.daemon.mailbox
    await receiver.wait(lambda: receiver.daemon.store.inbox_state(mailbox, msg_id) is not None)
    await receiver.wait(lambda: receiver.daemon.status()["inbox_pending"] == 0)
    return receiver.daemon.store.inbox_state(mailbox, msg_id)


def delivered(node: Node, msg_id: str) -> Any:
    (d,) = [d for d in node.adapter.deliveries if d.msg_id == msg_id]
    return d


def reason(node: Node, gid: str, msg_id: str) -> str:
    (row,) = [r for r in node.daemon.store.audit(gid) if r["msg_id"] == msg_id]
    return str(row["reason"])


def ask(node: Node, gid: str, to: Node, task: str | None = None) -> str:
    body: dict[str, Any] = {"parts": [{"text": "please"}]}
    if task is not None:
        body["taskId"] = task
    return node.daemon.send_message(gid, body, to=[to.me])


async def test_an_unsolicited_task_update_is_context_only(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    # Addressed to b, about a task b never asked for.
    msg_id = update(a, gid, "t1", b)
    assert await handled(b, a, msg_id) == "done"
    assert not delivered(b, msg_id).addressed_to_me
    assert reason(b, gid, msg_id) == "not_requested"
    # Naming a message b received, not one it sent, changes nothing.
    plain = a.daemon.send_message(gid, {"text": "hello"})
    assert await handled(b, a, plain) == "done"
    reply = update(a, gid, "t2", b, [plain])
    assert await handled(b, a, reply) == "done"
    assert not delivered(b, reply).addressed_to_me


async def test_unsolicited_updates_get_the_message_rate_in_windows_of_their_own(
    group: GroupFixture,
) -> None:
    (a, b), gid = await group(2)
    # More than the message rate, under the relay's per-second send rate.
    ids = [update(a, gid, "t1", b) for _ in range(SENDER_PER_MINUTE + 5)]
    assert await handled(b, a, ids[-1]) == "dropped"
    states = [b.daemon.store.inbox_state(a.daemon.mailbox, m) for m in ids]
    assert states.count("done") == SENDER_PER_MINUTE
    assert reason(b, gid, ids[-1]) == "context_rate_limited"
    # Not a violation: it may be an honest task for another member.
    assert b.daemon.safety.violations(gid, a.me) == 0
    # The ordinary messages have their own window, untouched.
    plain = a.daemon.send_message(gid, {"text": "still here"})
    assert await handled(b, a, plain) == "done"
    assert delivered(b, plain).addressed_to_me


async def test_a_reply_to_this_instances_request_triggers_on_the_task_budget(
    group: GroupFixture,
) -> None:
    (a, b), gid = await group(2)
    request = ask(b, gid, a)
    assert await handled(a, b, request) == "done"
    # Past the message rate: the task budget applies.
    ids = [update(a, gid, "t1", b, [request]) for _ in range(SENDER_PER_MINUTE + 5)]
    assert await handled(b, a, ids[-1]) == "done"
    assert all(delivered(b, m).addressed_to_me for m in ids)
    # And it holds across a restart.
    await b.restart()
    again = update(a, gid, "t1", b, [request])
    assert await handled(b, a, again) == "done"
    assert delivered(b, again).addressed_to_me


async def test_a_follow_up_names_its_task(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    follow_up = ask(b, gid, a, task="t1")
    assert await handled(a, b, follow_up) == "done"
    right = update(a, gid, "t1", b, [follow_up])
    wrong = update(a, gid, "t9", b, [follow_up])
    assert await handled(b, a, wrong) == "done"
    assert delivered(b, right).addressed_to_me
    assert not delivered(b, wrong).addressed_to_me


async def test_only_the_member_asked_answers(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    request = ask(b, gid, a)
    assert await handled(c, b, request) == "done"
    # c read the request (every member decrypts it) but wasn't asked.
    intruder = update(c, gid, "t1", b, [request])
    assert await handled(b, c, intruder) == "done"
    assert not delivered(b, intruder).addressed_to_me
    answer = update(a, gid, "t1", b, [request])
    assert await handled(b, a, answer) == "done"
    assert delivered(b, answer).addressed_to_me
    # c sees the progress of b's task as context only.
    assert await handled(c, a, answer) == "done"
    assert not delivered(c, answer).addressed_to_me


async def test_a_broadcast_request_may_be_answered_by_every_member(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    request = b.daemon.send_message(gid, {"text": "anyone?"})
    assert await handled(c, b, request) == "done"
    from_a = update(a, gid, "ta", b, [request])
    from_c = update(c, gid, "tc", b, [request])
    assert await handled(b, a, from_a) == "done"
    assert await handled(b, c, from_c) == "done"
    assert delivered(b, from_a).addressed_to_me
    assert delivered(b, from_c).addressed_to_me
