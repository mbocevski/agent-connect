"""One authenticated peer message can't wedge a receiver (SPEC 7.2, 10.2).

A ``hop`` outside a u32, a body nested past the depth limit, and a ``to``
or ``addressee`` past its size limit are malformed: dropped, audited and
counted against the sender like any malformed message. A message that
fails in the receiver's own handling for any other reason that isn't
transient fails alone: it is recorded as failed, its journal entry is
consumed, the relay's copy is acked, the audit log has a row and the human
gets ``message_failed``. The messages after it arrive, and nothing is left
pending (the security review's SR-11 and SR-54)."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

import agentconnect_core as ac
from agentconnect.limits import MAX_DEPTH, MAX_RECIPIENTS, SENDER_PER_MINUTE, U32_MAX
from agentconnect.policy import SafetyPolicy
from agentconnect.runtime.engine import Engine, journal_key, new_msg_id
from agentconnect_harness.cluster import WAIT, Node

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]


def raw(gid: str) -> bytes:
    return base64.urlsafe_b64decode(gid + "=" * (-len(gid) % 4))


def raw_send(node: Node, gid: str, body: dict[str, Any], **fields: Any) -> str:
    """Queue an inner message past the sender's own checks, with ``fields``
    replacing the inner message's own (a peer that doesn't enforce them)."""
    inner = node.daemon.inner("a2a.message", body, ["*"]) | fields
    msg_id = new_msg_id()
    node.daemon._enqueue("app", gid, {"inner": inner, "msg_id": msg_id})
    return msg_id


def raw_plaintext(node: Node, gid: str, plaintext: bytes) -> str:
    """Seal ``plaintext`` as it is, JSON or not, and queue it."""
    msg_id = new_msg_id()
    env = {
        "v": 0,
        "kind": "application",
        "group_id": gid,
        "epoch": node.daemon.client.epoch(raw(gid)),
        "msg_id": msg_id,
        "sender": node.daemon.mailbox,
        "ct": base64.urlsafe_b64encode(node.daemon.client.seal(raw(gid), plaintext))
        .rstrip(b"=")
        .decode(),
    }
    node.daemon._enqueue("app", gid, {"inner": {}, "msg_id": msg_id, "env": env})
    return msg_id


def nested(depth: int) -> dict[str, Any]:
    """A ``data`` part whose value takes the inner message to ``depth``
    levels: the inner message, ``body``, ``parts`` and the part are four of
    them."""
    value: Any = 1
    for _ in range(depth - 4):
        value = [value]
    return {"parts": [{"data": value}]}


def events(node: Node, kind: str) -> list[dict[str, Any]]:
    return [e["data"] for e in node.daemon.store.events(limit=10_000) if e["type"] == kind]


async def until(predicate: Callable[[], bool]) -> None:
    """Poll (yielding to the loop): a crashed worker announces nothing."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing to wait on after a crash
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


async def handled(receiver: Node, sender: Node, msg_id: str) -> str | None:
    """Wait until ``receiver`` recorded ``msg_id`` and has nothing pending."""
    await sender.idle()
    mailbox = sender.daemon.mailbox
    await receiver.wait(lambda: receiver.daemon.store.inbox_state(mailbox, msg_id) is not None)
    await receiver.wait(lambda: receiver.daemon.status()["inbox_pending"] == 0)
    return receiver.daemon.store.inbox_state(mailbox, msg_id)


async def unwedged(receiver: Node, sender: Node, gid: str) -> None:
    """A message after the bad one arrives, and the receiver is caught up:
    nothing left in the journal, nothing unacked."""
    after = raw_send(sender, gid, {"parts": [{"text": "after"}]})
    assert await handled(receiver, sender, after) == "done"
    assert [d.msg_id for d in receiver.adapter.deliveries if d.kind == "a2a.message"][-1] == after
    await receiver.wait(receiver.daemon.caught_up)
    assert receiver.daemon.client.journal_pending() == []


def audit_row(node: Node, gid: str, msg_id: str) -> dict[str, Any]:
    (row,) = [r for r in node.daemon.store.audit(gid) if r["msg_id"] == msg_id]
    return row


@pytest.mark.parametrize("hop", [U32_MAX + 1, 2**63 - 1, 2**63, 2**64, -1, "3", True, 1.5])
async def test_a_hop_outside_u32_is_malformed(group: GroupFixture, hop: Any) -> None:
    (a, b), gid = await group(2)
    bad = raw_send(a, gid, {"parts": [{"text": "bad hop"}]}, hop=hop)
    assert await handled(b, a, bad) == "dropped"
    row = audit_row(b, gid, bad)
    assert (row["decision"], row["reason"]) == ("drop", "malformed")
    assert b.daemon.safety.violations(gid, a.me) == 1
    # Malformed is no hop: the loop guard doesn't pause on it.
    assert not b.adapter.of_type("loop_guard")
    await unwedged(b, a, gid)


async def test_the_largest_hop_pauses_and_replies_stay_within_u32(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    top = raw_send(a, gid, {"parts": [{"text": "top"}]}, hop=U32_MAX)
    assert await handled(b, a, top) == "done"
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("loop_guard")))
    (delivery,) = [d for d in b.adapter.deliveries if d.msg_id == top]
    assert (delivery.hop, delivery.addressed_to_me) == (U32_MAX, False)
    # A reply to it is at the top too, not past it: the peer accepts it.
    send = b.adapter.send
    assert send is not None
    await send(gid, {"text": "reply"}, reply_to=[top])
    assert await a.wait_texts(gid, 1) == ["reply"]
    assert [d.hop for d in a.adapter.deliveries if d.kind == "a2a.message"] == [U32_MAX]


@pytest.mark.parametrize("depth", [MAX_DEPTH + 1, 2000])
async def test_a_body_nested_too_deep_is_malformed(group: GroupFixture, depth: int) -> None:
    (a, b), gid = await group(2)
    ok = raw_send(a, gid, nested(MAX_DEPTH))
    deep = raw_send(a, gid, nested(depth))
    assert await handled(b, a, ok) == "done"
    assert await handled(b, a, deep) == "dropped"
    assert (audit_row(b, gid, deep)["reason"]) == "malformed"
    assert [d.msg_id for d in b.adapter.deliveries if d.kind == "a2a.message"] == [ok]
    await unwedged(b, a, gid)


async def test_json_too_deep_to_parse_is_malformed(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    depth = 200_000  # past what Python's JSON parser recurses to
    head = f'{{"v":0,"sender":"{a.me}","instance_id":"{a.daemon.instance.instance_id_hex}","x":'
    bad = raw_plaintext(a, gid, head.encode() + b"[" * depth + b"]" * depth + b"}")
    assert await handled(b, a, bad) == "dropped"
    await unwedged(b, a, gid)


LONE = '"\\ud800"'  # a JSON string that decodes to a lone surrogate


def with_lone_surrogate(node: Node, where: str) -> bytes:
    """An inner message with one string or key that decodes to a lone
    surrogate at ``where``: valid JSON, and valid UTF-8 on the wire, inside
    every other bound. No UTF-8 encoder takes the decoded string."""
    inner = node.daemon.inner("a2a.message", {"parts": [{"text": "hi"}]}, ["*"])
    deepest: Any = "MARK"
    for _ in range(MAX_DEPTH - 4):  # the inner message, body, parts, the part
        deepest = [deepest]
    inner |= {
        "text": {"body": {"parts": [{"text": "MARK"}]}},
        "reply_to": {"reply_to": ["MARK"]},
        "to": {"to": ["MARK"]},
        "key": {"body": {"parts": [{"data": {"MARK": 1}}]}},
        "deep": {"body": {"parts": [{"data": deepest}]}},
    }[where]
    return json.dumps(inner).replace('"MARK"', LONE).encode()


@pytest.mark.parametrize("where", ["text", "reply_to", "to", "key", "deep"])
async def test_a_lone_surrogate_anywhere_is_malformed(group: GroupFixture, where: str) -> None:
    (a, b), gid = await group(2)
    bad = raw_plaintext(a, gid, with_lone_surrogate(a, where))
    assert await handled(b, a, bad) == "dropped"
    assert audit_row(b, gid, bad)["reason"] == "malformed"
    assert b.daemon.safety.violations(gid, a.me) == 1
    assert not events(b, "message_failed")
    assert not [d for d in b.adapter.deliveries if d.msg_id == bad]
    await unwedged(b, a, gid)


async def test_lone_surrogates_count_against_the_sender(group: GroupFixture) -> None:
    """Past the sender's rate: each is dropped and counted, and the human
    hears of it once, as ``repeated_violations``."""
    (a, b), gid = await group(2)
    n = SENDER_PER_MINUTE + 10
    ids = [raw_plaintext(a, gid, with_lone_surrogate(a, "reply_to")) for _ in range(n)]
    for msg_id in ids:
        assert await handled(b, a, msg_id) == "dropped"
    assert {audit_row(b, gid, msg_id)["reason"] for msg_id in ids} == {"malformed"}
    assert b.daemon.safety.violations(gid, a.me) == n
    assert len(events(b, "repeated_violations")) == 1
    assert not events(b, "message_failed")


@pytest.mark.parametrize(
    "fields",
    [
        {"to": [f"ac:v0:{i}" for i in range(MAX_RECIPIENTS + 1)]},
        {"to": ["x" * 129]},
        {"to": [["*"]]},
        {"to": "*"},
        {"addressee": [f"ac:v0:{i}" for i in range(MAX_RECIPIENTS + 1)]},
        {"addressee": ["x" * 129]},
    ],
    ids=["to-51", "to-long", "to-nested", "to-string", "addressee-51", "addressee-long"],
)
async def test_to_and_addressee_are_bounded(group: GroupFixture, fields: dict[str, Any]) -> None:
    (a, b), gid = await group(2)
    if "addressee" in fields:
        # SR-54: the receiver is listed, past the limit.
        fields = {"addressee": [*fields["addressee"], b.me]}
    bad = raw_send(a, gid, {"parts": [{"text": "bad"}]}, **fields)
    assert await handled(b, a, bad) == "dropped"
    assert audit_row(b, gid, bad)["reason"] == "malformed"
    await unwedged(b, a, gid)


async def test_recipients_at_the_limit_pass(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    others = [f"ac:v0:{i}" for i in range(MAX_RECIPIENTS - 1)]
    msg_id = raw_send(
        a, gid, {"parts": [{"text": "fits"}]}, to=[*others, b.me], addressee=[*others, b.me]
    )
    assert await handled(b, a, msg_id) == "done"
    (delivery,) = [d for d in b.adapter.deliveries if d.msg_id == msg_id]
    assert delivery.addressed_to_me


def raising_for(msg_ids: set[str], error: BaseException, times: int | None = None) -> Any:
    """A ``SafetyPolicy.transcribe`` that raises ``error`` for ``msg_ids``
    (``times`` times, or always): a failure inside the receiver's own
    handling of one message."""
    original = SafetyPolicy.transcribe
    left = [times]

    def transcribe(self: SafetyPolicy, group_id: str, direction: str, *args: Any) -> None:
        if direction == "in" and args[1] in msg_ids and left[0] != 0:
            if left[0] is not None:
                left[0] -= 1
            raise error
        original(self, group_id, direction, *args)

    return transcribe


async def test_a_message_that_fails_in_handling_fails_alone(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    acks: list[str] = []
    ack = b.daemon._ack

    async def record_ack(msg_id: str) -> None:
        acks.append(msg_id)
        await ack(msg_id)

    monkeypatch.setattr(b.daemon, "_ack", record_ack)
    poison: set[str] = set()
    monkeypatch.setattr(SafetyPolicy, "transcribe", raising_for(poison, RecursionError("deep")))
    # Sent once this test awaits: the set is complete by then.
    msg_id = raw_send(a, gid, {"parts": [{"text": "x"}]})
    poison.add(msg_id)
    assert await handled(b, a, msg_id) == "failed"
    assert msg_id in acks
    row = audit_row(b, gid, msg_id)
    assert (row["sender"], row["kind"], row["decision"], row["reason"]) == (
        a.me,
        "a2a.message",
        "drop",
        "processing_failed",
    )
    (event,) = events(b, "message_failed")
    assert event == {
        "sender": a.me,
        "msg_id": msg_id,
        "message_kind": "a2a.message",
        "reason": "RecursionError",
        "count": 1,
    }
    # Counted against the sender, like a malformed message.
    assert b.daemon.safety.violations(gid, a.me) == 1
    # The human's, like the policy's other events: never the agent's.
    assert not b.adapter.of_type("message_failed")
    assert not [d for d in b.adapter.deliveries if d.msg_id == msg_id]
    await unwedged(b, a, gid)
    # Not retried after a reconnect either.
    await b.restart()
    await b.wait(b.daemon.caught_up)
    assert len(events(b, "message_failed")) == 1
    assert b.daemon.store.inbox_state(a.daemon.mailbox, msg_id) == "failed"


async def test_a_commit_that_fails_in_handling_fails_alone(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    after_commit = b.daemon.groups.after_commit
    failed: list[int] = []

    async def failing(group_id: str, event: dict[str, Any], *args: Any, **kw: Any) -> None:
        if not failed:
            failed.append(1)
            msg = "unexpected"
            raise ValueError(msg)
        await after_commit(group_id, event, *args, **kw)

    monkeypatch.setattr(b.daemon.groups, "after_commit", failing)
    a.daemon.update(gid)
    await a.idle()
    await b.wait(lambda: bool(events(b, "message_failed")))
    (event,) = events(b, "message_failed")
    assert (event["message_kind"], event["reason"]) == ("commit", "ValueError")
    # The core merged it, and the cached view follows the core; the
    # bookkeeping it skipped leaves the group out of sync, and the human hears.
    await b.wait(lambda: b.epoch(gid) == a.epoch(gid))
    info = b.daemon.group_info(gid)
    assert (info["out_of_sync"], info["out_of_sync_reason"]) == (True, "commit_failed")
    assert [e["reason"] for e in events(b, "out_of_sync")] == ["commit_failed"]
    await unwedged(b, a, gid)


async def test_a_transient_failure_in_handling_is_retried(
    group: GroupFixture, advance: Advance, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    storage = ac.AgentConnectError("storage error: disk I/O error")
    storage.kind = "transient"
    poison: set[str] = set()
    monkeypatch.setattr(SafetyPolicy, "transcribe", raising_for(poison, storage, times=1))
    # Sent once this test awaits: the set is complete by then.
    msg_id = raw_send(a, gid, {"text": "later"})
    poison.add(msg_id)
    await a.idle()
    await b.wait(lambda: b.clock.sleepers > 0)
    assert b.daemon.store.inbox_state(a.daemon.mailbox, msg_id) is None
    await advance(300)
    assert await b.wait_texts(gid, 1) == ["later"]
    assert not events(b, "message_failed")


@pytest.mark.parametrize("point", ["poison.in_tx", "poison.after_tx", "receive.after_consume"])
async def test_a_crash_around_failing_a_message_records_it_once(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    (a, b), gid = await group(2)
    poison: set[str] = set()
    monkeypatch.setattr(SafetyPolicy, "transcribe", raising_for(poison, ValueError("bug")))
    b.daemon.failpoints.arm(point, "crash")
    # Sent once this test awaits: the set is complete by then.
    msg_id = raw_send(a, gid, {"text": "x"})
    poison.add(msg_id)
    await a.idle()
    await until(lambda: point in b.daemon.failpoints.fired)
    await b.restart()
    await b.wait(lambda: b.daemon.store.inbox_state(a.daemon.mailbox, msg_id) == "failed")
    await unwedged(b, a, gid)
    assert len(events(b, "message_failed")) == 1
    assert len([r for r in b.daemon.store.audit(gid) if r["msg_id"] == msg_id]) == 1


async def test_a_journal_entry_whose_replay_fails_fails_alone(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    b.daemon.failpoints.arm("receive.after_core", "crash")
    msg_id = raw_send(a, gid, {"text": "x"})
    await a.idle()
    await until(lambda: "receive.after_core" in b.daemon.failpoints.fired)
    key = journal_key(a.daemon.mailbox, msg_id)
    assert [e["key"] for e in b.daemon.client.journal_pending()] == [key]
    replay = Engine._replay_entry

    async def failing(self: Engine, entry: dict[str, Any]) -> None:
        if entry["key"] == key:
            msg = "bug"
            raise ValueError(msg)
        await replay(self, entry)

    monkeypatch.setattr(Engine, "_replay_entry", failing)
    await b.restart()
    await b.wait(lambda: b.daemon.store.inbox_state(a.daemon.mailbox, msg_id) == "failed")
    (event,) = events(b, "message_failed")
    assert (event["msg_id"], event["message_kind"], event["reason"]) == (
        msg_id,
        "a2a.message",
        "ValueError",
    )
    await unwedged(b, a, gid)
