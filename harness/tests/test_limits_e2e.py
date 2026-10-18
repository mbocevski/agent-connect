"""SPEC §10.2 and §7.2 between real daemons: a peer that ignores the limits
gets nothing past them, and the daemon refuses to break them itself."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.daemon import DaemonError, new_msg_id
from agentconnect.limits import MAX_MESSAGE_BYTES, SENDER_PER_MINUTE
from agentconnect_harness.cluster import Node

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]


def raw_send(node: Node, gid: str, kind: str, body: dict[str, Any]) -> str:
    """Queue an inner message without the sender's own checks (a peer that
    doesn't enforce SPEC 10.2)."""
    inner = node.daemon.inner(kind, body, ["*"])
    msg_id = new_msg_id()
    node.daemon._enqueue("app", gid, {"inner": inner, "msg_id": msg_id})
    return msg_id


async def test_receivers_drop_what_breaks_the_limits(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    raw_send(a, gid, "x.evil", {"text": "unknown kind"})
    raw_send(a, gid, "a2a.message", {"parts": [{"file": {"uri": "file:///etc/passwd"}}]})
    raw_send(a, gid, "a2a.message", {"text": "x" * (MAX_MESSAGE_BYTES + 1)})
    raw_send(a, gid, "a2a.message", {"text": "ok", "parts": [{"text": "ok"}]})
    assert await b.wait_texts(gid, 1) == ["ok"]
    await a.idle()
    assert [d.kind for d in b.adapter.deliveries if d.kind != "a2a.agent_card"] == ["a2a.message"]


async def test_receivers_rate_limit_a_flooding_sender(
    group: GroupFixture, advance: Advance
) -> None:
    (a, b), gid = await group(2)
    ids = [raw_send(a, gid, "a2a.message", {"text": str(i)}) for i in range(SENDER_PER_MINUTE + 5)]
    await a.idle()
    await b.wait(lambda: b.daemon.store.inbox_state(a.daemon.mailbox, ids[-1]) is not None)
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 0)
    assert len(b.adapter.texts(gid)) == SENDER_PER_MINUTE
    assert b.daemon.store.inbox_state(a.daemon.mailbox, ids[-1]) == "dropped"
    await advance(60)
    raw_send(a, gid, "a2a.message", {"text": "next minute"})
    texts = await b.wait_texts(gid, SENDER_PER_MINUTE + 1)
    assert texts[-1] == "next minute"


async def test_senders_refuse_to_break_the_limits(group: GroupFixture, advance: Advance) -> None:
    (a, _b), gid = await group(2)
    d = a.daemon
    with pytest.raises(DaemonError, match="unknown message kind"):
        d.send_message(gid, {}, kind="control.nope")
    with pytest.raises(DaemonError, match="text and data"):
        d.send_message(gid, {"parts": [{"file": {"uri": "x"}}]})
    with pytest.raises(DaemonError, match="256 KiB"):
        d.send_message(gid, {"text": "x" * MAX_MESSAGE_BYTES})
    for _ in range(SENDER_PER_MINUTE):
        d.send_message(gid, {"text": "x"})
    with pytest.raises(DaemonError, match="rate") as err:
        d.send_message(gid, {"text": "one too many"})
    assert err.value.code == "rate_limited"
    await advance(60)
    d.send_message(gid, {"text": "fine again"})


async def test_messages_queued_during_an_outage_are_exempt_but_a_live_flood_is_not(
    group: GroupFixture,
    partition: Callable[[Node], Awaitable[None]],
    heal: Callable[[Node], Awaitable[None]],
) -> None:
    (a, b), gid = await group(2)
    # A lower per-sender rate (the group's policy) keeps the test under the
    # relay's own 50/s.
    limit = 5
    b.daemon.update_safety(gid, {"sender_per_minute": limit})
    await partition(b)
    # Twice the limit queues at the relay while b is away.
    queued = [raw_send(a, gid, "a2a.message", {"text": f"q{i}"}) for i in range(2 * limit)]
    await a.idle()
    await heal(b)
    await b.wait(lambda: b.daemon.store.inbox_state(a.daemon.mailbox, queued[-1]) is not None)
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 0)
    assert len(b.adapter.texts(gid)) == 2 * limit, "the reconnect drain is not rate limited"
    # Live traffic after the relay's "drained" is.
    live = [raw_send(a, gid, "a2a.message", {"text": f"l{i}"}) for i in range(2 * limit)]
    await a.idle()
    await b.wait(lambda: b.daemon.store.inbox_state(a.daemon.mailbox, live[-1]) is not None)
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 0)
    assert len(b.adapter.texts(gid)) == 3 * limit
    assert b.daemon.store.inbox_state(a.daemon.mailbox, live[-1]) == "dropped"
