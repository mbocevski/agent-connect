"""The delivery queue the MCP host pulls from (agentconnect.deliveries)."""

from __future__ import annotations

import asyncio
import json
import random
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from agentconnect.adapter import Delivery, DeliveryResult, Event, GroupView, Sender
from agentconnect.clock import FakeClock
from agentconnect.deliveries import (
    LEASE_SECS,
    MAX_BATCH,
    MAX_WAIT_SECS,
    DeliveryQueue,
    Taken,
    delivery_key,
)
from agentconnect.store import Store

GROUP = GroupView("g1", "Ops", "Deploys", 3, "all")
OTHER = GroupView("g2", "Dev", "Builds", 1, "all")
SENDER = Sender("ac:v0:peer", "i1", "peer-bot", False)


def delivery(
    msg_id: str = "m1",
    *,
    group: str = "g1",
    kind: str = "a2a.message",
    addressed: bool = True,
    sender: Sender = SENDER,
) -> Delivery:
    return Delivery(
        group,
        msg_id,
        kind,
        {"parts": [{"text": f"text of {msg_id}"}]},
        sender,
        ["*"],
        addressed,
        "Deploys",
        {"self": "unverified", "verified_members": 0, "members": 2},
        "agent",
        1,
        {"kind": kind},
    )


async def until(predicate: Callable[[], bool]) -> None:
    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing announces it
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), 5)


@pytest.fixture
def store(tmp_path: Path, rng: random.Random) -> Iterator[Store]:
    s = Store(tmp_path / "d.sqlite3", rng.randbytes(32))
    yield s
    s.close()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def queue(store: Store, clock: FakeClock) -> DeliveryQueue:
    q = DeliveryQueue(clock)
    q.bind_store(store)
    return q


async def put(queue: DeliveryQueue, d: Delivery, group: GroupView = GROUP) -> DeliveryResult:
    return await queue.deliver(group, d.sender, d.to, d)


def ids(taken: list[Taken]) -> list[str]:
    return [t.payload["msg_id"] for t in taken]


async def test_content_is_queued_and_cards_and_controls_are_not(queue: DeliveryQueue) -> None:
    assert await put(queue, delivery("m1")) is DeliveryResult.ACK
    assert await put(queue, delivery("card", kind="a2a.agent_card")) is DeliveryResult.ACK
    assert await put(queue, delivery("c", kind="control.pause")) is DeliveryResult.ACK
    for kind in ("a2a.task_status", "a2a.task_artifact", "a2a.task_cancel"):
        await put(queue, delivery(kind, kind=kind))
    taken, more = await queue.take()
    assert ids(taken) == ["m1", "a2a.task_status", "a2a.task_artifact", "a2a.task_cancel"]
    assert more is False
    first = taken[0].payload
    assert (first["untrusted"], first["event"], first["addressed_to_me"]) == (True, "message", True)
    assert first["notice"].startswith('Message from remote agent "peer-bot"')
    assert queue.capabilities().originates is False


async def test_a_repeat_is_queued_once_and_not_after_it_was_returned(
    queue: DeliveryQueue, store: Store
) -> None:
    await put(queue, delivery("m1"))
    await put(queue, delivery("m1"))  # the runtime hands it over again
    taken, _ = await queue.take()
    assert ids(taken) == ["m1"]
    assert queue.ack([t.delivery_id for t in taken]) == 1
    assert store.handled_has(delivery_key(taken[0].payload))
    await put(queue, delivery("m1"))  # after a crash, once more
    assert (await queue.take())[0] == []
    assert queue.ack([taken[0].delivery_id]) == 0  # already gone


async def test_the_key_names_the_sender(queue: DeliveryQueue) -> None:
    """Another sender's message with the same msg_id is not a repeat."""
    await put(queue, delivery("m1"))
    other = replace(SENDER, identity="ac:v0:other")
    await put(queue, delivery("m1", sender=other))
    taken, _ = await queue.take()
    assert [t.payload["sender"]["identity"] for t in taken] == [SENDER.identity, other.identity]
    key = json.loads(delivery_key(taken[0].payload))
    assert key == ["msg", "g1", SENDER.identity, "m1"]


async def test_addressed_only_waits_for_an_addressed_one_and_brings_context(
    queue: DeliveryQueue, clock: FakeClock
) -> None:
    await put(queue, delivery("context", addressed=False))
    assert (await queue.take(addressed_only=True))[0] == []
    waiting = asyncio.ensure_future(queue.take(addressed_only=True, wait_secs=60))
    await until(lambda: queue.waiting == 1)
    await put(queue, delivery("question"))
    taken, _ = await waiting
    assert ids(taken) == ["context", "question"]
    assert queue.waiting == 0
    del clock


async def test_a_take_times_out_on_the_runtime_clock(
    queue: DeliveryQueue, clock: FakeClock
) -> None:
    waiting = asyncio.ensure_future(queue.take(wait_secs=MAX_WAIT_SECS * 10))
    await until(lambda: queue.waiting == 1)
    clock.advance(MAX_WAIT_SECS - 1)
    await asyncio.sleep(0)
    assert not waiting.done()
    clock.advance(2)  # the wait is capped at MAX_WAIT_SECS
    assert await asyncio.wait_for(waiting, 5) == ([], False)


async def test_leases_hide_messages_until_they_run_out(
    queue: DeliveryQueue, clock: FakeClock
) -> None:
    await put(queue, delivery("m1"))
    first, _ = await queue.take()
    assert ids(first) == ["m1"]
    assert (await queue.take())[0] == []  # leased to the first caller
    clock.advance(LEASE_SECS + 1)
    again, _ = await queue.take()
    assert ids(again) == ["m1"]
    queue.release(t.delivery_id for t in again)
    assert ids((await queue.take())[0]) == ["m1"]


async def test_a_waiter_wakes_when_a_lease_runs_out(queue: DeliveryQueue, clock: FakeClock) -> None:
    await put(queue, delivery("m1"))
    await queue.take()
    waiting = asyncio.ensure_future(queue.take(wait_secs=MAX_WAIT_SECS))
    await until(lambda: queue.waiting == 1)
    clock.advance(LEASE_SECS + 1)
    taken, _ = await asyncio.wait_for(waiting, 5)
    assert ids(taken) == ["m1"]


async def test_limit_more_and_groups(queue: DeliveryQueue) -> None:
    for n in range(MAX_BATCH + 2):
        await put(queue, delivery(f"m{n}"))
    await put(queue, delivery("elsewhere", group="g2"), OTHER)
    only, more = await queue.take("g2")
    assert (ids(only), more) == (["elsewhere"], False)
    taken, more = await queue.take(limit=1000)
    assert (len(taken), more) == (MAX_BATCH, True)
    rest, more = await queue.take()
    assert (ids(rest), more) == ([f"m{n}" for n in range(MAX_BATCH, MAX_BATCH + 2)], False)


async def test_closing_or_stopping_ends_a_wait(queue: DeliveryQueue) -> None:
    stop = asyncio.Event()
    waiting = asyncio.ensure_future(queue.take(wait_secs=60, stop=stop))
    await until(lambda: queue.waiting == 1)
    stop.set()
    assert await asyncio.wait_for(waiting, 5) == ([], False)
    waiting = asyncio.ensure_future(queue.take(wait_secs=60))
    await until(lambda: queue.waiting == 1)
    await queue.close()
    assert await asyncio.wait_for(waiting, 5) == ([], False)
    await put(queue, delivery("m1"))
    assert (await queue.take())[0] == []  # closed: nothing is handed out


async def test_a_cancelled_take_leases_nothing(queue: DeliveryQueue) -> None:
    waiting = asyncio.ensure_future(queue.take(wait_secs=60))
    await until(lambda: queue.waiting == 1)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    assert queue.waiting == 0
    await put(queue, delivery("m1"))
    assert ids((await queue.take())[0]) == ["m1"]


async def test_events_are_not_queued_and_a_queue_without_store_refuses(
    clock: FakeClock,
) -> None:
    q = DeliveryQueue(clock)
    await q.on_event(GROUP, Event("member_joined", "g1", {}, "e1"))

    async def send(*_a: object, **_k: object) -> str:
        return "m"

    await q.on_outbound(send)
    with pytest.raises(RuntimeError, match="no store"):
        await put(q, delivery("m1"))
    assert await put(q, delivery("card", kind="a2a.agent_card")) is DeliveryResult.ACK
