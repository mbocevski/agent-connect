"""The in-process callback adapter (the embedded SDK's delivery path)."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from agentconnect.adapter import Delivery, DeliveryResult, Event, GroupView, Sender
from agentconnect.callback import CallbackAdapter
from agentconnect.clock import FakeClock
from agentconnect.store import Store

GROUP = GroupView("g1", "Ops", "Deploys", 3, "free")
SENDER = Sender("ac:v0:peer", "i1", "peer-bot", False)
BODY_TEXT = "the launch codes"


def delivery(msg_id: str = "m1") -> Delivery:
    return Delivery(
        "g1",
        msg_id,
        "a2a.message",
        {"parts": [{"text": BODY_TEXT}]},
        SENDER,
        ["*"],
        True,
        "Deploys",
        {"self": "unverified", "verified_members": 0, "members": 2},
        "agent",
        1,
        {"kind": "a2a.message"},
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


class Recorder:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.fail_events = 0
        self.fail_messages = 0
        self.fail_ids: set[str] = set()

    async def message(self, payload: dict[str, Any]) -> None:
        if self.fail_messages:
            self.fail_messages -= 1
            raise RuntimeError(BODY_TEXT)
        self.messages.append(payload)

    async def event(self, payload: dict[str, Any]) -> None:
        if payload["event_id"] in self.fail_ids:
            self.fail_ids.discard(payload["event_id"])
            raise RuntimeError(BODY_TEXT)
        if self.fail_events:
            self.fail_events -= 1
            raise RuntimeError(BODY_TEXT)
        self.events.append(payload)


def adapter(rec: Recorder, clock: FakeClock, rng: random.Random) -> CallbackAdapter:
    return CallbackAdapter(rec.message, rec.event, clock, rng=rng)


async def test_messages_wait_until_open_and_arrive_as_webhook_payloads(
    fake_clock: FakeClock, rng: random.Random
) -> None:
    rec = Recorder()
    a = adapter(rec, fake_clock, rng)
    assert a.name == "sdk"
    assert not a.capabilities().originates
    pending = asyncio.ensure_future(a.deliver(GROUP, SENDER, ["*"], delivery()))
    for _ in range(10):
        await asyncio.sleep(0)
    assert not pending.done()
    assert not a.is_open
    a.open()
    assert await pending is DeliveryResult.ACK
    (payload,) = rec.messages
    assert payload["event"] == "message"
    assert payload["msg_id"] == "m1"
    assert payload["untrusted"] is True
    assert payload["notice"].startswith("Message from remote agent")
    a.pause()
    assert not a.is_open


async def test_a_failing_message_callback_is_retry_and_logs_no_body(
    fake_clock: FakeClock, rng: random.Random, capfd: pytest.CaptureFixture[str]
) -> None:
    rec = Recorder()
    rec.fail_messages = 1
    a = adapter(rec, fake_clock, rng)
    a.open()
    assert await a.deliver(GROUP, SENDER, ["*"], delivery()) is DeliveryResult.RETRY
    assert await a.deliver(GROUP, SENDER, ["*"], delivery()) is DeliveryResult.ACK
    logs = capfd.readouterr().err
    assert "callback_failed" in logs
    assert "RuntimeError" in logs
    assert BODY_TEXT not in logs


async def test_events_need_a_store() -> None:
    a = CallbackAdapter(Recorder().message, Recorder().event, FakeClock())
    with pytest.raises(RuntimeError, match="no store"):
        await a.on_event(GROUP, Event("member_joined", "g1", {}, "e1"))


async def test_events_are_queued_durably_and_retried_in_order(
    fake_clock: FakeClock, rng: random.Random, store: Store
) -> None:
    rec = Recorder()
    a = adapter(rec, fake_clock, rng)
    a.bind_store(store)
    await a.on_outbound(lambda *_a, **_k: asyncio.sleep(0, "x"))
    await a.on_outbound(lambda *_a, **_k: asyncio.sleep(0, "x"))  # one worker only
    await a.on_event(GROUP, Event("member_joined", "g1", {"n": 1}, "e1"))
    await a.on_event(GROUP, Event("member_joined", "g1", {"n": 1}, "e1"))  # a repeat
    await a.on_event(None, Event("epoch_changed", None, {"n": 2}, "e2"))
    for _ in range(10):
        await asyncio.sleep(0)
    assert rec.events == []  # not open yet: they wait in the store
    assert [p["event_id"] for _, p in store.adapter_events("sdk")] == ["e1", "e2"]
    rec.fail_ids = {"e1"}
    a.open()
    # g1's event backs off after its failure; the other group's isn't held up.
    await until(lambda: fake_clock.sleepers == 1 and len(rec.events) == 1)
    assert [e["event_id"] for e in rec.events] == ["e2"]
    assert rec.events[0]["group"] is None
    fake_clock.advance(10)
    await until(lambda: len(rec.events) == 2)
    assert [e["event_id"] for e in rec.events] == ["e2", "e1"]
    await until(lambda: store.adapter_events("sdk") == [])
    # Paused, a new event waits; reopened, it goes.
    a.pause()
    await a.on_event(GROUP, Event("member_left", "g1", {}, "e3"))
    for _ in range(10):
        await asyncio.sleep(0)
    assert len(rec.events) == 2
    a.open()
    await until(lambda: len(rec.events) == 3)
    await a.close()
    await a.close()  # idempotent


def test_the_event_queue_is_bounded(store: Store) -> None:
    for n in range(5):
        assert store.adapter_event_add("sdk", f"e{n}", {"n": n}, keep=3)
    assert not store.adapter_event_add("sdk", "e4", {"n": 4}, keep=3)
    assert [p["n"] for _, p in store.adapter_events("sdk")] == [2, 3, 4]
    assert store.adapter_events("other") == []


def test_handled_ids_are_bounded(store: Store) -> None:
    for n in range(5):
        store.handled_add(f"k{n}", keep=3)
    store.handled_add("k4", keep=3)  # a repeat changes nothing
    assert [store.handled_has(f"k{n}") for n in range(5)] == [False, False, True, True, True]


async def test_a_handler_past_the_timeout_is_cancelled_and_retried(
    fake_clock: FakeClock, rng: random.Random
) -> None:
    cancelled: list[str] = []

    async def stuck(_payload: dict[str, Any]) -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.append("message")
            raise

    a = CallbackAdapter(stuck, stuck, fake_clock, timeout=30, rng=rng)
    a.open()
    pending = asyncio.ensure_future(a.deliver(GROUP, SENDER, ["*"], delivery()))
    await until(a.busy)
    for _ in range(10):  # the timer starts in its own task
        await asyncio.sleep(0)
    assert fake_clock.sleepers == 0  # a deadline, not a retry pause
    fake_clock.advance(29)
    for _ in range(10):
        await asyncio.sleep(0)
    assert not pending.done()
    fake_clock.advance(2)
    assert await pending is DeliveryResult.RETRY
    assert cancelled == ["message"]


async def test_handler_tasks_are_known_while_they_run(
    fake_clock: FakeClock, rng: random.Random
) -> None:
    inside: list[bool] = []

    async def check(_payload: dict[str, Any]) -> None:
        inside.append(a.in_handler())

    a = CallbackAdapter(check, check, fake_clock, rng=rng)
    a.open()
    assert not a.in_handler()
    assert await a.deliver(GROUP, SENDER, ["*"], delivery()) is DeliveryResult.ACK
    assert inside == [True]
    assert await a.drain(1.0)  # nothing in flight


def test_handled_ids_from_before_namespacing_are_cleared(
    tmp_path: Path, rng: random.Random
) -> None:
    key = rng.randbytes(32)
    s = Store(tmp_path / "h.sqlite3", key)
    s.handled_add("bare-msg-id", keep=10)  # the old, un-namespaced form
    s.handled_add('["event","e1"]', keep=10)
    s.close()
    s = Store(tmp_path / "h.sqlite3", key)
    assert not s.handled_has("bare-msg-id")
    assert s.handled_has('["event","e1"]')
    s.close()
