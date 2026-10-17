"""The SSE hub over a durable feed: replay, filtering, ids and back-pressure."""

from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path

import pytest

from agentconnect.adapter import Delivery, DeliveryResult, Event, GroupView, Sender
from agentconnect.sse import Item, SseAdapter
from agentconnect.store import Store

G1 = GroupView("g1", "One", "p", 1, "free")
G2 = GroupView("g2", "Two", "p", 1, "free")
SENDER = Sender("ac:v0:peer", "i1", None, False)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "daemon.sqlite3", secrets.token_bytes(32))


@pytest.fixture
def hub(store: Store) -> SseAdapter:
    return SseAdapter(store)


def delivery(group: GroupView, msg_id: str) -> Delivery:
    return Delivery(
        group.group_id,
        msg_id,
        "a2a.message",
        {"text": msg_id},
        SENDER,
        ["*"],
        True,
        "p",
        {"self": "unverified", "verified_members": 0, "members": 2},
        "agent",
        1,
        {},
    )


async def put(hub: SseAdapter, group: GroupView, msg_id: str) -> DeliveryResult:
    d = delivery(group, msg_id)
    return await hub.deliver(group, d.sender, d.to, d)


def drain(queue: asyncio.Queue[Item]) -> list[str]:
    out = []
    while not queue.empty():
        out.append(str(queue.get_nowait().payload["msg_id"]))
    return out


async def test_no_listener_means_retry_so_the_daemon_keeps_the_message(hub: SseAdapter) -> None:
    assert await put(hub, G1, "m1") is DeliveryResult.RETRY
    sub = hub.subscribe("g2", None)  # listens to another group only
    assert await put(hub, G1, "m1") is DeliveryResult.RETRY
    assert await put(hub, G2, "m2") is DeliveryResult.ACK
    assert drain(sub.queue) == ["m2"]


async def test_resume_replays_after_the_given_id(hub: SseAdapter) -> None:
    first = hub.subscribe(None, None)
    for i in range(1, 4):
        await put(hub, G1, f"m{i}")
    items = [first.queue.get_nowait() for _ in range(3)]
    assert [i.id for i in items] == ["1", "2", "3"]
    hub.unsubscribe(first)

    resumed = hub.subscribe(None, items[0].id)
    assert drain(resumed.queue) == ["m2", "m3"]
    live = hub.subscribe(None, None)  # no id: live only
    assert live.queue.empty()
    await put(hub, G1, "m4")
    assert drain(live.queue) == ["m4"]
    assert drain(resumed.queue) == ["m4"]


async def test_resume_survives_a_new_hub_on_the_same_store(store: Store) -> None:
    """A daemon restart builds a new hub over the same database."""
    before = SseAdapter(store)
    sub = before.subscribe(None, None)
    await put(before, G1, "m1")
    await put(before, G1, "m2")
    first = sub.queue.get_nowait()

    after = SseAdapter(store)
    assert drain(after.subscribe(None, first.id).queue) == ["m2"]
    assert after.subscribe(None, None).queue.empty()


async def test_a_message_handed_over_again_is_not_appended_twice(
    hub: SseAdapter, store: Store
) -> None:
    sub = hub.subscribe(None, None)
    await put(hub, G1, "m1")
    await put(hub, G1, "m1")
    assert drain(sub.queue) == ["m1"]
    assert len(store.feed_since(0)) == 1


@pytest.mark.parametrize("bad", ["junk", "x.y", "1.2", "", "-1", "٣"])
async def test_malformed_resume_ids_start_live(hub: SseAdapter, bad: str) -> None:
    hub.subscribe(None, None)
    await put(hub, G1, "m1")
    assert hub.subscribe(None, bad).queue.empty()


async def test_group_filter_applies_to_replay_and_live(hub: SseAdapter) -> None:
    keep = hub.subscribe(None, None)
    await put(hub, G1, "a")
    await put(hub, G2, "b")
    first_id = keep.queue.get_nowait().id
    sub = hub.subscribe("g2", first_id)
    assert drain(sub.queue) == ["b"]
    await put(hub, G1, "c")
    assert sub.queue.empty()


async def test_events_are_published_with_their_event_id(hub: SseAdapter) -> None:
    sub = hub.subscribe(None, None)
    await hub.on_event(G1, Event("member_joined", "g1", {"k": 1}, "e1"))
    await hub.on_event(None, Event("relay_misbehaviour", None, {}, "e2"))
    await hub.on_event(G1, Event("member_joined", "g1", {"k": 1}, "e1"))  # sent again
    a, b = sub.queue.get_nowait(), sub.queue.get_nowait()
    assert sub.queue.empty()
    assert a.payload["event_id"] == "e1"
    assert b.payload["group"] is None
    frame = a.frame().decode()
    assert frame.startswith(f"id: {a.id}\nevent: member_joined\ndata: ")
    assert frame.endswith("\n\n")
    assert json.loads(frame.split("data: ", 1)[1])["data"] == {"k": 1}
    assert hub.capabilities().originates is False
    await hub.on_outbound(_noop)


async def _noop(*_a: object, **_k: object) -> str:
    return ""


async def test_a_slow_consumer_is_dropped_and_can_resume(
    hub: SseAdapter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentconnect.sse.SUBSCRIBER_QUEUE", 2)
    sub = hub.subscribe(None, None)
    for i in range(4):
        await put(hub, G1, f"m{i}")
    assert sub.overflowed
    assert not hub.has_listener("g1")
    assert await put(hub, G1, "m4") is DeliveryResult.RETRY
    last = sub.queue.get_nowait()
    resumed = hub.subscribe(None, last.id)
    assert drain(resumed.queue) == ["m1", "m2"]  # the feed has what it accepted


async def test_the_feed_is_bounded(store: Store) -> None:
    for i in range(5):
        store.feed_add(f"k{i}", "g1", {"event": "message", "msg_id": f"m{i}"}, keep=2)
    assert [p["msg_id"] for _, _, p in store.feed_since(0)] == ["m3", "m4"]
    assert store.feed_last() == 5


async def test_an_empty_feed_has_last_seq_zero(store: Store) -> None:
    assert store.feed_last() == 0


async def test_wait_listeners(hub: SseAdapter) -> None:
    waiter = asyncio.create_task(hub.wait_listeners(1))
    await asyncio.sleep(0)
    assert not waiter.done()
    sub = hub.subscribe(None, None)
    await waiter
    gone = asyncio.create_task(hub.wait_listeners(0))
    await asyncio.sleep(0)
    hub.unsubscribe(sub)
    await gone


def test_an_unbound_hub_refuses_to_run() -> None:
    with pytest.raises(RuntimeError, match="no feed"):
        SseAdapter().subscribe(None, None)
