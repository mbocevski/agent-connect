"""A group that delivers to several adapters (`daemon.adapters`, a group's
pinned list): every adapter gets every message and event, in order, and
each keeps its own delivery state, so one slow or failing adapter neither
holds up nor loses another's deliveries. The relay is acked once a message
is recorded in the inbox (ADR-004).

The embedded SDK and MCP hosts deliver to their one adapter, so these
scenarios run on the daemon host."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, override

import pytest

from agentconnect.adapter import (
    Adapter,
    Delivery,
    DeliveryResult,
    Event,
    GroupView,
    RecordingAdapter,
    Sender,
)
from agentconnect.clock import Clock
from agentconnect.config import Config
from agentconnect.runtime.engine import DaemonError
from agentconnect_harness.cluster import WAIT, Cluster, Node

pytestmark = pytest.mark.hosts("daemon")

Advance = Callable[[float], Awaitable[None]]
Cut = Callable[[Node], Awaitable[None]]
TEXTS = ["one", "two", "three"]


class Stuck(RecordingAdapter):
    """Answers ``RETRY`` to every delivery and fails every event until
    ``working`` is set: an adapter whose endpoint is down."""

    def __init__(self, name: str = "stuck") -> None:
        super().__init__(name)
        self.working = False
        self.refused = 0

    @override
    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        if not self.working:
            self.refused += 1
            self._poke()
            return DeliveryResult.RETRY
        return await super().deliver(group, sender, to, inner)

    @override
    async def on_event(self, group: GroupView | None, event: Event) -> None:
        if not self.working:
            msg = "endpoint down"
            raise RuntimeError(msg)
        await super().on_event(group, event)


class Slow(RecordingAdapter):
    """Takes a delivery only once ``go`` is set: an agent turn that takes long."""

    def __init__(self, name: str = "slow") -> None:
        super().__init__(name)
        self.go = asyncio.Event()
        self.waiting = 0

    @override
    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        self.waiting += 1
        self._poke()
        await self.go.wait()
        return await super().deliver(group, sender, to, inner)


def extra(*adapters: Adapter) -> Callable[[Config, Clock], list[Adapter]]:
    return lambda _config, _clock: list(adapters)


async def pair(cluster: Cluster, other: RecordingAdapter, **kw: Any) -> tuple[Node, Node, str]:
    """``a`` delivering to its recording adapter and ``other``, in a group
    with ``b``."""
    a = await cluster.node(
        "a", adapters=("recording", other.name), make_adapters=extra(other), **kw
    )
    b = await cluster.node("b")
    gid = a.daemon.create_group("Team", "Plan the release")
    await a.idle()
    await cluster.invite(a, b, gid)
    return a, b, gid


def application_frames(node: Node) -> int:
    return len([f for f in node.proxy.delivered if f["env"].get("kind") == "application"])


async def test_a_group_delivers_to_every_adapter_in_its_list(cluster: Cluster) -> None:
    second = RecordingAdapter("second")
    a, b, gid = await pair(cluster, second)
    for text in TEXTS:
        b.daemon.send_message(gid, {"text": text})
    assert await a.wait_texts(gid, 3) == TEXTS
    await second.wait_for(lambda: len(second.texts(gid)) == 3, WAIT)
    assert second.texts(gid) == TEXTS
    joined = {e.event_id for e in a.adapter.of_type("member_joined")}
    assert joined
    assert joined == {e.event_id for e in second.of_type("member_joined")}
    await a.wait(lambda: not a.daemon.store.pending_deliveries())
    info = a.daemon.group_info(gid)
    assert (info["adapters"], info["delivers_to"]) == (None, ["recording", "second"])
    # The human pins one adapter: only it gets what comes next.
    a.daemon.set_adapters(gid, ["second"])
    assert a.daemon.group_info(gid)["delivers_to"] == ["second"]
    b.daemon.send_message(gid, {"text": "four"})
    await second.wait_for(lambda: len(second.texts(gid)) == 4, WAIT)
    await a.wait(lambda: not a.daemon.store.pending_deliveries())
    assert a.adapter.texts(gid) == TEXTS
    # Unpinned, the group follows the config again.
    a.daemon.set_adapters(gid, None)
    b.daemon.send_message(gid, {"text": "five"})
    assert (await a.wait_texts(gid, 4))[-1] == "five"
    with pytest.raises(DaemonError, match="not an adapter"):
        a.daemon.set_adapters(gid, ["carrier-pigeon"])
    with pytest.raises(DaemonError, match="more than once"):
        a.daemon.set_adapters(gid, ["second", "second"])


async def test_a_failing_adapter_holds_up_and_loses_nothing_for_another(
    cluster: Cluster, partition: Cut, heal: Cut, advance: Advance
) -> None:
    stuck = Stuck()
    a, b, gid = await pair(cluster, stuck)
    for text in TEXTS:
        b.daemon.send_message(gid, {"text": text})
    # The working adapter gets everything, in order, while the other refuses.
    assert await a.wait_texts(gid, 3) == TEXTS
    await stuck.wait_for(lambda: stuck.refused > 0, WAIT)
    assert stuck.texts(gid) == []
    assert a.adapter.of_type("member_joined")
    # The relay was acked once the messages were recorded: a reconnect
    # brings none of them back.
    seen = application_frames(a)
    await partition(a)
    await heal(a)
    await a.wait(a.daemon.caught_up)
    assert application_frames(a) == seen
    # The endpoint comes back: it gets what it missed, in order, once.
    stuck.working = True
    await advance(300)
    await stuck.wait_for(lambda: len(stuck.texts(gid)) == 3, WAIT)
    assert stuck.texts(gid) == TEXTS
    await a.wait(lambda: not a.daemon.store.pending_deliveries())
    # Events it failed are told again on the next connect, to it alone.
    await partition(a)
    await heal(a)
    await stuck.wait_for(lambda: bool(stuck.of_type("member_joined")), WAIT)
    await a.wait(lambda: not a.daemon.store.unnotified_events())
    for adapter in (a.adapter, stuck):
        assert len(adapter.events) == len(adapter.unique_events()), adapter.name
    assert {e.event_id for e in stuck.events} == {e.event_id for e in a.adapter.events}


async def test_a_slow_adapter_holds_up_only_itself(cluster: Cluster) -> None:
    slow = Slow()
    a, b, gid = await pair(cluster, slow)
    for text in TEXTS:
        b.daemon.send_message(gid, {"text": text})
    assert await a.wait_texts(gid, 3) == TEXTS
    await slow.wait_for(lambda: slow.waiting == 1, WAIT)
    assert slow.texts(gid) == []
    slow.go.set()
    await slow.wait_for(lambda: len(slow.texts(gid)) == 3, WAIT)
    assert slow.texts(gid) == TEXTS


async def until(predicate: Callable[[], bool]) -> None:
    """Poll (yielding to the loop): a crashed worker announces nothing."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing to wait on after a crash
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


@pytest.mark.parametrize("mode", ["raise", "crash"])
async def test_a_crash_after_one_adapter_took_a_message(
    cluster: Cluster, advance: Advance, mode: str
) -> None:
    """ADR-004 with per-adapter markers: a failure between an adapter
    accepting a message and its marker being recorded hands it to that
    adapter again (at least once), and to no other adapter twice."""
    seconds: list[RecordingAdapter] = []

    def make(_config: Config, _clock: Clock) -> list[Adapter]:
        seconds.append(RecordingAdapter("second"))
        return [seconds[-1]]

    a = await cluster.node("a", adapters=("recording", "second"), make_adapters=make)
    b = await cluster.node("b")
    gid = a.daemon.create_group("Team", "Plan the release")
    await a.idle()
    await cluster.invite(a, b, gid)
    a.daemon.failpoints.arm("delivery.after_adapter", "crash" if mode == "crash" else "raise")
    b.daemon.send_message(gid, {"text": "one"})
    await until(lambda: "delivery.after_adapter" in a.daemon.failpoints.fired)
    if mode == "crash":
        await a.restart()
    else:
        await until(lambda: a.clock.sleepers > 0)
        await advance(300)
    await a.wait(lambda: not a.daemon.store.pending_deliveries())
    counts = sorted(
        [a.adapter.texts(gid).count("one"), sum(s.texts(gid).count("one") for s in seconds)]
    )
    assert counts == [1, 2], "the adapter that wasn't recorded gets it again, the other once"


@pytest.mark.parametrize("mode", ["raise", "crash"])
async def test_a_crash_after_one_adapter_heard_of_an_event(
    cluster: Cluster, mode: str, partition: Cut, heal: Cut
) -> None:
    seconds: list[RecordingAdapter] = []

    def make(_config: Config, _clock: Clock) -> list[Adapter]:
        seconds.append(RecordingAdapter("second"))
        return [seconds[-1]]

    a = await cluster.node("a", adapters=("recording", "second"), make_adapters=make)
    b = await cluster.node("b")
    gid = a.daemon.create_group("Team", "Plan the release")
    await a.idle()
    a.daemon.failpoints.arm("event.after_notify", "crash" if mode == "crash" else "raise")
    await cluster.invite(a, b, gid)
    await until(lambda: "event.after_notify" in a.daemon.failpoints.fired)
    if mode == "crash":
        await a.restart()
    else:
        await partition(a)
        await heal(a)
    await a.wait(lambda: not a.daemon.store.unnotified_events())
    mine = {e.event_id for e in a.adapter.events}
    theirs = {e.event_id for s in seconds for e in s.events}
    assert mine == theirs
    joined = [e for e in a.adapter.of_type("member_joined") if e.data.get("identity") == b.me]
    assert len({e.event_id for e in joined}) == 1


async def test_an_adapter_taken_out_of_the_list_holds_up_nothing(cluster: Cluster) -> None:
    """What waited only for an adapter the group no longer delivers to (the
    human pinned a list without it, or the config names one the runtime
    doesn't have) is done, and its plaintext goes."""
    stuck = Stuck()
    a, b, gid = await pair(cluster, stuck)
    for text in TEXTS:
        b.daemon.send_message(gid, {"text": text})
    assert await a.wait_texts(gid, 3) == TEXTS
    await stuck.wait_for(lambda: stuck.refused > 0, WAIT)
    assert a.daemon.store.pending_deliveries()
    a.daemon.set_adapters(gid, ["recording"])
    await a.wait(lambda: not a.daemon.store.pending_deliveries())
    assert stuck.texts(gid) == []
    # A name the runtime has no adapter for is skipped.
    c = await cluster.node("c", adapters=("recording", "gone"))
    await cluster.invite(a, c, gid)
    b.daemon.send_message(gid, {"text": "four"})
    assert (await c.wait_texts(gid, 1)) == ["four"]
    await c.wait(lambda: not c.daemon.store.pending_deliveries())
    assert c.daemon.adapter_names(gid) == ["recording"]
