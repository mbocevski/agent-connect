"""A group that delivers to several adapters (`daemon.adapters`, a group's
pinned list): every adapter gets every message and event, in order, and
each keeps its own delivery state, so one slow or failing adapter neither
holds up nor loses another's deliveries. The relay is acked once a message
is recorded in the inbox (ADR-004).

The embedded SDK and MCP hosts deliver to their one adapter, so these
scenarios run on the daemon host."""

from __future__ import annotations

import asyncio
import dataclasses
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
    _text_of,
)
from agentconnect.clock import Clock
from agentconnect.config import Config
from agentconnect.identity import load_db_key
from agentconnect.keystore import FileKeystore
from agentconnect.runtime.engine import DaemonError
from agentconnect.store import Store
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


# -- routing guarantees: upgrades, pins, back-pressure, triggering -----------------


class Echo(RecordingAdapter):
    """An answering agent: replies once to every a2a.message that triggers it."""

    def __init__(self, name: str = "recording") -> None:
        super().__init__(name)
        self.sent = 0

    @override
    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        result = await super().deliver(group, sender, to, inner)
        if inner.kind == "a2a.message" and inner.addressed_to_me and self.send is not None:
            self.sent += 1
            await self.send(inner.group_id, {"text": f"re:{self.name}"}, reply_to=[inner.msg_id])
        return result


class Gated(RecordingAdapter):
    """Answers RETRY ``retry_next`` times, then takes a delivery only once
    ``go`` is set."""

    def __init__(self, name: str = "gated") -> None:
        super().__init__(name)
        self.go = asyncio.Event()
        self.waiting = 0

    @override
    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        if self.retry_next > 0:
            return await super().deliver(group, sender, to, inner)
        self.waiting += 1
        self._poke()
        await self.go.wait()
        return await super().deliver(group, sender, to, inner)


class Blackhole(RecordingAdapter):
    """Takes messages, but never returns from ``on_event``."""

    @override
    async def on_event(self, group: GroupView | None, event: Event) -> None:
        await asyncio.Event().wait()


def recorded(node: Node, kind: str) -> list[dict[str, Any]]:
    return [e for e in node.daemon.store.events(0, limit=10_000) if e["type"] == kind]


def pending_texts(node: Node) -> list[str]:
    out = []
    for row in node.daemon.store.pending_deliveries():
        assert row.delivery is not None
        out.append(_text_of(Delivery.from_json(row.delivery).body))
    return out


def open_store(node: Node) -> Store:
    """The node's daemon database, opened as the runtime does (stopped)."""
    data = node.config.data_dir
    key = load_db_key(FileKeystore(data / "keys"), (data / "mls.sqlite3", data / "daemon.sqlite3"))
    return Store(data / "daemon.sqlite3", key)


async def test_an_upgrade_keeps_a_group_on_the_adapter_it_was_bound_to(
    cluster: Cluster,
) -> None:
    """Before `daemon.adapters`, a group stayed on the adapter it was bound
    to while that adapter ran (one daemon could serve an A2A agent in some
    groups and a webhook agent in others, ADR-005). The upgrade pins such a
    group to that adapter; one bound to what the config gives follows it."""
    other = RecordingAdapter("second")
    a = await cluster.node("a", adapters=("recording",), make_adapters=extra(other))
    b = await cluster.node("b")
    bound = a.daemon.create_group("Agent X", "X's group")
    plain = a.daemon.create_group("Agent Y", "Y's group")
    await a.idle()
    await cluster.invite(a, b, bound)
    await cluster.invite(a, b, plain)
    await a.stop()
    # The database as it was before: one adapter per group, no list.
    s = open_store(a)
    with s.tx() as raw:
        raw.execute("UPDATE groups SET adapter = 'second' WHERE group_id = ?", (bound,))
        raw.execute("UPDATE groups SET adapter = 'recording' WHERE group_id = ?", (plain,))
        raw.execute("ALTER TABLE groups DROP COLUMN adapters")
    s.close()
    await a.start()
    assert a.daemon.group_info(bound)["adapters"] == ["second"]
    assert a.daemon.group_info(plain)["adapters"] is None
    b.daemon.send_message(bound, {"text": "for agent X only"})
    b.daemon.send_message(plain, {"text": "for agent Y"})
    assert await a.wait_texts(plain, 1) == ["for agent Y"]
    await other.wait_for(lambda: other.texts(bound) == ["for agent X only"], WAIT)
    assert a.adapter.texts(bound) == []


async def test_a_pinned_list_with_nothing_running_holds_the_group(cluster: Cluster) -> None:
    """A pin is never overridden: with none of its adapters running, the
    group's messages wait (nothing is settled or deleted), the human hears
    of it once, and they go out once the adapter is back."""
    second = RecordingAdapter("second")
    a, b, gid = await pair(cluster, second)
    a.daemon.set_adapters(gid, ["second"])
    b.daemon.send_message(gid, {"text": "before"})
    await second.wait_for(lambda: second.texts(gid) == ["before"], WAIT)
    # The operator drops "second" from the runtime and restarts, twice.
    for _ in range(2):
        await a.stop()
        a.config = dataclasses.replace(a.config, adapters=("recording",))
        a.make_adapters = None
        await a.start()
    info = a.daemon.group_info(gid)
    assert (info["adapters"], info["delivers_to"], info["delivery_held"]) == (
        ["second"],
        [],
        True,
    )
    b.daemon.send_message(gid, {"text": "after"})
    await a.wait(lambda: pending_texts(a) == ["after"])
    assert a.adapter.texts(gid) == []
    (held,) = recorded(a, "adapter_unavailable")
    assert held["group_id"] == gid
    assert held["data"]["adapters"] == ["second"]
    assert not [e for e in a.adapter.events if e.type == "adapter_unavailable"]
    # "second" is back: it gets what waited for it.
    back = RecordingAdapter("second")
    await a.stop()
    a.config = dataclasses.replace(a.config, adapters=("recording", "second"))
    a.make_adapters = extra(back)
    await a.start()
    await back.wait_for(lambda: back.texts(gid) == ["after"], WAIT)
    await a.wait(lambda: not a.daemon.store.pending_deliveries())
    assert len(recorded(a, "adapter_available")) == 1
    assert a.daemon.group_info(gid)["delivery_held"] is False


async def test_a_dead_adapter_stops_the_early_ack_past_the_pending_limits(
    cluster: Cluster,
    partition: Cut,
    heal: Cut,
    advance: Advance,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acking the relay once a message is recorded must not lift the bound
    the relay mailbox gave: past a group's pending limits (bytes, or the
    age of its oldest pending message) the daemon stops acking that group
    early, so the relay mailbox fills as before, and the human hears which
    adapter is behind. Early acks resume once the pending messages drain."""
    monkeypatch.setattr("agentconnect.runtime.engine.PENDING_MAX_BYTES", 4096)
    stuck = Stuck()
    a, b, gid = await pair(cluster, stuck)
    sent = [f"secret-{i}-" + "x" * 900 for i in range(8)]
    for text in sent:
        b.daemon.send_message(gid, {"text": text})
    assert await a.wait_texts(gid, 8) == sent
    await a.wait(lambda: bool(recorded(a, "delivery_stalled")))
    (stalled,) = recorded(a, "delivery_stalled")
    assert stalled["data"]["adapters"] == ["stuck"]
    # Past the limit the relay keeps its copies: a reconnect brings them back.
    seen = application_frames(a)
    await partition(a)
    await heal(a)
    await a.wait(a.daemon.caught_up)
    assert application_frames(a) > seen
    assert len(recorded(a, "delivery_stalled")) == 1
    # The adapter catches up: the pending messages drain, and the early ack is back.
    stuck.working = True
    await advance(300)
    await a.wait(lambda: not a.daemon.store.pending_deliveries())
    await a.wait(lambda: bool(recorded(a, "delivery_resumed")))
    seen = application_frames(a)
    await partition(a)
    await heal(a)
    await a.wait(a.daemon.caught_up)
    assert application_frames(a) == seen
    # Age alone stalls it too: one message older than the relay keeps one.
    stuck.working = False
    b.daemon.send_message(gid, {"text": "old"})
    await a.wait(lambda: pending_texts(a) == ["old"])
    await until(lambda: a.clock.sleepers > 0)
    await advance(8 * 24 * 3600)
    await a.wait(lambda: len(recorded(a, "delivery_stalled")) == 2)


async def test_an_adapter_taken_out_gets_nothing_more_of_its_batch(
    cluster: Cluster, advance: Advance
) -> None:
    gated = Gated()
    gated.retry_next = 1  # one RETRY first, so its next batch holds all three
    a, b, gid = await pair(cluster, gated)
    for text in TEXTS:
        b.daemon.send_message(gid, {"text": text})
    assert await a.wait_texts(gid, 3) == TEXTS
    await gated.wait_for(lambda: gated.retry_next == 0, WAIT)
    await until(lambda: a.clock.sleepers > 0)
    await advance(300)
    await gated.wait_for(lambda: gated.waiting == 1, WAIT)
    a.daemon.set_adapters(gid, ["recording"])
    await a.wait(lambda: not a.daemon.store.pending_deliveries())
    gated.go.set()
    await gated.wait_for(lambda: len(gated.texts(gid)) >= 1, WAIT)
    for _ in range(20):
        await asyncio.sleep(0)
    assert gated.texts(gid) == ["one"], "only the one already in its hands"


async def _replies(cluster: Cluster, names: tuple[str, ...], tag: str) -> int:
    """How many agent replies one human message causes, with ``names``
    answering on one side and one agent on the other."""
    echoes = [Echo(n) for n in names]
    a = await cluster.node(
        f"a{tag}", adapters=names, default_adapter=names[0], make_adapters=extra(*echoes[1:])
    )
    a.adapter = echoes[0]
    await a.restart()
    b_echo = Echo()
    b = await cluster.node(f"b{tag}")
    b.adapter = b_echo
    await b.restart()
    gid = a.daemon.create_group("Team", "replies", {"max_agent_turns": 4})
    await a.idle()
    await cluster.invite(a, b, gid)
    b.daemon.send_message(gid, {"text": "go"}, origin="human")

    def quiet() -> bool:
        return all(
            not n.daemon.store.pending_deliveries() and not n.daemon.store.outbox() for n in (a, b)
        )

    await a.wait(
        lambda: any(
            e["type"] == "loop_guard"
            for n in (a, b)
            for e in n.daemon.store.events(0, limit=10_000)
        )
    )
    await a.wait(quiet)
    return sum(e.sent for e in echoes) + b_echo.sent


async def test_two_answering_adapters_reply_no_more_than_one(cluster: Cluster) -> None:
    """One adapter is triggered by a message, the others get it as context,
    so a second answering adapter doesn't multiply the replies."""
    assert await _replies(cluster, ("recording", "second"), "2") == await _replies(
        cluster, ("recording",), "1"
    )


async def test_a_reply_triggers_the_adapter_that_sent_the_message_it_answers(
    cluster: Cluster,
) -> None:
    facade = RecordingAdapter("second")  # sends through on_outbound, as the facade does
    a, b, gid = await pair(cluster, facade)
    assert facade.send is not None
    receipt = await facade.send(gid, {"text": "question from the facade client"})
    await b.wait_texts(gid, 1)
    b.daemon.send_message(gid, {"text": "for the facade client"}, reply_to=[str(receipt)])
    b.daemon.send_message(gid, {"text": "for anyone"}, origin="human")
    await a.wait_texts(gid, 2)
    await facade.wait_for(lambda: len(facade.texts(gid)) == 2, WAIT)
    first = {_text_of(d.body): d.addressed_to_me for d in a.adapter.deliveries}
    other = {_text_of(d.body): d.addressed_to_me for d in facade.deliveries}
    first.pop("", None)
    other.pop("", None)
    assert first == {"for the facade client": False, "for anyone": True}
    assert other == {"for the facade client": True, "for anyone": False}


async def test_an_adapter_that_never_returns_from_an_event_holds_up_nothing_else(
    cluster: Cluster,
) -> None:
    """Events go out from each adapter's own worker: one stuck in
    ``on_event`` stalls neither the inbound worker nor the other adapters."""
    hole = Blackhole("hole")
    a = await cluster.node("a", adapters=("hole", "recording"), make_adapters=extra(hole))
    b = await cluster.node("b")
    gid = a.daemon.create_group("Team", "Plan the release")
    await a.idle()
    await cluster.invite(a, b, gid)
    for text in TEXTS:
        b.daemon.send_message(gid, {"text": text})
    assert await a.wait_texts(gid, 3) == TEXTS
    await a.adapter.wait_for(lambda: bool(a.adapter.of_type("member_joined")), WAIT)
    await hole.wait_for(lambda: len(hole.texts(gid)) == 3, WAIT)


async def test_settling_runs_when_a_groups_list_changes_not_on_every_wake(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    stuck = Stuck()
    a, b, gid = await pair(cluster, stuck)
    calls: list[str] = []
    real = a.daemon.store.settle_deliveries

    def counted(group_id: str, targets: list[str]) -> int:
        calls.append(group_id)
        return real(group_id, targets)

    monkeypatch.setattr(a.daemon.store, "settle_deliveries", counted)
    for text in TEXTS:
        b.daemon.send_message(gid, {"text": text})
    assert await a.wait_texts(gid, 3) == TEXTS
    assert len(calls) <= 1
    a.daemon.set_adapters(gid, ["recording"])
    await a.wait(lambda: not a.daemon.store.pending_deliveries())
    assert len(calls) <= 2
