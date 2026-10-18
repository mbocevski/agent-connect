"""Crash consistency (ADR-004): a failure or a crash at every step boundary
of receive, own-commit confirmation and Welcome processing, in the core and
in the daemon, loses nothing and duplicates nothing, and epochs and SAS
converge.

Daemon failpoints either *raise* (a transient failure the daemon retries
after a backoff) or *crash* (the worker dies on the spot; the node is then
restarted with nothing flushed). Core failpoints fail the core's transaction
with a storage error (``error``: retried) or a panic (``panic``: the node is
restarted once the daemon is waiting to retry)."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable

import pytest

from agentconnect.failpoints import FailpointError, SimulatedCrash
from agentconnect_harness.cluster import WAIT, Cluster, Node, status
from agentconnect_harness.proxy import RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]
Proxy = Callable[[Node], RelayProxy]
Cut = Callable[[Node], Awaitable[None]]

STEPS = ("before_core", "after_core", "in_tx", "after_tx", "after_consume")
MODES = ("raise", "crash")


def raw(gid: str) -> bytes:
    return base64.urlsafe_b64decode(gid + "=" * (-len(gid) % 4))


async def until(predicate: Callable[[], bool]) -> None:
    """Poll (yielding to the loop) until ``predicate`` holds: a crashed
    worker announces nothing, so the daemon's change pulses can't be used."""

    async def loop() -> None:
        while not predicate():  # noqa: ASYNC110 - nothing to wait on after a crash
            await asyncio.sleep(0)

    await asyncio.wait_for(loop(), WAIT)


async def recover(node: Node, advance: Advance, mode: str, fired: Callable[[], bool]) -> None:
    """Wait for the failpoint, then restart the node (crash, panic) or let
    the daemon's retry run (raise, error)."""
    await until(fired)
    if mode in ("crash", "panic"):
        await node.restart()
        return
    await until(lambda: node.clock.sleepers > 0)
    await advance(300)


def daemon_point(node: Node, point: str, mode: str) -> Callable[[], bool]:
    node.daemon.failpoints.arm(point, "crash" if mode == "crash" else "raise")
    return lambda: point in node.daemon.failpoints.fired


def core_point(node: Node, point: str, mode: str) -> Callable[[], bool]:
    node.daemon.client._arm_failpoint_for_testing(point, mode)
    # The daemon retries a transient core failure after a backoff.
    return lambda: node.clock.sleepers > 0


def events(node: Node, kind: str) -> list[dict[str, object]]:
    return [e["data"] for e in node.daemon.store.events() if e["type"] == kind]


async def settled(nodes: list[Node], gid: str) -> None:
    """Every node at the same epoch and SAS, nothing left in a journal.

    A commit still in flight (a removal, a rebuilt intent) can move one node
    on while the others are being checked, so this repeats until the epochs
    are still equal after every node went idle."""

    def epochs() -> set[int]:
        return {n.daemon.client.epoch(raw(gid)) for n in nodes}

    for _ in range(10):
        await until(lambda: len(epochs()) == 1)
        for n in nodes:
            await n.wait(lambda n=n: n.epoch(gid) == n.daemon.client.epoch(raw(gid)))
            await n.idle()
            await until(lambda n=n: n.daemon.client.journal_pending() == [])
        if len(epochs()) == 1:
            break
    assert len(epochs()) == 1
    assert len({n.sas(gid) for n in nodes}) == 1
    for n in nodes:
        assert not n.daemon.group_info(gid)["out_of_sync"]


async def exactly(node: Node, gid: str, texts: list[str]) -> None:
    await node.adapter.wait_for(lambda: len(node.adapter.texts(gid)) >= len(texts), WAIT)
    await node.idle()
    assert node.adapter.texts(gid) == texts


RECEIVE = [("daemon", f"receive.{s}", m) for s in STEPS for m in MODES] + [
    ("core", p, m)
    for p in ("process.before_mls", "process.after_mls", "process.before_commit")
    for m in ("error", "panic")
]


@pytest.mark.parametrize(("layer", "point", "mode"), RECEIVE)
async def test_an_application_message_is_delivered_exactly_once(
    group: GroupFixture, advance: Advance, layer: str, point: str, mode: str
) -> None:
    (a, b), gid = await group(2)
    fired = (daemon_point if layer == "daemon" else core_point)(b, point, mode)
    a.daemon.send_message(gid, {"text": "one"})
    await recover(b, advance, mode, fired)
    await exactly(b, gid, ["one"])
    a.daemon.send_message(gid, {"text": "two"})
    await exactly(b, gid, ["one", "two"])
    await settled([a, b], gid)
    assert b.daemon.status()["inbox_pending"] == 0


COMMIT = [("daemon", f"receive.{s}", "crash") for s in STEPS] + [
    ("daemon", "receive.in_tx", "raise"),
    ("core", "process.after_merge", "error"),
    ("core", "process.after_merge", "panic"),
]


@pytest.mark.parametrize(("layer", "point", "mode"), COMMIT)
async def test_another_members_commit_is_merged_and_recorded_once(
    group: GroupFixture, advance: Advance, layer: str, point: str, mode: str
) -> None:
    (a, b, c), gid = await group(3)
    epoch = b.epoch(gid)
    fired = (daemon_point if layer == "daemon" else core_point)(b, point, mode)
    a.daemon.update(gid)
    await recover(b, advance, mode, fired)
    await settled([a, b, c], gid)
    assert b.epoch(gid) == epoch + 1
    assert [e["epoch"] for e in events(b, "epoch_changed")].count(epoch + 1) == 1
    a.daemon.send_message(gid, {"text": "after"})
    await exactly(b, gid, ["after"])


CONFIRM = [("daemon", f"confirm.{s}", m) for s in STEPS for m in MODES] + [
    ("core", p, "panic") for p in ("confirm.after_merge", "confirm.before_commit")
]


@pytest.mark.parametrize("case", CONFIRM)
async def test_an_own_commit_is_confirmed_once(
    group: GroupFixture, advance: Advance, malicious_relay: Proxy, case: tuple[str, str, str]
) -> None:
    layer, point, mode = case
    (a, b), gid = await group(2)
    epoch = a.epoch(gid)
    # Only the relay's `accepted` confirms it: the fan-out copy is held back.
    mailbox = a.daemon.mailbox
    malicious_relay(a).drop_deliveries(
        lambda env: env.get("kind") == "commit" and env.get("sender") == mailbox
    )
    fired = (daemon_point if layer == "daemon" else core_point)(a, point, mode)
    a.daemon.update(gid)
    await recover(a, advance, mode, fired)
    await settled([a, b], gid)
    assert a.epoch(gid) == epoch + 1
    assert [e["epoch"] for e in events(a, "epoch_changed")].count(epoch + 1) == 1
    assert not a.adapter.of_type("commit_failed")
    b.daemon.send_message(gid, {"text": "still here"})
    await exactly(a, gid, ["still here"])


WELCOME = [("daemon", f"welcome.{s}", m) for s in STEPS for m in MODES] + [
    ("core", p, m) for p in ("join.after_stage", "join.before_commit") for m in ("error", "panic")
]


@pytest.mark.parametrize("case", WELCOME)
async def test_a_welcome_joins_once(
    cluster: Cluster, group: GroupFixture, advance: Advance, case: tuple[str, str, str]
) -> None:
    layer, point, mode = case
    (a,), gid = await group(1)
    c = await cluster.node("c")
    fired = (daemon_point if layer == "daemon" else core_point)(c, point, mode)
    invite = await a.daemon.create_invite(gid)
    await c.daemon.accept_invite(invite["url"])
    await recover(c, advance, mode, fired)
    await until(lambda: status(c, gid) == "active")
    await settled([a, c], gid)
    assert len(events(c, "joined")) == 1
    assert c.daemon.keystore.get(f"join/{invite['invite_id']}") is None
    assert c.daemon.store.join_status(invite["invite_id"]) == ("joined", gid)
    a.daemon.send_message(gid, {"text": "welcome"})
    await exactly(c, gid, ["welcome"])


@pytest.mark.parametrize("point", ["event.after_record", "event.after_notify"])
async def test_a_security_alert_survives_a_crash_around_notifying(
    group: GroupFixture, advance: Advance, malicious_relay: Proxy, point: str
) -> None:
    (a, b), gid = await group(2)
    epoch = b.epoch(gid)
    # The relay lies about the routing of the next commit b receives: b
    # raises relay_misbehaviour, the first event the commit causes.
    malicious_relay(b).rewrite_routing(add=[a.daemon.mailbox])
    fired = daemon_point(b, point, "crash")
    a.daemon.update(gid)
    await recover(b, advance, "crash", fired)
    await settled([a, b], gid)
    await until(lambda: b.daemon.store.unnotified_events() == [])
    sent = [e for e in b.adapter.events if e.type == "relay_misbehaviour"]
    # Recorded before notifying: a crash before the adapter heard of it,
    # or before the daemon marked it heard, means it is sent again, with
    # the same id. After deduplication by event_id it arrives once.
    assert len(sent) == (2 if point == "event.after_notify" else 1)
    assert len({e.event_id for e in sent}) == 1
    (alert,) = [e for e in b.adapter.unique_events() if e.type == "relay_misbehaviour"]
    assert alert.data["reason"] == "routing_mismatch"
    changed = [e for e in b.adapter.unique_events() if e.type == "epoch_changed"]
    assert [e.data["epoch"] for e in changed].count(epoch + 1) == 1
    # The local API's event log has the same ids.
    logged = {e["event_id"] for e in b.daemon.store.events() if e["type"] == "relay_misbehaviour"}
    assert logged == {alert.event_id}


async def test_a_failing_adapter_hears_about_events_again(
    group: GroupFixture, partition: Cut, heal: Cut
) -> None:
    (a, b), gid = await group(2)
    b.daemon.failpoints.arm("event.after_record", "raise")
    a.daemon.update(gid)
    await until(lambda: "event.after_record" in b.daemon.failpoints.fired)
    await b.idle()
    assert b.daemon.store.unnotified_events() != []
    # The next (re)connect sends unnotified events again.
    await partition(b)
    await heal(b)
    await until(lambda: b.daemon.store.unnotified_events() == [])
    assert len({e.event_id for e in b.adapter.events}) == len(b.adapter.unique_events())


async def test_a_removal_survives_a_crash_before_the_core_state_goes(
    group: GroupFixture, advance: Advance
) -> None:
    (a, b, c), gid = await group(3)
    fired = daemon_point(c, "receive.after_tx", "crash")
    a.daemon.remove_member(gid, c.me)
    await recover(c, advance, "crash", fired)
    await until(lambda: status(c, gid) == "removed")
    # The daemon recorded the removal; the restart deleted the MLS state.
    with pytest.raises(Exception, match="unknown group"):
        c.daemon.client.epoch(raw(gid))
    assert len(events(c, "removed")) == 1
    await settled([a, b], gid)


async def test_a_leave_proposal_survives_a_crash(group: GroupFixture, advance: Advance) -> None:
    (a, b, c), gid = await group(3)
    fired = daemon_point(a, "receive.after_core", "crash")
    assert await c.daemon.leave(gid) == "leaving"
    await recover(a, advance, "crash", fired)
    await until(lambda: status(c, gid) == "left")
    await settled([a, b], gid)
    assert len(a.daemon.client.members(raw(gid))) == 2


async def test_an_invite_whose_registration_crashed_is_revoked(
    group: GroupFixture, advance: Advance
) -> None:
    (a, b), gid = await group(2)
    a.daemon.failpoints.arm("invite.after_register", "crash")
    with pytest.raises(SimulatedCrash):
        await a.daemon.create_invite(gid)
    (row,) = a.daemon.store.invites("registering")
    invite_id = str(row["invite_id"])
    assert a.daemon.keystore.get(f"invite/{invite_id}") is not None
    await a.restart()
    await until(lambda: (a.daemon.store.invite(invite_id) or {}).get("status") == "revoked")
    assert a.daemon.keystore.get(f"invite/{invite_id}") is None
    meta = await b.daemon.rest.invite_meta(invite_id)
    assert meta.get("status") == "revoked"


async def test_a_failed_registration_leaves_nothing(group: GroupFixture) -> None:
    (a, _b), gid = await group(2)
    a.daemon.failpoints.arm("invite.after_register", "raise")
    with pytest.raises(FailpointError):
        await a.daemon.create_invite(gid)
    assert a.daemon.store.invites("registering") == []
    assert a.daemon.store.invites("open") == []
