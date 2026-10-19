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
import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.failpoints import FailpointError, SimulatedCrash
from agentconnect.runtime import engine as engine_mod
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


@pytest.mark.hosts("daemon")
@pytest.mark.parametrize("step", ["in_tx", "after_tx", "after_consume"])
async def test_designated_committer_restarts_with_a_pending_leave(
    group: GroupFixture, advance: Advance, malicious_relay: Proxy, step: str
) -> None:
    """The member that commits a leave crashes around recording the leave
    proposal: after the restart it still commits it, and every member
    reports a leave, not a removal (the pending leaves come from the core,
    never from memory)."""
    (a, b, c), gid = await group(3)
    held: list[dict[str, object]] = []

    def hold(frame: dict[str, object]) -> list[dict[str, object]]:
        env = frame.get("env")
        if frame.get("t") == "deliver" and isinstance(env, dict) and env.get("kind") == "proposal":
            held.append(frame)
            return []
        return [frame]

    malicious_relay(a).server_filters.append(hold)
    await c.daemon.leave(gid)
    await until(lambda: bool(held))
    malicious_relay(a).server_filters.remove(hold)
    fired = daemon_point(a, f"receive.{step}", "crash")
    await malicious_relay(a).inject(held[0])
    await recover(a, advance, "crash", fired)
    await until(lambda: status(c, gid) == "left")
    await settled([a, b], gid)
    for n in (a, b):
        assert [e["identity"] for e in events(n, "member_left")] == [c.me]
        assert events(n, "member_removed") == []
    assert [e["by"] for e in events(c, "left")] == [a.me]


@pytest.mark.hosts("daemon")
@pytest.mark.parametrize("step", ["in_tx", "after_tx"])
async def test_a_timed_out_leave_survives_a_crash_at_the_deletion(
    cluster: Cluster, advance: Advance, malicious_relay: Proxy, step: str
) -> None:
    """A leave nobody commits times out: a crash around deleting the group
    leaves either the leave as it was (and the timeout runs again) or the
    group gone with its `left` event, which reaches the adapter once."""
    a = await cluster.node()
    gid = a.daemon.create_group("Crash", "A leave that times out")
    await a.idle()
    c = await cluster.node(groups_leave_timeout_secs=3600)
    await cluster.invite(a, c, gid)
    malicious_relay(a).drop_deliveries(lambda env: env.get("kind") == "proposal")
    await c.daemon.leave(gid)
    await c.idle()
    fired = daemon_point(c, f"leave_timeout.{step}", "crash")
    await advance(3600)
    await recover(c, advance, "crash", fired)
    await until(lambda: status(c, gid) == "left")
    assert [e["confirmed"] for e in events(c, "left")] == [False]
    await until(lambda: c.daemon.store.unnotified_events() == [])
    assert [e.data for e in c.adapter.unique_events() if e.type == "left"] == [{"confirmed": False}]
    with pytest.raises(Exception, match="unknown group"):
        c.daemon.client.epoch(raw(gid))


@pytest.mark.hosts("daemon")
@pytest.mark.parametrize("mode", ["crash", "raise"])
async def test_a_removal_replayed_from_an_older_daemons_journal_is_the_leave(
    group: GroupFixture,
    advance: Advance,
    malicious_relay: Proxy,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    """A journal entry written by a daemon from before the core reported
    leaves (no marker in its context) may hold a summary whose `left` reads
    back empty: a leaving instance reports a leave, whether the entry is
    replayed after a restart (crash) or the frame is processed again and the
    core hands back the journalled event (raise)."""
    (a, b, c), gid = await group(3)
    for n in (a, b):
        malicious_relay(n).drop_deliveries(lambda env: env.get("kind") == "proposal")
    await c.daemon.leave(gid)
    await c.idle()

    def older(
        env: dict[str, Any],
        *,
        from_relay: bool,
        invite_id: str | None = None,
        knock_id: str | None = None,
    ) -> bytes:
        ctx = json.loads(real(env, from_relay=from_relay, invite_id=invite_id, knock_id=knock_id))
        del ctx[engine_mod.SUMMARY_REPORTS_LEAVES]
        return engine_mod.canonical(ctx)

    real = engine_mod.journal_context
    monkeypatch.setattr(engine_mod, "journal_context", older)
    fired = daemon_point(c, "receive.after_core", mode)
    a.daemon.remove_member(gid, c.me)
    await until(fired)
    monkeypatch.setattr(engine_mod, "journal_context", real)
    await recover(c, advance, mode, fired)
    await until(lambda: status(c, gid) == "left")
    assert [e["confirmed"] for e in events(c, "left")] == [True]
    assert events(c, "removed") == []


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


# -- roles and the policy (docs/groups.md) ---------------------------------------------------


def owner_of(node: Node, gid: str) -> str:
    return str(json.loads(node.daemon.client.policy(raw(gid)))["owner"])


def hold_own_commits(proxy: RelayProxy, node: Node) -> None:
    """Only the relay's `accepted` confirms the node's commits: their fan-out
    copies to it are dropped."""
    mailbox = node.daemon.mailbox
    proxy.drop_deliveries(lambda env: env.get("kind") == "commit" and env.get("sender") == mailbox)


@pytest.mark.hosts("daemon")
@pytest.mark.parametrize("step", ["before_core", "after_core", "in_tx", "after_tx"])
async def test_an_owner_transfer_survives_a_crash_around_its_confirmation(
    group: GroupFixture, advance: Advance, malicious_relay: Proxy, step: str
) -> None:
    (a, b, c), gid = await group(3)
    hold_own_commits(malicious_relay(a), a)
    fired = daemon_point(a, f"confirm.{step}", "crash")
    assert a.daemon.transfer_ownership(gid, b.me) == "committing"
    await recover(a, advance, "crash", fired)
    await settled([a, b, c], gid)
    assert {owner_of(n, gid) for n in (a, b, c)} == {b.me}
    expected = sorted([(b.me, "member", "owner"), (a.me, "owner", "admin")])
    for n in (a, b, c):
        assert sorted((e["identity"], e["from"], e["to"]) for e in events(n, "role_changed")) == (
            expected
        )
    assert not a.adapter.of_type("commit_failed")
    # The old owner's last instance may leave now.
    assert await a.daemon.leave(gid) == "leaving"
    await until(lambda: status(a, gid) == "left")


@pytest.mark.hosts("daemon")
@pytest.mark.parametrize("step", ["after_core", "in_tx", "after_tx", "after_consume"])
async def test_a_role_change_is_reported_once_after_a_crash(
    group: GroupFixture, advance: Advance, step: str
) -> None:
    (a, b, c), gid = await group(3)
    fired = daemon_point(b, f"receive.{step}", "crash")
    assert a.daemon.set_role(gid, c.me, "admin") == "committing"
    await recover(b, advance, "crash", fired)
    await settled([a, b, c], gid)
    expected = [
        {
            "identity": c.me,
            "from": "member",
            "to": "admin",
            "moderator_from": False,
            "moderator_to": False,
            "by": a.me,
        }
    ]
    assert events(b, "role_changed") == expected
    await until(lambda: b.daemon.store.unnotified_events() == [])
    assert [e.data for e in b.adapter.unique_events() if e.type == "role_changed"] == expected


@pytest.mark.hosts("daemon")
@pytest.mark.parametrize("step", ["after_core", "in_tx", "after_tx"])
async def test_departed_roles_are_dropped_once_after_a_crash(
    group: GroupFixture, advance: Advance, malicious_relay: Proxy, step: str
) -> None:
    """The owner commits an admin's leave and crashes around confirming it:
    the cleanup is queued with the commit's effects, so after the restart
    it is committed, once."""
    (a, b, c), gid = await group(3)
    assert a.daemon.set_role(gid, b.me, "admin") == "committing"
    await settled([a, b, c], gid)
    hold_own_commits(malicious_relay(a), a)
    fired = daemon_point(a, f"confirm.{step}", "crash")
    assert await b.daemon.leave(gid) == "leaving"
    await recover(a, advance, "crash", fired)
    await until(lambda: status(b, gid) == "left")
    await until(lambda: json.loads(c.daemon.client.policy(raw(gid)))["admins"] == [])
    await settled([a, c], gid)
    dropped = [e for e in events(c, "role_changed") if e["to"] == "member"]
    assert dropped == [
        {
            "identity": b.me,
            "from": "admin",
            "to": "member",
            "moderator_from": False,
            "moderator_to": False,
            "by": a.me,
        }
    ]
    assert [e["by"] for e in events(c, "policy_changed")] == [a.me, a.me]


# -- floor control (docs/groups.md#floor-control) ---------------------------------------------


def holder_of(node: Node, gid: str) -> str | None:
    floor = node.daemon.group_info(gid)["floor"]
    return None if floor["holder"] is None else str(floor["holder"])


async def moderated_by(nodes: list[Node], gid: str, moderator: Node) -> None:
    owner = nodes[0]
    changes = {"floor": "moderated", "floor_moderator": moderator.me}
    assert owner.daemon.change_policy(gid, changes) == "committing"
    await settled(nodes, gid)


@pytest.mark.hosts("daemon")
@pytest.mark.parametrize("step", ["after_core", "in_tx", "after_tx", "after_consume"])
@pytest.mark.parametrize("mode", MODES)
async def test_a_floor_grant_is_taken_once_after_a_crash(
    group: GroupFixture, advance: Advance, step: str, mode: str
) -> None:
    """A received grant changes the holder in the same transaction as its
    inbox record: after a failure around it, the holder is taken and
    reported once."""
    (a, b, c), gid = await group(3)
    await moderated_by([a, b, c], gid, b)
    fired = daemon_point(c, f"receive.{step}", mode)
    b.daemon.grant_floor(gid, c.me)
    await recover(c, advance, mode, fired)
    await until(lambda: holder_of(c, gid) == c.me)
    await settled([a, b, c], gid)
    granted = [e for e in events(c, "floor_changed") if e["reason"] == "grant"]
    assert [e["holder"] for e in granted] == [c.me]
    assert [w[2:5] for w in c.daemon.store.floor_writes(gid) if w[4] == "grant"] == [
        (b.me, b.daemon.instance.instance_id_hex, "grant")
    ]
    if mode == "raise":
        # A failure after the transaction leaves its events for the next
        # start (or reconnect) to tell the adapter.
        await c.restart()
    await until(lambda: c.daemon.store.unnotified_events() == [])
    told = [e.data for e in c.adapter.unique_events() if e.type == "floor_changed"]
    assert [e["reason"] for e in told].count("grant") == 1
    # The grant reached c's adapter once, as context.
    await c.adapter.wait_for(
        lambda: any(d.kind == "control.floor" for d in c.adapter.deliveries), WAIT
    )
    await c.idle()
    floors = {d.msg_id for d in c.adapter.deliveries if d.kind == "control.floor"}
    assert len(floors) == 1


@pytest.mark.hosts("daemon")
@pytest.mark.parametrize(
    ("side", "step"),
    [("receive", s) for s in ("after_core", "in_tx", "after_tx", "after_consume")]
    + [("confirm", s) for s in ("after_core", "in_tx", "after_tx")],
)
async def test_a_holder_reset_is_reported_once_after_a_crash(
    group: GroupFixture, advance: Advance, malicious_relay: Proxy, side: str, step: str
) -> None:
    """The holder is removed: the member that receives the commit (b) or
    the one that made it (a) crashes around recording it, and reports the
    reset once after the restart."""
    (a, b, c), gid = await group(3)
    await moderated_by([a, b, c], gid, b)
    b.daemon.grant_floor(gid, c.me)
    await until(lambda: holder_of(a, gid) == holder_of(c, gid) == c.me)
    node = b if side == "receive" else a
    if side == "confirm":
        hold_own_commits(malicious_relay(a), a)
    fired = daemon_point(node, f"{side}.{step}", "crash")
    a.daemon.remove_member(gid, c.me)
    await recover(node, advance, "crash", fired)
    await until(lambda: status(c, gid) == "removed")
    await settled([a, b], gid)
    for n in (a, b):
        assert holder_of(n, gid) is None
        resets = [e for e in events(n, "floor_changed") if e["reason"] == "reset"]
        assert resets == [
            {
                "mode": "moderated",
                "moderator": b.me,
                "effective_moderator": b.me,
                "holder": None,
                "by": a.me,
                "reason": "reset",
            }
        ]
    await until(lambda: node.daemon.store.unnotified_events() == [])
    told = [e.data for e in node.adapter.unique_events() if e.type == "floor_changed"]
    assert [e["reason"] for e in told].count("reset") == 1


@pytest.mark.hosts("daemon")
async def test_the_floor_holder_survives_a_restart(group: GroupFixture) -> None:
    """The holder is stored, so a restarted member still triggers the
    holder, and an older grant still loses to the one it took."""
    (a, b, c), gid = await group(3)
    await moderated_by([a, b, c], gid, b)
    b.daemon.grant_floor(gid, c.me)
    await until(lambda: holder_of(a, gid) == holder_of(c, gid) == c.me)
    taken = a.daemon.store.floor_writes(gid)
    await a.restart()
    await a.connected()
    assert holder_of(a, gid) == c.me
    assert a.daemon.store.floor_writes(gid) == taken
    send = c.adapter.send
    assert send is not None
    await send(gid, {"text": "after the restart"})
    await a.adapter.wait_for(lambda: "after the restart" in a.adapter.texts(gid), WAIT)
    hit = next(d for d in a.adapter.deliveries if d.body == {"text": "after the restart"})
    assert hit.addressed_to_me is False  # a is neither the moderator nor the holder
    # An older grant from b, held back by the relay, is ignored after the restart.
    inner = b.daemon.inner("control.floor", {"holder": a.me, "counter": 0}, ["*"])
    b.daemon._enqueue("app", gid, {"inner": inner, "msg_id": engine_mod.new_msg_id()})
    b.daemon.send_message(gid, {"text": "marker"})
    await a.adapter.wait_for(lambda: "marker" in a.adapter.texts(gid), WAIT)
    assert holder_of(a, gid) == c.me


@pytest.mark.hosts("daemon")
async def test_an_own_grant_survives_a_crash_after_the_relay_took_it(group: GroupFixture) -> None:
    """b's grant is taken when it is sealed, in the same transaction as
    the envelope. b dies after the relay took it and before it is marked
    sent; the group moves on two epochs while b is down. On restart the
    resend is a duplicate the relay takes in its old epoch: b's floor
    agrees with everyone's."""
    (a, b, c), gid = await group(3)
    await moderated_by([a, b, c], gid, b)
    fired: list[str] = []

    def crashing(_group_id: str, msg_id: str) -> None:
        fired.append(msg_id)
        raise SimulatedCrash

    b.daemon.floor.confirmed = crashing  # ty: ignore[invalid-assignment]
    b.daemon.grant_floor(gid, a.me)
    await until(lambda: bool(fired) and holder_of(a, gid) == holder_of(c, gid) == a.me)
    await b.stop()
    for turns in (10, 11):
        assert a.daemon.change_policy(gid, {"max_agent_turns": turns}) == "committing"
        await until(lambda: a.daemon.store.outbox() == [])
        await until(lambda: c.epoch(gid) == a.epoch(gid))
    await b.start()
    await b.connected()
    await until(lambda: b.epoch(gid) == a.epoch(gid) and not b.daemon.store.outbox())
    await settled([a, b, c], gid)
    assert {holder_of(n, gid) for n in (a, b, c)} == {a.me}
    _, state = b.daemon.store.floor(gid) or (None, {})
    assert state["pending"] == {}


async def _floor_of(node: Node, gid: str) -> dict[str, Any]:
    row = node.daemon.store.floor(gid)
    assert row is not None
    return row[1]


@pytest.mark.hosts("daemon")
async def test_a_failed_grant_is_taken_back_with_its_row_after_a_crash(group: GroupFixture) -> None:
    """The row of b's refused grant is marked failed and the grant taken
    back in one transaction: a crash in between leaves both as they were,
    so b sends it again after the restart and every member agrees. Old
    epochs then fold away as usual."""
    (a, b, c), gid = await group(3)
    await moderated_by([a, b, c], gid, b)
    b.daemon.grant_floor(gid, a.me)
    await until(lambda: holder_of(a, gid) == holder_of(b, gid) == holder_of(c, gid) == a.me)
    fired: list[str] = []

    def crashing(_group_id: str, msg_id: str) -> None:
        fired.append(msg_id)
        raise SimulatedCrash

    b.daemon.floor.unsent = crashing  # ty: ignore[invalid-assignment]
    b.proxy.fail_next("send", "not_member", kind="application")
    b.daemon.grant_floor(gid, c.me)
    await until(lambda: bool(fired))
    await b.restart()
    await b.connected()
    for turns in (10, 11, 12):
        assert a.daemon.change_policy(gid, {"max_agent_turns": turns}) == "committing"
        await until(lambda: a.daemon.store.outbox() == [])
    await settled([a, b, c], gid)
    assert {holder_of(n, gid) for n in (a, b, c)} == {c.me}
    state = await _floor_of(b, gid)
    assert state["pending"] == {}
    epoch = b.epoch(gid)
    assert sorted(int(e) for e in state["facts"]) == [epoch - 1, epoch]


@pytest.mark.hosts("daemon")
async def test_a_pending_grant_whose_send_failed_is_taken_back_at_start(
    group: GroupFixture,
) -> None:
    """A database an earlier build left with a failed row and its grant
    still pending: at start the grant is taken back, and old epochs fold."""
    (a, b, c), gid = await group(3)
    await moderated_by([a, b, c], gid, b)
    b.daemon.grant_floor(gid, a.me)
    await until(lambda: holder_of(a, gid) == holder_of(b, gid) == holder_of(c, gid) == a.me)
    b.daemon.floor.unsent = lambda _gid, _msg_id: None  # ty: ignore[invalid-assignment]
    b.proxy.fail_next("send", "not_member", kind="application")
    b.daemon.grant_floor(gid, c.me)
    await until(lambda: bool(b.adapter.of_type("send_failed")))
    assert holder_of(b, gid) == c.me  # the earlier build's state
    await b.restart()
    await b.connected()
    assert holder_of(b, gid) == a.me
    for turns in (10, 11, 12):
        assert a.daemon.change_policy(gid, {"max_agent_turns": turns}) == "committing"
        await until(lambda: a.daemon.store.outbox() == [])
    await settled([a, b, c], gid)
    assert {holder_of(n, gid) for n in (a, b, c)} == {a.me}
    state = await _floor_of(b, gid)
    assert state["pending"] == {}
    epoch = b.epoch(gid)
    assert sorted(int(e) for e in state["facts"]) == [epoch - 1, epoch]
