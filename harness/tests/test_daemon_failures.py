"""Failure handling: relay errors, broken adapters, restarts mid-operation."""

from __future__ import annotations

import asyncio
import base64
import random
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.adapter import (
    Capabilities,
    Delivery,
    DeliveryResult,
    Event,
    GroupView,
    OutboundSend,
    Sender,
)
from agentconnect.keystore import FileKeystore
from agentconnect.relay import RelayError
from agentconnect.runtime.engine import (
    JOIN_CLOSED_GRACE_SECS,
    MAX_COMMIT_ATTEMPTS,
    RATE_WINDOW_SECS,
    UPDATE_AFTER_MESSAGES,
    WELCOME_MARGIN_SECS,
    DaemonError,
    Engine,
    new_msg_id,
)
from agentconnect_harness.cluster import WAIT, Cluster, Node, converged, status
from agentconnect_harness.proxy import RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]
Cut = Callable[[Node], Awaitable[None]]
Proxy = Callable[[Node], RelayProxy]


async def test_relay_errors_on_sends(
    group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    (a, b), gid = await group(2)
    proxy = malicious_relay(a)
    # A stale application epoch: sealed again and resent.
    proxy.fail_next("send", "epoch_conflict", kind="application")
    a.daemon.send_message(gid, {"text": "resealed"})
    assert await b.wait_texts(gid, 1) == ["resealed"]
    # Rate limited: retried after a pause on the daemon clock.
    proxy.fail_next("send", "rate_limited", kind="application")
    a.daemon.send_message(gid, {"text": "later"})
    await a.wait(lambda: a.clock.sleepers > 0)
    await advance(1)
    assert await b.wait_texts(gid, 2) == ["resealed", "later"]
    # Any other error fails that message only.
    proxy.fail_next("send", "not_member", kind="application")
    lost = a.daemon.send_message(gid, {"text": "lost"})
    await a.idle()
    # The failed row keeps its msg_id, not its plaintext, and the caller
    # hears about it.
    assert [r.payload for r in a.daemon.store.outbox("failed")] == [{"msg_id": lost}]
    (failed,) = a.adapter.of_type("send_failed")
    assert failed.data == {"msg_id": lost, "code": "not_member"}
    # A relay hiccup on a commit (rate_limited, internal) is retried with
    # the same bytes and msg_id after a backoff.
    epoch = a.epoch(gid)
    proxy.fail_next("send", "rate_limited", kind="commit")
    proxy.fail_next("send", "internal", kind="commit")
    a.daemon.update(gid)
    for _ in range(2):
        await a.wait(lambda: a.clock.sleepers > 0)
        await advance(60)
    await a.idle()
    assert a.epoch(gid) == epoch + 1
    assert not a.adapter.of_type("commit_failed")
    # A commit the relay rejects outright is discarded, not merged.
    epoch = a.epoch(gid)
    proxy.fail_next("send", "quota_exceeded", kind="commit")
    a.daemon.update(gid)
    await a.idle()
    assert a.epoch(gid) == epoch
    (commit_failed,) = a.adapter.of_type("commit_failed")
    assert commit_failed.data == {"intent": "update", "code": "quota_exceeded"}
    assert not a.daemon.client.has_pending_commit(bytes(base64.urlsafe_b64decode(gid + "==")))
    a.daemon.send_message(gid, {"text": "still in sync"})
    assert await b.wait_texts(gid, 3) == ["resealed", "later", "still in sync"]


async def test_a_send_refused_for_now_holds_up_only_its_group(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """N5: a commit or a message the relay refuses for now (`internal`)
    waits out its backoff without holding up the sender's other groups, and
    its own group's later rows still wait behind it."""
    (a, b), gid = await group(2)
    other = a.daemon.create_group("Other", "Elsewhere")
    await a.idle()
    await cluster.invite(a, b, other)
    proxy = malicious_relay(a)
    epoch = a.epoch(gid)
    proxy.fail_next("send", "internal", kind="commit")
    a.daemon.update(gid)
    await a.wait(lambda: a.clock.sleepers > 0)
    a.daemon.send_message(gid, {"text": "after the commit"})
    a.daemon.send_message(other, {"text": "elsewhere"})
    assert await b.wait_texts(other, 1) == ["elsewhere"]
    assert a.epoch(gid) == epoch
    await advance(1)
    assert await b.wait_texts(gid, 1) == ["after the commit"]
    assert a.epoch(gid) == epoch + 1
    proxy.fail_next("send", "internal", kind="application")
    a.daemon.send_message(gid, {"text": "first"})
    await a.wait(lambda: a.clock.sleepers > 0)
    a.daemon.send_message(gid, {"text": "second"})
    a.daemon.send_message(other, {"text": "meanwhile"})
    assert await b.wait_texts(other, 2) == ["elsewhere", "meanwhile"]
    assert b.adapter.texts(gid) == ["after the commit"]
    await advance(1)
    assert await b.wait_texts(gid, 3) == ["after the commit", "first", "second"]
    await a.idle()
    assert a.daemon._postponed == {}


async def test_rate_limited_pauses_every_group_and_costs_no_try(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """`rate_limited` is the mailbox's send budget, shared by every group:
    the whole outbox pauses, the oldest row goes first when it resumes, and
    a row refused more than MAX_COMMIT_ATTEMPTS times this way still goes
    out."""
    (a, b), gid = await group(2)
    other = a.daemon.create_group("Other", "Elsewhere")
    await a.idle()
    await cluster.invite(a, b, other)
    proxy = malicious_relay(a)
    refusals = MAX_COMMIT_ATTEMPTS + 2
    left = [refusals]

    def refuse(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if left[0] and env.get("kind") == "application" and env.get("group_id") == gid:
            left[0] -= 1
            proxy._forged.append({"t": "error", "msg_id": env["msg_id"], "code": "rate_limited"})
            return []
        return [frame]

    proxy.client_filters.append(refuse)
    a.daemon.send_message(gid, {"text": "first"})
    await a.wait(lambda: a.clock.sleepers > 0)
    elsewhere = a.daemon.send_message(other, {"text": "elsewhere"})
    await a.wait(lambda: a.daemon._next_row() is None)
    assert a.daemon.store.outbox_state_of(elsewhere) == "queued"  # every group waits
    for _ in range(refusals + 2):
        if b.adapter.texts(other):
            break
        await a.wait(lambda: a.clock.sleepers > 0 or bool(b.adapter.texts(other)))
        await advance(60)
    assert await b.wait_texts(gid, 1) == ["first"]
    assert await b.wait_texts(other, 1) == ["elsewhere"]
    await a.idle()
    assert not a.adapter.of_type("send_failed")
    assert a.daemon._refusals == {}


async def test_a_cadence_updates_refusals_count_toward_its_own_row(
    group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """The try cap counts the relay's refusals of a row's own send: a
    cadence Update that runs inside a message's row counts toward the
    Update, so together they may be refused more often than either may."""
    (a, b), gid = await group(2)
    epoch = a.epoch(gid)
    proxy = malicious_relay(a)
    a.daemon.store.update_group(gid, msgs_since_commit=UPDATE_AFTER_MESSAGES)
    each = MAX_COMMIT_ATTEMPTS - 2
    proxy.fail_next("send", "internal", kind="commit", times=each)
    proxy.fail_next("send", "internal", kind="application", times=each)
    a.daemon.send_message(gid, {"text": "after the update"})
    for _ in range(2 * each + 2):
        if b.adapter.texts(gid):
            break
        await a.wait(lambda: a.clock.sleepers > 0 or bool(b.adapter.texts(gid)))
        await advance(60)
    assert await b.wait_texts(gid, 1) == ["after the update"]
    assert a.epoch(gid) == epoch + 1
    assert not a.adapter.of_type("send_failed")
    assert not a.adapter.of_type("commit_failed")


# A scaled-down relay (relay.rs: 50 sends a second per mailbox) and an agent
# whose groups together want three times that.
BUDGET = 5
BUSY_GROUPS = 8
STEP = 0.1  # the daemon clock moves in short steps, as a busy agent does
SECONDS = 150  # past the 8 backoffs a row's own retries would take


def send_budget(node: Node, proxy: RelayProxy, most: int) -> list[str]:
    """The relay's per-mailbox send limit on the daemon clock: a one-second
    sliding window, where a refused send uses no budget. An application
    message inside it is accepted here and goes no further (the test reads
    only what the sender does), so the real relay's limit, on the real
    clock, never applies; commits go on to the relay. Returns the msg_ids
    of the messages accepted."""
    window: list[float] = []
    accepted: list[str] = []

    def client(frame: dict[str, Any]) -> list[dict[str, Any]]:
        if frame.get("t") != "send":
            return [frame]
        env = frame["env"]
        now = node.clock.unix_millis() / 1000
        while window and now - window[0] >= 1.0:
            window.pop(0)
        if len(window) >= most:
            proxy._forged.append({"t": "error", "msg_id": env["msg_id"], "code": "rate_limited"})
            return []
        window.append(now)
        if env.get("kind") == "application":
            accepted.append(str(env["msg_id"]))
            proxy._forged.append({"t": "accepted", "msg_id": env["msg_id"]})
            return []
        return [frame]

    proxy.client_filters.append(client)
    return accepted


async def test_busy_groups_share_the_relays_send_budget(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """Under the relay's per-mailbox send limit, busy groups' fresh messages
    don't take the budget from a row waiting to be sent again: nothing
    fails, a quiet group's message goes out, and the outbox keeps sending
    at about the budget."""
    (a, b), quiet = await group(2)
    busy = []
    for i in range(BUSY_GROUPS):
        gid = a.daemon.create_group(f"Busy {i}", "x")
        await a.idle()
        await cluster.invite(a, b, gid)
        busy.append(gid)
    await a.idle()
    accepted = send_budget(a, malicious_relay(a), BUDGET)
    q = a.daemon.send_message(quiet, {"text": "quiet"})
    steps = int(SECONDS / STEP)
    for step in range(steps):
        if step % 5 == 0:  # each busy group: two messages a second
            for gid in busy:
                a.daemon.send_message(gid, {"text": "busy"}, internal=True)
        await a.wait(lambda: a.daemon._next_row() is None)
        await advance(STEP)
    await a.wait(lambda: a.daemon._next_row() is None)
    assert not a.adapter.of_type("send_failed")
    assert a.daemon.store.outbox_state_of(str(q)) == "done"
    assert q in accepted
    assert len(accepted) >= 0.95 * BUDGET * SECONDS


async def test_invite_registration_failures_keep_no_secret(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, _b), gid = await group(2)

    async def down(_meta: dict[str, Any]) -> dict[str, Any]:
        raise RelayError("relay_unreachable", "ConnectError")

    monkeypatch.setattr(a.daemon.rest, "create_invite", down)
    before = set((a.config.data_dir / "keys").iterdir())
    with pytest.raises(DaemonError, match="relay_unreachable"):
        await a.daemon.create_invite(gid)
    assert set((a.config.data_dir / "keys").iterdir()) == before


async def test_join_and_proposal_errors(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    c = await cluster.node("c")
    malicious_relay(c).fail_next("join", "invite_not_open")
    invite = await a.daemon.create_invite(gid)
    await c.daemon.accept_invite(invite["url"])
    await c.adapter.wait_for(lambda: bool(c.adapter.of_type("join_failed")))
    assert c.daemon.store.join_status(invite["invite_id"]) == ("failed", None)
    assert c.daemon.keystore.get(f"join/{invite['invite_id']}") is None
    malicious_relay(b).fail_next("send", "epoch_conflict", kind="proposal")
    assert await b.daemon.leave(gid) == "leaving"
    await b.idle()
    assert b.daemon.store.outbox("failed")
    # The next commit b sees makes it propose again, and then it leaves.
    a.daemon.update(gid)
    await b.wait(lambda: status(b, gid) == "left")


async def test_join_request_rejections(cluster: Cluster, rng: random.Random) -> None:
    a = await cluster.node("a", auto_approve=False)
    b = await cluster.node("b")
    c = await cluster.node("c")
    gid = a.daemon.create_group("Strict", "")
    await a.idle()
    # A wrong secret in the link: the MAC fails and nothing is queued.
    invite = await a.daemon.create_invite(gid)
    secret = invite["url"].split("&s=")[1]
    wrong = base64.urlsafe_b64encode(rng.randbytes(32)).rstrip(b"=").decode()
    tampered = invite["url"].replace(secret, wrong)
    await b.daemon.accept_invite(tampered)
    # An invite whose secret is gone (e.g. revoked locally) is ignored.
    invite2 = await a.daemon.create_invite(gid)
    a.daemon.keystore.delete(f"invite/{invite2['invite_id']}")
    await c.daemon.accept_invite(invite2["url"])
    await b.idle()
    await c.idle()
    await a.wait(lambda: a.daemon.store.inbox_state(c.daemon.mailbox, _join_msg_id(c)) is not None)
    await a.wait(lambda: a.daemon.store.inbox_state(b.daemon.mailbox, _join_msg_id(b)) is not None)
    # Read only once both JoinRequests were processed (earlier, this check
    # was vacuous).
    rows = [r for r in a.daemon.store.events() if r["type"] == "pending_approval"]
    assert rows == []
    assert a.daemon.approvals() == []


def _join_msg_id(node: Node) -> str:
    (row,) = [r for r in node.daemon.store.outbox("done") if r.payload.get("t") == "join"]
    return str(row.payload["msg_id"])


async def test_welcome_failures_and_parked_messages(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    # c's stored invite metadata disagrees with the group: the Welcome is
    # refused (SPEC 6.3) and the join fails.
    c = await cluster.node("c")
    invite = await a.daemon.create_invite(gid, max_uses=2)
    await c.daemon.accept_invite(invite["url"])
    c.daemon.store.add_join(
        invite["invite_id"],
        {"group_name": "Other", "purpose": "x", "invite_id": invite["invite_id"], "protocol": 0},
        "c",
        0,
    )
    await c.adapter.wait_for(lambda: bool(c.adapter.of_type("join_failed")))
    await cluster.settle(gid, 2)
    # d receives a group message before its Welcome: it is parked and
    # processed once the join completes.
    d = await cluster.node("d")
    holding = malicious_relay(d).hold_welcome_until_application()
    epoch = a.epoch(gid)
    await d.daemon.accept_invite(invite["url"])
    await b.wait(lambda: b.epoch(gid) == epoch + 1)
    # Only once the Welcome is held: sent sooner, the message could overtake
    # it and leave it held for good.
    await asyncio.wait_for(holding.wait(), WAIT)
    b.daemon.send_message(gid, {"text": "early"}, to=["*"])
    assert await d.wait_texts(gid, 1) == ["early"]


def refuse_welcomes(proxy: RelayProxy, times: int) -> list[str]:
    """The relay answers the next ``times`` Welcomes `rate_limited`; the
    msg_id of every Welcome the daemon sends, refused or not."""
    tried: list[str] = []

    def count(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if frame.get("t") == "send" and env.get("kind") == "welcome_wrapped":
            tried.append(str(env["msg_id"]))
        return [frame]

    proxy.client_filters.append(count)
    proxy.fail_next("send", "rate_limited", kind="welcome_wrapped", times=times)
    return tried


def approval_of(node: Node, invite_id: str) -> dict[str, Any]:
    (approval,) = [
        a
        for status in ("pending", "approving", "approved", "failed")
        for a in node.daemon.store.approvals(status)
        if a["invite_id"] == invite_id
    ]
    return approval


async def test_a_welcome_the_relay_refuses_for_now_is_sent_again(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """After an approved join's Add, a Welcome the relay can't take yet
    (`rate_limited`, `internal`) is sent again after a backoff, under the
    same msg_id, and the joiner joins. It used to fail the commit's row,
    leaving the joiner in the MLS group without its Welcome."""
    (a, b), gid = await group(2)
    c = await cluster.node("c")
    tried = refuse_welcomes(malicious_relay(a), 2)
    invite = await a.daemon.create_invite(gid)
    await c.daemon.accept_invite(invite["url"])
    for _ in range(10):
        if c.daemon.store.group(gid) is not None:
            break
        await a.wait(lambda: a.clock.sleepers > 0 or c.daemon.store.group(gid) is not None)
        await advance(60)
    await c.wait(lambda: c.daemon.store.group(gid) is not None)
    await converged([a, b, c], gid)
    assert len(tried) == 3
    assert len(set(tried)) == 1
    assert approval_of(a, invite["invite_id"])["status"] == "approved"
    assert not a.adapter.of_type("commit_failed")
    assert len(c.adapter.of_type("joined")) == 1


async def test_no_welcome_goes_out_after_the_joiner_gave_up(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """The relay refuses the Welcome (`rate_limited`) until the joiner stops
    waiting, then would take it. The inviter checks the deadline before
    every try, so no Welcome goes out that late: the approval fails with
    `welcome_not_sent` and the instance the Add put in is removed again,
    instead of a member nobody holds."""
    (a,), gid = await group(1)
    c = await cluster.node("c")
    proxy = malicious_relay(a)
    invite = await a.daemon.create_invite(gid, ttl_secs=300)
    gives_up = int(invite["expires_at"]) + JOIN_CLOSED_GRACE_SECS
    tries: list[float] = []

    def refuse(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if frame.get("t") == "send" and env.get("kind") == "welcome_wrapped":
            now = a.clock.unix_millis() / 1000
            tries.append(now)
            if now < gives_up:
                proxy._forged.append(
                    {"t": "error", "msg_id": env["msg_id"], "code": "rate_limited"}
                )
                return []
        return [frame]

    proxy.client_filters.append(refuse)
    await c.daemon.accept_invite(invite["url"])
    await a.wait(lambda: bool(tries))
    while a.clock.unix_millis() / 1000 < gives_up + 120:
        await advance(5)
        await a.wait(lambda: not a.daemon.store.outbox() or a.daemon._next_row() is None)
    await a.idle()
    assert tries
    assert max(tries) < gives_up - WELCOME_MARGIN_SECS
    (failed,) = a.adapter.of_type("commit_failed")
    assert (failed.data["intent"], failed.data["code"]) == ("add", "welcome_not_sent")
    assert {m.identity for m in a.daemon.store.members(gid)} == {a.me}
    assert c.daemon.store.group(gid) is None


async def test_a_rate_limited_frame_is_sent_again(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """`group.create` and `join` count against the same per-mailbox budget
    as sends: one answered `rate_limited` waits out the shared pause and
    goes again, instead of failing for good."""
    (a, b), _ = await group(2)
    malicious_relay(a).fail_next("group.create", "rate_limited")
    gid = a.daemon.create_group("New", "x")
    await a.wait(lambda: a.daemon._next_row() is None)
    await advance(RATE_WINDOW_SECS)
    await a.idle()
    assert not a.daemon.store.outbox("failed")
    await cluster.invite(a, b, gid)
    c = await cluster.node("c")
    malicious_relay(c).fail_next("join", "rate_limited")
    invite = await a.daemon.create_invite(gid)
    await c.daemon.accept_invite(invite["url"])
    await c.wait(lambda: c.daemon._next_row() is None)
    assert not c.adapter.of_type("join_failed")
    await advance(RATE_WINDOW_SECS)
    await c.wait(lambda: c.daemon.store.group(gid) is not None)
    assert not c.adapter.of_type("join_failed")


async def test_a_welcome_that_cant_go_out_in_time_removes_the_joiner_again(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """A Welcome still refused once the joiner has given up (its invite's
    expiry and the grace for a Welcome in flight) is given up too: the
    approval fails, the human hears of it, and the instance the Add put in
    the group is removed again."""
    (a, b), gid = await group(2)
    c = await cluster.node("c")
    tried = refuse_welcomes(malicious_relay(a), 10_000)
    invite = await a.daemon.create_invite(gid, ttl_secs=600)
    epoch = a.epoch(gid)
    await c.daemon.accept_invite(invite["url"])
    await a.wait(lambda: bool(tried) and a.clock.sleepers > 0)
    await b.wait(lambda: b.epoch(gid) == epoch + 1)
    assert len(a.daemon.store.members(gid)) == 3
    for _ in range(30):
        if a.adapter.of_type("commit_failed"):
            break
        await a.wait(lambda: a.clock.sleepers > 0 or bool(a.adapter.of_type("commit_failed")))
        await advance(60)
    (failed,) = a.adapter.of_type("commit_failed")
    assert (failed.data["intent"], failed.data["code"]) == ("add", "welcome_not_sent")
    assert approval_of(a, invite["invite_id"])["status"] == "failed"
    await converged([a, b], gid)
    assert {m.identity for m in a.daemon.store.members(gid)} == {a.me, b.me}
    assert len(set(tried)) == 1


async def test_bad_outbox_rows_fail_cleanly(group: GroupFixture) -> None:
    (a, _b), gid = await group(2)
    d = a.daemon
    d._enqueue("commit", gid, {"intent": {"type": "bogus"}})
    d._enqueue("commit", gid, {"intent": {"type": "add", "request_id": "nope"}})
    d._enqueue("commit", gid, {"intent": {"type": "proposals"}})
    d._enqueue("weird", gid, {})
    d._enqueue("app", "no-such-group", {})
    d._enqueue("frame", None, {})
    d._enqueue(
        "app",
        gid,
        {
            "inner": {"v": 0, "sender": d.me, "instance_id": d.instance.instance_id_hex},
            "msg_id": new_msg_id(),
        },
    )
    await a.idle()
    assert len(d.store.outbox("failed")) == 6
    with pytest.raises(DaemonError, match="kind"):
        d.send_message(gid, {}, kind="nope")
    # control.resume is human-only (SPEC 7.3): adapters can't send it.
    send = a.adapter.send
    assert send is not None
    with pytest.raises(DaemonError, match="from the human"):
        await send(gid, {}, kind="control.resume")
    with pytest.raises(DaemonError, match="origin"):
        d.send_message(gid, {}, origin="robot")
    with pytest.raises(DaemonError, match="too large"):
        d.send_message(gid, {"text": "x" * (2 << 20)})
    with pytest.raises(DaemonError, match="too long"):
        d.create_group("x" * 200, "")


class BrokenAdapter:
    name = "broken"

    def __init__(self) -> None:
        self.calls = 0

    def capabilities(self) -> Capabilities:
        return Capabilities()

    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError
        return DeliveryResult.ACK

    async def on_event(self, group: GroupView | None, event: Event) -> None:
        raise RuntimeError

    async def on_outbound(self, send: OutboundSend) -> None:
        self.send = send


async def test_broken_adapters_do_not_stop_the_daemon(
    cluster: Cluster, group: GroupFixture, advance: Advance
) -> None:
    (a, b), gid = await group(2)
    broken = BrokenAdapter()
    await b.daemon.stop()
    b.daemon = Engine(
        b.config.with_overrides(default_adapter="broken"),
        [broken],
        clock=b.clock,
        keystore=FileKeystore(b.config.data_dir / "keys"),
    )
    b.daemon.store.update_group(gid, adapter="broken")
    await b.daemon.start()
    await b.connected()
    msg_id = await broken.send(gid, {"text": "from the adapter"})
    assert msg_id
    assert await a.wait_texts(gid, 1) == ["from the adapter"]
    a.daemon.send_message(gid, {"text": "to the broken one"})
    await b.wait(lambda: broken.calls == 1 and b.clock.sleepers > 0)
    await advance(5)
    await b.wait(lambda: broken.calls == 2)
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 0)


async def test_daemon_without_adapters(cluster: Cluster) -> None:
    n = await cluster.node("bare")
    await n.daemon.stop()
    n.daemon = Engine(
        n.config, [], clock=n.clock, keystore=FileKeystore(n.config.data_dir / "keys")
    )
    await n.daemon.start()
    gid = n.daemon.create_group("Quiet", "")
    await n.daemon.emit(gid, "custom")
    assert n.daemon.store.events()[-1]["type"] == "custom"


async def test_restart_recovers_unsent_commits_and_leaving(
    group: GroupFixture, partition: Cut, heal: Cut
) -> None:
    (a, b, c), gid = await group(3)
    raw = bytes(base64.urlsafe_b64decode(gid + "=="))
    # A commit built but never recorded for sending is discarded on restart.
    b.daemon.client.update(raw)
    await b.restart()
    assert not b.daemon.client.has_pending_commit(raw)
    # c leaves while a (the member that commits leaves) is cut off; c's
    # leaving state survives a restart, and it proposes again after the
    # next commit until someone commits its removal.
    await partition(a)
    await c.daemon.leave(gid)
    await c.idle()
    await c.restart()
    assert c.daemon.groups.leaving(gid)
    b.daemon.update(gid)
    await c.wait(
        lambda: len([r for r in c.daemon.store.outbox("done") if r.kind == "proposal"]) >= 1
    )
    await heal(a)
    await c.wait(lambda: status(c, gid) == "left", within=10)
    await a.wait(lambda: len(a.daemon.store.members(gid)) == 2)
    assert {e.type for e in a.adapter.events} >= {"member_left"}
    # An inactive group is skipped on the next restart.
    await c.restart()


async def test_commit_epoch_hint_mismatch(group: GroupFixture, malicious_relay: Proxy) -> None:
    (a, b), gid = await group(2)

    def bump(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if frame.get("t") == "deliver" and env.get("kind") == "commit":
            env["epoch"] += 5
        return [frame]

    malicious_relay(b).server_filters.append(bump)
    a.daemon.update(gid)
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("relay_misbehaviour")))
    assert b.adapter.of_type("relay_misbehaviour")[0].data["reason"] == "epoch_mismatch"


async def test_a_dead_worker_is_restarted(cluster: Cluster, advance: Advance) -> None:
    n = await cluster.node("w")
    calls = 0

    async def flaky() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            msg = "worker bug"
            raise RuntimeError(msg)
        n.daemon.running = False  # the second run ends with the daemon

    task = asyncio.ensure_future(n.daemon._supervised("flaky", flaky))
    await n.wait(lambda: calls == 1 and n.clock.sleepers > 0)
    await advance(60)
    await asyncio.wait_for(task, 5)
    assert calls == 2
    n.daemon.running = True


def refuse_kind(proxy: RelayProxy, gid: str, kind: str, code: str, times: int) -> list[int]:
    """Answer the node's next ``times`` sends of ``kind`` in ``gid`` with
    ``code``, without forwarding them. Returns the count left (a list, so
    the test can watch it)."""
    left = [times]

    def refuse(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if left[0] and env.get("kind") == kind and env.get("group_id") == gid:
            left[0] -= 1
            proxy._forged.append({"t": "error", "msg_id": env["msg_id"], "code": code})
            return []
        return [frame]

    proxy.client_filters.append(refuse)
    return left


async def test_storage_full_pauses_every_group_until_the_relay_takes_messages_again(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """Review F2: `storage_full` (the relay's storage at its high-water
    mark, SPEC 8.4) says "not now" for every group: the whole outbox pauses,
    and messages and commits alike go out once the relay takes them again,
    however many times it refused, never failing."""
    (a, b), gid = await group(2)
    other = a.daemon.create_group("Other", "Elsewhere")
    await a.idle()
    await cluster.invite(a, b, other)
    proxy = malicious_relay(a)
    times = MAX_COMMIT_ATTEMPTS + 2
    apps = refuse_kind(proxy, gid, "application", "storage_full", times)
    commits = refuse_kind(proxy, gid, "commit", "storage_full", times)
    epoch = a.epoch(gid)
    a.daemon.update(gid)
    a.daemon.send_message(gid, {"text": "after the mark"})
    await a.wait(lambda: a.clock.sleepers > 0)
    elsewhere = a.daemon.send_message(other, {"text": "elsewhere"})
    await a.wait(lambda: a.daemon._next_row() is None)
    assert a.daemon.store.outbox_state_of(elsewhere) == "queued"  # every group waits
    for _ in range(4 * times):
        if b.adapter.texts(gid):
            break
        await a.wait(lambda: a.clock.sleepers > 0 or bool(b.adapter.texts(gid)))
        await advance(60)
    assert await b.wait_texts(gid, 1) == ["after the mark"]
    assert await b.wait_texts(other, 1) == ["elsewhere"]
    assert (apps, commits) == ([0], [0])
    await a.idle()
    assert a.epoch(gid) == epoch + 1
    assert not a.adapter.of_type("send_failed")
    assert not a.adapter.of_type("commit_failed")


async def test_over_budget_holds_up_only_its_group_and_costs_no_try(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy, advance: Advance
) -> None:
    """Review F2: `over_budget` (the sender's budget of undelivered
    messages, SPEC 8.3) holds up only the group whose send it refused, for
    as long as it takes, and a cadence Update inside the message's row
    waits the same way."""
    (a, b), gid = await group(2)
    other = a.daemon.create_group("Other", "Elsewhere")
    await a.idle()
    await cluster.invite(a, b, other)
    proxy = malicious_relay(a)
    times = MAX_COMMIT_ATTEMPTS + 2
    epoch = a.epoch(gid)
    a.daemon.store.update_group(gid, msgs_since_commit=UPDATE_AFTER_MESSAGES)
    commits = refuse_kind(proxy, gid, "commit", "over_budget", times)
    apps = refuse_kind(proxy, gid, "application", "over_budget", times)
    a.daemon.send_message(gid, {"text": "once there is room"})
    await a.wait(lambda: a.clock.sleepers > 0)
    a.daemon.send_message(other, {"text": "meanwhile"})
    assert await b.wait_texts(other, 1) == ["meanwhile"]
    for _ in range(4 * times):
        if b.adapter.texts(gid):
            break
        await a.wait(lambda: a.clock.sleepers > 0 or bool(b.adapter.texts(gid)))
        await advance(60)
    assert await b.wait_texts(gid, 1) == ["once there is room"]
    assert (apps, commits) == ([0], [0])
    await a.idle()
    assert a.epoch(gid) == epoch + 1
    assert not a.adapter.of_type("send_failed")
    assert not a.adapter.of_type("commit_failed")


async def test_a_joiner_sends_its_capabilities_whatever_its_adapter(
    cluster: Cluster,
) -> None:
    """Review F3: right after joining, every instance sends
    `control.capabilities` (SPEC 7.3), also one whose adapter has no Agent
    Card. That first send in the group is what makes the relay count the
    group's traffic to it as member traffic (SPEC 8.3)."""
    a = await cluster.node("a")
    gid = a.daemon.create_group("Caps", "")
    await a.idle()
    b = await cluster.node("b")
    assert b.adapter.capabilities().agent_card is None
    await cluster.invite(a, b, gid)

    def caps() -> list[Any]:
        return [d for d in a.adapter.deliveries if d.kind == "control.capabilities"]

    await a.adapter.wait_for(lambda: bool(caps()), WAIT)
    (got,) = caps()
    assert got.sender.identity == b.me
    assert got.body["adapters"] == [], "nothing of the operator's configuration"
    assert "text" in got.body["accepts"]
    assert not got.addressed_to_me  # context: it triggers nobody
