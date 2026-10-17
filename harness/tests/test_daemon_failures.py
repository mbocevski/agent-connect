"""Failure handling: relay errors, broken adapters, restarts mid-operation."""

from __future__ import annotations

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
from agentconnect.daemon import Daemon, DaemonError, new_msg_id
from agentconnect.keystore import FileKeystore
from agentconnect_harness.cluster import Cluster, Node, status
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
    # The failed row keeps its msg_id, not its plaintext.
    assert [r.payload for r in a.daemon.store.outbox("failed")] == [{"msg_id": lost}]
    # A commit the relay rejects outright is discarded, not merged.
    epoch = a.epoch(gid)
    proxy.fail_next("send", "quota_exceeded", kind="commit")
    a.daemon.update(gid)
    await a.idle()
    assert a.epoch(gid) == epoch
    assert not a.daemon.client.has_pending_commit(bytes(base64.urlsafe_b64decode(gid + "==")))
    a.daemon.send_message(gid, {"text": "still in sync"})
    assert await b.wait_texts(gid, 3) == ["resealed", "later", "still in sync"]


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
    rows = [r for r in a.daemon.store.events() if r["type"] == "pending_approval"]
    await a.wait(lambda: a.daemon.store.inbox_state(c.daemon.mailbox, _join_msg_id(c)) is not None)
    await a.wait(lambda: a.daemon.store.inbox_state(b.daemon.mailbox, _join_msg_id(b)) is not None)
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
    malicious_relay(d).hold_welcome_until_application()
    epoch = a.epoch(gid)
    await d.daemon.accept_invite(invite["url"])
    await b.wait(lambda: b.epoch(gid) == epoch + 1)
    b.daemon.send_message(gid, {"text": "early"}, to=["*"])
    assert await d.wait_texts(gid, 1) == ["early"]


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
    b.daemon = Daemon(
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
    n.daemon = Daemon(
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
    assert gid in c.daemon._leaving
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
