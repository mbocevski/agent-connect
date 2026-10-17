"""Daemon behaviour against the real relay: cadence, retries, gating, joins."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.adapter import Delivery, GroupView, PolicyDecision, RecordingAdapter
from agentconnect.daemon import UPDATE_AFTER_MESSAGES, UPDATE_AFTER_SECS, DaemonError
from agentconnect_harness.cluster import Cluster, Node, status
from agentconnect_harness.proxy import RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]
Proxy = Callable[[Node], RelayProxy]


async def test_update_cadence_by_time_and_count(group: GroupFixture, advance: Advance) -> None:
    (a, b), gid = await group(2)
    epoch = a.epoch(gid)
    await advance(UPDATE_AFTER_SECS)
    a.daemon.send_message(gid, {"text": "after a day"})
    assert await b.wait_texts(gid, 1) == ["after a day"]
    assert a.epoch(gid) == b.epoch(gid) == epoch + 1
    a.daemon.store.update_group(gid, msgs_since_commit=UPDATE_AFTER_MESSAGES)
    a.daemon.send_message(gid, {"text": "after many"})
    await b.wait_texts(gid, 2)
    assert a.epoch(gid) == epoch + 2
    g = a.daemon.store.group(gid)
    assert g is not None
    assert g.msgs_since_commit == 1


async def test_adapter_retry_holds_the_relay_ack(group: GroupFixture, advance: Advance) -> None:
    (a, b), gid = await group(2)
    b.adapter.retry_next = 2
    a.daemon.send_message(gid, {"text": "eventually"})
    await b.wait(lambda: b.adapter.retry_next == 1 and b.clock.sleepers > 0)
    assert b.daemon.status()["inbox_pending"] == 1
    # Restarting before the adapter accepted: the relay redelivers and the
    # inbox deduplicates, so the message arrives exactly once.
    await b.restart()
    await b.wait(lambda: b.adapter.retry_next == 0 and b.clock.sleepers > 0)
    await advance(10)
    assert await b.wait_texts(gid, 1) == ["eventually"]
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 0)


class DropAll:
    def inbound(self, group: GroupView, delivery: Delivery) -> PolicyDecision:
        return PolicyDecision.DROP

    def outbound(self, group: GroupView, inner: dict[str, Any]) -> PolicyDecision:
        return PolicyDecision.DROP if inner["body"].get("blocked") else PolicyDecision.ALLOW


async def test_policy_hook_can_drop(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    b.daemon.policy = DropAll()
    a.daemon.send_message(gid, {"text": "dropped"})
    await b.wait(
        lambda: b.daemon.store.pending_deliveries() == [] and bool(b.daemon.store.events())
    )
    await a.idle()
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 0)
    assert b.adapter.texts(gid) == []
    with pytest.raises(DaemonError, match="policy"):
        b.daemon.send_message(gid, {"blocked": True})


async def test_require_verified_holds_deliveries(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    a.daemon.set_policy(gid, require_verified=True)
    await b.wait(lambda: b.daemon.group_info(gid)["policy"]["require_verified"])
    assert b.adapter.of_type("policy_changed")
    a.daemon.send_message(gid, {"text": "held"})
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 1)
    assert b.adapter.texts(gid) == []
    with pytest.raises(DaemonError):
        b.daemon.mark_verified(gid, b.me)  # not for oneself
    with pytest.raises(DaemonError):
        b.daemon.mark_verified(gid, "ac:v0:nobody")
    b.daemon.mark_verified(gid, a.me)
    assert await b.wait_texts(gid, 1) == ["held"]
    (d,) = b.adapter.deliveries
    assert d.trust_state == {"self": "verified", "verified_members": 1, "members": 2}
    assert d.sender.verified


async def test_agent_cards_are_exchanged(cluster: Cluster) -> None:
    a = await cluster.node("a")
    a.adapter = RecordingAdapter(card={"name": "Alice agent", "skills": []})
    await a.restart()
    gid = a.daemon.create_group("Cards", "Swap cards")
    await a.idle()
    b = await cluster.node("b")
    b.adapter = RecordingAdapter(card={"name": "Bob agent"})
    await b.restart()
    await cluster.invite(a, b, gid)
    await a.wait(lambda: a.me in b.daemon.store.cards(gid) and b.me in a.daemon.store.cards(gid))
    names = {m["identity"]: m["display_name"] for m in a.daemon.group_info(gid)["members"]}
    assert names[b.me] == "Bob agent"
    assert b.daemon.group_info(gid)["agent_cards"][a.me]["name"] == "Alice agent"


async def test_join_approval_rules(cluster: Cluster, advance: Advance) -> None:
    a = await cluster.node("a", auto_approve=False)
    b = await cluster.node("b")
    c = await cluster.node("c")
    gid = a.daemon.create_group("Rules", "")
    await a.idle()
    for joiner in (b, c):
        invite = await a.daemon.create_invite(gid)
        await joiner.daemon.accept_invite(invite["url"])
    await a.wait(lambda: len(a.daemon.approvals()) == 2)
    first, second = a.daemon.approvals()
    a.daemon.reject(first["request_id"])
    with pytest.raises(DaemonError):
        a.daemon.reject(first["request_id"])
    with pytest.raises(DaemonError):
        a.daemon.approve("nope")
    await advance(3601)
    with pytest.raises(DaemonError, match="1 hour"):
        a.daemon.approve(second["request_id"])
    assert a.daemon.approvals() == []
    assert a.daemon.store.group(gid) is not None
    assert b.daemon.store.group(gid) is None


async def test_expired_approvals_disappear_from_the_list(
    cluster: Cluster, advance: Advance
) -> None:
    a = await cluster.node("a", auto_approve=False)
    b = await cluster.node("b")
    gid = a.daemon.create_group("Old", "")
    await a.idle()
    invite = await a.daemon.create_invite(gid)
    await b.daemon.accept_invite(invite["url"])
    await a.wait(lambda: len(a.daemon.approvals()) == 1)
    await advance(3601)
    assert a.daemon.approvals() == []


async def test_invite_errors(cluster: Cluster, group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    c = await cluster.node("c")
    invite = await a.daemon.create_invite(gid, max_uses=1)
    await a.daemon.revoke_invite(invite["invite_id"])
    info = await c.daemon.inspect_invite(invite["url"])
    assert info["meta"]["status"] == "revoked"
    assert info["warning"] is not None
    assert "already used or revoked" in info["warning"]
    with pytest.raises(DaemonError, match="already used or revoked"):
        await c.daemon.accept_invite(invite["url"])
    with pytest.raises(DaemonError):
        await a.daemon.revoke_invite("nope")
    with pytest.raises(DaemonError, match="different relay"):
        await c.daemon.inspect_invite(invite["url"].replace("127.0.0.1", "localhost"))
    with pytest.raises(DaemonError, match="invalid invite URL"):
        await c.daemon.inspect_invite("https://example.org/x")
    unknown = invite["url"].replace(invite["invite_id"], "A" * 22)
    with pytest.raises(DaemonError, match="already used or revoked"):
        await c.daemon.inspect_invite(unknown)
    # A non-owner may not invite under the default policy.
    with pytest.raises(DaemonError, match=r"may not|does not let"):
        await b.daemon.create_invite(gid)
    with pytest.raises(DaemonError):
        await a.daemon.create_invite("no-such-group")


async def test_an_exhausted_invite_is_not_reused(cluster: Cluster) -> None:
    a = await cluster.node("a")
    b = await cluster.node("b")
    c = await cluster.node("c")
    gid = a.daemon.create_group("Once", "")
    await a.idle()
    invite = await a.daemon.create_invite(gid)
    await b.daemon.accept_invite(invite["url"])
    await b.wait(lambda: b.daemon.store.group(gid) is not None)
    await a.wait(
        lambda: (a.daemon.store.invite(invite["invite_id"]) or {})["status"] == "exhausted"
    )
    with pytest.raises(DaemonError, match="already used"):
        await c.daemon.accept_invite(invite["url"])


async def test_leave_rules_and_removal(cluster: Cluster, group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    with pytest.raises(DaemonError, match="transfer ownership"):
        await a.daemon.leave(gid)
    a.daemon.remove_member(gid, c.me)
    await c.wait(lambda: status(c, gid) == "removed")
    assert c.adapter.of_type("removed")
    await b.wait(lambda: len(b.daemon.store.members(gid)) == 2)
    assert b.adapter.of_type("member_removed")
    with pytest.raises(DaemonError):
        c.daemon.send_message(gid, {"text": "gone"})
    solo = await cluster.node("solo")
    sgid = solo.daemon.create_group("Solo", "")
    assert await solo.daemon.leave(sgid) == "left"
    assert solo.daemon.group_info(sgid)["status"] == "left"
    with pytest.raises(DaemonError):
        solo.daemon.group_info("nope")


async def test_misbehaviour_on_epoch_and_unknown_traffic(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    proxy = malicious_relay(b)

    def bump_epoch(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if frame.get("t") == "deliver" and env.get("kind") == "application":
            env["epoch"] += 1
        return [frame]

    proxy.server_filters.append(bump_epoch)
    a.daemon.send_message(gid, {"text": "tampered epoch"})
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("relay_misbehaviour")))
    assert b.adapter.of_type("relay_misbehaviour")[0].data["reason"] == "epoch_mismatch"
    assert b.adapter.texts(gid) == []
    proxy.server_filters.clear()
    # Frames for unknown groups, unknown kinds, other versions and junk
    # join requests are acknowledged and dropped.
    mb = a.daemon.mailbox
    junk = [
        {
            "v": 0,
            "kind": "application",
            "group_id": "Z" * 22,
            "msg_id": "J1" + "A" * 20,
            "sender": mb,
            "epoch": 0,
            "ct": "",
        },
        {"v": 1, "kind": "application", "msg_id": "J2" + "A" * 20, "sender": mb, "ct": ""},
        {"v": 0, "kind": "mystery", "msg_id": "J3" + "A" * 20, "sender": mb, "ct": ""},
        {
            "v": 0,
            "kind": "join_request",
            "msg_id": "J4" + "A" * 20,
            "sender": mb,
            "ct": "bm90IGpzb24",
        },
        {
            "v": 0,
            "kind": "join_request",
            "msg_id": "J5" + "A" * 20,
            "sender": mb,
            "ct": "eyJpbnZpdGVfaWQiOiJ4In0",
        },
        {
            "v": 0,
            "kind": "welcome_wrapped",
            "group_id": gid,
            "msg_id": "J6" + "A" * 20,
            "sender": mb,
            "ct": "AAAA",
        },
        {
            "v": 0,
            "kind": "application",
            "group_id": gid,
            "msg_id": "J7" + "A" * 20,
            "sender": mb,
            "epoch": 1,
            "ct": "AAAA",
        },
    ]
    for env in junk:
        await proxy.inject({"t": "deliver", "env": env})
    await proxy.inject({"t": "pong"})
    await proxy.inject({"t": "queue_overflow", "group_id": "unknown", "msg_id": "x"})
    await b.wait(lambda: b.daemon.store.inbox_state(mb, "J7" + "A" * 20) is not None)
    a.daemon.send_message(gid, {"text": "fine"})
    assert await b.wait_texts(gid, 1) == ["fine"]
    assert not b.daemon.group_info(gid)["out_of_sync"]
