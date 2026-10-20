"""What a daemon sees of a public relay's limits (SPEC 4.2, 8.3): a group the
relay deleted after its idle period, and invite text the relay refuses.

The harness relay runs on the system clock, so the idle period itself is
covered by the relay's tests (``relay/tests/group_quotas.rs``); here the
relay's answer for a deleted group, ``unknown_group``, comes from the proxy.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.runtime.engine import DaemonError
from agentconnect_harness.cluster import Cluster, Node
from agentconnect_harness.proxy import RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Proxy = Callable[[Node], RelayProxy]


def record_frames(proxy: RelayProxy) -> list[str]:
    """Every frame type the daemon sends from now on."""
    sent: list[str] = []

    def record(frame: dict[str, Any]) -> list[dict[str, Any]]:
        sent.append(str(frame.get("t")))
        return [frame]

    proxy.client_filters.insert(0, record)
    return sent


async def test_a_group_the_relay_no_longer_holds_goes_out_of_sync(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    proxy = malicious_relay(b)
    sent = record_frames(proxy)
    proxy.fail_next("send", "unknown_group", kind="application")
    lost = b.daemon.send_message(gid, {"text": "anyone there?"})
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("out_of_sync")))
    await b.idle()

    info = b.daemon.group_info(gid)
    assert info["out_of_sync"]
    assert info["out_of_sync_reason"] == "unknown_group"
    assert b.daemon.status()["out_of_sync"] == [gid]
    (failed,) = b.adapter.of_type("send_failed")
    assert failed.data == {"msg_id": lost, "code": "unknown_group"}

    # Later sends fail locally; the daemon tells the human once and neither
    # re-creates the group nor rejoins it.
    b.daemon.send_message(gid, {"text": "again"})
    await b.idle()
    assert len(b.adapter.of_type("out_of_sync")) == 1
    assert sent.count("send") == 1
    assert "group.create" not in sent
    assert "join" not in sent
    assert a.adapter.texts(gid) == []


async def test_a_commit_to_a_group_the_relay_no_longer_holds_goes_out_of_sync(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    epoch = b.epoch(gid)
    malicious_relay(b).fail_next("send", "unknown_group", kind="commit")
    b.daemon.update(gid)
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("out_of_sync")))
    await b.idle()
    assert b.daemon.group_info(gid)["out_of_sync_reason"] == "unknown_group"
    # The refused commit was discarded, not merged.
    assert b.epoch(gid) == epoch
    assert a.epoch(gid) == epoch


async def test_not_member_for_a_group_this_instance_is_in_tells_the_human(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    # Someone registered the id again after the relay deleted the group, or
    # the relay misbehaves: the human hears of it once, and the group stays.
    (_, b), gid = await group(2)
    proxy = malicious_relay(b)
    proxy.fail_next("send", "not_member", kind="application", times=2)
    b.daemon.send_message(gid, {"text": "refused"})
    b.daemon.send_message(gid, {"text": "refused again"})
    await b.wait(lambda: len(b.adapter.of_type("send_failed")) == 2)
    await b.idle()
    (alert,) = b.adapter.of_type("relay_misbehaviour")
    assert alert.data == {"reason": "not_member"}
    assert not b.daemon.group_info(gid)["out_of_sync"]


async def test_other_refusals_leave_the_group_as_it_is(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (_, b), gid = await group(2)
    malicious_relay(b).fail_next("send", "bad_request", kind="application")
    b.daemon.send_message(gid, {"text": "refused"})
    await b.wait(lambda: bool(b.adapter.of_type("send_failed")))
    await b.idle()
    assert not b.daemon.group_info(gid)["out_of_sync"]
    assert not b.adapter.of_type("relay_misbehaviour")


async def test_a_leave_proposal_queued_as_a_frame_hears_unknown_group_too(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (_, b), gid = await group(2)
    malicious_relay(b).fail_next("send", "unknown_group", kind="proposal")
    group_row = b.daemon.store.group(gid)
    assert group_row is not None
    b.daemon.groups._propose_own_leave(group_row)
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("out_of_sync")))
    await b.idle()
    assert b.daemon.group_info(gid)["out_of_sync_reason"] == "unknown_group"


async def test_a_lost_group_create_reply_leaves_the_group_in_sync(
    cluster: Cluster, heal: Callable[[Node], Awaitable[None]]
) -> None:
    # Verification probe V4: the relay registered the group, its `accepted`
    # was lost with the connection, and the resend after the reconnect is
    # answered `accepted` (the relay records who created a group).
    a = await cluster.node("alice")
    lost = asyncio.Event()
    state: dict[str, Any] = {"msg_id": None}

    def client(frame: dict[str, Any]) -> list[dict[str, Any]]:
        if frame.get("t") == "group.create" and state["msg_id"] is None:
            state["msg_id"] = frame.get("msg_id")
        return [frame]

    def server(frame: dict[str, Any]) -> list[dict[str, Any]]:
        if (
            frame.get("t") == "accepted"
            and frame.get("msg_id") == state["msg_id"]
            and not lost.is_set()
        ):
            lost.set()
            return []
        return [frame]

    a.proxy.client_filters.append(client)
    a.proxy.server_filters.append(server)
    gid = a.daemon.create_group("Trip", "Plan the offsite")
    await asyncio.wait_for(lost.wait(), 10)
    await a.proxy.cut()
    await a.wait(lambda: not a.daemon.link.connected)
    await heal(a)
    await a.idle()
    info = a.daemon.group_info(gid)
    assert not info["out_of_sync"], info["out_of_sync_reason"]
    assert not a.adapter.of_type("out_of_sync")
    assert (await a.daemon.create_invite(gid))["url"]


async def test_a_transient_refusal_of_group_create_is_tried_again(
    cluster: Cluster, advance: Callable[[float], Awaitable[None]]
) -> None:
    # Verification probe V4: `internal` is "not now", as for every other send.
    a = await cluster.node("alice")
    a.proxy.fail_next("group.create", "internal")
    gid = a.daemon.create_group("Trip", "Plan the offsite")
    await a.wait(lambda: a.clock.sleepers > 0)
    await advance(60)
    await a.idle()
    info = a.daemon.group_info(gid)
    assert not info["out_of_sync"], info["out_of_sync_reason"]
    assert (await a.daemon.create_invite(gid))["url"]


async def test_a_group_the_relay_refused_to_create_tells_the_human_and_takes_no_invites(
    cluster: Cluster,
) -> None:
    # Review probe H1: a group.create refused with quota_exceeded used to be
    # dropped silently, and the group later looked deleted as idle.
    a = await cluster.node("alice")
    a.proxy.fail_next("group.create", "quota_exceeded")
    gid = a.daemon.create_group("Trip", "Plan the offsite")
    await a.adapter.wait_for(lambda: bool(a.adapter.of_type("out_of_sync")))
    await a.idle()
    (event,) = a.adapter.of_type("out_of_sync")
    assert event.data == {"reason": "not_created", "code": "quota_exceeded"}
    info = a.daemon.group_info(gid)
    assert info["out_of_sync_reason"] == "not_created"
    assert a.daemon.status()["out_of_sync"] == [gid]
    with pytest.raises(DaemonError) as e:
        await a.daemon.create_invite(gid)
    assert e.value.code == "out_of_sync"
    assert a.daemon.store.invites("open") == []
    # Sends fail here, and nothing says the relay deleted the group.
    a.daemon.send_message(gid, {"text": "anyone?"})
    await a.idle()
    assert [x.data["code"] for x in a.adapter.of_type("send_failed")] == ["out_of_sync"]
    assert len(a.adapter.of_type("out_of_sync")) == 1


@pytest.mark.parametrize(
    "name",
    [
        "\u202eexe.txt",  # right-to-left override
        "Al\u200bice",  # zero-width space
        "e\u0301",  # not NFC
    ],
)
async def test_the_relay_refuses_invite_text_that_is_not_one_line_text(
    cluster: Cluster, name: str
) -> None:
    a = await cluster.node("alice")
    gid = a.daemon.create_group("Trip", "Plan the offsite")
    await a.idle()
    with pytest.raises(DaemonError) as e:
        await a.daemon.create_invite(gid, inviter_name=name)
    assert e.value.code == "relay"
    assert "bad_request" in str(e.value)
    # Nothing is left behind, and a plain name still works.
    assert a.daemon.store.invites("open") == []
    invite = await a.daemon.create_invite(gid, inviter_name="Alice")
    assert invite["url"]
