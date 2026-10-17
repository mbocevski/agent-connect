"""End-to-end scenarios: real relay, in-process daemons, recording adapters."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from agentconnect_harness.cluster import Cluster, Node
from agentconnect_harness.proxy import RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Cut = Callable[[Node], Awaitable[None]]
Proxy = Callable[[Node], RelayProxy]


async def cluster_settle(*args: object) -> None:
    *nodes, gid, epoch = args
    for n in nodes:
        assert isinstance(n, Node)
        assert isinstance(gid, str)
        assert isinstance(epoch, int)
        await n.wait(lambda n=n: n.epoch(gid) >= epoch)
        await n.idle()


async def test_one_to_one_lifecycle(cluster: Cluster) -> None:
    a = await cluster.node("alice", auto_approve=False)
    b = await cluster.node("bob")
    gid = a.daemon.create_group("Trip", "Plan the offsite")
    await a.idle()
    invite = await a.daemon.create_invite(gid)
    meta = await b.daemon.inspect_invite(invite["url"])
    assert meta["meta"]["group_name"] == "Trip"
    await b.daemon.accept_invite(invite["url"], "bob")
    await a.wait(lambda: len(a.daemon.approvals()) == 1)
    (pending,) = a.daemon.approvals()
    assert pending["display_name"] == "bob"
    a.daemon.approve(pending["request_id"])
    await b.wait(lambda: b.daemon.store.group(gid) is not None)
    await cluster.settle(gid, 1)
    assert a.sas(gid) == b.sas(gid)

    a.daemon.send_message(gid, {"text": "hi bob"})
    assert await b.wait_texts(gid, 1) == ["hi bob"]
    b.daemon.send_message(gid, {"text": "hi alice"})
    assert await a.wait_texts(gid, 1) == ["hi alice"]
    (d,) = b.adapter.deliveries
    assert d.untrusted
    assert d.scope == "Plan the offsite"
    assert d.addressed_to_me
    assert d.sender.identity == a.me
    assert d.trust_state["members"] == 2

    assert await b.daemon.leave(gid) == "leaving"
    await b.wait(lambda: (g := b.daemon.store.group(gid)) is not None and g.status == "left")
    await a.wait(lambda: len(a.daemon.store.members(gid)) == 1)
    assert a.adapter.of_type("member_left")


async def test_five_member_group_exchanges_messages(group: GroupFixture) -> None:
    nodes, gid = await group(5)
    assert len({n.sas(gid) for n in nodes}) == 1
    assert nodes[0].daemon.group_info(gid)["policy"]["floor"] == "mention"
    for i, n in enumerate(nodes):
        n.daemon.send_message(gid, {"text": f"from {i}"}, to=[nodes[(i + 1) % 5].me])
    for i, n in enumerate(nodes):
        texts = await n.wait_texts(gid, 4)
        assert sorted(texts) == sorted(f"from {j}" for j in range(5) if j != i)
        addressed = [d for d in n.adapter.deliveries if d.addressed_to_me]
        assert [d.body["text"] for d in addressed] == [f"from {(i - 1) % 5}"]


async def test_replicas_of_one_identity(group: GroupFixture) -> None:
    nodes, gid = await group(3, "replicas")
    info = nodes[0].daemon.group_info(gid)
    assert len(info["members"]) == 1
    assert len(info["members"][0]["instances"]) == 3
    nodes[1].daemon.send_message(gid, {"text": "replica"})
    assert await nodes[2].wait_texts(gid, 1) == ["replica"]


async def test_restart_mid_conversation_loses_nothing(
    group: GroupFixture, partition: Cut, heal: Cut
) -> None:
    (a, b), gid = await group(2)
    a.daemon.send_message(gid, {"text": "one"})
    await b.wait_texts(gid, 1)
    await b.daemon.stop()
    for text in ("two", "three"):
        a.daemon.send_message(gid, {"text": text})
    await a.idle()
    await b.start()
    assert await b.wait_texts(gid, 3) == ["one", "two", "three"]
    # Queued while cut off, then killed before it could send: the outbox
    # survives the restart.
    await partition(b)
    b.daemon.send_message(gid, {"text": "queued"})
    await b.daemon.stop()
    b.proxy.heal()
    await b.start()
    assert await a.wait_texts(gid, 1) == ["queued"]
    assert a.sas(gid) == b.sas(gid)
    assert b.daemon.group_info(gid)["status"] == "active"


async def test_epoch_conflict_resolves(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    epoch = a.epoch(gid)
    # Both commit at the same epoch; the relay orders them and the loser
    # discards, processes the winner and rebuilds.
    a.daemon.update(gid)
    b.daemon.update(gid)
    await cluster_settle(a, b, c, gid, epoch + 2)
    assert len({n.sas(gid) for n in (a, b, c)}) == 1
    c.daemon.send_message(gid, {"text": "after"}, to=["*"])
    assert await a.wait_texts(gid, 1) == ["after"]


async def test_partition_and_heal_drains_in_order(
    group: GroupFixture, partition: Cut, heal: Cut
) -> None:
    (a, b), gid = await group(2)
    await partition(b)
    for i in range(5):
        a.daemon.send_message(gid, {"text": f"in {i}"})
        b.daemon.send_message(gid, {"text": f"out {i}"})
    await a.idle()
    assert b.adapter.texts(gid) == []
    await heal(b)
    assert await b.wait_texts(gid, 5) == [f"in {i}" for i in range(5)]
    assert await a.wait_texts(gid, 5) == [f"out {i}" for i in range(5)]


async def test_queue_overflow_marks_out_of_sync(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    await malicious_relay(b).inject(
        {"t": "queue_overflow", "group_id": gid, "msg_id": "AAAAAAAAAAAAAAAAAAAAAA", "epoch": 1}
    )
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("out_of_sync")))
    info = b.daemon.group_info(gid)
    assert info["out_of_sync"]
    assert info["out_of_sync_reason"] == "queue_overflow"
    assert b.daemon.status()["out_of_sync"] == [gid]
    # Processing continues.
    a.daemon.send_message(gid, {"text": "still here"})
    assert await b.wait_texts(gid, 1) == ["still here"]


async def test_routing_hint_mismatch_raises_relay_misbehaviour(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    malicious_relay(b).rewrite_routing(add=[a.daemon.mailbox])
    epoch = a.epoch(gid)
    a.daemon.update(gid)
    await b.wait(lambda: b.epoch(gid) == epoch + 1)
    (alert,) = b.adapter.of_type("relay_misbehaviour")
    assert alert.data["reason"] == "routing_mismatch"
    assert not a.adapter.of_type("relay_misbehaviour")


async def test_replayed_frames_are_ignored(group: GroupFixture, malicious_relay: Proxy) -> None:
    (a, b), gid = await group(2)
    a.daemon.send_message(gid, {"text": "once"})
    await b.wait_texts(gid, 1)
    proxy = malicious_relay(b)
    frame = proxy.last_delivered("application")
    await proxy.replay(frame)  # same msg_id: deduplicated
    renamed = {**frame, "env": {**frame["env"], "msg_id": "BBBBBBBBBBBBBBBBBBBBBB"}}
    await proxy.replay(renamed)  # new msg_id, same ciphertext: MLS rejects it
    await b.wait(
        lambda: b.daemon.store.inbox_state(a.daemon.mailbox, "BBBBBBBBBBBBBBBBBBBBBB") is not None
    )
    a.daemon.send_message(gid, {"text": "twice"})
    assert await b.wait_texts(gid, 2) == ["once", "twice"]


async def test_fork_shows_as_differing_sas(group: GroupFixture, malicious_relay: Proxy) -> None:
    (a, b, c), gid = await group(3)
    malicious_relay(b).fork_own_commits()
    epoch = b.epoch(gid)
    b.daemon.update(gid)
    await b.wait(lambda: b.epoch(gid) == epoch + 1)
    assert a.epoch(gid) == c.epoch(gid) == epoch
    assert a.sas(gid) == c.sas(gid) != b.sas(gid)


async def test_own_commit_lost_after_rebuild_marks_out_of_sync(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    malicious_relay(a).lose_next_commit_confirmation()
    a.daemon.update(gid)
    await a.adapter.wait_for(lambda: bool(a.adapter.of_type("out_of_sync")))
    info = a.daemon.group_info(gid)
    assert info["out_of_sync_reason"] == "own_commit_lost"
    # The relay really accepted the commit: b moved on.
    await b.wait(lambda: b.epoch(gid) == info["epoch"] + 1)
