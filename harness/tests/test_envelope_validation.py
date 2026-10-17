"""Relay-visible envelope fields are checked before the core processes
anything, and the daemon's cached group view follows the core after every
merge, even if later bookkeeping fails (SPEC §7.1, §10.4)."""

from __future__ import annotations

import base64
import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from agentconnect.daemon import _envelope_problem
from agentconnect.store import GroupRow
from agentconnect_harness.cluster import Cluster, Node
from agentconnect_harness.proxy import RelayProxy

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Proxy = Callable[[Node], RelayProxy]


def raw(gid: str) -> bytes:
    return bytes(base64.urlsafe_b64decode(gid + "=="))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("routing", "x"),
        ("routing", ["not", "a", "dict"]),
        ("routing", {"add": [1]}),
        ("epoch", "1"),
    ],
)
async def test_a_malformed_commit_envelope_is_dropped_unprocessed(
    group: GroupFixture, malicious_relay: Proxy, field: str, value: Any
) -> None:
    (a, b), gid = await group(2)

    def mangle(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if frame.get("t") == "deliver" and env.get("kind") == "commit":
            env[field] = value
        return [frame]

    malicious_relay(b).server_filters.append(mangle)
    before = b.daemon.client.epoch(raw(gid))
    a.daemon.set_policy(gid, require_verified=True)
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("out_of_sync")))
    # The core never saw it: same epoch, old policy.
    assert b.daemon.client.epoch(raw(gid)) == before
    assert not json.loads(b.daemon.client.policy(raw(gid)))["require_verified"]
    (alert,) = b.adapter.of_type("relay_misbehaviour")
    assert alert.data["reason"] == "malformed_envelope"
    assert b.adapter.of_type("out_of_sync")[0].data["reason"] == "commit_dropped"


def cached(node: Node, gid: str) -> GroupRow:
    g = node.daemon.store.group(gid)
    assert g is not None
    return g


async def test_require_verified_holds_after_an_error_mid_processing(
    group: GroupFixture, malicious_relay: Proxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    # A routing mismatch makes b raise relay_misbehaviour after the merge;
    # here that bookkeeping fails outright.
    malicious_relay(b).rewrite_routing(add=[a.daemon.mailbox])
    real = b.daemon.emit

    async def failing(group_id: str | None, kind: str, **data: Any) -> None:
        if kind == "relay_misbehaviour":
            msg = "bookkeeping failed"
            raise RuntimeError(msg)
        await real(group_id, kind, **data)

    monkeypatch.setattr(b.daemon, "emit", failing)
    a.daemon.set_policy(gid, require_verified=True)
    await b.wait(lambda: json.loads(b.daemon.client.policy(raw(gid)))["require_verified"])
    # The cache followed the core despite the exception...
    await b.wait(lambda: bool(cached(b, gid).policy.get("require_verified")))
    assert cached(b, gid).epoch == b.daemon.client.epoch(raw(gid))
    monkeypatch.undo()
    # ...so an unverified peer's message is held until the human verifies.
    a.daemon.send_message(gid, {"text": "held"})
    await b.wait(lambda: b.daemon.status()["inbox_pending"] == 1)
    assert b.adapter.texts(gid) == []
    b.daemon.mark_verified(gid, a.me)
    assert await b.wait_texts(gid, 1) == ["held"]


def test_envelope_shapes() -> None:
    good = {
        "v": 0,
        "kind": "commit",
        "group_id": "g",
        "epoch": 3,
        "msg_id": "m",
        "sender": "s",
        "routing": {"add": ["x"], "remove": []},
        "ct": "",
    }
    assert _envelope_problem(good) is None
    assert _envelope_problem({**good, "kind": "join_request", "group_id": None}) is None
    for change, problem in [
        ({"v": True}, "version"),
        ({"v": 1}, "version"),
        ({"kind": "x"}, "kind"),
        ({"msg_id": 7}, "ids"),
        ({"sender": "s" * 65}, "ids"),
        ({"ct": None}, "ct"),
        ({"group_id": ""}, "group_id"),
        ({"epoch": -1}, "epoch"),
        ({"epoch": False}, "epoch"),
        ({"to": "all"}, "to"),
        ({"routing": {"remove": "x"}}, "routing"),
    ]:
        assert _envelope_problem({**good, **change}) == problem, change


async def test_a_proposal_with_a_mismatched_epoch_is_dropped(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)

    def bump(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if frame.get("t") == "deliver" and env.get("kind") == "proposal":
            env["epoch"] += 1
        return [frame]

    malicious_relay(a).server_filters.append(bump)
    assert await b.daemon.leave(gid) == "leaving"
    await a.adapter.wait_for(lambda: bool(a.adapter.of_type("relay_misbehaviour")))
    (alert,) = a.adapter.of_type("relay_misbehaviour")
    assert alert.data["reason"] == "epoch_mismatch"
    await a.idle()
    assert b.me in {m.identity for m in a.daemon.store.members(gid)}


async def test_an_application_epoch_mismatch_is_dropped_before_processing(
    group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    originals: list[bytes] = []

    def bump(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        if frame.get("t") == "deliver" and env.get("kind") == "application":
            originals.append(raw(env["ct"]))
            env["epoch"] += 1
        return [frame]

    malicious_relay(b).server_filters.append(bump)
    a.daemon.send_message(gid, {"text": "lied about"})
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("relay_misbehaviour")))
    (alert,) = b.adapter.of_type("relay_misbehaviour")
    assert alert.data["reason"] == "epoch_mismatch"
    await b.idle()
    assert b.adapter.texts(gid) == []
    # The core never processed it: its key is still there, so the bytes
    # the relay was given still decrypt (as they would under a correct
    # envelope).
    (ct,) = originals
    event = b.daemon.client.process(raw(gid), ct)
    assert event["type"] == "application"
    assert b"lied about" in event["plaintext"]


async def test_an_application_for_another_group_is_dropped_before_processing(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    other = a.daemon.create_group("Other", "")
    await a.idle()
    await cluster.invite(a, b, other)
    originals: list[bytes] = []

    def misroute(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        mine = env.get("group_id") == gid and env.get("kind") == "application"
        if frame.get("t") == "deliver" and mine:
            originals.append(raw(env["ct"]))
            env["group_id"] = other
            env["epoch"] = b.daemon.client.epoch(raw(other))
        return [frame]

    malicious_relay(b).server_filters.append(misroute)
    a.daemon.send_message(gid, {"text": "misrouted"})
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("relay_misbehaviour")))
    (alert,) = b.adapter.of_type("relay_misbehaviour")
    assert (alert.group_id, alert.data["reason"]) == (other, "group_mismatch")
    (ct,) = originals
    assert b.daemon.client.process(raw(gid), ct)["type"] == "application"


async def test_a_commit_for_another_group_is_flagged_and_rejected(
    cluster: Cluster, group: GroupFixture, malicious_relay: Proxy
) -> None:
    (a, b), gid = await group(2)
    other = a.daemon.create_group("Other", "")
    await a.idle()
    await cluster.invite(a, b, other)
    before = b.daemon.client.epoch(raw(other))

    def misroute(frame: dict[str, Any]) -> list[dict[str, Any]]:
        env = frame.get("env") or {}
        mine = env.get("group_id") == gid and env.get("kind") == "commit"
        if frame.get("t") == "deliver" and mine:
            env["group_id"] = other
        return [frame]

    malicious_relay(b).server_filters.append(misroute)
    a.daemon.update(gid)
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("relay_misbehaviour")))
    (alert,) = b.adapter.of_type("relay_misbehaviour")
    assert (alert.group_id, alert.data["reason"]) == (other, "group_mismatch")
    assert b.daemon.client.epoch(raw(other)) == before


async def test_correct_envelopes_still_process(group: GroupFixture) -> None:
    (a, b), gid = await group(2)
    a.daemon.send_message(gid, {"text": "fine"})
    assert await b.wait_texts(gid, 1) == ["fine"]
    assert not b.adapter.of_type("relay_misbehaviour")


async def test_control_close_prompts_the_human_and_never_leaves(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    # A non-owner's close is ignored (SPEC 7.3).
    b.daemon.send_message(gid, {"reason": "not mine to close"}, kind="control.close")
    a.daemon.send_message(gid, {"reason": "done here"}, kind="control.close")
    await c.adapter.wait_for(lambda: bool(c.adapter.of_type("close_requested")))
    (event,) = c.adapter.of_type("close_requested")
    assert event.data == {"sender": a.me, "reason": "done here"}
    await c.idle()
    assert [d.body for d in c.adapter.deliveries if d.kind == "control.close"] == [
        {"reason": "done here"}
    ]
    assert cached(c, gid).status == "active"
