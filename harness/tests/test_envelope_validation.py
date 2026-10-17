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
from agentconnect_harness.cluster import Node
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
