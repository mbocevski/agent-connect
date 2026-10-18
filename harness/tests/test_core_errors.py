"""Core errors are classified: transient ones (storage, a panic) are retried
without acking, and a commit that can't be merged marks the group
``out_of_sync`` instead of silently forking the member."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

import agentconnect_core as ac
from agentconnect.runtime.engine import MAX_TRANSIENT_RETRIES, _core_error
from agentconnect_harness.cluster import Node

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]


class FlakyCore:
    """Wraps a core client; ``process`` raises the queued errors first."""

    def __init__(self, client: ac.Client) -> None:
        self._client = client
        self.errors: list[Exception] = []
        self.calls = 0

    def process(self, gid: bytes, message: bytes, **journal: Any) -> dict[str, Any]:
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return self._client.process(gid, message, **journal)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def flaky(node: Node, monkeypatch: pytest.MonkeyPatch) -> FlakyCore:
    core = FlakyCore(node.daemon.client)
    monkeypatch.setattr(node.daemon, "client", core)
    return core


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (ac.AgentConnectError("storage error: database is locked"), "transient"),
        (ac.AgentConnectError("wrong database key, or not an encrypted store"), "transient"),
        (ac.AgentConnectError("internal error: x"), "transient"),
        (ac.CoreError("the core panicked; the operation did not complete"), "transient"),
        (ac.AgentConnectError("message is for a different epoch"), "rejected"),
        (ac.AgentConnectError("unauthorized commit: x"), "unauthorized_commit"),
    ],
)
def test_classification(error: Exception, kind: str) -> None:
    assert _core_error(error) == kind


async def test_transient_errors_are_retried_without_acking(
    group: GroupFixture, advance: Advance, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    core = flaky(b, monkeypatch)
    core.errors = [
        ac.AgentConnectError("storage error: disk I/O error"),
        ac.CoreError("the core panicked; the operation did not complete"),
    ]
    msg_id = a.daemon.send_message(gid, {"text": "eventually"})
    await b.wait(lambda: core.calls == 1 and b.clock.sleepers > 0)
    # Not recorded, so not acked: the relay still holds it.
    assert b.daemon.store.inbox_state(a.daemon.mailbox, msg_id) is None
    await advance(300)
    await b.wait(lambda: core.calls == 2 and b.clock.sleepers > 0)
    await advance(300)
    assert await b.wait_texts(gid, 1) == ["eventually"]
    assert core.calls == 3
    assert not b.adapter.of_type("out_of_sync")


async def test_persistent_transient_errors_give_up_unacked(
    group: GroupFixture, advance: Advance, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    core = flaky(b, monkeypatch)
    core.errors = [ac.AgentConnectError("storage error: x")] * MAX_TRANSIENT_RETRIES
    msg_id = a.daemon.send_message(gid, {"text": "later"})
    for n in range(1, MAX_TRANSIENT_RETRIES):
        await b.wait(lambda n=n: core.calls == n and b.clock.sleepers > 0)
        await advance(300)
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("processing_failed")))
    assert b.daemon.store.inbox_state(a.daemon.mailbox, msg_id) is None
    # A reconnect redelivers it and it goes through.
    await b.restart()
    assert await b.wait_texts(gid, 1) == ["later"]


async def test_a_commit_that_fails_marks_the_group_out_of_sync(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    core = flaky(b, monkeypatch)
    core.errors = [ac.AgentConnectError("invalid group context: something")]
    a.daemon.update(gid)
    await b.adapter.wait_for(lambda: bool(b.adapter.of_type("out_of_sync")))
    (event,) = b.adapter.of_type("out_of_sync")
    assert event.data["reason"] == "commit_rejected"
    assert b.daemon.group_info(gid)["out_of_sync"]
