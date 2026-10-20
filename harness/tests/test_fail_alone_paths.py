"""The edges of failing alone, one at a time: what happens when the
bookkeeping of a failure itself can't be done, a count runs out before a
message is handled, or an adapter can't write a message out."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any

import pytest

import agentconnect_core as ac
from agentconnect.adapter import DeliveryResult
from agentconnect.runtime import engine as engine_module
from agentconnect.runtime.engine import Engine, journal_key
from agentconnect_harness.cluster import Node

from .test_poison_messages import audit_row, events, handled, raw_send, unwedged

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]


async def test_a_message_counted_out_before_it_arrives_fails_alone(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Handlings that never finished (crashes) count before the next one runs:
    past the bound it fails alone without being handled."""
    monkeypatch.setattr(engine_module, "MAX_ENTRY_ATTEMPTS", 1)
    (a, b), gid = await group(2)
    msg_id = raw_send(a, gid, {"parts": [{"text": "x"}]})
    key = journal_key(a.daemon.mailbox, msg_id)
    b.daemon.store.attempt(key, b.daemon.now())
    assert await handled(b, a, msg_id) == "failed"
    (event,) = events(b, "message_failed")
    assert (event["msg_id"], event["reason"]) == (msg_id, "RetriesExhausted")
    assert audit_row(b, gid, msg_id)["reason"] == "processing_failed"
    assert b.daemon.store.attempt_count(key) == 0
    await unwedged(b, a, gid)


async def test_counts_that_cant_be_stored_are_retried(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (_a, b), _gid = await group(2)
    e = b.daemon
    assert e._count(None) == 0
    e._uncount(None)

    def broken(*_args: Any) -> int:
        msg = "disk I/O error"
        raise ac.AgentConnectError(msg)

    monkeypatch.setattr(e.store, "attempt", broken)
    monkeypatch.setattr(e.store, "attempt_clear", broken)
    e._counted = set()
    assert e._count("k") == 0
    e._uncount("k")  # logged, not raised


async def test_failing_alone_survives_its_own_failures(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    e = b.daemon
    # A frame with no message to fail is only logged.
    await e._fail_frame({"t": "caught_up"}, ValueError("x"))
    # The journal can't be read: no entry.
    monkeypatch.setattr(e, "client", SimpleNamespace(journal_pending=_raises_core))
    assert e._journal_entry({"sender": "s", "msg_id": "m"}) is None
    monkeypatch.undo()

    async def failing(*_args: Any, **_kw: Any) -> str:
        msg = "storage gone"
        raise RuntimeError(msg)

    monkeypatch.setattr(e, "_fail_message", failing)
    env = {"sender": a.daemon.mailbox, "msg_id": "m-1", "group_id": gid, "kind": "application"}
    await e._fail_frame({"t": "deliver", "env": env}, ValueError("x"))  # logged
    assert e.store.inbox_state(a.daemon.mailbox, "m-1") is None
    monkeypatch.undo()
    # A message recorded already isn't recorded again.
    done = raw_send(a, gid, {"parts": [{"text": "ok"}]})
    assert await handled(b, a, done) == "done"
    env = {"sender": a.daemon.mailbox, "msg_id": done, "group_id": gid, "kind": "application"}
    assert await e._fail_message(env, ValueError("x")) == "done"
    assert not events(b, "message_failed")


def _raises_core() -> list[Any]:
    msg = "the core panicked"
    raise ac.CoreError(msg)


async def test_journal_entries_that_cant_fail_alone_stay(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (_a, b), _gid = await group(2)
    e = b.daemon
    assert not await e._fail_entry({"key": "k", "context": b"{", "welcome": False}, ValueError())
    # An entry that isn't the daemon's own goes, with nothing to record.
    entry = {"key": "k2", "context": b'{"env": 1}', "welcome": False, "group_id": b"g"}
    monkeypatch.setattr(e, "client", SimpleNamespace(journal_consume=lambda *_a: None))
    assert await e._fail_entry(entry, ValueError())
    monkeypatch.undo()
    # One that can't fail alone stays, and the replay goes on.
    monkeypatch.setattr(engine_module, "MAX_ENTRY_ATTEMPTS", 0)

    async def stays(_entry: dict[str, Any], _error: Exception) -> bool:
        return False

    replayed: list[str] = []

    async def replay(entry: dict[str, Any]) -> None:
        replayed.append(entry["key"])

    entries = [{"key": "a"}, {"key": "b"}]
    fake = SimpleNamespace(
        client=SimpleNamespace(journal_pending=lambda: entries),
        _count=lambda _key: 1,
        _uncount=lambda _key: None,
        _fail_entry=stays,
        _replay_entry=replay,
    )
    await Engine._replay_journal(fake)  # ty: ignore[invalid-argument-type]
    assert replayed == []
    monkeypatch.setattr(engine_module, "MAX_ENTRY_ATTEMPTS", 8)

    async def broken(entry: dict[str, Any]) -> None:
        raise OverflowError

    fake._replay_entry = broken
    await Engine._replay_journal(fake)  # ty: ignore[invalid-argument-type]


async def test_followups_and_bookkeeping_edges(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    e = b.daemon
    # Parked frames released by a join are handled after the frame, also
    # when a test hands frames over directly.
    e._followups.append({"kind": "application", "msg_id": "m", "sender": "s"})
    await e._handle_frame({"t": "ignored"})
    assert not e._followups
    # message_failed reports are tracked for a bounded number of pairs.
    monkeypatch.setattr(engine_module, "MAX_FAILED_TRACKED", 1)
    e._failed_counted(("g", "x"), reported=True)
    e._failed_counted(("g", "y"), reported=True)
    assert list(e._failed) == [("g", "y")]
    # A joined group the daemon has a row for already goes out of sync.
    with e.store.tx():
        await e._joined_out_of_sync(gid, None)
    info = e.group_info(gid)
    assert (info["out_of_sync"], info["out_of_sync_reason"]) == (True, "welcome_failed")
    # The loop guard of a failed message: a malformed hop decides nothing,
    # a hop past the group's turns pauses.
    paused: list[int] = []

    async def guard(_group: Any, _msg_id: str, _identity: str, hop: int) -> None:
        paused.append(hop)

    monkeypatch.setattr(e, "_loop_guard", guard)
    row = e.store.group(gid)
    assert row is not None
    await e._guard_failed(row, "m", a.me, {"hop": -1})
    await e._guard_failed(row, "m", a.me, {"hop": 10_000, "to": ["*"]})
    assert paused == [10_000]


async def test_an_adapter_that_cant_write_a_message_out_fails_it_alone(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every adapter, not only MCP: a UnicodeError while writing out is the
    message's, so the adapter acks it and the human hears, once per window."""
    (a, b), gid = await group(2)
    deliver = b.adapter.deliver
    bad: set[str] = set()

    async def writing(view: Any, sender: Any, to: Any, delivery: Any) -> DeliveryResult:
        if delivery.msg_id in bad:
            raise UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed")
        return await deliver(view, sender, to, delivery)

    monkeypatch.setattr(b.adapter, "deliver", writing)
    first = raw_send(a, gid, {"parts": [{"text": "one"}]})
    second = raw_send(a, gid, {"parts": [{"text": "two"}]})
    bad.update({first, second})
    mailbox = a.daemon.mailbox
    await b.wait(lambda: b.daemon.store.inbox_state(mailbox, second) == "done")
    assert b.daemon.store.inbox_state(mailbox, first) == "done"
    (event,) = events(b, "message_failed")
    assert (event["msg_id"], event["reason"], event["count"]) == (first, "unencodable", 1)
    await unwedged(b, a, gid)
