"""Only a failure caused by a message fails it, and failing alone is
bounded (SPEC 7.2, 10.2).

- The per-sender rates come before any handling that can fail, and a
  message that fails alone counts against its sender as a violation. The
  human hears of failures once per sender, group and window, with a count.
- Housekeeping before a frame is no frame's failure.
- A commit that fails alone leaves the group out of sync, whether the core
  merged it or not; so does a Welcome the core joined but the daemon could
  never record.
- A failure that is retried (transient, or a joined Welcome's bookkeeping)
  is retried a bounded number of times, counted across restarts, then fails
  alone.
- A control or ceremony message outside the SPEC 7.2 bounds moves nothing.
- A failure is logged by its type, never its text."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import keyring.errors
import pytest

import agentconnect_core as ac
from agentconnect.failpoints import SimulatedCrash
from agentconnect.keystore import KeystoreError, KeystoreNameError
from agentconnect.limits import SENDER_PER_MINUTE
from agentconnect.policy import SafetyPolicy
from agentconnect.relay import RelayError
from agentconnect.runtime import engine as engine_module
from agentconnect.runtime.engine import Engine
from agentconnect_harness.cluster import WAIT, Cluster, Node, converged
from agentconnect_harness.proxy import RelayProxy

from .test_poison_messages import (
    audit_row,
    events,
    handled,
    raising_for,
    raw_plaintext,
    raw_send,
    until,
    unwedged,
)

GroupFixture = Callable[..., Awaitable[tuple[list[Node], str]]]
Advance = Callable[[float], Awaitable[None]]


def raw(gid: str) -> bytes:
    return base64.urlsafe_b64decode(gid + "=" * (-len(gid) % 4))


def failing_once(node: Node, original: Any) -> Any:
    """``original`` (an ``Engine`` method), raising once on ``node``."""
    left = [1]

    async def failing(self: Engine, *args: Any, **kw: Any) -> Any:
        if self is node.daemon and left[0]:
            left[0] -= 1
            msg = "a bug that is no message's"
            raise ValueError(msg)
        return await original(self, *args, **kw)

    return failing


async def through_retries(node: Node, advance: Advance, done: Callable[[], bool]) -> None:
    """Move the clock past every backoff (retries, reconnects) until ``done``."""
    for _ in range(200):
        await node.wait(lambda: done() or node.clock.sleepers > 0)
        if done():
            return
        await advance(300)
        if not node.daemon.link.connected:
            # The reconnect's sleep starts a loop turn after the link went
            # down: let it, then wake it.
            for _ in range(5):
                await asyncio.sleep(0)
            await advance(300)
            await node.connected()
        # A reconnect's drain arrives over the socket, in real time, unless
        # the runtime waits to retry a frame of it.
        await node.wait(lambda: done() or not node.daemon.link.draining or node.clock.sleepers > 0)
    assert done()


# -- the rates first, and failures counted -------------------------------------------


async def test_failures_count_against_the_sender_after_its_rate(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch, advance: Advance
) -> None:
    (a, b), gid = await group(2)
    b.daemon.safety.update(gid, {"violation_window_secs": 60})
    hop = Engine._received_hop

    def failing(self: Engine, group_id: str, inner: dict[str, Any]) -> int:
        parts = (inner.get("body") or {}).get("parts") or [{}]
        if self is b.daemon and parts[0].get("text") == "poison":
            msg = "a bug this message reaches"
            raise ValueError(msg)
        return hop(self, group_id, inner)

    monkeypatch.setattr(Engine, "_received_hop", failing)
    n = SENDER_PER_MINUTE + 10
    ids = [raw_send(a, gid, {"parts": [{"text": "poison"}]}) for _ in range(n)]
    states = [await handled(b, a, msg_id) for msg_id in ids]
    # The rate comes before the handling that fails: past it, dropped.
    assert states == ["failed"] * SENDER_PER_MINUTE + ["dropped"] * 10
    reasons = [audit_row(b, gid, msg_id)["reason"] for msg_id in ids]
    assert reasons == ["processing_failed"] * SENDER_PER_MINUTE + ["rate_limited"] * 10
    # Every one counts against the sender.
    assert b.daemon.safety.violations(gid, a.me) == n
    assert len(events(b, "repeated_violations")) == 1
    # The human hears once per window, not once per message.
    assert events(b, "message_failed") == [
        {
            "sender": a.me,
            "msg_id": ids[0],
            "message_kind": "a2a.message",
            "reason": "ValueError",
            "count": 1,
        }
    ]
    await advance(61)
    last = raw_send(a, gid, {"parts": [{"text": "poison"}]})
    assert await handled(b, a, last) == "failed"
    second = events(b, "message_failed")[1]
    # The failures since the last event, this one included.
    assert (second["msg_id"], second["count"]) == (last, SENDER_PER_MINUTE)
    await unwedged(b, a, gid)


# -- housekeeping is no message's failure --------------------------------------------


async def test_a_failure_in_housekeeping_fails_no_message(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    monkeypatch.setattr(Engine, "expire", failing_once(b, Engine.expire))
    honest = raw_send(a, gid, {"parts": [{"text": "honest"}]})
    assert await handled(b, a, honest) == "done"
    assert [d.msg_id for d in b.adapter.deliveries if d.msg_id == honest] == [honest]
    assert not events(b, "message_failed")


async def test_a_failure_in_housekeeping_skips_no_commit(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    monkeypatch.setattr(Engine, "expire", failing_once(b, Engine.expire))
    a.daemon.update(gid)
    await converged([a, b], gid)
    assert not events(b, "message_failed")
    assert not b.daemon.group_info(gid)["out_of_sync"]
    await unwedged(b, a, gid)


async def test_a_parked_message_that_fails_fails_alone_not_with_its_welcome(
    cluster: Cluster,
    malicious_relay: Callable[[Node], RelayProxy],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A message that came before the Welcome is parked, and handled once
    the join is recorded: as a message of its own, not the Welcome's."""
    a = await cluster.node("a")
    gid = a.daemon.create_group("G", "p")
    await a.idle()
    d = await cluster.node("d")
    holding = malicious_relay(d).hold_welcome_until_application()
    invite = await a.daemon.create_invite(gid)
    await d.daemon.accept_invite(invite["url"])
    await asyncio.wait_for(holding.wait(), WAIT)
    poison: set[str] = set()
    mismatch = engine_module._header_mismatch

    def failing(env: dict[str, Any], gid_: bytes, head: dict[str, Any]) -> str | None:
        if env.get("msg_id") in poison:
            msg = "a bug this message reaches, before the core"
            raise ValueError(msg)
        return mismatch(env, gid_, head)

    monkeypatch.setattr(engine_module, "_header_mismatch", failing)
    early = raw_send(a, gid, {"parts": [{"text": "early"}]})
    poison.add(early)
    mailbox = a.daemon.mailbox
    await d.wait(lambda: d.daemon.store.inbox_state(mailbox, early) is not None)
    assert d.daemon.store.inbox_state(mailbox, early) == "failed"
    (event,) = events(d, "message_failed")
    # Failed before the core opened it: its kind is the envelope's.
    assert (event["msg_id"], event["message_kind"]) == (early, "application")
    joined = d.daemon.store.group(gid)
    assert joined is not None
    assert (joined.status, joined.out_of_sync) == ("active", False)
    assert events(d, "joined")
    await unwedged(d, a, gid)


# -- a commit that fails alone leaves the group out of sync --------------------------


async def test_a_commit_that_fails_before_the_core_puts_the_group_out_of_sync(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    mismatch = engine_module._header_mismatch

    def failing(env: dict[str, Any], gid_: bytes, head: dict[str, Any]) -> str | None:
        if head.get("content_type") == "commit":
            msg = "a bug this commit reaches"
            raise ValueError(msg)
        return mismatch(env, gid_, head)

    monkeypatch.setattr(engine_module, "_header_mismatch", failing)
    epoch = b.epoch(gid)
    a.daemon.update(gid)
    await a.idle()
    await b.wait(lambda: bool(events(b, "message_failed")))
    (event,) = events(b, "message_failed")
    assert (event["message_kind"], event["reason"]) == ("commit", "ValueError")
    # Never merged: b stays behind the group, and says so.
    assert b.epoch(gid) == epoch
    info = b.daemon.group_info(gid)
    assert (info["out_of_sync"], info["out_of_sync_reason"]) == (True, "commit_unapplied")
    assert [e["reason"] for e in events(b, "out_of_sync")] == ["commit_unapplied"]


async def test_a_merged_commit_whose_bookkeeping_fails_puts_the_group_out_of_sync(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    (a, b), gid = await group(2)
    assert a.daemon.change_policy(gid, {"invite": "members"}) == "committing"
    await converged([a, b], gid)
    made = await b.daemon.create_invite(gid, max_uses=3)
    after_commit = b.daemon.groups.after_commit
    failed: list[int] = []

    async def failing(group_id: str, event: dict[str, Any], *args: Any, **kw: Any) -> None:
        if not failed:
            failed.append(1)
            msg = "bookkeeping bug"
            raise ValueError(msg)
        await after_commit(group_id, event, *args, **kw)

    monkeypatch.setattr(b.daemon.groups, "after_commit", failing)
    ended: list[str] = []
    on_epoch_changed = b.daemon.sas.on_epoch_changed

    def spy(group_id: str, committer: str | None) -> None:
        ended.append(group_id)
        on_epoch_changed(group_id, committer)

    monkeypatch.setattr(b.daemon.sas, "on_epoch_changed", spy)
    assert a.daemon.change_policy(gid, {"invite": "owner"}) == "committing"
    await converged([a, b], gid)
    await b.wait(lambda: bool(events(b, "message_failed")))
    row = b.daemon.store.group(gid)
    assert row is not None
    assert row.policy["invite"] == "owner"
    # The bookkeeping it skipped can't be trusted: out of sync, and the human
    # hears. b's commits can't land any more, so its invites close.
    info = b.daemon.group_info(gid)
    assert (info["out_of_sync"], info["out_of_sync_reason"]) == (True, "commit_unapplied")
    assert [e["reason"] for e in events(b, "out_of_sync")] == ["commit_unapplied"]
    # The earlier epoch's SAS runs end all the same (SPEC 11.3).
    assert ended == [gid]
    invite_id = made["invite_id"]
    await b.wait(lambda: b.daemon.store.invite(invite_id)["status"] == "revoked")  # ty: ignore[not-subscriptable]
    assert (await b.daemon.rest.invite_meta(invite_id))["status"] != "open"


# -- a joined Welcome's bookkeeping is finished, or the group is out of sync ---------


async def joining(cluster: Cluster, monkeypatch: pytest.MonkeyPatch) -> tuple[Node, Node, str]:
    """a's group; b redeems an invite while b's daemon can't record a join."""
    a = await cluster.node()
    gid = a.daemon.create_group("G", "p")
    await a.idle()
    b = await cluster.node()
    finish = Engine._finish_welcome

    async def failing(self: Engine, *args: Any, **kw: Any) -> str:
        if self is b.daemon:
            msg = "bookkeeping bug"
            raise ValueError(msg)
        return await finish(self, *args, **kw)

    monkeypatch.setattr(Engine, "_finish_welcome", failing)
    invite = await a.daemon.create_invite(gid)
    await b.daemon.accept_invite(invite["url"])
    await a.wait(lambda: len(a.daemon.client.members(raw(gid))) == 2)
    return a, b, gid


async def test_a_welcome_whose_bookkeeping_fails_is_finished_on_replay(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, b, gid = await joining(cluster, monkeypatch)
    await b.wait(lambda: bool(events(b, "processing_failed")))
    # The core joined; its journal entry stays for the replay, and the human
    # has heard.
    assert b.daemon.client.epoch(raw(gid)) >= 1
    (entry,) = b.daemon.client.journal_pending()
    assert entry["welcome"]
    assert b.daemon.store.group(gid) is None
    assert not events(b, "message_failed")
    monkeypatch.undo()
    await b.restart()
    await b.wait(lambda: (g := b.daemon.store.group(gid)) is not None and g.status == "active")
    await b.wait(b.daemon.caught_up)
    assert b.daemon.client.journal_pending() == []
    assert b.daemon.store.pending_joins() == []
    assert events(b, "joined")
    welcome = raw_send(a, gid, {"parts": [{"text": "welcome"}]})
    assert await handled(b, a, welcome) == "done"


async def test_a_welcome_that_never_records_fails_alone_out_of_sync(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch, advance: Advance
) -> None:
    monkeypatch.setattr(engine_module, "MAX_ENTRY_ATTEMPTS", 3)
    _a, b, gid = await joining(cluster, monkeypatch)
    await through_retries(b, advance, lambda: bool(events(b, "message_failed")))
    (event,) = events(b, "message_failed")
    assert event["message_kind"] == "welcome_wrapped"
    # Two give-ups, then it failed alone: the core's group is the daemon's,
    # out of sync, and the human hears.
    assert len(events(b, "processing_failed")) == 2
    group = b.daemon.store.group(gid)
    assert group is not None
    assert (group.out_of_sync, group.out_of_sync_reason) == (True, "welcome_failed")
    assert [e["reason"] for e in events(b, "out_of_sync")] == ["welcome_failed"]
    assert b.daemon.client.journal_pending() == []
    assert b.daemon.store.pending_joins() == []
    await through_retries(b, advance, b.daemon.caught_up)


# -- a failure that never clears fails alone after a bounded number of tries ---------


async def test_a_core_panic_on_one_message_fails_alone_after_the_bound(
    group: GroupFixture, advance: Advance, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine_module, "MAX_ENTRY_ATTEMPTS", 3)
    (a, b), gid = await group(2)
    poison: set[str] = set()
    monkeypatch.setattr(
        SafetyPolicy, "transcribe", raising_for(poison, ac.CoreError("the core panicked"))
    )
    bad = raw_send(a, gid, {"parts": [{"text": "x"}]})
    poison.add(bad)
    honest = raw_send(a, gid, {"parts": [{"text": "after"}]})
    await a.idle()
    await through_retries(b, advance, lambda: bool(events(b, "processing_failed")))
    # The count survives a restart.
    await b.restart()
    mailbox = a.daemon.mailbox
    await through_retries(b, advance, lambda: b.daemon.store.inbox_state(mailbox, bad) is not None)
    assert b.daemon.store.inbox_state(mailbox, bad) == "failed"
    assert len(events(b, "processing_failed")) == 2
    (event,) = events(b, "message_failed")
    assert (event["msg_id"], event["reason"]) == (bad, "CoreError")
    await b.wait(lambda: b.daemon.store.inbox_state(mailbox, honest) == "done")
    await through_retries(b, advance, b.daemon.caught_up)
    assert b.daemon.client.journal_pending() == []
    await unwedged(b, a, gid)


# -- SPEC 7.2: controls and ceremony messages outside the bounds move nothing ---------


async def test_a_malformed_floor_grant_moves_nothing(group: GroupFixture) -> None:
    (a, b, c), gid = await group(3)
    assert a.daemon.change_policy(gid, {"floor": "moderated"}) == "committing"
    await converged([a, b, c], gid)
    assert b.daemon.floor._load(gid)[0] is None
    inner = a.daemon.inner(
        "control.floor", {"holder": c.me, "counter": 1}, ["*"], origin="human", hop=2**63
    )
    msg_id = raw_plaintext(a, gid, json.dumps(inner).encode())
    assert await handled(b, a, msg_id) == "dropped"
    assert audit_row(b, gid, msg_id)["reason"] == "malformed"
    assert b.daemon.floor._load(gid)[0] is None
    # A valid grant still moves it.
    good = a.daemon.inner("control.floor", {"holder": c.me, "counter": 1}, ["*"], origin="human")
    ok = raw_plaintext(a, gid, json.dumps(good).encode())
    await handled(b, a, ok)
    assert b.daemon.floor._load(gid)[0] == c.me


@pytest.mark.parametrize("kind", ["control.sas_commit", "control.sas_reveal", "control.sas_cancel"])
async def test_a_malformed_ceremony_message_is_dropped(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    (a, b), gid = await group(2)
    seen: list[str] = []
    on_message = b.daemon.sas.on_message

    def spy(group_row: Any, event: dict[str, Any], inner: dict[str, Any]) -> None:
        seen.append(str(inner.get("kind")))
        on_message(group_row, event, inner)

    monkeypatch.setattr(b.daemon.sas, "on_message", spy)
    inner = a.daemon.inner(kind, {}, ["*"], origin="human") | {
        "to": [f"ac:v0:{i}" for i in range(51)]
    }
    msg_id = raw_plaintext(a, gid, json.dumps(inner).encode())
    assert await handled(b, a, msg_id) == "dropped"
    assert audit_row(b, gid, msg_id)["reason"] == "malformed"
    assert seen == []


# -- logs carry a failure's type, never its text --------------------------------------


async def test_a_failure_is_logged_by_its_type_only(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (a, b), gid = await group(2)
    marker = f"peer-text-{gid}"
    poison: set[str] = set()
    monkeypatch.setattr(SafetyPolicy, "transcribe", raising_for(poison, KeyError(marker)))
    msg_id = raw_send(a, gid, {"parts": [{"text": "x"}]})
    poison.add(msg_id)
    capsys.readouterr()
    assert await handled(b, a, msg_id) == "failed"
    err = capsys.readouterr().err
    assert marker not in err
    lines = [json.loads(line) for line in err.splitlines() if line.startswith("{")]
    (line,) = [x for x in lines if x.get("event") == "message_failed"]
    assert line["error"] == "KeyError"
    assert "exception" not in line


# -- local state is never the message's: a locked keyring consumes nothing -----------


def lock_keyring(node: Node, monkeypatch: pytest.MonkeyPatch, prefix: str) -> list[bool]:
    """``node``'s keystore refuses ``prefix/...`` secrets, as a locked OS
    keyring does, while the returned flag is set."""
    locked = [True]
    get = node.daemon.keystore.get

    def flaky(name: str) -> bytes | None:
        if locked[0] and name.startswith(prefix):
            msg = "keyring read failed"
            raise KeystoreError(msg)
        return get(name)

    monkeypatch.setattr(node.daemon.keystore, "get", flaky)
    return locked


async def test_a_locked_keyring_never_consumes_a_welcome(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch, advance: Advance
) -> None:
    monkeypatch.setattr(engine_module, "MAX_ENTRY_ATTEMPTS", 2)
    monkeypatch.setattr(engine_module, "MAX_TRANSIENT_RETRIES", 2)
    a = await cluster.node()
    gid = a.daemon.create_group("G", "p")
    await a.idle()
    b = await cluster.node()
    locked = lock_keyring(b, monkeypatch, "join/")
    invite = await a.daemon.create_invite(gid)
    await b.daemon.accept_invite(invite["url"])
    # Given up again and again, past the bound: a locked keyring is no
    # message's failure, so the Welcome waits.
    await through_retries(b, advance, lambda: len(events(b, "processing_failed")) >= 3)
    assert not events(b, "message_failed")
    assert b.daemon.store.group(gid) is None
    assert [j["invite_id"] for j in b.daemon.store.pending_joins()] == [invite["invite_id"]]
    locked[0] = False
    await through_retries(
        b, advance, lambda: (g := b.daemon.store.group(gid)) is not None and g.status == "active"
    )
    assert not events(b, "message_failed")
    assert events(b, "joined")


async def test_a_locked_keyring_never_consumes_a_join_request(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch, advance: Advance
) -> None:
    monkeypatch.setattr(engine_module, "MAX_ENTRY_ATTEMPTS", 2)
    monkeypatch.setattr(engine_module, "MAX_TRANSIENT_RETRIES", 2)
    a = await cluster.node()
    gid = a.daemon.create_group("G", "p")
    await a.idle()
    b = await cluster.node()
    locked = lock_keyring(a, monkeypatch, "invite/")
    invite = await a.daemon.create_invite(gid)
    await b.daemon.accept_invite(invite["url"])
    await through_retries(a, advance, lambda: len(events(a, "processing_failed")) >= 3)
    assert not events(a, "message_failed")
    assert len(a.daemon.client.members(raw(gid))) == 1
    locked[0] = False
    await through_retries(a, advance, lambda: len(a.daemon.client.members(raw(gid))) == 2)
    await b.wait(lambda: (g := b.daemon.store.group(gid)) is not None and g.status == "active")
    assert not events(a, "message_failed")


@pytest.mark.parametrize(
    "error",
    [
        KeystoreError("keyring read failed"),
        keyring.errors.KeyringLocked("locked"),
        MemoryError(),
        httpx.ConnectError("down"),
        RelayError("internal"),
    ],
    ids=["keystore", "keyring", "memory", "network", "relay-internal"],
)
def test_failures_of_local_state_are_transient(error: Exception) -> None:
    assert engine_module._transient(error)


@pytest.mark.parametrize(
    "error",
    [ValueError("x"), KeyError("x"), KeystoreNameError("invalid secret name"), RelayError("no")],
    ids=["value", "key", "secret-name", "relay-refusal"],
)
def test_failures_a_message_causes_are_not_transient(error: Exception) -> None:
    assert not engine_module._transient(error)


def test_only_an_unavailable_keystore_waits_without_end() -> None:
    assert engine_module._waits_unbounded(KeystoreError("keyring read failed"))
    assert engine_module._waits_unbounded(keyring.errors.KeyringLocked("locked"))
    assert not engine_module._waits_unbounded(KeystoreNameError("invalid secret name"))
    assert not engine_module._waits_unbounded(ac.CoreError("panic"))


# -- a message that crashes the process is counted, and fails alone ------------------


async def test_a_message_that_crashes_the_daemon_fails_alone_after_the_bound(
    group: GroupFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine_module, "MAX_ENTRY_ATTEMPTS", 3)
    (a, b), gid = await group(2)
    b.events_may_fail = True
    crashes: list[str] = []
    poison: set[str] = set()
    transcribe = SafetyPolicy.transcribe

    def crashing(self: SafetyPolicy, group_id: str, direction: str, *args: Any) -> None:
        if direction == "in" and args[1] in poison:
            crashes.append(args[1])
            msg = "the process died here"
            raise SimulatedCrash(msg)
        transcribe(self, group_id, direction, *args)

    monkeypatch.setattr(SafetyPolicy, "transcribe", crashing)
    bad = raw_send(a, gid, {"parts": [{"text": "x"}]})
    poison.add(bad)
    await a.idle()
    mailbox = a.daemon.mailbox
    for n in range(1, 6):
        await until(
            lambda n=n: len(crashes) >= n or b.daemon.store.inbox_state(mailbox, bad) is not None
        )
        if b.daemon.store.inbox_state(mailbox, bad) is not None:
            break
        await b.restart()
    # Each try was counted before it ran: three crashes, then it failed alone.
    await b.wait(lambda: b.daemon.store.inbox_state(mailbox, bad) == "failed")
    assert len(crashes) == 3
    (event,) = events(b, "message_failed")
    assert (event["msg_id"], event["reason"]) == (bad, "RetriesExhausted")
    b.events_may_fail = False
    await unwedged(b, a, gid)
