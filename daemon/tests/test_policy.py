"""The safety policy (agentconnect.policy): every decision path, every limit,
settings and overrides, violations, the audit log and retention."""

from __future__ import annotations

import random
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agentconnect.clock import FakeClock
from agentconnect.config import ConfigError, load_config
from agentconnect.limits import (
    GROUP_PER_MINUTE,
    MAX_MESSAGE_BYTES,
    SENDER_PER_MINUTE,
    TASK_PER_MINUTE,
    Limits,
    content_problem,
)
from agentconnect.policy import (
    DAY_SECS,
    DELIVER,
    KNOB,
    KNOBS,
    MAX_AUDIT_ROWS,
    VIOLATIONS,
    Decision,
    Inbound,
    Outbound,
    PolicyError,
    SafetyPolicy,
    Settings,
    Verdict,
    apply_changes,
    as_context,
    check_changes,
    drop,
    hold,
    verification_holds,
)
from agentconnect.store import Store

G = "g1"
ALICE = "ac:v0:alice"
BOB = "ac:v0:bob"


@pytest.fixture
def store(tmp_path: Path, rng: random.Random) -> Iterator[Store]:
    s = Store(tmp_path / "d.sqlite3", rng.randbytes(32))
    yield s
    s.close()


@pytest.fixture
def policy(store: Store, fake_clock: FakeClock) -> SafetyPolicy:
    return SafetyPolicy(Settings(), store, fake_clock)


def message(text: str = "hi", **extra: Any) -> dict[str, Any]:
    return {"kind": "a2a.message", "origin": "agent", "body": {"parts": [{"text": text}]}} | extra


def inbound(  # noqa: PLR0913
    inner: dict[str, Any] | None = None,
    *,
    sender: str = ALICE,
    size: int = 100,
    hop: int = 1,
    addressed: bool = True,
    replayed: bool = False,
    drain: bool = False,
    owner: str = BOB,
) -> Inbound:
    return Inbound(
        G,
        sender,
        inner or message(),
        size,
        owner,
        hop,
        20,
        addressed,
        replayed=replayed,
        drain_exempt=lambda: drain,
    )


def outbound(inner: dict[str, Any] | None = None, *, internal: bool = False) -> Outbound:
    return Outbound(G, BOB, inner or message(), 100, internal=internal)


# -- decisions -----------------------------------------------------------------------


def test_a_message_for_this_member_is_delivered(policy: SafetyPolicy) -> None:
    decision = policy.inbound(inbound())
    assert decision == DELIVER
    assert decision.delivered
    assert decision.reason == ""


def test_a_message_for_someone_else_is_context(policy: SafetyPolicy) -> None:
    assert policy.inbound(inbound(addressed=False)) == as_context("not_addressed")
    assert as_context("x").delivered


def test_past_the_loop_guard_a_message_is_context(policy: SafetyPolicy) -> None:
    assert policy.inbound(inbound(hop=21)) == as_context("loop_guard")


@pytest.mark.parametrize(
    ("inner", "size", "reason"),
    [
        (message(), MAX_MESSAGE_BYTES + 1, "too_large"),
        ({"kind": "x.evil", "body": {}}, 10, "unknown_kind"),
        ({"kind": "a2a.message", "body": []}, 10, "malformed"),
        ({"kind": "a2a.message", "body": {"parts": [{"file": {"uri": "x"}}]}}, 10, "part_kind"),
        ({"kind": "control.resume", "origin": "agent", "body": {}}, 10, "not_human"),
        ({"kind": "control.close", "body": {"reason": "bye"}}, 10, "not_owner"),
    ],
)
def test_drops(policy: SafetyPolicy, inner: dict[str, Any], size: int, reason: str) -> None:
    decision = policy.inbound(inbound(inner, size=size))
    assert decision == drop(reason)
    assert not decision.delivered


def test_the_owner_may_close_and_the_human_may_resume(policy: SafetyPolicy) -> None:
    close = {"kind": "control.close", "body": {}}
    assert policy.inbound(inbound(close, sender=BOB)).delivered
    resume = {"kind": "control.resume", "origin": "human", "body": {}}
    assert policy.inbound(inbound(resume)).delivered


def test_require_approval_holds_content_but_not_controls(policy: SafetyPolicy) -> None:
    policy.update(G, {"require_approval": "inbound"})
    assert policy.inbound(inbound()) == hold("require_approval")
    status = {"kind": "a2a.task_status", "body": {"status": {"state": "working"}}}
    assert policy.inbound(inbound(status)).verdict is Verdict.HOLD_FOR_APPROVAL
    pause = {"kind": "control.pause", "body": {"reason": "human"}}
    assert policy.inbound(inbound(pause)) == DELIVER
    card = {"kind": "a2a.agent_card", "body": {"name": "x"}}
    assert policy.inbound(inbound(card)) == DELIVER
    # Held before the loop guard or addressing apply: the human sees it.
    assert policy.inbound(inbound(hop=99, addressed=False)).verdict is Verdict.HOLD_FOR_APPROVAL
    # Inbound only: what the agent sends is not held.
    assert policy.outbound(outbound()) == DELIVER


def test_a_drop_beats_a_hold(policy: SafetyPolicy) -> None:
    policy.update(G, {"require_approval": "both"})
    assert policy.inbound(inbound(size=MAX_MESSAGE_BYTES + 1)) == drop("too_large")


def test_outbound_approval_holds_agent_messages_only(policy: SafetyPolicy) -> None:
    policy.update(G, {"require_approval": "outbound"})
    assert policy.outbound(outbound()) == hold("require_approval")
    assert policy.outbound(outbound(message(origin="human"))) == DELIVER
    assert policy.outbound(outbound(internal=True)) == DELIVER
    card = {"kind": "a2a.agent_card", "origin": "agent", "body": {}}
    assert policy.outbound(outbound(card)) == DELIVER
    assert policy.inbound(inbound()) == DELIVER


def test_outbound_content_and_rate(policy: SafetyPolicy) -> None:
    bad = {"kind": "a2a.message", "body": {"parts": [{"raw": "AAAA"}]}}
    assert policy.outbound(outbound(bad)) == drop("part_kind")
    for _ in range(SENDER_PER_MINUTE):
        assert policy.outbound(outbound()) == DELIVER
    assert policy.outbound(outbound()) == drop("rate_limited")
    assert policy.outbound(outbound(internal=True)) == DELIVER, "the daemon's own don't count"


# -- limits ---------------------------------------------------------------------------


def test_rates_per_sender_with_an_override(policy: SafetyPolicy, fake_clock: FakeClock) -> None:
    policy.update(G, {"sender_per_minute": 3}, sender=ALICE)
    assert [policy.inbound(inbound()).verdict for _ in range(4)] == [
        Verdict.DELIVER,
        Verdict.DELIVER,
        Verdict.DELIVER,
        Verdict.DROP,
    ]
    assert policy.inbound(inbound()) == drop("rate_limited")
    # Another sender keeps the group's limit.
    assert all(policy.inbound(inbound(sender=BOB)).delivered for _ in range(SENDER_PER_MINUTE))
    assert policy.inbound(inbound(sender=BOB)) == drop("rate_limited")
    fake_clock.advance(60)
    assert policy.inbound(inbound()).delivered, "the window slides"


def test_the_group_rate(policy: SafetyPolicy) -> None:
    policy.update(G, {"group_per_minute": 5})
    senders = [f"ac:v0:s{i}" for i in range(5)]
    assert all(policy.inbound(inbound(sender=s)).delivered for s in senders)
    assert policy.inbound(inbound(sender="ac:v0:new")) == drop("rate_limited")
    assert KNOB["group_per_minute"].default == GROUP_PER_MINUTE


def test_replays_and_the_reconnect_drain_are_not_counted(policy: SafetyPolicy) -> None:
    policy.update(G, {"sender_per_minute": 1})
    assert policy.inbound(inbound()).delivered
    assert policy.inbound(inbound(replayed=True)).delivered
    assert policy.inbound(inbound(drain=True)).delivered
    assert policy.inbound(inbound()) == drop("rate_limited")
    # ...but the content limits still apply to them.
    assert policy.inbound(inbound(drain=True, size=MAX_MESSAGE_BYTES + 1)) == drop("too_large")


def test_a_smaller_size_limit_for_one_sender(policy: SafetyPolicy) -> None:
    policy.update(G, {"max_message_bytes": 2048}, sender=ALICE)
    assert policy.inbound(inbound(size=2049)) == drop("too_large")
    assert policy.inbound(inbound(size=2048)).delivered
    assert policy.inbound(inbound(sender=BOB, size=2049)).delivered


def test_file_parts_when_allowed_and_their_cap(policy: SafetyPolicy) -> None:
    small = {"kind": "a2a.message", "body": {"parts": [{"raw": "QUFB"}]}}
    big = {"kind": "a2a.message", "body": {"parts": [{"raw": "Q" * 600}]}}
    assert policy.inbound(inbound(small)) == drop("part_kind"), "off by default"
    policy.update(G, {"allow_files": True, "max_file_bytes": 512})
    assert policy.inbound(inbound(small)).delivered
    assert policy.inbound(inbound(big)) == drop("file_too_large")
    # Per sender: Bob may not send files even though the group allows them.
    policy.update(G, {"allow_files": False}, sender=BOB)
    assert policy.inbound(inbound(small, sender=BOB)) == drop("part_kind")


def test_task_updates_have_their_own_budget(policy: SafetyPolicy) -> None:
    policy.update(G, {"sender_per_minute": 2, "task_per_minute": 5})
    update = {"kind": "a2a.task_status", "body": {"taskId": "t1", "status": {}}}
    # The first update of the task counts as an ordinary message; the rest
    # only against the task's budget.
    assert all(policy.inbound(inbound(update)).delivered for _ in range(5))
    assert policy.inbound(inbound(update)) == drop("rate_limited")
    assert policy.inbound(inbound()).delivered, "one ordinary message left"
    other = {"kind": "a2a.task_artifact", "body": {"taskId": "t2", "artifact": {}}}
    assert policy.inbound(inbound(other)) == drop("rate_limited"), "a new task opens as a message"
    assert KNOB["task_per_minute"].default == TASK_PER_MINUTE


def test_content_problem_with_group_limits() -> None:
    limits = Limits(max_message_bytes=10, allow_files=True, max_file_bytes=5)
    assert content_problem(message(), 11, limits) == "too_large"
    part = {"kind": "a2a.message", "body": {"parts": [{"url": "https://x.example"}]}}
    assert content_problem(part, 5, limits) == "file_too_large"
    explicit = {"kind": "a2a.message", "body": {"parts": [{"kind": "file", "file": {}}]}}
    assert content_problem(explicit, 5, Limits(allow_files=True)) is None


# -- settings -------------------------------------------------------------------------


def test_settings_merge_group_and_sender_overrides(policy: SafetyPolicy) -> None:
    assert policy.settings(G) == Settings()
    s = policy.update(G, {"frame_text": False, "require_approval": "both"})
    assert (s.frame_text, s.approve_inbound, s.approve_outbound) == (False, True, True)
    s = policy.update(G, {"sender_per_minute": 5}, sender=ALICE)
    assert s.limits(ALICE).sender_per_minute == 5
    assert s.limits(BOB).sender_per_minute == SENDER_PER_MINUTE
    assert s.limits().sender_per_minute == SENDER_PER_MINUTE
    assert policy.overrides(G) == {
        "frame_text": False,
        "require_approval": "both",
        "senders": {ALICE: {"sender_per_minute": 5}},
    }
    shown = s.as_json()
    assert set(shown) == {k.name for k in KNOBS} | {"senders"}
    # None clears an override, for the group and for a sender.
    policy.update(G, {"sender_per_minute": None}, sender=ALICE)
    policy.update(G, {"frame_text": None, "require_approval": None})
    assert policy.overrides(G) == {}
    assert policy.settings(G) == Settings()


@pytest.mark.parametrize(
    ("changes", "sender", "message_"),
    [
        ({"nope": 1}, False, "unknown setting"),
        ({"sender_per_minute": "10"}, False, "must be int"),
        ({"sender_per_minute": True}, False, "must be int"),
        ({"sender_per_minute": 0}, False, "1..1000"),
        ({"max_message_bytes": MAX_MESSAGE_BYTES + 1}, False, "1024..262144"),
        ({"require_approval": "sometimes"}, False, "one of off"),
        ({"frame_text": 1}, False, "must be bool"),
        ({"require_approval": "both"}, True, "one sender"),
        ({"group_per_minute": 5}, True, "one sender"),
    ],
)
def test_invalid_changes(changes: dict[str, Any], sender: bool, message_: str) -> None:
    with pytest.raises(PolicyError, match=message_):
        check_changes(changes, sender=sender)


def test_settings_of_refuses_a_null() -> None:
    with pytest.raises(PolicyError):
        Settings.of({"frame_text": None})
    assert Settings.of({"transcript": True}).transcript


def test_apply_changes_drops_empty_sender_entries() -> None:
    merged = apply_changes({"senders": {ALICE: {"sender_per_minute": 2}}}, {"x": None}, None)
    assert merged == {"senders": {ALICE: {"sender_per_minute": 2}}}
    assert apply_changes(merged, {"sender_per_minute": None}, ALICE) == {}


def test_verification_gate() -> None:
    assert verification_holds(True, {"self": "unverified"})
    assert not verification_holds(True, {"self": "verified"})
    assert not verification_holds(False, {"self": "unverified"})


def test_config_policy_keys(tmp_path: Path) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text(
        '[policy]\nrequire_approval = "inbound"\nsender_per_minute = 7\nframe_text = false\n'
        "audit_retention_days = 3\n",
        encoding="utf-8",
    )
    config = load_config(cfg, environ={})
    defaults = config.safety_defaults()
    assert (defaults.require_approval, defaults.sender_per_minute, defaults.frame_text) == (
        "inbound",
        7,
        False,
    )
    assert config.policy_audit_retention_days == 3
    assert load_config(tmp_path / "none.toml", environ={}).safety_defaults() == Settings()


@pytest.mark.parametrize(
    "line",
    ['require_approval = "maybe"', "sender_per_minute = 0", "audit_retention_days = 0"],
)
def test_config_rejects_bad_policy_values(tmp_path: Path, line: str) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text(f"[policy]\n{line}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="policy"):
        load_config(cfg, environ={})


# -- violations ------------------------------------------------------------------------


def test_repeated_violations_raise_one_alert_per_window(
    policy: SafetyPolicy, fake_clock: FakeClock
) -> None:
    policy.update(G, {"violation_threshold": 3, "violation_window_secs": 60})
    assert policy.violation(G, ALICE, "unknown_kind") is None, "not a violation"
    assert policy.violations(G, ALICE) == 0
    assert policy.violation(G, ALICE, "too_large") is None
    assert policy.violation(G, ALICE, "rate_limited") is None
    alert = policy.violation(G, ALICE, "part_kind")
    assert alert == {
        "sender": ALICE,
        "count": 3,
        "threshold": 3,
        "window_secs": 60,
        "last_reason": "part_kind",
    }
    assert policy.violation(G, ALICE, "part_kind") is None, "once per window"
    assert policy.violation(G, BOB, "part_kind") is None, "per sender"
    assert policy.violations(G, ALICE) == 4
    fake_clock.advance(61)
    assert policy.violations(G, ALICE) == 0
    assert policy.violation(G, ALICE, "too_large") is None
    assert policy.violation(G, ALICE, "too_large") is None
    assert policy.violation(G, ALICE, "too_large") is not None, "a new window alerts again"
    assert "unknown_kind" not in VIOLATIONS


# -- audit and transcript --------------------------------------------------------------


def test_audit_rows_hold_metadata_only(policy: SafetyPolicy, store: Store) -> None:
    policy.audit(
        G,
        "in",
        sender=ALICE,
        msg_id="m1",
        kind="a2a.message",
        size=12,
        decision=Verdict.DROP,
        reason="too_large",
    )
    (row,) = store.audit(G)
    assert set(row) == {
        "seq",
        "group_id",
        "at",
        "direction",
        "sender",
        "msg_id",
        "kind",
        "size",
        "decision",
        "reason",
    }
    assert (row["decision"], row["reason"], row["size"]) == ("drop", "too_large", 12)
    assert store.audit("other") == []


def test_transcript_only_when_on(policy: SafetyPolicy, store: Store) -> None:
    policy.transcribe(G, "in", ALICE, "m1", message("first"))
    assert store.transcript(G) == []
    policy.update(G, {"transcript": True})
    policy.transcribe(G, "in", ALICE, "m2", message("second"))
    (entry,) = store.transcript(G)
    assert entry["msg_id"] == "m2"
    assert entry["inner"]["body"]["parts"][0]["text"] == "second"


def test_retention(policy: SafetyPolicy, store: Store, fake_clock: FakeClock) -> None:
    policy.update(G, {"transcript": True, "transcript_retention_days": 1})
    meta: dict[str, Any] = {"sender": ALICE, "kind": "a2a.message", "size": 1, "decision": "x"}
    policy.audit(G, "in", msg_id="old", **meta)
    policy.transcribe(G, "in", ALICE, "old", message())
    fake_clock.advance(2 * DAY_SECS)
    policy.audit(G, "in", msg_id="new", **meta)
    policy.transcribe(G, "in", ALICE, "new", message())
    policy.purge()
    assert [r["msg_id"] for r in store.transcript(G)] == ["new"]
    assert [r["msg_id"] for r in store.audit(G)] == ["old", "new"], "30 days for the audit log"
    fake_clock.advance(31 * DAY_SECS)
    policy.purge()
    assert store.audit(G) == []
    assert store.transcript(G) == []
    assert MAX_AUDIT_ROWS == 100_000


def test_purge_runs_at_most_once_a_minute(
    policy: SafetyPolicy, store: Store, fake_clock: FakeClock
) -> None:
    policy.purge()
    meta: dict[str, Any] = {"sender": ALICE, "kind": "k", "size": 1, "decision": "x"}
    policy.audit(G, "in", msg_id="a", **meta)
    fake_clock.advance(31 * DAY_SECS)
    policy._purged_at = policy._now() - 1
    policy.purge()
    assert len(store.audit(G)) == 1, "too soon"
    fake_clock.advance(60)
    policy.purge()
    assert store.audit(G) == []


def test_audit_purge_keeps_the_newest_rows(store: Store) -> None:
    for i in range(5):
        store.audit_add(
            G,
            at=100,
            direction="in",
            sender=ALICE,
            msg_id=f"m{i}",
            kind="k",
            size=1,
            decision="x",
            reason="",
        )
    store.audit_purge(0, 2)
    assert [r["msg_id"] for r in store.audit()] == ["m3", "m4"]


def test_decision_helpers() -> None:
    assert Decision(Verdict.DROP, "x") == drop("x")
    assert hold("x").verdict == "hold_for_approval"
    assert not hold("x").delivered
