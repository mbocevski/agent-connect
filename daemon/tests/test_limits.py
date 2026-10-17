"""SPEC §10.2 limits and §7.2 kind checks (unit level)."""

from __future__ import annotations

from typing import Any

import pytest

from agentconnect.clock import FakeClock
from agentconnect.limits import (
    GROUP_PER_MINUTE,
    MAX_MESSAGE_BYTES,
    MAX_TASK_ID,
    SENDER_PER_MINUTE,
    TASK_PER_MINUTE,
    DrainBudget,
    RateLimiter,
    content_problem,
    part_kind,
)


@pytest.mark.parametrize(
    ("part", "kind"),
    [
        ({"kind": "text", "text": "x"}, "text"),
        ({"text": "x"}, "text"),
        ({"data": {"a": 1}}, "data"),
        ({"file": {"uri": "x"}}, "file"),
        ({"raw": "AAAA"}, "file"),
        ({"url": "https://x"}, "file"),
        ({"text": "x", "data": {}}, "invalid"),
        ({}, "invalid"),
        ("text", "invalid"),
    ],
)
def test_part_kinds(part: Any, kind: str) -> None:
    assert part_kind(part) == kind


def inner(kind: str, body: Any) -> dict[str, Any]:
    return {"kind": kind, "body": body}


@pytest.mark.parametrize(
    ("message", "size", "problem"),
    [
        (inner("a2a.message", {"parts": [{"text": "hi"}, {"data": {}}]}), 10, None),
        (inner("a2a.message", {"parts": [{"file": {"uri": "x"}}]}), 10, "part_kind"),
        (inner("a2a.message", {"parts": "x"}), 10, "part_kind"),
        (inner("a2a.task_artifact", {"artifact": {"parts": [{"raw": "x"}]}}), 10, "part_kind"),
        (inner("a2a.task_artifact", {"artifact": {"parts": 3}}), 10, "part_kind"),
        (inner("a2a.task_artifact", {"artifact": None}), 10, None),
        (
            inner("a2a.task_status", {"status": {"message": {"parts": [{"url": "u"}]}}}),
            10,
            "part_kind",
        ),
        (inner("a2a.task_status", {"status": {"message": {"parts": {}}}}), 10, "part_kind"),
        (inner("a2a.task_status", {"status": "working"}), 10, None),
        (inner("a2a.agent_card", {"name": "x"}), 10, None),
        (inner("control.pause", {"reason": "human"}), 10, None),
        (inner("x.evil", {}), 10, "unknown_kind"),
        (inner("control.nope", {}), 10, "unknown_kind"),
        (inner("a2a.message", {}), MAX_MESSAGE_BYTES + 1, "too_large"),
        (inner("a2a.message", []), 10, "malformed"),
    ],
)
def test_content_problems(message: dict[str, Any], size: int, problem: str | None) -> None:
    assert content_problem(message, size) == problem


def test_rates_per_sender_and_group(fake_clock: FakeClock) -> None:
    limiter = RateLimiter(fake_clock)
    assert all(limiter.allow("g", "a") for _ in range(SENDER_PER_MINUTE))
    assert not limiter.allow("g", "a")
    assert limiter.allow("other", "a"), "groups are independent"
    fake_clock.advance(60)
    assert limiter.allow("g", "a"), "the window slides"
    # The group as a whole: 120 a minute across senders.
    limiter = RateLimiter(fake_clock)
    senders = [f"s{i}" for i in range(GROUP_PER_MINUTE // SENDER_PER_MINUTE)]
    for s in senders:
        assert all(limiter.allow("g", s) for _ in range(SENDER_PER_MINUTE))
    assert not limiter.allow("g", "fresh")


def test_task_updates_have_their_own_budget(fake_clock: FakeClock) -> None:
    rl = RateLimiter(fake_clock)
    update = {"taskId": "t1", "status": {"state": "TASK_STATE_WORKING"}}
    # A long stream for one task is not cut off at the message rate...
    for _ in range(TASK_PER_MINUTE):
        assert rl.allow_inner("g", "a", "a2a.task_status", update)
    # ...but has its own cap.
    assert not rl.allow_inner("g", "a", "a2a.task_artifact", update)
    # The task's first update counted as one ordinary message.
    for _ in range(SENDER_PER_MINUTE - 1):
        assert rl.allow_inner("g", "a", "a2a.message", {"parts": []})
    assert not rl.allow_inner("g", "a", "a2a.message", {"parts": []})
    # A new task opens with an ordinary message, so it is held to the rate.
    assert not rl.allow_inner("g", "a", "a2a.task_status", {"taskId": "t2"})
    # No taskId, a non-string one, or an oversized one: ordinary messages.
    for body in ({}, {"taskId": 7}, {"taskId": "x" * (MAX_TASK_ID + 1)}, "not a dict"):
        assert not rl.allow_inner("g", "a", "a2a.task_status", body)
    # Other senders and groups are unaffected; the window slides.
    assert rl.allow_inner("g", "b", "a2a.task_status", update)
    fake_clock.advance(61)
    assert rl.allow_inner("g", "a", "a2a.task_status", update)


def test_the_drain_exemption_is_bounded_per_sender_and_in_all() -> None:
    budget = DrainBudget(total=5)
    assert [budget.take("a", 2) for _ in range(3)] == [True, True, False]
    assert [budget.take("b", 2) for _ in range(2)] == [True, True]
    assert budget.take("c", 2)
    assert not budget.take("c", 2), "the connection total is spent"
    budget.reset()
    assert budget.take("a", 2), "a new connection starts afresh"
