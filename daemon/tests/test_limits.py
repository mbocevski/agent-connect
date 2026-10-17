"""SPEC §10.2 limits and §7.2 kind checks (unit level)."""

from __future__ import annotations

from typing import Any

import pytest

from agentconnect.clock import FakeClock
from agentconnect.limits import (
    GROUP_PER_MINUTE,
    MAX_MESSAGE_BYTES,
    SENDER_PER_MINUTE,
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
