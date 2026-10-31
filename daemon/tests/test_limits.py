"""SPEC §10.2 limits and §7.2 kind checks (unit level)."""

from __future__ import annotations

import json
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from agentconnect.clock import FakeClock
from agentconnect.limits import (
    DRAIN_WINDOW_SECS,
    GROUP_PER_MINUTE,
    MAX_DEPTH,
    MAX_MESSAGE_BYTES,
    MAX_PAYLOAD_DEPTH,
    MAX_RECIPIENT_LEN,
    MAX_RECIPIENTS,
    MAX_TASK_ID,
    SENDER_PER_MINUTE,
    TASK_PER_MINUTE,
    U32_MAX,
    DrainBudget,
    Limits,
    RateLimiter,
    content_problem,
    inner_problem,
    json_too_deep,
    loads,
    parse_inner,
    part_kind,
    too_deep,
    unsound,
    valid_hop,
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
        (inner("a2a.message", {"parts": "x"}), 10, "malformed"),
        (inner("a2a.task_artifact", {"artifact": {"parts": [{"raw": "x"}]}}), 10, "part_kind"),
        (inner("a2a.task_artifact", {"artifact": {"parts": 3}}), 10, "malformed"),
        (inner("a2a.task_artifact", {"artifact": None}), 10, None),
        (
            inner("a2a.task_status", {"status": {"message": {"parts": [{"url": "u"}]}}}),
            10,
            "part_kind",
        ),
        (inner("a2a.task_status", {"status": {"message": {"parts": {}}}}), 10, "malformed"),
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


def deep(levels: int) -> Any:
    """``levels`` nested arrays and objects, alternating."""
    value: Any = 0
    for n in range(levels):
        value = [value] if n % 2 else {"a": value}
    return value


def test_depth_is_measured_without_recursing() -> None:
    assert not too_deep(1, 0)
    assert not too_deep(deep(MAX_DEPTH))
    assert too_deep(deep(MAX_DEPTH + 1))
    assert too_deep({"a": 1, "b": deep(MAX_DEPTH)})
    # Far past the interpreter's recursion limit.
    assert too_deep(deep(100_000))


@pytest.mark.parametrize(
    ("value", "ok"),
    [(0, True), (U32_MAX, True), (U32_MAX + 1, False), (-1, False), (True, False), ("1", False)],
)
def test_hop_is_a_u32(value: Any, ok: bool) -> None:
    assert valid_hop(value) is ok


def test_parse_inner_refuses_what_is_too_deep_or_not_an_object() -> None:
    assert parse_inner(json.dumps({"kind": "a2a.message"})) == {"kind": "a2a.message"}
    assert parse_inner(b"[]") is None
    assert parse_inner(b"{") is None
    assert parse_inner(json.dumps({"body": deep(MAX_DEPTH)})) is None
    depth = 200_000  # past what the JSON parser recurses to
    assert parse_inner("[" * depth + "]" * depth) is None


LONE = "\ud800"  # what the JSON escape \ud800 decodes to: no UTF-8 encoder takes it


def at_depth(levels: int, leaf: Any) -> Any:
    value = leaf
    for _ in range(levels):
        value = [value]
    return value


@pytest.mark.parametrize(
    "message",
    [
        {"kind": "a2a.message", "body": {"parts": [{"text": LONE}]}},
        {"kind": "a2a.message", "body": {"parts": [{"text": "ok" + "\udfff"}]}},
        {"kind": "a2a.message", "body": {"parts": [{"data": {LONE: 1}}]}},
        {"kind": "a2a.message", "body": {"parts": [{"text": "x"}]}, "reply_to": [LONE]},
        {"kind": "a2a.message", "body": {"parts": [{"text": "x"}]}, "to": [LONE]},
        {"kind": LONE, "body": {}},
        {LONE: "x", "kind": "a2a.message", "body": {}},
        # At the deepest level allowed: the inner message, body, parts and the
        # part are four of them.
        {"kind": "a2a.message", "body": {"parts": [{"data": at_depth(MAX_DEPTH - 4, LONE)}]}},
        {
            "kind": "a2a.message",
            "body": {"parts": [{"data": at_depth(MAX_DEPTH - 5, {LONE: 1})}]},
        },
    ],
    ids=["text", "text-low", "key", "reply_to", "to", "kind", "top-key", "deep", "deep-key"],
)
def test_a_lone_surrogate_anywhere_is_malformed(message: dict[str, Any]) -> None:
    text = json.dumps(message)  # escaped: valid JSON, and valid UTF-8 on the wire
    assert text.isascii()
    assert not too_deep(message)
    assert parse_inner(text) is None
    assert parse_inner(text.encode()) is None
    assert inner_problem(message) == "malformed"
    assert content_problem(message, 10) in ("malformed", "unknown_kind")


def test_objects_nested_too_deep_are_unsound() -> None:
    value: Any = {"a": 1}
    for _ in range(MAX_DEPTH):
        value = {"a": value}
    assert unsound(value)
    assert not unsound({"a": [{"b": "😀"}]})


def test_a_surrogate_pair_is_a_character() -> None:
    message = {"kind": "a2a.message", "body": {"parts": [{"text": "\U0001f600"}]}}
    text = json.dumps(message)
    assert "\\ud83d\\ude00" in text
    assert parse_inner(text) == message
    assert inner_problem(message) is None


def test_inner_text_is_utf8() -> None:
    message = {"kind": "a2a.message", "body": {"parts": [{"text": "x"}]}}
    assert parse_inner(json.dumps(message).encode("utf-16")) is None
    assert parse_inner(b'{"kind": "\xed\xa0\x80"}') is None  # a surrogate, UTF-8 encoded


@pytest.mark.parametrize(
    ("text", "limit", "deep_"),
    [
        ("[" * 64 + "]" * 64, 64, False),
        ("[" * 65 + "]" * 65, 64, True),
        ('{"a":' * 65 + "1" + "}" * 65, 64, True),
        ("[[], [], [[]]]", 2, True),
        ("[[], [], []]", 2, False),
        (json.dumps({"a": "[" * 1000}), 1, False),
        (json.dumps({"a": '"[[[' + "{" * 10}), 1, False),
        (json.dumps({"a": "\\" + "[" * 10}), 1, False),
        ('["\\\\", [[[]]]]', 3, True),  # an escaped backslash ends the string
        ('"' + "[" * 10, 3, True),  # unterminated: counted, never hidden
        ("1", 0, False),
    ],
)
def test_depth_is_read_from_json_text_without_parsing_it(
    text: str, limit: int, deep_: bool
) -> None:
    assert json_too_deep(text, limit) is deep_


@pytest.mark.parametrize(
    "text",
    [
        '"' + '\\"' * (1 << 20),  # 2 MiB: one string that never closes, all escapes
        '"' + "x" * (2 << 20),  # 2 MiB unterminated, no escapes
        '["' + '\\"' * (1 << 20) + "]",
        '"' * (2 << 20),  # 2 MiB of quotes
        "\\" * (2 << 20),
    ],
    ids=["escapes", "plain", "in-array", "quotes", "backslashes"],
)
def test_the_depth_scan_is_linear(text: str) -> None:
    """It ran from every quote that never closed: 128 KB took 12 s."""
    start = time.perf_counter()
    json_too_deep(text, MAX_DEPTH)
    assert time.perf_counter() - start < 0.5


def test_the_depth_scan_agrees_with_the_parser(rng: random.Random) -> None:
    """Valid JSON whose strings are full of brackets, quotes, backslashes and
    non-ASCII: the scan's depth is the parsed value's."""
    alphabet = ['"', "\\", "[", "]", "{", "}", ",", ":", "a", " ", "\n", "é", "\U0001f600"]

    def text_of() -> str:
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))

    def value(level: int, top: int) -> Any:
        if level >= top or rng.random() < 0.3:
            return rng.choice([text_of(), 1, None, True])
        if rng.random() < 0.5:
            return [value(level + 1, top) for _ in range(rng.randint(0, 3))]
        return {text_of(): value(level + 1, top) for _ in range(rng.randint(0, 3))}

    def depth_of(v: Any) -> int:
        if isinstance(v, list):
            return 1 + max((depth_of(c) for c in v), default=0)
        if isinstance(v, dict):
            return 1 + max((depth_of(c) for c in v.values()), default=0)
        return 0

    for _ in range(2000):
        v = value(0, rng.randint(1, 10))
        text = json.dumps(v, ensure_ascii=rng.random() < 0.5)
        d = depth_of(v)
        for limit in (d - 1, d, d + 1):
            if limit >= 0:
                assert json_too_deep(text, limit) is (d > limit), (limit, text)


def test_json_too_deep_is_refused_before_the_parser_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    parsed: list[str] = []
    real = json.loads

    def counting(text: Any, *args: Any, **kwargs: Any) -> Any:
        parsed.append(str(text)[:10])
        return real(text, *args, **kwargs)

    monkeypatch.setattr(json, "loads", counting)
    assert parse_inner("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1)) is None
    assert parse_inner(b'{"a":' + b"[" * 100_000 + b"]" * 100_000 + b"}") is None
    with pytest.raises(ValueError, match="too deep"):
        loads("[" * (MAX_PAYLOAD_DEPTH + 1) + "]" * (MAX_PAYLOAD_DEPTH + 1), MAX_PAYLOAD_DEPTH)
    assert parsed == []
    assert loads(b'{"a": [1]}') == {"a": [1]}
    assert parsed == ['{"a": [1]}']


# A child process (a crash must not take the test run with it) parses deep
# JSON on a 512 KiB thread stack, the macOS default for a secondary thread.
# Python 3.12 and 3.13 crash in json.loads there from a few thousand levels.
SMALL_STACK_CHILD = """
import sys, threading
from agentconnect.limits import MAX_PAYLOAD_DEPTH, loads, parse_inner
threading.stack_size(512 * 1024)
depth = int(sys.argv[1])
text = '{"kind": "a2a.message", "x": ' + "[" * depth + "]" * depth + "}"
out = []
def run():
    out.append(parse_inner(text))
    try:
        loads(text, MAX_PAYLOAD_DEPTH)
    except ValueError:
        out.append("refused")
thread = threading.Thread(target=run)
thread.start()
thread.join()
print(out)
"""


@pytest.mark.parametrize("depth", [MAX_DEPTH * 2 + 1, 4_000, 10_000, 500_000])
def test_deep_json_is_refused_on_a_small_thread_stack(depth: int) -> None:
    child = subprocess.run(
        [sys.executable, "-c", SMALL_STACK_CHILD, str(depth)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert (child.returncode, child.stdout.strip()) == (0, "[None, 'refused']"), child.stderr


@pytest.mark.parametrize(
    ("fields", "problem"),
    [
        ({}, None),
        ({"hop": U32_MAX, "to": ["*"], "addressee": ["ac:v0:x"]}, None),
        ({"hop": U32_MAX + 1}, "malformed"),
        ({"hop": None}, "malformed"),
        ({"to": ["x"] * MAX_RECIPIENTS}, None),
        ({"to": ["x"] * (MAX_RECIPIENTS + 1)}, "malformed"),
        ({"to": ["x" * MAX_RECIPIENT_LEN]}, None),
        ({"to": ["x" * (MAX_RECIPIENT_LEN + 1)]}, "malformed"),
        ({"to": [1]}, "malformed"),
        ({"to": "*"}, "malformed"),
        ({"addressee": ["x"] * MAX_RECIPIENTS}, None),
        ({"addressee": ["x"] * (MAX_RECIPIENTS + 1)}, "malformed"),
        ({"addressee": ["x" * (MAX_RECIPIENT_LEN + 1)]}, "malformed"),
        # SPEC 9.3: another shape triggers nobody, and isn't malformed.
        ({"addressee": "x"}, None),
        ({"addressee": [1]}, None),
        ({"body": {"parts": [{"data": deep(MAX_DEPTH)}]}}, "malformed"),
    ],
)
def test_inner_bounds(fields: dict[str, Any], problem: str | None) -> None:
    message = {"kind": "a2a.message", "body": {"parts": [{"text": "x"}]}} | fields
    assert inner_problem(message) == problem
    assert content_problem(message, 10) == problem


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


def test_unrequested_task_updates_get_the_message_rate_in_windows_of_their_own(
    fake_clock: FakeClock,
) -> None:
    rl = RateLimiter(fake_clock)
    update = {"taskId": "t1", "status": {"state": "TASK_STATE_WORKING"}}
    for n in range(SENDER_PER_MINUTE):
        assert rl.allow_inner("g", "a", "a2a.task_status", update | {"n": n}, requested=False)
    assert not rl.allow_inner("g", "a", "a2a.task_artifact", update, requested=False)
    # The sender's messages and the task budget are untouched.
    assert rl.allow_inner("g", "a", "a2a.message", {"parts": []})
    assert rl.allow_inner("g", "a", "a2a.task_status", update)
    # Only task updates can be unrequested.
    for _ in range(SENDER_PER_MINUTE - 2):
        assert rl.allow_inner("g", "a", "a2a.message", {"parts": []}, requested=False)


def test_the_drain_exemption_is_bounded_per_sender_and_in_all() -> None:
    budget = DrainBudget(total=5)
    assert [budget.take("a", 2, 0) for _ in range(3)] == [True, True, False]
    assert [budget.take("b", 2, 0) for _ in range(2)] == [True, True]
    assert budget.take("c", 2, 0)
    assert not budget.take("c", 2, 0), "the connection total is spent"
    budget.reset()
    assert budget.take("c", 2, 0), "a new connection has a new total"


def test_reconnecting_doesnt_refill_a_senders_drain_exemption() -> None:
    """SR-36: the relay decides when a drain ends and a connection starts,
    so a relay colluding with a member could reconnect over and over to give
    it a fresh exemption each time. A sender's exempt messages are counted
    across connections, over DRAIN_WINDOW_SECS."""
    budget = DrainBudget(total=100)
    assert [budget.take("a", 2, 0) for _ in range(3)] == [True, True, False]
    for t in (10, 600, DRAIN_WINDOW_SECS - 1):
        budget.reset()
        assert not budget.take("a", 2, t), t
    budget.reset()
    assert budget.take("a", 2, DRAIN_WINDOW_SECS), "an hour on, the exemption is back"


PARTS = json.loads(
    (Path(__file__).resolve().parents[2] / "testdata" / "a2a-parts.json").read_text()
)


@pytest.mark.parametrize("case", PARTS["valid"])
def test_valid_parts_from_the_vectors(case: dict[str, Any]) -> None:
    assert part_kind(case["part"]) == case["kind"]
    body = {"parts": [case["part"]]}
    assert content_problem(inner("a2a.message", body), 10, Limits(allow_files=True)) is None


@pytest.mark.parametrize("case", PARTS["invalid"])
def test_malformed_parts_from_the_vectors(case: dict[str, Any]) -> None:
    assert part_kind(case["part"]) == "invalid", case["why"]
    body = {"parts": [case["part"]]}
    limits = Limits(allow_files=True)
    assert content_problem(inner("a2a.message", body), 10, limits) == "malformed", case["why"]
