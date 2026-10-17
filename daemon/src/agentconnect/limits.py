"""SPEC §10.2 endpoint limits and the §7.2 kind and part checks.

The SPEC defaults (:data:`SPEC_LIMITS`):

* Messages are at most 256 KiB (the canonical JSON of the inner message).
* Each sender instance may send 30 messages per minute, all instances of one
  identity together 3 times that, and a group 120.
* Updates for a task (``a2a.task_status``, ``a2a.task_artifact`` with a
  ``taskId``) have their own budget: 300 per minute per task and sender
  instance, 3 times that for all of one identity's tasks, and 1200 for the
  group's. The first update of a task in the window counts as an ordinary
  message, so opening tasks is held to the message rates.
* A2A parts may be ``text`` or ``data``; ``file`` parts are disabled.
* Only the kinds of §7.2/§7.3 are delivered; unknown kinds are ignored.

A group, or one sender in it, can have lower values (:class:`Limits`), never
higher ones (SPEC 10.2); the safety policy (:mod:`agentconnect.policy`) picks
them. Rates are counted on the daemon clock over a sliding 60-second
window, separately for what is received (inbound) and what is queued
(outbound).
"""

from __future__ import annotations

import json
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any

from agentconnect.clock import Clock
from agentconnect.schemas import schema_ok

MAX_MESSAGE_BYTES = 256 * 1024
SENDER_PER_MINUTE = 30
GROUP_PER_MINUTE = 120
IDENTITY_RATE_MULTIPLE = 3  # all instances of an identity: 3 x SENDER_PER_MINUTE
TASK_PER_MINUTE = 300
GROUP_TASK_PER_MINUTE = 1200  # task updates from the whole group: 4 x TASK_PER_MINUTE
MAX_KEYS = 50_000  # rate windows tracked at most (least recently used go first)
SWEEP_FLOOR = 256  # sweep emptied windows once more than this many are tracked
MAX_TASK_ID = 256  # longer taskIds get no task budget
DEFAULT_MAX_FILE_BYTES = 64 * 1024
TASK_UPDATE_KINDS = frozenset({"a2a.task_status", "a2a.task_artifact"})
WINDOW_SECS = 60.0
ALLOWED_PARTS = frozenset({"text", "data"})
KNOWN_KINDS = frozenset(
    {
        "a2a.message",
        "a2a.task_status",
        "a2a.task_artifact",
        "a2a.agent_card",
        "a2a.task_cancel",
        "control.leave",
        "control.close",
        "control.floor",
        "control.pause",
        "control.resume",
        "control.capabilities",
    }
)
_PART_FIELDS = ("text", "data", "file", "raw", "url")


@dataclass(frozen=True)
class Limits:
    """The §10.2 limits one message is held to."""

    max_message_bytes: int = MAX_MESSAGE_BYTES
    sender_per_minute: int = SENDER_PER_MINUTE
    group_per_minute: int = GROUP_PER_MINUTE
    identity_rate_multiple: int = IDENTITY_RATE_MULTIPLE
    task_per_minute: int = TASK_PER_MINUTE
    group_task_per_minute: int = GROUP_TASK_PER_MINUTE
    allow_files: bool = False
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES


SPEC_LIMITS = Limits()


def part_kind(part: Any) -> str:
    """The kind of one A2A part: an explicit ``kind`` (A2A 0.x) or the
    member it carries (A2A 1.0: ``text``, ``data``, ``file``/``raw``/``url``)."""
    if not isinstance(part, dict):
        return "invalid"
    kind = part.get("kind")
    if isinstance(kind, str):
        return kind
    present = [f for f in _PART_FIELDS if f in part]
    if len(present) != 1:
        return "invalid"
    return "file" if present[0] in ("file", "raw", "url") else present[0]


def _parts_of(kind: str, body: dict[str, Any]) -> list[Any]:
    """Every part list a body of ``kind`` carries."""
    if kind == "a2a.message":
        parts = body.get("parts", [])
        return parts if isinstance(parts, list) else [None]
    if kind == "a2a.task_artifact":
        artifact = body.get("artifact")
        parts = artifact.get("parts", []) if isinstance(artifact, dict) else []
        return parts if isinstance(parts, list) else [None]
    if kind == "a2a.task_status":
        status = body.get("status")
        message = status.get("message") if isinstance(status, dict) else None
        parts = message.get("parts", []) if isinstance(message, dict) else []
        return parts if isinstance(parts, list) else [None]
    return []


def _part_size(part: Any) -> int:
    return len(json.dumps(part, sort_keys=True, separators=(",", ":")).encode())


def content_problem(inner: dict[str, Any], size: int, limits: Limits = SPEC_LIMITS) -> str | None:
    """Why ``inner`` (``size`` bytes of canonical JSON) breaks §10.2/§7.2
    under ``limits``: ``unknown_kind``, ``too_large``, ``malformed`` (not
    an object, or a control, card or cancel outside its strict schema,
    :mod:`agentconnect.schemas`), ``part_kind`` or ``file_too_large``."""
    kind = inner.get("kind")
    if kind not in KNOWN_KINDS:
        return "unknown_kind"
    if size > limits.max_message_bytes:
        return "too_large"
    body = inner.get("body")
    if not isinstance(body, dict) or not schema_ok(str(kind), body):
        return "malformed"
    allowed = ALLOWED_PARTS | {"file"} if limits.allow_files else ALLOWED_PARTS
    for part in _parts_of(str(kind), body):
        found = part_kind(part)
        if found not in allowed:
            return "part_kind"
        if found == "file" and _part_size(part) > limits.max_file_bytes:
            return "file_too_large"
    return None


MAX_DRAIN_EXEMPT = 1000  # rate-exempt messages per reconnect drain, all senders
DRAIN_RATE_MULTIPLE = 2  # ...and per identity: 2 x its sender_per_minute


class DrainBudget:
    """How many messages of a reconnect drain (SPEC 8.2/10.2) skip the rates:
    at most ``total`` per connection, and per sender at most what
    :meth:`take` is given, so one peer's queued messages can't use up the
    exemption."""

    def __init__(self, total: int = MAX_DRAIN_EXEMPT) -> None:
        self._total = total
        self._used: dict[str, int] = {}

    def reset(self) -> None:
        """A new connection: a new drain."""
        self._used.clear()

    def take(self, sender: str, cap: int) -> bool:
        """Count one exempt message from ``sender``; False when it is over
        ``cap`` for that sender or the connection's total is spent."""
        if sum(self._used.values()) >= self._total or self._used.get(sender, 0) >= cap:
            return False
        self._used[sender] = self._used.get(sender, 0) + 1
        return True


class RateLimiter:
    """Sliding-window counts per sender instance, identity, group and task.

    Each direction has its own windows (``direction`` is ``in`` for what
    peers send to this member, ``out`` for what it sends), so a member's own
    sends never use up the budget it grants its peers, and peer traffic
    never stops its own sends.

    The state is bounded: windows that emptied are swept away once the map
    grows, and past :data:`MAX_KEYS` the least recently used are evicted.
    """

    def __init__(self, clock: Clock, max_keys: int = MAX_KEYS) -> None:
        self._clock = clock
        self._max_keys = max_keys
        self._seen: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._sweep_at = SWEEP_FLOOR

    def _now(self) -> float:
        return self._clock.unix_millis() / 1000

    def size(self) -> int:
        """How many windows are tracked."""
        return len(self._seen)

    def _count(self, key: tuple[str, str], now: float) -> deque[float]:
        times = self._seen.get(key)
        if times is None:
            times = self._seen[key] = deque[float]()
        self._seen.move_to_end(key)
        while times and times[0] <= now - WINDOW_SECS:
            times.popleft()
        return times

    def _sweep(self, now: float) -> None:
        if len(self._seen) <= self._sweep_at:
            return
        for key in [k for k, t in self._seen.items() if not t or t[-1] <= now - WINDOW_SECS]:
            del self._seen[key]
        while len(self._seen) > self._max_keys:
            self._seen.popitem(last=False)
        self._sweep_at = max(SWEEP_FLOOR, 2 * len(self._seen))

    def forget_group(self, group_id: str) -> None:
        for key in [k for k in self._seen if k[0] == group_id]:
            del self._seen[key]

    def _windows(
        self, group_id: str, sender: str, identity: str | None, limits: Limits, direction: str
    ) -> list[tuple[deque[float], int]]:
        now = self._now()
        windows = [
            (self._count((group_id, f"{direction}\0{sender}"), now), limits.sender_per_minute),
            (self._count((group_id, f"{direction}\0group"), now), limits.group_per_minute),
        ]
        if identity is not None:
            cap = limits.sender_per_minute * limits.identity_rate_multiple
            windows.append((self._count((group_id, f"{direction}\0id\0{identity}"), now), cap))
        return windows

    @staticmethod
    def _take(windows: list[tuple[deque[float], int]], now: float) -> bool:
        if any(len(times) >= limit for times, limit in windows):
            return False
        for times, _limit in windows:
            times.append(now)
        return True

    def allow(
        self,
        group_id: str,
        sender: str,
        limits: Limits = SPEC_LIMITS,
        *,
        identity: str | None = None,
        direction: str = "in",
    ) -> bool:
        """Count one message from ``sender`` (an instance); False if it is
        over a limit (and then it doesn't count). With ``identity``, all
        instances of that identity together are also held to
        ``identity_rate_multiple`` times the per-sender rate."""
        now = self._now()
        ok = self._take(self._windows(group_id, sender, identity, limits, direction), now)
        self._sweep(now)
        return ok

    def allow_inner(  # noqa: PLR0913
        self,
        group_id: str,
        sender: str,
        kind: Any,
        body: Any,
        limits: Limits = SPEC_LIMITS,
        *,
        identity: str | None = None,
        direction: str = "in",
    ) -> bool:
        """Count one inner message against its budget (SPEC 10.2).

        A task update counts against its task's budget (per sender instance),
        against all of the identity's task updates (``identity_rate_multiple``
        times the task budget) and against the group's
        (``group_task_per_minute``). The first update of a task in the window
        also counts as an ordinary message. Anything else counts against the
        message rates."""
        task = body.get("taskId") if kind in TASK_UPDATE_KINDS and isinstance(body, dict) else None
        if not isinstance(task, str) or not 0 < len(task) <= MAX_TASK_ID:
            return self.allow(group_id, sender, limits, identity=identity, direction=direction)
        now = self._now()
        prefix = f"{direction}\0task"
        windows = [
            (self._count((group_id, f"{prefix}\0{sender}\0{task}"), now), limits.task_per_minute),
            (self._count((group_id, f"{prefix}\0group"), now), limits.group_task_per_minute),
        ]
        if identity is not None:
            cap = limits.task_per_minute * limits.identity_rate_multiple
            windows.append((self._count((group_id, f"{prefix}\0id\0{identity}"), now), cap))
        if not windows[0][0]:
            # A task new in this window opens with an ordinary message.
            windows += self._windows(group_id, sender, identity, limits, direction)
        ok = self._take(windows, now)
        self._sweep(now)
        return ok
