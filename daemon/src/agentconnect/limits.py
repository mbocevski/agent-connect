"""SPEC §10.2 endpoint limits and the §7.2 kind and part checks.

* Messages are at most 256 KiB (the canonical JSON of the inner message).
* Each sender may send 30 messages per minute, and a group 120.
* Updates for a task (``a2a.task_status``, ``a2a.task_artifact`` with a
  ``taskId``) have their own budget: 300 per minute per task and sender.
  The first update of a task in the window counts as an ordinary message, so
  opening tasks is held to the message rates.
* A2A parts may be ``text`` or ``data``; ``file`` parts are disabled.
* Only the kinds of §7.2/§7.3 are delivered; unknown kinds are ignored.

Rates are counted on the daemon clock over a sliding 60-second window, when
a message is received (inbound) or queued (outbound).
"""

from __future__ import annotations

from collections import deque
from typing import Any

from agentconnect.clock import Clock

MAX_MESSAGE_BYTES = 256 * 1024
SENDER_PER_MINUTE = 30
GROUP_PER_MINUTE = 120
TASK_PER_MINUTE = 300
MAX_TASK_ID = 256  # longer taskIds get no task budget
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


def content_problem(inner: dict[str, Any], size: int) -> str | None:
    """Why ``inner`` (``size`` bytes of canonical JSON) breaks §10.2/§7.2."""
    kind = inner.get("kind")
    if kind not in KNOWN_KINDS:
        return "unknown_kind"
    if size > MAX_MESSAGE_BYTES:
        return "too_large"
    body = inner.get("body")
    if not isinstance(body, dict):
        return "malformed"
    if any(part_kind(p) not in ALLOWED_PARTS for p in _parts_of(str(kind), body)):
        return "part_kind"
    return None


class RateLimiter:
    """Sliding-window counts per sender and per group."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._seen: dict[tuple[str, str], deque[float]] = {}

    def _now(self) -> float:
        return self._clock.unix_millis() / 1000

    def _count(self, key: tuple[str, str], now: float) -> deque[float]:
        times = self._seen.setdefault(key, deque())
        while times and times[0] <= now - WINDOW_SECS:
            times.popleft()
        return times

    def allow(self, group_id: str, sender: str) -> bool:
        """Count one message; False if it is over either limit (and then it
        doesn't count)."""
        now = self._now()
        per_sender = self._count((group_id, sender), now)
        per_group = self._count((group_id, ""), now)
        if len(per_sender) >= SENDER_PER_MINUTE or len(per_group) >= GROUP_PER_MINUTE:
            return False
        per_sender.append(now)
        per_group.append(now)
        return True

    def allow_inner(self, group_id: str, sender: str, kind: Any, body: Any) -> bool:
        """Count one inner message against its budget (SPEC 10.2): a task
        update against its task's, anything else against the message rates."""
        task = body.get("taskId") if kind in TASK_UPDATE_KINDS and isinstance(body, dict) else None
        if not isinstance(task, str) or not 0 < len(task) <= MAX_TASK_ID:
            return self.allow(group_id, sender)
        now = self._now()
        times = self._count((group_id, f"{sender}\0task\0{task}"), now)
        if not times:
            # A task new in this window opens with an ordinary message.
            if not self.allow(group_id, sender):
                return False
        elif len(times) >= TASK_PER_MINUTE:
            return False
        times.append(now)
        return True
