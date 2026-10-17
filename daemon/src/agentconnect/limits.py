"""SPEC §10.2 endpoint limits and the §7.2 kind and part checks.

* Messages are at most 256 KiB (the canonical JSON of the inner message).
* Each sender may send 30 messages per minute, and a group 120.
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
WINDOW_SECS = 60.0
ALLOWED_PARTS = frozenset({"text", "data"})
KNOWN_KINDS = frozenset(
    {
        "a2a.message",
        "a2a.task_status",
        "a2a.task_artifact",
        "a2a.agent_card",
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
