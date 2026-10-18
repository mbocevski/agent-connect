"""Test-only fault injection at the daemon's step boundaries (ADR-004).

Each :class:`~agentconnect.daemon.Daemon` has a :class:`Failpoints` set. It
is empty unless a test arms a point, and an empty set is one falsy check per
point, so the points are inert in production. An armed point either

* **raises** :class:`FailpointError`, a transient failure the daemon
  retries (the frame is neither recorded nor acked), or
* **crashes**: raises :class:`SimulatedCrash`, a ``BaseException`` that no
  handler in the daemon catches, so the worker dies on the spot as if the
  process had been killed there; the test then restarts the daemon.

The core has its own points (``Client._arm_failpoint_for_testing``). The
names are listed in :data:`POINTS` and in TESTING.md.
"""

from __future__ import annotations

from typing import Literal

Action = Literal["raise", "crash"]

#: Every daemon failpoint. ``<path>.before_core`` and ``<path>.after_core``
#: surround the core call; ``in_tx`` is inside the daemon transaction that
#: records the result, ``after_tx`` right after it commits, and
#: ``after_consume`` after the core journal entry is consumed (before the
#: relay ack). ``event.after_record`` and ``event.after_notify`` surround
#: telling the adapter about a recorded event.
PATHS = ("receive", "confirm", "welcome")
STEPS = ("before_core", "after_core", "in_tx", "after_tx", "after_consume")
POINTS = frozenset(
    {f"{path}.{step}" for path in PATHS for step in STEPS}
    | {"invite.after_register", "event.after_record", "event.after_notify"}
    | {"held_timer.expire"}
)


class FailpointError(Exception):
    """An injected transient failure."""


class SimulatedCrash(BaseException):
    """An injected crash: nothing in the daemon catches it."""


class Failpoints:
    """A daemon's armed failpoints."""

    def __init__(self) -> None:
        self._armed: dict[str, tuple[Action, int]] = {}
        self.fired: list[str] = []

    def arm(self, name: str, action: Action = "raise", times: int = 1) -> None:
        if name not in POINTS:
            msg = f"unknown failpoint {name}"
            raise ValueError(msg)
        self._armed[name] = (action, times)

    def clear(self) -> None:
        self._armed.clear()

    def hit(self, name: str) -> None:
        if not self._armed or name not in self._armed:
            return
        action, left = self._armed[name]
        if left <= 1:
            del self._armed[name]
        else:
            self._armed[name] = (action, left - 1)
        self.fired.append(name)
        if action == "crash":
            raise SimulatedCrash(name)
        raise FailpointError(name)
