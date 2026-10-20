"""Test-only fault injection at the daemon's step boundaries (ADR-004).

Each :class:`~agentconnect.runtime.engine.Engine` has a :class:`Failpoints` set. It
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
#: telling the adapter about a recorded event; ``delivery.after_adapter`` is
#: after the adapter accepted a message, before the inbox records that.
#: Publishing a listing (docs/discovery.md): ``door.after_register`` (the
#: relay has the door, the daemon doesn't record it yet), ``listing.after_sign``
#: (signed and stored, not posted) and ``listing.after_post`` (the directory
#: accepted it, not recorded yet); ``withdraw.after_close`` is after closing
#: the doors, before the withdrawal is sent.
#: Knocks: ``knock.in_tx`` and ``knock.after_tx`` around the owner's record
#: of a received knock (ledger, approval, inbox); ``knock_welcome.*`` are
#: the knocker's join steps (as ``welcome.*``); ``knock_send.after_core``
#: is after the core built the knock, before it is recorded and queued;
#: ``knock_approve.after_group`` after the core created the approval's
#: group, before it is recorded; ``knock_add.after_welcome`` after the
#: approved knock's Welcome went out, before the approval is recorded done.
#: Joins: ``join_request.in_tx`` and ``join_request.after_tx`` around the
#: inviter's record of a verified JoinRequest (replay ledger, approval, inbox).
#: Leaves: ``leave_timeout.in_tx`` and ``leave_timeout.after_tx`` around a
#: timed-out leave's deletion of the group and its ``left`` event.
#: A message that fails alone: ``poison.in_tx`` and ``poison.after_tx``
#: around recording it as failed (inbox, audit row, ``message_failed``).
PATHS = ("receive", "confirm", "welcome", "knock_welcome")
STEPS = ("before_core", "after_core", "in_tx", "after_tx", "after_consume")
POINTS = frozenset(
    {f"{path}.{step}" for path in PATHS for step in STEPS}
    | {"invite.after_register", "event.after_record", "event.after_notify"}
    | {"held_timer.expire", "delivery.after_adapter"}
    | {"door.after_register", "listing.after_sign", "listing.after_post"}
    | {"withdraw.after_close"}
    | {"knock.in_tx", "knock.after_tx", "knock_send.after_core"}
    | {"knock_approve.after_group", "knock_add.after_welcome"}
    | {"join_request.in_tx", "join_request.after_tx"}
    | {"leave_timeout.in_tx", "leave_timeout.after_tx"}
    | {"poison.in_tx", "poison.after_tx"}
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
