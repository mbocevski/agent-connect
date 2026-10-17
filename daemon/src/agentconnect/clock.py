"""Injectable time source.

Daemon code must not call ``datetime.now()`` or ``time.time()`` directly: it
takes a :class:`Clock` so tests can drive time with :class:`FakeClock` instead
of sleeping. Mirrors ``agentconnect_core::clock`` on the Rust side.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

# 2025-01-01T00:00:00Z: a fixed, recognisable default start for fake clocks.
DEFAULT_FAKE_START = datetime(2025, 1, 1, tzinfo=UTC)

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@runtime_checkable
class Clock(Protocol):
    """A source of wall-clock time."""

    def now(self) -> datetime:
        """The current time as a timezone-aware UTC datetime."""
        ...

    def unix_millis(self) -> int:
        """Whole milliseconds since the Unix epoch."""
        ...


def _millis(moment: datetime) -> int:
    return (moment - _EPOCH) // timedelta(milliseconds=1)


class SystemClock:
    """The real clock."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def unix_millis(self) -> int:
        return _millis(self.now())


class FakeClock:
    """A manually driven, thread-safe clock for tests.

    Time only moves through :meth:`advance` and :meth:`set`.
    """

    def __init__(self, start: datetime = DEFAULT_FAKE_START) -> None:
        self._lock = threading.Lock()
        self._now = self._checked(start)

    @staticmethod
    def _checked(moment: datetime) -> datetime:
        if moment.tzinfo is None:
            msg = "FakeClock needs a timezone-aware datetime"
            raise ValueError(msg)
        return moment.astimezone(UTC)

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def unix_millis(self) -> int:
        return _millis(self.now())

    def advance(self, by: timedelta | float) -> None:
        """Move forward by a timedelta or a number of seconds."""
        delta = by if isinstance(by, timedelta) else timedelta(seconds=by)
        with self._lock:
            self._now += delta

    def set(self, to: datetime) -> None:
        """Jump to an absolute time (may move backwards)."""
        moment = self._checked(to)
        with self._lock:
            self._now = moment
