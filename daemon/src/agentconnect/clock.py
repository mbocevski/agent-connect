"""Injectable time source.

Daemon code must not call ``datetime.now()``, ``time.time()`` or
``asyncio.sleep()`` directly: it takes a :class:`Clock` so tests can drive
time with :class:`FakeClock` instead of sleeping. Mirrors
``agentconnect_core::clock`` on the Rust side.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

# 2025-01-01T00:00:00Z: a fixed, recognisable default start for fake clocks.
DEFAULT_FAKE_START = datetime(2025, 1, 1, tzinfo=UTC)

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@runtime_checkable
class Clock(Protocol):
    """A source of wall-clock time and timers."""

    def now(self) -> datetime:
        """The current time as a timezone-aware UTC datetime."""
        ...

    def unix_millis(self) -> int:
        """Whole milliseconds since the Unix epoch."""
        ...

    async def sleep(self, seconds: float, *, deadline: bool = False) -> None:
        """Wait until ``seconds`` of this clock's time have passed.
        ``deadline=True`` marks a timer that bounds other work (a handler
        timeout) rather than a pause before the next attempt; a fake clock
        doesn't count it as a sleeper."""
        ...


def _millis(moment: datetime) -> int:
    return (moment - _EPOCH) // timedelta(milliseconds=1)


def unix_seconds(clock: Clock) -> int:
    """Whole seconds since the Unix epoch on ``clock``."""
    return clock.unix_millis() // 1000


class SystemClock:
    """The real clock."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def unix_millis(self) -> int:
        return _millis(self.now())

    async def sleep(self, seconds: float, *, deadline: bool = False) -> None:
        await asyncio.sleep(max(seconds, 0))


def _wake(fut: asyncio.Future[Any]) -> None:
    if not fut.done():
        fut.set_result(None)


class FakeClock:
    """A manually driven, thread-safe clock for tests.

    Time only moves through :meth:`advance` and :meth:`set`. :meth:`sleep`
    returns once the clock has been moved past its deadline, so timers
    (reconnect backoff, retries) run without real waiting.
    """

    def __init__(self, start: datetime = DEFAULT_FAKE_START) -> None:
        self._lock = threading.Lock()
        self._now = self._checked(start)
        self._sleepers: list[tuple[datetime, asyncio.AbstractEventLoop, asyncio.Future[Any]]] = []
        self._deadlines: set[int] = set()  # ids of the futures of deadline sleeps

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

    @property
    def sleepers(self) -> int:
        """How many :meth:`sleep` calls are waiting, not counting deadlines
        (timers that bound other work, such as a handler timeout): tests
        read this as "the runtime is waiting to retry"."""
        with self._lock:
            return len([s for s in self._sleepers if id(s[2]) not in self._deadlines])

    async def sleep(self, seconds: float, *, deadline: bool = False) -> None:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        with self._lock:
            entry = (self._now + timedelta(seconds=max(seconds, 0)), loop, fut)
            if seconds <= 0:
                fut.set_result(None)
            else:
                self._sleepers.append(entry)
                if deadline:
                    self._deadlines.add(id(fut))
        try:
            await fut
        finally:
            with self._lock:
                if entry in self._sleepers:
                    self._sleepers.remove(entry)
                self._deadlines.discard(id(fut))

    def _release_due(self) -> None:
        # Called with the lock held.
        due = [s for s in self._sleepers if s[0] <= self._now]
        for s in due:
            self._sleepers.remove(s)
            _, loop, fut = s
            if not loop.is_closed():
                loop.call_soon_threadsafe(_wake, fut)

    def advance(self, by: timedelta | float) -> None:
        """Move forward by a timedelta or a number of seconds."""
        delta = by if isinstance(by, timedelta) else timedelta(seconds=by)
        with self._lock:
            self._now += delta
            self._release_due()

    def set(self, to: datetime) -> None:
        """Jump to an absolute time (may move backwards)."""
        moment = self._checked(to)
        with self._lock:
            self._now = moment
            self._release_due()
