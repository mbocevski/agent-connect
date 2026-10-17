import threading
from datetime import UTC, datetime, timedelta, timezone

import pytest

from agentconnect.clock import DEFAULT_FAKE_START, Clock, FakeClock, SystemClock


def test_system_clock_satisfies_protocol_and_is_recent() -> None:
    clock = SystemClock()
    assert isinstance(clock, Clock)
    assert clock.now().tzinfo is not None
    assert clock.unix_millis() > 1_735_689_600_000


def test_fake_clock_satisfies_protocol() -> None:
    assert isinstance(FakeClock(), Clock)


def test_fake_clock_only_moves_when_told(fake_clock: FakeClock) -> None:
    assert fake_clock.now() == DEFAULT_FAKE_START
    assert fake_clock.now() == fake_clock.now()
    fake_clock.advance(timedelta(milliseconds=1500))
    assert fake_clock.unix_millis() == 1_735_689_601_500


def test_advance_accepts_seconds(fake_clock: FakeClock) -> None:
    fake_clock.advance(2.5)
    assert fake_clock.now() == DEFAULT_FAKE_START + timedelta(seconds=2.5)


def test_set_can_move_backwards(fake_clock: FakeClock) -> None:
    fake_clock.set(datetime(1970, 1, 1, 0, 0, 5, tzinfo=UTC))
    assert fake_clock.unix_millis() == 5_000


def test_naive_datetimes_are_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        FakeClock(datetime(2025, 1, 1))
    with pytest.raises(ValueError, match="timezone-aware"):
        FakeClock().set(datetime(2025, 1, 1))


def test_other_timezones_normalise_to_utc() -> None:
    clock = FakeClock(datetime(2025, 1, 1, 1, tzinfo=timezone(timedelta(hours=1))))
    assert clock.now() == DEFAULT_FAKE_START
    assert clock.now().tzinfo is UTC


def test_fake_clock_is_thread_safe() -> None:
    clock = FakeClock(datetime(1970, 1, 1, tzinfo=UTC))

    def work() -> None:
        for _ in range(200):
            clock.advance(timedelta(milliseconds=1))

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert clock.unix_millis() == 1_600
