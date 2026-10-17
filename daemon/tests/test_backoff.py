import random

import pytest

from agentconnect.backoff import Backoff


def test_delays_grow_with_jitter_and_cap(rng: random.Random) -> None:
    b = Backoff(base=1, cap=8, rng=rng)
    delays = [b.next() for _ in range(7)]
    for i, d in enumerate(delays):
        ceiling = min(8, 2**i)
        assert ceiling / 2 <= d <= ceiling
    assert b.attempts == 7
    b.reset()
    assert b.attempts == 0
    assert 0.5 <= b.next() <= 1


def test_same_seed_same_delays(test_seed: int) -> None:
    def run() -> list[float]:
        b = Backoff(rng=random.Random(test_seed))  # noqa: S311
        return [b.next() for _ in range(5)]

    assert run() == run()


def test_huge_attempt_counts_do_not_overflow() -> None:
    assert Backoff(cap=60).ceiling(10_000) == 60


@pytest.mark.parametrize(("base", "cap", "factor"), [(0, 1, 2), (2, 1, 2), (1, 2, 0.5)])
def test_invalid_parameters(base: float, cap: float, factor: float) -> None:
    with pytest.raises(ValueError, match="base"):
        Backoff(base, cap, factor)
