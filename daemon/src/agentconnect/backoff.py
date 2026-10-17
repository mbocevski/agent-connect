"""Exponential backoff with jitter for reconnects and retries."""

from __future__ import annotations

import random


class Backoff:
    """Delays ``base * factor**n`` capped at ``cap``, with "equal jitter":
    each delay is drawn uniformly from ``[d/2, d]``, so retries from many
    daemons spread out but never collapse to zero.

    ``rng`` is injectable so tests are deterministic.
    """

    def __init__(
        self,
        base: float = 0.5,
        cap: float = 60.0,
        factor: float = 2.0,
        rng: random.Random | None = None,
    ) -> None:
        if base <= 0 or cap < base or factor < 1:
            msg = "need 0 < base <= cap and factor >= 1"
            raise ValueError(msg)
        self.base, self.cap, self.factor = base, cap, factor
        self._rng = rng or random.SystemRandom()
        self.attempts = 0

    def ceiling(self, attempt: int) -> float:
        """The un-jittered delay for ``attempt`` (0-based)."""
        # min() before the power would be nicer, but ** on huge attempts
        # overflows floats, so clamp the exponent.
        return min(self.cap, float(self.base * self.factor ** min(attempt, 64)))

    def next(self) -> float:
        d = self.ceiling(self.attempts)
        self.attempts += 1
        return self._rng.uniform(d / 2, d)

    def reset(self) -> None:
        self.attempts = 0
