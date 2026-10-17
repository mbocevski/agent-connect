"""Idempotency for at-least-once delivery.

The daemon delivers each message and event at least once, so the same
``msg_id`` / ``event_id`` can arrive again (an ack was lost, the daemon
restarted, an SSE stream resumed). :class:`Deduper` remembers the ids a
handler finished with, so user code sees each one once.
"""

from __future__ import annotations

from collections import OrderedDict

DEFAULT_CAPACITY = 4096


class Deduper:
    """A bounded, in-memory record of handled ids.

    An id is *claimed* while its handler runs (a duplicate that arrives
    meanwhile is refused, not run twice) and *done* once the handler
    returned. A handler that raises releases the claim, so the redelivery
    runs it again. Memory only: a restart forgets, and the first redelivery
    after a restart runs the handler again, which is the at-least-once
    contract. Pass your own store to persist ids.
    """

    def __init__(self, capacity: int = DEFAULT_CAPACITY) -> None:
        if capacity < 1:
            msg = "capacity must be at least 1"
            raise ValueError(msg)
        self._capacity = capacity
        self._done: OrderedDict[str, None] = OrderedDict()
        self._claimed: set[str] = set()

    def claim(self, key: str) -> bool:
        """``True`` if the caller should handle ``key``; ``False`` for a
        duplicate (already handled, or being handled now)."""
        if key in self._done or key in self._claimed:
            return False
        self._claimed.add(key)
        return True

    def done(self, key: str) -> None:
        self._claimed.discard(key)
        self._done[key] = None
        while len(self._done) > self._capacity:
            self._done.popitem(last=False)

    def release(self, key: str) -> None:
        self._claimed.discard(key)

    def handled(self, key: str) -> bool:
        return key in self._done

    def in_flight(self, key: str) -> bool:
        return key in self._claimed
