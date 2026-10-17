"""Verify webhook requests from the AgentConnect daemon.

The daemon signs ``<timestamp>.<body>`` with HMAC-SHA256 and sends:

* ``X-AgentConnect-Timestamp``: Unix time in whole seconds, ASCII digits
  only (no sign, space or fraction);
* ``X-AgentConnect-Signature``: ``v0=`` and the 64 lowercase hex digits of the
  HMAC-SHA256 of ``<timestamp>.<body>``, with the body as the raw bytes
  received (never re-serialised).

The exact rules are in ``docs/adapters/webhook.md``.

:func:`verify` checks one request. :class:`WebhookVerifier` adds the replay
check: a signature it already accepted is refused until it ages out of the
skew window. The daemon signs every attempt afresh, so an honest retry is
never mistaken for a replay.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable, Mapping

from agentconnect_sdk.errors import ReplayError, SignatureError, SkewError

SIGNATURE_HEADER = "X-AgentConnect-Signature"
TIMESTAMP_HEADER = "X-AgentConnect-Timestamp"
SIGNATURE_VERSION = "v0"
DEFAULT_TOLERANCE = 300.0  # seconds: the 5 minute skew limit
MAX_REMEMBERED = 10_000
MAX_TIMESTAMP_DIGITS = 12


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """The signature header value for a request (the daemon's side; tests
    and custom senders use it too)."""
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return f"{SIGNATURE_VERSION}={mac.hexdigest()}"


def verify(  # noqa: PLR0913
    secret: str,
    timestamp: str,
    signature: str,
    body: bytes,
    *,
    now: float,
    tolerance: float = DEFAULT_TOLERANCE,
) -> None:
    """Raise :class:`SignatureError` unless the request is genuine and fresh.

    :class:`SkewError` (a subclass) means the timestamp is more than
    ``tolerance`` seconds from ``now``; it is checked first, so a stale
    request is refused whatever its signature.
    """
    if not (timestamp.isascii() and timestamp.isdigit()) or len(timestamp) > MAX_TIMESTAMP_DIGITS:
        raise SignatureError("timestamp is not Unix seconds")
    sent = int(timestamp)
    if str(sent) != timestamp:
        raise SignatureError("timestamp has leading zeros")
    if abs(now - sent) > tolerance:
        raise SkewError("timestamp is outside the allowed skew")
    expected = sign(secret, timestamp, body)
    if not signature.isascii() or not hmac.compare_digest(expected.encode(), signature.encode()):
        raise SignatureError("signature does not match")


class WebhookVerifier:
    """:func:`verify` for a headers mapping, plus replay protection.

    ``clock`` returns Unix seconds; pass a fake in tests.
    """

    def __init__(
        self,
        secret: str,
        *,
        tolerance: float = DEFAULT_TOLERANCE,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._secret = secret
        self._tolerance = tolerance
        self._clock = clock
        self._seen: dict[str, float] = {}

    def verify(self, headers: Mapping[str, str], body: bytes) -> None:
        lowered = {k.lower(): v for k, v in headers.items()}
        timestamp = lowered.get(TIMESTAMP_HEADER.lower())
        signature = lowered.get(SIGNATURE_HEADER.lower())
        if timestamp is None or signature is None:
            raise SignatureError("missing signature headers")
        now = self._clock()
        verify(self._secret, timestamp, signature, body, now=now, tolerance=self._tolerance)
        self._forget_old(now)
        if signature in self._seen:
            raise ReplayError("request was already received")
        if len(self._seen) >= MAX_REMEMBERED:
            # Bounded memory: drop the oldest entry. It is outside the skew
            # window for any realistic rate, and a replay of it would still
            # be refused by the receiver's dedupe by id.
            self._seen.pop(min(self._seen, key=self._seen.__getitem__))
        self._seen[signature] = now

    def _forget_old(self, now: float) -> None:
        cutoff = now - self._tolerance
        for key in [k for k, t in self._seen.items() if t < cutoff]:
            del self._seen[key]
