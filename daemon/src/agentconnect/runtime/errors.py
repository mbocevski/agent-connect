"""Errors of the runtime's operations, and how each maps to an API answer.

The local API and the embedded SDK both turn a failed operation into the
same ``(status, code, message)``, so a caller sees the same error whichever
host it uses.
"""

from __future__ import annotations

from agentconnect.relay import RelayError
from agentconnect.runtime.engine import DaemonError

ERROR_STATUS = {
    "bad_request": 400,
    "wrong_relay": 400,
    "forbidden": 403,
    "not_permitted": 403,
    "not_found": 404,
    "group_full": 409,
    "expired": 409,
    "stale_epoch": 409,
    "invite_not_open": 409,
    "not_moderated": 409,
    "too_large": 413,
    "rate_limited": 429,
    "relay": 502,
}


class ApiError(Exception):
    """A refused request: an HTTP ``status`` and a short ``code``."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code = status, code


def error_reply(e: Exception) -> tuple[int, str, str] | None:
    """``(status, code, message)`` for an operation's error, or ``None`` for
    an unexpected one (a bug: the caller logs it and answers 500)."""
    if isinstance(e, ApiError):
        return e.status, e.code, str(e)
    if isinstance(e, DaemonError):
        return ERROR_STATUS.get(e.code, 409), e.code, str(e)
    if isinstance(e, RelayError):
        return 502, e.code, str(e)
    return None
