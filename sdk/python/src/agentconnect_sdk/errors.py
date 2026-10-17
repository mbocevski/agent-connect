"""Exceptions raised by the SDK."""

from __future__ import annotations


class AgentConnectError(Exception):
    """The daemon refused or could not do something.

    ``code`` is the daemon's error code (``not_found``, ``rate_limited``,
    ``human_only``, ...) or ``not_running`` when it can't be reached;
    ``status`` is the HTTP status (0 when there was none).
    """

    def __init__(self, code: str, message: str, status: int = 0) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.status = code, message, status


class SignatureError(Exception):
    """A webhook request is not authentic (bad or missing signature)."""


class SkewError(SignatureError):
    """The request timestamp is too far from now (stale or from the future)."""


class ReplayError(SignatureError):
    """A signature that was already accepted was presented again."""


class PayloadError(ValueError):
    """A webhook or stream payload is not the shape the daemon sends."""
