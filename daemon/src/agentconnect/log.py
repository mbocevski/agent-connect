"""Structured JSON logging.

Rules (AGENTS.md): never log message bodies, keys, secrets or invite URLs.
Identifiers (group ids, mailbox ids, identities, msg_ids) are logged only as
:func:`hid` tags.
"""

from __future__ import annotations

import hashlib
import logging
import sys
from typing import Any

import structlog


def hid(value: str | bytes | None) -> str:
    """A short, stable tag for an identifier: the first 8 hex of SHA-256."""
    if value is None:
        return "-"
    raw = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()[:8]


def configure(level: int = logging.INFO) -> None:
    """JSON lines on stderr (called by ``agentconnect daemon run``)."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get(name: str) -> Any:
    return structlog.get_logger(name)
