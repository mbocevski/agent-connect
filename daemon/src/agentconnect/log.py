"""Structured JSON logging that can't leak message content.

Rules (AGENTS.md): never log message bodies, keys, secrets or invite URLs.
Identifiers (group ids, mailbox ids, identities, msg_ids) are logged only as
:func:`hid` tags.

Every logger from :func:`get` runs one fixed processor chain, whatever the
embedding application did to structlog's global configuration (the default
console renderer prints each frame's local variables with a traceback, and
those locals are envelopes, plaintext and secrets). The chain:

* drops events below the level set by :func:`configure` (INFO by default);
* replaces the value of any field whose name suggests content
  (:data:`REDACTED_FIELDS`) with ``"[redacted]"``;
* renders exceptions as a plain traceback: file, line and source text, never
  local variables;
* writes one JSON object per line to ``sys.stderr`` (looked up per event).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
import traceback
from collections.abc import MutableMapping
from typing import Any

import structlog

EventDict = MutableMapping[str, Any]

REDACTED_FIELDS = frozenset(
    {
        "body",
        "card",
        "ct",
        "delivery",
        "env",
        "frame",
        "inner",
        "key",
        "payload",
        "plaintext",
        "raw",
        "request",
        "secret",
        "sig",
        "text",
        "token",
        "url",
    }
)

_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "warn": logging.WARNING,
    "error": logging.ERROR,
    "exception": logging.ERROR,
    "critical": logging.CRITICAL,
    "fatal": logging.CRITICAL,
}
_state = {"level": logging.INFO}


def hid(value: str | bytes | None) -> str:
    """A short, stable tag for an identifier: the first 8 hex of SHA-256."""
    if value is None:
        return "-"
    raw = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()[:8]


def _filter(_logger: Any, method: str, event: EventDict) -> EventDict:
    if _LEVELS.get(method, logging.INFO) < _state["level"]:
        raise structlog.DropEvent
    return event


def _redact(_logger: Any, _method: str, event: EventDict) -> EventDict:
    for k in event:
        if k in REDACTED_FIELDS:
            event[k] = "[redacted]"
    return event


def _exc_info(_logger: Any, method: str, event: EventDict) -> EventDict:
    """Plain tracebacks only (no locals, no rich rendering)."""
    exc = event.pop("exc_info", None)
    if method == "exception" and exc is None:
        exc = True
    if exc:
        info = sys.exc_info() if exc is True else exc
        if isinstance(info, BaseException):
            info = (type(info), info, info.__traceback__)
        if isinstance(info, tuple) and info[0] is not None:
            event["exception"] = "".join(traceback.format_exception(*info))
    return event


def _render(_logger: Any, _method: str, event: EventDict) -> str:
    return json.dumps(dict(event), default=str, sort_keys=True)


PROCESSORS = [
    _filter,
    structlog.contextvars.merge_contextvars,
    structlog.processors.add_log_level,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
    _redact,
    _exc_info,
    _render,
]


class _Stderr:
    """Writes each rendered line to the current ``sys.stderr``."""

    def msg(self, message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    debug = info = warning = warn = error = exception = critical = fatal = log = msg


def configure(level: int = logging.INFO) -> None:
    """Set the level (``agentconnect daemon run`` calls this at start), and
    give stdlib logging (asyncio, httpx, websockets) a plain formatter, which
    never prints local variables."""
    _state["level"] = level
    logging.basicConfig(
        level=max(level, logging.WARNING),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def get(name: str) -> Any:
    return structlog.wrap_logger(
        _Stderr(), processors=PROCESSORS, wrapper_class=structlog.BoundLogger
    ).bind(logger=name)
