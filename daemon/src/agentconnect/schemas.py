"""Strict schemas for the kinds that carry no content: the controls (SPEC
§7.3), Agent Cards (§10.5) and task cancellations (§7.2).

Only ``a2a.message``, ``a2a.task_status`` and ``a2a.task_artifact`` carry
A2A parts. Every other kind has a fixed shape, and a body with any other
field, or with a ``parts`` list anywhere in it, is ``malformed``: a member
can't smuggle text, data or files to an agent (or past ``require_approval``)
under a kind that is never held and never shown as text.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

CONTENT_KINDS = frozenset({"a2a.message", "a2a.task_status", "a2a.task_artifact"})
MAX_REASON = 200
MAX_ID = 256
MAX_NAME = 200
MAX_ADAPTERS = 16
MAX_DEPTH = 32
PAUSE_REASONS = frozenset({"loop_guard", "human"})
ACCEPTS = frozenset({"text", "data", "file"})
# The A2A v1.0 AgentCard and CancelTaskRequest fields (their JSON names).
CARD_FIELDS = frozenset(
    {
        "name",
        "description",
        "supportedInterfaces",
        "provider",
        "version",
        "documentationUrl",
        "capabilities",
        "securitySchemes",
        "securityRequirements",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
        "signatures",
        "iconUrl",
    }
)
CANCEL_FIELDS = frozenset({"id", "metadata", "tenant"})


def _str(value: Any, longest: int, *, empty: bool = False) -> bool:
    return isinstance(value, str) and (empty or value != "") and len(value) <= longest


def _identity(value: Any) -> bool:
    return _str(value, 128) and str(value).startswith("ac:v0:")


def _has_parts(value: Any, depth: int = 0) -> bool:
    """Whether a ``parts`` key appears anywhere (or the body nests too deep)."""
    if depth > MAX_DEPTH:
        return True
    if isinstance(value, dict):
        return "parts" in value or any(_has_parts(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return any(_has_parts(v, depth + 1) for v in value)
    return False


NONE: frozenset[str] = frozenset[str]()


def _only(body: dict[str, Any], required: frozenset[str], optional: frozenset[str] = NONE) -> bool:
    return required <= body.keys() <= required | optional


def _empty(body: dict[str, Any]) -> bool:
    return body == {}


def _close(body: dict[str, Any]) -> bool:
    return _only(body, NONE, frozenset({"reason"})) and _str(
        body.get("reason", ""), MAX_REASON, empty=True
    )


def _floor(body: dict[str, Any]) -> bool:
    holder = body.get("holder")
    return _only(body, frozenset({"holder"})) and (holder is None or _identity(holder))


def _pause(body: dict[str, Any]) -> bool:
    return _only(body, frozenset({"reason"})) and body["reason"] in PAUSE_REASONS


def _capabilities(body: dict[str, Any]) -> bool:
    adapters, accepts = body.get("adapters"), body.get("accepts")
    return (
        _only(body, frozenset({"adapters", "accepts"}))
        and isinstance(adapters, list)
        and len(adapters) <= MAX_ADAPTERS
        and all(_str(a, 64) for a in adapters)
        and isinstance(accepts, list)
        and all(isinstance(a, str) and a in ACCEPTS for a in accepts)
        and len(set(accepts)) == len(accepts)
    )


def _card(body: dict[str, Any]) -> bool:
    return body.keys() <= CARD_FIELDS and _str(body.get("name"), MAX_NAME) and not _has_parts(body)


def _cancel(body: dict[str, Any]) -> bool:
    return body.keys() <= CANCEL_FIELDS and _str(body.get("id"), MAX_ID) and not _has_parts(body)


SCHEMAS: dict[str, Callable[[dict[str, Any]], bool]] = {
    "control.leave": _empty,
    "control.resume": _empty,
    "control.close": _close,
    "control.floor": _floor,
    "control.pause": _pause,
    "control.capabilities": _capabilities,
    "a2a.agent_card": _card,
    "a2a.task_cancel": _cancel,
}
# Kinds that never trigger an agent and are never surfaced as text.
NON_CONTENT_KINDS = frozenset(SCHEMAS) - {"a2a.task_cancel"}


def schema_ok(kind: str, body: dict[str, Any]) -> bool:
    """Whether ``body`` fits ``kind``'s schema (content kinds always do here;
    their parts are checked by :func:`agentconnect.limits.content_problem`)."""
    check = SCHEMAS.get(kind)
    return check is None or check(body)
