"""Schemas for the kinds that carry no content: the controls (SPEC §7.3),
Agent Cards (§10.5) and task cancellations (§7.2).

Only ``a2a.message``, ``a2a.task_status`` and ``a2a.task_artifact`` carry
A2A parts. Every other kind has a known shape, and :func:`normalize` keeps
only that shape:

* **Unknown fields are stripped** (SPEC §7.2, forward compatibility): a
  newer peer's extra field is never shown to the agent, and never counts
  against the peer.
* **Content is refused.** A ``parts`` list anywhere in the body, or a
  top-level content member (``text``, ``data``, ``file``, ``raw``) that the
  kind doesn't define, makes the message ``malformed``: a member can't
  smuggle text, data or files to an agent (or past ``require_approval``)
  under a kind that is never held as content and never shown as text. So
  does a known field of the wrong type.
* **Agent Card text is capped** (the listing limits of ADR-006, Decision 1):
  strings are cut and cleaned of control characters, lists are cut, and an
  extension's ``params`` larger than :data:`MAX_PARAMS_BYTES` is refused. A
  card that changed this way no longer verifies against a signature.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Callable
from typing import Any

CONTENT_KINDS = frozenset({"a2a.message", "a2a.task_status", "a2a.task_artifact"})
CONTENT_MEMBERS = frozenset({"parts", "text", "data", "file", "raw"})
MAX_REASON = 200
MAX_ID = 256
MAX_WORD = 64  # a pause reason, an adapter name, an accepted part kind
MAX_ADAPTERS = 16
MAX_DEPTH = 32
# ADR-006, Decision 1: the listing caps, applied to every card.
MAX_CARD_NAME = 80
MAX_CARD_DESCRIPTION = 500
MAX_CARD_VERSION = 32
MAX_SKILLS = 16
MAX_SKILL_NAME = 80
MAX_TAGS = 8
MAX_TAG = 32
MAX_EXAMPLES = 4
MAX_EXAMPLE = 200
MAX_MODES = 8
MAX_MODE = 128
MAX_EXTENSIONS = 8
MAX_URI = 512
MAX_PARAMS_BYTES = 4096
MAX_CARD_BYTES = 32 * 1024
MAX_METADATA_BYTES = 4096
# The A2A v1.0 AgentCard, AgentSkill and CancelTaskRequest fields (JSON names).
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
SKILL_FIELDS = frozenset(
    {"id", "name", "description", "tags", "examples", "inputModes", "outputModes"}
)
CANCEL_FIELDS = frozenset({"id", "metadata", "tenant"})


class MalformedError(ValueError):
    """The body doesn't fit its kind's schema."""


def _has_parts(value: Any, depth: int = 0) -> bool:
    """Whether a ``parts`` key appears anywhere (or the body nests too deep)."""
    if depth > MAX_DEPTH:
        return True
    if isinstance(value, dict):
        return "parts" in value or any(_has_parts(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return any(_has_parts(v, depth + 1) for v in value)
    return False


def _text(value: Any, longest: int) -> str:
    """A string field: control characters become spaces, cut to ``longest``."""
    if not isinstance(value, str):
        raise MalformedError
    flat = "".join(" " if unicodedata.category(c) == "Cc" else c for c in str(value))
    return flat[:longest]


def _word(value: Any, longest: int = MAX_WORD) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= longest:
        raise MalformedError
    return value


def _words(value: Any, most: int, longest: int) -> list[str]:
    if not isinstance(value, list):
        raise MalformedError
    return [_text(v, longest) for v in value[:most]]


def _small(value: Any, most: int) -> Any:
    """A JSON value of at most ``most`` bytes, kept as it is."""
    if len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()) > most:
        raise MalformedError
    return value


def _empty(_body: dict[str, Any]) -> dict[str, Any]:
    return {}


def _close(body: dict[str, Any]) -> dict[str, Any]:
    return {"reason": _text(body["reason"], MAX_REASON)} if "reason" in body else {}


def _floor(body: dict[str, Any]) -> dict[str, Any]:
    holder = body.get("holder", ...)
    if holder is not None and not (
        isinstance(holder, str) and holder.startswith("ac:v0:") and len(holder) <= MAX_ID
    ):
        raise MalformedError
    return {"holder": holder}


def _pause(body: dict[str, Any]) -> dict[str, Any]:
    # Any reason is kept (a newer peer may have new ones); it is a word.
    return {"reason": _word(body.get("reason"))}


def _capabilities(body: dict[str, Any]) -> dict[str, Any]:
    adapters, accepts = body.get("adapters"), body.get("accepts")
    if not isinstance(adapters, list) or not isinstance(accepts, list):
        raise MalformedError
    return {
        "adapters": [_word(a) for a in adapters[:MAX_ADAPTERS]],
        "accepts": [_word(a) for a in accepts[:MAX_ADAPTERS]],
    }


def _skill(skill: Any) -> dict[str, Any]:
    if not isinstance(skill, dict):
        raise MalformedError
    out: dict[str, Any] = {"id": _text(skill.get("id"), MAX_SKILL_NAME)}
    for key, longest in (("name", MAX_SKILL_NAME), ("description", MAX_CARD_DESCRIPTION)):
        if key in skill:
            out[key] = _text(skill[key], longest)
    if "tags" in skill:
        out["tags"] = _words(skill["tags"], MAX_TAGS, MAX_TAG)
    if "examples" in skill:
        out["examples"] = _words(skill["examples"], MAX_EXAMPLES, MAX_EXAMPLE)
    for key in ("inputModes", "outputModes"):
        if key in skill:
            out[key] = _words(skill[key], MAX_MODES, MAX_MODE)
    return out


def _extension(ext: Any) -> dict[str, Any]:
    if not isinstance(ext, dict):
        raise MalformedError
    out: dict[str, Any] = {"uri": _text(ext.get("uri"), MAX_URI)}
    if "description" in ext:
        out["description"] = _text(ext["description"], MAX_CARD_DESCRIPTION)
    if "required" in ext:
        out["required"] = bool(ext["required"])
    if "params" in ext:
        if not isinstance(ext["params"], dict):
            raise MalformedError
        out["params"] = _small(ext["params"], MAX_PARAMS_BYTES)
    return out


def _card(body: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {k: v for k, v in body.items() if k in CARD_FIELDS}
    out["name"] = _text(body.get("name"), MAX_CARD_NAME)
    if not out["name"].strip():
        raise MalformedError
    if "description" in out:
        out["description"] = _text(out["description"], MAX_CARD_DESCRIPTION)
    if "version" in out:
        out["version"] = _text(out["version"], MAX_CARD_VERSION)
    if "skills" in out:
        if not isinstance(out["skills"], list):
            raise MalformedError
        out["skills"] = [_skill(s) for s in out["skills"][:MAX_SKILLS]]
    for key in ("defaultInputModes", "defaultOutputModes"):
        if key in out:
            out[key] = _words(out[key], MAX_MODES, MAX_MODE)
    caps = out.get("capabilities")
    if caps is not None:
        if not isinstance(caps, dict):
            raise MalformedError
        caps = dict(caps)
        if "extensions" in caps:
            if not isinstance(caps["extensions"], list):
                raise MalformedError
            caps["extensions"] = [_extension(e) for e in caps["extensions"][:MAX_EXTENSIONS]]
        out["capabilities"] = caps
    return _small(out, MAX_CARD_BYTES)


def _cancel(body: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"id": _word(body.get("id"), MAX_ID)}
    if "tenant" in body:
        out["tenant"] = _word(body["tenant"], MAX_ID)
    if "metadata" in body:
        if not isinstance(body["metadata"], dict):
            raise MalformedError
        out["metadata"] = _small(body["metadata"], MAX_METADATA_BYTES)
    return out


SCHEMAS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
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


def normalize(kind: str, body: dict[str, Any]) -> dict[str, Any] | None:
    """``body`` as its kind's schema keeps it (unknown fields stripped, card
    text capped), or ``None`` when it is malformed: it carries content, or a
    known field has the wrong type. Content kinds come back unchanged (their
    parts are checked by :func:`agentconnect.limits.content_problem`)."""
    shape = SCHEMAS.get(kind)
    if shape is None:
        return body
    if _has_parts(body) or (body.keys() & CONTENT_MEMBERS):
        return None
    try:
        return shape(body)
    except (MalformedError, KeyError):
        return None


def schema_ok(kind: str, body: dict[str, Any]) -> bool:
    """Whether ``body`` fits ``kind``'s schema (see :func:`normalize`)."""
    return normalize(kind, body) is not None
