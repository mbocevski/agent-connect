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
* **Agent Cards are checked, never rewritten** (the listing limits of
  ADR-006, Decision 1): every known A2A v1.0 field is kept exactly as sent,
  so a signature over it still verifies; a string, list or object over its
  cap makes the card ``malformed`` instead of being cut. Unknown fields,
  which no A2A signature covers, are left out at every level.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Callable
from typing import Any

CONTENT_KINDS = frozenset({"a2a.message", "a2a.task_status", "a2a.task_artifact"})
CONTENT_MEMBERS = frozenset({"parts", "text", "data", "file", "raw"})
MAX_REASON = 200
MAX_ID = 256
# Floor epochs: what a signed 64-bit SQLite integer holds. Floor counters
# start again at each epoch, so no honest one comes near 2**32 (SPEC 9.3).
MAX_COUNTER = 2**63 - 1
MAX_FLOOR_COUNTER = 2**32
INSTANCE_ID = re.compile(r"[0-9a-f]{16}")
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
MAX_OBJECT_BYTES = 4096  # securitySchemes, securityRequirements, one signature
MAX_INTERFACES = 8
MAX_SIGNATURES = 4
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
    {
        "id",
        "name",
        "description",
        "tags",
        "examples",
        "inputModes",
        "outputModes",
        "securityRequirements",
    }
)
CAPABILITY_FIELDS = frozenset({"streaming", "pushNotifications", "extensions", "extendedAgentCard"})
EXTENSION_FIELDS = frozenset({"uri", "description", "required", "params"})
PROVIDER_FIELDS = frozenset({"organization", "url"})
INTERFACE_FIELDS = frozenset({"url", "protocolBinding", "protocolVersion", "tenant"})
SIGNATURE_FIELDS = frozenset({"protected", "signature", "header"})
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


def _identity(value: Any) -> str:
    if not (isinstance(value, str) and value.startswith("ac:v0:") and len(value) <= MAX_ID):
        raise MalformedError
    return value


def _counter(value: Any, most: int = MAX_COUNTER) -> int:
    """A floor counter (at most ``MAX_FLOOR_COUNTER``) or epoch (SPEC 9.3)."""
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= most:
        raise MalformedError
    return value


def _copy_key(copy: Any, counter: int) -> dict[str, Any]:
    """The key a copy names: a grant's (an identity and its instance) or a
    commit's reset (``""``, ``""``) or drop (``""``, the identity dropped),
    which have counter 0."""
    if not isinstance(copy, dict):
        raise MalformedError
    sender, instance = copy.get("sender"), copy.get("instance")
    if sender == "":
        if counter != 0 or not (instance == "" or _identity(instance)):
            raise MalformedError
    else:
        _identity(sender)
        if not (isinstance(instance, str) and INSTANCE_ID.fullmatch(instance)):
            raise MalformedError
    return {
        "epoch": _counter(copy.get("epoch")),
        "sender": sender,
        "instance": instance,
        "join": _counter(copy.get("join")),
        "seq": _counter(copy.get("seq"), MAX_FLOOR_COUNTER),
    }


def _floor(body: dict[str, Any]) -> dict[str, Any]:
    """``{holder, counter}``, and for the copy of the floor sent to members
    that join, ``copy: {epoch, sender, instance, join, seq}``: the key of the
    write copied, the epoch its recipients joined in and the copy's place
    among the copier's copies for that join (SPEC 9.3)."""
    holder = body.get("holder", ...)
    if holder is not None:
        holder = _identity(holder)
    counter = _counter(body.get("counter"), MAX_FLOOR_COUNTER)
    out: dict[str, Any] = {"holder": holder, "counter": counter}
    if "copy" in body:
        out["copy"] = _copy_key(body["copy"], counter)
    return out


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


def _capped(value: Any, longest: int) -> str:
    """A card string, kept exactly as sent (a signature covers it): over the
    cap it is refused, never cut. Control characters are cleaned only where
    it is shown (the CLI, the SPEC 10.1 notice)."""
    if not isinstance(value, str) or len(value) > longest:
        raise MalformedError
    return value


def _capped_list(value: Any, most: int, longest: int) -> list[str]:
    if not isinstance(value, list) or len(value) > most:
        raise MalformedError
    return [_capped(v, longest) for v in value]


def _known(value: Any, fields: frozenset[str]) -> dict[str, Any]:
    """An object with its known fields only: an unknown field is no field of
    the A2A object, so no signature covers it, and no free-text channel."""
    if not isinstance(value, dict):
        raise MalformedError
    return {k: v for k, v in value.items() if k in fields}


def _skill(skill: Any) -> dict[str, Any]:
    out = _known(skill, SKILL_FIELDS)
    out["id"] = _capped(out.get("id"), MAX_SKILL_NAME)
    for key, longest in (("name", MAX_SKILL_NAME), ("description", MAX_CARD_DESCRIPTION)):
        if key in out:
            out[key] = _capped(out[key], longest)
    if "tags" in out:
        out["tags"] = _capped_list(out["tags"], MAX_TAGS, MAX_TAG)
    if "examples" in out:
        out["examples"] = _capped_list(out["examples"], MAX_EXAMPLES, MAX_EXAMPLE)
    for key in ("inputModes", "outputModes"):
        if key in out:
            out[key] = _capped_list(out[key], MAX_MODES, MAX_MODE)
    if "securityRequirements" in out:
        out["securityRequirements"] = _small(out["securityRequirements"], MAX_OBJECT_BYTES)
    return out


def _extension(ext: Any) -> dict[str, Any]:
    out = _known(ext, EXTENSION_FIELDS)
    out["uri"] = _capped(out.get("uri"), MAX_URI)
    if "description" in out:
        out["description"] = _capped(out["description"], MAX_CARD_DESCRIPTION)
    if "required" in out and not isinstance(out["required"], bool):
        raise MalformedError
    if "params" in out:
        if not isinstance(out["params"], dict):
            raise MalformedError
        out["params"] = _small(out["params"], MAX_PARAMS_BYTES)
    return out


def _card_capabilities(caps: Any) -> dict[str, Any]:
    out = _known(caps, CAPABILITY_FIELDS)
    for key in ("streaming", "pushNotifications", "extendedAgentCard"):
        if key in out and not isinstance(out[key], bool):
            raise MalformedError
    if "extensions" in out:
        if not isinstance(out["extensions"], list) or len(out["extensions"]) > MAX_EXTENSIONS:
            raise MalformedError
        out["extensions"] = [_extension(e) for e in out["extensions"]]
    return out


def _interface(interface: Any) -> dict[str, Any]:
    out = _known(interface, INTERFACE_FIELDS)
    for key in INTERFACE_FIELDS & out.keys():
        out[key] = _capped(out[key], MAX_URI)
    return out


def _card(body: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
    """A card in its A2A v1.0 shape, every known field as sent, or refused.
    Unknown fields are left out, at the top level and in the nested objects."""
    out = _known(body, CARD_FIELDS)
    out["name"] = _capped(out.get("name"), MAX_CARD_NAME)
    if not out["name"].strip():
        raise MalformedError
    for key, longest in (
        ("description", MAX_CARD_DESCRIPTION),
        ("version", MAX_CARD_VERSION),
        ("documentationUrl", MAX_URI),
        ("iconUrl", MAX_URI),
    ):
        if key in out:
            out[key] = _capped(out[key], longest)
    if "skills" in out:
        if not isinstance(out["skills"], list) or len(out["skills"]) > MAX_SKILLS:
            raise MalformedError
        out["skills"] = [_skill(s) for s in out["skills"]]
    for key in ("defaultInputModes", "defaultOutputModes"):
        if key in out:
            out[key] = _capped_list(out[key], MAX_MODES, MAX_MODE)
    if "capabilities" in out:
        out["capabilities"] = _card_capabilities(out["capabilities"])
    if "provider" in out:
        provider = _known(out["provider"], PROVIDER_FIELDS)
        out["provider"] = {k: _capped(v, MAX_URI) for k, v in provider.items()}
    if "supportedInterfaces" in out:
        interfaces = out["supportedInterfaces"]
        if not isinstance(interfaces, list) or len(interfaces) > MAX_INTERFACES:
            raise MalformedError
        out["supportedInterfaces"] = [_interface(i) for i in interfaces]
    if "signatures" in out:
        signatures = out["signatures"]
        if not isinstance(signatures, list) or len(signatures) > MAX_SIGNATURES:
            raise MalformedError
        out["signatures"] = [
            _small(_known(s, SIGNATURE_FIELDS), MAX_OBJECT_BYTES) for s in signatures
        ]
    for key in ("securitySchemes", "securityRequirements"):
        if key in out:
            out[key] = _small(out[key], MAX_OBJECT_BYTES)
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
