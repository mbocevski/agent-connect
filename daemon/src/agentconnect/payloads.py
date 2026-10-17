"""The JSON shape the webhook and SSE adapters hand to headless agents.

One shape for both transports, so the SDK parses one thing. A message::

    {"event": "message" | "task_status" | "task_artifact" | "task_cancel" |
              "agent_card" | "control.<name>",
     "msg_id": ..., "group": {id, name, purpose, epoch, floor},
     "sender": {identity, instance_id, display_name, verified},
     "to": [...], "addressed_to_me": bool, "scope": <group purpose>,
     "untrusted": true, "trust_state": {...},
     "origin": "agent" | "human", "hop": n, "reply_to": [...],
     "addressee": [...],             # when the sender named it (SPEC 9.3)
     "a2a": <the inner body>}

A daemon event (``member_joined``, ``epoch_changed``, ``loop_guard``, ...)::

    {"event": <type>, "event_id": ..., "group": {...} | null,
     "untrusted": true, "data": {...}}

``msg_id`` and ``event_id`` are idempotency keys: the transports deliver at
least once, so a receiver must treat a repeated id as already handled. Event
data can carry peer-chosen text (display names), so it is marked untrusted
like message bodies (SPEC section 10.1).
"""

from __future__ import annotations

import json
from typing import Any

from agentconnect.adapter import Delivery, Event, GroupView

MESSAGE_EVENTS = {
    "a2a.message": "message",
    "a2a.task_status": "task_status",
    "a2a.task_artifact": "task_artifact",
    "a2a.task_cancel": "task_cancel",
    "a2a.agent_card": "agent_card",
}


def group_json(group: GroupView | None) -> dict[str, Any] | None:
    if group is None:
        return None
    return {
        "id": group.group_id,
        "name": group.name,
        "purpose": group.purpose,
        "epoch": group.epoch,
        "floor": group.floor,
    }


def event_name(kind: str) -> str:
    """The webhook ``event`` for a message kind (control kinds keep theirs)."""
    return MESSAGE_EVENTS.get(kind, kind)


def message_payload(group: GroupView, delivery: Delivery) -> dict[str, Any]:
    sender = delivery.sender
    out: dict[str, Any] = {
        "event": event_name(delivery.kind),
        "msg_id": delivery.msg_id,
        "group": group_json(group),
        "sender": {
            "identity": sender.identity,
            "instance_id": sender.instance_id,
            "display_name": sender.display_name,
            "verified": sender.verified,
        },
        "to": list(delivery.to),
        "addressed_to_me": delivery.addressed_to_me,
        "scope": delivery.scope,
        "untrusted": True,
        "trust_state": delivery.trust_state,
        "origin": delivery.origin,
        "hop": delivery.hop,
        "a2a": delivery.body,
    }
    refs = delivery.inner.get("reply_to")
    if isinstance(refs, list):
        out["reply_to"] = [str(r) for r in refs]
    addressee = delivery.inner.get("addressee")
    if isinstance(addressee, list):
        out["addressee"] = [str(a) for a in addressee]
    return out


def event_payload(group: GroupView | None, event: Event) -> dict[str, Any]:
    return {
        "event": event.type,
        "event_id": event.event_id,
        "group": group_json(group),
        "untrusted": True,
        "data": event.data,
    }


def encode(payload: dict[str, Any]) -> bytes:
    """The exact bytes that are signed and sent."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
