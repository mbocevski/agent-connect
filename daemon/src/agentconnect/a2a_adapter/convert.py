"""Conversions between inner-message bodies (A2A v1.0 JSON, SPEC §7.2) and
the ``a2a-sdk`` protobuf types.

Bodies are peer-controlled. Parsing ignores unknown fields and never raises:
a body that isn't a valid A2A ``Message`` becomes a message carrying its
``text`` (or the whole body as a ``data`` part), so a peer can't crash the
adapter with a malformed body.
"""

from __future__ import annotations

from typing import Any

from a2a.types import (
    AgentCard,
    CancelTaskRequest,
    Message,
    Part,
    Role,
    StreamResponse,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatusUpdateEvent,
)
from google.protobuf.json_format import MessageToDict, ParseDict, ParseError
from google.protobuf.message import Message as ProtoMessage

TERMINAL = frozenset(
    {
        TaskState.TASK_STATE_COMPLETED,
        TaskState.TASK_STATE_FAILED,
        TaskState.TASK_STATE_CANCELED,
        TaskState.TASK_STATE_REJECTED,
    }
)
INTERRUPTED = frozenset({TaskState.TASK_STATE_INPUT_REQUIRED, TaskState.TASK_STATE_AUTH_REQUIRED})


def to_json(msg: ProtoMessage) -> dict[str, Any]:
    """The A2A v1.0 JSON form (camelCase) of a protobuf message."""
    return MessageToDict(msg)


def _parse[T: ProtoMessage](body: Any, into: T) -> T | None:
    if not isinstance(body, dict):
        return None
    try:
        ParseDict(body, into, ignore_unknown_fields=True)
    except (ParseError, TypeError, ValueError, RecursionError):
        return None
    return into


def parse_message(body: dict[str, Any]) -> Message:
    """A peer's ``a2a.message`` body as an A2A ``Message`` (never raises)."""
    msg = _parse(body, Message())
    if msg is not None and len(msg.parts) > 0:
        return msg
    out = Message() if msg is None else msg
    text = body.get("text")
    if isinstance(text, str):
        out.parts.append(Part(text=text))
        return out
    fallback = _parse({"parts": [{"data": body}]}, Message())
    if fallback is not None:
        out.parts.extend(fallback.parts)
    return out


def parse_status(body: dict[str, Any]) -> TaskStatusUpdateEvent | None:
    return _parse(body, TaskStatusUpdateEvent())


def parse_artifact(body: dict[str, Any]) -> TaskArtifactUpdateEvent | None:
    return _parse(body, TaskArtifactUpdateEvent())


def parse_card(body: dict[str, Any]) -> AgentCard | None:
    return _parse(body, AgentCard())


def stream_to_inner(resp: StreamResponse, group_id: str) -> list[tuple[str, dict[str, Any]]]:
    """What one event from the local agent becomes in the group: a list of
    ``(kind, body)``. ``contextId`` is always the group (SPEC §7.2)."""
    out: list[tuple[str, dict[str, Any]]] = []
    payload = resp.WhichOneof("payload")
    if payload == "task":
        task = resp.task
        status = TaskStatusUpdateEvent(task_id=task.id, context_id=group_id)
        status.status.CopyFrom(task.status)
        out.append(("a2a.task_status", to_json(status)))
        for artifact in task.artifacts:
            event = TaskArtifactUpdateEvent(task_id=task.id, context_id=group_id)
            event.artifact.CopyFrom(artifact)
            out.append(("a2a.task_artifact", to_json(event)))
    elif payload == "status_update":
        event = TaskStatusUpdateEvent()
        event.CopyFrom(resp.status_update)
        event.context_id = group_id
        out.append(("a2a.task_status", to_json(event)))
    elif payload == "artifact_update":
        event = TaskArtifactUpdateEvent()
        event.CopyFrom(resp.artifact_update)
        event.context_id = group_id
        out.append(("a2a.task_artifact", to_json(event)))
    elif payload == "message":
        msg = Message()
        msg.CopyFrom(resp.message)
        msg.context_id = group_id
        out.append(("a2a.message", to_json(msg)))
    return out


def task_id_of(resp: StreamResponse) -> str:
    payload = resp.WhichOneof("payload")
    if payload == "task":
        return resp.task.id
    if payload == "status_update":
        return resp.status_update.task_id
    if payload == "artifact_update":
        return resp.artifact_update.task_id
    return ""


def is_final(resp: StreamResponse) -> bool:
    """Whether the stream has nothing more for this call."""
    payload = resp.WhichOneof("payload")
    if payload == "message":
        return True
    if payload == "task":
        return resp.task.status.state in TERMINAL | INTERRUPTED
    if payload == "status_update":
        return resp.status_update.status.state in TERMINAL | INTERRUPTED
    return False


def cancel_body(task_id: str) -> dict[str, Any]:
    """The ``a2a.task_cancel`` body (an A2A ``CancelTaskRequest``, SPEC 7.2)
    a requester sends to cancel a bridged task."""
    return to_json(CancelTaskRequest(id=task_id))


def parse_cancel(body: dict[str, Any]) -> CancelTaskRequest | None:
    request = _parse(body, CancelTaskRequest())
    return request if request is not None and request.id else None


def agent_text(text: str, group_id: str) -> Message:
    return Message(role=Role.ROLE_AGENT, parts=[Part(text=text)], context_id=group_id)
