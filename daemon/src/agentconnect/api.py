"""The local control API: small JSON over HTTP/1.1.

Transport: a Unix socket in the data directory (mode 0600) by default, or
``127.0.0.1:<port>`` when configured. The server is a minimal asyncio
HTTP/1.1 implementation (one request per connection, ``Content-Length``
bodies only, 1 MiB cap), so the daemon needs no web framework.

Authentication: ``Authorization: Bearer <token>``. There are two tokens,
each in a 0600 file in the data directory:

* ``api-token`` (scope ``agent``): everything an agent integration may do;
* ``human-token`` (scope ``human``): additionally approving JoinRequests
  and held messages, marking members verified, removing members, and
  changing or reading the group's safety policy, audit log and transcript.

Approval and verification are human decisions (SPEC §6.2, §11). An agent
that could approve joins or mark the SAS as compared would defeat both
checks, so those endpoints refuse the agent token. Hand only ``api-token``
to agent tooling. (Both files are readable by the same OS user; the split
keeps agent integrations from holding the human capability by default, it is
not a sandbox.)

Separate-OS-user mode (:mod:`agentconnect.isolation`): the socket is opened
to an agent group, every connection's peer UID is checked against an
allowlist, and the human token is accepted only from the daemon's own UID or
a configured human UID.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import re
import secrets
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentconnect import log
from agentconnect.cli_json import HELD
from agentconnect.daemon import HUMAN_EVENTS, HUMAN_ONLY_KINDS, Daemon, DaemonError, new_msg_id
from agentconnect.isolation import PeerGate
from agentconnect.keystore import write_private
from agentconnect.relay import RelayError
from agentconnect.shapes import Opt
from agentconnect.sse import SseAdapter, Subscription

LOG = log.get("agentconnect.api")

MAX_BODY = 1 << 20
MAX_HEADER = 16 << 10
READ_TIMEOUT = 10.0  # seconds to send a whole request
MAX_CONNECTIONS = 64
API_TOKEN_FILE = "api-token"  # noqa: S105 - a file name
HUMAN_TOKEN_FILE = "human-token"  # noqa: S105 - a file name
SCOPE = "_scope"  # handler parameter carrying the request's token scope
ACCEPT = "_accept"  # ... the Accept header
LAST_EVENT_ID = "_last_event_id"  # ... the Last-Event-ID header

STATUS_TEXT = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    408: "Request Timeout",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    413: "Payload Too Large",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}
ERROR_STATUS = {
    "bad_request": 400,
    "wrong_relay": 400,
    "forbidden": 403,
    "not_found": 404,
    "expired": 409,
    "stale_epoch": 409,
    "invite_not_open": 409,
    "too_large": 413,
    "rate_limited": 429,
    "relay": 502,
}


async def _close(writer: asyncio.StreamWriter) -> None:
    """Close and wait, so no transport outlives the server that made it."""
    writer.close()
    with contextlib.suppress(ConnectionError, OSError):
        await writer.wait_closed()


class SseStream:
    """A handler result that keeps the connection open and writes SSE frames
    until the client goes away (``text/event-stream``, see :mod:`sse`)."""

    def __init__(self, hub: SseAdapter, sub: Subscription) -> None:
        self.hub, self.sub = hub, sub
        self._stop = asyncio.Event()

    def stop(self) -> None:
        """End the stream (the daemon is shutting down)."""
        self._stop.set()

    async def run(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
            b"cache-control: no-cache\r\nconnection: close\r\n\r\n: connected\n\n"
        )
        gone = asyncio.ensure_future(reader.read(1))  # EOF: the client left
        stopped = asyncio.ensure_future(self._stop.wait())
        try:
            await writer.drain()
            while not gone.done() and not stopped.done():
                if self.sub.overflowed and self.sub.queue.empty():
                    break  # too slow: the client resumes with Last-Event-ID
                get = asyncio.ensure_future(self.sub.queue.get())
                await asyncio.wait({get, gone, stopped}, return_when=asyncio.FIRST_COMPLETED)
                if not get.done():
                    get.cancel()
                    break
                writer.write(get.result().frame())
                await writer.drain()
        except ConnectionError:
            pass
        finally:
            self.hub.unsubscribe(self.sub)
            gone.cancel()
            stopped.cancel()
            await _close(writer)


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code = status, code


def load_token(path: Path) -> str:
    """Read the token at ``path``, creating it (0600) if missing. An existing
    token file must be ours and private (no group or other bits)."""
    if path.exists():
        st = path.stat()
        if st.st_mode & 0o077 or st.st_uid != os.geteuid():
            msg = f"{path.name} must be owned by this user with mode 0600"
            raise PermissionError(msg)
        return path.read_text(encoding="ascii").strip()
    token = secrets.token_urlsafe(32)
    write_private(path, token.encode("ascii"))
    return token


Handler = Callable[[dict[str, str], dict[str, Any]], Awaitable[Any]]


class Route:
    def __init__(self, method: str, pattern: str, handler: Handler, human: bool = False) -> None:
        self.method = method
        self.regex = re.compile(
            "^" + re.sub(r"{(\w+)}", r"(?P<\1>[A-Za-z0-9_:.-]+)", pattern) + "$"
        )
        self.handler = handler
        self.human = human


@dataclass(frozen=True)
class RouteSpec:
    """One route: where it is served, who may call it and what it takes and
    returns. The table below is the only place routes are declared; the server
    is built from it and ``docs/api.md`` is generated from it
    (``scripts/gen_reference.py``)."""

    method: str
    path: str  # `{name}` segments become handler parameters
    handler: str  # name of the ApiServer method that serves it
    summary: str
    request: Any = None  # shape of the JSON body (None: no body); see shapes.py
    response: Any = None  # shape of the JSON answer
    query: str = ""  # query parameters, described in words
    human: bool = False  # True: the human token only


_GROUP_INFO: dict[str, Any] = {
    "group_id": "str",
    "name": "str",
    "purpose": "str",
    "status": "str",
    "epoch": "int",
    "policy": "object",
    "out_of_sync": "bool",
    "out_of_sync_reason": Opt("str"),
    "adapter": "str",
    "trust_state": {"self": "str", "verified_members": "int", "members": "int"},
    "members": [
        {
            "identity": "str",
            "fingerprint": "str",
            "display_name": Opt("str"),
            "display_name_verified": "bool",
            "role": "str",
            "verified": "bool",
            "instances": ["object"],
            "self": "bool",
        }
    ],
    "agent_cards": "object",
    "sas?": {"decimal": "str", "emoji_indices": ["int"]},
}

_HELD: dict[str, Any] = HELD

_SAFETY: dict[str, Any] = {"group_id": "str", "settings": "object", "overrides": "object"}

ROUTE_SPECS: tuple[RouteSpec, ...] = (
    RouteSpec(
        "GET",
        "/v0/status",
        "_status",
        "Daemon status: identity, relay connection, queue sizes.",
        response={
            "identity": "str",
            "fingerprint": "str",
            "instance_id": "str",
            "mailbox_id": "str",
            "relay": {"url": "str", "connected": "bool"},
            "keystore": "str",
            "groups": "int",
            "out_of_sync": ["str"],
            "outbox_queued": "int",
            "inbox_pending": "int",
            "pending_approvals": "int",
            "held_messages": "int",
        },
    ),
    RouteSpec(
        "GET",
        "/v0/groups",
        "_list_groups",
        "List groups.",
        response={
            "groups": [
                {
                    "group_id": "str",
                    "name": "str",
                    "status": "str",
                    "epoch": "int",
                    "members": "int",
                    "out_of_sync": "bool",
                }
            ]
        },
    ),
    RouteSpec(
        "POST",
        "/v0/groups",
        "_create_group",
        "Create a group you own.",
        request={"name": "str", "purpose?": "str"},
        response={"group_id": "str"},
    ),
    RouteSpec(
        "GET",
        "/v0/groups/{gid}",
        "_group_info",
        "One group: members, roles, verified flags, short code, `out_of_sync` and "
        "the peers' Agent Cards (each wrapped as `untrusted`).",
        response=_GROUP_INFO,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/invites",
        "_create_invite",
        "Create an invite. `ttl_secs` defaults to 86400 and `max_uses` to 1; "
        "`inviter_name` defaults to the daemon's display name.",
        request={"ttl_secs?": "int", "max_uses?": "int", "inviter_name?": "str"},
        response={"url": "str", "invite_id": "str", "expires_at": "int"},
    ),
    RouteSpec(
        "DELETE",
        "/v0/invites/{invite_id}",
        "_revoke",
        "Revoke an invite you created.",
        response={"revoked": "str"},
    ),
    RouteSpec(
        "POST",
        "/v0/invites/inspect",
        "_inspect",
        "Parse an invite URL locally and return its public metadata. Nothing is "
        "sent to the relay. The metadata is claimed by the link, so it is "
        "marked `untrusted`. An invite whose relay host is not this daemon's "
        "relay is refused with `400 wrong_relay` before anything is fetched "
        "(SPEC 4.4).",
        request={"url": "str"},
        response={"meta": "object", "warning": Opt("str"), "untrusted": "bool"},
    ),
    RouteSpec(
        "POST",
        "/v0/invites/accept",
        "_accept",
        "Send the join request for an invite URL. The inviter's human must approve it. "
        "An invite for another relay is refused with `400 wrong_relay`, as by "
        "`/v0/invites/inspect`.",
        request={"url": "str", "display_name?": Opt("str")},
        response={"invite_id": "str", "status": "str", "meta": "object"},
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/policy",
        "_policy",
        "Set the group policy. Turning `require_verified` on is allowed with "
        "either token; turning it off needs the human token (SPEC 10.4).",
        request={"require_verified": "bool"},
        response={"require_verified": "bool"},
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/messages",
        "_send",
        "Send a message. Give `text` (sent as an A2A v1.0 `Message` with a `messageId`, "
        "`contextId`, `role` and one text part), or a full `body` object. `to` defaults to "
        '`["*"]` (everyone) and `kind` to `a2a.message`. `reply_to` lists the '
        "`msg_id`s answered (SPEC 10.3). `addressee` names exactly who is triggered "
        '(SPEC 9.3); task replies go to `["*"]` with the requester as `addressee`. '
        "The agent token sends as the agent and "
        "the human token as the human; kinds reserved to humans (such as "
        "`control.resume`) need the human token (SPEC 7.3). `status` is `queued`, or "
        "`held` when the group's `require_approval` holds the agent's message for the "
        "human (see [safety.md](safety.md#approvals)).",
        request={
            "text?": "str",
            "body?": "object",
            "to?": ["str"],
            "kind?": "str",
            "reply_to?": ["str"],
            "addressee?": ["str"],
        },
        response={"msg_id": "str", "status": "str"},
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/leave",
        "_leave",
        "Leave a group. The owner's last instance must hand over ownership first.",
        response={"status": "str"},
    ),
    RouteSpec(
        "GET",
        "/v0/approvals",
        "_list_approvals",
        "Pending join requests, with the joiner's fingerprint, and the messages the "
        "safety policy holds for approval (`messages`, metadata only).",
        response={
            "approvals": [
                {
                    "request_id": "str",
                    "group_id": "str",
                    "identity": "str",
                    "display_name": "str",
                    "received_at": "int",
                    "display_name_verified": "bool",
                    "fingerprint": "str",
                }
            ],
            "messages": [_HELD],
        },
    ),
    RouteSpec(
        "GET",
        "/v0/approvals/messages/{hid}",
        "_held_message",
        "One held message with its content, for the human to decide on. A message "
        "from a peer is `untrusted`.",
        response={
            **_HELD,
            "untrusted": "bool",
            "to": Opt(["str"]),
            "addressee": Opt(["str"]),
            "reply_to": Opt(["str"]),
            "body": "object",
        },
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/approvals/messages/{hid}/approve",
        "_approve_message",
        "Release a held message: to the adapter (inbound) or to the group (outbound).",
        response={"hold_id": "str", "group_id": "str", "status": "str"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/approvals/messages/{hid}/reject",
        "_reject_message",
        "Drop a held message. The peer is not told; a rejected send raises `send_failed`.",
        response={"hold_id": "str", "group_id": "str", "status": "str"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/approvals/{rid}/approve",
        "_approve",
        "Approve a join request.",
        response={"status": "str"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/approvals/{rid}/reject",
        "_reject",
        "Reject a join request.",
        response={"status": "str"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/members/{identity}/verify",
        "_verify",
        "Mark a member verified (the human compared the short code). `verified` "
        "defaults to `true`.",
        request={"verified?": "bool"},
        response={"verified": "bool"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/members/{identity}/remove",
        "_remove",
        "Remove a member, every instance of it (an MLS commit; the group policy decides "
        "whether this instance may). For a member the safety policy reported with "
        "`repeated_violations`; the daemon never removes anyone on its own.",
        response={"status": "str"},
        human=True,
    ),
    RouteSpec(
        "GET",
        "/v0/groups/{gid}/safety",
        "_safety",
        "The group's safety policy: the effective `settings` (with per-sender "
        "`senders` overrides) and the group's own `overrides` of the defaults in "
        "`[policy]`.",
        response=_SAFETY,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/safety",
        "_set_safety",
        "Change the group's safety policy. `set` maps setting names to values; "
        "`null` clears the group's override. With `sender`, the changes apply to "
        "that member only (limits only). See [safety.md](safety.md#settings).",
        request={"set": "object", "sender?": "str"},
        response=_SAFETY,
        human=True,
    ),
    RouteSpec(
        "GET",
        "/v0/audit",
        "_audit",
        "The audit log, oldest first, at most 200 rows per call: who, when, kind, size "
        "and the policy's decision for every message in and out. Never a body.",
        query="`after`: only rows with a greater `seq` (default 0). `group`: only that group.",
        response={
            "audit": [
                {
                    "seq": "int",
                    "group_id": "str",
                    "at": "int",
                    "direction": "str",
                    "sender": "str",
                    "msg_id": "str",
                    "kind": "str",
                    "size": "int",
                    "decision": "str",
                    "reason": "str",
                }
            ]
        },
        human=True,
    ),
    RouteSpec(
        "GET",
        "/v0/groups/{gid}/transcript",
        "_transcript",
        "The group's transcript, when its `transcript` setting is on: every message "
        "delivered or sent, in full, at most 200 per call. Peer messages are untrusted.",
        query="`after`: only entries with a greater `seq` (default 0).",
        response={
            "transcript": [
                {
                    "seq": "int",
                    "group_id": "str",
                    "at": "int",
                    "direction": "str",
                    "sender": "str",
                    "msg_id": "str",
                    "kind": "str",
                    "inner": "object",
                }
            ],
            "untrusted": "bool",
        },
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/sas/mismatch",
        "_sas_mismatch",
        "Report that the short codes differ. The daemon leaves the group "
        "(SPEC 11). `epoch` is the epoch the human compared.",
        request={"epoch?": Opt("int")},
        response={"status": "str"},
        human=True,
    ),
    RouteSpec(
        "GET",
        "/v0/events",
        "_events",
        "Daemon events in order, at most 200 per call. The agent token doesn't see the "
        "safety policy's events (`message_held`, `held_expired`, `repeated_violations`): "
        "they would tell the agent, and so a peer, what the policy did. With "
        "`Accept: text/event-stream` it is instead a Server-Sent Events stream "
        "of messages and events from a durable feed (needs "
        '`daemon.default_adapter = "sse"`, else `409 no_sse_adapter`): each '
        "frame has `id` (the feed sequence number), `event` and one line of "
        "JSON `data`, in the payload shape of the webhook adapter. Send "
        "`Last-Event-ID` to resume after that id, also after a daemon restart; "
        "without it the stream starts live.",
        query="`after`: only events with a greater `seq` (default 0). `group`: only "
        "that group (`404 not_found` on a stream for an unknown group).",
        response={
            "events": [
                {
                    "seq": "int",
                    "group_id": Opt("str"),
                    "type": "str",
                    "data": "object",
                    "at": "int",
                    "event_id": "str",
                }
            ]
        },
    ),
)

# Every error the server can answer with: status, code, meaning.
API_ERRORS: tuple[tuple[int, str, str], ...] = (
    (
        400,
        "bad_request",
        "Malformed request: the body is not a JSON object, or a field is missing "
        "or has the wrong type.",
    ),
    (
        400,
        "wrong_relay",
        "The invite is for a different relay than this daemon's (SPEC 4.4). Nothing "
        "was fetched or sent.",
    ),
    (401, "auth_failed", "The bearer token is missing or wrong."),
    (403, "human_only", "The operation needs the human token."),
    (
        403,
        "peer_refused",
        "Separate-OS-user mode: the caller's OS user may not use the socket, or may "
        "not use the human token (docs/isolation.md).",
    ),
    (
        403,
        "forbidden",
        "The daemon refused: the owner must hand over first, or a browser request "
        "reached the TCP listener.",
    ),
    (404, "not_found", "No such endpoint, group, invite or request."),
    (405, "method_not_allowed", "The path exists but not for this method."),
    (408, "timeout", "The request was not received within 10 seconds."),
    (409, "stale_epoch", "The group changed since the epoch you passed."),
    (409, "expired", "The invite or request has expired."),
    (409, "invite_not_open", "The invite was used up, revoked or never open."),
    (413, "too_large", "The headers or the body (over 1 MiB) are too large."),
    (429, "rate_limited", "Too many requests."),
    (500, "internal", "An unexpected failure; the daemon logs it."),
    (502, "relay", "The relay reported an error."),
    (503, "busy", "Too many open connections."),
)


def a2a_text(group_id: str, text: str, human: bool) -> dict[str, Any]:
    """The ``text`` shorthand as an A2A v1.0 ``Message`` (SPEC 7.2)."""
    return {
        "messageId": new_msg_id(),
        "contextId": group_id,
        "role": "ROLE_USER" if human else "ROLE_AGENT",
        "parts": [{"text": text}],
    }


def _str(body: dict[str, Any], key: str, default: str | None = None) -> str:
    value = body.get(key, default)
    if not isinstance(value, str):
        raise ApiError(400, "bad_request", f"{key} must be a string")
    return value


def _int(body: dict[str, Any], key: str, default: int) -> int:
    value = body.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ApiError(400, "bad_request", f"{key} must be an integer")
    return value


def _query_int(p: dict[str, str], key: str) -> int:
    raw = p.get(key, "0") or "0"
    if not raw.isdigit():
        raise ApiError(400, "bad_request", f"{key} must be a non-negative integer")
    return int(raw)


class ApiServer:
    """Serves the control API for one :class:`Daemon`."""

    def __init__(self, daemon: Daemon, gate: PeerGate | None = None) -> None:
        self.daemon = daemon
        # Peer-credential checks; a no-op unless isolation.enabled.
        self.gate = gate if gate is not None else PeerGate.from_config(daemon.config)
        data_dir = daemon.config.data_dir
        self.tokens = {
            "agent": load_token(data_dir / API_TOKEN_FILE),
            "human": load_token(data_dir / HUMAN_TOKEN_FILE),
        }
        self._server: asyncio.Server | None = None
        self._connections = 0
        self._streams: set[SseStream] = set()
        self._idle = asyncio.Event()
        self._idle.set()
        self._port: int | None = None
        self.address: str | Path | None = None
        self.routes = [
            Route(spec.method, spec.path, getattr(self, spec.handler), human=spec.human)
            for spec in ROUTE_SPECS
        ]

    # -- handlers ----------------------------------------------------------

    async def _status(self, _p: dict[str, str], _b: dict[str, Any]) -> Any:
        return self.daemon.status()

    async def _list_groups(self, _p: dict[str, str], _b: dict[str, Any]) -> Any:
        return {"groups": self.daemon.list_groups()}

    async def _group_info(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        return self.daemon.group_info(p["gid"])

    async def _list_approvals(self, _p: dict[str, str], _b: dict[str, Any]) -> Any:
        await self.daemon.expire_held()
        return {"approvals": self.daemon.approvals(), "messages": self.daemon.held_messages()}

    async def _held_message(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        await self.daemon.expire_held()
        return self.daemon.held_message(p["hid"])

    async def _approve_message(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        await self.daemon.expire_held()
        return self.daemon.approve_message(p["hid"])

    async def _reject_message(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        await self.daemon.expire_held()
        return await self.daemon.reject_message(p["hid"])

    async def _remove(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        members = {m.identity for m in self.daemon.store.members(p["gid"])}
        if p["identity"] not in members or p["identity"] == self.daemon.me:
            raise ApiError(404, "not_found", "no such other member")
        self.daemon.remove_member(p["gid"], p["identity"])
        return {"status": "removing"}

    async def _safety(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        return self.daemon.safety_settings(p["gid"])

    async def _set_safety(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        changes = b.get("set")
        if not isinstance(changes, dict):
            raise ApiError(400, "bad_request", "set must be an object")
        sender = b.get("sender")
        if sender is not None and not isinstance(sender, str):
            raise ApiError(400, "bad_request", "sender must be a string")
        return self.daemon.update_safety(p["gid"], changes, sender)

    async def _audit(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        after = _query_int(p, "after")
        return {"audit": self.daemon.store.audit(p.get("group") or None, after)}

    async def _transcript(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        rows = self.daemon.transcript(p["gid"], _query_int(p, "after"))
        return {"transcript": rows, "untrusted": True}

    async def _create_group(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        return {"group_id": self.daemon.create_group(_str(b, "name"), _str(b, "purpose", ""))}

    async def _create_invite(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        name = b.get("inviter_name")
        if name is not None and not isinstance(name, str):
            raise ApiError(400, "bad_request", "inviter_name must be a string")
        return await self.daemon.create_invite(
            p["gid"], _int(b, "ttl_secs", 86_400), _int(b, "max_uses", 1), name
        )

    async def _policy(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        """Only ``require_verified``. Turning it on tightens the gate, so the
        agent token may; turning it off needs the human (SPEC 10.4)."""
        value = b.get("require_verified")
        if not isinstance(value, bool):
            raise ApiError(400, "bad_request", "require_verified must be a boolean")
        if not value and p.get(SCOPE) != "human":
            raise ApiError(403, "human_only", "relaxing verification needs the human token")
        self.daemon.set_policy(p["gid"], require_verified=value)
        return {"require_verified": value}

    async def _revoke(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        await self.daemon.revoke_invite(p["invite_id"])
        return {"revoked": p["invite_id"]}

    async def _inspect(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        return await self.daemon.inspect_invite(_str(b, "url"))

    async def _accept(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        name = b.get("display_name")
        if name is not None and not isinstance(name, str):
            raise ApiError(400, "bad_request", "display_name must be a string")
        return await self.daemon.accept_invite(_str(b, "url"), name)

    async def _send(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        body = b.get("body")
        human = p.get(SCOPE) == "human"
        if body is None:
            body = a2a_text(p["gid"], _str(b, "text"), human)
        if not isinstance(body, dict):
            raise ApiError(400, "bad_request", "body must be an object")
        to = b.get("to", ["*"])
        if not isinstance(to, list) or not all(isinstance(x, str) for x in to):
            raise ApiError(400, "bad_request", "to must be a list of strings")
        kind = _str(b, "kind", "a2a.message")
        reply_to = b.get("reply_to")
        if reply_to is not None and (
            not isinstance(reply_to, list) or not all(isinstance(x, str) for x in reply_to)
        ):
            raise ApiError(400, "bad_request", "reply_to must be a list of msg_ids")
        addressee = b.get("addressee")
        if addressee is not None and (
            not isinstance(addressee, list) or not all(isinstance(x, str) for x in addressee)
        ):
            raise ApiError(400, "bad_request", "addressee must be a list of identities")
        # SPEC 7.2/10.3: only the human's own requests are human-originated.
        # The agent token always sends as the agent, and can't send the
        # controls SPEC 7.3 reserves to humans.
        if kind in HUMAN_ONLY_KINDS and not human:
            raise ApiError(403, "human_only", f"{kind} needs the human token")
        msg_id, status = self.daemon.queue_message(
            p["gid"],
            body,
            to=to,
            kind=kind,
            origin="human" if human else "agent",
            reply_to=reply_to,
            addressee=addressee,
        )
        return {"msg_id": msg_id, "status": status}

    async def _leave(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        return {"status": await self.daemon.leave(p["gid"])}

    async def _approve(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        self.daemon.approve(p["rid"])
        return {"status": "approving"}

    async def _reject(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        self.daemon.reject(p["rid"])
        return {"status": "rejected"}

    async def _verify(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        verified = b.get("verified", True)
        if not isinstance(verified, bool):
            raise ApiError(400, "bad_request", "verified must be a boolean")
        self.daemon.mark_verified(p["gid"], p["identity"], verified)
        return {"verified": verified}

    async def _sas_mismatch(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        epoch = b.get("epoch")
        if epoch is not None and (not isinstance(epoch, int) or isinstance(epoch, bool)):
            raise ApiError(400, "bad_request", "epoch must be an integer")
        return {"status": await self.daemon.sas_mismatch(p["gid"], epoch)}

    async def _events(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        """Events as JSON (``after``), or, with ``Accept: text/event-stream``,
        the SSE feed of messages and events (``Last-Event-ID`` resumes)."""
        group = p.get("group") or None
        if "text/event-stream" not in p.get(ACCEPT, ""):
            after = int(p.get("after", "0") or 0)
            # The safety policy's events are the human's (SPEC 10.2): an agent
            # that heard of a hold could tell the sender.
            hidden = () if p.get(SCOPE) == "human" else tuple(HUMAN_EVENTS)
            return {"events": self.daemon.store.events(after, group_id=group, exclude=hidden)}
        hub = self.daemon.adapters.get("sse")
        if not isinstance(hub, SseAdapter):
            raise ApiError(409, "no_sse_adapter", 'set daemon.default_adapter = "sse"')
        if group is not None and self.daemon.store.group(group) is None:
            raise ApiError(404, "not_found", "no such group")
        return SseStream(hub, hub.subscribe(group, p.get(LAST_EVENT_ID)))

    # -- HTTP --------------------------------------------------------------

    def _authorize(self, headers: dict[str, str], human: bool) -> str:
        """Check the bearer token; returns the scope (``agent`` or ``human``)."""
        auth = headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ApiError(401, "auth_failed", "missing bearer token")
        is_human = hmac.compare_digest(token.encode(), self.tokens["human"].encode())
        is_agent = hmac.compare_digest(token.encode(), self.tokens["agent"].encode())
        if not (is_human or is_agent):
            raise ApiError(401, "auth_failed", "invalid token")
        if is_human and not self.gate.human_allowed():
            raise ApiError(403, "peer_refused", "the human token is not accepted from this user")
        if human and not is_human:
            raise ApiError(403, "human_only", "this operation needs the human token")
        return "human" if is_human else "agent"

    async def handle(
        self, method: str, target: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, Any]:
        path, _, query = target.partition("?")
        params = dict(
            (k, v) for k, _, v in (part.partition("=") for part in query.split("&") if part)
        )
        allowed = False
        for route in self.routes:
            m = route.regex.match(path)
            if m is None:
                continue
            allowed = True
            if route.method != method:
                continue
            scope = self._authorize(headers, route.human)
            try:
                data = json.loads(body) if body else {}
            except ValueError:
                raise ApiError(400, "bad_request", "body is not JSON") from None
            if not isinstance(data, dict):
                raise ApiError(400, "bad_request", "body must be a JSON object")
            extra = {
                SCOPE: scope,
                ACCEPT: headers.get("accept", ""),
                LAST_EVENT_ID: headers.get("last-event-id", ""),
            }
            return 200, await route.handler({**params, **m.groupdict(), **extra}, data)
        if allowed:
            raise ApiError(405, "method_not_allowed", "method not allowed")
        raise ApiError(404, "not_found", "no such endpoint")

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._serve_one(reader, writer)
        finally:
            writer.close()  # also when the handler is cancelled mid-request

    async def _serve_one(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self.gate.admit(writer):
            await self._reply(writer, 403, {"code": "peer_refused", "message": "user refused"})
            return
        if self._connections >= MAX_CONNECTIONS:
            await self._reply(writer, 503, {"code": "busy", "message": "too many connections"})
            return
        self._connections += 1
        self._idle.clear()
        try:
            status, payload = await self._request(reader)
            if isinstance(payload, SseStream):
                self._streams.add(payload)
                try:
                    await payload.run(reader, writer)
                finally:
                    self._streams.discard(payload)
                return
            await self._reply(writer, status, payload)
        finally:
            self._connections -= 1
            if self._connections == 0:
                self._idle.set()

    def _check_origin(self, headers: dict[str, str]) -> None:
        """Loopback TCP: no browser requests (no ``Origin``), and a ``Host``
        naming this listener only (DNS rebinding). Defence in depth: the
        bearer token already stops both."""
        if self._port is None:
            return
        if "origin" in headers:
            raise ApiError(403, "forbidden", "browser requests are not accepted")
        allowed = {f"127.0.0.1:{self._port}", f"localhost:{self._port}"}
        if headers.get("host") not in allowed:
            raise ApiError(403, "forbidden", "unexpected Host header")

    async def _request(self, reader: asyncio.StreamReader) -> tuple[int, Any]:
        status, payload = 500, {"code": "internal", "message": "internal error"}
        try:
            async with asyncio.timeout(READ_TIMEOUT):
                method, target, headers, body = await self._read(reader)
            self._check_origin(headers)
            status, payload = await self.handle(method, target, headers, body)
        except ApiError as e:
            status, payload = e.status, {"code": e.code, "message": str(e)}
        except DaemonError as e:
            status, payload = ERROR_STATUS.get(e.code, 409), {"code": e.code, "message": str(e)}
        except RelayError as e:
            status, payload = 502, {"code": e.code, "message": str(e)}
        except TimeoutError:
            status, payload = 408, {"code": "timeout", "message": "request not received in time"}
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            status, payload = 400, {"code": "bad_request", "message": "malformed request"}
        except Exception:
            LOG.exception("api_failed")
        return status, payload

    @staticmethod
    async def _read(reader: asyncio.StreamReader) -> tuple[str, str, dict[str, str], bytes]:
        head = await reader.readuntil(b"\r\n\r\n")
        if len(head) > MAX_HEADER:
            raise ApiError(413, "too_large", "headers too large")
        lines = head.decode("latin-1").split("\r\n")
        method, target, _version = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0") or 0)
        if length < 0 or length > MAX_BODY:
            raise ApiError(413, "too_large", "body too large")
        body = await reader.readexactly(length) if length else b""
        return method, target, headers, body

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: int, payload: Any) -> None:
        data = json.dumps(payload).encode()
        writer.write(
            f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'Error')}\r\n"
            f"content-type: application/json\r\ncontent-length: {len(data)}\r\n"
            "connection: close\r\n\r\n".encode()
            + data
        )
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        writer.close()

    async def start(self) -> None:
        cfg = self.daemon.config
        if cfg.api_tcp_port:
            port = cfg.api_tcp_port
            self._server = await asyncio.start_server(
                self._serve, "127.0.0.1", port, limit=MAX_HEADER
            )
            sock = self._server.sockets[0].getsockname()
            self._port = int(sock[1])
            self.address = f"http://127.0.0.1:{sock[1]}"
        else:
            path = cfg.socket_path
            with contextlib.suppress(FileNotFoundError):
                if not stat.S_ISSOCK(path.lstat().st_mode):
                    msg = f"{path} exists and is not a socket; refusing to replace it"
                    raise FileExistsError(msg)
                path.unlink()
            # Bind under a 0077 umask so the socket is never connectable by
            # others, not even between bind and chmod.
            old = os.umask(0o077)
            try:
                self._server = await asyncio.start_unix_server(self._serve, path, limit=MAX_HEADER)
            finally:
                os.umask(old)
            path.chmod(0o600)
            self.gate.publish(path)  # isolation: 0660 for the agent group
            self.address = path
        LOG.info("api_listening", transport="tcp" if cfg.api_tcp_port else "unix")

    async def stop(self) -> None:
        for stream in list(self._streams):
            stream.stop()
        if self._server is not None:
            self._server.close()
            close_clients = getattr(self._server, "close_clients", None)  # Python 3.13+
            if close_clients is not None:
                close_clients()  # connections accepted but not yet served
            await self._idle.wait()  # every connection handler has closed its transport
            await self._server.wait_closed()
            self._server = None
        if isinstance(self.address, Path):
            self.address.unlink(missing_ok=True)
