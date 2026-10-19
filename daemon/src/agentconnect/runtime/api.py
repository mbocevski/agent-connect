"""The local control API: small JSON over HTTP/1.1.

Transport: a Unix socket in the data directory (mode 0600) by default, or
``127.0.0.1:<port>`` when configured. The server is a minimal asyncio
HTTP/1.1 implementation (one request per connection, ``Content-Length``
bodies only, 1 MiB cap), so the daemon needs no web framework.

Authentication: ``Authorization: Bearer <token>``. There are two tokens,
each in a 0600 file in the data directory:

* ``api-token`` (scope ``agent``): everything an agent integration may do;
* ``human-token`` (scope ``human``): additionally approving JoinRequests,
  knocks and held messages, marking members verified, removing members,
  creating a replica invite (ADR-005: provisioning a replica is the human's),
  changing or reading the group's safety policy, audit log and transcript,
  and publishing a listing (SPEC 13.2.2: an agent can't put itself into a
  public directory; withdrawing is allowed to either token). Knocks this
  runtime received, and the events about them, are the human's only.

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
import json
import os
import re
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentconnect import log
from agentconnect.cli_json import APPROVAL, HELD, KNOCK_INSPECT, KNOCK_SUMMARY, KNOCKS, LISTING
from agentconnect.deliveries import DeliveryQueue
from agentconnect.isolation import PeerGate
from agentconnect.runtime.agent import AgentApi, a2a_text
from agentconnect.runtime.engine import Engine
from agentconnect.runtime.errors import ApiError, error_reply
from agentconnect.shapes import Opt
from agentconnect.sockets import bind_path, prepare_bind_dir
from agentconnect.sse import SseAdapter, Subscription
from agentconnect.tasks import cancel_and_wait
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE, TokenDigest

LOG = log.get("agentconnect.api")

MAX_BODY = 1 << 20
MAX_HEADER = 16 << 10
READ_TIMEOUT = 10.0  # seconds to send a whole request
MAX_CONNECTIONS = 64
# Agent-token requests in progress at most: the rest of MAX_CONNECTIONS is
# kept for the human token, so authenticated agent requests (long polls
# included) can't take every connection. The cap applies after
# authentication: connections that never send a whole request still count
# against MAX_CONNECTIONS until READ_TIMEOUT.
MAX_AGENT_REQUESTS = 48
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
    410: "Gone",
    413: "Payload Too Large",
    422: "Unprocessable Content",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
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


MAX_POLL_SECS = 60  # the longest one GET /v0/deliveries waits
MAX_POLLS = 4  # GET /v0/deliveries waiting at once, per token


class DeliveryPoll:
    """A handler result that waits for deliveries (``GET /v0/deliveries``)
    while watching the connection: a caller that goes away leases nothing,
    and a stopping server answers at once (empty)."""

    def __init__(
        self,
        queue: DeliveryQueue,
        stopping: asyncio.Event,
        done: Callable[[], None],
        **take: Any,
    ) -> None:
        self.queue, self.stopping, self.done, self.take = queue, stopping, done, take

    async def run(self, reader: asyncio.StreamReader) -> dict[str, Any] | None:
        """The answer, or ``None`` if the caller left first."""
        gone = asyncio.ensure_future(reader.read(1))  # EOF: the client left
        taking = asyncio.ensure_future(self.queue.take(stop=self.stopping, **self.take))
        try:
            await asyncio.wait({gone, taking}, return_when=asyncio.FIRST_COMPLETED)
            if not taking.done():
                return None
            batch = taking.result()
            if gone.done():
                self.queue.release(batch.lease, [t.delivery_id for t in batch.items])
                return None
        finally:
            self.done()
            gone.cancel()
            await cancel_and_wait(taking)
        return {
            "deliveries": [
                {"delivery_id": str(t.delivery_id), "message": t.payload} for t in batch.items
            ],
            "lease": batch.lease,
            "more": batch.more,
            "untrusted": True,
        }


@dataclass
class Connection:
    """One connection's request: whether it counts as an agent request."""

    agent: bool = False


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
    "leaving": Opt({"since": "int", "blocked": "bool"}),
    "policy_summary": {
        "invite": Opt("str"),
        "remove": Opt("str"),
        "max_members": Opt("int"),
        "max_agent_turns": Opt("int"),
    },
    "floor": {
        "mode": Opt("str"),
        "pinned": "bool",
        "moderator": Opt("str"),
        "effective_moderator": Opt("str"),
        "holder": Opt("str"),
    },
    "pending_leaves": [{"identity": "str", "instance_id": "str"}],
    "members": [
        {
            "identity": "str",
            "fingerprint": "str",
            "display_name": Opt("str"),
            "display_name_verified": "bool",
            "role": "str",
            "verified": "bool",
            "instances": [
                {
                    "instance_id": "str",
                    "mailbox_id": "str",
                    "leaf_index": "int",
                    "joined_epoch": "int",
                    "self": "bool",
                }
            ],
            "instances_since_verified": Opt(["str"]),
            "self": "bool",
            "listed_as?": {
                "directory": "str",
                "name": "str",
                "owner_domain": Opt("str"),
                "owner_state": "str",
            },
        }
    ],
    "agent_cards": "object",
    "sas?": {"decimal": "str", "emoji_indices": ["int"]},
    "origin?": {"kind": "str", "directory": "str", "name": "str"},
}

_HELD: dict[str, Any] = HELD

_SAFETY: dict[str, Any] = {"group_id": "str", "settings": "object", "overrides": "object"}

_WARNINGS: list[Any] = [{"code": "str", "message": "str"}]
_LISTING_REQUEST: dict[str, Any] = {
    "directory": "str",
    "card": "object",
    "token": "object",
    "owner_domain?": Opt("str"),
}

ROUTE_SPECS: tuple[RouteSpec, ...] = (
    RouteSpec(
        "GET",
        "/v0/status",
        "_status",
        "Daemon status: identity, relay connection, queue sizes. With the agent token, "
        "`held_messages` counts only the agent's own held sends.",
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
        "Create a group you own. `policy` takes the fields of `POST /v0/groups/{gid}/policy` "
        "over the default policy, set in the group's first epoch; a `floor` set here is "
        "pinned. With the agent token `policy` may hold only `require_verified`; anything "
        "else needs the human token (`403 human_only`).",
        request={"name": "str", "purpose?": "str", "policy?": "object"},
        response={"group_id": "str"},
    ),
    RouteSpec(
        "GET",
        "/v0/groups/{gid}",
        "_group_info",
        "One group: members, roles, verified flags, short code, `out_of_sync` and "
        "the peers' Agent Cards (each wrapped as `untrusted`). Each member lists its "
        "instances, `self` marking this one and `joined_epoch` the epoch this runtime first "
        "saw it in; `instances_since_verified` are those that joined after you verified the "
        "member (`null`: unknown, the member was verified before the daemon recorded the "
        "epoch, so verify it again). `policy_summary` and `floor` repeat the policy's "
        "permissions and floor; `floor` adds the `effective_moderator` and the `holder` "
        "of a moderated group's floor ([groups.md](groups.md#floor-control)), and "
        "`pending_leaves` the instances whose leave waits for a commit. `leaving` is set "
        "while this instance leaves the group; `blocked` says the leave waits for an "
        "ownership transfer ([groups.md](groups.md#leaving)).",
        response=_GROUP_INFO,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/invites",
        "_create_invite",
        "Create an invite. `ttl_secs` defaults to 86400 and `max_uses` to 1; "
        "`inviter_name` defaults to the daemon's display name. `replica: true` (human "
        "token only, else `403 human_only`) makes it an invite for another instance of "
        "this identity: it is allowed whatever the group's `invite` says, and join requests "
        "from any other identity are dropped. `instance` (16 lowercase hex, with `replica` "
        "only) pins it to the instance `identity import` printed: requests from any other "
        "instance are dropped too, and only a pinned replica invite is approved by "
        "`auto_approve` ([groups.md](groups.md#replicas)).",
        request={
            "ttl_secs?": "int",
            "max_uses?": "int",
            "inviter_name?": "str",
            "replica?": "bool",
            "instance?": "str",
        },
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
        "Change the group policy (a commit, SPEC 9.2): give only the fields that change. "
        "Setting `floor` also pins it (`floor_pinned`, SPEC 9.1) unless you give "
        "`floor_pinned`; `floor_moderator` takes an identity or `null`. The agent token may "
        "only turn `require_verified` on (SPEC 10.4); every other change needs the human "
        "token. `status` is `committing` (then `policy_changed` or `commit_failed`) or "
        "`unchanged`. A change your role doesn't allow is refused at once with "
        "`403 not_permitted` ([groups.md](groups.md#changing-roles-and-the-policy)).",
        request={
            "require_verified?": "bool",
            "invite?": "str",
            "remove?": "str",
            "max_members?": "int",
            "floor?": "str",
            "floor_pinned?": "bool",
            "floor_moderator?": Opt("str"),
            "max_agent_turns?": "int",
        },
        response={"status": "str"},
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/members/{identity}/role",
        "_role",
        "Make a member an admin or a plain member (`role`: `admin` or `member`; a commit "
        "only the owner may make). `status` is `committing` (then `role_changed`) or "
        "`unchanged`. The owner's role changes only with a transfer (`POST "
        "/v0/groups/{gid}/owner`).",
        request={"role": "str"},
        response={"status": "str"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/owner",
        "_owner",
        "Hand ownership over to another member (a commit only the owner may make, SPEC "
        "9.2). `keep_admin` (default `true`) keeps you an admin. `status` is `committing`, "
        "then `role_changed` for both. A leave of yours that waits for a transfer goes on "
        "once it lands ([groups.md](groups.md#the-owner-leaves-last)).",
        request={"identity": "str", "keep_admin?": "bool"},
        response={"status": "str"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/floor",
        "_floor",
        "Grant the floor of a `moderated` group to a member (`holder`: an identity), or "
        "release it (`holder: null`): the daemon sends `control.floor` (SPEC 9.3), which "
        "takes effect once the relay has taken it. Only the effective moderator or the "
        "owner may (`403 not_permitted`); a group whose floor isn't `moderated` answers "
        "`409 not_moderated`. Either token: a grant triggers nobody, and the floor mode and "
        "the moderator stay the human's (`POST /v0/groups/{gid}/policy`). The agent token's "
        "grants count against its send rate (`429 rate_limited`). `status` is `granted`; "
        "`floor_changed` follows when the holder changed "
        "([groups.md](groups.md#floor-control)).",
        request={"holder": Opt("str")},
        response={"status": "str", "holder": Opt("str"), "msg_id": "str"},
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
        "Leave a group: the daemon sends `control.leave` and a leave proposal, and another "
        "member commits it. `status` is `leaving`, or `left` for a sole member. The owner's "
        "last instance must hand over ownership first (`403 forbidden`).",
        response={"status": "str"},
    ),
    RouteSpec(
        "GET",
        "/v0/approvals",
        "_list_approvals",
        "Pending join requests (`kind: join`) with the joiner's fingerprint, knocks on "
        "your listing waiting for approval (`kind: knock`, no `group_id` yet: the knocker's "
        "name and note are claims, `known` is what this daemon already knows of its "
        "identity), and the messages the safety policy holds for approval (`messages`, "
        "metadata only). With the agent token, `approvals` is empty and `messages` lists "
        "only the agent's own held sends: what is held of the peers' messages, and who "
        "knocked, is the human's to know.",
        response={"approvals": [APPROVAL], "messages": [_HELD]},
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
        "Approve a join request or a knock. For a knock the daemon creates a new group named "
        "after the listing, with `purpose` (default: the listing's description) as its "
        "scope, and adds the knocker (SPEC 6.6.4); `group_id` is that group. A knock past "
        "its lapse (an hour after it was sent) answers `409 expired`. Only the human token "
        "approves a knock: there is no setting, policy or agent route that does.",
        request={"purpose?": "str"},
        response={"status": "str", "group_id?": "str"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/approvals/{rid}/reject",
        "_reject",
        "Reject a join request or a knock. Nothing is sent to the knocker: a rejection "
        "looks the same as no answer.",
        response={"status": "str"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/members/{identity}/verify",
        "_verify",
        "Mark a member verified (the human compared the short code). `verified` "
        "defaults to `true`; marking verified needs `epoch`, the epoch whose short code "
        "the human compared (`GET /v0/groups/{gid}` shows it with the code). If the group "
        "has moved on since, the code changed: `409 stale_epoch`, compare again (SPEC 11).",
        request={"verified?": "bool", "epoch?": "int"},
        response={"verified": "bool"},
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/groups/{gid}/members/{identity}/remove",
        "_remove",
        "Remove a member, every instance of it (an MLS commit; the group policy decides "
        "whether this instance may). For a member the safety policy reported with "
        "`repeated_violations`; the daemon never removes anyone on its own. With "
        "`instances` (instance ids, 16 hex characters), only those instances go, such as "
        "a dead replica; this way you may also remove your own identity's other instances, "
        "but never this one (leave instead). The result is a `member_removed` or "
        "`instance_removed` event, or `commit_failed`.",
        request={"instances?": ["str"]},
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
        "POST",
        "/v0/listing/preview",
        "_listing_preview",
        "Check a listing before publishing it ([discovery.md](discovery.md)): the card "
        "text (`card`, the card file's contents) and the operator's `token` are verified "
        "against the pinned `[[directory]]`, and the answer shows what would be signed, "
        "with `content_sha256` to pass to `publish`. With an owner domain, the daemon "
        "fetches that domain's owner file and returns the entry it should list "
        "(`owner_file_entry`). Nothing is registered, signed or sent to the directory.",
        request=_LISTING_REQUEST,
        response={
            "directory": "str",
            "name": "str",
            "identity": "str",
            "fingerprint": "str",
            "content": "object",
            "content_sha256": "str",
            "owner_domain": Opt("str"),
            "token": {"token_id": "str", "issued_at": "int", "expires_at": "int", "key_id": "str"},
            "owner_file_entry": Opt("object"),
            "warnings": _WARNINGS,
        },
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/listing/publish",
        "_listing_publish",
        "Publish the listing the preview showed (`content_sha256` must match): register "
        "a fresh door at the relay, sign and post. The runtime renews the door from then "
        "on. A directory that doesn't answer is retried with the same signed bytes "
        "(`retrying: true`, `state` `publishing`); a refusal answers with the "
        "directory's code. Publishing is a human decision (SPEC 13.2.2).",
        request={**_LISTING_REQUEST, "content_sha256": "str"},
        response={
            "directory": "str",
            "name": "str",
            "url": "str",
            "seq": "int",
            "state": "str",
            "door_expires_at": Opt("int"),
            "renews_at": Opt("int"),
            "token_expires_at": "int",
            "owner_domain": Opt("str"),
            "owner_state": Opt("str"),
            "warnings": _WARNINGS,
            "retrying": "bool",
        },
        human=True,
    ),
    RouteSpec(
        "POST",
        "/v0/listing/withdraw",
        "_listing_withdraw",
        "Withdraw the listing: every door is closed at the relay first (their keys are "
        "deleted at once), then the signed withdrawal goes to the directory. Either "
        "token may: withdrawing only reduces exposure (SPEC 13.2.3). `state` is "
        "`withdrawing` while the directory hasn't answered; the runtime keeps trying, "
        "and gives up after 7 days (`withdraw_failed`). `force: true` (the human token "
        "only, and only while a withdrawal is `withdrawing` or `withdraw_failed`; else "
        "`409 not_withdrawing`) ends it here without the directory, after the doors are "
        "closed: `state` is then `withdrawn_locally` and `forced` is true, and the "
        "directory may go on listing it. A directory removed from the config answers "
        "`400 unknown_directory`.",
        request={"force?": "bool"},
        response={
            "directory": "str",
            "name": "str",
            "seq": "int",
            "state": "str",
            "doors_closed": "int",
            "doors_close_pending": "int",
            "forced": "bool",
        },
    ),
    RouteSpec(
        "GET",
        "/v0/listing",
        "_listing_status",
        "The runtime's listing, if it has one: its state, door, token expiry and last "
        "error. `owner_state` is what the directory last reported, for information only. "
        "With the human token it adds `pending_knocks` and `knocks_dropped`.",
        response={"listing": Opt(LISTING)},
    ),
    RouteSpec(
        "POST",
        "/v0/knocks/inspect",
        "_knock_inspect",
        "Fetch a listing (`listing` is `<directory host>/a/<name>`, on a pinned "
        "`[[directory]]`) and check it as a knock would: signature, token under the pinned "
        "keys, directory and name, relay, door, and no rollback. With `domain_check` "
        "(default `knock.domain_check`) the daemon fetches the owner domain's file itself; "
        "`owner.state` is that check, never the directory's. The text is the listing's "
        "own claim: `untrusted`, with a `notice` to show in front of it. A listing that "
        "fails a check answers `422` (`listing_invalid`, `listing_mismatch`, "
        "`listing_rolled_back`) or `403 token_invalid`.",
        request={"listing": "str", "domain_check?": "bool"},
        response=KNOCK_INSPECT,
    ),
    RouteSpec(
        "POST",
        "/v0/knocks",
        "_knock",
        "Knock on a listing: ask its owner's human for a new group (SPEC 6.6.2). Pass the "
        "`sha256` the inspection showed as `listing_sha256` (`409 listing_changed` if it "
        "changed). `display_name` defaults to the daemon's; `note` is optional (one line, "
        "1 to 500 characters). The knock waits until `gives_up_at`: a `joined` event "
        "with its `knock_id` is the only answer, otherwise `knock_lapsed` (no answer, "
        "never why). Either token, unless `knock.agent_may_knock` is off (then "
        "`403 human_only` for the agent token).",
        request={
            "listing": "str",
            "listing_sha256?": "str",
            "display_name?": "str",
            "note?": "str",
            "domain_check?": "bool",
        },
        response=KNOCK_SUMMARY,
    ),
    RouteSpec(
        "GET",
        "/v0/knocks",
        "_knocks",
        "This daemon's own knocks, oldest first: `queued`, `sent`, `joined` (with "
        "`group_id`), `lapsed` or `failed`, each with what it knocked on: the listing's "
        "name, fingerprint and owner state, and its card's name and description (the "
        "listing owner's text, so `untrusted`). A knock the agent started is readable by "
        "its human here (SPEC 6.6.2).",
        response={"knocks": [KNOCKS], "untrusted": "bool"},
    ),
    RouteSpec(
        "GET",
        "/v0/events",
        "_events",
        "Daemon events in order, at most 200 per call. With the agent token `seq` is the "
        "agent's own sequence, with no gap where an event it doesn't see was recorded, and "
        "`after` takes it; the human token's `seq` numbers every event. The agent token "
        "doesn't see the safety policy's events (`message_held`, `held_expired`, "
        "`repeated_violations`): they would tell the agent, and so a peer, what the "
        "policy did. Nor does it see "
        "the knocks your listing received (`knock_received`, `knock_approved`, "
        "`knock_rejected`, `knock_expired`, `knock_approval_failed`), or "
        "`invite_flooded` (one of your invites gets more join requests than it can hold) "
        "and `join_ledger_full` (the join ledger itself is full). "
        "With "
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
    RouteSpec(
        "GET",
        "/v0/deliveries",
        "_deliveries",
        "Messages waiting for an agent that pulls them (an MCP session attached to this "
        "runtime, [adapters/mcp.md](adapters/mcp.md)), oldest first, at most 50, in the "
        "payload shape of the webhook adapter (`untrusted`, `notice`, `addressed_to_me`). "
        "Waits up to `timeout` seconds for one; with `addressed_only`, for one that "
        "addresses this agent, however many others are queued before it (the answer holds "
        "it and up to 49 queued messages before it, as context). The messages are leased "
        "to the caller under `lease` for 120 seconds: no other caller gets them meanwhile, "
        "and they are queued again unless acknowledged with `POST /v0/deliveries/ack`. "
        "`more` is true when more are queued. At most 4 polls per token wait at once; "
        "another answers `429 busy`. Needs "
        '`daemon.default_adapter = "mcp"` (the MCP host sets it), else `409 no_deliveries`.',
        query="`group`: only that group. `addressed_only`: `1` or `0` (default 0). "
        "`timeout`: seconds to wait, 0 to 60 (default 0).",
        response={
            "deliveries": [{"delivery_id": "str", "message": "object"}],
            "lease": "str",
            "more": "bool",
            "untrusted": "bool",
        },
    ),
    RouteSpec(
        "POST",
        "/v0/deliveries/ack",
        "_deliveries_ack",
        "Acknowledge deliveries of a `lease`: they leave the queue, and a repeat of one "
        "(after a crash) is not queued again. Only the lease that took them may: also "
        "after its 120 seconds ran out, unless another caller took them since. "
        "`acked` counts those acknowledged; `refused` lists the ids the lease doesn't "
        "hold (never leased, leased again, or already acknowledged).",
        request={"lease": "str", "ids": ["str"]},
        response={"acked": "int", "refused": ["str"]},
    ),
    RouteSpec(
        "POST",
        "/v0/deliveries/release",
        "_deliveries_release",
        "Give back deliveries of a `lease` that won't be returned (the caller's tool "
        "call was cancelled): they are queued again at once. Ids the lease doesn't hold "
        "are left alone.",
        request={"lease": "str", "ids": ["str"]},
        response={"released": "bool"},
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
    (
        400,
        "unknown_directory",
        "Publish: the directory has no `[[directory]]` table, so no keys are pinned for it.",
    ),
    (400, "bad_token", "Publish: the token is not a listing token (malformed)."),
    (
        400,
        "bad_listing_ref",
        "Knock: the listing is not `[https://]<host>/a/<name>[.json]` (no query, fragment, "
        "user or other path).",
    ),
    (400, "self_knock", "Knock: the listing is this runtime's own identity's."),
    (
        400,
        "bad_card",
        "Publish: the card is not valid listing text, or holds fields of a full Agent Card.",
    ),
    (
        400,
        "bad_listing",
        "Publish: the directory refused the listing as malformed. Also `wrong_relay`, "
        "`wrong_directory`, `bad_door` and `stale_ts`: the directory's codes "
        "(directory/README.md).",
    ),
    (401, "auth_failed", "The bearer token is missing or wrong."),
    (
        403,
        "token_invalid",
        "Publish or knock: the listing token doesn't verify under the pinned keys: "
        "expired, not valid yet, bad signature, an unpinned key, or for another directory.",
    ),
    (403, "unknown_key", "Publish: the token is signed by a key not pinned for the directory."),
    (
        403,
        "token_not_for_identity",
        "Publish: the token was issued for another identity (or owner domain).",
    ),
    (
        403,
        "token_revoked",
        "Publish: the directory refused the token (also `bad_token`, `bad_signature`, "
        "`wrong_identity`, `owner_revoked`).",
    ),
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
    (
        403,
        "not_permitted",
        "Policy, role or ownership change: the group policy doesn't let this identity make "
        "it now (the core's check, SPEC 9.2). Nothing was queued.",
    ),
    (404, "not_found", "No such endpoint, group, invite or request."),
    (405, "method_not_allowed", "The path exists but not for this method."),
    (408, "timeout", "The request was not received within 10 seconds."),
    (
        409,
        "stale_epoch",
        "The group changed since the epoch you passed: its short code is a new one. Show "
        "the new code and compare again.",
    ),
    (
        409,
        "no_deliveries",
        "Deliveries: this runtime has no delivery queue (`daemon.default_adapter` isn't `mcp`).",
    ),
    (
        409,
        "expired",
        "The invite or request has expired (a knock lapses an hour after it was sent).",
    ),
    (409, "invite_not_open", "The invite was used up, revoked or never open."),
    (409, "not_moderated", "Floor grant: the group's floor isn't `moderated`."),
    (
        409,
        "group_full",
        "Approve: the Add would take the group past its policy's `max_members`. The "
        "request stays pending; remove a member first.",
    ),
    (
        409,
        "too_many_invites",
        "Create invite: the open invites already reserve the whole join ledger (each "
        "its share plus its uses, SPEC 6.2); revoke the ones you no longer need.",
    ),
    (
        409,
        "listing_exists",
        "Publish: the runtime already has another listing; withdraw it first.",
    ),
    (
        409,
        "not_withdrawing",
        "Withdraw: `force` only ends a withdrawal the directory hasn't taken.",
    ),
    (409, "card_changed", "Publish: the card or token changed since the preview."),
    (
        409,
        "name_held",
        "Publish: the directory holds the name for a newer token or a higher `seq`.",
    ),
    (409, "listing_changed", "Knock: the listing changed since it was inspected."),
    (409, "already_pending", "Knock: a knock on this listing already waits for an answer."),
    (409, "door_closed", "Knock: the listing has no open door."),
    (410, "listing_withdrawn", "Knock: the directory says the listing was withdrawn."),
    (413, "too_large", "The headers or the body (over 1 MiB) are too large."),
    (
        422,
        "listing_invalid",
        "Knock: the listing the directory served doesn't verify (signature, canonical "
        "form, schema) or its door key is unusable. Also `listing_mismatch` (a listing "
        "for another name or directory) and `listing_rolled_back` (older than one this "
        "daemon has seen).",
    ),
    (429, "too_many_knocks", "Knock: 8 knocks (`knock.max_outgoing`) already wait."),
    (
        429,
        "rate_limited",
        "Too many requests (knocks: one per door in 10 minutes, `knock.per_hour`).",
    ),
    (500, "internal", "An unexpected failure; the daemon logs it."),
    (502, "relay", "The relay reported an error."),
    (
        502,
        "directory",
        "Publish: the directory refused the listing with a code of its own. Knock: it "
        "didn't serve the listing.",
    ),
    (
        503,
        "busy",
        "Too many open connections, or too many agent-token requests at once (part of the "
        "capacity is kept for the human token). Deliveries: `429` when 4 polls of the "
        "token wait already.",
    ),
)


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


def _opt_str(body: dict[str, Any], key: str) -> str | None:
    value = body.get(key)
    if value is not None and not isinstance(value, str):
        raise ApiError(400, "bad_request", f"{key} must be a string")
    return value


def _opt_bool(body: dict[str, Any], key: str) -> bool | None:
    value = body.get(key)
    if value is not None and not isinstance(value, bool):
        raise ApiError(400, "bad_request", f"{key} must be a boolean")
    return value


def _query_int(p: dict[str, str], key: str) -> int:
    raw = p.get(key, "0") or "0"
    if not raw.isdigit():
        raise ApiError(400, "bad_request", f"{key} must be a non-negative integer")
    return int(raw)


class ApiServer:
    """Serves the control API for one :class:`Engine`."""

    def __init__(
        self, daemon: Engine, gate: PeerGate | None = None, agent: AgentApi | None = None
    ) -> None:
        self.daemon = daemon
        self.agent = agent or AgentApi(daemon)
        # Peer-credential checks; a no-op unless isolation.enabled.
        self.gate = gate if gate is not None else PeerGate.from_config(daemon.config)
        data_dir = daemon.config.data_dir
        # Created (0600) on first start; only their hashes stay in memory.
        self._tokens = {
            "agent": TokenDigest.of_file(data_dir / API_TOKEN_FILE),
            "human": TokenDigest.of_file(data_dir / HUMAN_TOKEN_FILE),
        }
        self._server: asyncio.Server | None = None
        self._connections = 0
        self._streams: set[SseStream] = set()
        self._stopping = asyncio.Event()  # long polls answer at once
        self._polls: dict[str, int] = {}  # long polls waiting, per token scope
        self._agent_requests = 0  # agent-token requests in progress
        self._idle = asyncio.Event()
        self._idle.set()
        self._port: int | None = None
        self.address: str | Path | None = None
        self.routes = [
            Route(spec.method, spec.path, getattr(self, spec.handler), human=spec.human)
            for spec in ROUTE_SPECS
        ]

    # -- handlers ----------------------------------------------------------

    # Routes either token may call go to AgentApi for the agent token, so
    # the socket and the embedded SDK share one implementation. The human
    # token gets the fuller view where there is one.

    async def _status(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        if p.get(SCOPE) != "human":
            return await self.agent.status()
        return self.daemon.status()

    async def _list_groups(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        if p.get(SCOPE) == "human":
            return {"groups": self.daemon.list_groups()}
        return await self.agent.list_groups()

    async def _group_info(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        if p.get(SCOPE) == "human":
            return self.daemon.group_info(p["gid"])
        return await self.agent.group_info(p["gid"])

    async def _list_approvals(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        if p.get(SCOPE) != "human":
            return await self.agent.approvals()
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

    async def _remove(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        members = {m.identity for m in self.daemon.store.members(p["gid"])}
        instances = b.get("instances")
        if instances is not None:
            if not isinstance(instances, list) or not all(isinstance(i, str) for i in instances):
                raise ApiError(400, "bad_request", "instances must be a list of instance ids")
            if p["identity"] not in members:
                raise ApiError(404, "not_found", "no such member")
            self.daemon.remove_instances(p["gid"], p["identity"], instances)
            return {"status": "removing"}
        if p["identity"] not in members or p["identity"] == self.daemon.me:
            raise ApiError(404, "not_found", "no such other member")
        self.daemon.remove_member(p["gid"], p["identity"])
        return {"status": "removing"}

    async def _safety(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        if p.get(SCOPE) == "human":
            return self.daemon.safety_settings(p["gid"])
        return await self.agent.safety(p["gid"])

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

    async def _create_group(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        name, purpose = _str(b, "name"), _str(b, "purpose", "")
        raw = b.get("policy", {})
        if not isinstance(raw, dict):
            raise ApiError(400, "bad_request", "policy must be an object")
        policy: dict[str, Any] = raw
        if p.get(SCOPE) == "human" and len(policy) > 0:
            return {"group_id": self.daemon.create_group(name, purpose, policy)}
        if set(policy) - {"require_verified"}:
            raise ApiError(
                403, "human_only", "a group policy beyond require_verified needs the human token"
            )
        verified = policy.get("require_verified", False)
        if not isinstance(verified, bool):
            raise ApiError(400, "bad_request", "require_verified must be a boolean")
        return await self.agent.create_group(name, purpose, require_verified=verified)

    async def _create_invite(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        """Either token, except a replica invite: provisioning a replica is
        the human's (ADR-005), so ``replica: true`` needs the human token
        and goes past :class:`AgentApi`, which has no such parameter."""
        name = b.get("inviter_name")
        if name is not None and not isinstance(name, str):
            raise ApiError(400, "bad_request", "inviter_name must be a string")
        replica = b.get("replica", False)
        if not isinstance(replica, bool):
            raise ApiError(400, "bad_request", "replica must be a boolean")
        instance = b.get("instance")
        if instance is not None and (not replica or not isinstance(instance, str)):
            raise ApiError(400, "bad_request", "instance is a replica invite's pin: a string")
        ttl_secs, max_uses = _int(b, "ttl_secs", 86_400), _int(b, "max_uses", 1)
        if not replica:
            return await self.agent.create_invite(
                p["gid"], ttl_secs=ttl_secs, max_uses=max_uses, inviter_name=name
            )
        if p.get(SCOPE) != "human":
            raise ApiError(403, "human_only", "a replica invite needs the human token")
        return await self.daemon.create_invite(
            p["gid"], ttl_secs, max_uses, name, replica=True, instance=instance
        )

    async def _policy(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        """The human token changes any field. The agent token only turns
        ``require_verified`` on, which tightens the gate (SPEC 10.4)."""
        if p.get(SCOPE) == "human":
            return {"status": self.daemon.change_policy(p["gid"], b)}
        if set(b) != {"require_verified"}:
            raise ApiError(
                403,
                "human_only",
                "changing the group policy needs the human token, "
                "except turning require_verified on",
            )
        value = b["require_verified"]
        if not isinstance(value, bool):
            raise ApiError(400, "bad_request", "require_verified must be a boolean")
        return await self.agent.set_policy(p["gid"], require_verified=value)

    async def _role(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        return {"status": self.daemon.set_role(p["gid"], p["identity"], _str(b, "role"))}

    async def _owner(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        keep = b.get("keep_admin", True)
        if not isinstance(keep, bool):
            raise ApiError(400, "bad_request", "keep_admin must be a boolean")
        status = self.daemon.transfer_ownership(p["gid"], _str(b, "identity"), keep_admin=keep)
        return {"status": status}

    async def _floor(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        if "holder" not in b:
            raise ApiError(400, "bad_request", "holder is required (an identity or null)")
        holder = b["holder"]
        if holder is not None and not isinstance(holder, str):
            raise ApiError(400, "bad_request", "holder must be an identity or null")
        if p.get(SCOPE) == "human":
            return self.daemon.grant_floor(p["gid"], holder, origin="human")
        return await self.agent.grant_floor(p["gid"], holder)

    async def _revoke(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        return await self.agent.revoke_invite(p["invite_id"])

    async def _inspect(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        return await self.agent.inspect_invite(_str(b, "url"))

    async def _accept(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        name = b.get("display_name")
        if name is not None and not isinstance(name, str):
            raise ApiError(400, "bad_request", "display_name must be a string")
        return await self.agent.accept_invite(_str(b, "url"), name)

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
        if not human:
            # SPEC 7.2/10.3: the agent token always sends as the agent, and
            # can't send the controls SPEC 7.3 reserves to humans.
            return await self.agent.send(
                p["gid"], body, to=to, kind=kind, reply_to=reply_to, addressee=addressee
            )
        msg_id, status = self.daemon.queue_message(
            p["gid"],
            body,
            to=to,
            kind=kind,
            origin="human",
            reply_to=reply_to,
            addressee=addressee,
        )
        return {"msg_id": msg_id, "status": status}

    async def _leave(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        return await self.agent.leave(p["gid"])

    async def _approve(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        purpose = b.get("purpose")
        if purpose is not None and not isinstance(purpose, str):
            raise ApiError(400, "bad_request", "purpose must be a string")
        return self.daemon.approve(p["rid"], purpose)

    async def _reject(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        return self.daemon.reject(p["rid"])

    async def _verify(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        verified = b.get("verified", True)
        if not isinstance(verified, bool):
            raise ApiError(400, "bad_request", "verified must be a boolean")
        epoch = b.get("epoch")
        if (epoch is None and verified) or (
            epoch is not None and (not isinstance(epoch, int) or isinstance(epoch, bool))
        ):
            msg = "epoch must be the integer epoch whose short code the human compared"
            raise ApiError(400, "bad_request", msg)
        self.daemon.mark_verified(p["gid"], p["identity"], verified, epoch)
        return {"verified": verified}

    async def _sas_mismatch(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        epoch = b.get("epoch")
        if epoch is not None and (not isinstance(epoch, int) or isinstance(epoch, bool)):
            raise ApiError(400, "bad_request", "epoch must be an integer")
        return {"status": await self.daemon.sas_mismatch(p["gid"], epoch)}

    async def _listing_preview(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        return await self.daemon.listings.preview(b)

    async def _listing_publish(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        return await self.daemon.listings.publish(b)

    async def _listing_withdraw(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        force = b.get("force", False)
        if not isinstance(force, bool):
            raise ApiError(400, "bad_request", "force must be a boolean")
        if not force:
            return await self.agent.withdraw_listing()
        return await self.daemon.listings.withdraw(force=True, human=p.get(SCOPE) == "human")

    async def _listing_status(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        info = await self.agent.listing_status()
        if p.get(SCOPE) == "human" and info["listing"] is not None:
            # Who knocks is the human's to know (docs/discovery.md).
            info["listing"]["pending_knocks"] = self.daemon.knocks.pending()
            info["listing"]["knocks_dropped"] = self.daemon.knocks.dropped
        return info

    async def _knock_inspect(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        return await self.agent.knock_inspect(
            _str(b, "listing"), domain_check=_opt_bool(b, "domain_check")
        )

    async def _knock(self, p: dict[str, str], b: dict[str, Any]) -> Any:
        args: dict[str, Any] = {
            "listing_sha256": _opt_str(b, "listing_sha256"),
            "display_name": _opt_str(b, "display_name"),
            "note": _opt_str(b, "note"),
            "domain_check": _opt_bool(b, "domain_check"),
        }
        if p.get(SCOPE) == "human":
            return await self.daemon.knocks.knock(_str(b, "listing"), human=True, **args)
        return await self.agent.knock(_str(b, "listing"), **args)

    async def _knocks(self, _p: dict[str, str], _b: dict[str, Any]) -> Any:
        return await self.agent.knocks()

    async def _events(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        """Events as JSON (``after``), or, with ``Accept: text/event-stream``,
        the SSE feed of messages and events (``Last-Event-ID`` resumes)."""
        group = p.get("group") or None
        if "text/event-stream" not in p.get(ACCEPT, ""):
            after = int(p.get("after", "0") or 0)
            if p.get(SCOPE) != "human":
                return await self.agent.events(after, group)
            return {"events": self.daemon.store.events(after, group_id=group)}
        hub = self.daemon.adapters.get("sse")
        if not isinstance(hub, SseAdapter):
            raise ApiError(409, "no_sse_adapter", 'set daemon.default_adapter = "sse"')
        if group is not None and self.daemon.store.group(group) is None:
            raise ApiError(404, "not_found", "no such group")
        return SseStream(hub, hub.subscribe(group, p.get(LAST_EVENT_ID)))

    def _queue(self) -> DeliveryQueue:
        queue = self.daemon.adapters.get("mcp")
        if not isinstance(queue, DeliveryQueue):
            raise ApiError(409, "no_deliveries", 'set daemon.default_adapter = "mcp"')
        return queue

    async def _deliveries(self, p: dict[str, str], _b: dict[str, Any]) -> Any:
        addressed = p.get("addressed_only", "0") or "0"
        if addressed not in ("0", "1"):
            raise ApiError(400, "bad_request", "addressed_only must be 0 or 1")
        timeout = _query_int(p, "timeout")
        if timeout > MAX_POLL_SECS:
            raise ApiError(400, "bad_request", f"timeout must be 0..{MAX_POLL_SECS}")
        queue, scope = self._queue(), p.get(SCOPE, "agent")
        if self._polls.get(scope, 0) >= MAX_POLLS:
            msg = f"{MAX_POLLS} polls of this token wait already"
            raise ApiError(429, "busy", msg)
        self._polls[scope] = self._polls.get(scope, 0) + 1

        def done() -> None:
            self._polls[scope] -= 1

        return DeliveryPoll(
            queue,
            self._stopping,
            done,
            group=p.get("group") or None,
            addressed_only=addressed == "1",
            wait_secs=float(timeout),
        )

    async def _deliveries_release(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        queue = self._queue()
        lease = _str(b, "lease")
        ids = b.get("ids")
        if not isinstance(ids, list) or not all(isinstance(x, str) and x.isdigit() for x in ids):
            raise ApiError(400, "bad_request", "ids must be a list of delivery ids")
        queue.release(lease, [int(x) for x in ids])
        return {"released": True}

    async def _deliveries_ack(self, _p: dict[str, str], b: dict[str, Any]) -> Any:
        queue = self._queue()
        lease = _str(b, "lease")
        ids = b.get("ids")
        if not isinstance(ids, list) or not all(isinstance(x, str) and x.isdigit() for x in ids):
            raise ApiError(400, "bad_request", "ids must be a list of delivery ids")
        done = {str(d) for d in queue.ack(lease, [int(x) for x in ids])}
        return {"acked": len(done), "refused": [x for x in ids if x not in done]}

    # -- HTTP --------------------------------------------------------------

    def _authorize(self, headers: dict[str, str], human: bool) -> str:
        """Check the bearer token; returns the scope (``agent`` or ``human``)."""
        bearer_header = headers.get("authorization", "")
        scheme, _, token = bearer_header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ApiError(401, "auth_failed", "missing bearer token")
        is_human = self._tokens["human"].matches(token)
        is_agent = self._tokens["agent"].matches(token)
        if not (is_human or is_agent):
            raise ApiError(401, "auth_failed", "invalid token")
        if is_human and not self.gate.human_allowed():
            raise ApiError(403, "peer_refused", "the human token is not accepted from this user")
        if human and not is_human:
            raise ApiError(403, "human_only", "this operation needs the human token")
        return "human" if is_human else "agent"

    async def handle(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        body: bytes,
        conn: Connection | None = None,
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
            if scope == "agent" and conn is not None:
                if self._agent_requests >= MAX_AGENT_REQUESTS:
                    raise ApiError(503, "busy", "too many agent requests")
                self._agent_requests += 1
                conn.agent = True
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
        if isinstance(self.address, Path):
            # Used, so /tmp cleaners don't age it out (sockets.py).
            with contextlib.suppress(OSError):
                os.utime(self.address)
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
        conn = Connection()
        try:
            status, payload = await self._request(reader, conn)
            if isinstance(payload, DeliveryPoll):
                answer = await payload.run(reader)
                if answer is None:
                    return
                payload = answer
            if isinstance(payload, SseStream):
                self._streams.add(payload)
                try:
                    await payload.run(reader, writer)
                finally:
                    self._streams.discard(payload)
                return
            await self._reply(writer, status, payload)
        finally:
            if conn.agent:
                self._agent_requests -= 1
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

    async def _request(
        self, reader: asyncio.StreamReader, conn: Connection | None = None
    ) -> tuple[int, Any]:
        status, payload = 500, {"code": "internal", "message": "internal error"}
        try:
            async with asyncio.timeout(READ_TIMEOUT):
                method, target, headers, body = await self._read(reader)
            self._check_origin(headers)
            status, payload = await self.handle(method, target, headers, body, conn)
        except TimeoutError:
            status, payload = 408, {"code": "timeout", "message": "request not received in time"}
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            status, payload = 400, {"code": "bad_request", "message": "malformed request"}
        except Exception as e:
            reply = error_reply(e)
            if reply is None:
                LOG.exception("api_failed")
            else:
                status, code, message = reply
                payload = {"code": code, "message": message}
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
            # A configured path over the platform's limit binds at a short
            # private path the CLI and SDK derive the same way (sockets.py).
            path = bind_path(cfg.socket_path)
            if path != cfg.socket_path:
                prepare_bind_dir(path)
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
        self._stopping.set()
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
