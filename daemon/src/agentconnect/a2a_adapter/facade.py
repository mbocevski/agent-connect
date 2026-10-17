"""Direction 2: a local A2A client talks to a group through an A2A server
facade on ``127.0.0.1``.

* ``/g/<group_id>/``: the group. A 1:1 group's card mirrors the peer's; a
  larger group's is a composite of the members' skills. Address members with
  ``metadata.to`` (a list of identities); without it a message goes to
  ``["*"]``, which in ``mention`` mode triggers nobody (SPEC §9.3).
* ``/g/<group_id>/m/<identity>/``: one member; messages go to it alone.

Each path serves the JSON-RPC binding at its root and its card at
``.well-known/agent-card.json``. Every request needs
``Authorization: Bearer <a2a-facade-token>``, a loopback client, a ``Host``
of ``127.0.0.1:<port>`` or ``localhost:<port>``, and no ``Origin`` (a
browser page can't reach it).

Tasks are namespaced by group: each group has its own task store, and a
message's ``contextId`` must be the group (or empty). The facade's task ids
are its own; the peer's ``taskId`` is kept end to end behind them (follow-ups
on an ``input-required`` task carry it) and is reported in each event's
``metadata.remote_task_id``. ``GetTask``, ``CancelTask``, ``SubscribeToTask``
and push-notification configs are served by ``a2a-sdk``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, override
from urllib.parse import unquote

import httpx
from a2a.helpers.proto_helpers import new_task
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.agent_execution.simple_request_context_builder import (
    SimpleRequestContextBuilder,
)
from a2a.server.context import ServerCallContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_jsonrpc_routes
from a2a.server.tasks import (
    BasePushNotificationSender,
    InMemoryPushNotificationConfigStore,
    InMemoryTaskStore,
)
from a2a.types import (
    AgentCard,
    Message,
    Role,
    SendMessageRequest,
    Task,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
)
from a2a.utils.errors import InvalidParamsError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from agentconnect import log
from agentconnect.a2a_adapter import cards, convert
from agentconnect.a2a_adapter.serve import LoopbackServer

if TYPE_CHECKING:
    from agentconnect.a2a_adapter.adapter import A2AAdapter
    from agentconnect.adapter import Delivery

LOG = log.get("a2a.facade")
CARD_PATH = "/.well-known/agent-card.json"
MAX_TO = 50
MAX_GROUPS = 256  # facade apps kept; the oldest is dropped beyond this
GROUP_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


@dataclass
class Bound:
    """A facade task's peer side: who answers it and under which task id."""

    responder: str
    remote_task_id: str


class _GroupContext(SimpleRequestContextBuilder):
    """``contextId`` is the group: an empty one becomes the group, another
    one is refused (tasks never cross groups)."""

    def __init__(self, group_id: str) -> None:
        super().__init__()
        self._group_id = group_id

    @override
    async def build(
        self,
        context: ServerCallContext,
        params: SendMessageRequest | None = None,
        task_id: str | None = None,
        context_id: str | None = None,
        task: Task | None = None,
    ) -> RequestContext:
        if context_id not in (None, "", self._group_id):
            raise InvalidParamsError(message="contextId must be this group's id")
        if params is not None:
            params.message.context_id = self._group_id
        return await super().build(context, params, task_id, self._group_id, task)


def _to_list(raw: Any) -> list[str] | None:
    if isinstance(raw, str) and raw:
        return [raw]
    if isinstance(raw, list) and 0 < len(raw) <= MAX_TO and all(isinstance(x, str) for x in raw):
        return [str(x) for x in raw]
    return None


class BridgeExecutor(AgentExecutor):
    """Runs one facade request: sends it to the group and turns the peer's
    replies (``reply_to`` naming it) into task events."""

    def __init__(self, facade: Facade, group_id: str, member: str | None) -> None:
        self._facade = facade
        self._group_id = group_id
        self._member = member

    def _recipients(self, msg: Message) -> list[str]:
        if self._member is not None:
            return [self._member]
        meta = convert.to_json(msg).get("metadata")
        to = _to_list(meta.get("to")) if isinstance(meta, dict) else None
        return to or ["*"]

    @override
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        msg = context.message
        task_id = context.task_id or ""
        if msg is None or not task_id:
            return
        bound = self._facade.bound.get(task_id)
        body = convert.to_json(msg)
        body["contextId"] = self._group_id
        body.pop("taskId", None)
        if bound is not None:
            body["taskId"] = bound.remote_task_id
        to = [bound.responder] if bound is not None else self._recipients(msg)
        replies: asyncio.Queue[Delivery] = asyncio.Queue()
        try:
            msg_id = await self._facade.adapter.send_to_group(self._group_id, body, to)
        except Exception as e:
            code = getattr(e, "code", type(e).__name__)
            await self._start_task(context, event_queue)
            await self._status(
                event_queue, context, TaskState.TASK_STATE_FAILED, f"not sent: {code}"
            )
            return
        self._facade.waiters[msg_id] = replies
        task_mode = context.current_task is not None
        try:
            async with asyncio.timeout(self._facade.adapter.options.reply_timeout):
                while True:
                    d = await replies.get()
                    if bound is not None and d.sender.identity != bound.responder:
                        continue  # the task is bound to its first responder
                    if d.kind == "a2a.message" and not task_mode:
                        reply = convert.parse_message(d.body)
                        reply.role = Role.ROLE_AGENT
                        reply.context_id = self._group_id
                        reply.ClearField("task_id")
                        self._facade.tag(reply, d, "")
                        await event_queue.enqueue_event(reply)
                        return
                    if not task_mode:
                        await self._start_task(context, event_queue)
                        task_mode = True
                    done, bound = await self._forward(context, event_queue, d, bound)
                    if done:
                        return
        except TimeoutError:
            if not task_mode:
                await self._start_task(context, event_queue)
            await self._status(event_queue, context, TaskState.TASK_STATE_FAILED, "no reply")
        finally:
            self._facade.waiters.pop(msg_id, None)

    async def _forward(
        self, context: RequestContext, queue: EventQueue, d: Delivery, bound: Bound | None
    ) -> tuple[bool, Bound | None]:
        task_id = context.task_id or ""
        if d.kind == "a2a.task_status":
            event = convert.parse_status(d.body)
            if event is None:
                return False, bound
            if bound is None and event.task_id:
                bound = Bound(d.sender.identity, event.task_id)
                self._facade.bound[task_id] = bound
            remote = event.task_id
            event.task_id, event.context_id = task_id, self._group_id
            self._facade.tag(event, d, remote)
            await queue.enqueue_event(event)
            state = event.status.state
            return state in convert.TERMINAL | convert.INTERRUPTED, bound
        if d.kind == "a2a.task_artifact":
            art = convert.parse_artifact(d.body)
            if art is None:
                return False, bound
            remote = art.task_id
            art.task_id, art.context_id = task_id, self._group_id
            self._facade.tag(art, d, remote)
            await queue.enqueue_event(art)
            return False, bound
        if d.kind == "a2a.message":
            # A plain reply inside task mode completes the task with it.
            reply = convert.parse_message(d.body)
            reply.role = Role.ROLE_AGENT
            reply.context_id = self._group_id
            reply.task_id = task_id
            event = TaskStatusUpdateEvent(
                task_id=task_id,
                context_id=self._group_id,
                status=TaskStatus(state=TaskState.TASK_STATE_COMPLETED, message=reply),
            )
            self._facade.tag(event, d, "")
            await queue.enqueue_event(event)
            return True, bound
        return False, bound

    async def _start_task(self, context: RequestContext, queue: EventQueue) -> None:
        if context.current_task is not None or context.message is None:
            return
        task = new_task(
            context.task_id or "",
            self._group_id,
            TaskState.TASK_STATE_SUBMITTED,
            history=[context.message],
        )
        await queue.enqueue_event(task)

    async def _status(
        self, queue: EventQueue, context: RequestContext, state: TaskState, text: str
    ) -> None:
        event = TaskStatusUpdateEvent(
            task_id=context.task_id or "",
            context_id=self._group_id,
            status=TaskStatus(state=state, message=convert.agent_text(text, self._group_id)),
        )
        await queue.enqueue_event(event)

    @override
    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id = context.task_id or ""
        bound = self._facade.bound.get(task_id)
        if bound is not None:
            body = convert.cancel_body(bound.remote_task_id, self._group_id)
            try:
                await self._facade.adapter.send_to_group(
                    self._group_id, body, [bound.responder], kind="a2a.task_status"
                )
            except Exception as e:
                LOG.info("a2a_cancel_not_sent", error=type(e).__name__)
        event = TaskStatusUpdateEvent(
            task_id=task_id,
            context_id=self._group_id,
            status=TaskStatus(state=TaskState.TASK_STATE_CANCELED),
        )
        await event_queue.enqueue_event(event)


class _GroupApps:
    """One group's task store and push-config store, shared by the group's
    path and its member paths."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self.tasks = InMemoryTaskStore()
        self.push = InMemoryPushNotificationConfigStore()
        self.sender = BasePushNotificationSender(http, self.push)
        self.apps: dict[str | None, Any] = {}
        self.handlers: list[DefaultRequestHandler] = []


class Facade:
    def __init__(self, adapter: A2AAdapter, token: str, port: int) -> None:
        self.adapter = adapter
        self._token = token
        self._server = LoopbackServer(self, port)
        self._groups: dict[str, _GroupApps] = {}
        self._http = httpx.AsyncClient(timeout=10.0)
        # msg_id sent by the facade -> the request waiting for replies to it
        self.waiters: dict[str, asyncio.Queue[Delivery]] = {}
        # facade task id -> its peer side
        self.bound: dict[str, Bound] = {}

    @property
    def port(self) -> int:
        return self._server.port

    def listening(self) -> list[tuple[str, int]]:
        return self._server.addresses()

    def url(self, group_id: str, member: str | None = None) -> str:
        base = f"http://127.0.0.1:{self.port}/g/{group_id}/"
        return base if member is None else f"{base}m/{member}/"

    async def start(self) -> None:
        await self._server.start()

    async def stop(self) -> None:
        for group in self._groups.values():
            for handler in group.handlers:
                with contextlib.suppress(Exception):
                    await handler.aclose()
        await self._server.stop()
        await self._http.aclose()

    def route_reply(self, d: Delivery) -> bool:
        """Hand a reply to the facade request it answers; False if none."""
        refs = d.inner.get("reply_to")
        if not isinstance(refs, list):
            return False
        for ref in refs:
            queue = self.waiters.get(ref) if isinstance(ref, str) else None
            if queue is not None:
                queue.put_nowait(d)
                return True
        return False

    @staticmethod
    def tag(event: Any, d: Delivery, remote_task_id: str) -> None:
        """Say who answered (SPEC §10.1 framing), on an event's metadata."""
        meta: dict[str, Any] = {
            "untrusted": True,
            "sender": d.sender.identity,
            "sender_name": d.sender.display_name or "",
            "sender_verified": d.sender.verified,
            "scope": d.scope,
            "msg_id": d.msg_id,
        }
        if remote_task_id:
            meta["remote_task_id"] = remote_task_id
        event.metadata.update(meta)

    # -- cards -------------------------------------------------------------

    def card(self, group_id: str, member: str | None) -> AgentCard:
        known = self.adapter.peer_cards(group_id)
        names = {i: c.name for i, c in known.items()}
        url = self.url(group_id, member)
        info = self.adapter.group_info(group_id)
        if member is not None:
            return cards.facade_card(url, member, "", [], known.get(member))
        peers = self.adapter.peers(group_id)
        if len(peers) == 1 and next(iter(peers)) in known:
            return cards.facade_card(url, "", "", [], known[next(iter(peers))])
        name = info.name if info is not None else "AgentConnect group"
        purpose = info.purpose if info is not None else ""
        return cards.facade_card(url, name, purpose, cards.composite_skills(known, names))

    # -- ASGI --------------------------------------------------------------

    def _app(self, group_id: str, member: str | None) -> Any:
        group = self._groups.get(group_id)
        if group is None:
            if len(self._groups) >= MAX_GROUPS:
                self._groups.pop(next(iter(self._groups)))
            group = self._groups[group_id] = _GroupApps(self._http)
        app = group.apps.get(member)
        if app is not None:
            return app
        handler = DefaultRequestHandler(
            agent_executor=BridgeExecutor(self, group_id, member),
            task_store=group.tasks,
            agent_card=cards.facade_card(self.url(group_id, member), "", "", []),
            push_config_store=group.push,
            push_sender=group.sender,
            request_context_builder=_GroupContext(group_id),
        )
        group.handlers.append(handler)

        async def card_route(_request: Request) -> Response:
            return JSONResponse(convert.to_json(self.card(group_id, member)))

        routes = [Route(CARD_PATH, card_route, methods=["GET"])]
        routes.extend(create_jsonrpc_routes(handler, "/"))
        app = Starlette(routes=routes)
        group.apps[member] = app
        return app

    def _refuse(self, scope: dict[str, Any]) -> tuple[int, str] | None:
        client = scope.get("client")
        if not client or client[0] not in ("127.0.0.1", "::1"):
            return 403, "loopback only"
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        if "origin" in headers:
            return 403, "browser requests are refused"
        if headers.get("host") not in (f"127.0.0.1:{self.port}", f"localhost:{self.port}"):
            return 403, "bad host"
        scheme, _, token = headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            token.encode(), self._token.encode()
        ):
            return 401, "missing or invalid bearer token"
        return None

    @staticmethod
    def _split(path: str) -> tuple[str, str | None, str] | None:
        """``/g/<group>[/m/<member>]<rest>`` -> (group, member, rest)."""
        parts = path.split("/")
        if len(parts) < 3 or parts[0] != "" or parts[1] != "g":  # noqa: PLR2004
            return None
        if not GROUP_ID.fullmatch(parts[2]):
            return None
        group, rest = parts[2], parts[3:]
        member = None
        if len(rest) >= 2 and rest[0] == "m" and rest[1]:  # noqa: PLR2004
            member, rest = unquote(rest[1]), rest[2:]
        return group, member, "/" + "/".join(rest)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        refused = self._refuse(scope)
        target = self._split(scope["path"]) if refused is None else None
        if refused is None and target is None:
            refused = (404, "not found")
        if refused is not None or target is None:
            status, text = refused or (404, "not found")
            await JSONResponse({"error": text}, status_code=status)(scope, receive, send)
            return
        group_id, member, rest = target
        inner = dict(scope)
        inner["path"] = rest
        inner["raw_path"] = rest.encode()
        await self._app(group_id, member)(inner, receive, send)
