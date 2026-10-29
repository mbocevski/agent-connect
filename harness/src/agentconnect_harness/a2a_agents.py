"""A2A v1.0 server agents for tests, built on ``a2a-sdk`` and served on
loopback (``127.0.0.1``, a free port).

* :class:`HelloWorldExecutor` behaves like a2a-python's helloworld sample:
  every message gets the reply ``Hello World``.
* :class:`ScriptedExecutor` picks a behaviour from the first word of the
  last text part:

  - ``stream``: a task that streams ``working``, two artifact chunks and
    ``completed``;
  - ``ask``: a task that stops in ``input-required``; the follow-up on that
    task completes it with ``thanks, <text>``;
  - ``wait``: a task that stays ``working`` until it is canceled;
  - ``many <n>``: a task that streams ``n`` artifact chunks;
  - anything else: one message, ``echo: <text>``.

Both record every request they get (``received``), so tests can check what
the agent saw.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, override

import uvicorn
from a2a.helpers.proto_helpers import new_task
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
    TaskState,
)
from starlette.applications import Starlette
from starlette.responses import JSONResponse

from agentconnect.a2a_adapter import A2AAdapter, A2AOptions
from agentconnect.a2a_adapter.serve import LoopbackServer
from agentconnect_harness.cluster import Cluster, Node


@dataclass
class Seen:
    """One request as the agent got it."""

    message: Message
    task_id: str
    context_id: str
    continued: bool  # a follow-up on an existing task


def _text(msg: Message | None) -> str:
    if msg is None:
        return ""
    texts = [p.text for p in msg.parts if p.HasField("text")]
    return texts[-1] if texts else ""


def _reply(text: str, context_id: str, task_id: str = "") -> Message:
    return Message(
        role=Role.ROLE_AGENT,
        message_id=f"reply-{task_id or context_id}-{len(text)}",
        parts=[Part(text=text)],
        context_id=context_id,
        task_id=task_id,
    )


@dataclass
class _Recorder:
    received: list[Seen] = field(default_factory=list)
    canceled: list[str] = field(default_factory=list)
    changed: asyncio.Event = field(default_factory=asyncio.Event)

    def record(self, context: RequestContext) -> None:
        self.received.append(
            Seen(
                context.message or Message(),
                context.task_id or "",
                context.context_id or "",
                context.current_task is not None,
            )
        )
        self.changed.set()

    async def wait_for(self, n: int, within: float = 8.0) -> list[Seen]:
        async def loop() -> None:
            while len(self.received) < n:
                self.changed.clear()
                await self.changed.wait()

        await asyncio.wait_for(loop(), within)
        return self.received

    async def wait_canceled(self, n: int, within: float = 8.0) -> list[str]:
        async def loop() -> None:
            while len(self.canceled) < n:
                self.changed.clear()
                await self.changed.wait()

        await asyncio.wait_for(loop(), within)
        return self.canceled


class HelloWorldExecutor(AgentExecutor, _Recorder):
    def __init__(self) -> None:
        _Recorder.__init__(self)

    @override
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.record(context)
        await event_queue.enqueue_event(_reply("Hello World", context.context_id or ""))

    @override
    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError


class ScriptedExecutor(AgentExecutor, _Recorder):
    def __init__(self) -> None:
        _Recorder.__init__(self)

    @override
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.record(context)
        text = _text(context.message)
        word = text.split(" ", 1)[0]
        task_id, context_id = context.task_id or "", context.context_id or ""
        updater = TaskUpdater(event_queue, task_id, context_id)
        if context.current_task is not None:
            await updater.complete(_reply(f"thanks, {text}", context_id, task_id))
            return
        if word not in ("stream", "ask", "wait", "many"):
            await event_queue.enqueue_event(_reply(f"echo: {text}", context_id))
            return
        history = [] if context.message is None else [context.message]
        await event_queue.enqueue_event(
            new_task(task_id, context_id, TaskState.TASK_STATE_SUBMITTED, history=history)
        )
        await updater.start_work()
        if word == "stream":
            await updater.add_artifact([Part(text="part one")], artifact_id="a1", name="result")
            await updater.add_artifact(
                [Part(text="part two")], artifact_id="a1", append=True, last_chunk=True
            )
            await updater.complete()
        elif word == "many":
            n = int(text.split(" ")[1])
            for i in range(n):
                await updater.add_artifact(
                    [Part(text=f"chunk {i}")], artifact_id="a1", append=i > 0, last_chunk=i == n - 1
                )
            await updater.complete()
        elif word == "ask":
            await updater.requires_input(_reply("which one?", context_id, task_id))
        else:
            await asyncio.Event().wait()  # until canceled

    @override
    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.canceled.append(context.task_id or "")
        self.changed.set()
        updater = TaskUpdater(event_queue, context.task_id or "", context.context_id or "")
        await updater.cancel()


class _BearerOnly:
    """Require ``Authorization: Bearer <token>`` on every request."""

    def __init__(self, app: Any, token: str) -> None:
        self._app, self._token = app, token

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            given = headers.get("authorization", "").removeprefix("Bearer ")
            if not hmac.compare_digest(given.encode(), self._token.encode()):
                await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
                return
        await self._app(scope, receive, send)


class _UnixServer(LoopbackServer):
    """:class:`LoopbackServer` on a Unix socket at ``path`` instead."""

    def __init__(self, app: Any, path: Path) -> None:
        super().__init__(app)
        self._path = path

    @override
    async def start(self) -> int:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self._path))
        config = uvicorn.Config(
            self._app, lifespan="off", access_log=False, log_level="warning", log_config=None
        )
        config.load()
        server = uvicorn.Server(config)
        server.lifespan = config.lifespan_class(config)
        await server.startup(sockets=[sock])
        self._server = server
        return 0


class AgentServer:
    """An A2A agent on ``127.0.0.1``, or on a Unix socket at ``uds``
    (its card then names ``url``). ``card_url`` makes the card name
    another endpoint than the one it is served from; ``bindings`` are the
    protocol bindings its card lists, one interface each."""

    def __init__(  # noqa: PLR0913
        self,
        executor: AgentExecutor,
        name: str,
        skills: list[str] | None = None,
        streaming: bool = True,
        token: str | None = None,
        *,
        uds: Path | None = None,
        url: str = "http://localhost/",
        card_url: str | None = None,
        bindings: tuple[str, ...] = ("JSONRPC",),
    ) -> None:
        self.executor = executor
        self.uds, self._card_url = uds, card_url
        self._bindings = bindings
        self._uds_url = url
        self.name = name
        self._skills = skills or ["chat"]
        self._streaming = streaming
        self._token = token
        self._server: LoopbackServer | None = None
        self.url = ""
        self.card = AgentCard()

    async def start(self) -> str:
        holder: dict[str, Any] = {}

        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            await holder["app"](scope, receive, send)

        root: Any = app if self._token is None else _BearerOnly(app, self._token)
        if self.uds is not None:
            self._server = _UnixServer(root, self.uds)
            await self._server.start()
            self.url = self._uds_url
        else:
            self._server = LoopbackServer(root)
            port = await self._server.start()
            self.url = f"http://127.0.0.1:{port}/"
        self.card = AgentCard(
            name=self.name,
            description=f"{self.name}, a test agent",
            version="1.0.0",
            supported_interfaces=[
                AgentInterface(
                    url=self._card_url or self.url, protocol_binding=b, protocol_version="1.0"
                )
                for b in self._bindings
            ],
            capabilities=AgentCapabilities(streaming=self._streaming),
            default_input_modes=["text/plain"],
            default_output_modes=["text/plain"],
            skills=[
                AgentSkill(id=s, name=s, description=f"{s} skill", tags=[s]) for s in self._skills
            ],
        )
        handler = DefaultRequestHandler(
            agent_executor=self.executor, task_store=InMemoryTaskStore(), agent_card=self.card
        )
        routes = create_agent_card_routes(self.card) + create_jsonrpc_routes(handler, "/")
        holder["app"] = Starlette(routes=routes)
        holder["handler"] = handler
        self._holder = holder
        return self.url

    async def stop(self) -> None:
        if self._server is not None:
            await self._holder["handler"].aclose()
            await self._server.stop()
            self._server = None


async def a2a_node(
    cluster: Cluster,
    name: str,
    agent: AgentServer | None = None,
    *,
    facade: bool = False,
    facade_socket: Path | None = None,
    **kw: Any,
) -> Node:
    """A daemon whose groups deliver to an A2A adapter: bridged to ``agent``,
    with a facade on a free loopback port when ``facade`` is set, or on
    the Unix socket ``facade_socket``, open to this user."""

    def make(config: Any, _clock: Any) -> list[Any]:
        options = A2AOptions(
            local_agent_url=None if agent is None else agent.url,
            local_agent_socket=None if agent is None else agent.uds,
            receiver_uids=frozenset({os.geteuid()}),
            facade_port=0 if facade and facade_socket is None else None,
            facade_socket=facade_socket,
            facade_uids=frozenset({os.geteuid()}),
            data_dir=config.data_dir,
        )
        return [A2AAdapter(options)]

    return await cluster.node(name, default_adapter="a2a", make_adapters=make, **kw)


def a2a_of(node: Node) -> A2AAdapter:
    """The node's A2A adapter."""
    adapter = node.daemon.adapters["a2a"]
    if not isinstance(adapter, A2AAdapter):
        msg = "not an A2A node"
        raise TypeError(msg)
    return adapter
