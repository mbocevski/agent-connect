"""The SDK client: run the runtime in-process, or talk to a separate daemon.

Two modes, one API (ADR-005):

* :meth:`AgentConnect.embedded` (the default to reach for): the runtime runs
  inside this process, on this asyncio loop. Deliveries are direct
  callbacks; there is no daemon to install, start or supervise, and no
  second process holds the keys.
* :meth:`AgentConnect.attach` (or ``AgentConnect()``): talk to a separate
  daemon over its local API, and receive its webhook or SSE stream.

Both modes have the same at-least-once delivery with ``msg_id`` /
``event_id`` deduplication, and the same untrusted framing.

Security model: agent code gets the **agent-scope** operations and nothing
more. It can create groups and invites, send messages and read events. It
cannot approve joins, mark members verified, relax verification, change the
safety policy or send ``control.resume``: those are the human's, through the
CLI and the human token, which this package never reads and never exposes.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeVar, override

import httpx

from agentconnect_sdk import _log
from agentconnect_sdk.dedupe import Deduper
from agentconnect_sdk.errors import AgentConnectError, PayloadError
from agentconnect_sdk.models import Event, Message, idempotency_key, parse_payload
from agentconnect_sdk.receiver import WebhookReceiver, iter_sse
from agentconnect_sdk.settings import (
    API_TOKEN_FILE,
    WEBHOOK_SECRET_FILE,
    Settings,
    load_settings,
    read_secret,
)
from agentconnect_sdk.signature import DEFAULT_TOLERANCE, WebhookVerifier

if TYPE_CHECKING:
    from agentconnect_sdk.embedded import EmbeddedHost

MAX_NAME = 80  # SPEC 4.2: group names are 1 to 80 characters
RECONNECT_DELAY = 2.0
MAX_RECONNECT_DELAY = 30.0

MessageHandler = Callable[[Message, "Group"], Awaitable[None]]
EventHandler = Callable[[Event, "Group | None"], Awaitable[None]]
H = TypeVar("H")


class TaskState:
    """A2A v1.0 task states, as they appear in JSON."""

    SUBMITTED = "TASK_STATE_SUBMITTED"
    WORKING = "TASK_STATE_WORKING"
    INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
    COMPLETED = "TASK_STATE_COMPLETED"
    CANCELED = "TASK_STATE_CANCELED"
    FAILED = "TASK_STATE_FAILED"
    REJECTED = "TASK_STATE_REJECTED"


class Operations(Protocol):
    """The agent-scope operations, the same in both modes. Each answer has
    the shape of the matching local API route (``docs/api.md``)."""

    async def status(self) -> dict[str, Any]: ...
    async def create_group(self, name: str, purpose: str) -> dict[str, Any]: ...
    async def list_groups(self) -> dict[str, Any]: ...
    async def group_info(self, group_id: str) -> dict[str, Any]: ...
    async def create_invite(
        self, group_id: str, max_uses: int, ttl_secs: int
    ) -> dict[str, Any]: ...
    async def send(self, group_id: str, message: dict[str, Any]) -> dict[str, Any]: ...
    async def leave(self, group_id: str) -> dict[str, Any]: ...
    async def accept(self, url: str, display_name: str | None) -> dict[str, Any]: ...


def _parts(content: str | Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(content, str):
        return [{"text": content}]
    return [dict(p) for p in content]


def _agent_message(
    group_id: str,
    content: str | Sequence[Mapping[str, Any]],
    *,
    task_id: str | None = None,
    context_id: str | None = None,
) -> dict[str, Any]:
    """An A2A v1.0 ``Message`` from this agent. With ``task_id`` it is a
    follow-up on that task (A2A: a message that continues a task carries
    its ``taskId`` and ``contextId``)."""
    message = {
        "messageId": secrets.token_hex(16),
        "contextId": context_id or group_id,
        "role": "ROLE_AGENT",
        "parts": _parts(content),
    }
    if task_id is not None:
        if not isinstance(task_id, str) or not task_id:
            raise AgentConnectError("bad_request", "task_id must be a non-empty string", 400)
        message["taskId"] = task_id
    return message


def _task_of(msg: Message) -> tuple[str, str] | None:
    """The task a task status or artifact update is about: its ``taskId``
    and ``contextId``. ``None`` for any other message."""
    if msg.event not in ("task_status", "task_artifact"):
        return None
    task_id, context_id = msg.a2a.get("taskId"), msg.a2a.get("contextId")
    if not isinstance(task_id, str) or not task_id:
        return None
    return task_id, context_id if isinstance(context_id, str) and context_id else ""


def _task_for(msg: Message) -> str:
    """The task an answer to ``msg`` is about: its own ``taskId``, else one
    derived from its ``msg_id``, the same for every answer to it."""
    own = msg.a2a.get("taskId")
    if isinstance(own, str) and own:
        return own
    return "task-" + hashlib.sha256(msg.msg_id.encode()).hexdigest()[:16]


class Group:
    """One group, bound to the client that opened it."""

    def __init__(self, client: AgentConnect, group_id: str) -> None:
        self._client = client
        self.id = group_id

    @override
    def __repr__(self) -> str:
        return f"Group({self.id!r})"

    async def info(self) -> dict[str, Any]:
        """The runtime's view: members, policy, trust state, short code."""
        return await self._client._ops.group_info(self.id)

    async def invite(self, max_uses: int = 1, ttl_secs: int = 86_400) -> str:
        """Create an invite link. Share it with the other human; whoever
        redeems it still needs your human's approval."""
        reply = await self._client._ops.create_invite(self.id, max_uses, ttl_secs)
        return str(reply["url"])

    async def send(
        self,
        content: str | Sequence[Mapping[str, Any]],
        *,
        to: Sequence[str] = ("*",),
        reply_to: Sequence[str] = (),
        instance: str | None = None,
        task_id: str | None = None,
    ) -> str:
        """Send an A2A message (text, or a list of ``text``/``data`` parts).
        Returns its ``msg_id``. In a ``mention`` group only the identities in
        ``to`` are triggered. ``instance`` (an instance id, 16 lowercase hex)
        narrows that to one instance of them (SPEC section 9.4); every
        instance still receives the message. ``task_id`` makes it a
        follow-up on that task of a peer's agent, such as the answer to an
        ``input-required`` status: the peer's A2A adapter continues the task
        if its requester sends it (``reply`` does this for you)."""
        body = _agent_message(self.id, content, task_id=task_id)
        return await self._post("a2a.message", body, to, reply_to, instance=instance)

    async def reply(self, msg: Message, content: str | Sequence[Mapping[str, Any]]) -> str:
        """Answer ``msg``: to the whole group, with its sender as the only
        ``addressee`` (SPEC section 9.3) and its sending instance as the
        instance hint (SPEC section 9.4), so everyone sees the answer and only
        the instance that asked is triggered. ``reply_to`` carries
        ``msg.msg_id``, so the runtime sets ``hop`` (SPEC section 10.3) and
        the loop guard can stop a runaway exchange. An answer to a task
        status or artifact update (``msg.event`` ``task_status`` or
        ``task_artifact``) carries that task's ``taskId`` and ``contextId``,
        so it continues the task, as the answer to ``input-required`` must;
        an answer to a plain message names no task."""
        task = _task_of(msg)
        if task is None:
            body = _agent_message(self.id, content)
        else:
            body = _agent_message(self.id, content, task_id=task[0], context_id=task[1] or None)
        return await self._answer(msg, "a2a.message", body)

    async def reply_status(
        self,
        msg: Message,
        state: str,
        text: str | None = None,
        *,
        task_id: str | None = None,
    ) -> str:
        """Send an A2A ``TaskStatusUpdateEvent`` for the task ``msg`` started
        (``state``: a :class:`TaskState`). ``task_id`` defaults to the
        message's own ``taskId``, else one derived from ``msg``, so every
        update answering one message is about one task (the requester grants
        one task per request, SPEC section 9.3)."""
        status: dict[str, Any] = {"state": state}
        if text is not None:
            status["message"] = _agent_message(self.id, text)
        body = {
            "taskId": task_id or _task_for(msg),
            "contextId": self.id,
            "status": status,
        }
        return await self._answer(msg, "a2a.task_status", body)

    async def reply_artifact(  # noqa: PLR0913
        self,
        msg: Message,
        content: str | Sequence[Mapping[str, Any]],
        *,
        name: str | None = None,
        task_id: str | None = None,
        artifact_id: str | None = None,
        append: bool = False,
        last_chunk: bool = True,
    ) -> str:
        """Send an A2A ``TaskArtifactUpdateEvent`` (a result for a task).
        ``task_id`` defaults as for :meth:`reply_status`."""
        artifact: dict[str, Any] = {
            "artifactId": artifact_id or secrets.token_hex(8),
            "parts": _parts(content),
        }
        if name is not None:
            artifact["name"] = name
        body = {
            "taskId": task_id or _task_for(msg),
            "contextId": self.id,
            "artifact": artifact,
            "append": append,
            "lastChunk": last_chunk,
        }
        return await self._answer(msg, "a2a.task_artifact", body)

    async def leave(self) -> str:
        reply = await self._client._ops.leave(self.id)
        return str(reply["status"])

    async def _answer(self, msg: Message, kind: str, body: dict[str, Any]) -> str:
        return await self._post(
            kind,
            body,
            ["*"],
            [msg.msg_id],
            addressee=[msg.sender.identity],
            instance=msg.sender.instance_id,
        )

    async def _post(  # noqa: PLR0913
        self,
        kind: str,
        body: dict[str, Any],
        to: Sequence[str],
        reply_to: Sequence[str],
        *,
        addressee: Sequence[str] | None = None,
        instance: str | None = None,
    ) -> str:
        message: dict[str, Any] = {"kind": kind, "body": body, "to": list(to)}
        if reply_to:
            message["reply_to"] = list(reply_to)
        if addressee is not None:
            message["addressee"] = list(addressee)
        if instance is not None:
            message["instance"] = instance
        reply = await self._client._ops.send(self.id, message)
        return str(reply["msg_id"])


class _HttpOperations:
    """The operations over a separate daemon's local API (attach mode)."""

    def __init__(self, client: AgentConnect) -> None:
        self._client = client

    async def status(self) -> dict[str, Any]:
        return await self._client._request("GET", "/v0/status")

    async def create_group(self, name: str, purpose: str) -> dict[str, Any]:
        return await self._client._request("POST", "/v0/groups", {"name": name, "purpose": purpose})

    async def list_groups(self) -> dict[str, Any]:
        return await self._client._request("GET", "/v0/groups")

    async def group_info(self, group_id: str) -> dict[str, Any]:
        return await self._client._request("GET", f"/v0/groups/{group_id}")

    async def create_invite(self, group_id: str, max_uses: int, ttl_secs: int) -> dict[str, Any]:
        body = {"max_uses": max_uses, "ttl_secs": ttl_secs}
        return await self._client._request("POST", f"/v0/groups/{group_id}/invites", body)

    async def send(self, group_id: str, message: dict[str, Any]) -> dict[str, Any]:
        return await self._client._request("POST", f"/v0/groups/{group_id}/messages", message)

    async def leave(self, group_id: str) -> dict[str, Any]:
        return await self._client._request("POST", f"/v0/groups/{group_id}/leave")

    async def accept(self, url: str, display_name: str | None) -> dict[str, Any]:
        body: dict[str, Any] = {"url": url}
        if display_name is not None:
            body["display_name"] = display_name
        return await self._client._request("POST", "/v0/invites/accept", body)


class AgentConnect:
    """A headless agent's connection to AgentConnect.

    ``AgentConnect.embedded(name="my-agent")`` runs the runtime in this
    process; see :meth:`embedded`. ``AgentConnect()`` (or
    :meth:`attach`) talks to a separate daemon instead: it finds the daemon
    the way the CLI does (config file, ``AC_DATA_DIR``) and reads
    ``api-token`` from its data directory. Pass ``data_dir``, ``socket``,
    ``tcp_port`` or ``token`` to point elsewhere.
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        data_dir: Path | None = None,
        socket: Path | None = None,
        tcp_port: int | None = None,
        token: str | None = None,
        webhook_secret: str | None = None,
        config_path: Path | None = None,
        dedupe: Deduper | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        tolerance: float = DEFAULT_TOLERANCE,
    ) -> None:
        self._setup(dedupe or Deduper(), clock, sleep, tolerance)
        self._settings: Settings = load_settings(data_dir, config_path, os.environ)
        self._token = token or read_secret(self._settings.data_dir / API_TOKEN_FILE, "api-token")
        self._secret = webhook_secret
        port = tcp_port if tcp_port is not None else self._settings.tcp_port
        if transport is None and port == 0:
            transport = httpx.AsyncHTTPTransport(uds=str(socket or self._settings.socket))
        self._base = f"http://127.0.0.1:{port}" if port else "http://agentconnectd"
        self._http: httpx.AsyncClient | None = httpx.AsyncClient(
            transport=transport, base_url=self._base, timeout=30, trust_env=False
        )
        self._ops: Operations = _HttpOperations(self)
        self._host: EmbeddedHost | None = None
        self.data_dir: Path = self._settings.data_dir

    def _setup(
        self,
        dedupe: Deduper,
        clock: Callable[[], float],
        sleep: Callable[[float], Awaitable[None]],
        tolerance: float,
    ) -> None:
        self._dedupe = dedupe
        self._clock, self._sleep, self._tolerance = clock, sleep, tolerance
        self._verifier: WebhookVerifier | None = None
        self._message_handlers: list[MessageHandler] = []
        self._task_handlers: list[MessageHandler] = []
        self._event_handlers: list[EventHandler] = []
        self.last_event_id: str | None = None

    @classmethod
    def attach(  # noqa: PLR0913
        cls,
        *,
        data_dir: Path | None = None,
        socket: Path | None = None,
        tcp_port: int | None = None,
        token: str | None = None,
        webhook_secret: str | None = None,
        config_path: Path | None = None,
        dedupe: Deduper | None = None,
    ) -> AgentConnect:
        """Attach to a separate daemon (``agentconnect daemon run``) configured
        with the webhook or SSE adapter. The same as ``AgentConnect(...)``."""
        return cls(
            data_dir=data_dir,
            socket=socket,
            tcp_port=tcp_port,
            token=token,
            webhook_secret=webhook_secret,
            config_path=config_path,
            dedupe=dedupe,
        )

    @classmethod
    def embedded(  # noqa: PLR0913
        cls,
        name: str | None = None,
        *,
        data_dir: Path | str | None = None,
        relay: str | None = None,
        config: Path | str | None = None,
        display_name: str | None = None,
        dedupe: Deduper | None = None,
    ) -> AgentConnect:
        """Run the runtime inside this process (ADR-005's embedded mode).

        ``name`` picks the data directory, ``$XDG_DATA_HOME/agentconnect-<name>``
        (one directory is one identity); ``data_dir`` or ``AC_DATA_DIR`` replace
        it. One of ``name`` and ``data_dir`` is required, so two agents on one
        machine never share an identity by accident. ``relay`` is the relay's
        ``wss://`` URL (required: there is no built-in relay);
        ``config`` is a TOML file in the daemon's format (``docs/config.md``),
        for the ``[policy]`` defaults and the like. ``display_name`` is what
        peers see (default: ``name``).

        Nothing starts until ``async with`` (or :meth:`start`). Starting
        takes the data directory's lock: :class:`DataDirLockedError` if a
        separate daemon or another embedded agent already runs on it. The
        runtime serves the local API socket in the data directory, so the
        human runs ``AC_DATA_DIR=<data_dir> agentconnect approvals`` (and
        ``verify``, ``safety set``) against it from a terminal. Deliveries
        start with :meth:`serve`."""
        from agentconnect_sdk.embedded import EmbeddedHost  # noqa: PLC0415

        host = EmbeddedHost(
            EmbeddedHost.configure(
                name,
                data_dir=data_dir,
                relay=relay,
                config=config,
                display_name=display_name,
                environ=os.environ,
            )
        )
        return cls.hosted(host, dedupe=dedupe)

    @classmethod
    def hosted(cls, host: EmbeddedHost, *, dedupe: Deduper | None = None) -> AgentConnect:
        """A client over an :class:`~agentconnect_sdk.embedded.EmbeddedHost`
        you built yourself; :meth:`embedded` is the usual way."""
        self = cls.__new__(cls)
        self._setup(dedupe or host.deduper(), time.time, asyncio.sleep, DEFAULT_TOLERANCE)
        self._http = None
        self._ops = host.operations()
        self._host = host
        self.data_dir = host.data_dir
        return self

    @property
    def mode(self) -> Literal["embedded", "attach"]:
        return "attach" if self._host is None else "embedded"

    async def start(self) -> None:
        """Embedded: start the runtime (taking the data directory's lock).
        Attach: nothing to start. ``async with`` calls it."""
        if self._host is not None:
            await self._host.start(self.dispatch, self._release_claim)

    def _release_claim(self, payload: dict[str, Any]) -> None:
        """The runtime gave up on a handler that ignored its timeout: forget
        its claim, so the redelivery runs instead of being refused as busy."""
        with contextlib.suppress(PayloadError):
            self._dedupe.release(idempotency_key(payload))

    async def aclose(self) -> None:
        """Embedded: stop the runtime cleanly. Running handlers and queued
        sends get a few seconds to finish, then the relay link closes and the
        lock is released. Called from inside a handler, it only schedules
        that and returns at once; let the handler return, and ``serve()``
        returns when the runtime has stopped. Attach: close the HTTP client."""
        if self._host is not None:
            await self._host.stop()
        if self._http is not None:
            await self._http.aclose()

    async def __aenter__(self) -> AgentConnect:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # -- requests (attach mode) -----------------------------------------------

    def _attached(self) -> httpx.AsyncClient:
        if self._http is None:
            msg = "only a client attached to a separate daemon has this"
            raise AgentConnectError("embedded", msg)
        return self._http

    async def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        http = self._attached()
        try:
            resp = await http.request(
                method, path, json=body, headers={"authorization": f"Bearer {self._token}"}
            )
        except httpx.TransportError:
            raise AgentConnectError("not_running", "cannot reach the daemon") from None
        data = _json(resp)
        if resp.status_code != httpx.codes.OK:
            raise AgentConnectError(
                str(data.get("code", "error")), str(data.get("message", "")), resp.status_code
            )
        return data

    # -- operations -------------------------------------------------------------

    async def status(self) -> dict[str, Any]:
        return await self._ops.status()

    async def create_group(self, purpose: str = "", name: str | None = None) -> Group:
        """Create a group you own. ``purpose`` is what joiners are told."""
        shown = (name or purpose or "AgentConnect chat")[:MAX_NAME]
        reply = await self._ops.create_group(shown, purpose)
        return Group(self, str(reply["group_id"]))

    def group(self, group_id: str) -> Group:
        return Group(self, group_id)

    async def groups(self) -> list[dict[str, Any]]:
        """The groups: ``group_id``, ``name``, ``status``, ``epoch``,
        ``members``, ``out_of_sync``."""
        reply = await self._ops.list_groups()
        return [g for g in reply["groups"] if isinstance(g, dict)]

    async def accept(self, url: str, display_name: str | None = None) -> dict[str, Any]:
        """Redeem an invite link. The inviter's human still has to approve;
        the group appears in :meth:`groups` once they do."""
        return await self._ops.accept(url, display_name)

    # -- handlers -------------------------------------------------------------

    def on_message(self, handler: MessageHandler) -> MessageHandler:
        """Register ``async def handler(msg, group)`` for A2A messages.

        Called once per ``msg_id``. Check ``msg.addressed_to_me`` before
        acting; anything else is context. If the handler raises, the message
        is delivered again."""
        self._message_handlers.append(handler)
        return handler

    def on_task(self, handler: MessageHandler) -> MessageHandler:
        """Register ``async def handler(msg, group)`` for task status and
        artifact updates (``msg.event`` says which)."""
        self._task_handlers.append(handler)
        return handler

    def on_event(self, handler: EventHandler) -> EventHandler:
        """Register ``async def handler(event, group)`` for runtime events
        (``member_joined``, ``epoch_changed``, ``loop_guard``, ...). ``group``
        is ``None`` for events about no group."""
        self._event_handlers.append(handler)
        return handler

    # -- receiving ------------------------------------------------------------

    async def dispatch(self, payload: dict[str, Any]) -> Literal["handled", "duplicate", "busy"]:
        """Run the handlers for one payload, once per ``msg_id`` / ``event_id``.

        ``duplicate``: already handled. ``busy``: the same id is being
        handled now. Handler exceptions propagate and release the id, so a
        redelivery runs the handlers again."""
        parsed = parse_payload(payload)
        key = idempotency_key(payload)
        if not self._dedupe.claim(key):
            return "busy" if self._dedupe.in_flight(key) else "duplicate"
        try:
            await self._run_handlers(parsed)
        except BaseException:
            self._dedupe.release(key)
            raise
        self._dedupe.done(key)
        return "handled"

    async def _run_handlers(self, parsed: Message | Event) -> None:
        if isinstance(parsed, Event):
            group = None if parsed.group is None else Group(self, parsed.group.id)
            for event_handler in self._event_handlers:
                await event_handler(parsed, group)
            return
        group = Group(self, parsed.group.id)
        if parsed.event == "message":
            for handler in self._message_handlers:
                await handler(parsed, group)
        elif parsed.event in ("task_status", "task_artifact"):
            for handler in self._task_handlers:
                await handler(parsed, group)

    def _webhook_verifier(self) -> WebhookVerifier:
        if self._verifier is None:
            self._attached()
            secret = self._secret or read_secret(
                self._settings.data_dir / WEBHOOK_SECRET_FILE, "webhook-secret"
            )
            self._verifier = WebhookVerifier(secret, tolerance=self._tolerance, clock=self._clock)
        return self._verifier

    async def receive(self, headers: Mapping[str, str], body: bytes) -> str:
        """For your own web framework (attach mode): verify the signature
        headers, then dispatch. Raises :class:`SignatureError` (answer 401),
        :class:`PayloadError` (400) or the handler's exception (answer 500).
        Returns ``handled``, ``duplicate`` or ``busy`` (answer 503 for
        ``busy``, 2xx otherwise)."""
        self._webhook_verifier().verify(headers, body)
        payload = json.loads(body)
        if not isinstance(payload, dict):
            msg = "body must be an object"
            raise ValueError(msg)
        return await self.dispatch(payload)

    def webhook_receiver(self, host: str = "127.0.0.1", port: int | None = None) -> WebhookReceiver:
        """The built-in webhook server (attach mode); ``await
        receiver.start()``. ``port`` defaults to the port of the daemon's
        ``webhook.callback_url``."""
        self._attached()
        chosen = port if port is not None else self._settings.callback_port
        if chosen is None:
            msg = "no port: pass port= or set webhook.callback_url in the daemon config"
            raise AgentConnectError("bad_config", msg)
        return WebhookReceiver(self.dispatch, self._webhook_verifier(), host, chosen)

    async def stream(self, group_id: str | None = None, last_event_id: str | None = None) -> None:
        """Consume the daemon's SSE feed once, until it ends (attach mode).
        Each frame goes through :meth:`dispatch`; ``self.last_event_id``
        tracks the resume point. Handler exceptions propagate (the frame is
        not acked: resume from ``last_event_id`` redelivers it)."""
        http = self._attached()
        headers = {"authorization": f"Bearer {self._token}", "accept": "text/event-stream"}
        resume = last_event_id or self.last_event_id
        if resume is not None and resume != "":
            headers["last-event-id"] = resume
        params = {} if group_id is None or group_id == "" else {"group": group_id}
        try:
            async with http.stream(
                "GET", "/v0/events", params=params, headers=headers, timeout=None
            ) as resp:
                if resp.status_code != httpx.codes.OK:
                    data = _json(await _read(resp))
                    raise AgentConnectError(
                        str(data.get("code", "error")),
                        str(data.get("message", "")),
                        resp.status_code,
                    )
                async for frame in iter_sse(resp.aiter_lines()):
                    payload = json.loads(frame.data)
                    if isinstance(payload, dict):
                        await self.dispatch(payload)
                    if frame.id is not None and frame.id != "":
                        self.last_event_id = frame.id
        except httpx.TransportError as e:
            raise AgentConnectError("not_running", "the event stream closed") from e

    async def serve(
        self,
        mode: Literal["auto", "webhook", "sse"] = "auto",
        *,
        host: str = "127.0.0.1",
        port: int | None = None,
        group: str | None = None,
        ready: asyncio.Event | None = None,
    ) -> None:
        """Run until cancelled (or, embedded, until :meth:`aclose` has
        fully stopped the runtime), delivering to the registered handlers. ``ready`` is set once
        deliveries flow.

        Embedded: the runtime hands messages and events to the handlers
        directly; ``mode`` must be ``auto``. Attach: ``webhook`` serves the
        daemon's callback (needs ``webhook-secret``), ``sse`` reads the
        daemon's event stream, reconnecting with ``Last-Event-ID``, and
        ``auto`` picks ``webhook`` when the daemon config has a
        ``webhook.callback_url``, else ``sse``."""
        if self._host is not None:
            if mode != "auto":
                msg = "an embedded runtime delivers in-process; mode must be auto"
                raise AgentConnectError("bad_config", msg)
            await self._host.serve(ready)
            return
        chosen = mode
        if chosen == "auto":
            chosen = "sse" if self._settings.callback_url is None else "webhook"
        if chosen == "webhook":
            receiver = self.webhook_receiver(host, port)
            await receiver.start()
            if ready is not None:
                ready.set()
            try:
                await asyncio.Event().wait()
            finally:
                await receiver.close()
        else:
            await self._serve_sse(group, ready)

    async def _serve_sse(self, group: str | None, ready: asyncio.Event | None) -> None:
        delay = RECONNECT_DELAY
        while True:
            if ready is not None:
                ready.set()
            before = self.last_event_id
            try:
                await self.stream(group)
            except AgentConnectError as e:
                if e.status != 0:
                    raise  # refused (bad token, no SSE adapter): reconnecting won't help
                _log.LOG.warning("stream_closed")
            except Exception:
                _log.LOG.exception("handler_failed")
            if self.last_event_id != before:
                delay = RECONNECT_DELAY
            await self._sleep(delay)
            delay = min(delay * 2, MAX_RECONNECT_DELAY)


def _json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


async def _read(resp: httpx.Response) -> httpx.Response:
    await resp.aread()
    return resp
