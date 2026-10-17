"""The SDK client: talk to the local daemon, receive its deliveries.

Security model: the client holds the daemon's **agent-scope** ``api-token``
and nothing more. It can create groups and invites, send messages and read
events. It cannot approve joins, mark members verified, relax verification or
send ``control.resume``: those need the human token, which this package never
reads and an agent must never be given.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal, TypeVar, override

import httpx

from agentconnect_sdk import _log
from agentconnect_sdk.dedupe import Deduper
from agentconnect_sdk.errors import AgentConnectError
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


def _parts(content: str | Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(content, str):
        return [{"text": content}]
    return [dict(p) for p in content]


def _agent_message(group_id: str, content: str | Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """An A2A v1.0 ``Message`` from this agent."""
    return {
        "messageId": secrets.token_hex(16),
        "contextId": group_id,
        "role": "ROLE_AGENT",
        "parts": _parts(content),
    }


class Group:
    """One group, bound to the client that opened it."""

    def __init__(self, client: AgentConnect, group_id: str) -> None:
        self._client = client
        self.id = group_id

    @override
    def __repr__(self) -> str:
        return f"Group({self.id!r})"

    async def info(self) -> dict[str, Any]:
        """The daemon's view: members, policy, trust state, short code."""
        return await self._client._request("GET", f"/v0/groups/{self.id}")

    async def invite(self, max_uses: int = 1, ttl_secs: int = 86_400) -> str:
        """Create an invite link. Share it with the other human; whoever
        redeems it still needs your human's approval."""
        reply = await self._client._request(
            "POST",
            f"/v0/groups/{self.id}/invites",
            {"max_uses": max_uses, "ttl_secs": ttl_secs},
        )
        return str(reply["url"])

    async def send(
        self,
        content: str | Sequence[Mapping[str, Any]],
        *,
        to: Sequence[str] = ("*",),
        reply_to: Sequence[str] = (),
    ) -> str:
        """Send an A2A message (text, or a list of ``text``/``data`` parts).
        Returns its ``msg_id``. In a ``mention`` group only the identities in
        ``to`` are triggered."""
        body = _agent_message(self.id, content)
        return await self._post("a2a.message", body, to, reply_to)

    async def reply(self, msg: Message, content: str | Sequence[Mapping[str, Any]]) -> str:
        """Answer ``msg`` to its sender. ``reply_to`` carries ``msg.msg_id``,
        so the daemon sets ``hop`` (SPEC section 10.3) and the loop guard can
        stop a runaway exchange."""
        body = _agent_message(self.id, content)
        return await self._post("a2a.message", body, [msg.sender.identity], [msg.msg_id])

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
        message's own ``taskId``, else a new one."""
        status: dict[str, Any] = {"state": state}
        if text is not None:
            status["message"] = _agent_message(self.id, text)
        body = {
            "taskId": task_id or str(msg.a2a.get("taskId") or secrets.token_hex(8)),
            "contextId": self.id,
            "status": status,
        }
        return await self._post("a2a.task_status", body, [msg.sender.identity], [msg.msg_id])

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
        """Send an A2A ``TaskArtifactUpdateEvent`` (a result for a task)."""
        artifact: dict[str, Any] = {
            "artifactId": artifact_id or secrets.token_hex(8),
            "parts": _parts(content),
        }
        if name is not None:
            artifact["name"] = name
        body = {
            "taskId": task_id or str(msg.a2a.get("taskId") or secrets.token_hex(8)),
            "contextId": self.id,
            "artifact": artifact,
            "append": append,
            "lastChunk": last_chunk,
        }
        return await self._post("a2a.task_artifact", body, [msg.sender.identity], [msg.msg_id])

    async def leave(self) -> str:
        reply = await self._client._request("POST", f"/v0/groups/{self.id}/leave")
        return str(reply["status"])

    async def _post(
        self, kind: str, body: dict[str, Any], to: Sequence[str], reply_to: Sequence[str]
    ) -> str:
        payload: dict[str, Any] = {"kind": kind, "body": body, "to": list(to)}
        if reply_to:
            payload["reply_to"] = list(reply_to)
        reply = await self._client._request("POST", f"/v0/groups/{self.id}/messages", payload)
        return str(reply["msg_id"])


class AgentConnect:
    """A headless agent's connection to its local daemon.

    ``AgentConnect()`` finds the daemon the way the CLI does (config file,
    ``AC_DATA_DIR``) and reads ``api-token`` from its data directory. Pass
    ``data_dir``, ``socket``, ``tcp_port`` or ``token`` to point elsewhere.
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
        self._settings: Settings = load_settings(data_dir, config_path, os.environ)
        self._token = token or read_secret(self._settings.data_dir / API_TOKEN_FILE, "api-token")
        self._secret = webhook_secret
        port = tcp_port if tcp_port is not None else self._settings.tcp_port
        if transport is None and port == 0:
            transport = httpx.AsyncHTTPTransport(uds=str(socket or self._settings.socket))
        self._base = f"http://127.0.0.1:{port}" if port else "http://agentconnectd"
        self._http = httpx.AsyncClient(
            transport=transport, base_url=self._base, timeout=30, trust_env=False
        )
        self._dedupe = dedupe or Deduper()
        self._clock, self._sleep, self._tolerance = clock, sleep, tolerance
        self._verifier: WebhookVerifier | None = None
        self._message_handlers: list[MessageHandler] = []
        self._task_handlers: list[MessageHandler] = []
        self._event_handlers: list[EventHandler] = []
        self.last_event_id: str | None = None

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AgentConnect:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # -- requests -------------------------------------------------------------

    async def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            resp = await self._http.request(
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

    async def status(self) -> dict[str, Any]:
        return await self._request("GET", "/v0/status")

    async def create_group(self, purpose: str = "", name: str | None = None) -> Group:
        """Create a group you own. ``purpose`` is what joiners are told."""
        shown = (name or purpose or "AgentConnect chat")[:MAX_NAME]
        reply = await self._request("POST", "/v0/groups", {"name": shown, "purpose": purpose})
        return Group(self, str(reply["group_id"]))

    def group(self, group_id: str) -> Group:
        return Group(self, group_id)

    async def groups(self) -> list[dict[str, Any]]:
        """The daemon's groups: ``group_id``, ``name``, ``status``, ``epoch``,
        ``members``, ``out_of_sync``."""
        reply = await self._request("GET", "/v0/groups")
        return [g for g in reply["groups"] if isinstance(g, dict)]

    async def accept(self, url: str, display_name: str | None = None) -> dict[str, Any]:
        """Redeem an invite link. The inviter's human still has to approve;
        the group appears in :meth:`groups` once they do."""
        body: dict[str, Any] = {"url": url}
        if display_name is not None:
            body["display_name"] = display_name
        return await self._request("POST", "/v0/invites/accept", body)

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
        """Register ``async def handler(event, group)`` for daemon events
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
            secret = self._secret or read_secret(
                self._settings.data_dir / WEBHOOK_SECRET_FILE, "webhook-secret"
            )
            self._verifier = WebhookVerifier(secret, tolerance=self._tolerance, clock=self._clock)
        return self._verifier

    async def receive(self, headers: Mapping[str, str], body: bytes) -> str:
        """For your own web framework: verify the signature headers, then
        dispatch. Raises :class:`SignatureError` (answer 401),
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
        """The built-in webhook server; ``await receiver.start()``. ``port``
        defaults to the port of the daemon's ``webhook.callback_url``."""
        chosen = port if port is not None else self._settings.callback_port
        if chosen is None:
            msg = "no port: pass port= or set webhook.callback_url in the daemon config"
            raise AgentConnectError("bad_config", msg)
        return WebhookReceiver(self.dispatch, self._webhook_verifier(), host, chosen)

    async def stream(self, group_id: str | None = None, last_event_id: str | None = None) -> None:
        """Consume the daemon's SSE feed once, until it ends. Each frame goes
        through :meth:`dispatch`; ``self.last_event_id`` tracks the resume
        point. Handler exceptions propagate (the frame is not acked: resume
        from ``last_event_id`` redelivers it)."""
        headers = {"authorization": f"Bearer {self._token}", "accept": "text/event-stream"}
        resume = last_event_id or self.last_event_id
        if resume is not None and resume != "":
            headers["last-event-id"] = resume
        params = {} if group_id is None or group_id == "" else {"group": group_id}
        try:
            async with self._http.stream(
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
        """Run until cancelled, delivering to the registered handlers.

        ``webhook``: serve the daemon's callback (needs ``webhook-secret``).
        ``sse``: read the daemon's event stream, reconnecting with
        ``Last-Event-ID``. ``auto``: ``webhook`` when the daemon config has a
        ``webhook.callback_url``, else ``sse``. ``ready`` is set once
        listening or connected."""
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
