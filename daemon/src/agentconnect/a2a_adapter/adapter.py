"""The A2A adapter: lets an A2A v1.0 server agent take part in groups
without knowing about AgentConnect (docs/adapters/a2a.md).

**Direction 1, inbound.** A message that triggers this member (SPEC §9.3,
``addressed_to_me``) becomes a ``SendStreamingMessage`` call (``SendMessage``
when the agent doesn't stream) on the local agent, with ``contextId`` = the
group and the SPEC §10.1 framing in ``metadata``. Messages that don't
trigger it are kept, bounded, and handed over with the next call as
``metadata.context_messages``. What the agent streams back goes to the group
as ``a2a.task_status`` / ``a2a.task_artifact`` / ``a2a.message`` with
``reply_to`` = the triggering ``msg_id`` (SPEC §10.3), to the whole group
(``to: ["*"]``) with the requester as the only ``addressee`` (SPEC §9.3).
A follow-up that names one of the agent's tasks (``input-required``)
continues it; an ``a2a.task_cancel`` from the task's requester cancels it.

**Direction 2, the facade** (:mod:`.facade`): a local A2A client talks to
the group through a server on ``127.0.0.1``.

**At least once.** The daemon may repeat a delivery or an event (ADR-004);
both are deduplicated here by sender and ``msg_id`` (as the inbox does) and
by ``event_id`` (:mod:`.seen`), so the agent never sees one twice. The
message sent to the agent also has a ``messageId`` derived from the sender
and the ``msg_id`` (:func:`message_id`), for the crash window between the
agent accepting it and the adapter recording that.

Peer content is untrusted. It goes to the agent as data with the framing in
``metadata``; the peer's own ``metadata`` is nested under
``metadata.peer_metadata`` so it can't overwrite the framing, and nothing a
peer sends changes this adapter's configuration or the agent's credentials.
Logs carry tags and error types, never bodies.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import secrets
from collections import OrderedDict, deque
from collections.abc import AsyncIterator, Coroutine, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx
from a2a.client import A2ACardResolver, A2AClientError, Client, ClientConfig, ClientFactory
from a2a.types import (
    AgentCard,
    CancelTaskRequest,
    Message,
    Part,
    Role,
    SendMessageRequest,
    StreamResponse,
)
from a2a.utils.errors import A2AError, UnsupportedOperationError
from jwt import PyJWK

from agentconnect import log
from agentconnect.a2a_adapter import cards, convert
from agentconnect.a2a_adapter.facade import Facade
from agentconnect.a2a_adapter.seen import Seen
from agentconnect.adapter import (
    Capabilities,
    Delivery,
    DeliveryResult,
    Event,
    GroupView,
    OutboundSend,
    Sender,
)
from agentconnect.clock import Clock, unix_seconds
from agentconnect.isolation import facade_uids, receiver_uids, resolve_gid
from agentconnect.sockets import PeerMismatchError, receiver_async_transport
from agentconnect.tasks import cancel_and_wait

if TYPE_CHECKING:
    from agentconnect.config import Config
    from agentconnect.store import Store

LOG = log.get("a2a")
FACADE_TOKEN_FILE = "a2a-facade-token"  # noqa: S105 - a file name
# Where older daemons kept the seen set, in plain SQLite: moved into the
# encrypted database and deleted on first use.
SEEN_FILE = "a2a-seen.db"
MAX_CONTEXT_ENTRY = 64 * 1024  # bytes of JSON; bigger context entries are summarised
MAX_TASKS = 1024  # local agent tasks kept in memory (a cache of the database's)
TASKS_PER_PEER = 64  # tasks kept per requesting instance in the database
CARD_TIMEOUT = 5.0


@dataclass(frozen=True)
class A2AOptions:
    """The adapter's configuration (``[a2a]`` in config.toml)."""

    local_agent_url: str | None = None
    # A Unix socket every request to the local agent goes to, served by one
    # of receiver_uids (SR-10); local_agent_url then gives Host and paths.
    local_agent_socket: Path | None = None
    receiver_uids: frozenset[int] = frozenset()
    local_agent_token: str | None = field(default=None, repr=False)
    card_keys: Mapping[str, PyJWK] = field(default_factory=dict, repr=False)
    facade_port: int | None = None  # None: no facade; 0: any free port
    # The facade on a Unix socket instead, open to facade_uids only; created
    # 0660 with the group facade_gid when set (separate-OS-user mode).
    facade_socket: Path | None = None
    facade_uids: frozenset[int] = frozenset()
    facade_gid: int | None = None
    context_messages: int = 20
    frame_text: bool = True
    reply_timeout: float = 600.0
    data_dir: Path | None = None

    @staticmethod
    def from_config(config: Config) -> A2AOptions:
        token = None
        if config.a2a_local_agent_token_file is not None:
            text = config.a2a_local_agent_token_file.read_text(encoding="utf-8").strip()
            token = text or None
        return A2AOptions(
            local_agent_url=config.a2a_local_agent_url,
            local_agent_socket=config.a2a_local_agent_socket,
            receiver_uids=receiver_uids(config),
            local_agent_token=token,
            card_keys=cards.load_jwks(config.a2a_card_keys_file),
            facade_port=config.a2a_facade_port if config.a2a_facade_port > 0 else None,
            facade_socket=config.a2a_facade_socket,
            facade_uids=facade_uids(config),
            facade_gid=resolve_gid(config.isolation_group) if config.isolation else None,
            context_messages=config.a2a_context_messages,
            frame_text=config.a2a_frame_text,
            reply_timeout=float(config.a2a_reply_timeout),
            data_dir=config.data_dir,
        )


@dataclass(frozen=True)
class TaskRef:
    """One of the local agent's tasks: the group and the member it runs for."""

    group_id: str
    requester: str
    instance: str
    trigger: str


def _seen_key(sender: str, msg_id: str) -> str:
    """By sender too: a msg_id is its sender's, so another member reusing
    it must not pass for a redelivery and hide the first message."""
    return f"{sender}\0{msg_id}"


def message_id(d: Delivery) -> str:
    """The ``messageId`` the local agent sees: ``ac-`` and 22 base64url
    characters of SHA-256(sender, msg_id). The same for every redelivery,
    and different for another sender's message with the same msg_id."""
    digest = hashlib.sha256(f"{d.sender.identity}\0{d.msg_id}".encode()).digest()
    return "ac-" + base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()


class A2AAdapter:
    """See the module docstring."""

    def __init__(self, options: A2AOptions, name: str = "a2a") -> None:
        self.name = name
        self.options = options
        self._seen_store: Seen | None = None
        self._send: OutboundSend | None = None
        self._http: httpx.AsyncClient | None = None
        self._client: Client | None = None
        self._plain: Client | None = None
        self._card: AgentCard | None = None
        self._card_json: dict[str, Any] | None = None
        self._groups: dict[str, GroupView] = {}
        self._cards: dict[str, dict[str, tuple[AgentCard, str]]] = {}
        self._peers: dict[str, set[str]] = {}
        self._context: dict[str, deque[dict[str, Any]]] = {}
        self._tasks: OrderedDict[str, TaskRef] = OrderedDict()
        # The daemon's encrypted store, where the task map outlives a restart,
        # and the runtime's clock for its entries.
        self._store: Store | None = None
        self._clock: Clock | None = None
        self._running: set[asyncio.Task[None]] = set()
        self.facade: Facade | None = None
        self.facade_token: str | None = None

    def bind_store(self, store: Store) -> None:
        """The daemon's database: the local agent's tasks are kept there,
        so a follow-up or a cancel after a restart still finds its task."""
        self._store = store

    def bind_clock(self, clock: Clock) -> None:
        """The runtime's clock, which stamps the task map's entries."""
        self._clock = clock

    def _task(self, task_id: str) -> TaskRef | None:
        """One of the local agent's tasks, in memory or, after a restart,
        in the daemon's database."""
        ref = self._tasks.get(task_id)
        if ref is None and self._store is not None:
            row = self._store.a2a_task(task_id)
            ref = None if row is None else TaskRef(*row)
        return ref

    def asked(self, d: Delivery, request: str) -> bool:
        """Whether the request ``request`` this daemon sent asked the member
        (and instance) that sent ``d`` (SPEC 9.3, the daemon's record of its
        requests). Without the daemon's store (tests), every member."""
        return self._store is None or self._store.request_asks(
            d.group_id, request, d.sender.identity, d.sender.instance_id
        )

    def _keep_task(self, task_id: str, ref: TaskRef) -> None:
        self._tasks[task_id] = ref
        self._tasks.move_to_end(task_id)
        while len(self._tasks) > MAX_TASKS:
            self._tasks.popitem(last=False)
        if self._store is not None and self._clock is not None:
            self._store.a2a_task_put(
                task_id,
                group_id=ref.group_id,
                requester=ref.requester,
                instance=ref.instance,
                msg_id=ref.trigger,
                now=unix_seconds(self._clock),
                keep=TASKS_PER_PEER,
            )

    @property
    def _seen(self) -> Seen:
        # Opened on first use, in the daemon's encrypted database (bound by
        # then), taking over an older daemon's plain file if one is left.
        if self._seen_store is None:
            data_dir = self.options.data_dir
            legacy = None if data_dir is None else data_dir / SEEN_FILE
            self._seen_store = Seen(self._store, legacy)
        return self._seen_store

    # -- Adapter protocol ----------------------------------------------------

    def capabilities(self) -> Capabilities:
        return Capabilities(
            accepts=["text", "data"],
            originates=True,
            agent_card=self._card_json,
            # The facade alone answers nothing: it is triggered only by
            # replies to its own requests.
            answers=self.options.local_agent_url is not None,
        )

    async def on_outbound(self, send: OutboundSend) -> None:
        self._send = send
        await self.start()

    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        self._groups[group.group_id] = group
        if self.handled(sender.identity, inner.msg_id):
            return DeliveryResult.ACK  # redelivered (at least once)
        self._peers.setdefault(group.group_id, set()).add(sender.identity)
        result = await self._handle(group, inner)
        if result is DeliveryResult.ACK:
            self._seen.add("m", _seen_key(sender.identity, inner.msg_id))
        return result

    def handled(self, sender: str, msg_id: str) -> bool:
        """Whether this sender's message ``msg_id`` was handled already."""
        return self._seen.has("m", _seen_key(sender, msg_id))

    async def on_event(self, group: GroupView | None, event: Event) -> None:
        if group is not None:
            self._groups[group.group_id] = group
        if event.event_id and self._seen.has("e", event.event_id):
            return
        gid = event.group_id
        identity = event.data.get("identity")
        if gid is not None and isinstance(identity, str):
            if event.type == "member_joined":
                self._peers.setdefault(gid, set()).add(identity)
            elif event.type in ("member_left", "member_removed"):
                self._peers.get(gid, set()).discard(identity)
                self._cards.get(gid, {}).pop(identity, None)
        if self.facade is not None and event.type in ("send_approved", "send_failed"):
            # A facade send the group held for the human: approved or not.
            hold_id = event.data.get("hold_id")
            if isinstance(hold_id, str):
                self.facade.decided(hold_id, str(event.data.get("code", "approved")))
        if event.type == "joined" and self.options.local_agent_url is not None:
            # SPEC: the card goes out on join; fetch it fresh first.
            await self._load_card()
        if gid is not None and event.type in ("removed", "left"):
            self._forget(gid)
        if event.event_id:
            self._seen.add("e", event.event_id)

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        # a2a-sdk logs card contents and events at INFO/DEBUG: peer content.
        logging.getLogger("a2a").setLevel(logging.ERROR)
        if self.options.local_agent_url is not None and self._http is None:
            headers = {}
            if self.options.local_agent_token is not None:
                headers["Authorization"] = f"Bearer {self.options.local_agent_token}"
            uds = self.options.local_agent_socket
            transport = (
                None if uds is None else receiver_async_transport(uds, self.options.receiver_uids)
            )
            # No read timeout: a stream may stay quiet while the agent works.
            # No environment proxies and no redirects: the token and the
            # messages go to local_agent_url (or its socket) and nowhere else.
            self._http = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(30.0, read=None),
                transport=transport,
                trust_env=False,
                follow_redirects=False,
            )
            await self._load_card()
        on_socket = self.options.facade_socket is not None
        if (self.options.facade_port is not None or on_socket) and self.facade is None:
            self.facade_token = self._facade_token()
            facade = Facade(
                self,
                self.facade_token,
                self.options.facade_port or 0,
                path=self.options.facade_socket,
                uids=self.options.facade_uids,
                gid=self.options.facade_gid,
            )
            await facade.start()
            self.facade = facade
            LOG.info(
                "a2a_facade_started", transport="unix" if on_socket else "tcp", port=facade.port
            )

    async def close(self) -> None:
        """Called by ``Engine.stop``."""
        await self.aclose()

    async def aclose(self) -> None:
        try:
            await cancel_and_wait(*self._running, ignore=(Exception,))
        finally:
            try:
                if self.facade is not None:
                    await self.facade.stop()
                    self.facade = None
                if self._http is not None:
                    await self._http.aclose()
                    self._http = None
            finally:
                if self._seen_store is not None:
                    self._seen_store.close()
                    self._seen_store = None

    def _facade_token(self) -> str:
        if self.options.data_dir is None:
            return secrets.token_urlsafe(32)
        from agentconnect.tokens import load_token  # noqa: PLC0415 - avoid an import cycle

        return load_token(self.options.data_dir / FACADE_TOKEN_FILE)

    # -- for the facade --------------------------------------------------------

    def group_info(self, group_id: str) -> GroupView | None:
        return self._groups.get(group_id)

    def peers(self, group_id: str) -> set[str]:
        return set(self._peers.get(group_id, set()))

    def peer_cards(self, group_id: str) -> dict[str, AgentCard]:
        return {i: card for i, (card, _status) in self._cards.get(group_id, {}).items()}

    def card_status(self, group_id: str, identity: str) -> str | None:
        entry = self._cards.get(group_id, {}).get(identity)
        return None if entry is None else entry[1]

    async def send_to_group(
        self,
        group_id: str,
        body: dict[str, Any],
        to: list[str],
        kind: str = "a2a.message",
        instance: str | None = None,
    ) -> str:
        if self._send is None:
            msg = "the adapter has not been started"
            raise RuntimeError(msg)
        return await self._send(group_id, body, to=to, kind=kind, instance=instance)

    # -- inbound -------------------------------------------------------------

    async def _handle(self, group: GroupView, d: Delivery) -> DeliveryResult:
        if d.kind == "a2a.agent_card":
            self._keep_card(d)
            return DeliveryResult.ACK
        if self.facade is not None and self.facade.route_reply(d):
            return DeliveryResult.ACK
        if d.kind == "a2a.task_cancel":
            await self._maybe_cancel(d)
            return DeliveryResult.ACK
        if d.kind != "a2a.message" or self.options.local_agent_url is None:
            return DeliveryResult.ACK
        if not d.addressed_to_me:
            self._remember(d)
            return DeliveryResult.ACK
        return await self._trigger(group, d)

    def _keep_card(self, d: Delivery) -> None:
        card = convert.parse_card(d.body)
        if card is None:
            return
        status = cards.signature_status(card, self.options.card_keys)
        if status == "invalid":
            LOG.warning("a2a_peer_card_invalid", group=log.hid(d.group_id))
            return
        self._cards.setdefault(d.group_id, {})[d.sender.identity] = (card, status)

    def _remember(self, d: Delivery) -> None:
        entry: dict[str, Any] = {
            "msg_id": d.msg_id,
            "sender": d.sender.identity,
            "sender_name": d.sender.display_name or "",
            "to": d.to,
            "hop": d.hop,
            "parts": convert.to_json(convert.parse_message(d.body)).get("parts", []),
        }
        if len(json.dumps(entry)) > MAX_CONTEXT_ENTRY:
            entry = {k: v for k, v in entry.items() if k != "parts"} | {"omitted": "too_large"}
        limit = max(self.options.context_messages, 0)
        self._context.setdefault(d.group_id, deque(maxlen=limit)).append(entry)

    def _local_message(self, d: Delivery) -> Message:
        peer = convert.parse_message(d.body)
        msg = Message(role=Role.ROLE_USER, message_id=message_id(d), context_id=d.group_id)
        # The notice goes first unless the adapter (a2a.frame_text) or the
        # group's safety policy (frame_text) turned it off.
        framed = self.options.frame_text and d.frame_text
        if framed:
            msg.parts.append(Part(text=d.framed_text()))
        msg.parts.extend(peer.parts)
        ref = self._task(peer.task_id) if peer.task_id else None
        if ref is not None and ref.group_id == d.group_id and ref.requester == d.sender.identity:
            msg.task_id = peer.task_id  # a follow-up on one of the agent's tasks
        meta: dict[str, Any] = {
            "untrusted": True,
            "scope": d.scope,
            "frame_text": framed,
            "notice": d.framed_text(),
            "sender": {
                "identity": d.sender.identity,
                "instance_id": d.sender.instance_id,
                "display_name": d.sender.display_name,
                "verified": d.sender.verified,
            },
            "to": list(d.to),
            "addressed_to_me": d.addressed_to_me,
            "trust_state": dict(d.trust_state),
            "group_id": d.group_id,
            "msg_id": d.msg_id,
            "hop": d.hop,
            "origin": d.origin,
        }
        context = self._context.get(d.group_id)
        if context is not None and len(context) > 0:
            meta["context_messages"] = list(context)
        peer_meta = convert.to_json(peer).get("metadata")
        if peer_meta:
            meta["peer_metadata"] = peer_meta
        if peer.message_id:
            meta["peer_message_id"] = peer.message_id
        msg.metadata.update(meta)
        return msg

    async def _ensure_client(self) -> bool:
        return self._client is not None or await self._load_card()

    async def _trigger(self, group: GroupView, d: Delivery) -> DeliveryResult:
        if not await self._ensure_client() or self._client is None or self._plain is None:
            return DeliveryResult.RETRY  # the local agent is unreachable for now
        request = SendMessageRequest(message=self._local_message(d))
        try:
            try:
                stream = aiter(self._client.send_message(request))
                first = await anext(stream, None)
            except UnsupportedOperationError:
                # The agent refused streaming: fall back to SendMessage.
                stream = aiter(self._plain.send_message(request))
                first = await anext(stream, None)
        except A2AClientError as e:
            refused = _refusal(e)
            if refused is not None:
                LOG.warning("a2a_receiver_refused", reason=str(refused))
            LOG.warning(
                "a2a_local_unreachable", group=log.hid(group.group_id), error=type(e).__name__
            )
            return DeliveryResult.RETRY
        except A2AError as e:
            # A protocol error is the agent's answer, not a transient failure:
            # retrying would block every later delivery.
            LOG.warning("a2a_local_refused", group=log.hid(group.group_id), error=type(e).__name__)
            return DeliveryResult.ACK
        self._context.pop(d.group_id, None)
        LOG.info("a2a_triggered", group=log.hid(group.group_id), msg=log.hid(d.msg_id))
        if first is not None:
            self._spawn(self._forward(d, first, stream))
        return DeliveryResult.ACK

    def _spawn(self, work: Coroutine[Any, Any, None]) -> None:
        task = asyncio.get_running_loop().create_task(work)
        self._running.add(task)
        task.add_done_callback(self._running.discard)

    async def _forward(
        self, d: Delivery, first: StreamResponse, rest: AsyncIterator[StreamResponse]
    ) -> None:
        """Send what the local agent streams to the group."""
        # SPEC 9.3: everyone sees the progress; only the requester is triggered.
        addressee = [d.sender.identity]
        await self._emit(d, addressee, first)
        if convert.is_final(first):
            return
        try:
            async for resp in rest:
                await self._emit(d, addressee, resp)
                if convert.is_final(resp):
                    break
        except (A2AError, httpx.HTTPError) as e:
            LOG.warning("a2a_stream_failed", group=log.hid(d.group_id), error=type(e).__name__)

    async def _emit(self, d: Delivery, addressee: list[str], resp: StreamResponse) -> None:
        task_id = convert.task_id_of(resp)
        if task_id and task_id not in self._tasks:
            self._keep_task(
                task_id, TaskRef(d.group_id, d.sender.identity, d.sender.instance_id, d.msg_id)
            )
        if self._send is None:
            return
        for kind, body in convert.stream_to_inner(resp, d.group_id):
            try:
                await self._send(
                    d.group_id,
                    body,
                    to=["*"],
                    kind=kind,
                    reply_to=[d.msg_id],
                    addressee=addressee,
                    # SPEC 7.2/9.4: only the requesting instance is triggered.
                    instance=d.sender.instance_id,
                )
            except Exception as e:
                code = getattr(e, "code", type(e).__name__)
                LOG.warning("a2a_reply_not_sent", group=log.hid(d.group_id), code=code)

    async def _maybe_cancel(self, d: Delivery) -> None:
        """SPEC 7.2: ``a2a.task_cancel`` (an A2A ``CancelTaskRequest``) from
        the task's requester cancels the agent's task; from anyone else it is
        ignored, and so is one delivered as context (past the loop guard, or
        addressed to another member): it has no command's standing."""
        request = convert.parse_cancel(d.body)
        ref = None if request is None else self._task(request.id)
        if (
            not d.addressed_to_me
            or request is None
            or ref is None
            or ref.group_id != d.group_id
            or ref.requester != d.sender.identity
            or self._client is None
        ):
            LOG.info("a2a_cancel_ignored", group=log.hid(d.group_id))
            return
        with contextlib.suppress(A2AError, httpx.HTTPError):
            await self._client.cancel_task(CancelTaskRequest(id=request.id))
            LOG.info("a2a_task_canceled", group=log.hid(d.group_id))

    # -- the local agent's card ----------------------------------------------

    async def _load_card(self) -> bool:
        if self._http is None or self.options.local_agent_url is None:
            return False
        resolver = A2ACardResolver(self._http, self.options.local_agent_url)
        try:
            async with asyncio.timeout(CARD_TIMEOUT):
                card = await resolver.get_agent_card()
        except (A2AError, httpx.HTTPError, TimeoutError) as e:
            refused = _refusal(e)
            if refused is not None:
                LOG.warning("a2a_receiver_refused", reason=str(refused))
            LOG.warning("a2a_card_unavailable", error=type(e).__name__)
            return False
        pinned = (
            None if self.options.local_agent_socket is not None else self.options.local_agent_url
        )
        elsewhere = _other_endpoint(card, pinned)
        if elsewhere is not None:
            # On TCP the client would send the token and messages where the
            # card says: only the configured endpoint is trusted (SR-10). On
            # the socket every request goes there, so only an unusable URL is.
            LOG.warning(
                "a2a_card_endpoint_mismatch",
                configured_endpoint=_origin(self.options.local_agent_url),
                card_endpoint=_origin(elsewhere),
            )
            return False
        status = cards.signature_status(card, self.options.card_keys)
        if status == "invalid":
            LOG.warning("a2a_local_card_invalid")
            return False
        try:
            client = ClientFactory(ClientConfig(httpx_client=self._http, streaming=True)).create(
                card
            )
            plain = ClientFactory(ClientConfig(httpx_client=self._http, streaming=False)).create(
                card
            )
        except ValueError:
            # No interface the client can speak (JSON-RPC): unusable, like
            # any other bad card. Whoever answers local_agent_url chooses
            # the card, so it mustn't stop the runtime.
            LOG.warning(
                "a2a_card_unusable",
                reason="no JSON-RPC interface",
                configured_endpoint=_origin(self.options.local_agent_url),
            )
            return False
        self._card = card
        self._card_json = convert.to_json(card)
        self._client, self._plain = client, plain
        LOG.info("a2a_card_loaded", signature=status, skills=len(card.skills))
        return True

    def _forget(self, group_id: str) -> None:
        for table in (self._groups, self._cards, self._peers, self._context):
            table.pop(group_id, None)


def _refusal(e: BaseException) -> PeerMismatchError | None:
    """The receiver check behind a client error, if that was the cause."""
    seen: set[int] = set()
    cur: BaseException | None = e
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, PeerMismatchError):
            return cur
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return None


def _endpoint(url: str) -> tuple[str, str, int | None] | None:
    """Scheme, host and port of ``url``; ``None`` when it can't be parsed
    (a port out of range or not a number, an IPv6 host without brackets)."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    default = {"http": 80, "https": 443}.get(parts.scheme)
    return parts.scheme, (parts.hostname or "").lower(), port or default


def _origin(url: str) -> str:
    """``scheme://host:port`` of ``url``: what is compared, and safe to log
    (no path, query or credentials)."""
    endpoint = _endpoint(url)
    if endpoint is None:
        return "(unparsable)"
    scheme, host, port = endpoint
    return f"{scheme}://{host}:{port}"


def _other_endpoint(card: AgentCard, configured: str | None) -> str | None:
    """An interface URL of ``card`` that can't be parsed or, with a
    ``configured`` endpoint, whose scheme, host or port isn't its; else
    ``None``."""
    want = None if configured is None else _endpoint(configured)
    for interface in card.supported_interfaces:
        found = _endpoint(interface.url)
        if found is None or (configured is not None and found != want):
            return interface.url
    return None
