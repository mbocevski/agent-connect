"""Where the MCP server's tools go: a runtime of its own, or one it attaches to.

* :class:`HostBackend` runs a :class:`~agentconnect.runtime.Runtime` in this
  process with the delivery queue as its adapter, and calls the runtime's
  :class:`~agentconnect.runtime.AgentApi` and the queue directly. It holds
  the data directory's lock.
* :class:`AttachBackend` talks to the runtime that holds the lock (another
  MCP session, a daemon or an embedded agent) over its local API with the
  agent token (``api-token``), and pulls deliveries with
  ``GET /v0/deliveries``. It opens no key and no database, and never reads
  ``human-token``.

Both answer in the shapes of the local API's routes (``docs/api.md``), and
both turn a refused operation into :class:`ToolError` with the API's code.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal, Protocol
from urllib.parse import quote

import httpx

from agentconnect.runtime import (
    AgentApi,
    Clock,
    Config,
    DeliveryQueue,
    Keystore,
    Options,
    Runtime,
    error_reply,
)
from agentconnect.sockets import (
    PeerMismatchError,
    local_async_tcp_transport,
    local_async_transport,
    tcp_base_url,
)
from agentconnect.tokens import API_TOKEN_FILE

POLL_SECS = 60  # one GET /v0/deliveries waits at most this long
HTTP_SLACK_SECS = 15.0  # on top of the poll, before the HTTP client gives up


class ToolError(Exception):
    """A refused tool call: a short ``code`` (the local API's) and a message."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code, self.status = code, status


class OwnerGoneError(Exception):
    """The runtime this session attached to doesn't answer. ``sent``: the
    request may have reached it before it went (so it may have happened)."""

    def __init__(self, sent: bool) -> None:
        super().__init__("the runtime that owns the data directory isn't answering")
        self.sent = sent


ID_RE = re.compile(r"(?=[A-Za-z0-9_-]*[A-Za-z0-9])[A-Za-z0-9_-]+")  # base64url, not all - _


def segment(value: str) -> str:
    """An id as one path segment of the local API: group and message ids
    are base64url, so anything else (`/`, `?`, `%`, `:`, `.`) is refused;
    quoted anyway."""
    if ID_RE.fullmatch(value) is None:
        raise ToolError("bad_request", "not an id")
    return quote(value, safe="")


@dataclass(frozen=True)
class Pulled:
    """One leased delivery: ``delivery_id`` acknowledges it."""

    delivery_id: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class Pulls:
    """One take's batch: ``lease`` acknowledges it."""

    lease: str
    items: list[Pulled]
    more: bool


class Backend(Protocol):
    """The agent-scope operations a tool may call, and the delivery queue."""

    @property
    def mode(self) -> Literal["host", "attach"]: ...

    async def create_group(self, name: str, purpose: str) -> dict[str, Any]: ...
    async def create_invite(self, group: str, max_uses: int, ttl_secs: int) -> dict[str, Any]: ...
    async def accept(self, url: str, display_name: str | None) -> dict[str, Any]: ...
    async def send(
        self, group: str, text: str, to: Sequence[str], reply_to: Sequence[str] | None
    ) -> dict[str, Any]: ...
    async def groups(self) -> dict[str, Any]: ...
    async def group_info(self, group: str) -> dict[str, Any]: ...
    async def leave(self, group: str) -> dict[str, Any]: ...
    async def events(self, after: int, group: str | None) -> dict[str, Any]: ...
    async def knock_inspect(self, listing: str, domain_check: bool | None) -> dict[str, Any]: ...
    async def knock(
        self,
        listing: str,
        *,
        listing_sha256: str | None,
        display_name: str | None,
        note: str | None,
        domain_check: bool | None,
    ) -> dict[str, Any]: ...
    async def knocks(self) -> dict[str, Any]: ...
    async def listing_status(self) -> dict[str, Any]: ...
    async def take(self, group: str | None, addressed_only: bool, wait_secs: float) -> Pulls: ...
    async def ack(self, lease: str, delivery_ids: Sequence[str]) -> list[str]: ...
    async def release(self, lease: str, delivery_ids: Sequence[str]) -> None: ...
    async def close(self) -> None: ...


def _refused(e: Exception) -> ToolError | None:
    reply = error_reply(e)
    if reply is None:
        return None
    status, code, message = reply
    return ToolError(code, message, status)


class HostBackend:
    """A runtime in this process (the session that holds the lock)."""

    mode: Literal["host", "attach"] = "host"

    def __init__(self, runtime: Runtime, queue: DeliveryQueue) -> None:
        self.runtime, self.queue = runtime, queue
        self._agent: AgentApi = runtime.agent

    @classmethod
    async def start(
        cls,
        config: Config,
        clock: Clock,
        *,
        keystore: Keystore | None = None,
        options: Options | None = None,
    ) -> HostBackend:
        """Take the lock (``DataDirLockedError`` if another runtime has it),
        open the keys and databases and start the runtime, its local API
        included. Nothing stays open if this fails or is cancelled."""
        queue = DeliveryQueue(clock)
        runtime = Runtime(
            config,
            adapters=[queue],
            clock=clock,
            keystore=keystore,
            options=replace(options or Options(), lock_owner="mcp"),
        )
        await runtime.start()  # stops it again itself if this fails
        return cls(runtime, queue)

    async def _run(self, call: Any) -> dict[str, Any]:
        try:
            result: dict[str, Any] = await call
        except Exception as e:
            refused = _refused(e)
            if refused is None:
                raise
            raise refused from None
        return result

    async def create_group(self, name: str, purpose: str) -> dict[str, Any]:
        return await self._run(self._agent.create_group(name, purpose))

    async def create_invite(self, group: str, max_uses: int, ttl_secs: int) -> dict[str, Any]:
        return await self._run(
            self._agent.create_invite(group, ttl_secs=ttl_secs, max_uses=max_uses)
        )

    async def accept(self, url: str, display_name: str | None) -> dict[str, Any]:
        return await self._run(self._agent.accept_invite(url, display_name))

    async def send(
        self, group: str, text: str, to: Sequence[str], reply_to: Sequence[str] | None
    ) -> dict[str, Any]:
        return await self._run(self._agent.send(group, text=text, to=to, reply_to=reply_to))

    async def groups(self) -> dict[str, Any]:
        return await self._run(self._agent.list_groups())

    async def group_info(self, group: str) -> dict[str, Any]:
        return await self._run(self._agent.group_info(group))

    async def leave(self, group: str) -> dict[str, Any]:
        return await self._run(self._agent.leave(group))

    async def events(self, after: int, group: str | None) -> dict[str, Any]:
        return await self._run(self._agent.events(after, group))

    async def knock_inspect(self, listing: str, domain_check: bool | None) -> dict[str, Any]:
        return await self._run(self._agent.knock_inspect(listing, domain_check=domain_check))

    async def knock(
        self,
        listing: str,
        *,
        listing_sha256: str | None,
        display_name: str | None,
        note: str | None,
        domain_check: bool | None,
    ) -> dict[str, Any]:
        return await self._run(
            self._agent.knock(
                listing,
                listing_sha256=listing_sha256,
                display_name=display_name,
                note=note,
                domain_check=domain_check,
            )
        )

    async def knocks(self) -> dict[str, Any]:
        return await self._run(self._agent.knocks())

    async def listing_status(self) -> dict[str, Any]:
        return await self._run(self._agent.listing_status())

    async def take(self, group: str | None, addressed_only: bool, wait_secs: float) -> Pulls:
        if group is not None:
            await self.group_info(group)  # an unknown group is not_found, not silence
        batch = await self.queue.take(group, addressed_only=addressed_only, wait_secs=wait_secs)
        items = [Pulled(str(t.delivery_id), t.payload) for t in batch.items]
        return Pulls(batch.lease, items, batch.more)

    async def ack(self, lease: str, delivery_ids: Sequence[str]) -> list[str]:
        return [str(d) for d in self.queue.ack(lease, [int(d) for d in delivery_ids])]

    async def release(self, lease: str, delivery_ids: Sequence[str]) -> None:
        self.queue.release(lease, [int(d) for d in delivery_ids])

    async def close(self) -> None:
        """Stop the runtime: queued sends get the bounded flush, the lock is
        released (cancellation-safe: :meth:`Runtime.stop`)."""
        await self.runtime.stop()


class AttachBackend:
    """A client of the runtime that holds the lock, with the agent token."""

    mode: Literal["host", "attach"] = "attach"

    def __init__(
        self,
        config: Config,
        holder: str | None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.holder = holder  # what owns the directory: "mcp", "daemon", "embedded"
        try:
            token = (config.data_dir / API_TOKEN_FILE).read_text(encoding="ascii").strip()
        except FileNotFoundError:
            msg = f"no {API_TOKEN_FILE} in {config.data_dir}: is its runtime running?"
            raise ToolError("not_running", msg, 503) from None
        if transport is None:
            transport = (
                local_async_tcp_transport(config.api_tcp_port, config.data_dir)
                if config.api_tcp_port
                else local_async_transport(config.socket_path, config.data_dir)
            )
        base = tcp_base_url(config.api_tcp_port) if config.api_tcp_port else "http://agentconnectd"
        self._http = httpx.AsyncClient(
            transport=transport,
            base_url=base,
            timeout=POLL_SECS + HTTP_SLACK_SECS,
            trust_env=False,
            headers={"authorization": f"Bearer {token}"},
        )

    async def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None, **params: Any
    ) -> dict[str, Any]:
        try:
            resp = await self._http.request(method, path, json=body, params=params or None)
        except PeerMismatchError as e:
            raise ToolError(e.code, str(e), 503) from None
        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            raise OwnerGoneError(sent=False) from e
        except httpx.TransportError as e:
            raise OwnerGoneError(sent=True) from e
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        if resp.status_code != 200:  # noqa: PLR2004
            code = str(data.get("code", "error"))
            raise ToolError(code, str(data.get("message", "")), resp.status_code)
        return data

    async def create_group(self, name: str, purpose: str) -> dict[str, Any]:
        return await self._request("POST", "/v0/groups", {"name": name, "purpose": purpose})

    async def create_invite(self, group: str, max_uses: int, ttl_secs: int) -> dict[str, Any]:
        body = {"max_uses": max_uses, "ttl_secs": ttl_secs}
        return await self._request("POST", f"/v0/groups/{segment(group)}/invites", body)

    async def accept(self, url: str, display_name: str | None) -> dict[str, Any]:
        body: dict[str, Any] = {"url": url}
        if display_name is not None:
            body["display_name"] = display_name
        return await self._request("POST", "/v0/invites/accept", body)

    async def send(
        self, group: str, text: str, to: Sequence[str], reply_to: Sequence[str] | None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"text": text, "to": list(to)}
        if reply_to is not None:
            body["reply_to"] = list(reply_to)
        return await self._request("POST", f"/v0/groups/{segment(group)}/messages", body)

    async def groups(self) -> dict[str, Any]:
        return await self._request("GET", "/v0/groups")

    async def group_info(self, group: str) -> dict[str, Any]:
        return await self._request("GET", f"/v0/groups/{segment(group)}")

    async def leave(self, group: str) -> dict[str, Any]:
        return await self._request("POST", f"/v0/groups/{segment(group)}/leave")

    async def events(self, after: int, group: str | None) -> dict[str, Any]:
        params: dict[str, Any] = {"after": after}
        if group is not None:
            params["group"] = group
        return await self._request("GET", "/v0/events", **params)

    async def knock_inspect(self, listing: str, domain_check: bool | None) -> dict[str, Any]:
        body: dict[str, Any] = {"listing": listing}
        if domain_check is not None:
            body["domain_check"] = domain_check
        return await self._request("POST", "/v0/knocks/inspect", body)

    async def knock(
        self,
        listing: str,
        *,
        listing_sha256: str | None,
        display_name: str | None,
        note: str | None,
        domain_check: bool | None,
    ) -> dict[str, Any]:
        fields = {
            "listing_sha256": listing_sha256,
            "display_name": display_name,
            "note": note,
            "domain_check": domain_check,
        }
        body = {"listing": listing} | {k: v for k, v in fields.items() if v is not None}
        return await self._request("POST", "/v0/knocks", body)

    async def knocks(self) -> dict[str, Any]:
        return await self._request("GET", "/v0/knocks")

    async def listing_status(self) -> dict[str, Any]:
        return await self._request("GET", "/v0/listing")

    async def take(self, group: str | None, addressed_only: bool, wait_secs: float) -> Pulls:
        """Long-poll ``GET /v0/deliveries`` in steps of :data:`POLL_SECS`
        until something comes or ``wait_secs`` is used up."""
        if group is not None:
            await self.group_info(group)
        steps = max(1, math.ceil(wait_secs / POLL_SECS))
        left = wait_secs
        for _ in range(steps):
            wait = min(POLL_SECS, math.ceil(left))
            left -= wait
            params: dict[str, Any] = {"addressed_only": int(addressed_only), "timeout": wait}
            if group is not None:
                params["group"] = group
            data = await self._request("GET", "/v0/deliveries", **params)
            rows = data.get("deliveries") or []
            if rows:
                pulled = [Pulled(str(r["delivery_id"]), dict(r["message"])) for r in rows]
                return Pulls(str(data.get("lease", "")), pulled, bool(data.get("more")))
        return Pulls("", [], more=False)

    async def ack(self, lease: str, delivery_ids: Sequence[str]) -> list[str]:
        if not delivery_ids:
            return []
        body = {"lease": lease, "ids": list(delivery_ids)}
        refused = (await self._request("POST", "/v0/deliveries/ack", body)).get("refused") or []
        return [d for d in delivery_ids if d not in refused]

    async def release(self, lease: str, delivery_ids: Sequence[str]) -> None:
        if delivery_ids:
            body = {"lease": lease, "ids": list(delivery_ids)}
            await self._request("POST", "/v0/deliveries/release", body)

    async def close(self) -> None:
        await self._http.aclose()
