"""One MCP session's runtime: host it, or attach to the one that runs.

ADR-005, Decision 2: a session that finds the data directory free hosts the
runtime (:class:`~agentconnect.mcp.backend.HostBackend`); one that finds it
locked attaches to the holder (:class:`~agentconnect.mcp.backend.AttachBackend`).
When the holder was another MCP session and goes away, an attached session
takes the lock over on its next call; ``flock`` lets one session win, and
the others attach to it. The new owner finishes whatever the old one left
in its journal (ADR-004). A daemon or an embedded agent that holds the
directory is supervised by its own host, so an attached session waits for
it to come back instead of taking its directory.

Deduplication: the runtime delivers at least once, keyed by
``["msg", group, sender, msg_id]``. A host session records the keys it
returned in the runtime's handled ids (the encrypted database); this
session also remembers them in memory, so a message an owner handed over
right before it went away isn't returned again by the next owner.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Sequence
from typing import Any, Literal

import httpx

from agentconnect import log
from agentconnect.deliveries import delivery_key
from agentconnect.keystore import DataDirLock
from agentconnect.mcp.backend import (
    AttachBackend,
    Backend,
    HostBackend,
    OwnerGoneError,
    Pulled,
    ToolError,
)
from agentconnect.runtime import Clock, Config, DataDirLockedError, Keystore, Options

LOG = log.get("agentconnect.mcp")

REMEMBER = 4096  # keys of returned messages kept in memory
# Calls that are safe to repeat when the owner went away mid-request.
REPEATABLE = frozenset(
    {"groups", "group_info", "events", "knock_inspect", "knocks", "listing_status", "take"}
)


class Session:
    """Implements :class:`~agentconnect.mcp.backend.Backend` over whichever
    backend currently serves this session."""

    def __init__(
        self,
        config: Config,
        clock: Clock,
        *,
        keystore: Keystore | None = None,
        options: Options | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config, self._clock = config, clock
        self._keystore, self._options, self._transport = keystore, options, transport
        self.backend: Backend | None = None
        self._switch = asyncio.Lock()
        self._returned: OrderedDict[str, None] = OrderedDict()
        self._keys: dict[str, str] = {}  # delivery_id -> key, until acknowledged

    @property
    def mode(self) -> Literal["host", "attach"]:
        return self._current().mode

    def _current(self) -> Backend:
        if self.backend is None:
            msg = "the session isn't open"
            raise ToolError("not_running", msg, 503)
        return self.backend

    async def open(self) -> None:
        """Host the runtime if the directory is free, else attach. Without a
        relay this session can't host: it attaches, or fails if nothing
        holds the directory."""
        self.backend = await self._connect()
        LOG.info("mcp_session", mode=self.backend.mode)

    async def _connect(self, holder: str | None = None, *, take_over: bool = True) -> Backend:
        if take_over and self.config.relay_url:
            try:
                return await HostBackend.start(
                    self.config, self._clock, keystore=self._keystore, options=self._options
                )
            except DataDirLockedError as e:
                holder = e.holder
        elif take_over:
            holder = self._holder_or_fail()
        return AttachBackend(self.config, holder, self._transport)

    def _holder_or_fail(self) -> str | None:
        """Without a relay: who holds the directory (``ToolError`` if nobody)."""
        try:
            DataDirLock(self.config.data_dir, "mcp").release()
        except DataDirLockedError as e:
            return e.holder
        msg = (
            f"nothing runs on {self.config.data_dir} and no relay is configured: "
            "pass --relay (or set AC_RELAY_URL) so this server can run it"
        )
        raise ToolError("bad_config", msg)

    async def _recover(self, failed: Backend) -> None:
        """The holder went away: take over if it was an MCP session, else
        attach again (to whatever holds the directory now)."""
        async with self._switch:
            if self.backend is not failed:
                return  # another call already switched
            await failed.close()
            holder = failed.holder if isinstance(failed, AttachBackend) else None
            self.backend = await self._connect(holder, take_over=holder == "mcp")
            LOG.info("mcp_reconnected", mode=self.backend.mode)

    async def _call(self, op: str, *args: Any, **kwargs: Any) -> Any:
        backend = self._current()
        try:
            return await getattr(backend, op)(*args, **kwargs)
        except OwnerGoneError as e:
            if e.sent and op not in REPEATABLE:
                await self._recover(backend)
                msg = (
                    "the runtime went away during this call: it may or may not have "
                    "happened; check (agentconnect_groups, agentconnect_events) before "
                    "trying again"
                )
                raise ToolError("interrupted", msg, 503) from None
            await self._recover(backend)
        try:
            return await getattr(self._current(), op)(*args, **kwargs)
        except OwnerGoneError:
            msg = (
                f"the runtime that owns {self.config.data_dir} isn't answering; "
                "start it again (or end the other session) and retry"
            )
            raise ToolError("not_running", msg, 503) from None

    async def create_group(self, name: str, purpose: str) -> dict[str, Any]:
        return await self._call("create_group", name, purpose)

    async def create_invite(self, group: str, max_uses: int, ttl_secs: int) -> dict[str, Any]:
        return await self._call("create_invite", group, max_uses, ttl_secs)

    async def accept(self, url: str, display_name: str | None) -> dict[str, Any]:
        return await self._call("accept", url, display_name)

    async def send(
        self, group: str, text: str, to: Sequence[str], reply_to: Sequence[str] | None
    ) -> dict[str, Any]:
        return await self._call("send", group, text, to, reply_to)

    async def groups(self) -> dict[str, Any]:
        return await self._call("groups")

    async def group_info(self, group: str) -> dict[str, Any]:
        return await self._call("group_info", group)

    async def leave(self, group: str) -> dict[str, Any]:
        return await self._call("leave", group)

    async def events(self, after: int, group: str | None) -> dict[str, Any]:
        return await self._call("events", after, group)

    async def knock_inspect(self, listing: str, domain_check: bool | None) -> dict[str, Any]:
        return await self._call("knock_inspect", listing, domain_check)

    async def knock(
        self,
        listing: str,
        *,
        listing_sha256: str | None,
        display_name: str | None,
        note: str | None,
        domain_check: bool | None,
    ) -> dict[str, Any]:
        return await self._call(
            "knock",
            listing,
            listing_sha256=listing_sha256,
            display_name=display_name,
            note=note,
            domain_check=domain_check,
        )

    async def knocks(self) -> dict[str, Any]:
        return await self._call("knocks")

    async def listing_status(self) -> dict[str, Any]:
        return await self._call("listing_status")

    async def take(
        self, group: str | None, addressed_only: bool, wait_secs: float
    ) -> tuple[list[Pulled], bool]:
        """Leased deliveries, without the ones this session returned before
        (those are acknowledged again, quietly)."""
        taken, more = await self._call("take", group, addressed_only, wait_secs)
        fresh: list[Pulled] = []
        repeats: list[str] = []
        for item in taken:
            key = delivery_key(item.payload)
            if key in self._returned:
                repeats.append(item.delivery_id)
            else:
                self._keys[item.delivery_id] = key
                fresh.append(item)
        if repeats:
            await self._ack_quietly(repeats)
        return fresh, bool(more)

    async def ack(self, delivery_ids: Sequence[str]) -> None:
        """The messages are being returned to the model: remember their keys,
        then acknowledge them. An owner that went away meanwhile hands them
        over again later, and :meth:`take` drops them then."""
        for delivery_id in delivery_ids:
            key = self._keys.pop(delivery_id, None)
            if key is not None:
                self._returned[key] = None
                self._returned.move_to_end(key)
        while len(self._returned) > REMEMBER:
            self._returned.popitem(last=False)
        await self._ack_quietly(delivery_ids)

    async def _ack_quietly(self, delivery_ids: Sequence[str]) -> None:
        backend = self._current()
        try:
            await backend.ack(delivery_ids)
        except OwnerGoneError:
            LOG.info("mcp_ack_lost", count=len(delivery_ids))

    async def close(self) -> None:
        """Stop the runtime (host) or the client (attach)."""
        backend, self.backend = self.backend, None
        if backend is not None:
            await backend.close()
