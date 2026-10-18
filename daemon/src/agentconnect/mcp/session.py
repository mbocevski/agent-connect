"""One MCP session's runtime: host it, or attach to the one that runs.

ADR-005, Decision 2: a session that finds the data directory free hosts the
runtime (:class:`~agentconnect.mcp.backend.HostBackend`); one that finds it
locked attaches to the holder (:class:`~agentconnect.mcp.backend.AttachBackend`).

When the holder goes away, the session decides from the lock as it is now,
on every reconnect: held, it attaches to whoever holds it; free, it takes
the directory over unless its last holder was a daemon or an embedded agent
(those are supervised by a host of their own, which brings them back, and a
session holding the lock would keep them from starting). ``flock`` lets one
session win; the new owner finishes what the old one left in its journal
(ADR-004). A reconnect that fails leaves no backend: the next call tries
again.

Acknowledgement (at least once, never lost): a wait's batch stays leased
until the session has written the tool result to the client
(:meth:`Session.result_written`); only then is it acknowledged. A result
that was never written (the call was cancelled, the client stopped reading)
acknowledges nothing, and the batch is offered again when its lease runs
out. An ack the owner refuses or never answers is retried on the next wait,
events call or close, and until it went through the batch's messages are
not treated as repeats: offered again, they are returned again.
"""

from __future__ import annotations

import asyncio
import contextvars
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from agentconnect import log
from agentconnect.deliveries import LEASE_SECS, delivery_key
from agentconnect.keystore import DataDirAccessError, DataDirLock
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

REMEMBER = 4096  # keys of acknowledged messages kept in memory
UNWRITTEN_KEEP = 64  # batches whose result isn't written yet, at most
UNACKED_KEEP = 8  # batches whose ack failed, kept for a retry, at most
MAX_WAITS = 2  # agentconnect_wait calls running at once in one session
SUPERVISED = frozenset({"daemon", "embedded"})  # holders a session never takes over
# Calls that are safe to repeat when the owner went away mid-request.
REPEATABLE = frozenset(
    {"groups", "group_info", "events", "knock_inspect", "knocks", "listing_status", "take"}
)

# The MCP request a tool call serves (set by the server around each call).
current_request: contextvars.ContextVar[object | None] = contextvars.ContextVar(
    "agentconnect_mcp_request", default=None
)


@dataclass
class _Batch:
    lease: str
    ids: list[str]
    keys: list[str]
    msg_ids: list[str] = field(default_factory=list)  # what its result returns
    taken_at: float = 0.0  # Unix seconds on the session's clock


class Session:
    """The agent-scope operations of one MCP session, over whichever backend
    serves it now."""

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
        self._opened = False
        self._switch = asyncio.Lock()
        self._waits = 0
        self._acked: OrderedDict[str, None] = OrderedDict()  # keys acknowledged
        self._unwritten: OrderedDict[object, _Batch] = OrderedDict()
        self._unacked: list[_Batch] = []  # written, but the ack didn't go through
        self._acking: set[asyncio.Task[None]] = set()

    @property
    def mode(self) -> Literal["host", "attach"]:
        return "attach" if self.backend is None else self.backend.mode

    async def open(self) -> None:
        """Host the runtime if the directory is free, else attach. Without a
        relay this session can't host: it attaches, or fails if nothing
        holds the directory."""
        self.backend = await self._connect(startup=True)
        self._opened = True
        LOG.info("mcp_session", mode=self.backend.mode)

    async def _connect(self, *, startup: bool = False) -> Backend:
        """A backend for the directory as it is now (see the module doc)."""
        try:
            held, holder = DataDirLock.probe(self.config.data_dir)
        except DataDirAccessError as e:
            raise ToolError("data_dir_not_accessible", str(e), 403) from None
        if not held:
            if not startup and holder in SUPERVISED:
                msg = (
                    f"the {holder} runtime that owns {self.config.data_dir} isn't running; "
                    "start it again and retry"
                )
                raise ToolError("not_running", msg, 503)
            if not self.config.relay_url:
                msg = (
                    f"nothing runs on {self.config.data_dir} and no relay is configured: "
                    "pass --relay (or set AC_RELAY_URL) so this server can run it"
                )
                raise ToolError("bad_config", msg)
            try:
                return await HostBackend.start(
                    self.config, self._clock, keystore=self._keystore, options=self._options
                )
            except DataDirLockedError as e:
                holder = e.holder  # another session won the lock meanwhile
        return AttachBackend(self.config, holder, self._transport)

    def _connected(self) -> Backend | None:
        return self.backend

    async def _backend(self) -> Backend:
        """The backend, connecting again first if the last reconnect failed."""
        if self.backend is not None:
            return self.backend
        if not self._opened:
            msg = "the session isn't open"
            raise ToolError("not_running", msg, 503)
        async with self._switch:
            current = self._connected()  # another call may have connected meanwhile
            if current is None:
                current = await self._connect()
                self.backend = current
                LOG.info("mcp_reconnected", mode=current.mode)
            return current

    async def _recover(self, failed: Backend) -> None:
        """The holder went away: drop the failed backend, then connect to the
        directory as it is now. If that fails too, the next call retries."""
        async with self._switch:
            if self.backend is not failed:
                return  # another call already switched
            self.backend = None
            await failed.close()
            self.backend = await self._connect()
            LOG.info("mcp_reconnected", mode=self.backend.mode)

    async def _call(self, op: str, *args: Any, **kwargs: Any) -> Any:
        backend = await self._backend()
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
            return await getattr(await self._backend(), op)(*args, **kwargs)
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
        await self.retry_acks()
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
        """A wait's leased batch. At most :data:`MAX_WAITS` run at once per
        session (another is refused with ``busy``). Messages whose ack went
        through already are acknowledged again quietly and left out. The
        batch is acknowledged once its result is written (for the MCP request
        in :data:`current_request`; without one, at once)."""
        if self._waits >= MAX_WAITS:
            msg = f"{MAX_WAITS} agentconnect_wait calls run already in this session"
            raise ToolError("busy", msg, 429)
        self._waits += 1
        try:
            await self.retry_acks()
            pulls = await self._call("take", group, addressed_only, wait_secs)
        finally:
            self._waits -= 1
        fresh: list[Pulled] = []
        repeats: list[Pulled] = []
        for item in pulls.items:
            key = delivery_key(item.payload)
            (repeats if key in self._acked else fresh).append(item)
        now = self._now()
        if repeats:
            await self._ack(_Batch(pulls.lease, [r.delivery_id for r in repeats], [], [], now))
        if fresh:
            batch = _Batch(
                pulls.lease,
                [f.delivery_id for f in fresh],
                [delivery_key(f.payload) for f in fresh],
                [str(f.payload.get("msg_id")) for f in fresh],
                now,
            )
            request = current_request.get()
            if request is None:
                await self._ack(batch)
            else:
                # A batch still kept under this id never had its result
                # written (the client reused the id): it goes back now.
                await self.abandon(request)
                self._unwritten[request] = batch
                while len(self._unwritten) > UNWRITTEN_KEEP:
                    self._unwritten.popitem(last=False)  # its lease runs out
        return fresh, bool(pulls.more)

    def awaiting_write(self) -> bool:
        """Whether some batch waits for its result to be written."""
        return bool(self._unwritten)

    def _now(self) -> float:
        return self._clock.now().timestamp()

    async def result_written(self, request: object, msg_ids: Sequence[str]) -> None:
        """A result for ``request`` returning ``msg_ids`` reached the client's
        pipe: acknowledge the batch kept under that id, if that result is the
        one that returned it. Another answer with the same id (a client that
        reused it) acknowledges nothing."""
        batch = self._unwritten.get(request)
        if batch is not None and list(msg_ids) == batch.msg_ids:
            del self._unwritten[request]
            await self._ack(batch)

    def result_written_soon(self, request: object, msg_ids: Sequence[str]) -> None:
        """:meth:`result_written` in a task of its own (from the writer)."""
        if request not in self._unwritten:
            return
        task = asyncio.ensure_future(self.result_written(request, msg_ids))
        self._acking.add(task)
        task.add_done_callback(self._acking.discard)

    async def abandon(self, request: object) -> None:
        """The batch kept under ``request`` won't be written (the call was
        cancelled, or the client reused the id): release its lease, so its
        messages are offered again at once."""
        batch = self._unwritten.pop(request, None)
        if batch is None:
            return
        try:
            backend = await self._backend()
            await backend.release(batch.lease, batch.ids)
        except (OwnerGoneError, ToolError) as e:
            LOG.info("mcp_release_failed", code=getattr(e, "code", "gone"))

    async def _ack(self, batch: _Batch) -> bool:
        """Acknowledge ``batch``; if the owner refuses or doesn't answer, keep
        it for :meth:`retry_acks` (the newest :data:`UNACKED_KEEP`). Keys
        count as acknowledged only after the owner confirmed them."""
        try:
            backend = await self._backend()
            done = set(await backend.ack(batch.lease, batch.ids))
        except (OwnerGoneError, ToolError) as e:
            LOG.info("mcp_ack_failed", code=getattr(e, "code", "gone"), count=len(batch.ids))
            self._unacked.append(batch)
            del self._unacked[:-UNACKED_KEEP]
            return False
        for delivery_id, key in zip(batch.ids, batch.keys, strict=False):
            if delivery_id in done:
                self._acked[key] = None
                self._acked.move_to_end(key)
        while len(self._acked) > REMEMBER:
            self._acked.popitem(last=False)
        return True

    async def retry_acks(self) -> None:
        """Try again the acks that didn't go through, oldest first, until one
        fails again. A batch older than its lease is dropped instead: its
        messages are offered again anyway."""
        fresh_since = self._now() - LEASE_SECS
        pending = [b for b in self._unacked if b.taken_at >= fresh_since]
        self._unacked = []
        for n, batch in enumerate(pending):
            if not await self._ack(batch):
                self._unacked = [*self._unacked[:-1], *pending[n + 1 :], batch][-UNACKED_KEEP:]
                return

    async def close(self) -> None:
        """Finish the acks (written results only), then stop the runtime
        (host) or the client (attach)."""
        if self._acking:
            await asyncio.gather(*self._acking, return_exceptions=True)
        if self.backend is not None:
            for request in list(self._unwritten):
                await self.abandon(request)
            await self.retry_acks()
        backend, self.backend = self.backend, None
        self._opened = False
        if backend is not None:
            await backend.close()
