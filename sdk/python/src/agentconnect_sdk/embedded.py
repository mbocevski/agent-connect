"""The embedded host: the AgentConnect runtime inside the agent's process.

:meth:`AgentConnect.embedded <agentconnect_sdk.AgentConnect.embedded>` builds
an :class:`EmbeddedHost`. It runs one :class:`agentconnect.runtime.Runtime`
on the agent's asyncio loop, with an in-process callback adapter in place
of a webhook, and answers the SDK's operations through the runtime's
agent-scope :class:`~agentconnect.runtime.AgentApi`. Every check, limit and
approval path is the runtime's own, the same code the separate daemon runs.

What agent code gets here is the agent scope only. The runtime also serves
the local API socket with the agent/human token split, so the human runs
the human-only commands (approvals, verify, safety) with the CLI. This host
never reads the human token and offers no human operation (ADR-005,
Decision 4). It is not a sandbox: code in this process, or anything with
shell or file access as this OS user, can reach the data directory.
"""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal, override

from agentconnect.runtime import (
    STOP_FLUSH_SECS,
    Adapter,
    AgentApi,
    CallbackAdapter,
    Clock,
    Config,
    ConfigError,
    DataDirLockedError,
    HandledIds,
    Keystore,
    Options,
    Runtime,
    SystemClock,
    error_reply,
    load_config,
)
from agentconnect_sdk.dedupe import Deduper
from agentconnect_sdk.errors import AgentConnectError
from agentconnect_sdk.errors import DataDirLockedError as LockedError

ADAPTER_NAME = "sdk"  # the name groups created by an embedded agent are bound to
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

Dispatch = Callable[[dict[str, Any]], Awaitable[Literal["handled", "duplicate", "busy"]]]
Wrap = Callable[[CallbackAdapter], Adapter]


def default_data_dir(name: str, environ: Mapping[str, str] = os.environ) -> Path:
    """``$XDG_DATA_HOME/agentconnect-<name>`` (``~/.local/share`` without it)."""
    if not _NAME.match(name):
        msg = "name: 1 to 64 of A-Z a-z 0-9 . _ -, starting with a letter or digit"
        raise AgentConnectError("bad_config", msg)
    raw = environ.get("XDG_DATA_HOME", "").strip()
    base = Path(raw) if raw else Path(environ.get("HOME", str(Path.home()))) / ".local/share"
    return base / f"agentconnect-{name}"


class _BusyError(Exception):
    """The same id is being handled now: hand it over again later."""


class StoredDeduper(Deduper):
    """A :class:`Deduper` whose finished ids live in the runtime's encrypted
    database, so a delivery repeated after a crash or restart doesn't reach
    the handlers again."""

    def __init__(self, handled: Callable[[], HandledIds]) -> None:
        super().__init__()
        self._handled = handled
        # The store an id was claimed against, so done() records it there
        # even while the runtime is stopping.
        self._claims: dict[str, HandledIds] = {}

    @override
    def claim(self, key: str) -> bool:
        store = self._handled()
        if key in store or not super().claim(key):
            return False
        self._claims[key] = store
        return True

    @override
    def done(self, key: str) -> None:
        store = self._claims.pop(key, None) or self._handled()
        store.add(key)
        super().done(key)

    @override
    def release(self, key: str) -> None:
        self._claims.pop(key, None)
        super().release(key)

    @override
    def handled(self, key: str) -> bool:
        return key in self._handled() or super().handled(key)


class _Operations:
    """The SDK's operations over the runtime's :class:`AgentApi`, with its
    errors turned into :class:`AgentConnectError` as the local API would."""

    def __init__(self, host: EmbeddedHost) -> None:
        self._host = host

    async def _call(self, call: Callable[[AgentApi], Awaitable[dict[str, Any]]]) -> dict[str, Any]:
        agent = self._host.agent()
        try:
            return await call(agent)
        except Exception as e:
            reply = error_reply(e)
            if reply is None:
                raise
            status, code, message = reply
            raise AgentConnectError(code, message, status) from None

    async def status(self) -> dict[str, Any]:
        return await self._call(lambda a: a.status())

    async def create_group(self, name: str, purpose: str) -> dict[str, Any]:
        return await self._call(lambda a: a.create_group(name, purpose))

    async def list_groups(self) -> dict[str, Any]:
        return await self._call(lambda a: a.list_groups())

    async def group_info(self, group_id: str) -> dict[str, Any]:
        return await self._call(lambda a: a.group_info(group_id))

    async def create_invite(self, group_id: str, max_uses: int, ttl_secs: int) -> dict[str, Any]:
        return await self._call(
            lambda a: a.create_invite(group_id, ttl_secs=ttl_secs, max_uses=max_uses)
        )

    async def send(self, group_id: str, message: dict[str, Any]) -> dict[str, Any]:
        return await self._call(
            lambda a: a.send(
                group_id,
                message["body"],
                to=message.get("to", ("*",)),
                kind=message.get("kind", "a2a.message"),
                reply_to=message.get("reply_to"),
                addressee=message.get("addressee"),
            )
        )

    async def leave(self, group_id: str) -> dict[str, Any]:
        return await self._call(lambda a: a.leave(group_id))

    async def accept(self, url: str, display_name: str | None) -> dict[str, Any]:
        return await self._call(lambda a: a.accept_invite(url, display_name))


class EmbeddedHost:
    """One runtime in this process, for one :class:`AgentConnect`.

    ``extra_adapters``, ``wrap``, ``clock``, ``keystore``, ``options`` and
    ``serve_api`` are for tests and special setups; the defaults are what
    :meth:`AgentConnect.embedded` uses.
    """

    def __init__(  # noqa: PLR0913
        self,
        config: Config,
        *,
        extra_adapters: Iterable[Adapter] = (),
        wrap: Wrap | None = None,
        clock: Clock | None = None,
        keystore: Keystore | None = None,
        options: Options | None = None,
        serve_api: bool = True,
        flush: float = STOP_FLUSH_SECS,
    ) -> None:
        if config.isolation:
            msg = (
                "isolation.enabled is for a separate daemon only: the embedded "
                "runtime runs as the agent's own user (docs/isolation.md)"
            )
            raise AgentConnectError("bad_config", msg)
        self.config = config
        self._extra = list(extra_adapters)
        self._wrap = wrap
        self._clock = clock or SystemClock()
        self._keystore, self._serve_api, self._flush = keystore, serve_api, flush
        self._options = replace(options or Options(), lock_owner="embedded")
        self._runtime: Runtime | None = None
        self._adapter: CallbackAdapter | None = None
        self._stopped = asyncio.Event()
        self._starting = asyncio.Lock()  # one start at a time
        self._stopping: asyncio.Task[None] | None = None  # the one shutdown

    @property
    def data_dir(self) -> Path:
        return self.config.data_dir

    @staticmethod
    def configure(  # noqa: PLR0913
        name: str | None,
        *,
        data_dir: Path | str | None = None,
        relay: str | None = None,
        config: Path | str | None = None,
        display_name: str | None = None,
        environ: Mapping[str, str] = os.environ,
    ) -> Config:
        """The embedded runtime's :class:`Config`: the TOML file ``config``
        if given (never the separate daemon's default file), ``AC_*``
        environment overrides, then these arguments."""
        if name is None and data_dir is None:
            msg = "pass name= (or data_dir=): one data directory is one identity"
            raise AgentConnectError("bad_config", msg)
        env_dir = environ.get("AC_DATA_DIR", "")
        if data_dir is not None:
            where = Path(data_dir).expanduser()
        elif name is not None:
            where = default_data_dir(name, environ)
            # An AC_DATA_DIR exported for another agent's CLI must not hand
            # this name that agent's identity (ADR-005, Decision 2).
            if env_dir != "" and Path(env_dir).expanduser() != where:
                msg = (
                    f"AC_DATA_DIR is {env_dir}, not the data directory of name={name!r} "
                    f"({where}); unset it, or pass data_dir= to choose one"
                )
                raise AgentConnectError("bad_config", msg)
        else:
            where = Path(env_dir).expanduser()
        overrides: dict[str, Any] = {"data_dir": where, "default_adapter": ADAPTER_NAME}
        if relay is not None:
            overrides |= {"relay_url": relay, "relay_host": ""}
        if display_name is not None or (name is not None and config is None):
            overrides["display_name"] = display_name or name
        try:
            return load_config(
                None if config is None else Path(config).expanduser(),
                environ,
                use_file=config is not None,
                **overrides,
            )
        except ConfigError as e:
            raise AgentConnectError("bad_config", str(e)) from None

    def deduper(self) -> Deduper:
        return StoredDeduper(self._handled)

    def operations(self) -> _Operations:
        return _Operations(self)

    def _running(self) -> Runtime:
        if self._runtime is None:
            msg = "the embedded runtime isn't running: use async with, or await start()"
            raise AgentConnectError("not_running", msg)
        return self._runtime

    def _handled(self) -> HandledIds:
        return self._running().handled

    def agent(self) -> AgentApi:
        return self._running().agent

    @property
    def runtime(self) -> Runtime | None:
        """The running runtime, for the host's own use (tests, status)."""
        return self._runtime

    async def start(self, dispatch: Dispatch) -> None:
        """Take the lock, open the keys and databases, start the runtime.
        On failure or cancellation nothing stays open. Concurrent calls start
        one runtime; a start during a shutdown waits for it to finish."""
        async with self._starting:
            if self._stopping is not None:
                await asyncio.shield(self._stopping)
            if self._runtime is None:
                await self._start(dispatch)

    async def _start(self, dispatch: Dispatch) -> None:
        async def on_payload(payload: dict[str, Any]) -> None:
            if await dispatch(payload) == "busy":
                raise _BusyError

        adapter = CallbackAdapter(
            on_payload,
            on_payload,
            self._clock,
            name=ADAPTER_NAME,
            timeout=self.config.sdk_handler_timeout,
            rng=self._options.backoff_rng,
        )
        registered = adapter if self._wrap is None else self._wrap(adapter)
        try:
            runtime = Runtime(
                self.config,
                adapters=[registered, *self._extra],
                clock=self._clock,
                keystore=self._keystore,
                options=self._options,
                serve_api=self._serve_api,
            )
        except DataDirLockedError as e:
            msg = f"{e}. Use another name or data_dir for a second agent."
            raise LockedError(msg) from None
        await runtime.start()  # stops it again itself if this fails
        self._runtime, self._adapter = runtime, adapter
        self._stopped.clear()

    async def serve(self, ready: asyncio.Event | None = None) -> None:
        """Hand deliveries to the handlers until cancelled or stopped."""
        self._running()
        adapter = self._adapter
        if adapter is None:  # pragma: no cover - set together with the runtime
            return
        adapter.open()
        if ready is not None:
            ready.set()
        try:
            await self._stopped.wait()
        finally:
            adapter.pause()

    async def stop(self, *, flush: float | None = None) -> None:
        """Stop the runtime: stop handing over new deliveries, give handlers
        that are running and queued sends up to the flush window (3 s by
        default) to finish, then stop the API, the workers and the relay link,
        close the databases and release the lock. Handlers that finish in the
        window are recorded as handled, and what they send goes out.

        Concurrent calls share one shutdown. Called from inside a handler, it
        only schedules the shutdown and returns, so the handler can return
        (a handler can't wait for the end of its own runtime); ``serve()``
        returns once the shutdown is complete."""
        adapter = self._adapter
        if self._stopping is None:
            if self._runtime is None:
                return
            window = self._flush if flush is None else flush
            self._stopping = asyncio.ensure_future(self._shutdown(window))
        if adapter is not None and adapter.in_handler():
            return
        await self._stopping

    async def _shutdown(self, window: float) -> None:
        runtime, adapter = self._runtime, self._adapter
        try:
            if adapter is not None:
                adapter.pause()
                await adapter.drain(window)
            if runtime is not None:
                await runtime.stop(flush=window)
        finally:
            self._runtime = self._adapter = None
            self._stopping = None
            self._stopped.set()
