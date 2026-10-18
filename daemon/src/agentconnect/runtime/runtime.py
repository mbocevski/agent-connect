"""The runtime: one identity and instance, hosted by ``agentconnectd`` or
inside an agent's process (ADR-005, Decision 1).

A :class:`Runtime` owns the data-directory lock, the protocol engine (keys,
both databases, the relay link, the journal, the inbox and outbox, the
safety policy, approvals, audit and transcript), the adapters, and the local
API server. Hosts decide only where the configuration comes from, when the
runtime starts and stops, which adapters they register and what surface the
agent sees. No host reimplements or overrides a check.

The local API (with the agent and human tokens) is served whenever the
runtime runs, in every host, so the human can always run the CLI's
human-only commands against it. Neither :class:`Runtime` nor its
:attr:`Runtime.agent` offers a human-scope operation.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from agentconnect.adapter import Adapter
from agentconnect.clock import Clock
from agentconnect.config import Config
from agentconnect.isolation import PeerGate
from agentconnect.keystore import Keystore
from agentconnect.runtime.agent import AgentApi
from agentconnect.runtime.api import ApiServer
from agentconnect.runtime.engine import Engine, Options
from agentconnect.runtime.registry import AdapterRegistry

STOP_FLUSH_SECS = 3.0  # how long stop() lets queued sends go out
HANDLED_KEEP = 50_000  # ids an in-process agent's handlers finished with


class HandledIds:
    """The ``msg_id`` and ``event_id`` values an in-process agent's handlers
    finished with, in the runtime's encrypted database, so a redelivery
    after a restart doesn't reach user code again. Keeps the newest
    :data:`HANDLED_KEEP`."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and self._engine.store.handled_has(key)

    def add(self, key: str) -> None:
        self._engine.store.handled_add(key, HANDLED_KEEP)


class Runtime:
    """One runtime. ``async with Runtime(config) as rt:`` or
    :meth:`start` and :meth:`stop`.

    Construction takes the data-directory lock (``DataDirLockedError`` if
    another runtime holds it) and opens the keys and both databases;
    :meth:`start` finishes the journal, starts the workers and the relay
    link, then serves the local API.
    """

    def __init__(  # noqa: PLR0913
        self,
        config: Config,
        *,
        adapters: Iterable[Adapter] = (),
        clock: Clock | None = None,
        keystore: Keystore | None = None,
        options: Options | None = None,
        gate: PeerGate | None = None,
        serve_api: bool = True,
    ) -> None:
        self.config = config
        self.adapters = AdapterRegistry(adapters)
        # Separate-OS-user mode: refuse a loose setup before any key is opened.
        gate = gate if gate is not None else PeerGate.from_config(config)
        self._engine = Engine(
            config, self.adapters, clock=clock, keystore=keystore, options=options
        )
        try:
            self.agent = AgentApi(self._engine)
            self._api = ApiServer(self._engine, gate, self.agent) if serve_api else None
        except BaseException:
            self._engine.close()
            raise
        self.handled = HandledIds(self._engine)
        self._started = False
        self._stopped = False

    @property
    def running(self) -> bool:
        return self._engine.running

    @property
    def api_address(self) -> Path | str | None:
        """The local API's socket path (or ``http://127.0.0.1:<port>``)
        once started; ``None`` before, or when the API isn't served."""
        return None if self._api is None else self._api.address

    def status(self) -> dict[str, Any]:
        """The agent-scope status (what ``GET /v0/status`` answers the agent
        token)."""
        info = self._engine.status(human=False)
        info["held_messages"] = len(self._engine.held_messages(direction="out"))
        return info

    async def start(self) -> None:
        """Journal recovery, workers, relay link, then the local API. If
        this fails or is cancelled, everything is released again and the
        error (or the cancellation) propagates."""
        if self._started:
            msg = "a runtime starts once"
            raise RuntimeError(msg)
        self._started = True
        try:
            await self._engine.start()
            if self._api is not None:
                await self._api.start()
        except BaseException:
            await self.stop(flush=0)
            raise

    async def stop(self, *, flush: float = STOP_FLUSH_SECS) -> None:
        """Give queued sends up to ``flush`` seconds to go out while the
        relay is connected, then stop the API, the workers and the relay
        link, close the databases and release the lock. What hasn't gone out
        stays in the encrypted outbox for the next start; work in progress
        is finished from the journal then (ADR-004). Idempotent. Every step
        runs even if the caller is cancelled meanwhile; that cancellation
        propagates once the lock is released."""
        if self._stopped:
            return
        self._stopped = True
        try:
            if flush > 0 and self._engine.running:
                await self._flush(flush)
        finally:
            try:
                if self._api is not None:
                    await self._api.stop()
            finally:
                await self._engine.stop()

    async def _flush(self, within: float) -> None:
        engine = self._engine
        with contextlib.suppress(TimeoutError):
            await engine.wait_until(
                lambda: not engine.store.outbox() or not engine.link.connected, within
            )

    async def __aenter__(self) -> Runtime:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()
