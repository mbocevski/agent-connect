"""``agentconnectd``: the separate-daemon host of the runtime (ADR-005).

It reads the configuration, registers the adapters the configuration names
(:func:`agentconnect.adapters.build_adapters`), runs one
:class:`~agentconnect.runtime.Runtime` until SIGINT or SIGTERM, and stops
it. Everything else, every check included, is the runtime's.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal

from agentconnect.adapters import build_adapters
from agentconnect.runtime import Config, Runtime, SystemClock

SIGNALS = (signal.SIGINT, signal.SIGTERM)


async def serve(config: Config, ready: asyncio.Event | None = None) -> None:
    """Run the daemon until a signal (or cancellation); ``ready`` is set
    once the runtime and its local API are up. Logging is the caller's
    (``agentconnect.log.configure``)."""
    clock = SystemClock()
    runtime = Runtime(config, adapters=build_adapters(config, clock), clock=clock)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    await runtime.start()
    try:
        for sig in SIGNALS:
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop.set)
        if ready is not None:
            ready.set()
        await stop.wait()
    finally:
        for sig in SIGNALS:
            with contextlib.suppress(NotImplementedError):
                loop.remove_signal_handler(sig)
        await runtime.stop()
