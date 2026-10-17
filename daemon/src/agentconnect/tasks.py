"""Stopping helper tasks without swallowing the caller's own cancellation.

``task.cancel(); with suppress(CancelledError): await task`` is wrong: if
the *calling* task is cancelled while it waits, its ``CancelledError`` is
suppressed too, and the caller carries on as if nothing happened (so
``Daemon.stop`` or a shutdown that cancels a worker never takes effect).
"""

from __future__ import annotations

import asyncio
from typing import Any


async def cancel_and_wait(
    *tasks: asyncio.Future[Any], ignore: tuple[type[BaseException], ...] = ()
) -> None:
    """Cancel ``tasks`` and wait until every one has finished.

    How a task ended is ignored when it is its own cancellation or an
    exception in ``ignore``; any other exception is raised (the first, in
    argument order). If the calling task is cancelled meanwhile, its
    ``CancelledError`` propagates: ``gather`` passes the caller's
    cancellation on and reports the tasks' own as results."""
    for t in tasks:
        t.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, BaseException) and not isinstance(r, (asyncio.CancelledError, *ignore)):
            raise r
