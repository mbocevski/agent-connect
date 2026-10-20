"""Events have a retention (``daemon.event_retention_days``), and nothing the
human hasn't read goes unnoticed: a human-only event stays past it until the
human read it, and a reader that asks for events that are gone is told."""

from __future__ import annotations

from typing import Any

import pytest

from agentconnect.runtime.api import ApiServer
from agentconnect.runtime.engine import DAY_SECS
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE
from agentconnect_harness.cluster import Cluster

pytestmark = pytest.mark.hosts("daemon")


async def test_unread_human_events_outlive_their_retention(cluster: Cluster) -> None:
    a = await cluster.node(serve_api=True)
    engine = a.daemon
    tokens = {
        scope: (engine.config.data_dir / name).read_text(encoding="ascii").strip()
        for scope, name in (("agent", API_TOKEN_FILE), ("human", HUMAN_TOKEN_FILE))
    }
    server = ApiServer(engine)

    async def get(scope: str, target: str) -> dict[str, Any]:
        headers = {"authorization": f"Bearer {tokens[scope]}"}
        _, out = await server.handle("GET", target, headers, b"")
        return out

    async def trim() -> None:
        engine._trimmed_at = -DAY_SECS  # the next expire() trims
        await engine.expire()

    old = engine.now() - (engine.config.event_retention_days + 1) * DAY_SECS
    engine.store.add_event(None, "message_failed", {"msg_id": "m"}, old, "unread", agent=False)
    await trim()
    # Past its retention, but the human never read it: kept.
    page = await get("human", "/v0/events?group=x")  # a filtered read reads nothing
    await trim()
    assert "unread" in {e["event_id"] for e in engine.store.events(limit=1000)}
    page = await get("human", "/v0/events")
    assert (page["gap"], page["oldest_available"]) == (False, 1)
    assert "unread" in {e["event_id"] for e in page["events"]}
    await trim()  # read now: it goes
    assert "unread" not in {e["event_id"] for e in engine.store.events(limit=1000)}
    # Asking from before what is left says so, with the token's own sequence.
    page = await get("human", "/v0/events?after=0")
    assert page["gap"] is True
    assert page["oldest_available"] > 1
    latest = page["events"][-1]["seq"] if page["events"] else page["oldest_available"]
    assert (await get("human", f"/v0/events?after={latest}"))["gap"] is False
    agent = await get("agent", "/v0/events")
    assert (agent["gap"], agent["oldest_available"]) == (False, 1)
