"""One peer message can't stop an agent's MCP server (SPEC 7.2).

A lone surrogate (the JSON escape ``\\ud800``) is valid JSON and valid
UTF-8 on the wire, but no UTF-8 encoder takes the string it decodes to: the
MCP server's stdout writer died on it, the batch was never acknowledged, and
every restart died on the same message. Now the daemon drops it as
malformed; and a message that can't be written out anyway (one recorded
before this check) fails alone for that adapter, acked and reported."""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

import pytest

from agentconnect import limits
from agentconnect.runtime.engine import new_msg_id
from agentconnect_harness.cluster import WAIT, Cluster
from agentconnect_harness.mcp import McpInstance

from .test_mcp import joined_pair

pytestmark = pytest.mark.hosts("daemon")


def seal_lone_surrogate(alice: McpInstance, gid: str) -> str:
    """Queue an ``a2a.message`` from Alice whose text is ``"\\ud800"``."""
    e = alice.engine
    raw = base64.urlsafe_b64decode(gid + "=" * (-len(gid) % 4))
    inner = e.inner("a2a.message", {"parts": [{"text": "MARK"}]}, ["*"])
    plaintext = json.dumps(inner).replace('"MARK"', '"\\ud800"').encode()
    msg_id = new_msg_id()
    env = {
        "v": 0,
        "kind": "application",
        "group_id": gid,
        "epoch": e.client.epoch(raw),
        "msg_id": msg_id,
        "sender": e.mailbox,
        "ct": base64.urlsafe_b64encode(e.client.seal(raw, plaintext)).rstrip(b"=").decode(),
    }
    e._enqueue("app", gid, {"inner": {}, "msg_id": msg_id, "env": env})
    return msg_id


async def wait_survives(bob: McpInstance) -> dict[str, Any]:
    """``agentconnect_wait`` answers, and the server is still running."""
    task = bob._task
    assert task is not None
    call = asyncio.ensure_future(bob.client.ok("agentconnect_wait", {"timeout_s": 30}))
    done, _ = await asyncio.wait({call, task}, timeout=WAIT, return_when=asyncio.FIRST_COMPLETED)
    assert call in done, "the MCP server died, or never answered"
    assert not task.done()
    return call.result()


async def test_a_lone_surrogate_never_reaches_the_mcp_server(cluster: Cluster) -> None:
    alice, bob, gid = await joined_pair(cluster)
    bad = seal_lone_surrogate(alice, gid)
    await alice.client.ok("agentconnect_send", {"group": gid, "text": "after"})
    await alice.wait(lambda: not alice.engine.store.outbox())
    got = await wait_survives(bob)
    (message,) = got["messages"]
    assert message["text"].endswith("after")
    mailbox = alice.engine.mailbox
    assert bob.engine.store.inbox_state(mailbox, bad) == "dropped"
    (row,) = [r for r in bob.engine.store.audit(gid) if r["msg_id"] == bad]
    assert row["reason"] == "malformed"


async def test_a_message_that_cant_be_written_out_fails_alone(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """As if recorded before the check: it reaches the delivery worker."""
    alice, bob, gid = await joined_pair(cluster)
    monkeypatch.setattr(limits, "unsound", limits.too_deep)
    bad = seal_lone_surrogate(alice, gid)
    await alice.client.ok("agentconnect_send", {"group": gid, "text": "after"})
    await alice.wait(lambda: not alice.engine.store.outbox())
    got = await wait_survives(bob)
    (message,) = got["messages"]
    assert message["text"].endswith("after")
    # Acknowledged for the adapter, and the human hears.
    mailbox = alice.engine.mailbox
    await bob.wait(lambda: bob.engine.store.inbox_state(mailbox, bad) == "done")
    (event,) = [
        e["data"] for e in bob.engine.store.events(limit=1000) if e["type"] == "message_failed"
    ]
    assert (event["msg_id"], event["reason"]) == (bad, "unencodable")
    assert not (await wait_survives_empty(bob))["messages"]


async def wait_survives_empty(bob: McpInstance) -> dict[str, Any]:
    """A wait that returns at once: nothing is offered again."""
    return await bob.client.ok("agentconnect_wait", {"timeout_s": 0})
