"""No automatic approval of knocks, anywhere (SPEC 6.6.4, docs/discovery.md).

Every knock needs its human: there is no config key that approves one, no
policy verdict that does, no agent route, runtime agent method, SDK call or
MCP tool. These tests look for each way in, structurally and by running
it. (The MCP host doesn't exist yet; its PR adds the same check over its
tool list.)"""

from __future__ import annotations

import inspect
import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

import agentconnect_core as ac
import agentconnect_sdk
from agentconnect.adapter import RecordingAdapter
from agentconnect.clock import FakeClock
from agentconnect.config import Config, ConfigError, load_config
from agentconnect.identity import Seeded
from agentconnect.keystore import FileKeystore
from agentconnect.policy import KNOCK_VERDICTS, KnockInbound, SafetyPolicy, Verdict
from agentconnect.relay import b64, unb64
from agentconnect.runtime import AgentApi, ApiError, Options, Runtime
from agentconnect.runtime.api import ROUTE_SPECS, ApiServer
from agentconnect.runtime.engine import HUMAN_EVENTS, KNOCK_OWNER_EVENTS
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE

TESTDATA = Path(__file__).resolve().parents[2] / "testdata"
VECTORS: dict[str, Any] = json.loads((TESTDATA / "knocks.json").read_text())
DECIDING = ("approve", "reject", "decide", "publish", "preview", "verify", "mismatch")


def test_every_route_that_decides_needs_the_human_token() -> None:
    deciding = [s for s in ROUTE_SPECS if any(w in s.path for w in DECIDING)]
    assert {s.path for s in deciding} >= {
        "/v0/approvals/{rid}/approve",
        "/v0/approvals/{rid}/reject",
        "/v0/listing/publish",
        "/v0/listing/preview",
    }
    assert all(s.human for s in deciding), [s.path for s in deciding if not s.human]


def test_the_agent_api_has_no_deciding_method() -> None:
    names = [n for n, _ in inspect.getmembers(AgentApi) if not n.startswith("__")]
    assert not [n for n in names if any(w in n for w in DECIDING)]


def test_the_sdk_has_no_deciding_method() -> None:
    public = [getattr(agentconnect_sdk, n) for n in agentconnect_sdk.__all__]
    for obj in (*public, agentconnect_sdk.AgentConnect, agentconnect_sdk.Group):
        names = [n for n, _ in inspect.getmembers(obj) if not n.startswith("_")]
        assert not [n for n in names if any(w in n for w in DECIDING[:4])], obj


@pytest.mark.parametrize("table", ["knock", "listing"])
def test_no_config_table_approves_knocks(tmp_path: Path, table: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(f"[{table}]\nauto_approve = true\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="always need a human"):
        load_config(path, {"HOME": str(tmp_path)})
    path.write_text(f"[{table}]\napprove = true\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(path, {"HOME": str(tmp_path)})


def test_the_owners_knock_events_are_the_humans() -> None:
    assert {
        "knock_received",
        "knock_approved",
        "knock_rejected",
        "knock_expired",
        "knock_approval_failed",
    } == KNOCK_OWNER_EVENTS
    assert KNOCK_OWNER_EVENTS <= HUMAN_EVENTS


@given(
    on_door=st.integers(0, 100),
    for_identity=st.integers(0, 5),
    limit=st.integers(-5, 100),
)
def test_the_knock_policy_holds_or_drops_and_nothing_else(
    on_door: int, for_identity: int, limit: int
) -> None:
    decision = SafetyPolicy.knock(KnockInbound("ac:v0:x", "door", on_door, for_identity, limit))
    assert decision.verdict in KNOCK_VERDICTS
    assert not decision.delivered
    if decision.verdict is Verdict.HOLD_FOR_APPROVAL:
        assert for_identity == 0
        assert on_door < min(limit, 32)


@pytest.fixture
async def owner(tmp_path: Path, rng: random.Random) -> Any:
    """A runtime with ``policy.auto_approve`` on, holding the vectors' door,
    with a recording adapter as its default adapter."""
    door = VECTORS["door"]
    now = int(VECTORS["valid"]["now"])
    clock = FakeClock(datetime.fromtimestamp(now, UTC))
    recording = RecordingAdapter()
    config = Config(
        relay_url="ws://127.0.0.1:1",
        relay_host="127.0.0.1:1",
        data_dir=tmp_path / "data",
        keystore="file",
        auto_approve=True,
        default_adapter=recording.name,
    )
    rt = Runtime(
        config,
        adapters=[recording],
        clock=clock,
        keystore=FileKeystore(tmp_path / "data" / "keys"),
        options=Options(testing=Seeded(rng.getrandbits(63))),
        serve_api=False,
    )
    engine = rt._engine
    d = ac.Door._derive_for_testing(
        unb64(door["id"]), bytes.fromhex(door["ikm"]), int(door["expires_at"])
    )
    engine.store.add_door(
        door_id=door["id"],
        directory="directory.example.org",
        name="release-planner",
        secret=d.to_secret_bytes(),
        expires_at=d.expires_at,
        now=now,
    )
    engine.listings._doors[door["id"]] = d
    env = {
        "v": 0,
        "kind": "knock",
        "door_id": door["id"],
        "msg_id": b64(rng.randbytes(16)),
        "sender": "knocker",
        "ct": VECTORS["valid"]["sealed"],
    }
    await engine._handle_frame({"t": "deliver", "env": env})
    yield rt, recording
    await rt.stop(flush=0)


async def test_auto_approve_leaves_a_knock_for_the_human(owner: Any) -> None:
    rt, recording = owner
    engine = rt._engine
    (request,) = engine.knocks.approvals()
    assert engine.store.knock_request(request["request_id"])["status"] == "pending"  # type: ignore[index]
    assert engine.store.outbox() == []
    assert [g for g in engine.store.groups() if g.status == "active"] == []
    # The adapter (the agent) heard nothing of it; the event log has it.
    assert not [e for e in recording.events if e.type.startswith("knock")]
    assert [e["type"] for e in engine.store.events()] == ["knock_received"]
    # Not after a timer pass either: the knock lapses, it is never approved.
    rt._engine.clock.advance(3600)  # type: ignore[attr-defined]
    await engine.knocks.step()
    assert engine.store.knock_request(request["request_id"])["status"] == "expired"  # type: ignore[index]
    assert engine.store.outbox() == []


async def test_the_agent_token_cant_list_read_or_decide_knocks(owner: Any) -> None:
    rt, _ = owner
    engine = rt._engine
    (request,) = engine.knocks.approvals()
    server = ApiServer(engine)
    data = engine.config.data_dir
    tokens = {
        scope: (data / name).read_text(encoding="ascii").strip()
        for scope, name in (("agent", API_TOKEN_FILE), ("human", HUMAN_TOKEN_FILE))
    }

    def headers(scope: str) -> dict[str, str]:
        return {"authorization": f"Bearer {tokens[scope]}"}

    rid = request["request_id"]
    for path in (f"/v0/approvals/{rid}/approve", f"/v0/approvals/{rid}/reject"):
        with pytest.raises(ApiError) as e:
            await server.handle("POST", path, headers("agent"), b"")
        assert (e.value.status, e.value.code) == (403, "human_only")
    _, listed = await server.handle("GET", "/v0/approvals", headers("agent"), b"")
    assert listed["approvals"] == []
    _, status = await server.handle("GET", "/v0/status", headers("agent"), b"")
    assert status["pending_approvals"] == 0
    _, seen = await server.handle("GET", "/v0/events", headers("agent"), b"")
    assert seen["events"] == []
    _, human = await server.handle("GET", "/v0/approvals", headers("human"), b"")
    assert [a["request_id"] for a in human["approvals"]] == [rid]
    _, status = await server.handle("GET", "/v0/status", headers("human"), b"")
    assert status["pending_approvals"] == 1
    _, out = await server.handle("POST", f"/v0/approvals/{rid}/approve", headers("human"), b"")
    assert out["status"] == "approving"
