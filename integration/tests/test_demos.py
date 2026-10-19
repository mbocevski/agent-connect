"""Both demos, end to end in docker compose, and what the relay saw.

Each demo puts unique markers in its message bodies. After the run, the
markers must be in the agents' output (they got the messages) and nowhere
in what the relay handled: every WebSocket frame each host's tap recorded
in both directions, the relay's logs and its database (with the WAL)."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

pytestmark = pytest.mark.timeout(600)


def relay_evidence(dep: Any, hosts: list[str]) -> dict[str, bytes]:
    """Everything the relay saw or kept: the taps' frames, its logs, its
    database files."""
    evidence = {f"frames:{h}": json.dumps(dep.tap(h, "frames")).encode() for h in hosts}
    evidence["relay-logs"] = dep.logs("relay").encode()
    with tempfile.TemporaryDirectory() as tmp:
        dep.compose("cp", "relay:/relay", tmp)
        files = sorted(Path(tmp, "relay").iterdir())
        assert any(f.name == "relay.db" for f in files)
        for f in files:
            evidence[f"db:{f.name}"] = f.read_bytes()
    return evidence


def assert_no_plaintext(
    evidence: dict[str, bytes], markers: list[str], encodings: Callable[[str], list[bytes]]
) -> None:
    leaks = [
        (where, marker)
        for marker in markers
        for where, data in evidence.items()
        for needle in encodings(marker)
        if needle in data
    ]
    assert leaks == []


def application_frames(frames: list[dict[str, Any]], group_id: str) -> int:
    return sum(
        1
        for f in frames
        if (f["frame"].get("env") or {}).get("kind") == "application"
        and f["frame"]["env"].get("group_id") == group_id
    )


def test_one_to_one_demo_shows_the_relay_no_plaintext(
    one_to_one_deployment: Any,
    driver: ModuleType,
    encodings: Callable[[str], list[bytes]],
    run_id: str,
) -> None:
    dep = one_to_one_deployment
    result = driver.one_to_one(dep, run_id)
    m1, m2, m3, m4 = result.markers
    # The agents got every message (so the markers were really sent).
    agent_a, agent_b = dep.logs("agent-a"), dep.logs("agent-b")
    assert m1 in agent_a
    assert m2 in agent_a
    assert m3 in agent_b
    assert m3 in agent_a  # B's answer quotes it
    closes = [e for e in dep.events("daemon-b") if e["type"] == "close_requested"]
    assert m4 in closes[0]["data"]["reason"]
    # The taps saw the conversation, encrypted, in both directions.
    for host in ("host-a", "host-b"):
        frames = dep.tap(host, "frames")
        assert application_frames(frames, result.group_id) >= 5
        assert {f["dir"] for f in frames} == {"in", "out"}
    assert_no_plaintext(relay_evidence(dep, ["host-a", "host-b"]), result.markers, encodings)


def test_group_demo_shows_the_relay_no_plaintext(
    group_deployment: Any, driver: ModuleType, encodings: Callable[[str], list[bytes]], run_id: str
) -> None:
    dep = group_deployment
    result = driver.group_demo(dep, run_id)
    g1, g2, g3, g4 = result.markers
    agent_b, agent_c = dep.logs("agent-b"), dep.logs("agent-c")
    assert g1 in agent_c
    assert g2 in agent_b
    assert g2 in agent_c
    assert g3 in agent_b
    assert g3 not in agent_c
    assert g4 in agent_b
    for host in ("host-a", "host-b", "host-c"):
        assert application_frames(dep.tap(host, "frames"), result.group_id) >= 3
    assert_no_plaintext(
        relay_evidence(dep, ["host-a", "host-b", "host-c"]), result.markers, encodings
    )
