"""A daemon started outside the separate-OS-user mode with rules in its database
says so to the human, once per start, and keeps them (ADR-007 Decision 1)."""

from __future__ import annotations

from agentconnect_harness.cluster import Cluster


async def test_a_start_outside_the_mode_announces_inert_rules(cluster: Cluster) -> None:
    node = await cluster.node("a")
    node.daemon.store.put_trust_rule(
        {
            "name": "r1",
            "kind": "fake",
            "enabled": True,
            "created_at": 1,
            "changed_at": 1,
            "caps": {"new_per_hour": 1, "new_per_day": 1, "open_at_once": 1, "lifetime_secs": 1},
            "profile": "standard",
            "purpose": None,
            "fields": {},
        }
    )
    await node.restart()
    told = [e for e in node.daemon.store.events(limit=100) if e["type"] == "rules_inert"]
    assert [e["data"]["rules"] for e in told] == [1]
    assert node.daemon.store.trust_rule("r1") is not None
    await node.restart()
    told = [e for e in node.daemon.store.events(limit=100) if e["type"] == "rules_inert"]
    assert len(told) == 2
