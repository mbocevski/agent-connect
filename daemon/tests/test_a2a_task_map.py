"""The A2A adapter's task map in the daemon's database: it outlives a
restart, each requesting instance keeps its own newest entries so no peer
can push another's out, and entries carry the runtime's clock."""

from __future__ import annotations

import random
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentconnect.a2a_adapter.adapter import TASKS_PER_PEER, A2AAdapter, A2AOptions, TaskRef
from agentconnect.clock import FakeClock, unix_seconds
from agentconnect.store import Store

G = "g1"


@pytest.fixture
def store(tmp_path: Path, rng: random.Random) -> Iterator[Store]:
    s = Store(tmp_path / "d.sqlite3", rng.randbytes(32))
    yield s
    s.close()


def put(store: Store, task: str, requester: str, instance: str, now: int) -> None:
    store.a2a_task_put(
        task,
        group_id=G,
        requester=requester,
        instance=instance,
        msg_id=f"m-{task}",
        now=now,
        keep=TASKS_PER_PEER,
    )


def test_a_peer_cannot_push_another_peers_tasks_out(store: Store) -> None:
    put(store, "honest", "ac:v0:alice", "a1", 1000)
    for n in range(4 * TASKS_PER_PEER):
        put(store, f"t{n}", "ac:v0:mallory", "m1", 1001 + n)
    assert store.a2a_task("honest") == (G, "ac:v0:alice", "a1", "m-honest")
    kept = [n for n in range(4 * TASKS_PER_PEER) if store.a2a_task(f"t{n}") is not None]
    assert kept == list(range(3 * TASKS_PER_PEER, 4 * TASKS_PER_PEER)), "its newest only"
    # Another instance of the same identity has a share of its own.
    put(store, "replica", "ac:v0:mallory", "m2", 5000)
    assert store.a2a_task("replica") is not None
    assert store.a2a_task(f"t{4 * TASKS_PER_PEER - 1}") is not None


def test_the_adapter_keeps_its_tasks_on_the_runtime_clock_across_a_restart(
    store: Store, fake_clock: FakeClock
) -> None:
    adapter = A2AAdapter(A2AOptions())
    adapter.bind_store(store)
    adapter.bind_clock(fake_clock)
    ref = TaskRef(G, "ac:v0:alice", "a1", "m1")
    adapter._keep_task("t1", ref)
    ((at,),) = store._all("SELECT at FROM a2a_agent_tasks WHERE task_id = ?", "t1")
    assert at == unix_seconds(fake_clock)
    # A fresh adapter on the same database (a restart) still knows the task.
    again = A2AAdapter(A2AOptions())
    again.bind_store(store)
    assert again._task("t1") == ref
    assert again._task("t2") is None
