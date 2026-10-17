"""pytest fixtures for multi-node tests (registered in the root conftest).

* ``relay``: the real relay binary on a random port (one per session);
* ``cluster``: daemons with recording adapters on a shared FakeClock;
* ``group``: ``await group(n, mode)`` -> ``(nodes, group_id)``;
* ``invite``: ``await invite(inviter, joiner, group_id)``;
* ``partition``: ``await partition(node)`` cuts a daemon off; ``heal(node)``;
* ``advance``: ``await advance(seconds)`` moves daemon time;
* ``malicious_relay``: ``malicious_relay(node)`` is that node's proxy, with
  drop/reorder/replay/inject/rewrite/forge/fork controls.
"""

from __future__ import annotations

import random
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path

import pytest
import pytest_asyncio

from agentconnect_harness.cluster import Cluster, Node
from agentconnect_harness.proxy import RelayProxy
from agentconnect_harness.relay import RelayProcess, run_relay

# Harness tests start and stop a real relay process and several daemons, so
# setup and teardown alone can take seconds on a loaded CI runner. They get a
# larger per-test ceiling than the 10 s unit-test default (TESTING.md); an
# explicit @pytest.mark.timeout on a test still wins.
HARNESS_TIMEOUT_SECS = 30


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "harness" in item.path.parts and item.get_closest_marker("timeout") is None:
            item.add_marker(pytest.mark.timeout(HARNESS_TIMEOUT_SECS))


@pytest.fixture(scope="session")
def relay(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RelayProcess]:
    with run_relay(tmp_path_factory.mktemp("relay")) as r:
        yield r


@pytest_asyncio.fixture
async def cluster(
    relay: RelayProcess, tmp_path: Path, rng: random.Random
) -> AsyncIterator[Cluster]:
    c = Cluster(relay, tmp_path, rng)
    try:
        yield c
    finally:
        await c.close()


@pytest.fixture
def group(cluster: Cluster) -> Callable[..., Awaitable[tuple[list[Node], str]]]:
    return cluster.group


@pytest.fixture
def invite(cluster: Cluster) -> Callable[..., Awaitable[None]]:
    return cluster.invite


@pytest.fixture
def advance(cluster: Cluster) -> Callable[[float], Awaitable[None]]:
    return cluster.advance


@pytest.fixture
def partition() -> Callable[[Node], Awaitable[None]]:
    async def cut(node: Node) -> None:
        await node.proxy.cut()
        await node.wait(lambda: not node.daemon.link.connected)

    return cut


@pytest.fixture
def heal(advance: Callable[[float], Awaitable[None]]) -> Callable[[Node], Awaitable[None]]:
    async def fix(node: Node) -> None:
        node.proxy.heal()
        # The daemon waits out its reconnect backoff on the fake clock.
        for _ in range(20):
            if node.daemon.link.connected:
                return
            await node.wait(lambda: node.daemon.link.connected or node.clock.sleepers > 0)
            await advance(60)
        await node.connected()

    return fix


@pytest.fixture
def malicious_relay() -> Callable[[Node], RelayProxy]:
    return lambda node: node.proxy
