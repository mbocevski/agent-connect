"""pytest fixtures for multi-node tests (registered in the root conftest).

* ``relay``: the real relay binary on a random port (one per session);
* ``directory``: the real directory binary, listing that relay (one per session);
* ``cluster``: runtimes with recording adapters on a shared FakeClock,
  once per host (``daemon``, ``embedded``); ``@pytest.mark.hosts(...)``
  keeps a scenario to some;
* ``sockdir``: a short temp directory for API sockets;
* ``group``: ``await group(n, mode)`` -> ``(nodes, group_id)``;
* ``invite``: ``await invite(inviter, joiner, group_id)``;
* ``partition``: ``await partition(node)`` cuts a daemon off; ``heal(node)``;
* ``advance``: ``await advance(seconds)`` moves daemon time;
* ``malicious_relay``: ``malicious_relay(node)`` is that node's proxy, with
  drop/reorder/replay/inject/rewrite/forge/fork controls.
"""

from __future__ import annotations

import random
import shutil
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path

import pytest
import pytest_asyncio

from agentconnect_harness.cluster import HOSTS, Cluster, Node
from agentconnect_harness.directory import DirectoryProcess, run_directory
from agentconnect_harness.proxy import RelayProxy
from agentconnect_harness.relay import RelayProcess, run_relay

# Harness tests start and stop a real relay process and several daemons, so
# setup and teardown alone can take seconds on a loaded CI runner. They get a
# larger per-test ceiling than the 10 s unit-test default (TESTING.md); an
# explicit @pytest.mark.timeout on a test still wins.
HARNESS_TIMEOUT_SECS = 30


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    kept: list[pytest.Item] = []
    deselected: list[pytest.Item] = []
    for item in items:
        if "harness" in item.path.parts and item.get_closest_marker("timeout") is None:
            item.add_marker(pytest.mark.timeout(HARNESS_TIMEOUT_SECS))
        (kept if _runs_on_its_host(item) else deselected).append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = kept


def _runs_on_its_host(item: pytest.Item) -> bool:
    """``@pytest.mark.hosts("daemon")`` keeps a scenario to the hosts named
    (one that is about a host itself, such as ``agentconnect daemon run``)."""
    marker = item.get_closest_marker("hosts")
    callspec = getattr(item, "callspec", None)
    if marker is None or callspec is None or "cluster" not in callspec.params:
        return True
    return callspec.params["cluster"] in marker.args


@pytest.fixture(scope="session")
def relay(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RelayProcess]:
    with run_relay(tmp_path_factory.mktemp("relay")) as r:
        yield r


@pytest.fixture(scope="session")
def directory(relay: RelayProcess, session_seed: int) -> Iterator[DirectoryProcess]:
    """The real directory on the in-memory store, listing the harness relay
    (one per session, like the relay: scenarios use names of their own)."""
    with run_directory(relay.host, session_seed) as d:
        yield d


@pytest_asyncio.fixture(params=HOSTS)
async def cluster(
    request: pytest.FixtureRequest, relay: RelayProcess, tmp_path: Path, rng: random.Random
) -> AsyncIterator[Cluster]:
    """Runs each scenario once per host: ``daemon`` and ``embedded``."""
    c = Cluster(relay, tmp_path, rng, host=str(request.param))
    try:
        yield c
    finally:
        await c.close()


@pytest.fixture
def sockdir() -> Iterator[Path]:
    """A short directory for Unix sockets (pytest's tmp paths can be too long)."""
    d = Path(tempfile.mkdtemp(prefix="ac-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


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
