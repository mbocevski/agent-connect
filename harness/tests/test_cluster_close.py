"""A teardown that hangs says where: ``Cluster.close`` names the stage it is
in, and every task's stack, when it runs past ``CLOSE_STALL_SECS``. Before,
a stuck teardown ended at pytest's per-test timeout with nothing to say which
stage waited."""

from __future__ import annotations

import asyncio
import random
from pathlib import Path
from typing import cast

import pytest

from agentconnect_harness import cluster as cluster_module
from agentconnect_harness.cluster import Cluster, Node
from agentconnect_harness.relay import RelayProcess


class _Proxy:
    async def stop(self) -> None:
        return None


class _Hangs:
    """A node whose stop waits until the test lets it go."""

    name = "b"

    def __init__(self, release: asyncio.Event) -> None:
        self.proxy = _Proxy()
        self._release = release

    async def stop(self) -> None:
        await self._release.wait()


class _Quick:
    name = "a"

    def __init__(self) -> None:
        self.proxy = _Proxy()

    async def stop(self) -> None:
        return None


def _cluster(tmp_path: Path, *nodes: object) -> Cluster:
    c = Cluster(cast(RelayProcess, object()), tmp_path, random.Random(1))  # noqa: S311 - a fixed seed, not a secret
    c.nodes.extend(cast(Node, n) for n in nodes)
    return c


async def test_a_stalled_close_names_its_stage_and_dumps_the_tasks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cluster_module, "CLOSE_STALL_SECS", 0.0)
    release = asyncio.Event()
    closing = asyncio.ensure_future(_cluster(tmp_path, _Quick(), _Hangs(release)).close())
    for _ in range(5):  # the report is due on the next loop turn
        await asyncio.sleep(0)
    report = capsys.readouterr().err
    assert "Cluster.close still running" in report
    assert "stopping node b" in report
    assert "_Hangs.stop" in report, "the stuck coroutine is in the task dump"
    release.set()
    await closing


async def test_a_close_that_finishes_says_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cluster_module, "CLOSE_STALL_SECS", 0.0)
    await _cluster(tmp_path, _Quick(), _Quick()).close()
    for _ in range(5):
        await asyncio.sleep(0)
    assert capsys.readouterr().err == ""
