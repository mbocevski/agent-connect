"""The runtime's boundary (ADR-005): Runtime, AdapterRegistry, token digests.

No relay here: the relay link points at a closed loopback port and backs
off on the fake clock. Scenarios against the real relay are in the harness.
"""

from __future__ import annotations

import asyncio
import random
from pathlib import Path

import pytest

from agentconnect.adapter import RecordingAdapter
from agentconnect.clock import FakeClock
from agentconnect.config import Config, load_config
from agentconnect.identity import Seeded
from agentconnect.keystore import DataDirLock, FileKeystore
from agentconnect.relay import RelayError
from agentconnect.runtime import AdapterRegistry, ApiError, Options, Runtime, error_reply
from agentconnect.runtime.engine import DaemonError
from agentconnect.tokens import HUMAN_TOKEN_FILE, TokenDigest


def test_errors_map_to_one_answer_in_every_host() -> None:
    assert error_reply(ApiError(403, "human_only", "no")) == (403, "human_only", "no")
    assert error_reply(DaemonError("not_found", "gone")) == (404, "not_found", "gone")
    assert error_reply(DaemonError("something_new", "x")) == (409, "something_new", "x")
    assert error_reply(RelayError("rate_limited", "slow")) == (
        502,
        "rate_limited",
        "rate_limited: slow",
    )
    assert error_reply(ValueError("a bug")) is None


async def test_agent_sends_are_the_agents(
    tmp_path: Path, rng: random.Random, fake_clock: FakeClock
) -> None:
    async with runtime(tmp_path, rng, fake_clock, serve_api=False) as rt:
        gid = (await rt.agent.create_group("Ops", "deploys"))["group_id"]
        sent = await rt.agent.send(gid, text="hello")
        assert sent["status"] == "queued"
        with pytest.raises(ApiError, match="text or body"):
            await rt.agent.send(gid)
        assert (await rt.agent.events(group_id=gid))["events"] == []  # nothing committed yet
        assert (await rt.agent.safety(gid))["group_id"] == gid


def config(tmp_path: Path) -> Config:
    return Config(
        relay_url="ws://127.0.0.1:1",
        relay_host="127.0.0.1:1",
        data_dir=tmp_path / "data",
        keystore="file",
        api_socket=tmp_path / "s.sock",
    )


def runtime(
    tmp_path: Path, rng: random.Random, clock: FakeClock, *, serve_api: bool = True
) -> Runtime:
    return Runtime(
        config(tmp_path),
        clock=clock,
        keystore=FileKeystore(tmp_path / "data" / "keys"),
        options=Options(testing=Seeded(rng.getrandbits(63))),
        serve_api=serve_api,
    )


def test_the_registry_binds_groups_by_name_and_closes_at_start() -> None:
    a, b = RecordingAdapter("a"), RecordingAdapter("b")
    reg = AdapterRegistry([a])
    reg.register(b)
    with pytest.raises(ValueError, match="already registered"):
        reg.register(RecordingAdapter("a"))
    assert reg.bound("b") is b
    assert reg.bound("gone") is a  # unbound groups deliver to the first
    assert list(reg) == ["a", "b"]
    assert len(reg) == 2
    assert reg["a"] is a
    reg.close()
    with pytest.raises(RuntimeError, match="before the runtime starts"):
        reg.register(RecordingAdapter("c"))
    assert AdapterRegistry().bound("x") is None


def test_a_token_digest_matches_without_keeping_the_token(tmp_path: Path) -> None:
    path = tmp_path / HUMAN_TOKEN_FILE
    digest = TokenDigest.of_file(path)
    token = path.read_text(encoding="ascii")
    assert digest.matches(token)
    assert not digest.matches(token + "x")
    assert token not in repr(digest)
    assert not hasattr(digest, "__dict__")  # nothing but the hash in it


def test_the_embedded_config_reads_no_file_unless_asked(tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('[daemon]\ndisplay_name = "from-file"\n', encoding="utf-8")
    env = {"AC_CONFIG": str(cfg), "HOME": str(tmp_path)}
    assert load_config(None, env).display_name == "from-file"
    assert load_config(None, env, use_file=False).display_name == "agent"


async def test_a_runtime_starts_once_and_stops_idempotently(
    tmp_path: Path, rng: random.Random, fake_clock: FakeClock
) -> None:
    rt = runtime(tmp_path, rng, fake_clock)
    assert rt.api_address is None  # not served yet
    async with rt:
        assert rt.running
        assert rt.api_address == tmp_path / "s.sock"
        assert rt.status()["relay"]["connected"] is False
        with pytest.raises(RuntimeError, match="starts once"):
            await rt.start()
    assert not rt.running
    await rt.stop()
    DataDirLock(tmp_path / "data").release()  # released
    assert not (tmp_path / "s.sock").exists()


async def test_a_runtime_without_the_api_and_one_that_never_started(
    tmp_path: Path, rng: random.Random, fake_clock: FakeClock
) -> None:
    rt = runtime(tmp_path, rng, fake_clock, serve_api=False)
    await rt.stop()  # never started: just releases
    DataDirLock(tmp_path / "data").release()
    rt = runtime(tmp_path, rng, fake_clock, serve_api=False)
    await rt.start()
    assert rt.api_address is None
    await rt.stop(flush=1.0)  # disconnected: the flush returns at once
    DataDirLock(tmp_path / "data").release()


async def test_a_bad_token_file_releases_the_lock(
    tmp_path: Path, rng: random.Random, fake_clock: FakeClock
) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    (data / HUMAN_TOKEN_FILE).write_text("loose")
    (data / HUMAN_TOKEN_FILE).chmod(0o644)
    with pytest.raises(PermissionError, match="mode 0600"):
        runtime(tmp_path, rng, fake_clock)
    DataDirLock(data).release()  # nothing holds it


async def test_a_cancelled_stop_still_releases(
    tmp_path: Path, rng: random.Random, fake_clock: FakeClock
) -> None:
    rt = runtime(tmp_path, rng, fake_clock)
    await rt.start()
    stopping = asyncio.ensure_future(rt.stop())
    await asyncio.sleep(0)
    stopping.cancel()
    with pytest.raises(asyncio.CancelledError):
        await stopping
    assert not rt.running
    DataDirLock(tmp_path / "data").release()
