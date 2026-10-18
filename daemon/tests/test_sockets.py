"""Unix socket paths longer than the platform allows (macOS: 104 bytes)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentconnect.config import Config
from agentconnect.isolation import IsolationError, check_config
from agentconnect.sockets import (
    MAX_SOCKET_PATH,
    SocketPathError,
    bind_path,
    prepare_bind_dir,
)


def long_path(tmp_path: Path) -> Path:
    path = tmp_path / ("x" * 80) / ("y" * 40) / "agentconnectd.sock"
    assert len(os.fsencode(path)) > MAX_SOCKET_PATH
    return path


def test_a_short_path_is_used_as_is(tmp_path: Path) -> None:
    short = Path("/tmp/a.sock")  # noqa: S108 - only computed, never bound
    assert bind_path(short) == short


def test_a_long_path_maps_to_a_short_stable_one(tmp_path: Path) -> None:
    path = long_path(tmp_path)
    mapped = bind_path(path)
    assert mapped != path
    assert len(os.fsencode(mapped)) <= MAX_SOCKET_PATH
    assert bind_path(path) == mapped  # the CLI computes the same path
    assert bind_path(path.with_name("other.sock")) != mapped
    assert mapped.parent.name == f"agentconnect-{os.geteuid()}"


def test_the_short_directory_is_private_and_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentconnect.sockets.SHORT_ROOT", tmp_path)
    mapped = bind_path(long_path(tmp_path))
    prepare_bind_dir(mapped)
    assert (mapped.parent.stat().st_mode & 0o777) == 0o700
    prepare_bind_dir(mapped)  # idempotent
    mapped.parent.chmod(0o755)
    with pytest.raises(SocketPathError, match="0700"):
        prepare_bind_dir(mapped)
    mapped.parent.rmdir()
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o700)
    mapped.parent.symlink_to(target)
    with pytest.raises(SocketPathError, match="symlink"):
        prepare_bind_dir(mapped)


def test_isolation_refuses_a_socket_path_over_the_limit(tmp_path: Path) -> None:
    agent_dir = tmp_path / ("a" * 120)
    cfg = Config(
        relay_url="ws://127.0.0.1:1",
        relay_host="127.0.0.1:1",
        data_dir=tmp_path / "data",
        isolation=True,
        isolation_agent_dir=agent_dir,
    )
    with pytest.raises(IsolationError, match=f"{MAX_SOCKET_PATH} bytes"):
        check_config(cfg, 1000, set(), set())
