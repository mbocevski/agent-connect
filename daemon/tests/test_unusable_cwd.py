"""The CLI runs from a working directory its user can't search.

A human runs `sudo -u agentconnect agentconnect ...` from wherever they are
(docs/isolation.md). On macOS, `getcwd` then fails with a permission error, and
a dependency calls it while it is imported, so the CLI died before it read its
arguments. Linux answers `getcwd` whatever the permissions, so here a stand-in
fails the way macOS does until the process moves. The isolation-hosts workflow
runs the real thing on macOS.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, get_args, get_type_hints

import pytest
import typer
from typer.models import ArgumentInfo, OptionInfo

from agentconnect import cli, entry

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"

AS_ON_MACOS = """
import errno, os, sys
real_getcwd, real_chdir = os.getcwd, os.chdir
moved = []
def getcwd():
    if not moved:
        raise PermissionError(errno.EACCES, "Permission denied")
    return real_getcwd()
def chdir(path):
    moved.append(path)
    real_chdir(path)
os.getcwd, os.chdir = getcwd, chdir
"""
ENTRY = "from agentconnect.entry import main\nsys.argv[0] = 'agentconnect'\nmain()\n"


def as_on_macos(
    *args: str, env: dict[str, str] | None = None, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", AS_ON_MACOS + ENTRY, *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
        env={**os.environ, **(env or {})},
    )


def test_the_cli_runs_where_its_user_cant_search_the_working_directory() -> None:
    result = as_on_macos("version")
    assert result.returncode == 0, result.stderr
    assert "agentconnect" in result.stdout
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "args",
    [
        ("status", "--config", "config.toml"),
        ("status", "--config", "./config.toml"),
        ("mcp", "--log-file", "mcp.log"),
        ("identity", "import", "export.json"),
        ("identity", "export", "--out", "export.json"),
        ("listing", "publish", "--directory", "d.example.org", "--card", "card.json"),
    ],
)
def test_a_relative_path_is_refused_once_the_process_has_moved(args: tuple[str, ...]) -> None:
    result = as_on_macos(*args, env={"COLUMNS": "200"})
    assert result.returncode == 2, result.stdout + result.stderr
    assert "absolute path" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("name", entry.PATH_VARIABLES)
def test_a_relative_path_in_the_environment_is_refused_too(name: str) -> None:
    result = as_on_macos("status", env={name: "relative/path"})
    assert result.returncode == 2
    assert name in result.stderr
    assert "absolute path" in result.stderr


def test_an_absolute_path_works_after_the_move(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        f'[relay]\nurl = "ws://127.0.0.1:1"\n[daemon]\ndata_dir = "{tmp_path}"\n',
        encoding="utf-8",
    )
    result = as_on_macos("status", "--config", str(config))
    # The daemon isn't running: past the argument, and an answer of its own.
    assert result.returncode == 5, result.stderr
    assert "absolute path" not in result.stderr


def test_a_relative_path_still_works_from_a_usable_directory(tmp_path: Path) -> None:
    (tmp_path / "config.toml").write_text(
        f'[relay]\nurl = "ws://127.0.0.1:1"\n[daemon]\ndata_dir = "{tmp_path}"\n',
        encoding="utf-8",
    )
    code = "import sys\n" + ENTRY
    result = subprocess.run(
        [sys.executable, "-c", code, "status", "--config", "config.toml"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 5, result.stderr


def test_importing_the_package_leaves_the_process_where_it_is() -> None:
    """Moving is for the command: a program that embeds the SDK owns its cwd."""
    code = AS_ON_MACOS + "import agentconnect, agentconnect.entry\nprint(moved)\n"
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"


def test_the_entry_module_imports_nothing_that_calls_getcwd() -> None:
    code = "import sys, agentconnect.entry; print('httpx' in sys.modules, 'rich' in sys.modules)"
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "False False"


def test_the_command_starts_at_the_entry_module() -> None:
    with PYPROJECT.open("rb") as f:
        scripts = tomllib.load(f)["project"]["scripts"]
    assert scripts == {"agentconnect": "agentconnect.entry:main"}


def _commands(app: typer.Typer) -> Iterator[Any]:
    for command in app.registered_commands:
        yield command.callback
    for group in app.registered_groups:
        instance = group.typer_instance
        assert instance is not None
        yield from _commands(instance)


def test_every_path_option_has_the_callback() -> None:
    """A new path option fails here until it refuses a relative path too."""
    seen = 0
    for callback in _commands(cli.app):
        for name, hint in get_type_hints(callback, include_extras=True).items():
            parts = get_args(hint)
            if not parts or not any(Path in (p, *get_args(p)) for p in parts[:1]):
                continue
            infos = [p for p in parts[1:] if isinstance(p, OptionInfo | ArgumentInfo)]
            assert infos, f"{callback.__name__}({name})"
            assert infos[0].callback is cli.absolute_path, f"{callback.__name__}({name})"
            seen += 1
    assert seen >= 10
