"""The CLI runs from a working directory its user can't search.

A human runs `sudo -u agentconnect agentconnect ...` from wherever they are
(docs/isolation.md). On macOS, `getcwd` then fails with a permission error, and
a dependency calls it while it is imported, so the CLI died before it read its
arguments. Linux answers `getcwd` whatever the permissions, so here a stand-in
fails the way macOS does until the process moves. The isolation-hosts workflow
runs the real thing on macOS.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

AS_ON_MACOS = """
import errno, os
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


def test_the_cli_runs_where_its_user_cant_search_the_working_directory() -> None:
    code = AS_ON_MACOS + "from agentconnect.cli import app; app(['version'])"
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "agentconnect" in result.stdout
    assert "Traceback" not in result.stderr


def test_a_usable_directory_is_left_alone(tmp_path: Path) -> None:
    code = "import os, agentconnect; print(os.getcwd())"
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert Path(result.stdout.strip()).resolve() == tmp_path.resolve()
