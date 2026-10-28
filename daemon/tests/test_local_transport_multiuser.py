"""Clients refuse another real user's socket without sending (SR-09), and
accept the daemon's own in the separate-OS-user mode.

Integration tier: needs root, to run the other users' servers, and
``AC_RUN_MULTIUSER=1``::

    sudo AC_RUN_MULTIUSER=1 uv run --all-packages pytest -m multiuser

On Linux a user namespace stands in for root::

    AC_RUN_MULTIUSER=1 unshare --map-auto --map-root-user .venv/bin/python -m pytest \\
        -m multiuser daemon/tests/test_local_transport_multiuser.py

The fast tier skips it; ``test_local_transport.py`` covers the same checks
with injected credentials.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agentconnect.cli import app
from agentconnect.cli_support import EXIT_REFUSED
from agentconnect.config import Config
from agentconnect.mcp.backend import AttachBackend, ToolError
from agentconnect.sockets import bind_path
from agentconnect_sdk import AgentConnect, AgentConnectError

NOBODY = 65534
THIRD = 1234
# The other users' processes run the system Python: they may not be able to
# reach a virtualenv under a private home directory.
OTHER_PYTHON = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable

pytestmark = [
    pytest.mark.multiuser,
    pytest.mark.skipif(
        os.environ.get("AC_RUN_MULTIUSER") != "1" or os.geteuid() != 0,
        reason="needs root and AC_RUN_MULTIUSER=1",
    ),
]

# Binds the path (making its directory 0777 first with "mkdir"), says
# "ready", waits for a line on stdin, then prints how many bytes a client
# sent, or "none" if no client connected.
SQUATTER = """
import os, socket, sys
path = sys.argv[1]
if sys.argv[2] == "mkdir":
    os.mkdir(os.path.dirname(path))
    os.chmod(os.path.dirname(path), 0o777)
s = socket.socket(socket.AF_UNIX)
s.bind(path)
os.chmod(path, 0o666)
s.listen(1)
print("ready", flush=True)
sys.stdin.readline()
s.setblocking(False)
try:
    c, _ = s.accept()
except BlockingIOError:
    print("none", flush=True)
    sys.exit()
c.setblocking(True)
data = b""
while chunk := c.recv(65536):
    data += chunk
print(len(data), flush=True)
"""


class Squatter:
    def __init__(self, path: Path, mkdir: bool) -> None:
        self.proc = subprocess.Popen(
            [OTHER_PYTHON, "-I", "-c", SQUATTER, str(path), "mkdir" if mkdir else "-"],
            user=NOBODY,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self.proc.stdout is not None
        assert self.proc.stdout.readline().strip() == "ready"

    def received(self) -> str:
        out, _ = self.proc.communicate("done\n", timeout=5)
        return out.strip()


@pytest.fixture
def shared() -> Iterator[Path]:
    """A directory anyone may create entries in, like /tmp."""
    d = Path(tempfile.mkdtemp(prefix="ac-mu-"))
    d.chmod(0o1777)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def data_dir(base: Path, rng: random.Random, *parts: str) -> Path:
    d = base.joinpath(*parts)
    d.mkdir(parents=True, mode=0o700)
    for name in ("api-token", "human-token"):
        (d / name).write_text(rng.randbytes(16).hex(), encoding="ascii")
    return d


def run_cli(config: Path) -> tuple[int, Any]:
    result = CliRunner().invoke(app, ["status", "--json", "--config", str(config)])
    return result.exit_code, json.loads(result.output)["error"]


def test_the_cli_refuses_another_users_configured_socket(
    shared: Path, tmp_path: Path, rng: random.Random
) -> None:
    sock = shared / "s.sock"
    squatter = Squatter(sock, mkdir=False)
    data = data_dir(tmp_path, rng, "data")
    config = tmp_path / "config.toml"
    config.write_text(f'[daemon]\ndata_dir = "{data}"\n\n[api]\nsocket = "{sock}"\n')
    code, error = run_cli(config)
    assert (code, error["code"]) == (EXIT_REFUSED, "peer_mismatch")
    assert f"uid {NOBODY}" in error["message"]
    assert squatter.received() == "0"  # connected, then closed unwritten


def test_the_cli_refuses_a_squatted_short_directory(
    shared: Path, tmp_path: Path, rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentconnect.sockets.SHORT_ROOT", shared)
    data = data_dir(tmp_path, rng, "x" * 80, "y" * 40)
    sock = bind_path(data / "agentconnectd.sock")
    assert sock.parent.parent == shared
    squatter = Squatter(sock, mkdir=True)
    config = tmp_path / "config.toml"
    config.write_text(f'[daemon]\ndata_dir = "{data}"\n')
    code, error = run_cli(config)
    assert (code, error["code"]) == (EXIT_REFUSED, "peer_mismatch")
    assert squatter.received() == "none"  # refused before connecting


# Answers each of two connections that sends a request with an empty group
# list, then prints how many bytes they sent in all.
DAEMON = r"""
import os, socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o666)
s.listen(2)
print("ready", flush=True)
total = 0
for _ in range(2):
    c, _ = s.accept()
    data = b""
    while b"\r\n\r\n" not in data and (chunk := c.recv(65536)):
        data += chunk
    total += len(data)
    if data:
        c.sendall(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
            b"content-length: 13\r\nconnection: close\r\n\r\n" + b'{"groups":[]}'
        )
    c.close()
print(total, flush=True)
"""


@pytest.fixture
def agent_dir(rng: random.Random) -> Iterator[Path]:
    """An agent directory owned by the daemon's user (nobody), as
    agentconnect owns /run/agentconnect, with an agent token in it."""
    d = Path(tempfile.mkdtemp(prefix="ac-mu-"))
    d.chmod(0o777)  # so a server of any user can bind in it
    (d / "api-token").write_text(rng.randbytes(16).hex(), encoding="ascii")
    os.chown(d, NOBODY, NOBODY)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def serve_as(uid: int, sock: Path) -> subprocess.Popen[str]:
    server = subprocess.Popen(
        [OTHER_PYTHON, "-I", "-c", DAEMON, str(sock)], user=uid, stdout=subprocess.PIPE, text=True
    )
    assert server.stdout is not None
    assert server.stdout.readline().strip() == "ready"
    return server


@pytest.mark.parametrize(("server_uid", "accepted"), [(NOBODY, True), (THIRD, False)])
async def test_separate_user_mode_accepts_only_the_daemons_socket(
    agent_dir: Path, server_uid: int, accepted: bool
) -> None:
    # The agent client is another user (root here) than the daemon's.
    server = serve_as(server_uid, agent_dir / "agentconnectd.sock")
    sdk = AgentConnect(data_dir=agent_dir, config_path=agent_dir / "none.toml")
    mcp = AttachBackend(Config(relay_url="", relay_host="", data_dir=agent_dir), "daemon")
    try:
        if accepted:
            assert await sdk.groups() == []
            assert await mcp.groups() == {"groups": []}
        else:
            with pytest.raises(AgentConnectError) as sdk_error:
                await sdk.groups()
            assert sdk_error.value.code == "peer_mismatch"
            with pytest.raises(ToolError) as mcp_error:
                await mcp.groups()
            assert mcp_error.value.code == "peer_mismatch"
    finally:
        await sdk.aclose()
        await mcp.close()
    out, _ = server.communicate(timeout=5)
    received = int(out.strip())
    assert received > 0 if accepted else received == 0
