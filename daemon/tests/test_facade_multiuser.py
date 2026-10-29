"""The A2A facade on a Unix socket admits only the users it lists (MAR-270
design, SR-10 class), with a real second user.

Integration tier: needs root, to run the client as another user, and
``AC_RUN_MULTIUSER=1``::

    sudo AC_RUN_MULTIUSER=1 uv run --all-packages pytest -m multiuser

On Linux a user namespace stands in for root::

    AC_RUN_MULTIUSER=1 unshare --map-auto --map-root-user .venv/bin/python -m pytest \\
        -m multiuser daemon/tests/test_facade_multiuser.py

The fast tier skips it; ``test_a2a_facade.py`` covers the same check with
injected credentials.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentconnect.a2a_adapter import A2AAdapter, A2AOptions

NOBODY = 65534  # its group is 65534 too
OTHER_PYTHON = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable

pytestmark = [
    pytest.mark.multiuser,
    pytest.mark.skipif(
        os.environ.get("AC_RUN_MULTIUSER") != "1" or os.geteuid() != 0,
        reason="needs root and AC_RUN_MULTIUSER=1",
    ),
]

# Connects, asks for a card without a token, prints the status line, or
# "closed" when the server closed the connection without answering.
CLIENT = r"""
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
try:
    s.sendall(b"GET /g/Z3JvdXA/.well-known/agent-card.json HTTP/1.1\r\nhost: localhost\r\n\r\n")
    data = s.recv(65536)
except OSError:
    data = b""
print(data.split(b"\r\n", 1)[0].decode() if data else "closed", flush=True)
"""


@pytest.fixture
def shared() -> Iterator[Path]:
    d = Path(tempfile.mkdtemp(prefix="ac-mu-"))
    d.chmod(0o755)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.parametrize(("listed", "answer"), [(False, "closed"), (True, "HTTP/1.1 401")])
async def test_only_a_listed_user_reaches_the_facade(
    shared: Path, tmp_path: Path, listed: bool, answer: str
) -> None:
    path = shared / "facade.sock"
    uids = frozenset({os.geteuid(), NOBODY} if listed else {os.geteuid()})
    # 0660 with nobody's group: the file lets nobody connect, so the peer
    # check alone decides.
    adapter = A2AAdapter(
        A2AOptions(facade_socket=path, facade_uids=uids, facade_gid=NOBODY, data_dir=tmp_path)
    )
    await adapter.start()
    try:
        out = await asyncio.to_thread(
            subprocess.run,
            [OTHER_PYTHON, "-I", "-c", CLIENT, str(path)],
            user=NOBODY,
            group=NOBODY,
            extra_groups=[],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    finally:
        await adapter.aclose()
    shown = str(out.stdout).strip()
    assert shown.startswith(answer), shown
