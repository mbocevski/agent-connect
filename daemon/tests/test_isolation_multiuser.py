"""Separate-OS-user mode with a real second OS user (integration tier).

Needs root, to start a client as another user, and ``AC_RUN_MULTIUSER=1``::

    sudo AC_RUN_MULTIUSER=1 uv run --all-packages pytest -m multiuser

The fast tier skips it; ``test_isolation.py`` covers the same checks with an
injected credential provider.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from agentconnect.isolation import PeerGate, peer_credentials

NOBODY = 65534
# The test's own interpreter may be under a home that this user can't enter.
OTHER_PYTHON = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable

pytestmark = [
    pytest.mark.multiuser,
    pytest.mark.skipif(
        os.environ.get("AC_RUN_MULTIUSER") != "1" or os.geteuid() != 0,
        reason="needs root and AC_RUN_MULTIUSER=1",
    ),
]

CLIENT = "import socket, sys; s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.recv(1)"


def test_kernel_reports_the_other_users_uid() -> None:
    d = Path(tempfile.mkdtemp(prefix="ac-mu-"))
    try:
        d.chmod(0o711)
        path = d / "s.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
            srv.bind(str(path))
            path.chmod(0o666)
            srv.listen(1)
            child = subprocess.Popen([OTHER_PYTHON, "-I", "-c", CLIENT, str(path)], user=NOBODY)
            try:
                conn, _ = srv.accept()
                with conn:
                    cred = peer_credentials(conn)
                    assert cred.uid == NOBODY
                    assert cred.pid == child.pid or cred.pid is None
                    # A gate that doesn't list the user refuses it.
                    gate = PeerGate(enabled=True, runtime_uid=1)

                    class Transport:
                        def get_extra_info(self, name: str, default: object = None) -> object:
                            return conn if name == "socket" else default

                    assert gate.admit(Transport()) is False
                    allowed = PeerGate(enabled=True, runtime_uid=1, agent_uids=[NOBODY])
                    assert allowed.admit(Transport()) is True
                    assert allowed.human_allowed() is False
                    conn.sendall(b"x")
            finally:
                child.wait(timeout=5)
    finally:
        shutil.rmtree(d, ignore_errors=True)
