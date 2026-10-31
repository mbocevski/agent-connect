"""Deliveries reach a real agent user's receiver, and never another user's
socket at the same path (SR-10).

Integration tier: needs root, to run the receivers as other users, and
``AC_RUN_MULTIUSER=1``::

    sudo AC_RUN_MULTIUSER=1 uv run --all-packages pytest -m multiuser

On Linux a user namespace stands in for root::

    AC_RUN_MULTIUSER=1 unshare --map-auto --map-root-user .venv/bin/python -m pytest \\
        -m multiuser daemon/tests/test_receivers_multiuser.py

The fast tier skips it; ``test_receivers.py`` covers the same checks with
injected credentials.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentconnect.adapter import Delivery, DeliveryResult, GroupView, Sender
from agentconnect.clock import FakeClock
from agentconnect.sockets import receiver_async_transport
from agentconnect.webhook import SOCKET_URL, WebhookAdapter

AGENT_USER = 65534  # nobody, standing in for an isolation.agent_users entry
OTHER_USER = 1234
OTHER_PYTHON = os.environ.get("AC_MULTIUSER_PYTHON") or (
    "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable
)
GROUP = GroupView("g1", "Ops", "Deploys", 3, "free")
SENDER = Sender("ac:v0:peer", "i1", "peer-bot", False)
TEXT = "for the agent's receiver only"

pytestmark = [
    pytest.mark.multiuser,
    pytest.mark.skipif(
        os.environ.get("AC_RUN_MULTIUSER") != "1" or os.geteuid() != 0,
        reason="needs root and AC_RUN_MULTIUSER=1",
    ),
]

# Accepts one connection, reads the request (headers and body), answers
# 204 if anything arrived, then prints how many bytes it got.
RECEIVER = r"""
import os, socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o666)
s.listen(1)
print("ready", flush=True)
c, _ = s.accept()
data = b""
while b"\r\n\r\n" not in data and (chunk := c.recv(65536)):
    data += chunk
head, _, rest = data.partition(b"\r\n\r\n")
length = 0
for line in head.split(b"\r\n"):
    if line.lower().startswith(b"content-length:"):
        length = int(line.split(b":", 1)[1])
while len(rest) < length and (chunk := c.recv(65536)):
    rest += chunk
if data:
    c.sendall(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
c.close()
print(len(head) + len(rest), flush=True)
"""


def delivery() -> Delivery:
    body = {"text": TEXT}
    return Delivery(
        "g1",
        "m1",
        "a2a.message",
        body,
        SENDER,
        ["*"],
        True,
        "Deploys",
        {"self": "unverified", "verified_members": 0, "members": 2},
        "agent",
        1,
        {"kind": "a2a.message", "body": body},
    )


@pytest.fixture
def shared() -> Iterator[Path]:
    """A directory any user may bind a socket in."""
    d = Path(tempfile.mkdtemp(prefix="ac-mu-"))
    d.chmod(0o1777)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def serve_as(uid: int, path: Path) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        [OTHER_PYTHON, "-I", "-c", RECEIVER, str(path)], user=uid, stdout=subprocess.PIPE, text=True
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == "ready"
    return proc


@pytest.mark.parametrize(("served_by", "accepted"), [(AGENT_USER, True), (OTHER_USER, False)])
async def test_only_the_agent_users_receiver_gets_the_delivery(
    shared: Path, served_by: int, accepted: bool
) -> None:
    path = shared / "hook.sock"
    receiver = serve_as(served_by, path)
    transport = receiver_async_transport(path, {AGENT_USER})
    adapter = WebhookAdapter(SOCKET_URL, "s" * 32, FakeClock(), transport=transport, timeout=5)
    result = await adapter.deliver(GROUP, SENDER, ["*"], delivery())
    await adapter.close()
    out, _ = receiver.communicate(timeout=5)
    received = int(out.strip())
    if accepted:
        assert (result, received > 0) == (DeliveryResult.ACK, True)
    else:
        assert (result, received) == (DeliveryResult.RETRY, 0)


# -- the receiver directory's group (docs/isolation.md) ------------------------

DAEMON_USER = 2345  # the daemon's user
SHARED_GID = 4567  # agentconnect: the daemon's user and every agent user
RECV_GID = 5678  # agentconnect-recv: the daemon's user alone

# Listens as the agent's SDK receiver does in the separate-OS-user mode:
# 0660, its group from the setgid directory.
LISTENER = r"""
import os, socket, sys
os.umask(0o007)
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o660)
s.listen(8)
print("ready", flush=True)
sys.stdin.read()
"""

CONNECT = r"""
import socket, sys
c = socket.socket(socket.AF_UNIX)
try:
    c.connect(sys.argv[1])
except OSError as e:
    print(type(e).__name__)
else:
    print("connected")
"""


def connect_as(uid: int, groups: list[int], path: Path) -> str:
    out = subprocess.run(
        [OTHER_PYTHON, "-I", "-c", CONNECT, str(path)],
        user=uid,
        group=groups[0],
        extra_groups=groups,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return out.stdout.strip()


@pytest.mark.parametrize(
    ("dir_gid", "other_agent"),
    [(RECV_GID, "PermissionError"), (SHARED_GID, "connected")],
    ids=["own-group", "shared-group"],
)
def test_only_the_daemons_user_reaches_an_agents_receiver(dir_gid: int, other_agent: str) -> None:
    base = Path(tempfile.mkdtemp(prefix="ac-mu-"))
    try:
        base.chmod(0o755)
        recv = base / "agent"
        recv.mkdir()
        os.chown(recv, AGENT_USER, dir_gid)
        recv.chmod(0o2750)
        path = recv / "hook.sock"
        listener = subprocess.Popen(
            [OTHER_PYTHON, "-I", "-c", LISTENER, str(path)],
            user=AGENT_USER,
            group=AGENT_USER,
            extra_groups=[SHARED_GID],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert listener.stdout is not None
            assert listener.stdout.readline().strip() == "ready"
            assert path.stat().st_gid == dir_gid  # from the setgid directory
            assert connect_as(DAEMON_USER, [SHARED_GID, RECV_GID], path) == "connected"
            # Another agent user of the same daemon: in agentconnect, not in
            # agentconnect-recv.
            assert connect_as(OTHER_USER, [SHARED_GID], path) == other_agent
        finally:
            listener.communicate("", timeout=5)
    finally:
        shutil.rmtree(base, ignore_errors=True)
