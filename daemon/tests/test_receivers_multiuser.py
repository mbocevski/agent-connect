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
OTHER_PYTHON = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable
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
