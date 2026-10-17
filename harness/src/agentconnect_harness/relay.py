"""The real relay binary, run on a random loopback port with a temp database.

The binary is built once per session (``cargo build -p agentconnect-relay``;
a no-op when it is up to date). ``AC_RELAY_BIN`` points at a prebuilt one.
The relay uses the system clock: the harness controls daemon time only, so
relay TTL behaviour stays covered by the relay's own Rust tests.
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
READY_LINE = "relay listening"


def _newest(paths: list[Path]) -> float:
    return max((p.stat().st_mtime for d in paths for p in d.rglob("*.rs")), default=0.0)


def relay_binary() -> Path:
    """The relay binary, building it if missing or older than its sources."""
    override = os.environ.get("AC_RELAY_BIN", "")
    if override:
        return Path(override)
    target = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    binary = target / "debug" / "agentconnect-relay"
    sources = [REPO / "relay" / "src", REPO / "core" / "src"]
    if not binary.exists() or binary.stat().st_mtime < _newest(sources):
        subprocess.run(
            ["cargo", "build", "--quiet", "--locked", "-p", "agentconnect-relay"],  # noqa: S607
            cwd=REPO,
            check=True,
        )
    return binary


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class RelayProcess:
    port: int
    proc: subprocess.Popen[str]

    @property
    def host(self) -> str:
        """The host string clients sign (``AC_RELAY_HOST``)."""
        return f"127.0.0.1:{self.port}"

    @property
    def ws_url(self) -> str:
        return f"ws://{self.host}"

    @property
    def http_url(self) -> str:
        return f"http://{self.host}"


@contextmanager
def run_relay(tmp: Path) -> Generator[RelayProcess]:
    """Start the relay and wait for its "listening" log line (no polling)."""
    binary = relay_binary()
    for _ in range(5):
        port = free_port()
        env = {
            **os.environ,
            "AC_RELAY_ADDR": f"127.0.0.1:{port}",
            "AC_RELAY_HOST": f"127.0.0.1:{port}",
            "AC_RELAY_DB": str(tmp / f"relay-{port}.db"),
            "RUST_LOG": "info",
            "NO_COLOR": "1",
        }
        proc = subprocess.Popen(  # noqa: S603
            [str(binary)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if proc.stdout is None:
            msg = "no relay output pipe"
            raise RuntimeError(msg)
        ready = False
        for line in proc.stdout:
            if READY_LINE in line:
                ready = True
                break
        if ready:
            # Keep draining output so the relay never blocks on a full pipe.
            threading.Thread(target=proc.stdout.read, daemon=True).start()
            try:
                yield RelayProcess(port, proc)
            finally:
                proc.terminate()
                proc.wait(timeout=10)
            return
        proc.wait(timeout=10)  # port taken between probe and bind: retry
    msg = "relay did not start"
    raise RuntimeError(msg)
