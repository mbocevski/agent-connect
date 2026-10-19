"""The real directory binary on the in-memory store, for publish and
withdraw scenarios (docs/discovery.md).

Built like the relay (``cargo build -p agentconnect-directory``, a no-op
when up to date; ``AC_DIRECTORY_BIN`` points at a prebuilt one). It runs on
a random loopback port with ``AC_DIRECTORY_DB=memory:``, lists the harness
relay, and pins one operator key derived from the run's seed. Listings in
the harness claim no owner domain, so the directory's owner fetcher stays
idle. Like the relay, it uses the system clock.
"""

from __future__ import annotations

import base64
import os
import subprocess
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import agentconnect_core as ac
from agentconnect.config import DirectoryConfig
from agentconnect_harness.relay import REPO, _newest, reserved_port

READY_LINE = "directory listening"


def directory_binary() -> Path:
    """The directory binary, building it if missing or older than its sources."""
    override = os.environ.get("AC_DIRECTORY_BIN", "")
    if override:
        return Path(override)
    target = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    binary = target / "debug" / "agentconnect-directory"
    sources = [REPO / "directory" / "src", REPO / "core" / "src"]
    if not binary.exists() or binary.stat().st_mtime < _newest(sources):
        subprocess.run(
            ["cargo", "build", "--quiet", "--locked", "-p", "agentconnect-directory"],  # noqa: S607
            cwd=REPO,
            check=True,
        )
    return binary


@dataclass
class DirectoryProcess:
    port: int
    key: ac.DirectoryKey
    proc: subprocess.Popen[str]

    @property
    def host(self) -> str:
        """``AC_DIRECTORY_HOST``: what listings and tokens name."""
        return f"127.0.0.1:{self.port}"

    @property
    def url(self) -> str:
        return f"http://{self.host}"

    @property
    def config(self) -> DirectoryConfig:
        """The ``[[directory]]`` a daemon pins for it."""
        return DirectoryConfig(self.host, (self.key.public_key,), self.url)

    def token(self, name: str, identity: str, now: int, lifetime: int = 30 * 86_400) -> bytes:
        return self.key.issue_token(self.host, name, identity, now, now + lifetime)


@contextmanager
def run_directory(relay_host: str, seed: int) -> Generator[DirectoryProcess]:
    """Start the directory and wait for its "listening" log line."""
    binary = directory_binary()
    key = ac.DirectoryKey._generate_for_testing(seed)
    public = base64.urlsafe_b64encode(key.public_key).rstrip(b"=").decode()
    for _ in range(5):
        with reserved_port() as port:
            env = {
                **os.environ,
                "AC_DIRECTORY_ADDR": f"127.0.0.1:{port}",
                "AC_DIRECTORY_HOST": f"127.0.0.1:{port}",
                "AC_DIRECTORY_DB": "memory:",
                "AC_DIRECTORY_RELAYS": relay_host,
                "AC_DIRECTORY_TOKEN_KEYS": public,
                "RUST_LOG": "info",
                "NO_COLOR": "1",
            }
            proc = subprocess.Popen(  # noqa: S603
                [str(binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            if proc.stdout is None:
                msg = "no directory output pipe"
                raise RuntimeError(msg)
            ready = any(READY_LINE in line for line in proc.stdout)
        if ready:
            threading.Thread(target=proc.stdout.read, daemon=True).start()
            try:
                yield DirectoryProcess(port, key, proc)
            finally:
                proc.terminate()
                proc.wait(timeout=10)
            return
        proc.wait(timeout=10)  # the directory failed to start: retry
    msg = "directory did not start"
    raise RuntimeError(msg)
