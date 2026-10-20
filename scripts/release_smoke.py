#!/usr/bin/env python3
"""Smoke-test an installed `agentconnect` CLI (the release verification jobs).

usage: release_smoke.py <version> <relay-url>

Checks that `agentconnect --version` and `agentconnect version --json` report
<version>, then starts `agentconnect mcp --agent t --relay <relay-url>` and
talks MCP to it over stdio: `initialize` must name the server and the version, and `tools/list`
must list the agent tools and none of the human-only operations. Closing
stdin must stop the server with exit code 0.

Standard library only: it runs in a bare `python:3.12-slim` container next
to the installed CLI, not in the development environment.
"""

from __future__ import annotations

import json
import os
import selectors
import shutil
import subprocess
import sys
import time
from typing import Any

PROTOCOL = "2025-11-25"
STARTUP_SECS = 120.0
REPLY_SECS = 30.0
EXIT_SECS = 30.0
# A few tools every release has; the harness checks the full list.
REQUIRED_TOOLS = {"agentconnect_create_group", "agentconnect_send", "agentconnect_wait"}
# Human-only operations: no tool may name one (docs/adapters/mcp.md).
HUMAN_WORDS = ("approve", "reject", "verify", "safety")


class SmokeError(Exception):
    pass


def check_version(cli: str, version: str) -> None:
    """`agentconnect --version` (`agentconnect <version> (protocol vN)`) and
    `agentconnect version --json` both report <version>."""
    line = subprocess.run(  # noqa: S603 - the installed CLI, fixed arguments
        [cli, "--version"], capture_output=True, text=True, check=True, timeout=60
    ).stdout.strip()
    words = line.split()
    if len(words) < 2 or words[:2] != ["agentconnect", version]:  # noqa: PLR2004
        msg = f"agentconnect --version printed {line!r}, expected 'agentconnect {version} ...'"
        raise SmokeError(msg)
    print(f"ok: agentconnect --version: {line}")
    out = subprocess.run(  # noqa: S603 - the installed CLI, fixed arguments
        [cli, "version", "--json"], capture_output=True, text=True, check=True, timeout=60
    ).stdout
    got = json.loads(out)["version"]
    if got != version:
        msg = f"agentconnect version --json reports {got!r}, expected {version!r}"
        raise SmokeError(msg)
    print(f"ok: agentconnect version --json: {got}")


class Server:
    """An `agentconnect mcp` process and newline-delimited JSON-RPC on its stdio."""

    def __init__(self, argv: list[str]) -> None:
        self.proc = subprocess.Popen(  # noqa: S603 - the installed CLI, fixed arguments
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        assert self.proc.stdout is not None  # noqa: S101 - set by Popen
        assert self.proc.stdin is not None  # noqa: S101 - set by Popen
        self._out = self.proc.stdout
        self._in = self.proc.stdin
        self._sel = selectors.DefaultSelector()
        self._sel.register(self._out, selectors.EVENT_READ)
        self._buf = b""

    def send(self, msg: dict[str, Any]) -> None:
        self._in.write(json.dumps({"jsonrpc": "2.0", **msg}).encode() + b"\n")
        self._in.flush()

    def _line(self, deadline: float) -> bytes:
        while b"\n" not in self._buf:
            left = deadline - time.monotonic()
            if left <= 0 or not self._sel.select(left):
                msg = "timed out waiting for the server"
                raise SmokeError(msg)
            chunk = os.read(self._out.fileno(), 65536)
            if not chunk:
                msg = "the server closed its output"
                raise SmokeError(msg)
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line

    def request(self, rid: int, method: str, params: dict[str, Any], secs: float) -> Any:
        self.send({"id": rid, "method": method, "params": params})
        deadline = time.monotonic() + secs
        while True:
            reply = json.loads(self._line(deadline))
            if reply.get("id") != rid:
                continue  # a notification or log message
            if "error" in reply:
                msg = f"{method}: {reply['error']}"
                raise SmokeError(msg)
            return reply["result"]

    def stop(self) -> int:
        self._in.close()
        try:
            return self.proc.wait(timeout=EXIT_SECS)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            msg = "the server did not stop on stdin EOF"
            raise SmokeError(msg) from None

    def stderr(self) -> str:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        assert self.proc.stderr is not None  # noqa: S101 - set by Popen
        return self.proc.stderr.read().decode(errors="replace")


def check_mcp(cli: str, version: str, relay: str) -> None:
    server = Server([cli, "mcp", "--agent", "t", "--relay", relay])
    try:
        info = server.request(
            1,
            "initialize",
            {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "release-smoke", "version": version},
            },
            STARTUP_SECS,
        )
        name, got = info["serverInfo"]["name"], info["serverInfo"].get("version")
        if name != "agentconnect" or got != version:
            msg = f"initialize: serverInfo {info['serverInfo']}, expected agentconnect {version}"
            raise SmokeError(msg)
        if "tools" not in info.get("capabilities", {}):
            msg = f"initialize: no tools capability in {info.get('capabilities')}"
            raise SmokeError(msg)
        print(f"ok: initialize ({info['protocolVersion']}, {name} {got})")
        server.send({"method": "notifications/initialized"})
        tools = {t["name"] for t in server.request(2, "tools/list", {}, REPLY_SECS)["tools"]}
        if missing := REQUIRED_TOOLS - tools:
            msg = f"tools/list: missing {sorted(missing)} in {sorted(tools)}"
            raise SmokeError(msg)
        if human := sorted(t for t in tools if any(w in t for w in HUMAN_WORDS)):
            msg = f"tools/list: human-only operations exposed: {human}"
            raise SmokeError(msg)
        print(f"ok: tools/list ({len(tools)} tools)")
        code = server.stop()
        if code != 0:
            msg = f"the server exited with {code} on stdin EOF"
            raise SmokeError(msg)
        print("ok: stopped on stdin EOF")
    except Exception:
        sys.stderr.write(server.stderr()[-4000:])
        raise


def main(argv: list[str]) -> int:
    if len(argv) != 3:  # noqa: PLR2004 - two arguments
        print(__doc__, file=sys.stderr)
        return 2
    version, relay = argv[1], argv[2]
    cli = shutil.which("agentconnect")
    if cli is None:
        print("error: agentconnect is not on PATH", file=sys.stderr)
        return 1
    try:
        check_version(cli, version)
        check_mcp(cli, version, relay)
    except (SmokeError, subprocess.CalledProcessError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
