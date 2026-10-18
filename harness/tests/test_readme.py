"""The README quickstart, run as written against a local relay and daemons.

A shell block in README.md is runnable when the line before its fence is
``<!-- runnable: <actor> -->``. The blocks run in order. For each actor the
test owns the environment, so a few lines are interpreted, not executed:

* ``source .venv/bin/activate`` and ``export AC_*=...``: the test puts the
  workspace's ``agentconnect`` on PATH and sets the same variables to its own
  values (the variables the README exports must be the ones it sets);
* ``agentconnect daemon run ...``: starts that actor's daemon in-process, on
  the harness relay, with the local API on its Unix socket.

Every other line runs in bash as the actor, with ``<url>`` replaced by the
last invite URL printed, ``<request_id>`` by the actor's pending approval
and ``<group>`` by the actor's group. Every command must exit 0. Commands
that wait for another actor (``accept`` waits for the approval) run in the
background, as in a separate terminal; the actor's next step waits for them.
"""

from __future__ import annotations

import asyncio
import os
import random
import re
import shutil
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import pytest_asyncio
import typer.main

from agentconnect.cli import app
from agentconnect.runtime.api import ApiServer
from agentconnect_harness.cluster import WAIT, Cluster, Node
from agentconnect_harness.relay import REPO, RelayProcess

README = REPO / "README.md"
MARKER = re.compile(r"^<!-- runnable: ([a-z]+) -->$")
FENCE = re.compile(r"^```(sh|bash)$")
EXPORT = re.compile(r"^export (AC_[A-Z_]+)=")
PLACEHOLDER = re.compile(r"<(url|request_id|group)>")
INVITE_URL = re.compile(r"https?://\S+/i/[A-Za-z0-9_-]+#\S+")
ACTIVATE = "source .venv/bin/activate"
DAEMON = "agentconnect daemon run"
README_ENV = {"AC_RELAY_URL", "AC_DATA_DIR"}
# CLI commands the quickstart may use (docs/cli.md).
KNOWN = {"daemon", "invite", "accept", "approvals", "groups", "verify", "send", "status"}
# Commands that block until another actor acts.
BACKGROUND = {"accept"}
# Answers for any confirmation prompt (accept, approve, verify).
YES = b"y\n" * 8
# The whole quickstart spawns about ten CLI processes.
QUICKSTART_TIMEOUT = 30


@dataclass(frozen=True)
class Step:
    actor: str
    line: str


def runnable_steps(text: str) -> list[Step]:
    """The commands of every runnable block, in order (continuations joined,
    blank and comment lines dropped)."""
    steps: list[Step] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = MARKER.match(lines[i].strip())
        i += 1
        if m is None:
            continue
        if i >= len(lines) or FENCE.match(lines[i].strip()) is None:
            msg = f"README line {i}: a runnable marker must be followed by a sh block"
            raise ValueError(msg)
        i += 1
        pending = ""
        while i < len(lines) and lines[i].strip() != "```":
            line = pending + lines[i].strip()
            i += 1
            if line.endswith("\\"):
                pending = line[:-1].rstrip() + " "
                continue
            pending = ""
            if line and not line.startswith("#"):
                steps.append(Step(m.group(1), line))
        if i >= len(lines):
            msg = "README: unterminated runnable block"
            raise ValueError(msg)
    return steps


def cli_commands() -> set[str]:
    group = typer.main.get_command(app)
    return set(getattr(group, "commands", {}))


def test_parser_reads_markers_continuations_and_comments() -> None:
    text = "\n".join(
        [
            "intro",
            "```sh",
            "not runnable",
            "```",
            "<!-- runnable: alice -->",
            "```sh",
            "# a comment",
            "",
            "agentconnect send x \\",
            '  "hi"',
            "```",
            "<!-- runnable: bob -->",
            "```bash",
            "agentconnect status",
            "```",
        ]
    )
    assert runnable_steps(text) == [
        Step("alice", 'agentconnect send x "hi"'),
        Step("bob", "agentconnect status"),
    ]


@pytest.mark.parametrize(
    "text",
    ["<!-- runnable: a -->\ntext\n", "<!-- runnable: a -->\n```sh\nls\n", "<!-- runnable: a -->"],
)
def test_parser_rejects_malformed_blocks(text: str) -> None:
    with pytest.raises(ValueError, match="runnable"):
        runnable_steps(text)


def test_readme_quickstart_is_well_formed() -> None:
    """Holds today, before the CLI lands: every actor activates the venv,
    exports exactly the variables the test provides, starts a daemon before
    using it, and uses only known commands and placeholders."""
    steps = runnable_steps(README.read_text(encoding="utf-8"))
    actors = {s.actor for s in steps}
    assert actors == {"alice", "bob"}
    assert cli_commands() >= KNOWN
    known = KNOWN
    for actor in actors:
        mine = [s.line for s in steps if s.actor == actor]
        assert mine[0] == ACTIVATE
        assert {m.group(1) for line in mine if (m := EXPORT.match(line))} == README_ENV
        started = next(i for i, line in enumerate(mine) if line.startswith(DAEMON))
        for i, line in enumerate(mine):
            if line == ACTIVATE or EXPORT.match(line):
                continue
            assert line.startswith("agentconnect "), line
            assert line.split()[1] in known, line
            assert i >= started, f"{actor} runs {line!r} before starting a daemon"


@pytest.fixture
def shortdir() -> Iterator[Path]:
    # Unix socket paths are limited to ~100 bytes; pytest's tmp paths can be longer.
    d = Path(tempfile.mkdtemp(prefix="ac-readme-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest_asyncio.fixture
async def readme_cluster(
    relay: RelayProcess, shortdir: Path, rng: random.Random
) -> AsyncIterator[Cluster]:
    c = Cluster(relay, shortdir, rng)
    try:
        yield c
    finally:
        await c.close()


class Quickstart:
    def __init__(self, cluster: Cluster, home: Path) -> None:
        self.cluster = cluster
        self.home = home
        self.nodes: dict[str, Node] = {}
        self.servers: list[ApiServer] = []
        self.url: str | None = None
        self.sent: list[str] = []
        self.pending: dict[str, asyncio.Task[None]] = {}

    async def start(self, actor: str) -> None:
        node = await self.cluster.node(actor, auto_approve=False)
        server = ApiServer(node.daemon)
        await server.start()
        self.nodes[actor] = node
        self.servers.append(server)

    def env(self, node: Node) -> dict[str, str]:
        bin_dir = str(Path(sys.executable).parent)
        return {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(self.home),
            "AC_CONFIG": str(self.home / "absent.toml"),
            "AC_DATA_DIR": str(node.config.data_dir),
            "AC_RELAY_URL": node.config.relay_url,
            "AC_RELAY_HOST": node.config.relay_host,
            "NO_COLOR": "1",
        }

    def group_of(self, node: Node) -> str:
        groups = node.daemon.list_groups()
        assert len(groups) == 1, groups
        return str(groups[0]["group_id"])

    async def settle(self) -> None:
        """Every daemon idle, and every member on the same epoch."""
        for node in self.nodes.values():
            await node.idle()
        gids = {self.group_of(n) for n in self.nodes.values() if n.daemon.list_groups()}
        for gid in gids:
            members = [n for n in self.nodes.values() if n.daemon.store.group(gid)]
            await self.cluster.settle(gid, max(n.epoch(gid) for n in members))

    async def fill(self, node: Node, line: str) -> str:
        async def value(name: str) -> str:
            if name == "url":
                assert self.url is not None, "no invite URL printed before <url>"
                return self.url
            if name == "request_id":
                await node.wait(lambda: bool(node.daemon.approvals()))
                return str(node.daemon.approvals()[0]["request_id"])
            # Every started daemon has joined before the group is used.
            for n in self.nodes.values():
                await n.wait(lambda n=n: bool(n.daemon.list_groups()))
            await self.settle()
            return self.group_of(node)

        for name in sorted(set(PLACEHOLDER.findall(line))):
            line = line.replace(f"<{name}>", await value(name))
        return line

    async def run(self, step: Step) -> None:
        if step.line == ACTIVATE or EXPORT.match(step.line):
            return
        await self.wait_for(step.actor)
        if step.line.startswith(DAEMON):
            await self.start(step.actor)
            return
        node = self.nodes[step.actor]
        line = await self.fill(node, step.line)
        if line.split()[0] == "agentconnect" and line.split()[1] in BACKGROUND:
            self.pending[step.actor] = asyncio.create_task(self.execute(step, node, line))
            return
        await self.execute(step, node, line)

    async def wait_for(self, actor: str) -> None:
        """Wait for the actor's background command, as a human would before
        typing the next one in that terminal."""
        task = self.pending.pop(actor, None)
        if task is not None:
            await task

    async def execute(self, step: Step, node: Node, line: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "bash",
            "-euo",
            "pipefail",
            "-c",
            line,
            cwd=self.home,
            env=self.env(node),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(YES), WAIT)
        text = out.decode()
        assert proc.returncode == 0, f"{step.actor}: {step.line}\n{text}\n{err.decode()}"
        if (m := INVITE_URL.search(text)) is not None:
            self.url = m.group(0)
        if line.split()[:2] == ["agentconnect", "send"]:
            self.sent.append(line)
            await self.settle()

    async def finish(self) -> None:
        for actor in list(self.pending):
            await self.wait_for(actor)

    async def close(self) -> None:
        for task in self.pending.values():
            task.cancel()
        for server in self.servers:
            await server.stop()


async def test_runner_drives_the_cli_against_harness_daemons(
    readme_cluster: Cluster, shortdir: Path
) -> None:
    """The runner itself, with commands that exist today, so it stays
    working while the quickstart test waits for the CLI."""
    home = shortdir / "home"
    home.mkdir()
    qs = Quickstart(readme_cluster, home)
    try:
        for line in (ACTIVATE, "export AC_DATA_DIR=x", f"{DAEMON} 2>> a.log &"):
            await qs.run(Step("alice", line))
        await qs.run(Step("alice", "agentconnect status --json | grep -q '\"connected\": true'"))
        alice = qs.nodes["alice"]
        gid = alice.daemon.create_group("Readme", "Runner test")
        await qs.run(Step("alice", f"test '<group>' = '{gid}'"))
        await qs.run(Step("alice", "echo 'http://127.0.0.1:1/i/abc#v=0&s=x'"))
        assert qs.url == "http://127.0.0.1:1/i/abc#v=0&s=x"
        with pytest.raises(AssertionError, match="exit"):
            await qs.run(Step("alice", "echo exit; false"))
    finally:
        await qs.close()


@pytest.mark.timeout(QUICKSTART_TIMEOUT)
async def test_readme_quickstart_runs(readme_cluster: Cluster, shortdir: Path) -> None:
    home = shortdir / "home"
    home.mkdir()
    qs = Quickstart(readme_cluster, home)
    try:
        for step in runnable_steps(README.read_text(encoding="utf-8")):
            await qs.run(step)
        await qs.finish()
        assert qs.url is not None, "the quickstart never printed an invite URL"
        assert qs.sent, "the quickstart never sent a message"
        alice, bob = qs.nodes["alice"], qs.nodes["bob"]
        gid = qs.group_of(alice)
        assert qs.group_of(bob) == gid
        texts = await bob.wait_texts(gid, 1)
        assert "Hello from Alice" in texts
        for node in (alice, bob):
            members = node.daemon.group_info(gid)["members"]
            assert all(m["verified"] for m in members if not m["self"]), members
    finally:
        await qs.close()
