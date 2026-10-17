"""N in-process daemons against one real relay, each behind its own proxy.

All daemons share one :class:`FakeClock` (starting at the real current time,
so signed REST timestamps and invite expiries agree with the relay's system
clock). ``advance`` is the only way daemon time moves.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentconnect.adapter import RecordingAdapter
from agentconnect.clock import FakeClock
from agentconnect.config import Config
from agentconnect.daemon import Daemon, Options
from agentconnect.identity import Seeded
from agentconnect.keystore import FileKeystore
from agentconnect_harness.proxy import RelayProxy
from agentconnect_harness.relay import RelayProcess

WAIT = 8.0  # real-time guard for every wait; nothing sleeps


@dataclass
class Node:
    name: str
    config: Config
    proxy: RelayProxy
    adapter: RecordingAdapter
    clock: FakeClock
    seed: int
    starts: int = 0
    daemon: Daemon = field(init=False)

    def _make(self) -> Daemon:
        # A fresh seed per start: a restarted daemon must not replay the
        # randomness (keys, msg_ids) of its previous run.
        self.starts += 1
        seed = self.seed + self.starts
        return Daemon(
            self.config,
            [self.adapter],
            clock=self.clock,
            keystore=FileKeystore(self.config.data_dir / "keys"),
            options=Options(testing=Seeded(seed), backoff_rng=random.Random(seed)),  # noqa: S311
        )

    async def start(self) -> None:
        self.daemon = self._make()
        await self.daemon.start()
        await self.connected()

    async def connected(self) -> None:
        await asyncio.wait_for(self.daemon.link.wait_connected(), WAIT)

    async def restart(self) -> None:
        """Kill (stop without any flush) and start again on the same state."""
        await self.daemon.stop()
        await self.start()

    async def wait(self, predicate: Any, within: float = WAIT) -> None:
        await self.daemon.wait_until(predicate, within)

    async def wait_texts(self, group_id: str, n: int) -> list[str]:
        await self.adapter.wait_for(lambda: len(self.adapter.texts(group_id)) >= n, WAIT)
        return self.adapter.texts(group_id)

    async def idle(self) -> None:
        """Wait until the outbox has nothing queued."""
        await self.wait(lambda: not self.daemon.store.outbox())

    @property
    def me(self) -> str:
        return self.daemon.me

    def sas(self, group_id: str) -> str:
        return str(self.daemon.group_info(group_id)["sas"]["decimal"])

    def epoch(self, group_id: str) -> int:
        return int(self.daemon.group_info(group_id)["epoch"])


def status(node: Node, group_id: str) -> str | None:
    """The group's local status on ``node`` (``None`` if unknown)."""
    g = node.daemon.store.group(group_id)
    return None if g is None else g.status


class Cluster:
    def __init__(self, relay: RelayProcess, tmp: Path, rng: random.Random) -> None:
        self.relay = relay
        self.tmp = tmp
        self.rng = rng
        now = datetime.now(UTC).replace(microsecond=0)
        self.clock = FakeClock(now)
        self.nodes: list[Node] = []

    async def node(
        self, name: str | None = None, auto_approve: bool = True, identity_of: Node | None = None
    ) -> Node:
        """A started daemon. ``identity_of`` makes it a replica (another
        instance of that node's identity)."""
        name = name or f"n{len(self.nodes)}"
        proxy = RelayProxy(self.relay.ws_url)
        await proxy.start()
        data_dir = self.tmp / name
        if identity_of is not None:
            secret = identity_of.daemon.keystore.get("identity")
            if secret is None:
                msg = "the original node has no identity"
                raise RuntimeError(msg)
            FileKeystore(data_dir / "keys").put("identity", secret)
        config = Config(
            relay_url=proxy.url,
            relay_host=self.relay.host,
            relay_rest_url=self.relay.http_url,
            data_dir=data_dir,
            display_name=name,
            default_adapter="recording",
            keystore="file",
            auto_approve=auto_approve,
        )
        node = Node(name, config, proxy, RecordingAdapter(), self.clock, self.rng.getrandbits(63))
        await node.start()
        self.nodes.append(node)
        return node

    async def invite(
        self, inviter: Node, joiner: Node, group_id: str, approve: bool = True
    ) -> None:
        """Create an invite, redeem it, and (with auto-approve) wait until the
        joiner and every existing member have settled on the new epoch."""
        before = inviter.epoch(group_id)
        invite = await inviter.daemon.create_invite(group_id)
        await joiner.daemon.accept_invite(invite["url"])
        if not approve:
            return
        await joiner.wait(lambda: joiner.daemon.store.group(group_id) is not None)
        await self.settle(group_id, before + 1)

    async def settle(self, group_id: str, epoch: int) -> None:
        """Wait until every member node is at ``epoch`` with an idle outbox."""
        members = [n for n in self.nodes if n.daemon.store.group(group_id) is not None]
        for n in members:
            await n.wait(
                lambda n=n: (
                    (g := n.daemon.store.group(group_id)) is not None
                    and (g.epoch >= epoch or g.status != "active")
                )
            )
            await n.idle()

    async def group(self, n: int, mode: str = "distinct") -> tuple[list[Node], str]:
        """``n`` members, fully joined. ``mode="replicas"``: every member is an
        instance of one identity."""
        if mode not in ("distinct", "replicas"):
            msg = f"unknown mode {mode}"
            raise ValueError(msg)
        first = await self.node()
        gid = first.daemon.create_group("Harness", "Exercise the daemon")
        await first.idle()
        nodes = [first]
        for _ in range(n - 1):
            joiner = await self.node(identity_of=first if mode == "replicas" else None)
            await self.invite(first, joiner, gid)
            nodes.append(joiner)
        return nodes, gid

    async def advance(self, seconds: float) -> None:
        """Advance the shared clock and let woken timers run."""
        self.clock.advance(seconds)
        for _ in range(5):
            await asyncio.sleep(0)

    async def close(self) -> None:
        for n in self.nodes:
            if n.daemon.running:
                await n.daemon.stop()
            await n.proxy.stop()
