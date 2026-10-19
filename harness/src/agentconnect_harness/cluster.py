"""N in-process runtimes against one real relay, each behind its own proxy.

Every node is a :class:`~agentconnect.runtime.Runtime`, hosted the way one
of the two hosts hosts it (ADR-005):

* ``daemon``: what ``agentconnectd`` runs, the runtime with the node's
  adapters;
* ``embedded``: what ``AgentConnect.embedded`` runs, the SDK's
  :class:`~agentconnect_sdk.embedded.EmbeddedHost` with its in-process
  callback adapter, its stored deduplication and the SDK's dispatch to user
  handlers. The node's recording adapter sits in front of the callback
  adapter (:class:`EmbeddedTap`), so a scenario sees the same recording in
  both hosts, and :attr:`Node.handled` records what reached user code.

The ``cluster`` fixture runs every scenario once per host.

All nodes share one :class:`FakeClock` (starting at the real current time,
so signed REST timestamps and invite expiries agree with the relay's system
clock). ``advance`` is the only way runtime time moves.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, override

from agentconnect.adapter import (
    Adapter,
    Delivery,
    DeliveryResult,
    Event,
    GroupView,
    OutboundSend,
    RecordingAdapter,
    Sender,
)
from agentconnect.callback import CallbackAdapter
from agentconnect.clock import Clock, FakeClock
from agentconnect.config import Config
from agentconnect.identity import Seeded
from agentconnect.keystore import FileKeystore
from agentconnect.relay import b64, unb64
from agentconnect.runtime import Runtime
from agentconnect.runtime.api import ApiServer
from agentconnect.runtime.engine import Engine, Options
from agentconnect.tasks import cancel_and_wait
from agentconnect.tokens import API_TOKEN_FILE, HUMAN_TOKEN_FILE
from agentconnect_harness.mcp import McpInstance
from agentconnect_harness.proxy import RelayProxy
from agentconnect_harness.relay import RelayProcess
from agentconnect_sdk import AgentConnect, Group, Message
from agentconnect_sdk import Event as SdkEvent
from agentconnect_sdk.embedded import EmbeddedHost

WAIT = 8.0  # real-time guard for every wait; nothing sleeps
# Loop turns a wait gives the adapters' event workers once its predicate
# holds: enough for every healthy adapter, bounded for one that fails.
HANDOVER_TURNS = 100


async def handed_over(engines: list[Any]) -> None:
    """Let the event workers hand over what was recorded: until no running
    engine has an event an adapter hasn't accepted, or the turns run out
    (an adapter that fails keeps its events)."""
    for _ in range(HANDOVER_TURNS):
        running = [e for e in engines if getattr(e, "running", False)]
        if not any(e.store.unnotified_events() for e in running):
            return
        await asyncio.sleep(0)


HOSTS = ("daemon", "embedded")


class EmbeddedTap(RecordingAdapter):
    """The embedded host's callback adapter with a recording in front: it
    records what the runtime handed over and passes everything on. Each
    start of the node attaches the new host's adapter (:meth:`attach`)."""

    def __init__(self, name: str = "recording", card: dict[str, Any] | None = None) -> None:
        super().__init__(name, card)
        self.inner: CallbackAdapter | None = None

    def attach(self, inner: CallbackAdapter) -> Adapter:
        self.inner = inner
        return self

    def _callback(self) -> CallbackAdapter:
        if self.inner is None:
            msg = "no embedded host attached"
            raise RuntimeError(msg)
        return self.inner

    def bind_store(self, store: Any) -> None:
        self._callback().bind_store(store)

    @override
    async def deliver(
        self, group: GroupView, sender: Sender, to: list[str], inner: Delivery
    ) -> DeliveryResult:
        if self.retry_next > 0:
            self.retry_next -= 1
            self._poke()
            return DeliveryResult.RETRY
        result = await self._callback().deliver(group, sender, to, inner)
        if result is DeliveryResult.ACK:
            self.deliveries.append(inner)
        self._poke()
        return result

    @override
    async def on_event(self, group: GroupView | None, event: Event) -> None:
        await self._callback().on_event(group, event)
        await super().on_event(group, event)

    @override
    async def on_outbound(self, send: OutboundSend) -> None:
        self.send = send
        await self._callback().on_outbound(send)

    async def close(self) -> None:
        await self._callback().close()


@dataclass
class Node:
    name: str
    config: Config
    proxy: RelayProxy
    adapter: RecordingAdapter
    clock: FakeClock
    seed: int
    host: str = "daemon"
    # Serve the local API as the hosts do (scenarios usually build their own).
    serve_api: bool = False
    starts: int = 0
    make_adapters: Callable[[Config, Clock], list[Adapter]] | None = None
    # Extra Options seams for every start (e.g. a short door lifetime).
    options: dict[str, Any] = field(default_factory=dict)
    runtime: Runtime = field(init=False)
    # The node's protocol engine (the runtime's), which scenarios drive.
    daemon: Engine = field(init=False)
    # Embedded host only: the SDK client, and what reached its handlers.
    sdk: AgentConnect | None = None
    handled: list[Message | SdkEvent] = field(default_factory=list)
    # The cluster's nodes (shared): their changes wake this node's waits too.
    peers: list[Node] = field(default_factory=list, repr=False, compare=False)
    _serving: asyncio.Task[None] | None = None

    def _options(self) -> Options:
        # A fresh seed per start: a restarted runtime must not replay the
        # randomness (keys, msg_ids) of its previous run.
        self.starts += 1
        seed = self.seed + self.starts
        return Options(
            testing=Seeded(seed),
            backoff_rng=random.Random(seed),  # noqa: S311
            **self.options,
        )

    def recorder(self, card: dict[str, Any] | None = None) -> RecordingAdapter:
        """A fresh recording adapter for this node's host (set it as
        ``adapter`` and restart), e.g. to send an Agent Card."""
        return recorder(self.host, card)

    def _make(self) -> Runtime:
        """A runtime on this node's state, constructed but not started (it
        holds the lock and the databases until stopped)."""
        return Runtime(
            self.config,
            adapters=[self.adapter, *self._extra_adapters()],
            clock=self.clock,
            keystore=FileKeystore(self.config.data_dir / "keys"),
            options=self._options(),
            serve_api=self.serve_api,
        )

    def _extra_adapters(self) -> list[Adapter]:
        # Fresh per start: a restarted runtime gets a fresh adapter.
        if self.make_adapters is None:
            return []
        return self.make_adapters(self.config, self.clock)

    async def start(self) -> None:
        await self._stop_serving()
        if self.host == "embedded":
            await self._start_embedded(FileKeystore(self.config.data_dir / "keys"))
        else:
            self.runtime = self._make()
            await self.runtime.start()
        self.daemon = self.runtime._engine
        await self.connected()

    async def _start_embedded(self, keystore: FileKeystore) -> None:
        tap = self.adapter
        if not isinstance(tap, EmbeddedTap):
            msg = "an embedded node records through an EmbeddedTap"
            raise TypeError(msg)
        host = EmbeddedHost(
            self.config,
            extra_adapters=self._extra_adapters(),
            wrap=tap.attach,
            clock=self.clock,
            keystore=keystore,
            options=self._options(),
            serve_api=self.serve_api,
            flush=0,
        )
        sdk = AgentConnect.hosted(host)

        async def record(item: Message | SdkEvent, _group: Group | None) -> None:
            self.handled.append(item)

        sdk.on_message(record)
        sdk.on_task(record)
        sdk.on_event(record)
        await sdk.start()
        if host.runtime is None:  # pragma: no cover - start sets it
            msg = "the embedded runtime did not start"
            raise RuntimeError(msg)
        self.sdk, self.runtime = sdk, host.runtime
        ready = asyncio.Event()
        self._serving = asyncio.ensure_future(sdk.serve(ready=ready))
        await asyncio.wait_for(ready.wait(), WAIT)

    async def _stop_serving(self) -> None:
        if self._serving is not None:
            serving, self._serving = self._serving, None
            await cancel_and_wait(serving)

    async def stop(self) -> None:
        """Stop without any flush (a crash, for the journal)."""
        await self._stop_serving()
        if self.sdk is not None:
            await self.sdk.aclose()
        else:
            await self.runtime.stop(flush=0)
        if self.daemon.running:  # a scenario swapped in an engine of its own
            await self.daemon.stop()

    async def connected(self) -> None:
        await asyncio.wait_for(self.daemon.link.wait_connected(), WAIT)

    async def restart(self) -> None:
        """Kill (stop without any flush) and start again on the same state."""
        await self.stop()
        await asyncio.wait_for(self.proxy.wait_no_sessions(), WAIT)
        await self.start()

    async def wait(self, predicate: Any, within: float = WAIT) -> None:
        """Wait until ``predicate`` holds. It may read any node's state, so
        any node's change pulse wakes it, not only this node's. Then wait
        until the adapters have the events recorded so far (each adapter's
        own worker hands them over), as far as they take them."""

        async def loop() -> None:
            while True:
                engines = [n.daemon for n in {id(n): n for n in (self, *self.peers)}.values()]
                pulses = [e._changed for e in engines if hasattr(e, "_changed")]
                for pulse in pulses:  # clear before checking: no pulse is lost
                    pulse.clear()
                if predicate():
                    await handed_over(engines)
                    return
                waits = [asyncio.ensure_future(p.wait()) for p in pulses]
                try:
                    await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for w in waits:
                        w.cancel()

        await asyncio.wait_for(loop(), within)

    async def wait_texts(self, group_id: str, n: int) -> list[str]:
        await self.adapter.wait_for(lambda: len(self.adapter.texts(group_id)) >= n, WAIT)
        return self.adapter.texts(group_id)

    async def idle(self) -> None:
        """Wait until the outbox has nothing queued."""
        await self.wait(lambda: not self.daemon.store.outbox())

    @property
    def me(self) -> str:
        return self.daemon.me

    def state(self, group_id: str) -> str:
        """A fingerprint of this node's view of the group (its epoch
        authenticator, through a test-only hook): equal on two nodes that
        share a view. Never a short code; those come from SAS runs
        (:func:`compare`)."""
        return bytes(self.daemon.client._state_fingerprint_for_testing(unb64(group_id))).hex()

    def epoch(self, group_id: str) -> int:
        return int(self.daemon.group_info(group_id)["epoch"])

    def unchecked_commit(
        self,
        group_id: str,
        *,
        adds: list[bytes] | None = None,
        remove_leaves: list[int] | None = None,
        policy: bytes | None = None,
        meta: bytes | None = None,
    ) -> dict[str, Any]:
        """Build a commit with none of the core's checks
        (``Client._commit_unchecked_for_testing``: what a malicious member
        could send) and send it through this node's outbox to the real
        relay. The node's own core merges it; honest members must not."""
        gid = unb64(group_id)
        out = self.daemon.client._commit_unchecked_for_testing(
            gid, adds or [], remove_leaves or [], policy, meta
        )
        env = {
            "v": 0,
            "kind": "commit",
            "group_id": group_id,
            "epoch": out["epoch"],
            "msg_id": out["msg_id"],
            "sender": self.daemon.mailbox,
            "routing": out["routing"],
            "ct": b64(out["commit"]),
        }
        self.daemon._enqueue(
            "frame", None, {"frame": {"t": "send", "env": env}, "msg_id": out["msg_id"]}
        )
        return out


async def serve_api(node: Node, sockdir: Path) -> ApiServer:
    """Serve ``node``'s runtime on a Unix socket in ``sockdir``. Its tokens
    are in ``node.config.data_dir`` (``api-token``, ``human-token``)."""
    node.config = node.config.with_overrides(api_socket=sockdir / f"{node.name}.sock")
    node.daemon.config = node.config
    server = ApiServer(node.daemon)
    await server.start()
    return server


def api_token(server: ApiServer, scope: str) -> str:
    """The token a caller with ``scope`` presents, read from its file as the
    CLI and agents do (the server keeps only hashes). Any other ``scope`` is
    returned as is, a wrong token."""
    files = {"agent": API_TOKEN_FILE, "human": HUMAN_TOKEN_FILE}
    if scope not in files:
        return scope
    path = server.daemon.config.data_dir / files[scope]
    return path.read_text(encoding="ascii").strip()


def recorder(host: str, card: dict[str, Any] | None = None) -> RecordingAdapter:
    return EmbeddedTap(card=card) if host == "embedded" else RecordingAdapter(card=card)


def status(node: Node, group_id: str) -> str | None:
    """The group's local status on ``node`` (``None`` if unknown)."""
    g = node.daemon.store.group(group_id)
    return None if g is None else g.status


def group_state(node: Node, group_id: str) -> tuple[Any, ...]:
    """What every member of a converged group agrees on: epoch, view
    (:meth:`Node.state`), members with their roles and instances, the policy
    and the floor holder."""
    info = node.daemon.group_info(group_id)
    members = sorted(
        (m["identity"], m["role"], tuple(sorted(i["instance_id"] for i in m["instances"])))
        for m in info["members"]
    )
    return (
        info["epoch"],
        node.state(group_id),
        tuple(members),
        sorted(info["policy"].items()),
        info["floor"]["holder"],
    )


async def unpaired(a: Node, b: Node, group_id: str) -> tuple[str, str]:
    """Both humans start a SAS run and every commitment went out, yet
    neither run paired: how a fork shows when the views differ in their
    epoch (SPEC 12). Returns the two run ids."""
    run_a = str(a.daemon.sas_start(group_id, b.me)["run"])
    run_b = str(b.daemon.sas_start(group_id, a.me)["run"])
    await a.idle()
    await b.idle()
    await a.wait(lambda: not a.daemon.status()["inbox_pending"])
    await b.wait(lambda: not b.daemon.status()["inbox_pending"])
    for node, run in ((a, run_a), (b, run_b)):
        view = node.daemon.sas_run(group_id, run)
        # Still waiting, or ended without pairing (an out-of-sync group sends nothing).
        if view["state"] not in ("waiting", "aborted") or "peer_instance" in view:
            raise AssertionError(view)
    return run_a, run_b


async def compare(a: Node, b: Node, group_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """A SAS run between ``a`` and ``b`` (SPEC 11.3), both humans starting
    their side through the human API at once; returns both final views
    (``done`` with a code, or ``aborted``)."""
    run_a = a.daemon.sas_start(group_id, b.me)["run"]
    run_b = b.daemon.sas_start(group_id, a.me)["run"]

    def ended(node: Node, run: str) -> bool:
        return node.daemon.sas_run(group_id, run)["state"] in ("done", "aborted")

    await a.wait(lambda: ended(a, run_a) and ended(b, run_b))
    return a.daemon.sas_run(group_id, run_a), b.daemon.sas_run(group_id, run_b)


async def verify(a: Node, b: Node, group_id: str) -> dict[str, Any]:
    """``a``'s human verifies ``b`` the way SPEC 11 has it: a SAS run with
    both humans taking part, the same code on both sides, and ``a``'s answer
    "same" for its run. Returns ``a``'s run."""
    run_a, run_b = await compare(a, b, group_id)
    mirrored = {
        "self": run_b.get("labels", {}).get("peer"),
        "peer": run_b.get("labels", {}).get("self"),
    }
    if not (
        run_a["state"] == run_b["state"] == "done"
        and run_a["sas"] == run_b["sas"]
        and run_a["labels"] == mirrored
    ):
        raise AssertionError((run_a, run_b))
    a.daemon.mark_verified(group_id, b.me, True, run_a["run"])
    return run_a


async def converged(nodes: list[Node], group_id: str) -> None:
    """Wait until every node is active in the group with the same
    :func:`group_state` and an idle outbox."""

    def same() -> bool:
        if any(status(n, group_id) != "active" or n.daemon.store.outbox() for n in nodes):
            return False
        return len({repr(group_state(n, group_id)) for n in nodes}) == 1

    await nodes[0].wait(same)


class Cluster:
    def __init__(
        self, relay: RelayProcess, tmp: Path, rng: random.Random, host: str = "daemon"
    ) -> None:
        if host not in HOSTS:
            msg = f"unknown host {host}"
            raise ValueError(msg)
        self.relay = relay
        self.tmp = tmp
        self.rng = rng
        self.host = host
        now = datetime.now(UTC).replace(microsecond=0)
        self.clock = FakeClock(now)
        self.nodes: list[Node] = []
        self.mcps: list[McpInstance] = []
        self._proxies: list[RelayProxy] = []

    async def node(  # noqa: PLR0913
        self,
        name: str | None = None,
        auto_approve: bool = True,
        identity_of: Node | None = None,
        *,
        default_adapter: str = "recording",
        make_adapters: Callable[[Config, Clock], list[Adapter]] | None = None,
        host: str | None = None,
        serve_api: bool = False,
        data_dir: Path | None = None,
        options: dict[str, Any] | None = None,
        **overrides: Any,
    ) -> Node:
        """A started node. ``identity_of`` makes it a replica (another
        instance of that node's identity). ``make_adapters`` adds adapters
        built from its config. ``host`` overrides the cluster's host;
        ``serve_api`` serves the local API on the node's socket, in
        ``data_dir`` (default ``<tmp>/<name>``) unless ``api_socket`` says
        otherwise. ``options`` adds Options seams to each start."""
        name = name or f"n{len(self.nodes)}"
        proxy = RelayProxy(self.relay.ws_url)
        await proxy.start()
        data_dir = data_dir or self.tmp / name
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
            default_adapter=default_adapter,
            keystore="file",
            auto_approve=auto_approve,
            **overrides,
        )
        chosen = host or self.host
        node = Node(
            name,
            config,
            proxy,
            recorder(chosen),
            self.clock,
            self.rng.getrandbits(63),
            host=chosen,
            serve_api=serve_api,
            make_adapters=make_adapters,
            options=options or {},
            peers=self.nodes,
        )
        await node.start()
        self.nodes.append(node)
        return node

    async def mcp(
        self,
        name: str,
        *,
        data_dir: Path | None = None,
        start: bool = True,
        **overrides: Any,
    ) -> McpInstance:
        """An ``agentconnect mcp`` server in this process (started unless
        ``start=False``), on its own proxy to the relay and the cluster's
        clock. Its data directory is ``<tmp>/<name>`` unless given: pass
        another instance's (or a node's) to attach to it."""
        proxy = RelayProxy(self.relay.ws_url)
        await proxy.start()
        self._proxies.append(proxy)
        config = Config(
            relay_url=proxy.url,
            relay_host=self.relay.host,
            relay_rest_url=self.relay.http_url,
            data_dir=data_dir or self.tmp / name,
            display_name=name,
            default_adapter="mcp",
            keystore="file",
            **overrides,
        )
        instance = McpInstance(name, config, self.clock, self.rng.getrandbits(63))
        self.mcps.append(instance)
        if start:
            await instance.start()
        return instance

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

    async def group(
        self, n: int, mode: str = "distinct", invite: str = "single"
    ) -> tuple[list[Node], str]:
        """``n`` members, fully joined. ``mode="replicas"``: every member is an
        instance of one identity. ``invite="multi"``: they all redeem one
        invite with ``max_uses = n - 1``, one after the other."""
        if mode not in ("distinct", "replicas") or invite not in ("single", "multi"):
            msg = f"unknown mode {mode} or invite {invite}"
            raise ValueError(msg)
        first = await self.node()
        gid = first.daemon.create_group("Harness", "Exercise the daemon")
        await first.idle()
        nodes = [first]
        url = None
        if invite == "multi" and n > 1:
            url = (await first.daemon.create_invite(gid, max_uses=n - 1))["url"]
        for _ in range(n - 1):
            joiner = await self.node(identity_of=first if mode == "replicas" else None)
            if url is None:
                await self.invite(first, joiner, gid)
            else:
                before = first.epoch(gid)
                await joiner.daemon.accept_invite(url)
                await joiner.wait(lambda j=joiner: j.daemon.store.group(gid) is not None)
                await self.settle(gid, before + 1)
            nodes.append(joiner)
        return nodes, gid

    async def advance(self, seconds: float) -> None:
        """Advance the shared clock and let woken timers run."""
        self.clock.advance(seconds)
        for _ in range(5):
            await asyncio.sleep(0)

    async def close(self) -> None:
        for m in reversed(self.mcps):  # attached sessions first
            await m.stop()
        for n in self.nodes:
            await n.stop()
            await n.proxy.stop()
        for p in self._proxies:
            await p.stop()
