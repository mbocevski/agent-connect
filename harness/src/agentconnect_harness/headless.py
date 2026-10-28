"""A daemon node with the SDK in front of it, for headless-agent tests.

``headless(cluster, name, sockdir)`` starts a daemon whose adapter is the
webhook (or SSE) adapter, serves its local API on a Unix socket, and returns
an :class:`~agentconnect_sdk.AgentConnect` bound to it with the API token only.
The SDK reads the cluster's fake clock, so signature skew tracks daemon time.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from agentconnect.adapter import Adapter
from agentconnect.clock import Clock
from agentconnect.config import Config
from agentconnect.runtime.api import ApiServer
from agentconnect.sockets import receiver_async_transport
from agentconnect.sse import SseAdapter
from agentconnect.webhook import SOCKET_URL, WebhookAdapter
from agentconnect_harness.cluster import Cluster, Node, serve_api, serve_api_tcp
from agentconnect_sdk import AgentConnect
from agentconnect_sdk.receiver import WebhookReceiver

UNREACHABLE = "http://127.0.0.1:1/"  # nothing listens: the webhook is "down"


@dataclass
class Headless:
    node: Node
    server: ApiServer
    sdk: AgentConnect
    mode: str
    receiver: WebhookReceiver | None = None
    hook_socket: Path | None = None  # the receiver's Unix socket, if on one

    async def up(self) -> None:
        """Start the SDK's webhook server and point the daemon at it."""
        if self.hook_socket is not None:
            self.receiver = self.sdk.webhook_receiver(path=self.hook_socket)
            await self.receiver.start()
            return
        self.receiver = self.sdk.webhook_receiver(port=0)
        await self.receiver.start()
        self.hook.url = f"http://127.0.0.1:{self.receiver.address[1]}/"

    async def down(self) -> None:
        """Stop the webhook server (the daemon sees connection refused)."""
        if self.receiver is not None:
            if self.hook_socket is None:
                self.hook.url = UNREACHABLE  # nothing new reaches the receiver while it closes
            await self.hook.drain()  # requests already sent finish first
            await self.receiver.close()
            self.receiver = None

    @property
    def hook(self) -> WebhookAdapter:
        return cast("WebhookAdapter", self.node.daemon.adapters["webhook"])

    @property
    def hub(self) -> SseAdapter:
        return cast("SseAdapter", self.node.daemon.adapters["sse"])

    async def close(self) -> None:
        await self.down()
        await self.sdk.aclose()
        await self.server.stop()


async def headless(  # noqa: PLR0913
    cluster: Cluster,
    name: str,
    sockdir: Path,
    mode: Literal["webhook", "sse"] = "webhook",
    *,
    auto_approve: bool = True,
    started: bool = True,
    hook_socket: bool = False,
    tcp: bool = False,
    **config: Any,
) -> Headless:
    """``started=False`` leaves the webhook unreachable until :meth:`Headless.up`.
    ``hook_socket=True`` puts the webhook receiver on a Unix socket in
    ``sockdir``, checked by its server's user. ``tcp=True`` serves the API on a
    loopback port (TLS) instead of a socket."""
    secret = secrets.token_urlsafe(16)
    hook_path = sockdir / f"{name}-hook.sock" if hook_socket else None

    def adapters(config: Config, clock: Clock) -> list[Adapter]:
        if mode == "sse":
            return [SseAdapter(clock, config.sse_retention)]
        if hook_path is not None:
            transport = receiver_async_transport(hook_path, {os.geteuid()})
            return [WebhookAdapter(SOCKET_URL, secret, clock, transport=transport)]
        if config.webhook_url is None:
            msg = "the webhook adapter needs a callback_url"
            raise ValueError(msg)
        return [WebhookAdapter(config.webhook_url, secret, clock)]

    node = await cluster.node(
        name,
        auto_approve=auto_approve,
        default_adapter=mode,
        make_adapters=adapters,
        webhook_url=UNREACHABLE if mode == "webhook" else None,
        **config,
    )
    server = await (serve_api_tcp(node) if tcp else serve_api(node, sockdir))
    sdk = AgentConnect(
        data_dir=node.config.data_dir,
        socket=None if tcp else Path(str(server.address)),
        tcp_port=node.config.api_tcp_port if tcp else None,
        webhook_secret=secret,
        clock=lambda: cluster.clock.unix_millis() / 1000,
    )
    out = Headless(node, server, sdk, mode, hook_socket=hook_path)
    if started and mode == "webhook":
        await out.up()
    return out
