"""Builds the adapters ``agentconnectd`` runs from its configuration."""

from __future__ import annotations

from agentconnect.adapter import Adapter
from agentconnect.clock import Clock
from agentconnect.config import Config
from agentconnect.deliveries import DeliveryQueue
from agentconnect.isolation import receiver_uids
from agentconnect.sockets import receiver_async_transport
from agentconnect.sse import SseAdapter
from agentconnect.tokens import load_token
from agentconnect.webhook import SECRET_FILE, SOCKET_URL, WebhookAdapter


def build_adapters(config: Config, clock: Clock) -> list[Adapter]:
    """The adapters named by ``daemon.adapters`` (or ``daemon.default_adapter``),
    in that order: ``webhook`` (needs ``webhook.callback_url`` or
    ``webhook.callback_socket``, checked by its server's user), ``sse``,
    ``mcp`` (the delivery queue that MCP sessions attached to this daemon pull
    from, docs/adapters/mcp.md) and ``a2a``. The A2A adapter
    (docs/adapters/a2a.md) also runs whenever ``a2a.local_agent_url`` or
    ``a2a.facade_port`` is set, listed or not. A group delivers to every
    adapter of its list (its pinned one, else the config's); with none
    named, to the first adapter built, so with ``none`` and the A2A adapter
    configured that is the A2A adapter. Without any, received messages wait
    in the inbound queue.

    The webhook secret lives in ``<data_dir>/webhook-secret`` (0600, created
    on first use) next to ``api-token``; the SDK reads both. It signs
    deliveries. It grants no access to the daemon."""
    adapters: list[Adapter] = []
    names = config.adapter_names
    for name in names:
        if name == "webhook" and (config.webhook_url or config.webhook_socket) is not None:
            config.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            secret = load_token(config.data_dir / SECRET_FILE)
            transport = (
                None
                if config.webhook_socket is None
                else receiver_async_transport(config.webhook_socket, receiver_uids(config))
            )
            adapters.append(
                WebhookAdapter(
                    config.webhook_url or SOCKET_URL,
                    secret,
                    clock,
                    transport=transport,
                    timeout=config.webhook_timeout,
                )
            )
        elif name == "sse":
            adapters.append(SseAdapter(clock, config.sse_retention))
        elif name == "mcp":
            adapters.append(DeliveryQueue(clock))
    if config.a2a_enabled:
        from agentconnect.a2a_adapter import A2AAdapter, A2AOptions  # noqa: PLC0415

        a2a = A2AAdapter(A2AOptions.from_config(config))
        if a2a.name in names:
            adapters.insert(names.index(a2a.name), a2a)
        elif not names:
            adapters.insert(0, a2a)  # groups bound to no adapter deliver to the first
        else:
            adapters.append(a2a)
    return adapters
