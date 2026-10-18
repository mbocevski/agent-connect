"""Builds the adapters ``agentconnectd`` runs from its configuration."""

from __future__ import annotations

from agentconnect.adapter import Adapter
from agentconnect.clock import Clock
from agentconnect.config import Config
from agentconnect.deliveries import DeliveryQueue
from agentconnect.sse import SseAdapter
from agentconnect.tokens import load_token
from agentconnect.webhook import SECRET_FILE, WebhookAdapter


def build_adapters(config: Config, clock: Clock) -> list[Adapter]:
    """The adapter named by ``daemon.default_adapter``: ``webhook`` (needs
    ``webhook.callback_url``), ``sse`` or ``mcp`` (the delivery queue that
    MCP sessions attached to this daemon pull from, docs/adapters/mcp.md),
    and the A2A adapter (docs/adapters/a2a.md) when ``a2a.local_agent_url`` or
    ``a2a.facade_port`` is set. Groups deliver to the adapter their binding
    names (``default_adapter`` when they were created); with ``none`` and the
    A2A adapter configured, that is the A2A adapter. Without any, received
    messages wait in the inbound queue.

    The webhook secret lives in ``<data_dir>/webhook-secret`` (0600, created
    on first use) next to ``api-token``; the SDK reads both. It signs
    deliveries. It grants no access to the daemon."""
    adapters: list[Adapter] = []
    if config.default_adapter == "webhook" and config.webhook_url is not None:
        config.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        secret = load_token(config.data_dir / SECRET_FILE)
        adapters.append(
            WebhookAdapter(config.webhook_url, secret, clock, timeout=config.webhook_timeout)
        )
    elif config.default_adapter == "sse":
        adapters.append(SseAdapter(clock, config.sse_retention))
    elif config.default_adapter == "mcp":
        adapters.append(DeliveryQueue(clock))
    if config.a2a_enabled:
        from agentconnect.a2a_adapter import A2AAdapter, A2AOptions  # noqa: PLC0415

        a2a = A2AAdapter(A2AOptions.from_config(config))
        # A group bound to no adapter (`none`) delivers to the first one.
        if config.default_adapter in ("none", a2a.name):
            adapters.insert(0, a2a)
        else:
            adapters.append(a2a)
    return adapters
