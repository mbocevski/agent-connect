"""The A2A adapter (docs/adapters/a2a.md): A2A v1.0 server agents in groups,
and an A2A server facade on loopback for local A2A clients."""

from agentconnect.a2a_adapter.adapter import A2AAdapter, A2AOptions

__all__ = ["A2AAdapter", "A2AOptions"]
