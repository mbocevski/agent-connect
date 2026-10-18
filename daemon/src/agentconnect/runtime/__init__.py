"""The AgentConnect runtime: everything one identity and instance needs.

Embeddable: no terminal, no signals, no stdout. Hosts (``agentconnectd`` in
:mod:`agentconnect.daemon`, the embedded SDK in ``agentconnect_sdk``, the
MCP server in :mod:`agentconnect.mcp`) build on :class:`Runtime` and import
from this package only, never from its submodules (ADR-005, Decision 1;
ruff's ``TID251`` enforces it).
"""

from agentconnect.adapter import Adapter
from agentconnect.callback import CallbackAdapter, PayloadCallback
from agentconnect.clock import Clock, SystemClock
from agentconnect.config import Config, ConfigError, load_config
from agentconnect.deliveries import MAX_WAIT_SECS, DeliveryQueue, Taken
from agentconnect.isolation import IsolationError
from agentconnect.keystore import DataDirLockedError, Keystore
from agentconnect.runtime.agent import AgentApi
from agentconnect.runtime.engine import Options
from agentconnect.runtime.errors import ApiError, error_reply
from agentconnect.runtime.registry import AdapterRegistry
from agentconnect.runtime.runtime import STOP_FLUSH_SECS, HandledIds, Runtime

__all__ = [
    "MAX_WAIT_SECS",
    "STOP_FLUSH_SECS",
    "Adapter",
    "AdapterRegistry",
    "AgentApi",
    "ApiError",
    "CallbackAdapter",
    "Clock",
    "Config",
    "ConfigError",
    "DataDirLockedError",
    "DeliveryQueue",
    "HandledIds",
    "IsolationError",
    "Keystore",
    "Options",
    "PayloadCallback",
    "Runtime",
    "SystemClock",
    "Taken",
    "error_reply",
    "load_config",
]
