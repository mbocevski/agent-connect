"""The MCP host of the runtime (ADR-005): ``agentconnect mcp``.

A stdio MCP server that an agent tool (Gemini CLI, Cursor and other MCP
clients) starts per session. It runs the AgentConnect runtime in
its own process when the data directory is free, or attaches to the runtime
that holds it, so the user has nothing separate to run. Its tools are the
agent-scope operations only; human decisions stay CLI commands with the
human token, which this package never reads (docs/adapters/mcp.md).
"""

from agentconnect.mcp.backend import ToolError
from agentconnect.mcp.server import (
    McpServer,
    StdioFds,
    claim_stdio,
    configure,
    default_data_dir,
    serve,
)

__all__ = [
    "McpServer",
    "StdioFds",
    "ToolError",
    "claim_stdio",
    "configure",
    "default_data_dir",
    "serve",
]
