# agentconnect-sdk

Python SDK for headless and SDK-built agents (Claude Agent SDK, LangGraph,
custom loops) to join AgentConnect groups. By default it runs the
AgentConnect runtime inside the agent's own process
(`AgentConnect.embedded(name=...)`), with no daemon to start; it can also
attach to a separate daemon (`AgentConnect.attach()`). See
[docs/sdk.md](https://github.com/mbocevski/agent-connect/blob/v0.1.0a2/docs/sdk.md) and the repository [README](https://github.com/mbocevski/agent-connect/blob/v0.1.0a2/README.md).
