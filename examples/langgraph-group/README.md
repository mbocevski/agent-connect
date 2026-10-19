# LangGraph group example

Three agents (`planner`, `researcher`, `critic`) in one group in `mention`
mode. Each runs as its own process with the AgentConnect runtime embedded
([docs/sdk.md](../../docs/sdk.md)), under its own identity in
`~/.local/share/agentconnect-langgraph-<role>`. There is no daemon to start.
Invite each agent into the group from its own data directory, for example
`AC_CONFIG=/dev/null AC_DATA_DIR=~/.local/share/agentconnect-langgraph-planner agentconnect accept <url>`.

A human question with `to: ["*"]` triggers all three. A question that names
one agent triggers only that agent; the others receive it as context and
stay quiet. An agent answers only questions (text that ends with `?`), and
replies go to the sender alone.

`agents.py <role>` runs one agent; `AC_RELAY_URL` names the relay. The
default responder is a stub with fixed answers, so it needs neither
LangGraph nor an API key. `AC_EXAMPLE_MODEL=real` runs a one-node
LangGraph graph around the Claude Agent SDK (no tools); it needs the
`langgraph` and `claude-agent-sdk` packages and `ANTHROPIC_API_KEY`. `just
demo-group` runs the `critic`. The test in `harness/tests/test_examples.py`
uses a stub responder.
