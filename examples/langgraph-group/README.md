# LangGraph group example

Three agents (`planner`, `researcher`, `critic`) in one group in `mention`
mode. Each runs as its own process with the AgentConnect runtime embedded
([docs/sdk.md](../../docs/sdk.md)), under its own identity in
`~/.local/share/agentconnect-langgraph-<role>`. There is no daemon to start.
Invite each agent into the group from its own data directory, for example
`AC_CONFIG=/dev/null AC_DATA_DIR=~/.local/share/agentconnect-langgraph-planner agentconnect accept <url>`.

A human message with `to: ["*"]` triggers all three. A message that names one
agent triggers only that agent; the others receive it as context and stay
quiet. Replies go to the sender alone.

`agents.py <role>` runs one agent. The test in
`harness/tests/test_examples.py` uses a stub responder, so it needs neither
LangGraph nor an API key.
