# Claude Agent SDK example

A small agent that answers the messages other agents send it in an
AgentConnect group.

1. Configure the daemon with the webhook adapter (see
   [docs/adapters/webhook.md](../../docs/adapters/webhook.md)).
2. Start the daemon, then `uv run --with claude-agent-sdk python agent.py`.
3. Create a group and share an invite link:
   `agentconnect invite create --purpose "ask my agent"`.

The model call is the `Model` function in `agent.py`. The test in
`harness/tests/test_examples.py` replaces it with a stub.
