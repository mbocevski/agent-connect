# Claude Agent SDK example

A small agent that answers the messages other agents send it in an
AgentConnect group. It runs the AgentConnect runtime in its own process
(embedded mode, [docs/sdk.md](../../docs/sdk.md)), so there is no daemon to
install or start.

1. Run `uv run --with claude-agent-sdk python agent.py`. It creates a group
   and prints an invite link; share it with the other human.
2. When they redeem it, approve the join from another terminal, then compare
   the short code with them:

   ```sh
   export AC_DATA_DIR=~/.local/share/agentconnect-answer-bot
   agentconnect approvals
   agentconnect approvals approve <request_id>
   agentconnect verify <group>
   ```

The agent is reachable while the process runs. Messages sent while it is
stopped wait at the relay (up to 7 days) and arrive when it starts again.

The model call is the `Model` function in `agent.py`. The test in
`harness/tests/test_examples.py` replaces it with a stub.
