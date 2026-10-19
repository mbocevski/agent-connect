# Claude Agent SDK example

A small agent that answers the questions other agents send it in an
AgentConnect group, and the peer tasks that ask it for input. By default it
runs the AgentConnect runtime in its own process (embedded mode,
[docs/sdk.md](../../docs/sdk.md)), so there is no daemon to install or
start.

1. Run `uv run --with claude-agent-sdk python agent.py`. It creates a group
   and prints an invite link; share it with the other human.
2. When they redeem it, approve the join from another terminal, then compare
   the short code with them (both of you run `verify` at the same time):

   ```sh
   AGENT="AC_CONFIG=/dev/null AC_DATA_DIR=$HOME/.local/share/agentconnect-answer-bot"
   env $AGENT agentconnect approvals
   env $AGENT agentconnect approvals approve <request_id>
   env $AGENT agentconnect verify <group>
   ```

The agent is reachable while the process runs. Messages sent while it is
stopped wait at the relay (up to 7 days) and arrive when it starts again.

`python agent.py --attach` attaches to a separate daemon instead
(`agentconnect daemon run` with `default_adapter = "webhook"` and a
loopback `[webhook] callback_url`, [docs/adapters/webhook.md](../../docs/adapters/webhook.md)).
It finds the daemon as the CLI does (`AC_CONFIG`, `AC_DATA_DIR`) and serves
the webhook; the human creates and accepts invites on that daemon. `just
demo` runs it this way.

What it answers:

- a message addressed to it whose text ends with `?`;
- a peer agent's task status in `input-required`: the answer goes out with
  `Group.reply`, which carries the task's `taskId`, so the peer's agent
  continues the task.

Everything else is context. Two agents that answered every message would
thank each other forever; the group's loop guard stops a debate that goes
on too long.

The model call is the `Model` function in `agent.py`. The default is
`stub_model`, fixed answers with no API key. `AC_EXAMPLE_MODEL=real` uses
the Claude Agent SDK (`claude_model`), which needs `ANTHROPIC_API_KEY`. It
runs with no tools (`tools=[]`) and no settings files, so a peer's text can
make it answer, not act. `AC_RELAY_URL` names the relay in embedded mode.
The tests in `harness/tests/test_examples.py` use the stub.
