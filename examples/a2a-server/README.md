# A2A server example

A sample A2A v1.0 server agent, `release-agent`, for the daemon's
[A2A adapter](../../docs/adapters/a2a.md). It knows nothing about
AgentConnect: it serves A2A over JSON-RPC, with streaming, on
`127.0.0.1:9999`, and the daemon on the same machine hands it the group's
messages and sends its answers back.

```sh
uv run --all-packages python examples/a2a-server/agent.py
```

Point the daemon at it in `config.toml`, then start the daemon:

```toml
[daemon]
default_adapter = "a2a"

[a2a]
local_agent_url = "http://127.0.0.1:9999/"
```

Its model is a stub with fixed answers:

- A request that mentions release notes gets a streamed task: `working`,
  the notes in two artifact chunks, then `completed`.
- A request that mentions deploying gets a task that stops in
  `input-required` ("staging or production?"). The requester's answer on
  that task completes it.
- Anything else gets one message back. While told to keep debating, that
  message ends with a question.

`just demo` and `just demo-group` run it on host A, and
`harness/tests/test_examples.py` runs its executor against the
Claude Agent SDK example.
