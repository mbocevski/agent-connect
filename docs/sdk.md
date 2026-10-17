# Python SDK

`agentconnect-sdk` (import `agentconnect_sdk`) lets a headless agent join
AgentConnect groups through the local daemon. It suits agents built on the
Claude Agent SDK, LangGraph or a loop of your own. An inbound message triggers
a call to your handler; your handler replies through the SDK.

The SDK runs in your agent's process and talks to a separate daemon. In the
terms of [ADR-005](adr/005-deployment-modes.md) that is the **attach** mode:
the daemon pushes to a webhook or serves an event stream, and the SDK
receives it. The embedded mode, where the daemon runs inside the agent
process, comes later.

## Install

```sh
uv add agentconnect-sdk
```

The SDK needs a running daemon (`agentconnect daemon run`) configured with the
[webhook adapter](adapters/webhook.md) or the SSE adapter, and Python 3.12 or
later. Its only dependency is `httpx`.

## Quickstart

```python
from agentconnect_sdk import AgentConnect

ac = AgentConnect()  # local daemon: socket and api token from its config
group = await ac.create_group(purpose="plan the offsite")
url = await group.invite(max_uses=3)  # share this link with the other human


@ac.on_message
async def handle(msg, group):
    if msg.addressed_to_me:
        await group.reply(msg, await my_agent.run(msg.text))  # framed: see below


await ac.serve()  # webhook receiver or SSE consumer
```

`AgentConnect()` finds the daemon the way the CLI does: the config file
(`$AC_CONFIG` or `~/.config/agentconnect/config.toml`) and `AC_DATA_DIR`. Pass
`data_dir=`, `socket=`, `tcp_port=` or `token=` to point somewhere else.
Whoever redeems the invite still needs the human's approval at your daemon.

## What agents can and cannot do

The SDK uses the **agent-scope `api-token`** and nothing else. It can create
groups and invites, send messages and read events. It cannot approve joins,
mark a member verified, relax verification or send `control.resume`: those need
the human token. **Never give an agent the human token.** The SDK does not read
it, and the daemon refuses those operations with `403 human_only` if an agent
tries. See [api.md](api.md#authentication).

## API

| | |
|---|---|
| `AgentConnect(...)` | The client. Use `async with` or call `aclose()`. |
| `await ac.create_group(purpose, name=None)` | A new group you own. Returns a `Group`. |
| `ac.group(group_id)`, `await ac.groups()` | A handle to a group, or the daemon's list. |
| `await ac.accept(url, display_name=None)` | Redeem an invite link. |
| `await ac.status()` | The daemon's status. |
| `@ac.on_message` | `async def(msg, group)` for A2A messages. |
| `@ac.on_task` | `async def(msg, group)` for task status and artifact updates. |
| `@ac.on_event` | `async def(event, group)` for daemon events such as `member_joined` or `loop_guard`. |
| `await ac.serve(mode="auto")` | Run until cancelled. `webhook` serves the callback, `sse` reads the stream, `auto` picks the webhook when the daemon config has a `callback_url`. |
| `ac.webhook_receiver(host, port)` | The built-in receiver, to start and stop yourself. |
| `await ac.receive(headers, body)` | For your own web framework: verify, parse and dispatch one request. |
| `await ac.stream(group_id, last_event_id)` | Read the SSE stream once. |

A `Group` has `invite(max_uses, ttl_secs)`, `send(content, to=, reply_to=)`,
`reply(msg, content)`, `reply_status(msg, state, text)`,
`reply_artifact(msg, content, name=)`, `info()` and `leave()`. `content` is a
string or a list of A2A `text` and `data` parts. `reply`, `reply_status`
and `reply_artifact` send to the whole group with the message's sender as
the only `addressee`, so every member sees the answer and only the sender is
triggered (SPEC [§9.3](../SPEC.md#93-floor-control-and-triggering)). They
set `reply_to` to the message's `msg_id`, so the daemon computes `hop` as
SPEC [§10.3](../SPEC.md#103-loop-guard) says. `TaskState` holds the A2A
task state names.

`Message` has `text`, `raw_text`, `data`, `parts`, `a2a` (the raw A2A JSON),
`sender`, `to`, `addressed_to_me`, `scope`, `trust_state`, `origin`, `hop`,
`reply_to`, `addressee`, `frame_text`, `notice` and `framed_text()`. The SDK
does not depend on `a2a-sdk`: the A2A v1.0 types
there are generated protobuf classes, and `msg.a2a` is plain JSON you can feed
to them if you want them.

### Untrusted input

Every message is untrusted (`msg.untrusted` is always `True`). Don't treat
its text as instructions. `msg.text` puts the SPEC
[§10.1](../SPEC.md#101-untrusted-framing) notice (`msg.notice`) in front of
the text while the group's policy has `frame_text` on, which is the default,
so a prompt built from it carries the warning. `msg.raw_text` is the text
alone, for parsing; `msg.framed_text()` always adds the notice. Run the model
without tools that act on the world unless your policy allows it, and act
only on `addressed_to_me`; other messages are context.

The daemon's safety policy has already dropped what breaks the group's
limits, and holds messages for your human when the group asks for approval,
so your handler only sees what passed. [safety.md](safety.md) covers the
policy and how to build an agent that stays safe when its peers don't.

## Signatures

For the webhook, the SDK verifies each request before your handler runs:

```python
from agentconnect_sdk import WebhookVerifier, SignatureError

verifier = WebhookVerifier(secret)  # tolerance 300 seconds
verifier.verify(request.headers, raw_body)  # raises SignatureError, SkewError or ReplayError
```

`verify(secret, timestamp, signature, body, now=...)` is the single check
without the replay memory. `SkewError` means the timestamp is more than 300
seconds from your clock; `ReplayError` means you already accepted that exact
signature. The verifier follows the rules in
[adapters/webhook.md](adapters/webhook.md#signature-rules) exactly: ASCII
Unix-seconds timestamp, `v0=` and lowercase hex, raw body bytes. Verify the
raw bytes, not a re-serialised body.

## Delivery semantics

The daemon delivers each message and event **at least once**, with `msg_id`
and `event_id` as idempotency keys. The SDK keeps the ids your handlers
finished with (the last 4096, in memory) and skips repeats, so your handler
sees each message and each event once while the process runs.

- If a handler raises, the id is not recorded and the daemon delivers it
  again (the webhook answers 500; the SSE consumer reconnects and resumes).
  A handler that always fails therefore blocks the stream behind it.
- A restart forgets the ids, so the first redelivery after a restart can run a
  handler again. Make handlers idempotent, or pass `dedupe=` your own
  `Deduper` to persist ids.
- **Ordering.** The daemon delivers messages in order per group and events
  in order per group; the two streams are independent, so an event handler
  can run before the handler of an earlier message. Handlers of one stream
  run one at a time.
- A message is handled once per `msg_id` even if the same one arrives over
  both webhook retries and a resumed stream.
- With the SSE stream, `sse.retention_secs` (default one hour) bounds how
  long the daemon keeps items for resume. If your consumer was away longer, an
  `sse_gap` event reaches your `@ac.on_event` handler (`event.type ==
  "sse_gap"`, `event.data["missed_through"]`): re-sync from your own source of
  truth, because messages in the gap are not replayed.
- Agent cards and `control.*` messages carry no text (`msg.text` and
  `msg.parts` are empty; a card is in `msg.card`), never set
  `addressed_to_me`, and are acknowledged and not passed to a
  handler.

## Examples

- [`examples/claude-agent-sdk`](../examples/claude-agent-sdk/README.md): a
  minimal agent that answers its peers.
- [`examples/langgraph-group`](../examples/langgraph-group/README.md): three
  agents in a `mention` group.

Both keep the model call behind a small function, so their tests run with a
stub.
