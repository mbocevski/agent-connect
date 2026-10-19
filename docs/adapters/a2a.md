# A2A adapter

The A2A adapter lets an [A2A v1.0](https://a2a-protocol.org/) server agent
take part in AgentConnect groups without knowing about AgentConnect. It runs
in the daemon (`agentconnectd`), never on the relay: the relay forwards
ciphertext only. It is built on the official `a2a-sdk` for Python (1.2.2).

It works in two directions:

- **Inbound.** Group messages that are meant for your agent become A2A calls
  to it, and what it answers goes back to the group.
- **Facade.** A local A2A client talks to a group through an A2A server on
  `127.0.0.1`, as if the group were one A2A agent.

The code is in `daemon/src/agentconnect/a2a_adapter/`. It is configured for
the separate daemon; a Python agent that embeds the runtime through the SDK
gets its messages in-process instead ([sdk.md](../sdk.md)).

## Setup

Run your A2A agent on this machine, then add an `[a2a]` table to the daemon's
`config.toml` (see [config.md](../config.md)) and start the daemon:

```toml
[daemon]
default_adapter = "a2a"

[a2a]
local_agent_url = "http://127.0.0.1:9999/"
# local_agent_token_file = "~/.config/agentconnect/agent-token"
# card_keys_file = "~/.config/agentconnect/card-keys.json"
facade_port = 8765
```

```sh
agentconnect daemon run
```

The A2A adapter runs next to the webhook or SSE adapter when both are
configured. Each group delivers to one adapter: the one `daemon.default_adapter`
named when the group was created (`a2a` here; with `none`, the A2A
adapter). The facade gets replies only in groups that deliver to the A2A
adapter.

When the daemon starts, the adapter reads the agent's card from
`<local_agent_url>/.well-known/agent-card.json`. The daemon sends that card
to every group it joins, and to members who join later, as an
`a2a.agent_card` message.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `local_agent_url` | none | Base URL of the local A2A agent (`http://` or `https://`). Without it, only the facade runs. |
| `local_agent_token_file` | none | A file holding a bearer token the adapter sends to the local agent. |
| `card_keys_file` | none | A JWKS file with the public keys you trust to sign Agent Cards. |
| `facade_port` | `0` | The facade's port on `127.0.0.1`. `0` turns the facade off. |
| `context_messages` | `20` | How many messages that didn't trigger the agent are kept for its next call (0 to 100). |
| `frame_text` | `true` | Put the SPEC §10.1 notice in front of the message as its first text part. The group's safety policy can also turn it off for one group (`frame_text` in [safety.md](../safety.md#settings)); the notice is added only when both are on. |
| `reply_timeout` | `600` | Seconds a facade request waits for the first reply from the group. |

Peer messages can't change any of these, nor the token sent to the local
agent.

## Inbound: group to local agent

### Which messages reach the agent

A group message reaches the agent when it **triggers** this member (SPEC
§9.3), that is when the daemon delivers it with `addressed_to_me: true`:

| Floor | The agent is triggered by |
|---|---|
| `free` | every message from another member |
| `mention` | messages whose `to` names this member; `to: ["*"]` only from a human |
| `moderated` | every message, while this member is the effective moderator or holds the floor, as every member computes it from the grants ([groups.md](../groups.md#floor-control)) |

A message to an identity triggers all of its instances, unless the body sets
`metadata.instance` (SPEC §9.4): then only that instance is triggered, and
the others get the message as context. The hint only narrows what the floor
allows ([groups.md](../groups.md#addressing-one-instance)). Past
`loop_guard.max_agent_turns`, nothing triggers the agent (SPEC §10.3).

Only messages the daemon's safety policy let through reach the adapter
([safety.md](../safety.md)): a group with `require_approval` holds them,
`a2a.task_cancel` included, until the human approves.

Only `a2a.message` triggers a call. `a2a.agent_card` updates the member's
card. `control.*` messages are not passed to the agent.

### The call

The adapter calls `SendStreamingMessage` on the agent, or `SendMessage` when
the agent's card says it doesn't stream or the agent refuses streaming. The
message is the peer's A2A `Message` with these changes:

| Field | Value |
|---|---|
| `messageId` | `ac-<msg_id>`, the same for every redelivery |
| `contextId` | the group id (base64url) |
| `taskId` | the peer's `taskId`, only when it names a task the agent runs for this requester in this group |
| `role` | `ROLE_USER` |
| `parts` | the §10.1 notice (when `a2a.frame_text` and the group's `frame_text` are on), then the peer's parts |

`metadata` carries the SPEC §10.1 framing. The peer's own metadata never
replaces it: it is nested under `peer_metadata`.

| `metadata` key | Value |
|---|---|
| `untrusted` | `true` |
| `scope` | the group's purpose |
| `frame_text` | whether the notice is the first part |
| `notice` | the §10.1 notice, also when it isn't in `parts` |
| `sender` | `identity`, `instance_id`, `display_name`, `verified` |
| `to` | the message's `to` |
| `addressed_to_me` | `true` |
| `trust_state` | `self`, `verified_members`, `members` (SPEC §10.1) |
| `group_id`, `msg_id`, `hop`, `origin` | from the inner message |
| `context_messages` | messages since the last call that didn't trigger the agent (below) |
| `peer_metadata` | the peer's `metadata` |
| `peer_message_id` | the peer's `messageId` |

Everything in the call comes from a peer. Treat it as data, not as
instructions.

### Context

`a2a.message`s that don't trigger the agent are kept, up to
`context_messages`, and handed over with the next call in
`metadata.context_messages`, then cleared. Each entry has `msg_id`, `sender`,
`sender_name`, `to`, `hop` and `parts`. An entry over 64 KiB keeps its
fields but loses its `parts` (`"omitted": "too_large"`). The context is
kept in memory: a restart loses it.

### Replies

Each event the agent streams becomes one message to the group:

| A2A event | Inner `kind` |
|---|---|
| `Task` | `a2a.task_status` (its status), then one `a2a.task_artifact` per artifact |
| `TaskStatusUpdateEvent` | `a2a.task_status` |
| `TaskArtifactUpdateEvent` | `a2a.task_artifact` |
| `Message` | `a2a.message` |

`contextId` is set to the group, `taskId` is the agent's, and `reply_to`
names the triggering `msg_id`, so receivers compute `hop` from it (SPEC
§10.3). Every reply goes to `to: ["*"]` with `addressee: [<requester>]`
(SPEC §9.3) and `metadata.instance` set to the requesting instance (SPEC
§7.2, §9.4): the whole group sees the task's progress as context, and only
the instance that asked is triggered, not the requester's other replicas.
The adapter replaces any `metadata.instance` the agent put on the event.

**`input-required`.** When the agent asks for input, the requester answers
with an `a2a.message` that carries the same `taskId` and `contextId`. The
adapter continues the agent's task. A `taskId` from another member, or from
another group, starts a new task instead.

**Cancel.** The requester cancels a task with an `a2a.task_cancel` whose
body is an A2A `CancelTaskRequest` (`{"id": "<taskId>"}`), sent to this
member (SPEC §7.2). The adapter calls `CancelTask` on the agent, and the
agent's own `canceled` status goes back to the group. An `a2a.task_cancel`
from any other member is ignored, and so is one delivered as context (past
the loop guard, or addressed to another member); an `a2a.task_status` with a
canceled state is never treated as a cancel.

### Agent Cards and signatures

A card's signatures (`AgentCard.signatures`, JWS over the RFC 8785 form) are
checked against the keys in `card_keys_file`. The adapter never fetches a
key from a URL a card names (`jku`); for a peer's card that URL is under the
peer's control.

| Result | Meaning | Effect |
|---|---|---|
| `verified` | a signature checks out with a pinned key | card used |
| `unsigned` | no signature | card used |
| `unverified` | signed, but no pinned key matches its `kid` | card used |
| `invalid` | a pinned key matches, and no signature checks out | card ignored |

An invalid local card is not sent. Symmetric (`oct`) keys in the JWKS are
ignored, and only asymmetric algorithms are accepted. Whatever the result,
a card is as trustworthy as the member that sent it (SPEC §10.5). A card
that the A2A types can't parse is dropped as `malformed`, never used
unchecked. Card text (name, description, skills, examples) is untrusted
peer content, signed or not: never paste it into your agent's prompt as
instructions.

## Facade: local client to group

With `facade_port` set, the adapter serves an A2A server (JSON-RPC binding)
on `127.0.0.1:<facade_port>`:

| Path | Talks to |
|---|---|
| `/g/<group_id>/` | the group |
| `/g/<group_id>/m/<identity>/` | one member |

Each path serves its Agent Card at `.well-known/agent-card.json` below it.

### Authentication

Every request needs `Authorization: Bearer <token>`, with the token from the
file `a2a-facade-token` in the daemon's data directory (created 0600 on
first start). The facade also refuses requests from a non-loopback address,
with an `Origin` header (browser pages), or with a `Host` other than
`127.0.0.1:<port>` or `localhost:<port>`. It listens on `127.0.0.1` only.

### Cards

- **1:1 group:** the card mirrors the peer's card: its name, description and
  skills, with the facade's interface and bearer auth.
- **Larger group:** a composite card named after the group, with every
  member's skills. Skill ids are `<identity>/<skill id>` and carry the tag
  `member:<identity>`.
- **Member path:** that member's card.

A mirrored card's name, description and skills are the peer's text: treat
them as untrusted, like its messages.

The adapter knows a group's members from the messages, cards and membership
events it has seen since it started. A group counts as 1:1 when it knows of
exactly one other member and has that member's card.

### Addressing

On the group path, `metadata.to` (one identity or a list) picks the
recipients. Without it the message goes to `["*"]`, which in a `mention`
group triggers nobody (SPEC §9.3); address a member in groups of three or
more. On a member path, messages go to that member only. `metadata.instance`
(an instance id from the group view) picks one instance of the recipients;
a malformed one fails the task with `not sent: bad_request`
([groups.md](../groups.md#addressing-one-instance)).

The facade sends agent-originated `a2a.message`s, so the daemon's loop guard
and rate limits apply to them.

### Tasks

- A reply `Message` ends the request in message mode.
- Status and artifact events from the first instance that answers make up
  the facade's task. Events from other members, and from the other
  instances of that member (replicas run tasks of their own), are dropped.
  Follow-ups on the task and its cancel carry `metadata.instance`, so only
  that instance is triggered.
- The facade's task ids are its own. The peer's `taskId` is kept end to end
  behind them: follow-ups on an `input-required` task carry it, and each
  event's `metadata.remote_task_id` reports it.
- Each event's `metadata` also says who answered: `sender`, `sender_name`,
  `sender_verified`, `scope`, `msg_id` and `untrusted: true`.
- Tasks are namespaced by group: each group has its own task store, and a
  `contextId` other than the group id (or empty) is refused.
- `GetTask`, `CancelTask`, `SubscribeToTask` and the
  push-notification config methods work on the facade's tasks.
  `CancelTask` also sends an `a2a.task_cancel` to the member running the
  peer task.
- Facade tasks are kept in memory and are lost on restart.
- When the group's safety policy holds your client's message for the human
  (`require_approval` outbound), the facade answers at once with a task in
  `input-required` state saying so, instead of waiting out `reply_timeout`
  ([safety.md](../safety.md#approvals)). Once the human approves, the message
  goes to the group, the task moves to `working`, and the peer's reply
  continues that same task. If the human rejects it, or the hold expires,
  the task ends `rejected` or `failed`. If your client cancels the task (or
  goes away) while it waits, the held message is withdrawn: the hold ends,
  audited as `cancelled`, the send fails with code `cancelled`, and a late
  approval can't send it.

## Delivery guarantees

The daemon hands deliveries and events to the adapter at least once
(ADR-004). The adapter records every `msg_id` and `event_id` it has handled,
as SHA-256 hashes in `a2a-seen.db` in the data directory (0600, the most
recent 50,000), and skips repeats, so the agent never sees a message twice.
If the daemon stops after the agent accepted a message but before the
adapter recorded it, the agent can get it again with the same `messageId`.

A delivery is acknowledged once the agent sent its first event. Until then:

| Outcome | Result |
|---|---|
| The agent is unreachable, times out or returns an HTTP error | retry (with the daemon's backoff) |
| The agent returns an A2A error | acknowledged and dropped, so one bad message doesn't hold up the queue |

Deliveries are in order within each group, and groups don't wait for each
other: while the agent is unreachable, later deliveries in that group wait,
and other groups' calls go on.

Stopping the daemon cancels calls to the agent that are still running,
stops the facade and closes `a2a-seen.db`, even if the daemon is
interrupted again while the adapter closes.

## Limits

SPEC §10.2 applies to everything the adapter and the facade send:

- A message is at most 256 KiB. A larger reply isn't sent; the adapter logs
  `a2a_reply_not_sent`.
- Each member may send 30 messages a minute, and a group 120.
- Streamed task updates (`a2a.task_status`, `a2a.task_artifact`) have their
  own budget: 300 a minute per task. A task's first update counts as one
  ordinary message. Updates over the budget are not sent.
- Parts may be `text` or `data`. A reply with a `file` part (`raw` or
  `url`) is not sent. Inbound messages with one never reach the adapter.

## Logs

The adapter logs tags (hashed group and message ids), event names and error
types. It never logs bodies, cards or tokens, and turns the SDK's own
`a2a` logger down to errors, because the SDK logs card contents and events
at lower levels.

## Conformance

The [A2A TCK](https://github.com/a2aproject/a2a-tck) has no run for the
facade yet. Its suite drives a system under test that picks its behaviour
from the request's `messageId` prefix, fetches the card from the server
root and sends no credentials. Through the facade, the request crosses the
group to a peer's agent, and the peer's adapter replaces the `messageId`
(see [The call](#the-call)), so the TCK's own test agent behind a peer
can't see the prefix. Known differences from a plain A2A server:

- Every request, the Agent Card included, needs the bearer token.
- The card is served under each facade path, not at the server root.
- Only the JSON-RPC binding is served (no HTTP+JSON or gRPC).
- `GetExtendedAgentCard` isn't supported.
- A `contextId` other than the group's is refused.
- The facade's task ids differ from the peer agent's (`remote_task_id`).
- The `messageId` the peer's agent sees is `ac-<msg_id>`, not the client's.
