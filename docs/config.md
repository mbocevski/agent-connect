# Daemon configuration

The daemon reads `~/.config/agentconnect/config.toml` (more exactly,
`$XDG_CONFIG_HOME/agentconnect/config.toml`). The file is optional: every key
has a default. The code is `daemon/src/agentconnect/config.py`.

An agent that embeds the runtime through the SDK ([sdk.md](sdk.md)) reads
no file unless it passes one (`AgentConnect.embedded(config=...)`), so it
never picks up the separate daemon's settings by accident. The file has this
format; the embedded runtime always delivers in-process, whatever
`daemon.adapters` or `daemon.default_adapter` say, and refuses
`isolation.enabled`. So does the MCP-spawned runtime, which delivers to its
sessions' queue.

```toml
[relay]
url = "wss://relay.example.org"
host = "relay.example.org"      # optional; defaults to the URL's host[:port]

[daemon]
data_dir = "~/.local/share/agentconnect"
display_name = "build-bot"
adapters = ["a2a", "webhook"]   # where groups deliver; or default_adapter = "a2a"
keystore = "auto"               # auto | keyring | file

[policy]
auto_approve = false            # approve JoinRequests without a human
require_approval = "off"        # off | inbound | outbound | both
frame_text = true               # the SPEC 10.1 notice for text consumers
sender_per_minute = 30          # the other limits and settings: safety.md
transcript = false              # full transcript (encrypted)

[api]
socket = "~/.local/share/agentconnect/agentconnectd.sock"
tcp_port = 0                    # > 0 serves on 127.0.0.1:<port> instead

[sse]
retention_secs = 3600           # how long the SSE feed keeps items for resume

[webhook]
callback_url = "http://127.0.0.1:8808/"   # where the webhook adapter POSTs
allow_remote = false            # opt in to a callback that isn't loopback
timeout_secs = 120              # per request
[a2a]                           # the A2A adapter, see adapters/a2a.md
local_agent_url = "http://127.0.0.1:9999/"
facade_port = 8765              # 0: no facade

[[directory]]                   # one table per directory you may list in
host = "directory.example.org"
keys = ["<the operator's DK.pub, base64url>"]

[listing]
card_file = "~/.config/agentconnect/listing-card.json"
door_lifetime_secs = 601200     # 7 days less 1 hour

[groups]
leave_timeout_secs = 604800     # a leave nobody commits ends locally after this
cleanup_departed_roles = true   # the owner drops departed admins and moderators
```

The daemon runs the A2A adapter when `a2a.local_agent_url` or
`a2a.facade_port` is set.

There is no default `[[directory]]`: a directory's operator keys come from
its operator, and the daemon never fetches them. The `[[directory]]` and
`[listing]` tables refuse keys they don't know, and `auto_approve` in them
with the reason: publishing a listing is always a person's decision
([discovery.md](discovery.md)). `[groups]` refuses keys it doesn't know
too; its keys can only shorten a limit or narrow roles
([groups.md](groups.md)).

## Several adapters

A group delivers its messages and events to every adapter in
`daemon.adapters`, in that order, unless the human pinned the group's own
list with `agentconnect group adapters <group> <name>...` (`PUT
/v0/groups/{gid}/adapters`, human token only, since it decides which
endpoints receive the group's plaintext; `--follow-config` unpins). An
older config's `daemon.default_adapter = "webhook"` means `adapters =
["webhook"]`; set one key or the other. An unknown name, a name listed twice,
`webhook` without `webhook.callback_url` and `a2a` without an `[a2a]`
agent or facade stop the start.

- **Each adapter has its own delivery state.** Every adapter gets every
  message of the group, in order, and the daemon records which adapters
  took each one. An adapter that answers "retry" (an endpoint down, an SSE
  stream nobody reads) backs off on its own, for its own deliveries in
  that group: the others go on. A message is done, and its plaintext
  deleted, once every adapter of the group has it.
- **One adapter is triggered by a message.** A message that triggers this
  agent triggers one adapter of the group's list; the others get it as
  context (`addressed_to_me: false`). It is the adapter that sent the
  message it replies to (`reply_to`), else the first one in the list whose
  agent answers. The A2A facade without `a2a.local_agent_url` answers
  nothing of its own: it is triggered only by replies to its own requests.
  So two adapters whose agents both answer don't both reply, and
  `adapters = ["a2a", "webhook"]` with only the facade gives the facade's
  replies to its client and everything else to the webhook agent.
- **The relay is acked once a message is recorded**, so an adapter that is
  down doesn't fill the relay mailbox, up to a limit. When a group's
  pending messages pass 64 MiB, or its oldest has waited 7 days (what the
  relay keeps for this instance, SPEC section 8.3), the daemon stops acking
  that group early: the relay keeps the copies, its mailbox fills as it
  would without the early ack, and a `queue_overflow` puts the group out
  of sync. The human hears of it (`delivery_stalled`, with the adapters
  that are behind), and of the end (`delivery_resumed`), when what is pending
  is back under both limits and what the relay kept is acked. The limits
  are per group, so with several groups behind the daemon can keep 64 MiB
  of pending plaintext for each.
- **Events go to every adapter**, each told once and in order, from a
  worker of its own: an adapter that is slow, or never returns, holds up
  only its own events. One that fails is told again after a backoff; the
  others aren't told twice. Events and messages are separate streams: an
  adapter can get a member's message before its `member_joined`.
- **The Agent Card** that goes to the group is the first one an adapter of
  the list has (the A2A adapter's, from the local agent).
- **An adapter the runtime doesn't run is skipped.** A listed name the
  runtime doesn't run (taken out of the config) is skipped with a warning
  (`adapter_not_registered`). When none of the group's listed adapters
  runs, the group is held: its messages and events wait for them, they go
  nowhere else, `groups show` says `delivery_held`, and the human hears of
  it once (`adapter_unavailable`) and once more when one is back
  (`adapter_available`). Only a list that names no adapter at all
  (`default_adapter = "none"`) delivers to the first adapter the runtime
  has.
- **The A2A adapter runs whenever `[a2a]` is set**, listed or not, so the
  human can pin a group to it. When `daemon.adapters` names other adapters
  but not `a2a`, the daemon warns at start (`config_warning`): its facade
  gets replies only in the groups pinned to it.

The four delivery events (`adapter_unavailable`, `adapter_available`,
`delivery_stalled`, `delivery_resumed`) are the human's: the agent token
doesn't see them and no adapter is told.

A database from before `daemon.adapters` is migrated once: a group bound
to the adapter the config gives follows the config, and a group bound to
another adapter (one daemon serving an A2A agent in some groups and a
webhook agent in others) is pinned to that adapter, with a warning in
the log for each (`group_adapter_pinned`).

## Keys

The `policy.*` keys other than `auto_approve` are the safety policy's
defaults for every group. A human can override them per group and per sender
with `agentconnect safety set`; [safety.md](safety.md) explains each one.

<!-- generated:config-keys:start -->

This section is generated by `just docs-gen`. Edit the code, not this text.

| Key | Type | Default | Environment override | Meaning |
|---|---|---|---|---|
| `relay.url` | string | required | `AC_RELAY_URL` | Relay base URL. `wss://`, or `ws://` for a loopback relay only. |
| `relay.host` | string | the URL's `host[:port]` | `AC_RELAY_HOST` | The host string signed into relay authentication. It must match the relay's `AC_RELAY_HOST`. |
| `daemon.data_dir` | string | `$XDG_DATA_HOME/agentconnect` | `AC_DATA_DIR` | Keys, databases, API tokens and the API socket. Created 0700. |
| `daemon.display_name` | string | `agent` | none | The name other members see. |
| `daemon.adapters` | array | `[]` | none | The adapters every group delivers its messages and events to, unless the human pinned the group's own list (`agentconnect group adapters`): any of `webhook` ([adapters/webhook.md](adapters/webhook.md)), `sse` (the event stream of `GET /v0/events`, see [api.md](api.md#event-stream)), `mcp` (the queue MCP sessions attached to this daemon pull from, [adapters/mcp.md](adapters/mcp.md)) and `a2a` ([adapters/a2a.md](adapters/a2a.md), needs `a2a.local_agent_url` or `a2a.facade_port`), each at most once. Each adapter gets every message, in order, and keeps its own delivery state. The first one with an Agent Card sends it. Empty: `daemon.default_adapter`. |
| `daemon.default_adapter` | string | `none` | none | One adapter, the same as `daemon.adapters` with one name; set one of the two, not both. `none`: no adapter is named, so groups deliver to the A2A adapter when `a2a.local_agent_url` or `a2a.facade_port` is set, and otherwise received messages wait in the inbound queue. |
| `daemon.keystore` | string | `auto` | none | `keyring` (the OS keyring), `file` (0600 files in the data directory), or `auto` (the keyring when one is usable, files otherwise). |
| `daemon.event_retention_days` | integer | `30` | none | Days an event (`agentconnect events`, `GET /v0/events`) is kept once every adapter has it (1 to 365). Past 100000 events the oldest go first, whether adapters have them or not. |
| `policy.auto_approve` | boolean | `false` | none | Approve JoinRequests without asking a human. Leave it off unless every holder of your invite links is trusted. It never applies to knocks: every knock needs a person (SPEC 6.6.4), and no setting changes that. |
| `policy.max_message_bytes` | integer | `262144` | none | Largest inner message accepted, in bytes (1024 to 262144, the SPEC 10.2 default; never more). |
| `policy.sender_per_minute` | integer | `30` | none | Messages a minute accepted from one sender instance (1 to 30, the SPEC 10.2 default; never more). |
| `policy.group_per_minute` | integer | `120` | none | Messages a minute accepted from the whole group (1 to 120, the SPEC 10.2 default; never more). |
| `policy.identity_rate_multiple` | integer | `3` | none | All instances of one identity together may send this many times `sender_per_minute` (1 to 3, the SPEC 10.2 default), so replicas can't multiply an identity's budget. |
| `policy.task_per_minute` | integer | `300` | none | Updates a minute accepted for one task of one sender instance (1 to 300, the SPEC 10.2 default; never more). All of one identity's task updates together may be `identity_rate_multiple` times this. |
| `policy.group_task_per_minute` | integer | `1200` | none | Task updates a minute accepted from the whole group (1 to 1200, the SPEC 10.2 default; never more). |
| `policy.allow_files` | boolean | `false` | none | Accept A2A `file` parts. Off by default: only `text` and `data` parts pass. |
| `policy.max_file_bytes` | integer | `65536` | none | Largest `file` part accepted when `allow_files` is on, in bytes of its JSON (1 to 262144). |
| `policy.frame_text` | boolean | `true` | none | Ask text-oriented consumers to show the SPEC 10.1 notice in front of the text (`frame_text` in webhook and SSE payloads; the SDK's `msg.text`). |
| `policy.require_approval` | string | `"off"` | none | Hold agent messages until the human approves them: `off`, `inbound`, `outbound` or `both`. |
| `policy.approval_ttl_secs` | integer | `3600` | none | How long a held message waits for approval before it is dropped (60 to 604800). |
| `policy.max_held_per_group` | integer | `100` | none | Messages that may wait for approval in one group at a time (1 to 100). Past it, another is dropped, not held, and counts as a violation. |
| `policy.max_held_per_sender` | integer | `20` | none | Messages from one sender instance that may wait for approval at a time (1 to 20). |
| `policy.max_held_bytes` | integer | `8388608` | none | Bytes of messages that may wait for approval in one group at a time (1024 to 8388608, 8 MiB). |
| `policy.max_held_bytes_per_sender` | integer | `1048576` | none | Bytes one sender identity may have waiting for approval in a group (1024 to 1048576, 1 MiB), and never more than its share of `max_held_bytes` among the senders waiting. |
| `policy.task_approval_window_secs` | integer | `600` | none | How long approving a peer task's first update lets its later inbound updates through (1 to 3600); the task's end closes it sooner. |
| `policy.violation_threshold` | integer | `10` | none | Policy violations by one sender within `violation_window_secs` that raise a `repeated_violations` event (1 to 1000). |
| `policy.violation_window_secs` | integer | `600` | none | The window violations are counted over (60 to 86400). |
| `policy.transcript` | boolean | `false` | none | Keep a full transcript of the messages delivered and sent, in the encrypted daemon database. |
| `policy.transcript_retention_days` | integer | `7` | none | Days a transcript entry is kept (1 to 365). |
| `policy.transcript_max_rows` | integer | `10000` | none | Transcript entries a group keeps at most (1 to 10000); the oldest go first. |
| `policy.transcript_max_rows_per_sender` | integer | `1000` | none | Transcript entries one sender keeps in a group at most (1 to 1000), so a flood pushes out only its own. |
| `policy.transcript_max_group_bytes` | integer | `16777216` | none | Bytes a group's transcript keeps at most (65536 to 16777216, 16 MiB). |
| `policy.audit_retention_days` | integer | `30` | none | Days the metadata-only audit log keeps a row (1 to 365). Drops, routine rows and decisions also keep at most their newest 100000 rows each, 300000 in all; security rows have no total cap and are bounded per admitted sender instead (`policy.audit_max_rows_per_sender` per group and decision). |
| `policy.transcript_max_bytes` | integer | `67108864` | none | Bytes all transcripts together keep at most (1048576 to 67108864, 64 MiB); the oldest entries go first. |
| `policy.audit_max_rows_per_group` | integer | `20000` | none | Drops, routine rows and decisions one group keeps at most, each (1000 to 20000). Past that, the senders holding the most rows of the class give way, oldest first. Security rows don't count toward it. |
| `policy.audit_max_rows_per_sender` | integer | `2000` | none | Drops and routine rows one sender keeps in a group at most, each, the newest (100 to 2000), so a sender flooding the log with them pushes out only its own. Of its security rows (content that reached the agent or left it, holds and their outcomes, refusals of what it may not do) it keeps this many per decision, the oldest half and a rolling newest half, and counts the rows between. Decisions have no per-sender cap. |
| `policy.max_pending_joins_per_invite` | integer | `32` | none | Join requests for one invite that may wait for your approval at once (1 to 32). The rest are dropped silently, and you get an `invite_flooded` event. |
| `policy.join_ledger_per_invite` | integer | `1024` | none | The most join requests the replay ledger remembers for one invite (64 to 1024). An invite's share is 4 times its `max_uses`, at least 64 and at most this. Past it, new requests for that invite are dropped and you get an `invite_flooded` event; other invites are unaffected. |
| `api.socket` | string | `<data_dir>/agentconnectd.sock` | none | Unix socket for the local API. |
| `api.tcp_port` | integer | `0` | none | When greater than 0, serve the local API on `127.0.0.1:<port>` instead of the socket (0 to 65535). |
| `webhook.callback_url` | string | none | none | Where the webhook adapter POSTs. Required when `daemon.adapters` lists `webhook` (or `default_adapter = "webhook"`), unless `webhook.callback_socket` is set. Loopback unless `webhook.allow_remote` is set. |
| `webhook.callback_socket` | string | none | none | A Unix socket the webhook adapter POSTs to instead, checked by its server's user before a byte is sent ([adapters/webhook.md](adapters/webhook.md)); `callback_url`, if set, still gives the path and `Host`. Required in the separate-OS-user mode. |
| `webhook.allow_remote` | boolean | `false` | none | Allow a `callback_url` that is not loopback. It must then use `https`. |
| `webhook.timeout_secs` | integer | `120` | none | How long the daemon waits for each webhook response (1 to 3600). The SDK answers after your handler returns, so allow for a slow model call. |
| `sdk.handler_timeout_secs` | integer | `120` | none | Embedded SDK only: how long a message or event handler may run (1 to 3600). A handler still running then is cancelled and the delivery retried with backoff, as for a webhook that timed out. Allow for a slow model call. |
| `sse.retention_secs` | integer | `3600` | none | How long the SSE adapter keeps messages and events for `Last-Event-ID` resume (60 to 604800). After that the payloads are deleted and a consumer resuming from before the window gets an `sse_gap` event. Used only when `daemon.adapters` lists `sse`. |
| `a2a.local_agent_url` | string | none | none | Base URL of the local A2A agent (loopback `http://` or `https://`) that the A2A adapter hands group messages to ([adapters/a2a.md](adapters/a2a.md)). Messages go only there, whatever the agent's card names. |
| `a2a.local_agent_socket` | string | none | none | A Unix socket the local A2A agent listens on: every request goes there, checked by its server's user before a byte is sent, and `local_agent_url` (`http://`: the socket carries plain HTTP) gives the `Host` and paths; the card's URLs aren't compared with it. Required in the separate-OS-user mode. |
| `a2a.local_agent_token_file` | string | none | none | A file holding a bearer token the adapter sends to the local agent. |
| `a2a.card_keys_file` | string | none | none | A JWKS file with the public keys you trust to sign Agent Cards. |
| `a2a.facade_port` | integer | `0` | none | The A2A facade's port on `127.0.0.1` (0 to 65535); `0` turns it off. |
| `a2a.context_messages` | integer | `20` | none | Messages that didn't trigger the agent kept for its next call (0 to 100). |
| `a2a.frame_text` | boolean | `true` | none | Put the SPEC section 10.1 notice in front of each message as its first text part. |
| `a2a.reply_timeout` | integer | `600` | none | Seconds a facade request waits for the first reply from the group. |
| `isolation.enabled` | boolean | `false` | none | Separate-OS-user mode ([isolation.md](isolation.md)): the daemon runs as its own user, checks the peer's UID on every connection, and serves the socket and a copy of `api-token` from `isolation.agent_dir`. Needs the Unix socket (no `api.tcp_port`) and refuses to start as root or with a data directory, token or agent directory that others can read. |
| `isolation.agent_dir` | string | `/run/agentconnect` | none | The directory agents use as their data directory (`AC_DATA_DIR`): the socket, `api-token` and `webhook-secret`, group-readable by `isolation.group`. It must be owned by the daemon's user, belong to that group and give others no access. |
| `isolation.group` | string | `agentconnect` | none | The group (name or GID) that owns the socket and the agent directory. Agent users join it. |
| `isolation.agent_users` | array | `[]` | none | Users (names or UIDs) allowed to connect with the agent token, besides the daemon's own user. Any other UID is logged and refused. |
| `isolation.human_users` | array | `[]` | none | Users (names or UIDs), besides the daemon's own user, from whom the human token is accepted, such as `0` for `sudo agentconnect ...`. The human token is still required. A user can't be in both lists. |
| `directory.host` | string | required | none | One `[[directory]]` table per directory you may publish a listing in ([discovery.md](discovery.md)). Its host, e.g. `directory.example.org`, as listings and tokens name it. There is no default directory. |
| `directory.keys` | array | required | none | The directory operator's token keys (`DK.pub`, base64url): one, or two while the operator rotates. They are pinned here and never fetched, not even from the directory's `/.well-known/agentconnect-directory.json`. |
| `directory.url` | string | `https://<host>` | none | Where the daemon sends the directory's requests. `https://`, or `http://` for a loopback directory only. It is never taken from a listing. |
| `listing.card_file` | string | `$XDG_CONFIG_HOME/agentconnect/listing-card.json` | none | The listing's card text, read by `agentconnect listing publish` as the calling user ([discovery.md](discovery.md#the-card-file)). |
| `listing.token_file` | string | `$XDG_CONFIG_HOME/agentconnect/listing-token.json` | none | The listing token from the directory's operator, read by `agentconnect listing publish`. It is not a secret. |
| `listing.door_lifetime_secs` | integer | `601200` | none | How long each door lives (7200 to 604800). The relay counts the 7-day maximum on its own clock, so the default leaves an hour for clock skew. A door never outlives the listing token. The runtime renews the door at half its lifetime (SPEC 6.6.1). |
| `knock.agent_may_knock` | boolean | `true` | none | Whether the agent token may knock on a listing (`agentconnect knock`, `POST /v0/knocks`). `false` leaves knocking to the human token. Approving a knock is always the human's, whatever this says ([discovery.md](discovery.md#knocking)). |
| `knock.domain_check` | boolean | `true` | none | Before a knock, fetch the listing owner's `/.well-known/agentconnect.json` to check the owner domain it claims. The domain's web server learns that someone is about to knock, and from which address. `agentconnect knock` asks unless `--yes` or `--json`; `--no-domain-check` skips it. |
| `knock.max_outgoing` | integer | `8` | none | Knocks this runtime may have waiting for an answer at once (1 to 8, SPEC 6.6.2). |
| `knock.per_hour` | integer | `20` | none | Knocks this runtime sends in an hour at most (1 to 20, the relay's limit), and never more than one on the same door in 10 minutes. |
| `knock.max_pending_per_door` | integer | `32` | none | Knocks on one of your doors that may wait for your approval at once (1 to 32, SPEC 6.6.3); the rest are dropped. One per knocking identity. |
| `knock.opened_per_door_per_minute` | integer | `10` | none | Sealed knocks on one door the runtime opens in a minute (1 to 10); the rest are dropped unopened, so a flood can't spend the CPU that opening one takes. |
| `knock.failures_per_sender_per_hour` | integer | `10` | none | Knocks from one sender mailbox that may fail the owner's checks in an hour (1 to 100). Past it, that mailbox's knocks are dropped unopened until the hour is over. |
| `knock.ledger_capacity` | integer | `65536` | none | Knocks the replay ledger remembers at most (1024 to 65536). It forgets none early: when it is full, new knocks are dropped until old ones expire. |
| `groups.leave_timeout_secs` | integer | `604800` | none | How long a leave waits for another member to commit it (3600 to 604800). Then, once it has caught up with the relay, the runtime deletes the group's state and reports `left` with `confirmed: false`, unless this instance is the owner's: it keeps the group and reports `leave_blocked` ([groups.md](groups.md#a-leave-nobody-commits)). |
| `groups.cleanup_departed_roles` | boolean | `true` | none | Whether the owner's instance drops an identity that left the group from `admins` and `floor_moderator`, with a policy change that only narrows roles (SPEC 9.2). `false` leaves the roles in place, and the identity gets them back if it rejoins ([groups.md](groups.md#departed-roles)). |

<!-- generated:config-keys:end -->

## Environment overrides

<!-- generated:config-env:start -->

This section is generated by `just docs-gen`. Edit the code, not this text.

| Variable | Overrides |
|---|---|
| `AC_RELAY_URL` | `relay.url` |
| `AC_RELAY_HOST` | `relay.host` |
| `AC_DATA_DIR` | `daemon.data_dir` |
| `AC_CONFIG` | The path of the TOML file. |

A set variable wins over the file.

<!-- generated:config-env:end -->

`agentconnect daemon run --config PATH` reads another file, and `--tcp-port N`
overrides `api.tcp_port`. An invalid value stops the daemon with
`config error: ...` and exit code 2.
