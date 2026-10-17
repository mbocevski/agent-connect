# agentconnect

The AgentConnect daemon (`agentconnectd`) and CLI (`agentconnect`). See the
repository [README](../README.md) and [SPEC.md](../SPEC.md).

```sh
agentconnect daemon run [--config PATH] [--tcp-port N]   # foreground, JSON logs on stderr
agentconnect status [--json]                             # reads the local API
```

The invite lifecycle (`group`, `invite`, `accept`, `groups`, `approvals`,
`verify`, `leave`, `send`, `events`) is documented in
[docs/cli.md](../docs/cli.md), with the `--json` schemas and exit codes.
`approvals approve`, `approvals reject` and `verify` use the human token:
**never give an agent the human token or let it run those commands for the
human.**

## What the daemon holds

- One identity and one instance, created on first start, in the OS keyring
  when one is usable and otherwise in 0600 key files (`keystore = "auto" |
  "keyring" | "file"`).
- The core's MLS state in `mls.sqlite3`, a SQLCipher database encrypted
  under a `db_key` from the same keystore.
- Its own `daemon.sqlite3`: groups, members (with the local *verified*
  flag), Agent Cards, out-of-sync flags, and the durable outbox and inbox.
  It is a SQLCipher database too, under a key the core derives from
  `db_key` (ADR-003). Plaintext stays only while it is needed: an outbox
  row keeps only its ids once the relay has answered it, and an inbox row
  drops its message once the adapter has accepted it.

The data directory (`~/.local/share/agentconnect`) is 0700 and every file in
it 0600. Configuration is `~/.config/agentconnect/config.toml`; see
[docs/config.md](../docs/config.md) for the keys and the `AC_*` overrides.

## Local control API

JSON over HTTP/1.1 on a Unix socket in the data directory, or on
`127.0.0.1:<port>`. Every request needs `Authorization: Bearer <token>`.
[docs/api.md](../docs/api.md) describes the transport, tokens, errors and
every route with its request and response shapes.

Two tokens live in the data directory: `api-token` (agent scope) and
`human-token` (human scope, also accepted for everything else). Approving a
join and marking a member verified are human decisions (SPEC §6.2, §11): an
agent that could approve its own joins, or mark the short code as compared,
would remove exactly the checks that catch a leaked link or a relay in the
middle. Give agent tooling only `api-token`. Both files belong to the same OS
user, so the split keeps the human capability out of agent integrations by
default; it is not a sandbox.

Invite secrets never leave the daemon: the URL is returned to the caller and
the relay only receives the public invite metadata.

## Adapters

`agentconnect.adapter.Adapter` is the interface for agent integrations:
`deliver(group, sender, to, inner) -> ack | retry`, `on_event(group, event)`,
`on_outbound(send)` and `capabilities()`. Every delivery carries the SPEC
§10.1 untrusted framing. A relay frame is acknowledged only after the core
processed it and the adapter accepted the resulting delivery.

Delivery is **at least once**: after a crash, `deliver` and `on_event` may
repeat a message or an event. Every delivery has a stable `msg_id` and every
event a stable `event_id`; deduplicate by them. Nothing is lost: an event is
recorded before the adapter hears of it and sent again on restart until
`on_event` returns (ADR-004).
`RecordingAdapter` is the in-memory adapter used by tests; the policy layer
plugs in through `PolicyHook` (pass-through by default).
