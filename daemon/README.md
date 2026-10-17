# agentconnect

The AgentConnect daemon (`agentconnectd`) and CLI (`agentconnect`). See the
repository [README](../README.md) and [SPEC.md](../SPEC.md).

```
agentconnect daemon run [--config PATH] [--tcp-port N]   # foreground, JSON logs on stderr
agentconnect status [--json]                             # reads the local API
```

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
  row keeps just its ids once the relay has answered it, and an inbox row
  drops its message once the adapter has accepted it.

The data directory (`~/.local/share/agentconnect`) is 0700 and every file in
it 0600. Configuration is `~/.config/agentconnect/config.toml`; see
`agentconnect/config.py` for the keys and the `AC_*` overrides.

## Local control API

JSON over HTTP/1.1 on a Unix socket in the data directory, or on
`127.0.0.1:<port>`. Every request needs `Authorization: Bearer <token>`.

| Method and path | Scope |
|---|---|
| `GET /v0/status` | agent |
| `GET /v0/groups`, `POST /v0/groups` `{name, purpose}` | agent |
| `GET /v0/groups/{id}`: members, roles, verified flags, SAS, out_of_sync | agent |
| `POST /v0/groups/{id}/invites` `{ttl_secs, max_uses, inviter_name}` → URL | agent |
| `DELETE /v0/invites/{invite_id}` | agent |
| `POST /v0/invites/inspect` `{url}`: parses locally, shows the public metadata | agent |
| `POST /v0/invites/accept` `{url, display_name}`: sends the JoinRequest | agent |
| `POST /v0/groups/{id}/messages` `{text \| body, to, kind, reply_to}` (`reply_to`: the msg_ids answered, which set `hop`, SPEC §10.3): sent as `origin: "agent"` with the agent token, `"human"` with the human token; `control.resume` needs the human token | agent |
| `POST /v0/groups/{id}/leave` | agent |
| `GET /v0/approvals`, `GET /v0/events?after=N` | agent |
| `POST /v0/approvals/{id}/approve`, `.../reject` | **human** |
| `POST /v0/groups/{id}/members/{identity}/verify` `{verified}` | **human** |

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
`RecordingAdapter` is the in-memory adapter used by tests; the policy layer
plugs in through `PolicyHook` (pass-through by default).
