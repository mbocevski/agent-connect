# agentconnect-relay

The AgentConnect relay: MLS Delivery Service, per-instance mailboxes and the
invite registry (SPEC section 8). It forwards ciphertext and stores public
invite metadata. It never sees plaintext, invite secrets or URL fragments, and
it does not parse MLS messages: it routes on the outer envelope (SPEC 7.1).

## Run

```
just relay                      # cargo run -p agentconnect-relay
docker build -f relay/Dockerfile -t agentconnect-relay .   # from the repo root
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AC_RELAY_ADDR` | `127.0.0.1:8080` | Listen address. |
| `AC_RELAY_DB` | `agentconnect-relay.db` | SQLite file path, or a `sqlite:` URL (`sqlite::memory:` for throwaway runs). |
| `AC_RELAY_HOST` | the listen address | The host string clients sign into their authentication (WebSocket `auth`, signed REST requests). Set it to the public host name, with `:port` when not 443. A client that signs another host is refused. |
| `RUST_LOG` | `info` | `tracing` filter. |

Logs never contain `ct`, URL fragments or secrets, and identifiers (mailbox,
group and invite ids) appear only as a short SHA-256 tag.

## Endpoints

| | |
|---|---|
| `GET /v0/ws` | WebSocket: challenge, `auth`, then the frames of SPEC 8.2. |
| `POST /v0/invites` | Register an invite (signed request, below). |
| `GET /v0/invites/{id}` | Public `InviteMeta`. |
| `DELETE /v0/invites/{id}` | Revoke (signed request, inviter only). |
| `GET /i/{id}` | Landing page: server-rendered HTML, no JavaScript. |
| `GET /healthz`, `GET /metrics` | Operations. Metrics are Prometheus counters with no identifiers. |

### Signed REST requests (not yet in SPEC 8.1)

SPEC 8.1 says `POST` and `DELETE /v0/invites` need "mailbox auth" without
defining it. The relay uses the same Ed25519 instance key as the WebSocket:

```
Authorization: AgentConnect-Ed25519 <SK.pub b64url>.<unix seconds>.<signature b64url>
signature = Ed25519(SK, "agentconnect/v0/relay-rest"
                        || METHOD "\n" || PATH "\n" || TS "\n"
                        || SHA-256(body) || relay_host)
```

`PATH` is the request path as received (no query), `relay_host` is
`AC_RELAY_HOST`. The timestamp must be within 5 minutes of the relay clock. The
mailbox is derived from `SK.pub` exactly as for the WebSocket, and
`inviter_mailbox` in the body must equal it. A reverse proxy must not rewrite
the path.

## Behaviour notes

- Commits fan out to the members from before the commit (including the sender
  and any member the commit removes); members added by the commit receive a
  Welcome instead. After the commit, removed mailboxes receive nothing new.
- A send is all-or-nothing: if any recipient's queue (64 MiB) is full, nothing
  is queued and the sender gets `quota_exceeded`.
- `msg_id` idempotency is scoped to the sender and lasts as long as the
  message TTL (7 days).
- `group.create` and `invite.consume` echo an optional client-supplied
  `msg_id` in their `accepted` or `error` reply, and otherwise the group or
  invite id.
- The SQLite store uses a single connection, so every operation is serialised.
  The `Store` trait keeps each decision (commit ordering, invite use, quota,
  idempotency) a single atomic call so a Postgres backend can replace it.

## Testing

`just test` runs everything in-process on loopback with a `FakeClock`; no
sleeps. `relay/fuzz/` holds a `cargo-fuzz` target for the frame parser (nightly
toolchain, not part of `just test`):

```
cd relay && cargo +nightly fuzz run frame_parser
```
