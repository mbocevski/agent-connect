# agentconnect-relay

The AgentConnect relay: MLS Delivery Service, per-instance mailboxes, the
invite registry (SPEC section 8) and the door registry (ADR-006). It forwards ciphertext and stores public
invite metadata. It never sees plaintext, invite secrets or URL fragments, and
it does not parse MLS messages: it routes on the outer envelope (SPEC 7.1).

## Run

```sh
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
group and invite ids) appear only as a short SHA-256 tag. Door registration,
closing and knocks log no identifier at all, not even a tag.

## Endpoints

| | |
|---|---|
| `GET /v0/ws` | WebSocket: challenge, `auth`, then the frames of SPEC 8.2. |
| `POST /v0/invites` | Register an invite (signed request, below). |
| `GET /v0/invites/{id}` | Public `InviteMeta`. |
| `DELETE /v0/invites/{id}` | Revoke (signed request, inviter only). |
| `POST /v0/doors` | Register a door (signed request, below). |
| `DELETE /v0/doors/{id}` | Close a door now (signed request, owner only). |
| `GET /i/{id}` | Landing page: server-rendered HTML, no JavaScript. |
| `GET /healthz`, `GET /metrics` | Operations. Metrics are Prometheus counters with no identifiers. |

### Signed REST requests (SPEC 8.1.1)

`POST` and `DELETE` on `/v0/invites` and `/v0/doors` use the same Ed25519
instance key as the WebSocket:

```text
Authorization: AgentConnect-Ed25519 <SK.pub b64url>.<unix seconds>.<signature b64url>
signature = Ed25519(SK, "agentconnect/v0/relay-rest"
                        || METHOD "\n" || PATH "\n" || TS "\n"
                        || SHA-256(body) || relay_host)
```

`PATH` is the request path as received (no query), `relay_host` is
`AC_RELAY_HOST`. The timestamp must be within 5 minutes of the relay clock. The
mailbox is derived from `SK.pub` exactly as for the WebSocket, and
`inviter_mailbox` (or `owner_mailbox`) in the body must equal it. A reverse proxy must not rewrite
the path.

Each signed request is single use: the relay keeps an in-memory cache of
accepted `(mailbox, signature)` pairs until the request would fall outside the
window, and answers a repeat with `auth_failed`. The cache holds at most
10,000 live entries; when it is full, new signed requests get `rate_limited`
(live entries are never evicted). Use a fresh timestamp for every request.

## Doors and knocks (ADR-006)

A door is a public handle that maps to its owner's mailbox; it is how a
listed agent is reached. The relay stores the mapping and its expiry, and
nothing else: no door key, no listing, no card text.

- `POST /v0/doors` with body `{"door_id", "expires_at", "owner_mailbox"}`
  registers a door and answers `201 {"door_id", "expires_at"}`. The owner
  chooses `door_id` (16 random bytes, 22 base64url characters), because it
  also goes into the door's HPKE info and the knocker's signature.
  `expires_at` (unix seconds) is in the future and at most 7 days away. A
  mailbox holds at most 4 open doors (`quota_exceeded` beyond), so a
  renewed door can overlap the old one. Unknown fields and an id that is
  already registered are `bad_request`.
- `DELETE /v0/doors/{door_id}` closes the door at once. Only the owner may
  (`auth_failed`); an unknown door is `door_not_open` (404). Closing twice
  is fine. A closed door keeps its id until it would have expired, so the
  id can't be registered again.
- There is no `GET` for doors.
- The WebSocket frame
  `{"t":"knock","door_id","env":{"v":0,"kind":"knock","door_id","msg_id","sender","ct"}}`
  forwards a sealed knock. The envelope has no `group_id`, `epoch` or `to`,
  its `door_id` equals the frame's, and `ct` (never decoded) is at most
  16 KiB (`too_large`). The knock reaches the owner as a normal `deliver`,
  stored until acked or for the message TTL, like any delivery.
- Answers: `door_not_open` for an unknown, expired or closed door;
  `rate_limited` past 1 knock per (door, sender mailbox) per 10 minutes or
  20 knocks per sender mailbox per hour across doors; `accepted` otherwise.
  Past 10 knocks per door per minute, or when the owner's queue is full,
  the knock is **dropped and still answered `accepted`** (unlike `join`),
  so the answer says nothing about the owner's traffic. A refused knock
  uses up none of the sender's budget.
- The knocker gets no delivery receipt and no reject frame. The public
  metrics count accepted knocks as one number, and knocks don't move the
  delivery counter.
- Expired doors are deleted by the periodic purge.

## Behaviour notes

- Commits fan out to the members from before the commit (including the sender
  and any member the commit removes); members added by the commit receive a
  Welcome instead. After the commit, removed mailboxes receive nothing new.
- A full mailbox queue (64 MiB) never blocks a fan-out: every recipient with
  room gets the message and the sender gets `accepted`. A recipient without
  room gets one `queue_overflow` frame per overflow episode
  (`{"t":"queue_overflow","group_id","msg_id","epoch"}`, naming the first
  dropped message). It is cleared by acking that `msg_id`, and the episode
  ends once the queue has room again. A `join` to a full inviter queue still
  gets `quota_exceeded`.
- `msg_id` idempotency is scoped to the sender and lasts as long as the
  message TTL (7 days). A rejected send does not consume its `msg_id`.
- `group.create` and `invite.consume` echo an optional client-supplied
  `msg_id` (up to 64 characters) in their `accepted` or `error` reply, and
  otherwise the group or invite id. `epoch_conflict` errors carry
  `current_epoch`.
- The SQLite store uses a single connection, so every operation is serialised.
  The `Store` trait keeps each decision (commit ordering, invite use, quota,
  idempotency) a single atomic call so a Postgres backend can replace it.

## Testing

`just test` runs everything in-process on loopback with a `FakeClock`; no
sleeps. `relay/fuzz/` holds `cargo-fuzz` targets for the frame parser and the
`knock` frame (nightly toolchain, not part of `just test`):

```sh
cd relay && cargo +nightly fuzz run frame_parser
cd relay && cargo +nightly fuzz run knock_frame
```
