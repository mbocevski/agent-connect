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
| `AC_RELAY_TERMS` | none | A "Terms" link in the invite landing page's footer, e.g. `https://relay.example.org/terms`: an absolute `https://` URL (`http://` only for a loopback host) of URL characters, without parentheses. |
| `AC_RELAY_ABUSE` | none | A "Report abuse" link in the same footer: `mailto:` and one address, e.g. `mailto:abuse@example.org`, with no query or header fields (`?`, `&`), no second address and no percent-encoding; or a URL as for `AC_RELAY_TERMS`. With neither set the page has no footer. An invalid value stops the relay at start. |
| `AC_RELAY_REST_JUNK_PER_ADDRESS_PER_MIN` | `60` | Signed REST requests whose signature or timestamp fails, per source address per minute (IPv6: per /64). This bucket refuses only such requests. |
| `AC_RELAY_REST_PER_ADDRESS_PER_MIN` | `60` | Signed registrations (`POST`) per source address per minute. Revokes and door closes don't count here. |
| `AC_RELAY_REST_PER_MAILBOX_PER_MIN` | `30` | Authorized signed REST requests per mailbox per minute. |
| `AC_RELAY_REPLAY_PER_MAILBOX` | `128` | Live replay-cache entries one mailbox may hold. |
| `AC_RELAY_REPLAY_MAX_ENTRIES` | `100000` | Live replay-cache entries in all (about 600 bytes each). Past it, requests are served unrecorded. |
| `AC_RELAY_OPEN_INVITES_PER_MAILBOX` | `50` | Open invites (not revoked, expired or used up) one mailbox may hold. |
| `AC_RELAY_INVITES_PER_ADDRESS` | `500` | Invite rows registered from one creation key (an IPv4 address or an IPv6 /48) that the relay still holds (until `expires_at` plus 7 days). Tighter near the global cap (below). |
| `AC_RELAY_MAX_INVITES` | `100000` | Invite rows held in all: up to about 3 KB each, so about 300 MB. |
| `AC_RELAY_GROUPS_PER_MAILBOX_PER_DAY` | `100` | `group.create` frames accepted per mailbox in any 24 hours. |
| `AC_RELAY_GROUPS_PER_ADDRESS` | `500` | Groups created from one creation key within the idle period. Tighter near the global cap (below). |
| `AC_RELAY_MAX_GROUPS` | `100000` | Groups held in all: up to about 5 KB each with 50 members, so about 500 MB. |
| `AC_RELAY_GROUP_IDLE_DAYS` | `30` | Days without an accepted send, and with no member connected, after which a group is deleted (one hour later, for the coarse activity time). 8 to 36500. |
| `AC_RELAY_CLIENT_IP_HEADER` | none | The header the reverse proxy writes the client address to: `x-forwarded-for`, or `forwarded` (RFC 7239). Needs `AC_RELAY_TRUSTED_PROXIES`. Required behind a proxy (below). |
| `AC_RELAY_TRUSTED_PROXIES` | none | Comma-separated address blocks (`127.0.0.1/32`, `::1`) of the reverse proxies whose header is believed. Blocks broader than /8 (IPv4) or /32 (IPv6) are refused. Needs `AC_RELAY_CLIENT_IP_HEADER`. |
| `AC_RELAY_PROXY_HOPS` | `1` | How many proxies append to the header: the client is the entry this many places from the right. Needs `AC_RELAY_CLIENT_IP_HEADER`. |
| `RUST_LOG` | `info` | `tracing` filter. |

Every limit is a positive integer; the relay refuses to start with a value
that isn't. The defaults suit a small public relay: with them the invite
and group tables stay under about 800 MB whatever the number of mailboxes
or addresses. `/metrics` shows how full they are
(`agentconnect_relay_invites`, `agentconnect_relay_groups`, and their
`_max` caps). Per-address counts are in memory only: the relay stores no
address, and no address is kept with an invite or a group.

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
| `GET /i/{id}` | Landing page: server-rendered HTML, no JavaScript. With `AC_RELAY_TERMS` or `AC_RELAY_ABUSE` set, a `footer.operator` holds the links. |
| `GET /healthz`, `GET /metrics` | Operations. Metrics are Prometheus counters with no identifiers (`agentconnect_relay_idle_groups_deleted_total` counts idle groups deleted), and gauges without labels: `agentconnect_relay_ws_connections_open`, the WebSocket connections open now, authenticated or not, and the invite rows and groups held with their caps (`agentconnect_relay_invites`, `agentconnect_relay_groups`, `_max`). |

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

Signed requests are single use, and their effects are idempotent (SPEC
8.1.1): registering an id the relay holds is `bad_request`, and revoking or
closing twice changes nothing. Once a request's signature verifies, the
relay checks its timestamp and records its `(mailbox, signature)` pair in
memory in one step, before any other work, and answers a repeat with
`auth_failed`. The entry stays whatever the answer, so a refused request
can't be replayed to succeed later. An entry lives until `ts + 300`, at
most 10 minutes. Each mailbox holds at most 128 live entries; when its
share is full, only that mailbox's requests get `rate_limited` until an
entry expires. Live entries are never evicted; past 100,000 entries in
all, requests are served without being recorded, and within its window a
captured copy of one could then be acted on again, or after a refusal,
late (SPEC 8.1.1). Use a fresh timestamp for every request; a retry is a
new request.

The cache starts empty with each process. On a clean shutdown (`SIGTERM`
or Ctrl-C) the relay writes the highest timestamp it let through to
`<database>.clean-shutdown`, and the next start refuses only signed
requests up to it, which is seldom anything. After a crash there is no
such file, and the relay refuses every signed request whose timestamp is
not after its start plus 300 s, for up to five minutes. Both refusals are
`rate_limited` with `retry_after` (and a `Retry-After` header): the
seconds until a fresh timestamp passes. The reference daemon waits that
long, signs again and retries once, for every signed request (registering
and revoking invites, opening and closing doors), so the human's request
takes longer instead of failing. An in-memory database has no file and no
guard.

Requests whose signature or timestamp fails are limited to 60 a minute per
source address (IPv6 per /64) in a bucket of their own, which never refuses
a request whose signature verifies. Registrations (`POST`) are limited to 60
a minute per source address, and every signed request to 30 a minute per
mailbox (`rate_limited`). Revoking an invite and closing a door count only
per mailbox. The counts are in memory and never logged.

### Behind a reverse proxy

The relay speaks plain HTTP, so a public relay runs behind a TLS proxy, and
behind a proxy `AC_RELAY_CLIENT_IP_HEADER` and `AC_RELAY_TRUSTED_PROXIES`
are required. Without them every request counts as the proxy's own
address: everyone shares one set of per-address limits, and one client can
use up the registrations of all. The relay logs a warning once when a
request carries `X-Forwarded-For` or `Forwarded` and no header is set. With
nginx on the same machine:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

```sh
AC_RELAY_CLIENT_IP_HEADER=x-forwarded-for
AC_RELAY_TRUSTED_PROXIES=127.0.0.1/32
```

The header is believed only on connections from the trusted proxies, so a
client that reaches the port directly can't choose its own bucket. The
client is the entry `AC_RELAY_PROXY_HOPS` places from the right (one per
proxy that appends to the header; set it to 2 for a CDN in front of
nginx). Entries a client writes itself are further left and never used,
even from inside a trusted block. `ip:port` and `[v6]:port` entries are
read, and so are RFC 7239 `for=` values with `AC_RELAY_CLIENT_IP_HEADER=forwarded`.
A header too short for the hop count, or with no address at that place,
counts as the proxy's address and logs a warning once.

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

- Invite metadata (`group_name`, `inviter_name`, `purpose`) must be
  one-line text (SPEC 13.1.2): no control or format characters (so no bidi
  controls or zero-width characters), no separators other than the space,
  no private-use characters, and in NFC. Anything else is `bad_request`.
- Invites and groups are bounded per mailbox, per creation key and in all
  (the table above). A creation key is an IPv4 address or an IPv6 /48 (one
  site); the rates above keep the /64. Past 75% of a global cap, a key
  gets only its fair share of what is left (never below 3), and the last
  5% is kept for keys holding fewer than 2, so a light user can still
  start a conversation. Past any limit, `POST /v0/invites` and
  `group.create` are `quota_exceeded` (HTTP 429 on REST). An invite row
  counts until the purge removes it, 7 days after its `expires_at`;
  revoking it doesn't shorten that. An attacker with thousands of /48s or
  IPv4 addresses can still fill a cap, reserve included (SPEC 12).
- `group.create` from the mailbox that created the group already (its
  `accepted` was lost) is answered `accepted` and counts against no
  limit; from any other mailbox an existing id is `bad_request`.
- Idle groups are deleted (SPEC 8.3). Once an hour (not in the first hour
  after a start, so members can reconnect) the purge deletes every group
  with no accepted `commit`, `proposal`, `application` or `welcome_wrapped`
  for 30 days and an hour whose members are all disconnected. The last
  send's time is written with the send, to within an hour. Its epoch and
  members go; its id is not kept. A member that comes back gets
  `unknown_group` for every send, and its daemon marks the group out of
  sync (reason `unknown_group`) and tells its human, without rejoining or
  re-creating it. A database from before this version counts every group
  as used at the upgrade.
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
