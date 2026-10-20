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
| `AC_RELAY_NON_MEMBER_QUEUE_BYTES` | `16777216` (16 MiB) | Per-mailbox queue for traffic from non-members, kept apart from the 64 MiB queue for group traffic (below). |
| `AC_RELAY_SENDER_BUDGET_BYTES` | `134217728` (128 MiB) | Bytes of undelivered messages one sender may have stored, and half of it in one group. Each payload counts once, however many mailboxes it goes to, until the last of them acks it, is removed from the group, or it expires. |
| `AC_RELAY_STORAGE_HIGH_WATER_BYTES` | `4294967296` (4 GiB) | Storage high-water mark, in bytes of database pages in use. Set it below the free space of the database's volume, less the 64 MiB reserve for commits that add nobody and room for the WAL and a migration. |
| `AC_RELAY_METRICS_ADDR` | `127.0.0.1:9091` | The operator's listener: `/metrics` and `/healthz`. The public listener has no `/metrics`. In a container, set it to an address only your monitoring network reaches. Two relays on one host collide on the default port, and a relay that can't bind it exits at start: give each its own. |
| `RUST_LOG` | `info` | `tracing` filter for the relay's own logs (below). |

Every limit is a positive integer; the relay refuses to start with a value
that isn't. The defaults suit a small public relay: with them the invite
and group tables stay under about 800 MB whatever the number of mailboxes
or addresses. `/metrics` shows how full they are
(`agentconnect_relay_invites`, `agentconnect_relay_groups`, and their
`_max` caps). Per-address counts are in memory only: the relay stores no
address, and no address is kept with an invite or a group.

Connection limits (below), all in memory, none of them logged:

| Variable | Default | Meaning |
|---|---|---|
| `AC_RELAY_MAX_HTTP_CONNECTIONS` | `512` | TCP connections still in the HTTP phase (not WebSockets yet). At the limit a new one closes the oldest connection of the source holding the most; accepting never pauses. |
| `AC_RELAY_MAX_HTTP_CONNECTIONS_PER_SOURCE` | `8` | HTTP-phase connections one source may hold. Past it a new one is closed at once. A daemon makes one REST request at a time and holds its WebSocket outside this count, so 8 leaves room for a few daemons behind one address, and it takes 64 sources to reach the total. |
| `AC_RELAY_HEADER_TIMEOUT_SECS` | `10` | How long a client has to send a request's headers, also the next request's on a kept-alive connection. Then the connection is closed. |
| `AC_RELAY_REQUEST_TIMEOUT_SECS` | `30` | How long a request may take once its headers are in: reading the body and handling it. Then the answer is 408 and the connection closes. |
| `AC_RELAY_WRITE_TIMEOUT_SECS` | `30` | How long a write of an HTTP response may make no progress before the connection is dropped. |
| `AC_RELAY_MAX_BODY_BYTES` | `65536` | The largest request body (413 past it). |
| `AC_RELAY_SHUTDOWN_GRACE_SECS` | `10` | On SIGTERM or SIGINT, how long the relay waits for requests in flight and for queued knocks to be written before it exits. |
| `AC_RELAY_MAX_CONNECTIONS` | `1024` | Authenticated WebSocket connections. At the limit a connection that authenticates closes the oldest connection of the source holding the most (code 1013, `relay_full`); if that source is its own, it gets `rate_limited` and close code 1013 instead. |
| `AC_RELAY_MAX_UNAUTHENTICATED` | `128` | WebSocket connections waiting to authenticate, in a pool of their own. Past it an upgrade gets HTTP 503. |
| `AC_RELAY_MAX_CONNECTIONS_PER_SOURCE` | `32` | WebSocket connections one source may hold, authenticated or not. Past it an upgrade gets HTTP 503. |
| `AC_RELAY_MAX_CONNECTIONS_PER_MAILBOX` | `4` | Authenticated connections per mailbox. A new one past it closes that mailbox's oldest connection (code 1000, `replaced`): the newest is the one known to be alive. |
| `AC_RELAY_AUTH_TIMEOUT_SECS` | `5` | How long a client has to answer the challenge. |
| `AC_RELAY_SEND_TIMEOUT_SECS` | `30` | How long one send to a WebSocket client may take. A client that stops reading is dropped after it. |
| `AC_RELAY_PING_INTERVAL_SECS` | `30` | How often the relay pings each WebSocket client. |
| `AC_RELAY_IDLE_TIMEOUT_SECS` | `90` | How long a WebSocket client may send no whole message and answer no ping before it is closed (code 1001). Pongs nobody asked for don't count. Longer than the ping interval. |
| `AC_RELAY_MIN_UPLOAD_BYTES_PER_SEC` | `4096` | While a client sends a message, the slowest it may go, measured over each idle timeout. A message must also be done within the idle timeout plus the frame limit at this rate. |
| `AC_RELAY_READ_BUFFER_BYTES` | `134217728` (128 MiB) | Relay-wide bytes read from WebSocket clients and not yet handed on as whole messages. Past it connections are closed (code 1009), from the source holding the most first and its largest connection first. At least 8 MiB. |
| `AC_RELAY_DRAIN_BATCH_BYTES` | `4194304` (4 MiB) | Most bytes of queued envelopes loaded per batch when sending a mailbox's queue; at least one message always is. At least 2 MiB (the frame limit). |
| `AC_RELAY_FRAMES_PER_SEC` | `100` | Sustained client frames per second, per connection, after authentication. |
| `AC_RELAY_FRAME_BURST` | `200` | Frames a connection may send at once above that rate. |

### Logging

Logs never contain `ct`, URL fragments, secrets or client addresses.
Identifiers (group, sender and invite ids) appear only as a short tag: the
first 4 bytes of HMAC-SHA256 under a key drawn at random when the process
starts and never stored. Tags let you follow one group through a run's logs,
but they differ after a restart and can't be computed from an id. Connection
lines (`connected`, `disconnected`) carry no tag, and door registration,
closing and knocks log no identifier at all.

`RUST_LOG` selects what the relay's own code (`agentconnect_relay`,
`agentconnect_core`) logs. Every other crate is held at `warn` and above,
whatever `RUST_LOG` says: at `trace`, `tungstenite` would log whole
WebSocket frames, `ct` included, and the HTTP stack client addresses. A
`RUST_LOG` that names only other crates (`tungstenite=trace`) turns the
relay's own lines off, `relay listening` included, since that is how the
filter syntax works; add `info` to keep them (`info,tungstenite=trace`).

### Connection limits

A source is the client's IPv4 address or its IPv6 /64. The relay keeps only
an opaque per-process key for it, never the address, and only in memory.

**Behind a reverse proxy, set the client address header** ("Behind a
reverse proxy", below). Without it every client counts as one source, the
proxy's address, and the per-source limits apply to all clients together.
With it, the WebSocket limits count the address the proxy reports, grouped
as the per-address rates are. The HTTP-phase limits can't: a connection is
counted before its headers are read, so by its TCP peer, and a trusted
proxy has no per-source share there, only the total.

- **HTTP phase.** Every stage has a deadline: the headers, the request (body
  and handling), and each write of the answer. One source holds at most its
  share of the HTTP slots, and at the total a new connection closes the
  oldest connection of the source holding the most rather than wait, so
  connections that stall after their headers, or pipeline requests and never
  read the answers, can't keep everyone else out, from one source or from
  many. An idle kept-alive connection is closed at the header timeout; a
  reverse proxy's upstream keep-alive should be shorter than that, or it may
  reuse a connection the relay is closing.
- **WebSockets.** Sockets that haven't authenticated wait in their own pool
  and go at the auth deadline. Authenticated connections are capped per
  source, and at the total a newcomer takes the place of the oldest
  connection of the source holding the most, so free mailboxes from a few
  sources can't take every slot.
- **Liveness.** The relay pings every connection. Only a whole message or
  the answer to the relay's own ping counts as activity; while a client is
  in the middle of a message, the bytes must keep arriving at the minimum
  upload rate instead. A daemon on a slow link uploading a large message is
  not closed as idle, and one that sends the first fragment of a message
  and then only pongs is closed at the next check.
- **Frames.** Client frames pass two token buckets per connection, each at
  `AC_RELAY_FRAMES_PER_SEC` with `AC_RELAY_FRAME_BURST`: one for acks and
  one for everything else, control frames included. The size limit and the
  rate are checked before a frame is parsed. A frame over the rate is
  answered with `{"t": "error", "code": "rate_limited", "detail": "frame
  rate exceeded"}`, carrying the frame's `msg_id` when it has one, and is
  not processed. An ack over the rate is never refused, since a lost ack
  would leave a delivered message queued: the relay waits for its token
  instead, which slows the client down. Pings over the rate close the
  connection (1008).
- **Memory.** A client that stops reading holds at most one batch of its
  queue (`AC_RELAY_DRAIN_BATCH_BYTES`, or one message if larger) and one
  write buffer (the largest message plus 128 KiB) until its send times out;
  a connection that is replaced or closed drops its batch before its close
  frame goes out. That is about 6 MiB per authenticated connection with the
  defaults, so about 6 GiB at the 1024 cap. On the read side,
  `AC_RELAY_READ_BUFFER_BYTES` bounds the bytes counted across connections;
  in memory that is up to about twice as much (measured: 32 connections
  holding 2 MiB unfinished messages each, 67 MiB counted, grew the relay's
  RSS by about 120 MiB), so about 256 MiB with the defaults. Lower the
  connection caps on a smaller host.
- **File descriptors.** The defaults allow about 512 HTTP and 1152
  WebSocket connections, plus the store and the listeners: about 1700
  descriptors. Set `LimitNOFILE=` (systemd) or `--ulimit nofile=` (docker)
  to at least 4096; under the common soft limit of 1024 the relay runs out
  of descriptors before it reaches its caps, and logs `accept failed`.
- **Knocks.** One source holds at most 64 of the knock queue's 1024 places
  and one door at most 16; past either, a knock is dropped behind its
  `accepted`, as for a busy door.
- **What remains.** These limits share the relay out between sources; they
  don't make it unlimited. An attacker with many addresses (IPv6 /64s are
  cheap) can still fill the total caps, and while it keeps doing so honest
  clients compete with it for slots. Deploy a public relay behind a proxy
  or provider with connection-level DDoS protection.
- **Shutdown.** On SIGTERM or SIGINT the relay stops accepting, closes
  WebSocket sessions with 1001 `shutting_down`, writes the knocks it has
  answered and not written yet, and waits for HTTP requests in flight for
  at most `AC_RELAY_SHUTDOWN_GRACE_SECS`.

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
| `GET /healthz` | Health. Also on the operator's listener, with `GET /metrics`: Prometheus metrics with no identifiers and no addresses (below). The public listener has no `/metrics`. |

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
address: everyone shares one set of per-address limits and one source's
share of the WebSocket connections, and one client can use up the
registrations of all. The relay logs a warning once when a
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

### Metrics

`/metrics` is served only on the operator's listener (`AC_RELAY_METRICS_ADDR`,
loopback by default). Every metric is named `agentconnect_relay_*` and
carries no mailbox, group, invite or door id and no address. The only labels
are fixed values. No metric moves differently for a forwarded knock and a
dropped one (SPEC 8.3): knock deliveries stay out of the byte counters, and
acks, which an online owner sends for each knock it receives, are not
counted as frames.

| Metric | Type | Meaning |
|---|---|---|
| `connections_total` | counter | WebSocket connections opened. |
| `auth_failures_total` | counter | Failed WebSocket authentications, timeouts included. |
| `frames_total` | counter | Client frames handled, acks not included. |
| `accepted_total`, `duplicates_total`, `deliveries_total`, `queue_overflows_total`, `commits_total`, `joins_forwarded_total`, `invites_created_total`, `invites_consumed_total`, `doors_registered_total`, `doors_closed_total`, `knocks_accepted_total` | counter | Delivery Service events. Forwarded and dropped knocks are one number. |
| `errors_total{code}` | counter | Errors returned, by SPEC 8.4 code. |
| `idle_groups_deleted_total` | counter | Idle groups deleted (SPEC 8.3, "Idle groups"). |
| `invites`, `invites_max`, `groups`, `groups_max` | gauge | Invite rows and groups held, and their caps. |
| `ws_connections_open` | gauge | WebSocket connections open now, authenticated or not. |
| `ws_connections_unauthenticated` | gauge | WebSocket connections open now that haven't authenticated. |
| `http_connections_open` | gauge | TCP connections open now that are not WebSockets, on both listeners. |
| `connections_evicted_total{cap}` | counter | Connections closed at a total cap to admit one from another source: `http` or `ws`. |
| `connections_refused_total{reason}` | counter | Connections refused at a cap: `total`, `unauthenticated`, `source` (WebSocket) or `http_source`. |
| `connections_replaced_total` | counter | Connections closed because a newer one for the same mailbox passed the per-mailbox cap. |
| `connections_shed_total` | counter | Connections closed because the read budget was exceeded. |
| `connection_timeouts_total{kind}` | counter | Connections closed by a deadline: `header`, `request`, `auth`, `idle`, `upload` (a message arriving too slowly) or `send`. |
| `frames_rate_limited_total` | counter | Client frames over the frame rate: refused, or delayed for acks. |
| `read_bytes_held` | gauge | Bytes read from WebSocket clients and not yet handed on as whole messages. |
| `drain_bytes_total` | counter | Bytes of queued messages other than knocks sent to connections, on reconnect and live. |
| `drain_bytes_loaded` | gauge | Bytes of queued messages other than knocks loaded into memory for sending now. |
| `storage_bytes` | gauge | Bytes of database pages in use, as of the last purge (every minute). It counts stored knocks too, as one total with everything else. |
| `storage_high_water_bytes` | gauge | The storage high-water mark (`AC_RELAY_STORAGE_HIGH_WATER_BYTES`). |
| `storage_full` | gauge | 1 while new messages are refused with `storage_full`, else 0. |

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
- An accepted knock, forwarded or dropped, goes to a bounded queue (1024
  knocks, at most 64 from one source and 16 for one door; past any of them
  a knock is dropped behind its `accepted`, like one to a busy door). A single worker writes the queue every 250 ms, so neither the
  answer nor the store's load right after it depends on whether the knock
  was forwarded. What remains: the worker's write at its next tick takes
  store time only for a forwarded knock, and a knocker that keeps measuring
  the store's latency across that tick can tell (with a 60,000-message owner
  queue, about 46 ms against 7 ms). A knock answered `accepted` is held in
  memory until that tick, so a crash can lose it; `accepted` for a knock
  was never a delivery promise.
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
- A mailbox's queue has two parts. Group traffic of a group the mailbox has
  sent in goes to a 64 MiB part. Everything from non-members goes to a
  separate part (`AC_RELAY_NON_MEMBER_QUEUE_BYTES`): Welcomes, join
  requests, knocks, and the traffic of a group the mailbox was added to
  but hasn't sent in yet (the relay can't tell a real joiner from a
  mailbox named in a stranger's routing hints until it sends; the daemon
  sends `control.capabilities` right after joining, whatever its
  adapters, so this lasts moments). Within each part, one group holds at
  most half (join requests and knocks together count as one group). So a
  stranger who knows a mailbox id can fill half of the non-member part,
  and a co-member half of the group part, never the rest; two hostile
  groups can fill a part between them, and then every group that loses
  messages gets its own marker (below).
- A full queue part never blocks a fan-out of group traffic: every
  recipient with room gets the message and the sender gets `accepted`. A
  recipient without room gets one `queue_overflow` frame per overflow
  episode, and an episode is per (mailbox, part, group), so every group
  that loses messages is told
  (`{"t":"queue_overflow","group_id","msg_id","epoch"}`, naming the first
  dropped message). It is cleared by acking that `msg_id`, and the episode
  ends once the group's share has room again. Markers may exceed a part's
  cap by 256 KiB (about 1,700 of them); a drop past that goes unmarked. A
  `join` to a full inviter queue gets `quota_exceeded`, and so does a
  Welcome: it is queued for all of its recipients or none, and the sender
  tries again later.
- A Welcome goes only to mailboxes that an accepted commit of its sender
  added (`routing.add`) and that haven't had their Welcome: one Welcome per
  Add, within the message TTL, and none once the mailbox is removed again.
  Anything else is `bad_request`. A Welcome's `ct` is at most 256 KiB
  decoded and a `join_request`'s at most 16 KiB (`too_large`). The largest
  Welcome a group sends, for its fiftieth member once every member has
  committed an update path (the full ratchet tree), is about 147 KB; a
  JoinRequest is about 4.2 KB. A nightly test checks both.
- Each payload is stored once and every recipient's queue row refers to
  it; each recipient's queue is still charged its full size. Past its
  budget (`AC_RELAY_SENDER_BUDGET_BYTES`, in all, and half of it in one
  group) a sender's messages are refused with `over_budget` until
  recipients ack, are removed, or the messages expire. When a commit
  removes a member, what is still queued for it in that group goes (the
  removing commit excepted), with its charges. Knocks are not charged to
  their sender, so the budget can't tell a knocker when the owner acked
  its knock; joins and group traffic are, so a sender can learn by
  probing its budget when its slowest recipient fetched a message.
- At or above the storage high-water mark, every new message is refused
  with `storage_full` ("relay storage is above its high-water mark").
  Acks, the purge, invite and door requests and `group.create` go on, and
  a knock is still answered `accepted` and dropped. A commit that adds
  nobody (an Update, a removal, a policy change) with a `ct` of at most
  128 KiB may still use a 64 MiB reserve above the mark, charged to its
  sender's budget: a group can shed a member and renew its keys while the
  relay is full. The largest such commit measured, an Update in a sparse
  50-member tree, is about 67 KB. Adds and messages wait, and once the
  reserve is used up so do Updates, which delays post-compromise security
  for as long as the relay stays full. The daemon treats `storage_full`
  and `over_budget` as "not now": it keeps the message or commit queued
  and sends it again after a backoff (`storage_full` pauses every group,
  `over_budget` only the group refused), however long it takes.
- The mark is one switch for the whole relay, and mailboxes are free:
  about 32 throwaway mailboxes at the default budget reach a 4 GiB mark.
  Put connection and request limits per source address, and DDoS
  protection, in front of a public relay, and size the mark so the
  reserve, the WAL and a migration fit the free space.
- `msg_id` idempotency is scoped to the sender and lasts as long as the
  message TTL (7 days). A rejected send does not consume its `msg_id`.
- `group.create` and `invite.consume` echo an optional client-supplied
  `msg_id` (up to 64 characters) in their `accepted` or `error` reply, and
  otherwise the group or invite id. `epoch_conflict` errors carry
  `current_epoch`.
- The SQLite store writes through a single connection, so every write is
  serialised; queue drains and lookups use up to four read-only
  connections, which in WAL mode neither wait for the writer nor hold it
  up. Quotas are byte counters kept in the transaction that changes the
  queue, so no check scans a queue, and acks use an index on
  `(mailbox, msg_id)`. The `Store` trait keeps each decision (commit
  ordering, invite use, quota, idempotency) a single atomic call so a
  Postgres backend can replace it.
- Deleted rows are overwritten (`secure_delete`), and the purge, every
  minute, ends with a truncating WAL checkpoint, so acked or expired
  ciphertext doesn't stay readable in the database files. The cost is in
  the deletes: removing a payload writes about twice its size again
  (about 4% more bytes written for a 1 KB message, 50% for 16 KB, eight
  times for 256 KB, measured per acked message on a 3-member group), so a
  sender that sends and fetches its own large messages makes the relay
  write about three times what it receives; only the send rate bounds it.
  The purge deletes expired messages 16 MiB at a time, with a passive WAL
  checkpoint and a yield to waiting writes between batches.
- Migration `0005` converts an existing database in place, in one
  transaction: the relay serves nothing until it is done, and it needs
  about the size of the queued messages in free space (it copies each
  envelope before it drops the old table). Queued messages keep their
  order and each becomes its own payload, charged to its sender (a sender
  with many fan-outs from before the upgrade may start over its budget
  until they are fetched or expire; knocks are charged to nobody, as new
  ones are). Welcomes, join requests and knocks already queued count as
  non-member traffic, and existing members count as members. A Welcome
  for an Add committed before the upgrade is refused (`bad_request`), so
  that joiner needs a new invite.

## Testing

`just test` runs everything in-process on loopback with a `FakeClock`; no
sleeps. Connection deadlines (header, auth, idle, ping, stalled send, frame
pacing) run on a manual timer (`timer::ManualTimer`) that a test advances,
and `tests/ws_limits.rs` drives slow readers over in-memory connections with
a small buffer. `tests/trace_logs.rs` runs the binary at `RUST_LOG=trace`.
The same limits on real time and the binary's memory under 20 stalled
connections (`tests/limits_int.rs`) run in `just test-int`. The load tests in `tests/load.rs` (sender budget, a relay with
full queues under a flood, a purge of large expired messages) are ignored
there and run with `just nightly-relay-load` in the nightly tier, with the
core test that the largest Welcome, JoinRequest and reserve commit fit the
caps. `relay/fuzz/` holds `cargo-fuzz` targets for the frame parser and the
`knock` frame (nightly toolchain, not part of `just test`):

```sh
cd relay && cargo +nightly fuzz run frame_parser
cd relay && cargo +nightly fuzz run knock_frame
```
