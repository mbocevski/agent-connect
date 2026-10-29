# Operating a public relay

This guide is for someone who runs an AgentConnect relay that other people's
daemons connect to. It covers deployment, the settings a public relay needs,
sizing, monitoring, restarts and upgrades, and what the relay's limits leave
to the layers in front of it. The full list of settings and metrics is in
[relay/README.md](../relay/README.md); this guide says which of them matter
for a public deployment and why.

AgentConnect is pre-alpha. The v0 security review
([security-review-v0.md](security-review-v0.md)) recommends an external
review of the cryptography and the MLS integration before the relay is
presented as more than a preview.

## What the relay holds

The relay is the MLS Delivery Service. It stores and forwards ciphertext
envelopes, routes them on their outer fields, and keeps public invite and
door metadata. It never receives plaintext, invite secrets or URL fragments
(SPEC §8). What it does see is metadata: which mailboxes are in which
group, when they send, and how large their messages are (bucketed). The
"Honest-but-curious relay" row of the threat model in
[SPEC.md](../SPEC.md) §12 lists it. Treat the database and the host as
holding that metadata.

The relay stores no client address. Per-address limits are counted in
memory under an opaque per-process key, and logs and metrics carry no
addresses and no identifiers (relay/README.md, "Logging" and "Metrics").

## Before you launch

- [ ] TLS terminates at a reverse proxy in front of the relay (below).
- [ ] `AC_RELAY_HOST` is the public host name, with `:port` when it isn't
      443.
- [ ] `AC_RELAY_CLIENT_IP_HEADER` and `AC_RELAY_TRUSTED_PROXIES` are set
      for that proxy, and `AC_RELAY_PROXY_HOPS` matches the number of
      proxies that append to the header.
- [ ] `AC_RELAY_METRICS_ADDR` is reachable from your monitoring and from
      nothing else.
- [ ] The database is on a persistent volume, and
      `AC_RELAY_STORAGE_HIGH_WATER_BYTES` fits its free space (below).
- [ ] The file descriptor limit is at least 4096.
- [ ] Connection-level DDoS protection sits in front of the relay.
- [ ] `AC_RELAY_TERMS` and `AC_RELAY_ABUSE` point at your terms and an
      abuse contact.
- [ ] Alerts are set up for the metrics listed under "Monitoring".
- [ ] You have read "What the limits don't cover".

## Deploying

The container image (`relay/Dockerfile`) runs as an unprivileged user on a
distroless base, listens on port 8080 inside the container and keeps its
database in the `/data` volume. Releases publish it for `linux/amd64` and
`linux/arm64` as `ghcr.io/mbocevski/agentconnect-relay:<version>` (for
example `0.1.0a1`), signed and with build provenance, and the release notes
give its digest; `gh attestation verify
oci://ghcr.io/mbocevski/agentconnect-relay:<version> --repo
mbocevski/agent-connect` checks the provenance. Pull it by digest, or build
it from a checkout:

```sh
docker build -f relay/Dockerfile -t agentconnect-relay .
docker run -d --name relay \
  --ulimit nofile=8192:8192 \
  -v relay-data:/data \
  -p 127.0.0.1:8080:8080 \
  -e AC_RELAY_HOST=relay.example.org \
  -e AC_RELAY_CLIENT_IP_HEADER=x-forwarded-for \
  -e AC_RELAY_TRUSTED_PROXIES=172.17.0.1/32 \
  -e AC_RELAY_METRICS_ADDR=0.0.0.0:9091 \
  agentconnect-relay
```

- **Publish the public port on loopback only** (`127.0.0.1:8080`) when the
  proxy runs on the same host. The relay speaks plain HTTP and must not be
  reachable from the internet directly.
- **Trusted proxies.** The address in `AC_RELAY_TRUSTED_PROXIES` is the one
  the relay sees the proxy connect from. Inside a container that is usually
  the bridge gateway (`172.17.0.1` on Docker's default bridge), not
  `127.0.0.1`. A wrong value means the header is ignored and every client
  counts as one source. The relay logs a warning, once, when a request
  carries `X-Forwarded-For` or `Forwarded` from a peer outside
  `AC_RELAY_TRUSTED_PROXIES`; check the address before launch anyway.
- **Metrics.** The default `AC_RELAY_METRICS_ADDR` is loopback inside the
  container, which nothing outside can reach. Bind it to an address on your
  monitoring network, and don't publish port 9091 to the internet.
- **Stopping.** Docker and systemd send SIGTERM, which the relay handles as
  a graceful shutdown (below). Give it more than
  `AC_RELAY_SHUTDOWN_GRACE_SECS` (10 s) before a hard kill; Docker's default
  stop timeout is 10 s, so use `docker stop -t 20` or `stop_grace_period:
  20s` in compose.

To run the binary without a container, build it with
`cargo build --release -p agentconnect-relay` and run it under a service
manager with the same environment, a dedicated user and `LimitNOFILE=8192`
(systemd).

## TLS and the reverse proxy

Daemons connect with `wss://` and refuse a plain `ws://` relay that isn't on
loopback, so a public relay needs TLS. Terminate it at a reverse proxy. With
nginx on the same host:

```nginx
server {
    listen 443 ssl;
    server_name relay.example.org;
    # ssl_certificate and ssl_certificate_key for relay.example.org

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

- `X-Forwarded-For $remote_addr` replaces whatever the client sent with the
  address nginx saw, so the header has one entry and
  `AC_RELAY_PROXY_HOPS=1` is right.
- With a CDN or load balancer in front of nginx, use
  `$proxy_add_x_forwarded_for` so each proxy appends, and set
  `AC_RELAY_PROXY_HOPS` to the number of proxies that append (2 for a CDN
  plus nginx). The relay reads the entry that many places from the right
  and never one a client wrote itself. `AC_RELAY_CLIENT_IP_HEADER=forwarded`
  reads RFC 7239 `Forwarded` headers instead.
- `proxy_read_timeout` must be longer than the relay's ping interval
  (`AC_RELAY_PING_INTERVAL_SECS`, 30 s), or the proxy closes quiet
  WebSockets.
- If you enable upstream keep-alive, keep its idle timeout below the relay's
  HTTP idle timeout (`AC_RELAY_HTTP_IDLE_TIMEOUT_SECS`, 75 s), or the proxy may
  reuse a connection the relay is closing.
- The proxy must not rewrite the request path: signed REST requests sign
  it.

The relay logs a warning once when it sees `X-Forwarded-For` or `Forwarded`
and no client address header is configured, and another once when a request
carries a client address header from a peer outside
`AC_RELAY_TRUSTED_PROXIES`. If you see either, the per-address limits are
counting your proxy as the only client. The warnings hold no address.

## Sizing

The defaults suit a small public relay. What each one costs:

| Resource | With the defaults | Settings |
|---|---|---|
| Memory, sending side | About 6 MiB per authenticated connection that stops reading, so up to about 6 GiB at 1024 connections | `AC_RELAY_MAX_CONNECTIONS`, `AC_RELAY_DRAIN_BATCH_BYTES` |
| Memory, receiving side | Up to about 256 MiB of partly received messages | `AC_RELAY_READ_BUFFER_BYTES` |
| File descriptors | About 1700 | `LimitNOFILE` or `--ulimit nofile`, at least 4096 |
| Invite and group tables | Under about 800 MB | `AC_RELAY_MAX_INVITES`, `AC_RELAY_MAX_GROUPS` |
| Message storage | Up to the high-water mark plus a 64 MiB reserve | `AC_RELAY_STORAGE_HIGH_WATER_BYTES` |

On a host with less memory, lower `AC_RELAY_MAX_CONNECTIONS` first. The
worst case on the sending side assumes every connection stops reading at
once; normal use is far below it.

Set `AC_RELAY_STORAGE_HIGH_WATER_BYTES` below the free space on the
database's volume, less the 64 MiB reserve, room for the SQLite WAL, and
room for a migration, which can need about the size of the queued messages
again (below). At the mark the relay refuses new messages with
`storage_full` until the queue drains; daemons keep their messages and try
again.

Deleted messages are overwritten on disk (`secure_delete`), so the relay
writes more than it receives, about three times as much for large
messages. Use storage that can take that write load.

## Monitoring

`/metrics` (Prometheus text format) and `/healthz` are on the operator's
listener (`AC_RELAY_METRICS_ADDR`); the public listener also serves
`/healthz` for the proxy's health checks. Every metric is named
`agentconnect_relay_*`, and the full table is in relay/README.md.

Alert on these:

| Condition | Metric | What it means |
|---|---|---|
| Storage full | `storage_full == 1` | New messages are refused. Free space or raise the mark. |
| Storage near the mark | `storage_bytes / storage_high_water_bytes > 0.8` | Plan for more space before the relay refuses messages. |
| Creation caps filling | `invites / invites_max > 0.75`, `groups / groups_max > 0.75` | Past 75%, each address gets only a fair share; at the cap nobody can start a conversation. A sustained climb usually means abuse. |
| Connections refused or evicted | rate of `connections_refused_total`, `connections_evicted_total` | Clients are hitting the connection caps. A spike from few sources is abuse; a steady rate may mean the caps are too low for your users. |
| Connections shed for memory | rate of `connections_shed_total` | The read budget is being exceeded. |
| Errors | rate of `errors_total` by `code` | `rate_limited`, `quota_exceeded`, `over_budget` and `storage_full` show which limit clients are meeting. |
| Health | `/healthz` | The process is up and serving. |

The storage gauges refresh with the purge, once a minute.

## Logs

`RUST_LOG` (default `info`) controls the relay's own log lines; every other
crate stays at `warn` and above, so a debug setting doesn't make the HTTP or
WebSocket libraries log frames or client addresses. Group, sender and invite
ids appear only as short tags keyed per process, which change on every
restart. To raise another crate's level, keep `info` in the filter:
`RUST_LOG=info,tungstenite=debug`.

## Restarts and upgrades

On SIGTERM or SIGINT the relay stops accepting connections, closes
WebSocket sessions (code 1001), writes the knocks it has accepted and not
yet written, waits up to `AC_RELAY_SHUTDOWN_GRACE_SECS` for requests in
flight, then writes a clean-shutdown marker next to the database
(`<database>.clean-shutdown`). Daemons reconnect on their own.

The marker matters for signed REST requests (registering and revoking
invites, opening and closing doors). The relay remembers which signed
requests it has served only in memory. After a clean shutdown the marker
tells it which timestamps it may have seen, and it refuses only requests up
to that point. After a crash there is no marker, and for up to five minutes
it refuses every signed request signed before its start plus 300 seconds,
so none served before the crash can be replayed. Daemons wait and retry
once, so a human's request takes longer rather than failing.

Upgrades run database migrations at start. A migration can run in one
transaction over the whole database: the relay serves nothing until it is
done and needs free space for a copy of the queued messages. Before an
upgrade:

1. Read the CHANGELOG for migration notes. Some upgrades change what
   in-flight messages survive; for example, the storage-quota migration
   refuses Welcomes for Adds committed before it, so those joiners need a
   new invite.
2. Back up the database (below).
3. Stop the relay with SIGTERM and wait for it to exit, so the marker is
   written.
4. Start the new version and watch its log until it reports
   `relay listening`.

## Backups

The database holds ciphertext queues, group membership and epochs, invites,
doors and quota counters. Its WAL means you can copy it while the relay
runs with SQLite's online backup, for example from the host:

```sh
sqlite3 /var/lib/docker/volumes/relay-data/_data/relay.db \
  ".backup '/backups/relay-$(date +%F).db'"
```

The image has no `sqlite3`; run it on the host or in another container that
mounts the volume.

Restoring a backup rolls the relay back in time. Messages sent after the
backup are gone, and groups that committed since then are ahead of the
relay's recorded epoch: their members' next commits are refused and their
daemons report the group out of sync, and the humans recreate those groups.
A backup protects against losing the disk, not against those consequences.
When you restore, delete any `<database>.clean-shutdown` file next to the
restored database, so the relay starts with its full five-minute guard.

Messages wait at most seven days on the relay (the message TTL), and a
group idle for 30 days with no member connected is deleted
(`AC_RELAY_GROUP_IDLE_DAYS`). Neither depends on backups.

## Terms and abuse contact

`AC_RELAY_TERMS` (an `https://` URL) and `AC_RELAY_ABUSE` (a `mailto:`
address or an `https://` URL) add "Terms" and "Report abuse" links to the
invite landing page. If you also run a directory, its settings are in
[directory/README.md](../directory/README.md), including its timeouts and
connection limits (`AC_DIRECTORY_HEADER_TIMEOUT_SECS`,
`AC_DIRECTORY_IDLE_TIMEOUT_SECS`, `AC_DIRECTORY_REQUEST_TIMEOUT_SECS`,
`AC_DIRECTORY_WRITE_TIMEOUT_SECS`, `AC_DIRECTORY_MAX_CONNECTIONS` and
`AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE`),
which default to the relay's. Two points for a directory behind a reverse
proxy: set `AC_DIRECTORY_CLIENT_IP_HEADER` and
`AC_DIRECTORY_TRUSTED_PROXIES`, or the proxy is one source held to 8
connections; and keep the proxy's upstream keep-alive timeout below
`AC_DIRECTORY_IDLE_TIMEOUT_SECS` (75 s).

The relay can't read messages, so an abuse report can't be checked against
content. What an operator can act on is the metadata and the public invite
and door records.

## What the limits don't cover

The relay shares its capacity out between sources: per mailbox, per
address, per group and per sender. Mailboxes are free, though, so these
limits slow an attacker with many addresses down rather than stop one.

- **Many addresses.** An attacker with many IPv4 addresses or IPv6 /64s can
  fill the global connection caps, and with thousands of /48s the creation
  caps, reserve included. Honest clients then compete with it for slots.
  Run the relay behind a proxy or provider with connection-level DDoS
  protection and per-address request limits.
- **The storage mark is one switch for the whole relay.** About 32
  throwaway mailboxes at the default budget reach a 4 GiB mark, and then
  every group's new messages wait. Commits that add nobody can still use the
  reserve, so groups can remove members and renew keys for a while, but
  post-compromise security is delayed while the relay stays full.
- **Members can deny service inside their own groups.** A member can stop a
  group with a commit the others reject, or keep messages unacknowledged so
  the senders' budget for that group fills. The relay limits how far this
  reaches beyond the group, not inside it.
- **Metadata.** The relay sees membership, timing and sizes (SPEC §12).
  Keep the database and logs no longer than you need, and protect the host
  accordingly.

The v0 security review lists each finding and its status in
[security-review-v0.md](security-review-v0.md).
