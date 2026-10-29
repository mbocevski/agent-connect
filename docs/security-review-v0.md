# Security review: v0

- **Date:** 2026-10-19
- **Commit reviewed:** `a95af1c` (`main` after PR #57). `04326be` (#58)
  changed only two harness tests.
- **Scope:** the protocol (`SPEC.md`), `core/`, `core-py/`, `relay/`,
  `directory/`, `daemon/`, `sdk/python/`, `web/` and `packaging/`.
- **Purpose:** this review gates any publicly hosted relay. It is an
  internal review and does not replace the external review recommended in
  [External review](#external-review).

The review measures the code against the canonical claim of
[SPEC §1](../SPEC.md#1-overview):

> The relay can't read or silently alter your agents' conversation. If
> members compare the short code, nobody can sit in the middle, the relay
> operator included.

Finding [SR-01](#sr-01-a-member-can-choose-the-short-code-by-trying-commits)
shows that the second sentence does not hold yet against an attacker in the
middle who can spend a few core-hours of computation. It stays open until
the protocol changes. Everything else is measured against
[SPEC §12](../SPEC.md#12-threat-model).

## Contents

- [Method](#method)
- [Summary](#summary)
- [Findings: High](#findings-high)
- [Findings: Medium](#findings-medium)
- [Findings: Low](#findings-low)
- [Findings: Info](#findings-info)
- [Threat model mapping](#threat-model-mapping)
- [MLS usage](#mls-usage)
- [Group mode](#group-mode)
- [Discovery](#discovery)
- [Relay](#relay)
- [Web](#web)
- [Daemon local API](#daemon-local-api)
- [Policy layer](#policy-layer)
- [Tool results](#tool-results)
- [External review](#external-review)
- [Follow-up tasks](#follow-up-tasks)

## Method

- Every SPEC section was read against the code that implements it. The
  per-PR adversarial reviews of PRs #35, #41 and #43 to #55 were the
  starting point. What they examined, and what was fixed after them, is not
  repeated here; this review looks at what crosses component boundaries.
- **Confirmed** findings were reproduced with a probe: a scratch test or a
  script run against the reviewed commit, kept outside the repository.
  The others say **by reading**.
- Severity:
  - **High:** breaks the canonical claim, or a SPEC §12 mitigation, under
    an attacker the threat model names.
  - **Medium:** weakens a mitigation, needs an uncommon setup or a local
    attacker, or lets one client exhaust a hosted relay.
  - **Low:** a gap in defence in depth, or a SPEC rule not implemented
    where the impact is small.
  - **Info:** a note, an accepted residual or a documentation mismatch.
- **Status** is one of: fixed in a PR; open, with a follow-up task (the
  one-line tasks are under [Follow-up tasks](#follow-up-tasks)); accepted, with the reason.

## Summary

| Severity | Count | Status |
|---|---|---|
| High | 1 | Fixed in #67 |
| Medium | 12 | SR-61 fixed in #72; SR-02 and SR-07 fixed in #71; SR-06 fixed in #74; SR-03 to SR-05 fixed in #73 (SR-05's frame rate limit in #74); SR-11 fixed in #87; SR-12 fixed in #89; SR-09 fixed in #103; SR-08 fixed in #107; SR-10 fixed in #108 |
| Low | 28 | SR-13 and SR-15 fixed in #74; SR-14 fixed in #74 and #77; SR-16 fixed in #74 and #73; SR-17 and SR-18 fixed in #73; SR-19 fixed in #71; SR-28 fixed in #61; the rest open, follow-up task |
| Info | 20 | Notes; 7 accepted; SR-54 fixed in #87 |

- **SR-01 (High).** The short code is a 39-bit (decimal) or 42-bit (emoji)
  truncation of a value that the last committer of an epoch chooses. An
  attacker in the middle of two forked views is a member of both, so it
  can try commits offline in each view until the two codes collide. That
  takes about 2^21 commits per view. The probe chose 12 bits of the honest
  member's next code in 808 tries at 8.3 ms each. This defeats the SAS
  fork detection that the SPEC §12 rows "Malicious relay" and "Link
  leaked before use" rely on.
- Nothing found lets the relay read plaintext or invite secrets. The relay
  parses no `ct`, stores no secret and logs no message body at its default
  levels (SR-14 was the trace-level exception; fixed in #74 and #77).
- No path was found that lets the agent token perform a human-only
  operation: SAS verification, approvals, knock approval, publishing, or
  sending with `origin: "human"`.
- Six of the Medium findings let one client exhaust or lock up a hosted
  relay (SR-02 to SR-07). They don't touch confidentiality, but they gate a
  public relay; see [Before a public relay](#before-a-public-relay).
- The other Medium findings are local attacks on the daemon's loopback
  transports (SR-08 to SR-10), and authenticated peer messages that stall a
  receiver's inbound queue or trigger its agent beyond the message rates
  (SR-11, fixed in #87; SR-12, fixed in #89).
- `cargo audit`, `cargo deny check` and `pip-audit` found no vulnerable
  dependency. Nine fuzz targets, three of them new, ran for 10 minutes each
  without a crash.
- The only code change from this review is PR #63, which adds the three
  fuzz targets. No finding is fixed here: the High needs a protocol
  decision, and the Medium findings are listed as follow-up tasks.

### Before a public relay

These must be fixed, or explicitly accepted by the maintainer, before a
relay is offered to the public:

1. SR-01 (fixed in #67).
2. SR-02 (fixed in #71).
3. SR-03 and SR-04 (fixed in #73), and SR-07 (fixed in #71) (disk
   exhaustion and forced re-syncs by a stranger).
4. SR-05, SR-06 and SR-13 (one connection stalls the relay; memory
   exhaustion; no connection caps or timeouts). SR-06, SR-13 and SR-05's
   frame rate limit fixed in #74, the rest of SR-05 in #73.
5. SR-14 (trace logs carry `ct` and client addresses, against
   `relay/README.md`). Fixed: the relay in #74, the directory in #77.

## Findings: High

### SR-01: a member can choose the short code by trying commits

- **Severity:** High. It breaks the second sentence of the canonical claim
  under the SPEC §14.4 attack: a leaked (or swapped) link plus a colluding
  relay.
- **Component:** protocol (SPEC §3.5, §11), `core/src/sas.rs`,
  `core/src/group.rs` (`Group::sas`).
- **Status:** fixed in #67. Short codes now come from pairwise
  commit-then-reveal runs (SPEC §11): each run mixes a fresh nonce from
  both humans' daemons into the code, and neither side reveals its nonce
  before it holds the other's commitment, so an attacker in the middle
  gets one guess per run instead of an offline search.
- **Confirmed.**

`sas_bytes` = HKDF(`epoch_authenticator`, `group_id`, label ‖ epoch), and
the human compares 42 bits (emoji) or 39 bits (decimal) of it. The
`epoch_authenticator` of epoch e+1 is a function of the epoch-e secrets,
which every member holds, and of the commit that starts e+1: its
`commit_secret` (from the committer's path secret) and its transcript hash.
So whoever makes the last commit knows the next code before it sends the
commit, and can try as many commits as it likes. Any member may commit an
Update for its own leaf at any time (SPEC §9.2).

The forked-view attack of SPEC §14.4: Mallory has A's link and the relay.
In view 1 Mallory is a member next to A; in view 2 Mallory poses as A and
invites the real B. Mallory is a member of both views, so for each view it
can compute the code a candidate commit produces. It keeps N candidate
Updates for view 1 and N candidate commits for view 2 (the Add of B, while
B waits for "approval", or a later Update), and looks for a pair with the
same rendered code. With N = 2^(b/2) per view one collision is expected:
about 741,000 per view for the 39-bit decimal code and 2.1 million for the
42-bit emoji code. Mallory then sends the two commits. A and B both see
the same code, compare it over their independent channel, and mark each
other verified. Nothing in the protocol commits Mallory to its commits
before it sees what the other view will show.

Evidence:

- Probe `a_member_grinds_commits_to_choose_the_sas` (scratch integration
  test of `core`, release build): Mallory joins A's group through the
  invite, then copies its SQLCipher state for each try, builds an Update,
  merges it in the copy and reads the code. It sent the first commit whose
  code matched a 12-bit target. A processed that commit and showed the code
  Mallory had chosen:
  `GRIND bits=12 tries=808 per_try_ms=8.32 alice_decimal=5136-7296-6372 target_prefix_ok=true`.
- At 8.3 ms per try, which includes a database copy and a full commit with
  its ML-KEM encapsulation, a 42-bit collision costs about 2 × 2.1 million
  tries, or 9.7 core-hours: about 9 minutes on 64 cores. The 39-bit decimal
  code costs a third of that. A grinder that keeps the state in memory, or
  varies only the commit's authenticated data, is faster.

Possible fixes, for the maintainer to choose (T-01):

1. **Commitment before reveal (recommended).** Make verification an
   exchange inside the group, as ZRTP and Matrix SAS do: the initiator
   sends a hash commitment to a random nonce, the others answer with their
   nonces, the initiator reveals its nonce, and the code is derived from
   the `epoch_authenticator` and all nonces. A party in the middle must fix
   its nonce in each view before it learns the other view's, so it gets one
   guess per comparison, with probability 2^-39 to 2^-42. The comparison is
   refused if the epoch changes during the exchange. It needs new control
   messages, vectors in Rust and Python, and changes to `verify` in the CLI.
2. **Bind the code to a fresh commit by the verifier.** The human's daemon
   commits an Update when verification starts, and the code is the one of
   that epoch. The attacker then has to hit a random target (a second
   preimage, 2^39 to 2^42 tries) during the live comparison. This is weaker
   than option 1 and doesn't extend to groups as cleanly.
3. **A longer code** only raises the birthday bound (for example 2^32 per
   view for 64 bits) and costs usability. It is not a fix on its own.

Until a fix lands, SPEC §1 and the §12 rows that name the SAS overstate
what comparing the code proves. The canonical claim is the maintainer's to
change, so this review doesn't edit it.

## Findings: Medium

### SR-02: one client fills the relay's signed-request cache and locks everyone out of REST

- **Severity:** Medium. At almost no cost, one client stops every user from
  revoking an invite, registering or closing a door and registering an
  invite, for as long as it refills the cache.
- **Component:** relay (`relay.rs:297`, `relay.rs:428-452`,
  `rest.rs:85-109`), SPEC §8.1.1.
- **Status:** fixed in #71. Once a request's signature verifies, its
  timestamp is checked and its `(mailbox, sig)` pair recorded in one step,
  at the cache's own forward-only time, and the entry stays whatever the
  answer, so a refused request can't be replayed to succeed later. Each
  mailbox has a bounded share (a full
  share refuses only that mailbox; live entries are never evicted), and
  the cache as a whole is bounded: past it, requests are served
  unrecorded, which is harmless because every signed effect is idempotent
  (SPEC §8.1.1 states it and the relay keeps it, along with the residual
  of a refused request applied late, bounded by the 600 s window). A clean
  shutdown records the highest accepted `ts` and the next start refuses
  only up to it; after a crash the relay refuses requests signed before
  its start plus 300 s, with `retry_after`, which the runtime waits out
  and retries once.
  Requests whose signature fails are limited per address in a bucket of
  their own that never refuses a verified request, registrations per
  address, and everything per mailbox; revokes and door closes count only
  per mailbox. The client address behind a proxy uses a trusted-hop count
  (the SR-22 fix), reads `ip:port` and RFC 7239 `Forwarded`, and the relay
  warns once when a forwarded request meets no configuration. The
  accepted future skew stays 300 s.
- **Confirmed.**

`REPLAY_CACHE_CAP` is 10,000 entries for the whole relay. An entry lives
until `ts + 300`, so a request signed with `ts = now + 299` keeps its slot
for about 600 s. `check_replay` runs before the body is parsed, so a
request that ends in `bad_request` still takes a slot. Mailboxes cost
nothing, so a per-mailbox share alone doesn't help. Probe (release build):
10,000 junk signed POSTs in 33 s answered `{400: 9999, 429: 1}`; after
that a victim's `DELETE /v0/invites/{id}` and `POST /v0/doors` both got
`429 rate_limited`, and the invite stayed `open` at the relay. The
inviter's daemon still refuses joins for an invite it revoked, so this is
a denial of service, not a way back in.

Fix: record a signature only after the request validated; give each
mailbox a bounded share and refuse only that mailbox when it is full;
narrow the accepted future skew; limit signed requests per source address
in memory; drop the global refusal from SPEC §8.1.1.

### SR-03: one Welcome frame writes 50 full copies to the relay's disk

- **Severity:** Medium. One client can fill a hosted relay's disk; the
  copies stay for 7 days because nobody acks for invented mailboxes.
- **Component:** relay (`proto.rs:238-248`, `sqlite.rs:145-206`,
  `sqlite.rs:506-508`, `store.rs:88`).
- **Status:** fixed in #73. Each payload is stored once and referenced by
  every recipient's queue row. A Welcome goes only to mailboxes an
  accepted commit of its sender added (the relay already sees
  `routing.add`), once each, and its `ct` is at most 256 KiB. A sender
  may have 128 MiB of undelivered payloads stored, half of it in one
  group (`over_budget`), and above a storage high-water mark (4 GiB by
  default, on `/metrics`) new messages are refused (`storage_full`).
  Commits that add nobody, with a `ct` of at most 128 KiB, may use a
  64 MiB reserve above the mark, charged to the budget like everything
  else. The bounds are per mailbox: with free mailboxes and no per-address
  limits (SR-13) a Sybil can still reach the mark, which then refuses
  everyone's messages until enough is fetched or expires (SPEC §12, "A
  full relay's storage").
- **Confirmed.**

`welcome_wrapped.to` takes any 1 to 50 well-formed mailbox ids, and the
store keeps one full copy of the envelope per recipient. The only quota is
per recipient, and recipients are free. `routing.add` with invented
mailboxes followed by application messages does the same. Probe: one
1.87 MB `welcome_wrapped` frame to 50 new mailboxes was accepted and grew
the database and WAL by 188 MB. The sender may send 50 frames a second.

Fix: store a payload once and reference it per recipient; accept a
Welcome only for mailboxes the group's last accepted commit added; cap a
Welcome's `ct`; add a byte budget per sender and a disk high-water mark.

### SR-04: anyone who knows a mailbox id can make it lose group traffic

- **Severity:** Medium. A stranger forces the victim to re-sync every
  group it is in (SPEC §8.3 overflow rule).
- **Component:** relay (as SR-03; one 64 MiB queue per mailbox for every
  kind).
- **Status:** fixed in #73. Non-member traffic (Welcomes, joins, knocks,
  and the traffic of a group the mailbox hasn't sent in yet, since
  `routing.add` can name any mailbox) has its own 16 MiB part of each
  queue. In each part one group holds at most half, and overflow episodes
  and markers are per group, so every group that loses messages is told.
  The daemon sends `control.capabilities` right after joining, so its
  group traffic leaves the non-member part at once. A Welcome that doesn't
  fit is refused instead of dropped. Residual: two hostile groups can fill
  a part between them (each loss is marked), and past a 256 KiB reserve of
  markers per part a drop goes unmarked.
- **Confirmed.**

Welcomes, joins and group traffic share the recipient's queue. Probe: with
the victim offline, a stranger created its own group and sent the victim
40 Welcomes of 1.87 MB and 500 of 4 KB in 26 s. A member's real commit in
the victim's group was `accepted`, and the victim's drain held 356
`welcome_wrapped` envelopes and two `queue_overflow` markers, without the
commit. Mailbox ids are visible to every member of a group the victim is
in, and to an inviter.

Fix: a separate sub-quota for traffic from non-members (`welcome_wrapped`,
`join_request`, `knock`), plus the Welcome restriction of SR-03.

### SR-05: the quota query and one database connection let a client stall the relay

- **Severity:** Medium. One connection raises every other client's latency
  by two to three orders of magnitude.
- **Component:** relay (`sqlite.rs:65-71`, `sqlite.rs:113-126`,
  `sqlite.rs:607-614`, `relay.rs:555-560`, `ws.rs:374-381`).
- **Status:** fixed: the per-connection frame rate limit in #74, the rest
  in #73. Quotas are counters kept in the queue's transaction, acks use an
  index on `(mailbox, msg_id)`, drains and lookups use read-only WAL
  connections, and the purge deletes expired messages 16 MiB a
  transaction.
- **Confirmed.**

Every recipient of every send runs `SUM(size) … WHERE mailbox = ? AND
expires_at > ?`, and with the `(mailbox, seq)` index SQLite reads every
overflow page of large envelopes. The pool has one connection, so
everything queues behind it. `ack` deletes by `(mailbox, msg_id)`, which
has no index, and neither acks nor malformed frames are throttled. Probe:
with 20 throwaway mailboxes at quota, one attacker connection looping tiny
Welcomes raised an unrelated `group.create` from 0.5 ms to 208 ms; the
quota query took 17.25 s of 17.9 s of SQL time.

Fix: a per-mailbox byte counter kept in the same transaction (or a
covering index `(mailbox, expires_at, size)`); an index on
`(mailbox, msg_id)`; a rate limit on every frame per connection.

### SR-06: the reconnect drain holds whole queues in memory

- **Severity:** Medium. One client drives the relay's memory up by
  gigabytes with its own mailbox and traffic.
- **Component:** relay (`ws.rs:241`, `ws.rs:305-338`, `relay.rs:492-505`).
- **Status:** fixed in #74. Batches are capped by bytes, connections per
  mailbox, per source and in total, and a send that doesn't complete in
  time drops the connection; the probe's 20 stalled connections now grow
  the relay by well under 128 MiB (`relay/tests/limits_int.rs`). The
  review of #74 found the read side outside the bound (unfinished messages
  up to 4 MiB each, kept alive with pongs); messages are now capped at the
  frame limit plus 64 KiB, must keep arriving at a minimum rate, and count
  against a relay-wide read budget.
- **Confirmed.**

The drain loads up to 256 messages at once, which can be a whole 64 MiB
queue, and keeps the batch while `socket.send` waits on a client that
doesn't read. Connections per mailbox are not capped. Probe: one mailbox
filled to 64 MiB and 20 connections for it that never read took the
relay's RSS from 43 MiB to 1,367 MiB.

Fix: cap each batch by bytes, cap connections per mailbox and in total,
and time out a send that doesn't progress.

### SR-07: groups and invites can be created without limit, and groups are never deleted

- **Severity:** Medium. Disk exhaustion of a hosted relay at about 2.4 MB
  a second from one mailbox.
- **Component:** relay (`relay.rs:718`, `relay.rs:1009-1069`,
  `sqlite.rs:616-648`), SPEC §8.3 ("the relay never deletes groups").
- **Status:** fixed in #71. Mailboxes are free, so creations are bounded per
  mailbox, per creation key (an IPv4 address or an IPv6 /48; in memory only,
  no address is stored) and in all: open invites per mailbox, invite rows
  held per key and in all, groups per mailbox per day, per key per idle
  period and in all (`quota_exceeded`), with `/metrics` gauges for the rows
  held and the caps. So that the global caps aren't a relay-wide lockout,
  each key gets only its fair share past 75% of a cap, and the last 5% is
  kept for keys holding fewer than two rows; an attacker with thousands of
  /48s or IPv4 addresses (2,500 for the reserve alone, at the defaults) can
  still fill a cap, which SPEC §12 states. `group.create` is idempotent for
  its creator, and the runtime retries `internal`. The defaults keep the two
  tables under about 800 MB. SPEC §8.3 has a rule for idle groups: the relay
  deletes a group with no accepted send for the idle period (plus the hour
  its activity time is coarse to) and no member connected, writing the time
  in the send's transaction; existing groups count as used at the upgrade.
  Members that come back get `unknown_group`, and the runtime marks the
  group out of sync and tells the human without rejoining; a refused
  `group.create` marks the group `not_created`, refuses its invites and
  fails an approved knock waiting on it. Every limit is configurable.
- **Confirmed.**

`group.create` is limited only by the per-mailbox send rate, and group
rows are permanent. `POST /v0/invites` has no per-mailbox quota or rate
limit, and invites stay until `expires_at` + 7 days. Signing with
`ts = now - 299` keeps the replay cache from slowing this down. Probe: one
mailbox created 450 groups in 10 s, and 11,000 invites in 20 s at about
4.5 KB each.

Fix: quotas per mailbox (open invites, groups per day), REST limits per
mailbox and per source address, and a SPEC rule for deleting idle groups.

### SR-08: over loopback TCP, every client sends its bearer token to whoever holds the port

- **Severity:** Medium. A local OS user who binds `api.tcp_port` while the
  daemon is down receives the human token from the CLI, and can use it
  against the real daemon later: over TCP there is no peer-UID check. It
  needs the opt-in TCP mode and a hostile local user, so it is not High.
- **Component:** daemon (`apiclient.py:24-42`, `mcp/backend.py:262-283`),
  SDK (`agentconnect_sdk/client.py:337-340`, `client.py:490`), `runtime/api.py:1650-1656`.
- **Status:** fixed in #107. The TCP API is TLS only, with a self-signed
  certificate in the data directory; the clients trust only that
  certificate, pinned by its SHA-256 next to the token, and send nothing to
  another server. The design is in `docs/api.md` (TLS on loopback TCP).
- **Confirmed.**

The CLI, the MCP attach backend and the SDK send `Authorization: Bearer
<token>`, and request bodies such as invite URLs with their secret, to any
process listening on `127.0.0.1:<port>`, and trust its answers (a forged
invite URL, a forged short code). Probe: a plain socket on the port
captured the human token from `POST /v0/groups/G/invites` and the agent
token with an invite secret from `POST /v0/invites/accept`. A squatter
that binds first also stops the daemon from starting.

Fix: never send the token itself over TCP. Either the server first proves
it knows the token (an HMAC over a client nonce) and requests carry an
HMAC over method, path, body and time instead of the token, or the human
token is refused over TCP and human commands use the socket.

### SR-09: clients use the short socket path in /tmp without the runtime's checks

- **Severity:** Medium (low likelihood). Another local user who creates the
  short socket directory first gets the tokens and invite URLs the client
  sends, and can forge answers, including the short code.
- **Component:** daemon (`sockets.py:57-64`, used by `apiclient.py:33`,
  `mcp/backend.py:271`, `sdk/.../settings.py:79`).
- **Status:** fixed in #103. Every client connects through one transport
  (`agentconnect.sockets.local_transport`) that checks the short directory
  with `lstat` and then the server's UID against the owner of the token's
  directory, before sending a byte; a configured `api.socket` is covered
  too.
- **Confirmed.**

When the configured socket path is longer than 103 bytes, everything uses
`/tmp/agentconnect-<uid>/<digest>.sock`. The runtime refuses to start when
that directory isn't its own 0700 directory (`prepare_bind_dir`), but the
clients connect without checking. The digest is predictable from the home
directory and the agent name; agent names over about 45 characters
trigger it on Linux. Probe: with a 0777 directory standing in for one
another user owns, the runtime refused to start and the client's request
delivered the human token to the squatter's socket.

Fix: before connecting, every client checks the directory with `lstat`
(owner is the effective UID, mode 0700, not a symlink) and the socket's
owner.

### SR-10: the daemon delivers to loopback receivers it doesn't authenticate

- **Severity:** Medium. A local user who binds the webhook `callback_url`
  port, or the A2A `local_agent_url`, while the agent's receiver is down
  reads every delivery in plaintext and acks it away; for A2A it also gets
  `local_agent_token` and can answer peers as the agent. This holds in
  separate-OS-user mode too.
- **Component:** daemon (`webhook.py:150-160`, `config.py:705-724`,
  `a2a_adapter/adapter.py:207-212`, `adapter.py:461-482`).
- **Status:** fixed in #108. The webhook and the local A2A agent can be on Unix
  sockets (`webhook.callback_socket`, `a2a.local_agent_socket`), and the
  daemon checks the socket server's UID before it writes a byte: the
  daemon's own, or an `isolation.agent_users` entry in separate-OS-user
  mode, which requires the sockets. A mismatch is a retry. The A2A adapter
  sends only to `local_agent_url` (a card naming another endpoint is
  refused), which must be loopback. TCP receivers outside that mode keep the
  documented risk.
- **By reading.**

The webhook HMAC proves the daemon to the receiver, never the receiver to
the daemon, and any 2xx counts as an ack.

Fix: support Unix-socket callbacks in a private directory (required in
separate-OS-user mode), or require a response MAC over the delivery id
before a 2xx counts as an ack; document the risk for TCP receivers.

### SR-11: one authenticated peer message can wedge the receiver's inbound queue

- **Severity:** Medium. A malicious member makes a receiver fail a message
  without telling its human, keeps a journal entry pending and the frame
  unacked at the relay, suppresses the loop-guard pause SPEC §10.3
  requires, and blocks the receiver's leave timeouts.
- **Component:** daemon (`runtime/engine.py:1511-1525`, `engine.py:1624`,
  `store.py:1974-1979`, `engine.py:1390-1391`, `engine.py:1715`,
  `engine.py:3436`, `limits.py:124-148`, `engine.py:1413-1421`,
  `engine.py:1032`).
- **Status:** fixed in #87. Every inner message is bounded before
  anything reads it (SPEC §7.2): a `hop` from 0 to 2^32 − 1, at most 64
  levels of nesting, a `to` and an `addressee` of at most 50 entries of at
  most 128 characters; anything else is `malformed`, and replies never
  carry a hop past 2^32 − 1. A message that fails in the daemon's own
  handling for a reason that would repeat fails alone: recorded as failed,
  its journal entry consumed, the relay acked, an audit row with reason
  `processing_failed` and a `message_failed` event for the human.
  Transient failures are still retried. The core's parsers already stop
  at `serde_json`'s 128 levels (`core/tests/deep_json.rs`).
- **Confirmed.**

`_received_hop` accepts any integer, while SPEC §7.2 makes `hop` a u32.
A hop of 2^63 or more raises `OverflowError` in `record_hop`; a hop of
2^63 − 1 overflows when the loop-guard pause computes hop + 1. A `data`
part nested 2,000 levels deep passes the core and `json.loads`, then
raises `RecursionError` in `json.dumps` when the inbox row is written.
All three end in the generic `except Exception` (`inbound_failed`): no
ack, no inbox row, the core's journal entry stays pending, no event for
the human, and `caught_up()` stays false. Each reconnect retries the frame
and fails again until the relay's TTL. Probes: hop 2^64 gave
`OverflowError ... record_hop` with `JOURNAL_PENDING 1` and no pause;
depth 2000 gave `RecursionError` at `engine.py:1419`.

Fix: treat a `hop` outside 0 to 2^32 − 1 as malformed; limit nesting depth
and node count for every body, `to` and `addressee`; in `_effects`, catch
non-transient errors per message, mark the row failed, consume the
journal entry, ack and tell the human.

### SR-12: unsolicited task updates trigger the agent at the task budget

- **Severity:** Medium. One identity triggers a webhook, SSE, SDK or MCP
  agent up to 900 times a minute instead of 90, which undoes the §12
  "Agent loops" bound.
- **Component:** daemon (`limits.py:283-300`, `policy.py:647-702`).
- **Status:** fixed in #89. The daemon records the A2A messages and task
  cancels it sends as requests, with the instances each one asks (those it
  triggers under the floor rules; for a follow-up naming a task, only the
  instance running it). A request grants each asked instance one task, and
  that task triggers the requester only on entering input required, auth
  required or an end state: once per state for each request, and not
  after it ended, on the adapter whose request it is. Its progress is
  context (SPEC §9.3, §10.2). A request therefore triggers its sender a
  small, fixed number of times, and a member triggers another's agent with
  task updates only as often as that agent sends it requests, which its own
  send rate bounds. Any other task update is context at the ordinary rates,
  never a violation. An update that triggers passes the task budget its
  progress used. The sender exempts its own update only when it answers a
  request its instance received and that asked it, on that request's task,
  entering a state for the first time before the task ended, so an agent
  can't invent requests or tasks to get past its own rates. The A2A facade
  takes answers only from the members its request asked (found in the PR's
  review).
- **Confirmed.**

Any `a2a.task_status` or `a2a.task_artifact` with a `taskId` counts
against the per-task budget of 300 a minute, and with `addressee:
[victim]` it triggers the victim whether or not the victim asked for that
task. Nothing checks that `reply_to` names a message the victim sent. Only
the A2A adapter ignores task updates for triggering (`adapter.py:287`).
Probe: within one minute 120 task updates were delivered and all 120
triggered, against 28 plain messages.

Fix: give the task budget, and triggering, only to updates whose
`reply_to` names a message this instance sent; count the rest as ordinary
messages or deliver them as context; say so in SPEC §9.3 and §10.2.

### SR-61: a removed member keeps its last epoch's HPKE private keys

- **Severity:** Medium. Private key material outlives the group it belongs
  to. Whoever later reads the store, with its key, gets the member's leaf
  and path HPKE private keys of the epoch before its removal.
- **Component:** core (`group.rs`, `Group::delete`; OpenMLS 0.9.1
  `MlsGroup::delete` and `StagedCommit` merge).
- **Status:** fixed in #72.
- **Confirmed.** Found by mutation testing: closing the gaps in
  `provider.rs` added a test that every OpenMLS row of a deleted group is
  gone.

When a member merges the commit that removes it, OpenMLS takes the path for
a group it is no longer in and doesn't delete the previous epoch's
encryption key pairs. `MlsGroup::delete` then deletes the key pairs of the
current epoch only, so one row of `openmls_epoch_keys_pairs` stayed for
every group the instance was removed from, or left. The daemon deletes
groups through `Group::delete`, so the rows stayed in its store. A removal
blanks the removed leaf's direct path, so no later commit should be
encrypted to these keys. A commit that lost its epoch could have been.
Probe: A removes B from a group of two at epoch 1; after B deletes the
group, the row for epoch 1, leaf 1 (4477 bytes) is still there.

Fix: `Group::delete` and the refused-Welcome path delete every row keyed by
the group in every OpenMLS table after OpenMLS's own delete. Opening a
SQLite store deletes the epoch key pairs of groups with no state left, which
removes what earlier versions left behind. Tests in `provider.rs` delete a
group that is active, has a pending leave, was removed and was left, and
check that no row of any table references it, on both stores; one opens a
store written the old way.

## Findings: Low

| ID | Component | Finding | Evidence | Status |
|---|---|---|---|---|
| SR-13 | relay | No connection caps, no header-read timeout (axum sets no hyper timer), no WebSocket ping or idle timeout after authentication. Unauthenticated sockets are closed after 10 s, as they should be. | `main.rs:39-52`, `ws.rs:365-396`. Probe: unfinished headers held for 40 s; an idle authenticated socket held for 45 s. Confirmed. | Fixed in #74 |
| SR-14 | relay, directory | At `RUST_LOG=trace`, `tungstenite` logs whole frames (`ct`, every id) and `axum::serve` logs client addresses; `relay/README.md` says logs never contain `ct`. The directory's filter clamps only `rmcp`, so it logs client addresses at trace too. Debug and info are clean. | `relay/src/main.rs:15-17`, `directory/src/lib.rs:37-40`. Probe: `TRACE tungstenite::protocol: Received message {"t": "send", "env": {... "ct": ...}}`. Confirmed. | Fixed in #74 (relay) and #77 (directory) |
| SR-15 | relay | `connected` and `disconnected` lines log the mailbox tag next to the knock lines, and tags are an unkeyed 32-bit hash prefix, so anyone holding an id can find it. SPEC §8.3: knock paths log no identifier, hashed or not. `door_log_privacy.rs` doesn't go through `ws.rs`. | `ws.rs:125`, `ws.rs:174`, `proto.rs:43-50`. Confirmed in probe logs. | Fixed in #74 |
| SR-16 | relay | Answer timing tells a knocker whether a busy door dropped its knock or forwarded it, which SPEC §8.3 hides by answering both `accepted`. | `relay.rs:885-889`. Probe: dropped knocks answered in a median of 108-359 µs, forwarded ones in 245-2011 µs. Confirmed. | Fixed in #74, the residual in #73 (T-16) |
| SR-17 | relay | Join requests have only the 2 MiB frame cap, and the per-invite budget of 10 a minute is shared by anyone who knows the public `invite_id`: junk joins fill the inviter's queue in about 3.5 minutes and use up the real joiner's budget. | `relay.rs:756-827`, `proto.rs:249`. Confirmed. | Fixed in #73: `ct` at most 16 KiB, joins charged to the inviter's non-member queue |
| SR-18 | relay | Deleted rows stay in the database file: `secure_delete` is off, so acked ciphertext and expired door mappings remain readable on disk. | `sqlite.rs:59-64`. Probe found acked ciphertext in the file after a checkpoint. Confirmed. | Fixed in #73: `secure_delete`, and a truncating WAL checkpoint every minute |
| SR-19 | relay, web | Invite registration rejects only Cc characters, so bidi controls and zero-width characters in `group_name`, `inviter_name` and `purpose` reach the landing page unaltered (escaped, but reordering what the human reads). The CLI already replaces them. | `relay.rs:374-380`, `landing.rs:29-41`. Probe: U+202E accepted and rendered raw. Confirmed. | Fixed in #71: the three fields must be one-line text (SPEC §4.2, §13.1.2). |
| SR-20 | directory | `/search` and MCP `search_agents` results omit the verbatim signed listing that SPEC §13.2.6 requires in machine-readable results; only `get_card` has it. | `api.rs:24-61`, `http.rs:273-283`, `mcp.rs:93-110`. Confirmed. | Open (T-20) |
| SR-21 | directory | The client's HTTP method is logged verbatim at info, so any client can write arbitrary text (an address, a name) into the logs. | `http.rs:682`, `http.rs:714`. Probe: `method=ME-203.0.113.9-alice`. Confirmed. | Open (T-21) |
| SR-22 | directory | The `X-Forwarded-For` walk skips every address in the trusted proxy blocks, so a client behind a shared CDN range that is listed as a proxy picks its own key and bypasses the per-address limits. | `http.rs:618-653`, `ratelimit.rs:179-189`. Confirmed with a trusted loopback peer; the CDN case by reading. | Open (T-22) |
| SR-23 | directory | Revoked token ids are purged 90 days after the directory received the revocation, not after the token's expiry, so a token issued after the revocation time becomes publishable again. | `store.rs:22`, `memory.rs:298`, `memory.rs:456`, `postgres.rs:783`. By reading. | Open (T-23) |
| SR-24 | directory, daemon | After the operator rotates `DK`, the directory keeps serving listings whose token key it no longer pins; knockers refuse them, and the owner's renewals fail with `unknown_key`, which is retried forever. | `directory.rs:347-360`, `runtime/knocks.py:773`, `runtime/listing.py` (`STOP_RENEWING`). By reading. | Open (T-24) |
| SR-25 | daemon | The knocker never checks token revocations, so against a malicious directory "rollback is bounded by token revocation" (SPEC §12) does not hold. `docs/discovery.md` already says so. | `runtime/knocks.py:773`. By reading. | Open (T-25) |
| SR-26 | daemon | A JoinRequest with a failed MAC is not counted toward rate limiting (SPEC §6.2 step 2 MUST); only the relay's per-invite limit applies. | `engine.py:_on_join_request` (around line 1772). By reading. | Open (T-26) |
| SR-27 | daemon | The A2A adapter's `a2a-seen.db` is a plain SQLite file (0600) in the data directory, against "there is no unencrypted on-disk mode" (SPEC §12). It holds SHA-256 hashes of `msg_id`s, which the relay also sees. | `a2a_adapter/seen.py:22-30`. By reading. | Open (T-27) |
| SR-28 | daemon | Unauthenticated connections fill the local API's 64 slots and lock the human out (503) for 10 s at a time. In separate-OS-user mode any listed agent user can do it without a token. | `runtime/api.py:63-70`, `api.py:1552-1558`. Probe: human request 503 while 64 idle connections were held. Confirmed. | Fixed in #61: unfinished connections give way (32, hard 128; 8 and 64 per UID in separate-OS-user mode), quiet ones first after 0.5 s, and a connection whose headers arrived is never closed. Re-probed on c0d0c12: with 64 or 200 idle connections held, on the socket and on TCP, the human's requests are answered at once. Tests: `harness/tests/test_api.py` (`test_half_sent_connections_dont_keep_the_human_out`, `test_a_connection_that_sent_nothing_gives_way_first`, `test_connects_behind_a_whole_request_dont_close_it`, `test_past_the_hard_limit_a_stalled_connection_goes_not_a_fresh_one`) |
| SR-29 | daemon | `check_agent_dir` accepts a group-writable agent directory (0770, 0730) and doesn't check its parents, so an agent user may be able to replace the socket and show the human forged approvals or a forged code. | `isolation.py:158-180`. Probe: 770 and 730 accepted. Confirmed. | Open (T-29) |
| SR-30 | daemon | The A2A local-agent client and the facade's push client honour `HTTP_PROXY` and `ALL_PROXY` for loopback URLs, sending peer messages and `local_agent_token` to a proxy in the daemon's environment. | `a2a_adapter/adapter.py:212`, `a2a_adapter/facade.py:357`. Confirmed with the same client setup. | Fixed: the adapter's client in #108, the facade's push client in #113 (`trust_env=False`, no redirects) |
| SR-31 | daemon | Facade push-notification URLs are not screened, so the facade token holder can make the daemon POST task updates to any address. | `a2a_adapter/facade.py:346`. By reading. | Open (T-31) |
| SR-32 | daemon | `GET /v0/status` with the agent token counts a group hidden from the agent (an approved knock before the knocker joins) and lists its id in `out_of_sync`. | `engine.py:3616-3628`, `runtime/agent.py:58-63`, `api.py:1426-1427`. Confirmed. | Open (T-32) |
| SR-33 | daemon | The agent's `reply_to` choice resets the loop-guard hop: two agents that keep naming the human's first message never reach `max_agent_turns`. | `engine.py:1672-1691`, `engine.py:1518-1524`, `mcp/tools.py:283-288`. Probe: eight replies at hop 1, no pause. Confirmed. | Open (T-33) |
| SR-34 | daemon | `close_requested` carries the owner's 200-character reason to the agent while `require_verified` still holds deliveries, and the agent may then leave, though SPEC §7.3 makes that the human's decision. | `engine.py:1427-1436`, `engine.py:146-157`. Confirmed. | Open (T-34) |
| SR-35 | daemon | In `free` mode a replica is triggered by its sibling's messages, although SPEC §9.3 triggers "all members except the sender" and a member is an identity. | `engine.py:414-415`. Confirmed. | Open (T-35) |
| SR-36 | daemon | The reconnect-drain exemption from the rates resets on every connection, and the relay decides when the drain ends, so a relay colluding with a member bypasses the §10.2 rates. | `relay.py:114-115`, `relay.py:190-199`, `engine.py:763-773`. By reading. | Open (T-36) |
| SR-37 | daemon | The A2A facade takes the first reply from any member, even for a request addressed to one member (`/g/<gid>/m/<X>`). | `facade.py:441-451`, `facade.py:182-200`. By reading. | Open (T-37) |
| SR-38 | daemon | Webhook, SSE and SDK agents receive `a2a.task_cancel` from any member, with no requester check and no guidance in the docs; SPEC §7.2 says the member running the task MUST ignore it. Only the A2A adapter checks. | `adapter.py:438-457`, `docs/adapters/webhook.md:93-105`. By reading. | Open (T-38) |
| SR-39 | build | Signed releases are never verified by a test, `just release-verify` checks the GitHub attestations but not the cosign bundles, and `release.yml` doesn't require the reproducibility check for the tagged commit. | `.github/workflows/release.yml`, `.github/workflows/repro.yml`, `justfile` (`release-verify`). By reading. | Open (T-39) |
| SR-40 | tooling | No workflow runs the fuzz targets, nightly included. | `.github/workflows/nightly.yml`. By reading. | Open (T-40) |

## Findings: Info

| ID | Component | Note | Status |
|---|---|---|---|
| SR-41 | relay | Envelope validation is lenient: `to` is accepted unchecked on `application`, `commit`, `proposal` and `join_request`, and `epoch` and `group_id` on kinds that SPEC §7.1 doesn't give them (`proto.rs:229-258`). Receivers check what they act on. | Open (T-41) |
| SR-42 | relay, directory | `/metrics` is on the public listener (the relay always, the directory unless `AC_DIRECTORY_METRICS_ADDR` is set). No identifiers and only fixed labels; on a quiet relay the counters can be matched to one user's actions. | Open (T-42) |
| SR-43 | relay | Group rows and memberships are kept indefinitely, which gives a mailbox social graph over time; `overflow` rows are never purged. SPEC §12 doesn't state the retention. | Partly fixed in #71: idle groups and their memberships are deleted after 30 days (SPEC §8.3, §12). `overflow` rows are still kept. |
| SR-44 | relay | The replay check reads the clock twice (`rest.rs:103`, `relay.rs:429`); a request at exactly `ts = now - 300` could be replayed in the microseconds between the reads. | Fixed in #71: the cache checks the timestamp and records the request in one step, at its own forward-only time. |
| SR-45 | directory | Owner-revocation entries in the withdrawals feed are unsigned JSON written by the directory, so a mirror can't verify them as SPEC §13.2.5 says (`directory.rs:892-906`). Censorship only. | Open (T-45) |
| SR-46 | directory | Search responses are `Cache-Control: public, max-age=60`, so a CDN in front caches and logs search terms keyed by URL (`http.rs:247`, `http.rs:279`). | Open (T-46) |
| SR-47 | directory | Each `llms.txt` request parses up to 10,000 cards (`directory.rs:408-434`); CPU amplification on a large directory. | Accepted: availability is a v0 non-goal; the per-address limit bounds it. |
| SR-48 | relay | `GET /v0/invites/{id}` returns attacker-controlled strings with no `nosniff` and no `Cache-Control` (`rest.rs:128`, `rest.rs:212`). | Open (T-48) |
| SR-49 | web | The landing page tells the reader that the page never sees the secret part (`landing.rs:94`), which SPEC §4.4 contradicts for a malicious operator. | Open (T-49) |
| SR-50 | relay, directory | Neither sends HSTS; `frame-ancestors 'none'` covers framing. | Accepted: HSTS belongs to the TLS proxy in front. |
| SR-51 | daemon | `a2a.local_agent_url` allows plain `http` to a non-loopback host, unlike `webhook.callback_url` (`config.py:753-758`). | Open (T-51) |
| SR-52 | daemon | In the same-user modes the agent process can read `human-token`; in separate-OS-user mode all agent users share `webhook-secret`. | Accepted: documented in ADR-005 and `docs/isolation.md`. |
| SR-53 | daemon | Small free-text fields in controls (`control.pause.reason`, `control.capabilities` words, `control.close.reason`) are never held for approval and reach webhook and SSE consumers as context (`schemas.py:126-130`). | Open (T-53) |
| SR-54 | daemon | Inbound `addressee` over 50 entries still triggers the listed members, and `to` is bounded only by the message size (`engine.py:410-413`). | Fixed in #87: both are malformed past 50 entries or 128 characters an entry (SPEC §7.2) |
| SR-55 | daemon | Approving a peer task's first update lets its later updates through unseen for up to 600 s. | Accepted: documented in `docs/safety.md`. |
| SR-56 | daemon | A modified peer daemon can send `origin: "human"`, hop 0 or `control.resume` and reset the receiver's loop guard. | Accepted: SPEC §12 residual, documented in `docs/safety.md`. |
| SR-57 | relay | A malicious relay can inject a `queue_overflow` marker and stop a member's sends in a group until it re-syncs. | Accepted: relay denial of service is a v0 non-goal. |
| SR-58 | dependencies | The OpenMLS provider crates are patched to an unreleased upstream commit, and the hpke-rs crates are MPL-2.0 under a scoped exception. | Accepted: ADR-001 §2 and §4; `scripts/check_cargo_patch.py` guards the patch. |
| SR-59 | SPEC | SPEC §12 differs from the code in seven places; see [SPEC claims that don't match](#spec-claims-that-dont-match). | Open (T-59) |
| SR-60 | tests | Nine mitigations have no test or only a positive one; see [Test gaps](#test-gaps). | Open (T-60) |

## Threat model mapping

Each SPEC §12 row is split into its mitigations, with the code that
implements each one and the tests that cover it. Tests are
`file::name`; Rust unit tests sit in the file they test. "Covered" means
there is a negative test (the attack fails).

| Threat | Mitigation | Code | Tests | Status |
|---|---|---|---|---|
| Honest-but-curious relay | MLS, `PrivateMessage` only | `core/src/group.rs` (`create_group_with_policy`, `process_inner`) | `core/src/group/tests.rs::processing_after_eviction_and_public_messages` | Covered |
| | Padding buckets | `core/src/padding.rs` (`bucket_for`) | `core/tests/group.rs::padding_hides_length_within_a_bucket`, `::real_ciphertexts_follow_padding_vectors`; `core-py/tests/test_vectors.py::test_padding_vectors` | Covered |
| Malicious relay without the link | Invite MAC | `core/src/join.rs` (`join_request_mac`), `group.rs` (`verify_join_request`) | `core/tests/group.rs::wrong_invite_secret_fails_mac_and_welcome`, `::relay_cannot_rename_the_joiner`, `::mailbox_must_match_key_package` | Covered; failed MACs aren't rate-limited (SR-26) |
| | AEAD-wrapped Welcome | `core/src/invite.rs` (`unwrap_welcome`) | `core/src/invite.rs::welcome_wrap_round_trips_and_rejects_wrong_secret_or_tamper`; `core/tests/group.rs::non_welcome_payload_is_rejected` | Covered |
| | Welcome content checks (suite, PSK, GroupInfo extensions, KEM and key lengths, meta) | `group.rs` (`join_inner`), `core/src/mls.rs` (`check_welcome_kem_outputs`, `check_tree_keys`) | `core/src/group/tests.rs::welcome_with_a_wrong_length_kem_output_is_rejected`, `::joiner_rejects_a_real_welcome_whose_tree_has_a_short_hpke_key`, `::welcome_with_an_extra_group_info_extension_is_rejected`; `core/tests/group.rs::welcome_meta_must_match_invite_meta` | Covered, except a Welcome in another suite (test gap 1) |
| | Single-use KeyPackages | `group.rs` (`after_merge`), `core/src/records.rs` | `core/tests/group.rs::replayed_join_request_cannot_re_add_a_departed_member`; `core/src/group/tests.rs::re_add_of_a_used_key_package_is_rejected_by_receivers` | Covered |
| | No KeyPackage extensions, not last resort | `core/src/mls.rs` (`validate_key_package`) | none | Gap (test gap 2) |
| | Inviter's JoinRequest replay record | `core/src/ledger.rs`, `daemon/.../runtime/ledger.py`, `engine.py` (`_on_join_request`) | `core/tests/join_ledger.rs::a_join_request_seen_before_is_a_replay`, `::a_full_join_ledger_refuses_without_evicting`; `harness/tests/test_join_replay.py::test_a_rejected_request_replayed_is_dropped_silently`, `::test_a_replay_after_a_restart_is_dropped` | Covered |
| | MLS signatures, epochs, generation counters | OpenMLS through `group.rs` (`process_inner`) | `core/tests/group.rs::tampered_and_replayed_messages_are_rejected`; `harness/tests/test_scenarios.py::test_replayed_frames_are_ignored` | Covered |
| | `msg_id` deduplication | relay store, daemon inbox | `relay/tests/delivery.rs::duplicate_msg_id_is_accepted_but_not_redelivered` | Covered |
| | Own commit confirmed only by `msg_id` or exact bytes | `group.rs` (`confirm_pending_commit_inner`, `merge_own`) | `core/tests/group.rs::accepted_confirms_only_its_own_msg_id_and_later_echo_is_harmless`, `::stale_own_commit_is_not_taken_for_the_pending_one`; `core/src/group/tests.rs::forged_own_commit_echo_neither_confirms_nor_discards` | Covered |
| | Routing-hint check | `daemon/.../runtime/groups.py` (`after_commit`) | `harness/tests/test_scenarios.py::test_routing_hint_mismatch_raises_relay_misbehaviour` | Covered for `add`; a rewritten `remove` hint isn't tested |
| | Envelope shape, epoch and group against the header (§7.1) | `engine.py` (`_envelope_problem`, `_header_mismatch`), `group.rs` (`peek_header`) | `harness/tests/test_envelope_validation.py::test_envelope_shapes`, `::test_an_application_epoch_mismatch_is_dropped_before_processing`, `::test_a_commit_for_another_group_is_flagged_and_rejected` | Covered |
| | SAS detects forks | `core/src/sas.rs`, `group.rs` (`sas`) | `core/tests/group.rs::forked_group_view_gives_different_sas`; `harness/tests/test_scenarios.py::test_fork_shows_as_differing_sas` | Was broken by SR-01 (grinding); fixed in #67, see `core/src/group/sas_grind_tests.rs` |
| Link leaked before use | Use limits, atomic consume | `relay/src/relay.rs` (`invite.consume`), `sqlite.rs` | `relay/tests/invites.rs::two_concurrent_consumes_of_a_single_use_invite_have_one_winner`; `harness/tests/test_invite_uses.py::test_two_concurrent_redemptions_of_a_single_use_link` | Covered |
| | "Already used" warning | `engine.py`, `cli_support.py` | `harness/tests/test_cli_lifecycle.py::test_a_used_invite_raises_the_interception_warning`, `::test_a_revoked_invite_raises_the_same_warning` | Covered |
| | Inviter approval, 1 h timeout, no automatic approval by default | `engine.py`, `config.py` | `harness/tests/test_daemon_flows.py::test_expired_approvals_disappear_from_the_list`; `daemon/tests/test_no_auto_approve.py::test_every_route_that_decides_needs_the_human_token` | Covered |
| | SAS | as above | as above | Was broken by SR-01; fixed in #67 |
| Link leaked after exhaustion | The secret authenticates joins only; closed invites refused; secrets deleted | `engine.py` (`_on_join_request`, `_forget_invite_requests`) | `harness/tests/test_daemon_flows.py::test_an_exhausted_invite_is_not_reused`; `harness/tests/test_expiry.py::test_expired_invites_and_joins_lose_their_secrets` | Covered |
| Malicious member | Roles and policy checked by every receiver | `core/src/policy.rs`, `group.rs` (`inspect_commit`) | `core/src/group/tests.rs::member_removing_another_member_is_rejected`, `::non_owner_policy_change_is_rejected`; `core/src/group/group_mode_tests.rs::unauthorized_commits_are_rejected_and_fork_only_the_committer`; `harness/tests/test_group_roles.py::test_a_policy_change_beyond_the_committers_role_is_rejected_by_every_member` | Covered |
| | Removal starts a new epoch | `group.rs` (`remove`, `remove_instances`) | `core/tests/group.rs::removed_member_cannot_decrypt_next_epoch`; `relay/tests/delivery.rs::a_removed_member_gets_the_removing_commit_then_nothing` | Covered |
| | Endpoint policy (§10) | see "Prompt-injected peer" | | Covered (SR-11 fixed in #87, SR-12 fixed in #89) |
| Removed member | Forward secrecy across epochs | OpenMLS; `group.rs` (`is_active`) | `core/tests/group.rs::removed_member_cannot_decrypt_next_epoch`, `::member_that_missed_its_removal_cannot_decrypt_either` | Partial (test gap 3) |
| | Previous epoch kept for one epoch only | `core/src/mls.rs` (`MAX_PAST_EPOCHS = 1`) | `core/src/group/tests.rs::grace_window_sender_must_have_been_a_member_then` (positive only) | Gap (test gap 4) |
| Quantum adversary | One hybrid suite, no negotiation | `core/src/lib.rs`, `core/src/mls.rs` (`CS`, `precheck_key_package`) | `core/tests/key_package.rs::wrong_ciphersuite_is_rejected`; `core/src/mls.rs::derive_hpke_keypair_matches_the_hpke_pq_known_answer` | Covered |
| | Key and KEM ciphertext lengths | `core/src/mls.rs` (`check_tree_keys`, `check_welcome_kem_outputs`), provider | `core/src/mls.rs::provider_rejects_wrong_length_kem_outputs_without_panicking`; `core/tests/key_package.rs::short_hpke_init_key_is_rejected_without_panic` | Covered |
| | Update cadence (24 h or 1000 messages) | `runtime/groups.py` (`update_due`), `store.py` (`bump_messages`) | `harness/tests/test_daemon_flows.py::test_update_cadence_by_time_and_count` | Covered (test gap 5) |
| Model provider | none (inherent) | | | Nothing claimed |
| Compromised host | Encrypted-at-rest storage | see the last rows | | Covered, except SR-27 |
| | Updates heal after re-key | `group.rs` (`update`) | `core/tests/group.rs::update_commits_converge_and_change_sas` | Positive only (test gap 6) |
| Prompt-injected peer agent | Untrusted framing and scope (§10.1) | `daemon/.../payloads.py`, `adapter.py` | `harness/tests/test_safety_policy.py::test_scope_and_framing_reach_the_webhook_sse_and_the_sdk`; `daemon/tests/test_a2a_adapter.py::test_peer_metadata_cannot_override_the_framing` | Covered |
| | Limits (§10.2), lower only, silent drops | `daemon/.../limits.py`, `policy.py` | `harness/tests/test_limits_e2e.py::test_receivers_drop_what_breaks_the_limits`, `::test_receivers_rate_limit_a_flooding_sender`; `daemon/tests/test_policy.py::test_limits_can_only_be_lowered`; `harness/tests/test_unsolicited_task_updates.py`; `harness/tests/test_poison_messages.py` | Covered (SR-11 fixed in #87, SR-12 fixed in #89) |
| | Approval hooks and SAS verification human-only | `runtime/api.py` (`ROUTE_SPECS`), `mcp/tools.py` | `daemon/tests/test_human_only_routes.py::test_every_route_is_classified_and_the_deciding_ones_need_the_human_token`; `daemon/tests/test_no_auto_approve.py::test_the_agent_api_has_no_deciding_method`; `harness/tests/test_mcp.py::test_the_tools_are_the_agent_scope_only` | Covered |
| | Control and card bodies stripped; cards checked against pinned keys only | `engine.py`, `schemas.py`, `a2a_adapter/cards.py` | `harness/tests/test_safety_policy.py::test_content_under_control_or_card_kinds_never_reaches_the_agent`, `::test_a_signed_card_reaches_a_peer_unchanged_and_a_forged_one_is_dropped` | Covered |
| Agent loops | Loop guard | `engine.py` (`_received_hop`, `_reply_hop`, `_loop_guard`) | `harness/tests/test_loop_guard.py::test_replies_carry_hop_and_the_guard_pauses`, `::test_an_agent_resume_is_ignored`, `::test_a_hop_below_the_referenced_messages_is_raised` | Covered; SR-33 |
| | Rate limits, own sends included | `limits.py`, `policy.py` | `harness/tests/test_limits_e2e.py::test_senders_refuse_to_break_the_limits`; `harness/tests/test_unsolicited_task_updates.py` | Covered (SR-12 fixed in #89) |
| | Floor modes | `runtime/floor.py`, `engine.py` (`addressed_to_me`) | `harness/tests/test_floor.py::test_grants_the_policy_does_not_allow_are_ignored`; `harness/tests/test_group_acceptance.py::test_mention_mode_unaddressed_does_not_trigger_and_a_two_agent_loop_pauses` | Covered; SR-35 |
| Malicious software distributor | Reproducible builds | `.github/workflows/repro.yml` | CI job only | Linux only |
| | Signed releases with provenance | `.github/workflows/release.yml`, `justfile` (`release-verify`) | none | Gap (SR-39) |
| Spam lister | Token bound to directory, name and identity | `core/src/listing/token.rs`, `directory/src/directory.rs` | `core/src/listing/token.rs::token_binding_checks_every_field`; `directory/tests/publish.rs::token_scope_and_lifetime_are_enforced` | Covered |
| | Per-address publish limits | `directory/src/ratelimit.rs` | `directory/tests/limits_logs.rs::searches_writes_and_mcp_have_their_own_budgets`; `directory/tests/review_regressions.rs::m2_write_limits_are_per_name_too` | Covered; SR-22 |
| | Operator revocation | `directory.rs` (`revoke_inner`) | `directory/tests/publish.rs::token_revocation_withdraws_the_listing_and_bars_the_token` | Covered at the directory; SR-23, SR-25 |
| Impersonator | Signature binds the card to its `IK` | `core/src/listing/card.rs` | `core/src/listing/card.rs::signature_rules`; `core/tests/listing_props.rs::no_single_byte_change_is_accepted` | Covered |
| | Owner domain and organization shown only when verified | `core/src/listing/owner.rs`, `directory/src/owner.rs`, `render.rs` | `directory/tests/search_owner.rs::a_file_that_does_not_list_the_key_fails_at_once`, `::a_verified_owner_shows_the_organization` | Covered |
| | Names are ASCII slugs | `core/src/listing/mod.rs` (`is_listing_name`) | `core/src/listing/mod.rs::listing_names_are_ascii_slugs` | Covered for the slug; the display name is Unicode (SPEC mismatch 6) |
| | "Key changed" banner for 30 days | `directory.rs` (`view`) | `directory/tests/pages.rs::owner_states_and_the_key_changed_banner_show` | Covered at the directory only |
| | The knocker fetches the owner file itself | `runtime/knocks.py` (`_owner`), `ownerfile.py` | `daemon/tests/test_knocks.py::test_the_owner_domain_is_checked_by_this_runtime`; `daemon/tests/test_ownerfile.py::test_special_use_addresses_are_never_dialled` | Covered |
| | Then the SAS | knock groups start unverified | `core/src/group/knock_tests.rs::a_forked_knock_group_shows_a_different_short_code` | Was broken by SR-01; fixed in #67 |
| Scraper | Rate limits | `ratelimit.rs` | `directory/tests/limits_logs.rs::reads_are_limited_per_address_and_recover` | Covered |
| | No mailbox id or secret in listings | `card.rs` (closed schema) | `core/src/listing/card.rs::closed_schema_rejects_extra_fields` | Covered |
| | Doors rotate | `runtime/listing.py` | `daemon/tests/test_listing.py::test_renewal_at_exactly_half_life` | Covered (rotation is every 3.5 days, SPEC mismatch 5) |
| Malicious directory operator | Listings and withdrawals signed by `IK` | `card.rs`, `core/src/listing/withdrawal.rs` | `core/src/listing/withdrawal.rs::withdrawal_signature_and_fields_are_checked`; `daemon/tests/test_knocks.py::test_a_lying_directory_gets_nothing_sent` | Covered |
| | Tokens checked against a pinned `DK`; the knocker re-verifies | `knocks.py` (`_verified`), `config.py` | `daemon/tests/test_knocks.py::test_a_lying_directory_gets_nothing_sent`; `daemon/tests/test_config_discovery.py::test_a_directory_is_pinned_with_its_keys` | Covered |
| | Rollback bounded by door expiry and closing | `card.rs`, relay `close_door` | `relay/tests/doors.rs::only_the_owner_can_close_a_door_and_it_closes_at_once`; `harness/tests/test_knocks.py::test_after_a_withdrawal_a_knock_gets_door_not_open` | Covered |
| | Rollback bounded by token revocation | not on the knocker | none | Not implemented (SR-25) |
| Relay and directory colluding | Sealed knocks | `core/src/knock.rs` | `core/src/knock.rs::owner_checks_1_to_3`; `harness/tests/test_knocks.py::test_a_malicious_relay_cant_get_a_knock_through` | Covered (test gap 7) |
| | No identifiers in logs | `directory/src/http.rs`, `metrics.rs`; relay | `directory/tests/log_privacy.rs::logs_carry_route_templates_and_no_identifiers`; `relay/tests/door_log_privacy.rs::door_and_knock_logs_carry_no_identifiers`; `relay/tests/ws_log_privacy.rs`, `relay/tests/trace_logs.rs`; `directory/tests/trace_logs.rs` | Covered; SR-21; SR-14 fixed in #74 and #77, SR-15 in #74 |
| Stale door | Door expiry checked by the knocker | `card.rs`, `knocks.py` | `core/src/listing/card.rs::publish_time_checks` | Covered |
| | Relay answers `door_not_open` | `relay.rs` (`knock`) | `relay/tests/doors.rs::unknown_expired_and_closed_doors_are_not_open` | Covered |
| | Owner drops knocks on doors expired over 1 h | `knock.rs` (`Door::open_knock`) | `core/src/knock.rs::owner_checks_1_to_3` | Covered |
| | `seq`, tombstones, high-water mark | `core/src/listing/name.rs` | `core/src/listing/name.rs::a_superseded_key_cannot_take_the_name_back`; `directory/tests/vectors.rs::tombstones_block_only_their_own_identity` | Covered |
| Knock flooder | Relay limits | `relay.rs` (`knock`) | `relay/tests/doors.rs::one_knock_per_door_and_sender_per_ten_minutes`, `::twenty_knocks_per_sender_per_hour_across_doors`, `::per_door_overflow_is_accepted_and_dropped_silently`, `::forwarded_and_dropped_knocks_take_the_same_path_until_the_worker_writes` | Covered; SR-16 partly fixed in #74 |
| | Owner caps, 1 h lapse, local drops | `policy.py` (`SafetyPolicy.knock`), `knocks.py` | `daemon/tests/test_knocks.py::test_one_pending_knock_per_identity_and_a_full_door`, `::test_an_approval_lapses_at_ts_plus_an_hour` | Covered |
| Prompt injection through card text | Card text shown as data, never linked | `directory/src/mcp.rs`, `render.rs`, `knocks.py` (`_view`) | `directory/tests/render_props.rs::fenced_text_cannot_close_its_block`; `directory/tests/pages.rs::card_text_is_escaped_never_linked_and_fenced_in_markdown`; `directory/tests/mcp.rs::search_agents_returns_untrusted_results` | Covered (test gap 8); SR-20 |
| | One-line fields with caps | `core/src/listing/mod.rs` (`is_one_line_text`) | `core/src/listing/card.rs::line_breaking_and_disguising_characters_are_rejected` | Covered |
| | Knock approval is human | `runtime/api.py` | `daemon/tests/test_no_auto_approve.py::test_no_config_table_approves_knocks`, `::test_the_agent_token_cant_list_read_or_decide_knocks` | Covered |
| At-rest storage | SQLCipher MLS store and records database | `core/src/provider.rs` (`apply_key`), `core/src/db.rs` | `core/src/provider.rs::a_wrong_key_fails_cleanly`, `::an_unencrypted_file_is_refused`, `::the_database_file_holds_no_plaintext`; `harness/tests/test_storage_at_rest.py::test_the_data_directory_holds_no_plaintext` | Covered; SR-27 |
| | Key in the keyring or a 0600 file | `daemon/.../identity.py`, `keystore.py` | `daemon/tests/test_keystore.py::test_file_keystore_is_private_and_round_trips`; `harness/tests/test_storage_at_rest.py::test_a_wrong_or_missing_key_fails_cleanly` | Covered |
| | Plaintext dropped once delivered | `store.py` (`update_outbox`, `set_inbox_state`) | `daemon/tests/test_store.py::test_inbox_deduplicates_and_forgets_delivered_plaintext` | Outbox covered; inbox positive only (test gap 9) |
| Queue overflow | Marker means "possibly out of sync", never proof | `engine.py` | `harness/tests/test_scenarios.py::test_queue_overflow_marks_out_of_sync`; `relay/tests/delivery.rs::overflow_marker_is_sent_once_per_episode_and_delivery_resumes_after_drain` | Covered |

The five crypto negative tests AGENTS.md requires all exist:

- wrong secret: `core/tests/group.rs::wrong_invite_secret_fails_mac_and_welcome`,
  `core/src/export.rs::a_wrong_code_does_not_open_it`;
- tamper: `core/tests/group.rs::tampered_and_replayed_messages_are_rejected`,
  `core/tests/key_package.rs::tampered_or_truncated_key_package_is_rejected`;
- replay: `core/tests/group.rs::replayed_join_request_cannot_re_add_a_departed_member`,
  `relay/tests/rest.rs::a_replayed_signed_request_is_refused_but_a_fresh_one_is_not`;
- credential and key mismatch: `core/tests/key_package.rs::credential_identity_must_match_cert`,
  `::leaf_key_must_match_cert`;
- forked view gives a different SAS: `core/tests/group.rs::forked_group_view_gives_different_sas`.

### Test gaps

1. A Welcome whose ciphersuite isn't the v0 suite (`group.rs:841`,
   `group.rs:875`).
2. A KeyPackage with KeyPackage extensions or marked last resort
   (`mls.rs:347`).
3. Forward secrecy after removal: the existing test fails on OpenMLS's
   local `is_active` flag. No test keeps a removed member's state and tries
   to process the next epoch's messages with it.
4. A message from epoch e − 2 is refused (`MAX_PAST_EPOCHS = 1`).
5. The update cadence: both tests set the message counter directly; none
   checks that received messages increment it.
6. Post-compromise security: no test shows that a copied state can't
   decrypt after the victim's Update.
7. The relay side of a sealed knock carries no identity, display name or
   KeyPackage in clear.
8. The MCP tool `agentconnect_knock_inspect` returns `untrusted: true`.
9. An inbox row read after delivery has no plaintext.

### SPEC claims that don't match

1. §6.2 step 2: a failed MAC isn't counted toward rate limiting (SR-26).
2. §12, at-rest paragraph: "There is no unencrypted on-disk mode" doesn't
   hold for `a2a-seen.db` (SR-27).
3. §12, at-rest paragraph: "MUST NOT create a new key while either file
   exists": `identity.py:91` creates a key when a file exists but is empty.
   Harmless, but not the rule as written.
4. §12, at-rest paragraph: plaintext is also kept, encrypted, in the
   opt-in transcript, in held approvals and in the outbox row of a held
   send.
5. §12, "Scraper" row: doors rotate at half-life, about every 3.5 days by
   default, not weekly, and the lifetime can be as short as 2 hours.
6. §12, "Impersonator" row: only the slug is ASCII; the display `name` is
   one-line Unicode text, so lookalike display names remain possible.
7. §12, "Malicious directory operator" row: rollback bounded by token
   revocation holds only at an honest directory or a conforming mirror
   (SR-25). ADR-006's copy of the row already leaves it out.

## MLS usage

| Item | Result |
|---|---|
| One pinned suite, no downgrade | `CS` is the only suite (`core/src/mls.rs`); KeyPackages are checked on their raw bytes before OpenMLS (`precheck_key_package`), Welcomes before staging (`group.rs:841`, `group.rs:875`). There is no negotiation code. Sound; test gap 1. |
| Credential and key binding | Every leaf carries exactly one extension, `ac_instance_cert`; the certificate's identity must equal the credential and its `sig_key` the leaf key, checked with strict Ed25519 (`identity.rs`, `mls.rs:validate_leaf`). Receivers reject a commit whose update path changes the committer's certificate, and a second leaf with an existing `instance_id` (PR #52 review N1, fixed). Sound. |
| Invite MAC and PSK binding | HMAC-SHA256 under `join_key` over length-prefixed fields, verified in constant time (`join.rs`); the Welcome is ChaCha20-Poly1305 under `welcome_key` with the invite id in the AAD. No PSK is used and a Welcome with a PSK is refused. Sound; SR-26. |
| SAS from `epoch_authenticator` | Derivation matches SPEC §3.5 and the vectors. The derivation is correct but the design is grindable: **SR-01**. |
| Epoch conflicts | Own commits merge only on `accepted` for their `msg_id` or exact bytes; examined in depth by the PR #48 and #51 reviews. Sound. |
| Policy on received commits | Every receiver runs `authorize` against the policy in force at the commit's epoch (`group.rs:inspect_commit`, `policy.rs`); examined by the PR #48 and #52 reviews. Sound. |
| Removal cuts access | A removed leaf can't derive the next epoch's secrets (TreeKEM). The relay stops fan-out to removed mailboxes in the same transaction. Sound; test gap 3. |
| Update cadence | 24 h or about 1000 messages with a per-instance random threshold (`runtime/groups.py:update_due`). Sound; test gap 5. |
| Storage at rest | Both databases are SQLCipher with a raw 32-byte key; `apply_key` fails closed on a build without SQLCipher; the records key is HKDF-derived; key files are 0600 written through `mkstemp`, `fchmod` and `os.replace`. Sound, except SR-27. |

## Group mode

- **Unauthorized commits.** Each receiver enforces the §9.2 table itself;
  a rejected commit forks only its committer, who is reported with
  `unauthorized_commit` (`group_mode_tests.rs::unauthorized_commits_are_rejected_and_fork_only_the_committer`).
- **Multi-use invite abuse.** The replay ledger bounds each invite's share,
  pending approvals and the daemon-wide record (PR #45 review F1, fixed);
  a link holder can still make new requests with fresh KeyPackages, which
  the human sees and can revoke (accepted in that review, F6).
- **Fork detection through SAS:** weakened by SR-01 (fixed in #67).
- **Replicas and the floor.** Replica provisioning moves only `IK`, as a
  human operation (PR #55 review). The floor register was examined over
  five rounds in the PR #54 review, with no findings left. SR-35 is the
  remaining replica issue.

What a malicious member can do, with a modified daemon:

1. Read every message of every epoch it is a member of.
2. Send content to everyone, within the receivers' limits, and trigger
   their agents under the floor rules (SR-12, fixed in #89, raised that
   to the task budget); SR-33 keeps the loop guard from pausing it.
3. Commit an Update at any time, and so choose the next short code (SR-01).
4. Add identities if its identity satisfies `invite`, remove others if it
   satisfies `remove`, change the policy if it is the owner, and change
   the floor fields if it is an admin.
5. Add more instances of its own identity, up to `max_members`, and remove
   its own instances, whatever the policy says.
6. Stop the group by sending a commit the honest members reject (SPEC §12
   residual).
7. Wedge a receiver's inbound queue with one malformed message (SR-11,
   fixed in #87).
8. Send `control.close` (owner only), `control.pause`, `control.leave`,
   `control.capabilities`, and, with a modified daemon, `control.resume`
   with `origin: "human"` (SR-56).
9. Send Agent Cards with any text; they reach agents as untrusted context.
10. Learn every member's identity, instance ids, display names and, from
    the envelopes, mailbox ids, which it can use for SR-04 after it leaves.
11. Send `a2a.task_cancel` for any task; headless agents receive it
    (SR-38).

What it can't do: read epochs after its removal, forge another member's
messages, mark anyone verified or approve anything on another daemon,
change the policy beyond its role, re-add a used KeyPackage, or reuse
another leaf's `instance_id`.

## Discovery

- **Listings and owner verification.** The knocker verifies the JWS, the
  token against a pinned `DK`, the door expiry and the relay, applies a
  rollback guard, and fetches the owner file itself. The directory's owner
  fetcher is as strict as the daemon's: HTTPS on port 443, public
  addresses only with no rebinding, no redirects or proxies, a 64 KiB cap
  and a 5 s timeout (`directory/src/owner.rs:96-331`).
- **Doors and knocks.** Relay limits match SPEC §8.3, forwarded and
  dropped knocks look the same in the metrics, and the owner's checks run
  in the SPEC order. SR-15 and SR-16 leaked a little to the relay's logs and
  to the knocker's timing. #74 fixed the logs and moved the knock's write
  off its answer's path; #73's quota counters made the remaining write
  cheap whatever the owner's queue, so timing the relay across it tells
  nothing (SR-16 residual).
- **Replay ledger.** 65,536 entries; through an honest relay a flooder
  can deliver at most about 2,600 knocks per mailbox in 65 minutes, so it
  can't fill it. A malicious relay can, which is relay denial of service.
- **Directory operator trust.** Every mitigation of the §12 row is in
  place except revocation at the knocker (SR-25). SR-23, SR-24 and SR-45
  are smaller gaps.
- **Withdrawals.** A replayed withdrawal answers `changed: false`, an old
  one after a republish answers `stale_seq`, and a stale `ts` answers
  `stale_ts` (`withdrawal.rs:153-172`).

## Relay

What it stores, and for how long:

| Table | Columns | Kept |
|---|---|---|
| `invites` | `invite_id`, `group_name`, `inviter_name`, `purpose`, `expires_at`, `max_uses`, `uses_left`, `member_count`, `inviter_mailbox`, `revoked`, `created_at` | `expires_at` + 7 days |
| `groups` | `group_id`, `epoch`, `created_at`, `active_at` | until idle for 30 days with no member connected (SR-43, fixed in #71) |
| `group_members` | `group_id`, `mailbox` | until a commit's `routing.remove` names it, or its group is deleted |
| `messages` | `seq`, `mailbox`, `msg_id`, `payload`, `group_id`, `size`, `bucket`, `expires_at`, `marker` | until acked, or at most 7 days |
| `payloads` | `id`, `sender`, `group_id`, `size`, `env` (the envelope with `ct`) | until its last queue row goes (since #73) |
| `mailbox_usage`, `group_usage`, `sender_usage`, `sender_group_usage` | byte counters per mailbox queue part, per (mailbox, part, group), per sender and per (sender, group) | while non-zero (since #73) |
| `welcome_due` | `group_id`, `mailbox`, `added_by`, `expires_at` | until the Welcome, a removal or 7 days (since #73) |
| `seen` | `sender`, `msg_id`, `expires_at` | 7 days |
| `overflow` | `mailbox`, `bucket`, `group_id` | until the next enqueue for that group that fits |
| `doors` | `door_id`, `owner_mailbox`, `expires_at`, `closed`, `created_at` | until `expires_at` |
| memory | rate windows, the signed-request cache, live connections | seconds to 1 hour |

- **No plaintext and no invite secret reach it.** The relay parses only
  envelopes, `NewInviteRequest` and `NewDoorRequest`; `ct` is only checked
  as base64url; unknown invite fields are ignored and not stored. No IP
  address is stored.
- **Logs.** At debug: mailbox tags on connect and disconnect (SR-15), group
  and sender tags with the kind and recipient count on fan-out, the invite
  tag on a join. At warn: the group tag and overflow count. All tags are
  unkeyed 32-bit SHA-256 prefixes. The door and knock lines carry no
  identifiers. There is no access log. Third-party trace logs: SR-14
  (fixed in #74 and #77). Since #74: tags are keyed per process, connection lines carry none, and
  third-party crates log at `warn` and above only.
- **Metrics.** Counters `agentconnect_relay_{connections, auth_failures,
  frames, accepted, duplicates, deliveries, queue_overflows, commits,
  joins_forwarded, invites_created, invites_consumed, doors_registered,
  doors_closed, knocks_accepted}_total`, `errors_total{code}` with 11 fixed
  values, and the gauge `ws_connections_open`. No per-mailbox or per-group
  data (SR-42).
- **Mailbox authentication.** 32-byte challenge from `getrandom`;
  `verify_strict`; distinct labels for WebSocket and REST signatures; one
  canonical host form on both sides; REST signs method, path, `ts`, body
  hash and host, with the 300 s window and the `(mailbox, sig)` cache
  (SR-02, SR-44). The envelope `sender` must equal the authenticated
  mailbox on `send`, `join` and `knock`.
- **Frame parser.** Size checked before parsing; duplicate keys rejected;
  canonical unpadded base64url; `epoch` strictly a u64; id and mailbox
  formats; at most 50 routing hints each and 1 to 50 Welcome recipients;
  knock `ct` at most 16 KiB, checked before decoding; binary frames
  refused. SR-41 lists the lenient fields.
- **Delivery Service rules.** Commit check-and-increment is atomic (five
  concurrent commits at one epoch gave one `accepted` and four
  `epoch_conflict`); fan-out uses the membership before the hints; Welcomes
  only from members; `msg_id` idempotent per sender; `invite.consume`
  atomic; `group.create` of an existing id refused.
- **Limits:** SR-02 to SR-07, SR-13 and SR-17.

## Web

Landing page, `GET /i/{invite_id}`, as served:

```text
content-security-policy: default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
referrer-policy: no-referrer
x-content-type-options: nosniff
cache-control: no-store
```

- The page has no script, so nothing can read `location.hash`; the only
  other request is same-origin CSS without `url()` or `@import`;
  `<meta name="referrer" content="no-referrer">` is set as well. Browsers
  don't send the fragment, and the relay logs no path, User-Agent or
  Referer for `/i/{id}`, even at trace level.
- Every `InviteMeta` field is escaped (probed with `<script>`, `onerror`
  and a meta refresh); SR-19 (fixed in #71) was the remaining text issue,
  SR-49 is the page's wording.

Directory HTML pages:

```text
content-security-policy: default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
x-content-type-options: nosniff
referrer-policy: no-referrer
```

The same headers go on every directory response, and the CSP gains
`font-src 'self'` when fonts are served. Card text is escaped and never
linked; Markdown fences can't be closed by card text (probed with 2 to 5
backticks); `llms.txt` has slugs only; MCP checks `Host` and `Origin`.

## Daemon local API

- **Tokens:** 256-bit, kept only as SHA-256, compared with
  `hmac.compare_digest`; files 0600 through `mkstemp`, `fchmod` and
  `os.replace`; an existing token file readable by others is refused; no
  token in logs, URLs, errors, process arguments or child processes.
- **Socket and TCP:** the socket is bound under umask 077 and then set to
  0600 (0660 for the group in separate-OS-user mode); TCP binds only
  `127.0.0.1` and refuses any `Origin` and a foreign `Host`; clients check
  the socket server's UID before sending (SR-09, fixed in #103); TCP is TLS
  with a certificate the clients pin (SR-08, fixed in #107); unfinished
  connections give way to whole requests (SR-28, fixed in #61).
- **Separate-OS-user mode:** the peer's UID is checked with `SO_PEERCRED`
  or `getpeereid` before the request is read; the human token is accepted
  only from the daemon's UID or `human_users`; TCP and root are refused;
  the agent directory receives only `api-token` and `webhook-secret`.
  Packaging sets `UMask=0077`, `StateDirectoryMode=0700`,
  `RuntimeDirectoryMode=0750` and a sudoers `timestamp_timeout=0`. SR-29 is
  the gap.
- **Webhook:** HMAC-SHA256 over `<timestamp>.<body>`; the SDK verifier
  checks a 300 s skew before the MAC, compares in constant time and
  remembers seen signatures; no redirects and no environment proxies. There
  is no inbound callback route; replies go through the authenticated API.
  A receiver on a Unix socket is checked by its server's UID before a byte
  is sent (SR-10, fixed in #108); a TCP receiver, outside separate-OS-user mode,
  isn't.
- **A2A facade, MCP and SSE:** the facade binds loopback and checks `Host`,
  `Origin` and the client address; MCP tool descriptions and instructions
  are constants and ids are checked before they go into a path; SSE takes
  a bearer token only, sends no CORS headers and filters human-only events.
  SR-31 and SR-37 are the gaps; SR-30 is fixed for both clients.

## Policy layer

- **Peer messages and side effects.** Every peer-triggered side effect
  passes the MLS sender binding (inner `sender` and `instance_id` equal the
  leaf, `group.rs:1078-1091`), the size, kind and part checks, the control
  and card schemas, the rates, the holds, the loop guard, the floor and
  addressing rules and the `require_verified` gate before it reaches an
  adapter. The side effects are: the audit row, the loop-guard pause, floor
  register writes, `repeated_violations`, hop records, the loop-guard
  reset, `close_requested`, holds, transcript rows, adapter deliveries,
  stored cards, A2A agent calls and task continuation or cancellation, and
  facade replies. The gaps are SR-33 to SR-38 and SR-53 (SR-11 is fixed in
  #87, SR-12 in #89).
- **SAS verification stays human.** `set_verified` is reachable only from
  the human-token verify route, which requires the epoch shown and refuses
  `stale_epoch`; the CLI re-reads the epoch and the code before it records
  the answer; a mismatch is human-only too.
- **Human-only operations.** Every route marked human-only refuses the
  agent token. `origin: "human"` can't be set by the agent: `AgentApi.send`
  refuses human-only kinds, `queue_message` refuses them unless the origin
  is human, and `adapter_send` (used by the facade and A2A) hard-codes
  `origin: "agent"`. `control.resume` is refused on every agent path.

## Tool results

| Tool | Result |
|---|---|
| `cargo audit` (root `Cargo.lock`, 463 crates, and the three fuzz lock files) | No vulnerabilities. One allowed warning: RUSTSEC-2026-0173, `proc-macro-error2` unmaintained, a build-time dependency of libcrux's `hax-lib-macros`; ignored in `deny.toml` with that reason. |
| `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok`. |
| `pip-audit` 2.10.1 on `uv export --frozen --all-packages --all-groups --all-extras --no-emit-workspace` (81 pinned packages, `--no-deps --disable-pip`) | No known vulnerabilities. Environment markers were evaluated for the running interpreter. |
| `/security-review` (on the diff of PR #63, the only code change of this review) | No findings. The diff adds test-only fuzz targets in a detached workspace that nothing builds or ships, with no literal key material. |

Fuzzing: `cargo fuzz` with AddressSanitizer, 10 minutes per target, one
process each, on an 8-core host running all nine at once. Fresh corpora.
The toolchain was the pinned stable 1.99.1 with `RUSTC_BOOTSTRAP=1`,
because the installed nightly is older than the workspace's
`rust-version`.

| Crate | Target | New | Runs | Coverage (edges) | Result |
|---|---|---|---|---|---|
| relay | `frame_parser` | no | 20,528,446 | 1,251 | no crash |
| relay | `knock_frame` | no | 19,855,768 | 1,425 | no crash |
| core | `listing_parser` | no | 9,407,611 | 3,203 | no crash |
| core | `knock_open` | no | 1,746,122 | 2,747 | no crash |
| core | `owner_file` | no | 15,300,235 | 916 | no crash |
| directory | `card_text` | no | 50,306,930 | 1,913 | no crash |
| core | `mls_message` | yes | 46,445 | 17,459 | no crash |
| core | `join_and_welcome` | yes | 1,591,174 | 12,850 | no crash |
| core | `wire_json` | yes | 9,449,677 | 3,286 | no crash |

The new targets, added in PR #63:

- `mls_message` mutates a real application message, a commit with an
  update path and a leave proposal from a three-member group, or feeds raw
  bytes, to `peek_header`, `Group::open` and `Group::process`. It runs
  slowly because a failed message reloads the group from its store; most
  mutations stop at the AEAD, so it mainly exercises the framing and
  header paths.
- `join_and_welcome` sends mutated KeyPackages with a valid MAC to
  `verify_join_request` (any link holder can) and asserts that a changed
  KeyPackage never verifies; it also wraps mutated Welcomes under the
  invite for `join_from_wrapped_welcome`. The encrypted GroupInfo can't be
  reached by mutation.
- `wire_json` covers JoinRequests, invite links, `InviteMeta`, instance
  certificates, `ac_group_meta`, `ac_group_policy`, identity exports and
  wrapped Welcomes, with round-trip checks on the canonical encodings.

## External review

**Recommendation:** an external cryptographic and MLS review is needed
before any "1.0" claim, and before a public relay is described as more
than a preview. SR-01 shows that the protocol's composition with MLS has
properties that unit tests and per-PR reviews don't reach.

Suggested scope, in priority order:

1. **The SAS design**, including the fix chosen for SR-01, the
   forked-view analysis of SPEC §14.4, the trust states, and what a
   verified flag means after later commits and new instances. Ask for a
   symbolic model (Tamarin or ProVerif) of invite, join, knock and
   verification.
2. **The post-quantum suite integration:** suite TBD1 of
   `draft-ietf-mls-pq-ciphersuites` through OpenMLS 0.9.1 and the provider
   patched to an unreleased upstream commit, the labelled `DeriveKeyPair`,
   the KEM and key length checks, and hpke-rs 0.8.
3. **Invite and knock binding:** the JoinRequest MAC, the AEAD-wrapped
   Welcome without a PSK, the sealed knock (HPKE base mode, the signature
   over JCS, `welcome_secret`), the replay ledgers, and single-use
   KeyPackages.
4. **Commit authorization in `core`** (SPEC §8.3 and §9.2): own-commit
   confirmation, policy evaluation per receiver, owner transfer, leaves by
   reference, `instance_id` uniqueness and certificate pinning, ideally
   with a differential or model-based test against the SPEC table.
5. **Canonical encodings:** JCS, the I-JSON integer rule, listing JWS and
   the Unicode 17.0.0 one-line rule, for parser differentials between Rust
   and Python and other A2A tooling.
6. **Storage and key handling:** SQLCipher with a raw key, the derived
   records key, the keystore, zeroization, and what the Python bindings
   copy.
7. **The relay as metadata observer and as a hosted service:** what the
   Delivery Service rules reveal, and the denial-of-service fixes for
   SR-02 to SR-07.

## Follow-up tasks

One line per open item, ready to file.

- **T-01 (High, SR-01):** Redesign SAS verification so that no member can
  choose the code: commit-then-reveal nonces inside the group, with SPEC
  §11, vectors, CLI and daemon changes; state the residual in SPEC §1 and
  §12 until it lands.
- **T-02 (Medium, SR-02):** (done in #71) Relay: record signed REST requests only after
  validation, give each mailbox a bounded share of the replay cache, limit
  per source address, and drop the global refusal from SPEC §8.1.1.
- **T-03 (Medium, SR-03, fixed in #73):** Relay: store each payload once, accept Welcomes
  only for mailboxes the group's last commit added, cap Welcome `ct`, add a
  per-sender byte budget and a disk high-water mark.
- **T-04 (Medium, SR-04, fixed in #73):** Relay: give non-member traffic (Welcome, join,
  knock) its own per-mailbox sub-quota.
- **T-05 (Medium, SR-05, fixed in #73 and #74):** Relay: per-mailbox byte counter (or covering
  index), index on `(mailbox, msg_id)`, per-connection frame rate limit
  (the frame rate limit is done in #74).
- **T-06 (Medium, SR-06):** Relay: cap drain batches by bytes, cap
  connections per mailbox and in total, time out stalled sends. Done in #74.
- **T-07 (Medium, SR-07, SR-43):** (done in #71) Relay: quotas for open invites and new
  groups per mailbox, REST limits per mailbox and address, and a SPEC rule
  for deleting idle groups and stale memberships.
- **T-08 (Medium, SR-08, fixed in #107):** Daemon: stop sending bearer tokens to
  an unauthenticated server over loopback TCP. Done with TLS and a pinned
  certificate.
- **T-09 (Medium, SR-09, fixed in #103):** Daemon, SDK, MCP: check the short socket
  directory and socket owner before connecting.
- **T-10 (Medium, SR-10, fixed in #108):** Daemon: Unix-socket callbacks, or a receiver
  MAC before a 2xx counts as an ack; required in separate-OS-user mode.
- **T-11 (Medium, SR-11, SR-54, fixed in #87):** Daemon: bound `hop` to u32, limit body
  depth and size of `to` and `addressee`, and fail a poison message per
  message (ack, consume, tell the human).
- **T-12 (Medium, SR-12, fixed in #89):** Daemon: task budget and triggering only for
  updates that reply to this instance's own message; update SPEC §9.3 and
  §10.2.
- **T-13 (Low, SR-13):** Relay: header-read timeout, accept concurrency
  limit, WebSocket ping and idle timeout. Done in #74.
- **T-14 (Low, SR-14):** Relay and directory: clamp `tungstenite`,
  `axum::serve`, `hyper` and `hyper_util` logs whatever `RUST_LOG` says;
  correct `relay/README.md`. Done: the relay in #74, the directory in #77.
- **T-15 (Low, SR-15):** Relay: keyed log tags (per-process HMAC key), no
  mailbox tag on connect lines, and a log-privacy test through `ws.rs`.
  Done in #74.
- **T-16 (Low, SR-16):** Relay: answer `accepted` for a knock before the
  enqueue. Partly done in #74: the answer goes first and knocks are written
  by a worker on a 250 ms tick, forwarded and dropped alike, so the next
  frames' timing is at chance (52% on the review's probes, with a small and
  a 60,000-message owner queue). The residual, a knocker probing
  continuously across the next tick seeing the write (46 ms against 7 ms
  with the large queue), is gone with #73's quota counters: the same probe
  tells the two apart at chance (45% to 60% single-shot accuracy, against
  95% to 98% on main before it, on the same machine).
- **T-17 (Low, SR-17, fixed in #73):** Relay: cap `join_request` `ct` and count joins in
  the non-member sub-quota.
- **T-18 (Low, SR-18, fixed in #73):** Relay: `secure_delete` and periodic WAL
  checkpoints.
- **T-19 (Low, SR-19):** (done in #71) Relay: apply the one-line text rule to
  `InviteMeta` strings at registration (SPEC §4.2).
- **T-20 (Low, SR-20):** Directory: put the verbatim signed listing in
  `/search` and MCP `search_agents` results.
- **T-21 (Low, SR-21):** Directory: log the HTTP method from a fixed set.
- **T-22 (Low, SR-22):** Directory: a trusted-hop count for
  `X-Forwarded-For`, and docs against listing shared CDN ranges.
- **T-23 (Low, SR-23):** Directory: keep revoked token ids until the
  revoked token can't be valid any more.
- **T-24 (Low, SR-24):** Directory and daemon: treat listings with an
  unpinned token key as expired; add `unknown_key` to `STOP_RENEWING`.
- **T-25 (Low, SR-25):** Daemon: check token revocations from the
  withdrawals feed before knocking, or correct the SPEC §12 row.
- **T-26 (Low, SR-26):** Daemon: count failed-MAC JoinRequests per invite
  and tell the human past a threshold (SPEC §6.2 step 2).
- **T-27 (Low, SR-27):** Daemon: move the A2A seen set into the encrypted
  records database.
- **T-28 (Low, SR-28, fixed in #61):** Daemon: per-peer connection caps and a reserve
  for the human UID on the local API.
- **T-29 (Low, SR-29):** Daemon: refuse a group-writable agent directory
  and check its parents.
- **T-30 (Low, SR-30, fixed in #108 and #113):** Daemon: `trust_env=False` and no redirects in the
  A2A adapter and facade HTTP clients.
- **T-31 (Low, SR-31):** Daemon: screen facade push URLs, or turn push
  configs off.
- **T-32 (Low, SR-32):** Daemon: filter hidden groups from the agent's
  status, pending counts and SSE group checks.
- **T-33 (Low, SR-33):** Daemon: an agent's hop is at least its last
  trigger's hop + 1 until a resume, whatever `reply_to` names.
- **T-34 (Low, SR-34):** Daemon: make `close_requested` a human event, or
  hold its reason behind the verification gate.
- **T-35 (Low, SR-35):** Daemon: don't trigger an instance on its own
  identity's messages in `free` mode unless addressed.
- **T-36 (Low, SR-36):** Daemon: bound the drain exemption per identity
  across connections and in time.
- **T-37 (Low, SR-37):** Daemon: a member-addressed facade request accepts
  replies only from that member.
- **T-38 (Low, SR-38):** Daemon: deliver a non-requester's
  `a2a.task_cancel` to headless agents as context, and document the rule.
- **T-39 (Low, SR-39):** Release: verify cosign bundles in
  `release-verify`, test it, and require the reproducibility check before
  publishing.
- **T-40 (Low, SR-40):** CI: run every fuzz target for a bounded time in
  the nightly workflow.
- **T-41 (Info, SR-41):** Relay: reject envelope fields SPEC §7.1 doesn't
  give the kind.
- **T-42 (Info, SR-42):** Relay and directory: serve `/metrics` on a
  separate listener by default.
- **T-44 (Info, SR-44):** (done in #71) Relay: read the clock once per replay check.
- **T-45 (Info, SR-45):** Directory: make owner-revocation feed entries
  verifiable by mirrors, or say in SPEC §13.2.5 that they aren't.
- **T-46 (Info, SR-46):** Directory: `Cache-Control: private` or
  `no-store` on responses with a query.
- **T-48 (Info, SR-48):** Relay: `nosniff` and `Cache-Control` on
  `GET /v0/invites/{id}`.
- **T-49 (Info, SR-49):** Relay: reword the landing page's statement about
  the secret.
- **T-51 (Info, SR-51):** Daemon: apply the `callback_url` rule to
  `a2a.local_agent_url`.
- **T-53 (Info, SR-53):** Daemon: restrict control words to
  `[a-z0-9._/-]`.
- **T-59 (Info, SR-59):** SPEC: correct the seven §12 statements listed
  under [SPEC claims that don't match](#spec-claims-that-dont-match).
- **T-60 (Info, SR-60):** Tests: add the nine tests listed under
  [Test gaps](#test-gaps).
