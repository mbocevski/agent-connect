# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The wire protocol is versioned separately (see `SPEC.md` §13).

## [Unreleased]

### Added

- MCP adapter: `agentconnect mcp`, a stdio MCP server that an agent tool
  (Gemini CLI, Cursor and other MCP clients) starts per session
  (docs/adapters/mcp.md, ADR-005). It runs the runtime in its own process on
  `$XDG_DATA_HOME/agentconnect-<--agent>`, or attaches to the MCP session or
  daemon that holds that data directory, and takes the directory over when
  the MCP session that held it ends. Its tools wrap the agent-scope
  operations only: `agentconnect_create_group`, `agentconnect_invite`,
  `agentconnect_accept`, `agentconnect_send`, `agentconnect_groups`,
  `agentconnect_leave`, `agentconnect_events`, `agentconnect_wait`,
  `agentconnect_knock_inspect`, `agentconnect_knock`, `agentconnect_knocks`
  and `agentconnect_listing_status`. `agentconnect_wait` waits on the
  runtime (at most 300 seconds, cancellable) and returns each message once,
  with the SPEC 10.1 notice always in front of the text and `untrusted` set.
  Approving joins and knocks, verify, the safety policy and publishing stay
  CLI commands with the human token: no tool exposes it, and an attached
  session reads `api-token` only. It stops
  on stdin EOF or SIGTERM with the runtime's bounded flush; stdout carries
  MCP only. New dependency: `mcp` (MIT).
- Daemon: `daemon.default_adapter = "mcp"`, a delivery queue in the
  encrypted database for MCP sessions attached to the daemon, and the
  agent-scope routes `GET /v0/deliveries` (a long poll that leases messages
  for 120 seconds under a lease token, at most 4 waiting per token) and
  `POST /v0/deliveries/ack` (only the lease's ids), and
  `POST /v0/deliveries/release` (give a lease's ids back at once).
  Authenticated agent-token requests may use 48 of the local API's 64
  connections, so they can't take every one. The data directory's lock
  note names an MCP server as its holder.
- Daemon and CLI: knocking on a listing, and approving knocks
  (docs/discovery.md, SPEC 6.6). `agentconnect knock <host>/a/<name>`
  (agent token, unless the new `[knock] agent_may_knock` is off) fetches
  the listing from the pinned `[[directory]]` and checks it again whatever
  the directory says: signature and canonical form, its name and
  directory, the token under the pinned keys, the relay, the door, and a
  rollback guard against an older listing than one seen before. It fetches
  the owner domain's file itself (asked first, `knock.domain_check`), shows
  the listing's text as unverified, and sends a knock the core builds and
  seals. The knock waits until `ts + 3900`; with no answer it lapses as "no
  answer" and its secret and KeyPackage keys are deleted. A Welcome is
  joined only if it is the listed identity's new group of two; one that
  opens but isn't raises `relay_misbehaviour`. On the owner's side, knocks
  on the listing's doors are checked by the core, recorded in a replay
  ledger persisted with everything else they lead to, and held for the
  human: `approvals` lists them with the knocker's claimed name and note
  and what the daemon knows of its identity, and `approvals approve
  <kn-id> [--purpose]` (human token only) creates the new group and adds
  the knocker. There is no automatic approval of knocks: no setting,
  policy verdict, agent route or SDK call does it, and `policy.auto_approve`
  never applies to knocks. Rejections, lapses and every drop send the
  knocker nothing. The owner's knock events (`knock_received`,
  `knock_approved`, `knock_rejected`, `knock_expired`,
  `knock_approval_failed`) and knock counts are the human's only; the
  knocker's (`knock_sent`, `knock_failed`, `knock_lapsed`, `joined` with a
  `knock_id`) are seen by both tokens. New routes: `POST /v0/knocks/inspect`,
  `POST /v0/knocks`, `GET /v0/knocks`; `GET /v0/approvals` lists knocks
  (`kind`), and `POST /v0/approvals/{rid}/approve` takes a `purpose`. New
  `[knock]` limits, each at most the SPEC's: `max_outgoing`, `per_hour`,
  `max_pending_per_door`, `opened_per_door_per_minute`,
  `failures_per_sender_per_hour`, `ledger_capacity`. New CLI commands
  `knock` and `knocks`, and exit code 7 for a listing that fails
  verification. Group views gain `origin` and, on the knocker's side,
  `listed_as`. Every new step resumes after a crash (failpoints `knock.*`,
  `knock_welcome.*`, `knock_send.after_core`, `knock_approve.after_group`,
  `knock_add.after_welcome`). An approved knock's group is hidden from the
  owner's agent until the knocker is in, and the knocker's claimed name never
  reaches that agent; `GET /v0/knocks` shows the human what an agent knocked
  on (name, fingerprint, owner state, description); knocks started at once
  can't pass the outgoing limits; a Welcome the relay can't take yet is
  retried. While the group is hidden, the knocker's messages wait in the
  owner's inbox and its events reach the agent, in order, once it is
  visible; the hidden state and the group's `origin` are kept on the group,
  and a failed approval that never added the knocker deletes its group. The
  core's test-only knock hook is behind a `test-hooks` cargo feature, off in
  the release wheel (`scripts/check_wheel_hooks.py` checks it).
- Daemon and CLI: publishing a listing (docs/discovery.md). `agentconnect
  listing publish --directory <host>` (human token only; the agent token
  gets `403 human_only`) reads the card text and the operator's listing
  token from files as the calling user, has the daemon check them against
  the directory pinned in a new `[[directory]]` table (`host`, `keys`,
  `url`; no default) and the runtime's identity, shows what will be signed,
  and then registers a fresh door at the relay, signs and posts the
  listing. With an owner domain it fetches that domain's owner file under
  the SPEC §13.2.4 address rules and prints the entry to add. The runtime
  then renews the door at half its lifetime (`[listing]
  door_lifetime_secs`, default 7 days less 1 hour, never past the token),
  keeps the old door until it expires, deletes each door key an hour after
  its door expires, retries a directory that doesn't answer with the same
  signed bytes, and reports `listing_stale`, `listing_token_expiring` and
  `listing_token_expired`. `agentconnect listing withdraw` (either token)
  closes every door at the relay before sending the withdrawal, and
  `listing status` shows the listing. New routes: `POST
  /v0/listing/preview`, `POST /v0/listing/publish`, `POST
  /v0/listing/withdraw` and `GET /v0/listing`. Door keys are kept in the
  daemon's encrypted database, and every step resumes after a crash
  (failpoints `door.after_register`, `listing.after_sign`,
  `listing.after_post`, `withdraw.after_close`). The `[[directory]]` and
  `[listing]` tables refuse unknown keys and `auto_approve`, and an
  `https://` directory URL on a loopback or private address. A failed
  publish puts the listing back exactly as it was (a withdrawn listing stays
  withdrawn); a directory answer that can't be read is checked against the
  listing, never taken as a refusal; a door the relay may hold is kept until
  the relay confirms it closed; only `token_revoked`, `bad_token` and
  `name_held` stop renewal, other refusals are retried and reported. Only
  known directory codes and owner states come through. The last signed
  relay request's `ts` is kept across restarts, unless it is more than a
  minute ahead of the clock. A withdrawal the directory never takes is
  reported after an hour, stops after 7 days (`withdraw_failed`), and
  `listing withdraw --force` (human token, only for a pending or failed
  withdrawal) ends it locally as `withdrawn_locally`. The worker sleeps
  on one timer set against the clock (`Clock.sleep_until`), and retries
  door closes with a backoff. The preview hash covers the card, the token, the directory and
  the owner domain. The core bindings gain `check_directory_keys`, the
  pinned-key check every verification makes.
- Directory: `AC_DIRECTORY_FONT_DIR` serves the font files in a directory at
  `/static/fonts/<file>` and adds `font-src 'self'` to the
  Content-Security-Policy, so a replacement stylesheet can use its own
  fonts. Off by default, and the policy is unchanged without it.
- Relay: `/metrics` exposes `agentconnect_relay_ws_connections_open`, a
  gauge of the WebSocket connections open now. It carries no labels or
  identifiers, and a drop guard takes each connection off the count exactly
  once, however the connection ends.
- Core: approving a knock and joining from its Welcome, and listing
  renewal (SPEC §6.6.4, §6.6.5, §13.2.2), with Python bindings.
  `Group::add_knocker` (`Client.add_knock`) commits the Add of an approved
  knock's KeyPackage in a fresh group of the owner's own (one leaf, owned
  and created by it, floor `free`, no admin or moderator but the owner,
  epoch 0) and wraps the Welcome under the knock key. On the client's clock
  it refuses a knock past its `lapses_at` or stamped more than 300 s
  ahead; it also refuses a used KeyPackage and a knock from the owner's own
  identity. A pending own commit now reserves the KeyPackages it Adds, so
  neither `add_knocker` nor `add_member` can Add one KeyPackage in two
  groups at once. `Client::join_from_knock_welcome` and
  `join_knock_journaled` (`Client.join_knock`) check the Welcome against
  the listing: its name, `created_by` and `owner`, epoch 1, floor `free`,
  no roles for another identity, and exactly two members, the knocker and
  one instance of the listed identity. A mismatch spends the KeyPackage and
  has the new error kind `welcome_mismatch`; a Welcome after `gives_up_at`
  is refused unopened (kind `expired`). A knock join's journal entry is
  bound to the knock and the listing, so it never replays for another knock
  or an invite join. `Client::restore_knock` rebuilds a verified knock
  from `VerifiedKnock::to_secret_bytes` with its KeyPackage and signature
  checked again, so an approval can wait across a restart, and
  `create_knock_at` (`create_knock(ts=...)`) stamps the caller's clock.
  `ListingContent` is the card text a human approves, in its own closed
  schema (`canonical_listing_content`, `sign_listing_content`), and
  `SignedListing::renew` (`Listing.renew`) re-signs only `door`, `seq`
  and `issued_at`, never with a lower `seq` or an earlier `issued_at`.
  The public-address rule for outbound fetches moves from the directory to
  `agentconnect_core::net::is_public_ip` (`is_public_address`), so the
  directory and the daemon share it, and it now also refuses `3fff::/20`
  (RFC 9637), with a rule of its own for every IPv6 special-purpose block.
  Vectors: `listings.json` gains a renewal and content cases, and
  `public-addresses.json` is new.
- Embedded SDK mode (ADR-005): `AgentConnect.embedded(name="my-agent")`
  runs the AgentConnect runtime inside the agent's own process and asyncio
  loop, so a headless agent needs no separate daemon, and no second
  process holds its keys. Messages and events reach the handlers through an
  in-process adapter (`agentconnect.callback.CallbackAdapter`) with the
  webhook's semantics: a handler that raises, or runs past
  `sdk.handler_timeout_secs` (default 120 s, then cancelled), is retried
  with backoff, in order within its group, and logged without the message.
  The ids handlers finished with are kept in the runtime's encrypted
  database, namespaced by kind, group and sender, so a redelivery after a
  crash or restart doesn't reach user code and a peer can't pick a `msg_id`
  that hides an event or another sender's message. The data directory is
  `$XDG_DATA_HOME/agentconnect-<name>` (or `data_dir=`, `AC_DATA_DIR`), one
  per identity; an `AC_DATA_DIR` that disagrees with `name=` is refused.
  Starting fails with `DataDirLockedError` when a daemon or another
  embedded agent holds the directory. The embedded runtime serves the same
  local API socket, so the human runs `agentconnect approvals`, `verify`
  and `safety set` against it with `AC_DATA_DIR`; the SDK offers no human
  operation and never reads the human token. `async with` and `aclose()`
  give running handlers and queued sends a bounded window (3 s), then stop
  and release the lock, and are safe to cancel; concurrent calls share one
  start or stop; a cancelled `aclose()` still stops the runtime and
  releases the lock first. Called from inside a handler, `aclose()`
  schedules the shutdown and returns, and `serve()` returns once the
  runtime has fully stopped. A handler that ignores the timeout's
  cancellation is abandoned after a grace and its message redelivered; one
  that ends with a stray `CancelledError` is retried like any failure. `AgentConnect.attach()` names today's mode against a
  separate daemon; both modes have the same API, errors and framing. See
  `docs/sdk.md`.
- `agentconnect.runtime.Runtime`, the embeddable runtime (ADR-005): the
  engine, the local API, an `AdapterRegistry` and `AgentApi`, the
  agent-scope operations that the local API's agent-token routes and the
  embedded SDK both call. `agentconnectd` is now a thin host over it
  (`agentconnect.daemon.serve`), and on SIGINT or SIGTERM it gives queued
  sends up to 3 seconds to go out. `agentconnect.callback.CallbackAdapter`
  hands messages and events to Python callbacks in-process, with the
  webhook adapter's retry rules.
- The daemon failpoint `delivery.after_adapter`, between an adapter's ack
  and the inbox recording it.
- Discovery: the directory of signed listings (`directory/`, ADR-006). Its
  pages are a plain, unbranded default (system fonts, light and dark, no
  JavaScript) that operators restyle with `AC_DIRECTORY_STYLESHEET`;
  `AC_DIRECTORY_HOST` is required, with no built-in directory host. It
  serves search (`/search`, JSON), the exact signed card
  (`/a/<name>.json`), listing pages in HTML with a Markdown copy
  (`/a/<name>.md`, or `Accept: text/markdown`), `llms.txt`, and an MCP
  server at `/mcp` with `search_agents` and `get_card`, whose results carry
  `untrusted: true`. Publishing (`POST /v0/listings`) is authenticated by the
  listing's JWS and operator token only, and withdrawing
  (`POST /v0/withdrawals`) by an IK-signed withdrawal, which applies at once
  and enters the feed. The owner domain's
  `/.well-known/agentconnect.json` is checked on publish and every 6 hours,
  with no redirects and no private addresses. The store is Postgres with
  full-text search. Logs and metrics carry no identifiers, and rate limits
  are per address and in memory. Every signature, token and canonical-form
  check is the core's (`agentconnect_core::listing`), under the operator
  keys pinned in `AC_DIRECTORY_TOKEN_KEYS`, and refusals carry the core's
  error `kind`. Who may publish a name is the core's `NameRecord`: `seq`
  and tombstones are per (name, identity), a new identity takes a name only
  under a later-issued token, and the newest token ever accepted for a name
  is kept, so a name can't go back to a rotated-out key (`name_held`). A
  listing whose owner state becomes `revoked` is withdrawn, and that
  identity can't list the name again until it has a token issued more than
  the 300 s publish skew after the revocation. The owner domain is also
  checked when the identity withdraws, or relists without it or under
  another domain, so withdrawing ahead of the recheck doesn't escape a
  revocation, and a change of owner domain is shown like a change of key.
  Tombstones are never purged. Postgres is reached with TLS and
  `sslmode=verify-full` unless it is a Unix socket or a loopback address
  literal, or `AC_DIRECTORY_DB_INSECURE` is set. A client-address header is
  believed only from `AC_DIRECTORY_TRUSTED_PROXIES` (blocks broader than /8
  or /32 need `AC_DIRECTORY_TRUST_ANY_PROXY=1`) and is walked from the right
  past trusted hops, writes are also limited per listing name, and the
  limiter is sharded with constant-time eviction. See `directory/README.md`.
- `just test-int` runs the integration tier: the directory's Postgres store
  in docker compose (`compose.test.yaml`).
- Separate-OS-user mode for the daemon (`isolation.enabled`): the daemon
  runs as its own user, so agents with a shell under another user can't read
  the human token, the keys or the data directory. The socket and copies of
  `api-token` and `webhook-secret` live in a group-readable agent directory;
  each connection's peer UID is checked (`SO_PEERCRED` on Linux,
  `getpeereid` on macOS) against `isolation.agent_users`, and the human
  token is accepted only from the daemon's own UID or
  `isolation.human_users` (`403 peer_refused`). The daemon refuses to start
  as root, on TCP, or with a data directory, token or agent directory that
  is too open. The human runs the human-only commands with
  `sudo -u agentconnect agentconnect ...`. `packaging/` has a systemd unit,
  sysusers.d and tmpfiles.d snippets, a sudoers drop-in and a launchd plist.
  See `docs/isolation.md`.
- Relay: doors and knocks (ADR-006). `POST /v0/doors` (signed) registers a
  door that maps a public `door_id` to the owner's mailbox for at most 7
  days, with at most 4 open doors per mailbox. `DELETE /v0/doors/{door_id}`
  (signed, owner only) closes it at once. The WebSocket `knock` frame
  forwards a sealed `knock` envelope (`ct` at most 16 KiB, never parsed) to
  the owner as a normal `deliver`. The new error `door_not_open` answers
  knocks to unknown, expired or closed doors. Knocks are limited to 1 per
  door and sender per 10 minutes and 20 per sender per hour
  (`rate_limited`). Past 10 per door per minute, or when the owner's queue
  is full, a knock is dropped but still answered `accepted`. There are no
  delivery receipts and no reject frame.
- Core: discovery (`agentconnect_core::listing` and `::knock`, with Python
  bindings), the one implementation the directory and the daemon verify
  through. Signed listings: the closed AgentCard schema and text limits,
  one-line text everywhere (no control, format, separator, private-use or
  unassigned characters of Unicode 17.0.0, no default-ignorable or blank
  characters, no space but U+0020, at most 4 combining marks in a row, and
  NFC; the same for knock display names and notes, JoinRequest display
  names and group names and purposes),
  the canonical JCS profile (non-canonical bytes are rejected), and the
  single `EdDSA` JWS by the identity key, which a2a-sdk's own verifier
  accepts; the token's binding to the listing is checked as part of
  parsing. Operator listing tokens checked against pinned directory keys
  (90-day lifetime, not-before, expiry, revocation), token revocations,
  `seq` and tombstones per (directory, name, identity) with
  `SignedListing::replaces`, `tombstoned_by` and a `NameRecord` that keeps
  each name's token high-water mark and
  tombstones for directories and mirrors, so a superseded key can't take a
  name back,
  withdrawals, and the owner well-known file with its owner states (a
  negative result is sticky until a later fetch vouches, and a file that
  doesn't parse counts as a failed fetch; `OwnerHistory` in Python). Doors
  (HPKE key pairs in the v0 suite, checked when loaded), sealed and signed
  knocks, the owner's checks 1 to 5, a `KnockLedger` that drops replayed
  knocks by `knock_id` and KeyPackage until they lapse (bounded, never
  evicting a live entry, and exportable so the daemon persists it), and the knock
  Welcome wrap. A knock to a door key HPKE refuses leaves no KeyPackage
  behind, and `Client::forget_knock` deletes a lapsed knock's KeyPackage. Vectors in `testdata/`
  (`listings.json`, `listing-tokens.json`, `withdrawals.json`,
  `owner-files.json`, `knocks.json`), property tests and a `core/fuzz`
  target for the parsers. Every core error has a stable kind
  (`Error::kind()`, `AgentConnectError.kind` in Python: `signature`,
  `unknown_key`, `expired`, `revoked`, `token_mismatch`, `door_expired`,
  `stale_timestamp` and so on), so callers never match on messages.
- Protocol: discovery (ADR-006). SPEC gains signed listings, a closed A2A
  AgentCard profile carrying the `e2e` extension
  (`https://yggdrasill.network/ext/agentconnect/e2e/v0`) and one `EdDSA`
  JWS by the identity key (§13.1); directories with operator-signed
  listing tokens, token revocations, signed withdrawals, the owner
  `/.well-known/agentconnect.json` file and its states, and the cache and
  mirror rules (§13.2); doors and sealed, signed knocks that become new
  two-member groups on human approval only (§6.6); the `knock` envelope
  and frame, `POST`/`DELETE /v0/doors` and `door_not_open` (§7.1, §8); and
  the new threat-model rows (§12).
- Linux arm64 and macOS arm64 support. CI runs the fast tier on both and
  builds the relay container image for `linux/amd64` and `linux/arm64`.
  Releases add an aarch64 manylinux 2.28 `agentconnect-core` wheel, an
  aarch64 relay binary and a macOS arm64 `agentconnect-core` wheel, all
  signed and attested. The reproducibility check covers both Linux
  architectures. See ADR-001 for the platform table.
- Safety policy (`agentconnect.policy`): every decrypted message gets one
  decision before any adapter sees it (`deliver`, `deliver_as_context`,
  `hold_for_approval` or `drop` with a reason), and every message the agent
  sends goes through it too. The SPEC 10.2 limits, the 7.3 control rules and
  the loop guard moved into it unchanged. See `docs/safety.md`.
- Every A2A part must have exactly one content member that matches its
  `kind`, and no other members but `metadata`, `filename` and
  `mediaType`; any other part is `malformed`. The daemon, the A2A adapter
  and the SDK apply the same rule (`testdata/a2a-parts.json`), and the
  approval preview shows every member of a part.
- The loop guard decides on the hop alone, so its pause no longer tells a
  peer whether the policy accepted a probe. The reconnect drain's rate
  exemption is bounded per identity (twice its per-sender rate). An
  `a2a.task_cancel` delivered as context no longer cancels the A2A agent's
  task, and the A2A facade answers a held send with an `input-required`
  task instead of timing out. Adapters' sends return a `SendReceipt` (the
  `msg_id`, with `held`).
- The transcript is capped per group (`policy.transcript_max_rows`, 10000)
  and for the whole daemon (`policy.transcript_max_bytes`, 64 MiB), oldest
  first, and the audit log's 100000-row cap holds on every row.
- The approval preview shows every part (data as JSON, files by name, type
  and size), the body's other fields and the routing, and
  `approvals approve --yes` needs `--full` when the preview was cut. The
  CLI prints every peer-controlled string with control characters
  replaced, the audit log records unknown kinds as `unknown`, and the
  SPEC 10.1 notice quotes and cleans the sender's name and the scope.
- Audit rows come in two classes, drops and decisions, with their own caps:
  a sender's flood of drops can no longer push out the deliver row of the
  injection it sent before.
- Held messages: each identity may have at most its byte share waiting
  (`policy.max_held_bytes_per_sender`, 1 MiB, or `max_held_bytes` divided
  by the senders waiting), and a task approval covers a peer task's later
  updates for `policy.task_approval_window_secs` (600 seconds, at most
  3600) instead of `approval_ttl_secs`.
- The adapter, SDK, webhook and API docs list `send_approved` and the codes
  of a held send's `send_failed`, and no longer say the policy's own events
  reach the webhook.
- A facade request cancelled while its send waits for approval withdraws
  the send (audited as `cancelled`, `send_failed` code `cancelled`), so a late
  approval can't send it. `send_approved` and a held send's `send_failed`
  carry its `hold_id`, and adapters' `SendReceipt` has `hold_id` and
  `withdraw()`.
- The A2A facade follows a held send through: its task waits in
  `input-required`, moves to `working` when the human approves (the agent's
  adapter gets a new `send_approved` event), receives the peer's reply, and
  ends `rejected` or `failed` if the human rejects it or the hold expires.
- `agentconnect events` and `agentconnect approvals` (list) now need the
  human token. With the agent token, `GET /v0/approvals` lists only the
  agent's own held sends (no join requests, no held peer messages) and
  `GET /v0/status` counts only those.
- The audit log and the transcript are also capped per group and per sender
  (`policy.audit_max_rows_per_group` 20000, `policy.audit_max_rows_per_sender`
  2000, `transcript_max_rows_per_sender` 1000, `transcript_max_group_bytes`
  16 MiB), and the daemon-wide transcript cap takes from the biggest group
  first, so one sender can't flush the record of the others. Each cap is
  enforced through an index, with running byte totals.
- The held-message expiry timer logs a failure by type, backs off and keeps
  running (failpoint `held_timer.expire`).
- Held messages: each direction has its own queue, the per-sender cap also
  counts all instances of an identity, and a full group queue drops a new
  message as `hold_queue_full` (no violation) unless its sender holds its
  fair share already. Approving a peer task's first update covers only that
  task's inbound updates, for `approval_ttl_secs` or until the task ends;
  the agent's own task updates are each held.
- Held messages: the queue is capped per group (100), per sender instance
  (20) and in bytes (8 MiB; `policy.max_held_per_group`,
  `max_held_per_sender`, `max_held_bytes`), and a message over a cap is
  dropped as `hold_overflow` and counts as a violation. A task is held once,
  on its first update, and decided whole. Holds expire on a timer, are
  decided exactly once, and fail with `send_failed` code `group_gone` when
  the group ends. `message_held` is recorded with the hold. The policy's
  events are the human's: they no longer reach the agent's adapter, and
  `GET /v0/events` leaves them out for the agent token.
- Rate limits: received and sent messages have separate budgets, so a
  member's own sends no longer make honest peers look like violators and
  peer traffic can't stop the human's sends; the human's control messages
  are never rate limited. Task updates also count against an identity cap
  (3 times the task budget) and a group cap (`policy.group_task_per_minute`,
  1200). The limiter and the violation counters are bounded and forget a
  group once it ends.
- Control messages, Agent Cards and task cancellations keep only the fields
  their schemas define: unknown fields are stripped (SPEC 7.2), and a body
  that carries content (`parts` anywhere, or a top-level `text`, `data`,
  `file` or `raw`) is malformed, so they can't carry text, data or files
  past `require_approval` or the file-part ban. An Agent Card the A2A
  types can't parse is dropped as `malformed`, so its signature check is
  never skipped. A card's signature
  is verified against the pinned keys first (a failing card is dropped as
  `bad_signature`), its known A2A fields are kept exactly as sent, a card
  over the ADR-006 listing limits is refused rather than cut, our own card
  goes out as built, and with inbound approval a changed card is held.
  Controls and cards are delivered as context only, the SDK shows no text
  for them (a card is in `msg.card`), and the agent token can't send them.
  The safety and adapter docs say card text is untrusted peer content,
  never to be pasted into a prompt as instructions.
- Per-group safety settings with per-sender overrides of the limits: message
  size, messages a minute per sender and per group, a per-task budget for task
  updates (300 a minute), and `file` parts (off by default, with a size cap
  when on). Defaults come from new `[policy]` keys in `config.toml`;
  `agentconnect safety show|set` and `GET|POST /v0/groups/{gid}/safety`
  (human token to change) override them.
- `require_approval` (`inbound`, `outbound` or `both`): agent messages wait
  for the human, who sees them with `agentconnect approvals` and decides with
  `approvals approve|reject <id>` (human token). Held messages raise
  `message_held` and expire after `approval_ttl_secs` with `held_expired`,
  without telling the sender.
- `repeated_violations` event when one sender breaks the policy
  `violation_threshold` times (10) within `violation_window_secs` (600). The
  daemon never removes a member on its own; the new `agentconnect remove`
  (human token, `POST /v0/groups/{gid}/members/{identity}/remove`) lets the
  owner or an admin do it.
- Audit log in the encrypted daemon database: who, when, kind, size and the
  decision for every message in and out, never a body, kept 30 days
  (`agentconnect audit`, `GET /v0/audit`, human token). An opt-in
  per-group transcript keeps full messages, also encrypted, for
  `transcript_retention_days` (`agentconnect transcript`).
- The A2A adapter honours the group's `frame_text` (the notice is the first
  part only while both `a2a.frame_text` and the group's setting are on) and
  adds `frame_text` and `notice` to the call's `metadata`, next to
  `scope`. `require_approval` also holds `a2a.task_cancel`.
- Webhook and SSE payloads carry `frame_text` and `notice` (the SPEC 10.1
  sentence); `POST /v0/groups/{gid}/messages` answers with `status`
  (`queued` or `held`); `GET /v0/status` counts `held_messages`.
- Webhook adapter (`daemon.default_adapter = "webhook"`): every message and
  event is POSTed to a loopback `webhook.callback_url` (remote hosts need
  `webhook.allow_remote` and https), signed with HMAC-SHA256 over
  `timestamp.body` under a per-daemon `webhook-secret`. A 2xx acks; other
  responses retry with backoff on the daemon clock, in order, at least once.
  See `docs/adapters/webhook.md`.
- SSE adapter (`default_adapter = "sse"`): `GET /v0/events` with
  `Accept: text/event-stream` streams the same payloads from a durable feed
  and resumes with `Last-Event-ID`, also across a daemon restart. The feed
  exists only with the SSE adapter and keeps items `sse.retention_secs`
  (default one hour); a consumer resuming from before that gets an
  `sse_gap` event;
  `GET /v0/events?group=` filters the JSON log by group.
- Python SDK (`agentconnect-sdk`): `AgentConnect`, groups, invites, replies
  that carry `reply_to`, task status and artifact replies, webhook
  signature verification, and deduplication by `msg_id` and `event_id`. It
  uses only the agent-scope API token. See `docs/sdk.md`.
- Examples for the Claude Agent SDK and for three LangGraph agents in a
  `mention` group, tested with stubbed models.
- Protocol: `a2a.task_cancel` (an A2A `CancelTaskRequest`, sent only by the
  task's requester), the optional inner `addressee` field that names
  exactly who a message triggers (SPEC §9.3), a per-task budget of 300 task
  updates a minute (§10.2), and the Agent Card trust rules (§10.5). The
  local API's send takes `addressee`, webhook and SSE payloads carry it,
  and the SDK's `reply`, `reply_status` and `reply_artifact` send to the
  group with the requester as `addressee`.
- A2A adapter (`[a2a]` in the daemon config, `docs/adapters/a2a.md`), on
  `a2a-sdk` 1.2.2. Messages that trigger this member become
  `SendStreamingMessage` calls (`SendMessage` as a fallback) to a local
  A2A v1.0 agent, with `contextId` = the group, the SPEC §10.1 framing in
  `metadata` and the messages that didn't trigger it as
  `metadata.context_messages`. The agent's status, artifact and message
  events go back as `a2a.*` messages with `reply_to`; `input-required`
  follow-ups and `a2a.task_cancel` reach the agent's task. Replies go to
  the whole group with the requester as `addressee`. The local Agent Card
  is sent on join; card signatures are checked against pinned keys.
  Deliveries and events are deduplicated by `msg_id` and `event_id`.
- A2A facade: an A2A server on `127.0.0.1` (bearer token, loopback only)
  at `/g/<group_id>/` and `/g/<group_id>/m/<identity>/`, with a mirrored
  (1:1) or composite (group) Agent Card, streaming, `GetTask`,
  `CancelTask`, `SubscribeToTask` and push-notification configs.
- Generated reference docs: `just docs-gen` writes the CLI commands and
  options, exit codes, `--json` shapes, local API routes and errors, and
  config keys into `docs/cli.md`, `docs/api.md` and `docs/config.md` from the
  code, and a fast-tier test fails when the committed docs are stale.
- ADR-005 (accepted): deployment modes. One embeddable runtime with three
  hosts (separate daemon, embedded SDK, MCP-spawned), attach to a running
  instance on a locked data directory (default for MCP, opt-in for the SDK),
  `$XDG_DATA_HOME/agentconnect-<name>` data directories, one daemon per
  identity, human-only operations over the local API in every mode with the
  human token kept as a 0600 file, and a per-mode security comparison.
- Security notes in the README and `daemon/README.md`: don't give agents
  shell or file access to the AgentConnect data directory, because an agent
  that can read it can approve joins and mark codes verified as you.
- Docs gate: `docs/MAP.toml` maps user-facing code (CLI, local API, daemon
  config, relay protocol, `testdata/` wire formats) to the docs that must
  change with it, checked by `scripts/check_docs.py` in the pre-push hook,
  `just docs-check` and a CI `docs` job; the `skip-docs` PR label skips it.
- Markdown checks in the pre-commit hook and CI: rumdl lint, lychee
  relative-link and anchor check (external links nightly), and Vale prose
  rules against filler, hype, absolute security claims and emoji.
- The README quickstart runs as a test against a local relay and two
  daemons, from `invite create` to a verified group and a delivered message.
- Docs: daemon configuration (`docs/config.md`) and the local control API
  (`docs/api.md`).
- Daemon core (`agentconnectd`, package `agentconnect`): identity and
  instance in the OS keyring or 0600 key files, the core's encrypted MLS
  store, a persistent relay WebSocket with challenge auth and jittered
  reconnect backoff, signed invite REST calls, durable outbox and inbox
  (at-least-once, deduplicated by `msg_id`, relay acks only after the adapter
  accepted), relay-confirmed commits with `epoch_conflict` rebuilds,
  routing-hint and epoch checks that raise `relay_misbehaviour`,
  `out_of_sync` on queue overflow or a lost own commit, the §3.1 Update
  cadence, an adapter interface with the §10.1 untrusted framing, a policy
  hook, and a local JSON control API (Unix socket or loopback TCP) whose
  approve and verify operations need a separate human token.
- CLI: `agentconnect daemon run` and `agentconnect status`.
- CLI invite lifecycle (`group create`, `invite create|revoke`, `accept`,
  `groups [show]`, `approvals [approve|reject]`, `verify`, `leave`, `send`,
  `events`), each with a stable `--json` shape and documented exit codes
  (`docs/cli.md`). `approve`, `reject` and `verify` use the human token.
  `accept` shows the invite, asks first and prints the short code;
  an already used or revoked invite prints the interception warning and exits
  with code 4.
- Local API: `POST /v0/groups/{id}/policy` (`require_verified`; relaxing it
  needs the human token) and the joiner's `fingerprint` in `GET /v0/approvals`.
- Multi-node test harness (`harness/`): the real relay on a random port,
  in-process daemons with recording adapters on a shared fake clock, and a
  per-daemon proxy for partitions and malicious-relay behaviour (drop,
  reorder, replay, inject, routing rewrites, forged replies, forks).
- Relay (`relay/`): MLS Delivery Service with commit ordering and fan-out,
  per-instance mailboxes with store-and-forward, invite registry and join
  forwarding, single-use signed-request REST auth with a bounded replay
  cache, Prometheus counters, SQLite storage behind a `Store` trait, and a
  container image (`relay/Dockerfile`). A full mailbox no longer blocks a
  fan-out: it receives one `queue_overflow` marker per episode instead.
- Protocol: `SPEC.md` now specifies signed REST requests and the replay cache
  (§8.1.1), queue overflow, the commit fan-out set, welcome rules, error
  mapping, invite registration limits and a threat-model note on dropped
  messages.
- Invite landing page served by the relay at `GET /i/{invite_id}`: no
  JavaScript, strict CSP, light and dark themes.
- `agentconnect-core` crypto core on OpenMLS with the v0 ciphersuite only
  (`MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`): identities, instances
  and JCS-signed instance certificates; invite URLs, `join_key`/`welcome_key`,
  JoinRequest MAC and AEAD-wrapped Welcomes; group create/join/add/remove/
  update/leave/policy change with relay-confirmed pending commits; receiver
  enforcement of the group policy and of instance-certificate binding on
  every commit; HPKE key-length checks before OpenMLS (mitigates
  RUSTSEC-2026-0331); application padding buckets; SAS; SQLite and in-memory
  storage.
- Python bindings for the core (`agentconnect_core`): identities, invites,
  join requests, groups, messages and SAS, bytes in and bytes out.
- Relay authentication signing in the core: `Instance.sign_relay_challenge`
  (SPEC §8.2) and `Instance.sign_relay_request` (§8.1.1), with the signed
  message layout shared by core and relay and a contract vector
  (`testdata/relay-auth.json`). Signing happens in the core and no generic
  signer is exposed; the instance key itself still passes through Python
  as bytes when the daemon stores it.
- Shared test vectors in `testdata/` for key derivation, SAS, padding,
  instance certificates and invite URLs (`just vectors` regenerates them).
- Spike validating OpenMLS 0.9 with post-quantum hybrid ciphersuites
  (`spikes/mls-xwing`), with findings and decisions in
  `docs/spikes/mls-xwing.md`.
- Protocol specification v0 draft (`SPEC.md`): MLS groups with a
  post-quantum hybrid ciphersuite (ML-KEM-768 + X25519, MLS WG draft),
  invite links with AEAD-wrapped Welcomes, SAS verification, relay Delivery
  Service, group roles and floor control, threat model.
- ADR-001 recording the tech stack, crypto and tooling decisions.
- Repository skeleton: Rust workspace (`core`, `core-py`, `relay`) and uv
  workspace (`daemon`, `sdk/python`).
- `agentconnect version [--json]` CLI command.
- Relay `/healthz` endpoint.
- Linting: ruff and ty (Python); rustfmt, clippy, rustdoc, cargo-shear and
  cargo-deny (Rust); taplo (TOML); shellcheck; actionlint; typos; gitleaks.
  `just lint`, `just lint-py`, `just lint-rust`.
- `scripts/hygiene.py`: rejects AI-tool attribution and internal tooling
  references in files, commit messages and PR text (hooks, CI, `just merge`).
- Repository configuration as code: Dependabot (cargo, uv, Actions,
  pre-commit hooks, Rust toolchain), a `v*` tag ruleset, CODEOWNERS, and PR
  and issue templates.
- Tooling: justfile, prek hooks (pre-commit, commit-msg, pre-push), CI,
  nightly audit/mutation runs, reproducibility check, signed release workflow,
  and local merge gating (`just merge`).
- Test strategy (`TESTING.md`): tiers, placement and flaky-test rules, a
  `Clock`/`FakeClock` in `agentconnect-core` and `agentconnect.clock`, seeded
  randomness via `AC_TEST_SEED` and Hypothesis profiles, cross-language
  contract data in `testdata/` (with the Matrix SAS emoji table) checked by
  `just contract`, and a coverage ratchet (`coverage-baseline.json`).
- README gate (`docs/MAP.toml`, `scripts/check_docs.py`): the Status section
  has one bullet per `[[component]]`, marked `<!-- component: name -->`, and
  `just docs-check` fails when a bullet and a component don't match, when a
  Cargo or uv workspace member is in no component, or when a `.rs` or `.py`
  source file is in no rule and not `internal`. A branch that adds a
  CHANGELOG `Added` entry and changes a component's paths must change
  `README.md` too, unless the PR has the `skip-readme` label. New rules
  cover signed listings and knocks in the core, the embeddable runtime, the
  separate-OS-user mode and the whole directory.

### Changed

- Protocol: group mode (SPEC §9). The policy gains `floor_pinned` (default
  false): the `free` → `mention` floor switch is refused while it is true,
  and a policy change that sets `floor` should set it. The switch now
  counts identities, not instances, so a new instance of a member no
  longer switches a 1:1 group; `max_members` still counts instances.
  Admins may change `floor_pinned` with the floor. `moderated` mode gets
  floor control: the effective moderator (`floor_moderator` while it is a
  member, otherwise the owner) or the owner grants the floor with
  `control.floor`, ordered by `seq`, and each instance keeps the holder,
  which resets when it has no instance left or a commit changes `floor` or
  `floor_moderator`. A leaver sends `control.leave` before its self-Remove
  proposal, and membership changes only with the commit. Task replies
  should name the requesting instance in `body.metadata.instance`. An
  owner instance should drop departed identities from `admins` and
  `floor_moderator`. A new instance of a verified identity keeps the flag
  and is shown as new. A knock Welcome must have `floor_pinned` false
  (§6.6.5). The threat model gains a member stalling the group with a
  rejected commit, instances added with a stolen `IK`, and floor holders
  that differ when grants are dropped (§12); §14 gains the leave and the
  owner transfer. New vectors in `testdata/group-policy.json`: the default
  and valid and invalid policies, checked in Rust and through the Python
  bindings, and commit authorisation cases checked in Rust, with the
  `floor_pinned` and identity-counting cases marked pending until the core
  implements them. The core doesn't implement the new rules yet.
- Local API: with the agent token, `GET /v0/events` numbers events with a
  sequence of the agent's own (`seq`, and `after` takes it), with no gap
  where an event the agent doesn't see was recorded. Before, the global
  `seq` showed how many held-message events (and now knock events) the
  agent wasn't shown. The human token's `seq` is unchanged. An agent that
  stored an `after` from before this change should start again from 0.
- Core: HPKE `DeriveKeyPair` for the v0 suite's KEM (`MLKEM768-X25519`) now
  follows `draft-ietf-hpke-pq`, `SHAKE256.LabeledDerive(ikm,
  "DeriveKeyPair", "", 32)`, as implemented by hpke-rs 0.8 (SPEC §3.1). It
  was the unlabeled `SHAKE256(ikm, 32)`. Every HPKE key pair of the suite
  changes for the same input (KeyPackage, TreeKEM path and door keys,
  `external_pub`), so daemons built before this don't interoperate on
  commits that carry an update path; v0 is unreleased, so there is no
  migration, and the derivation is fixed for v0 from here on. The
  door-key vectors in `knocks.json`, `listings.json`, `listing-tokens.json`
  and `withdrawals.json` are regenerated from their stored seeds, and the
  draft's own test vectors (`testdata/hpke-pq-test-vectors.json`, vendored
  byte-for-byte) are a known-answer test in Rust and Python.
- There is no built-in relay any more: `relay.url` (daemon, CLI, embedded SDK) and
  `AC_DIRECTORY_RELAYS` (directory) are required.
- The daemon's protocol engine and local API moved into the
  `agentconnect.runtime` package (ADR-005): `agentconnect.daemon.Daemon` is
  now `agentconnect.runtime.engine.Engine` and `agentconnect.api` is
  `agentconnect.runtime.api`. `load_token` and the token file names moved to
  `agentconnect.tokens`. The engine's log records now come from the logger
  `agentconnect.engine` (was `agentconnect.daemon`); nothing else changes.
- The local API keeps only the SHA-256 of `api-token` and `human-token`
  (read once at start, compared in constant time), not their values.
- The data-directory lock records its holder, so a second runtime's error
  says whether a daemon or an embedded agent has the directory, and its pid.
- `agentconnect-sdk` depends on `agentconnect` (the runtime and the CLI).
- Deliveries to adapters (webhook, SSE, A2A and the embedded SDK) run per
  group: in order within a group, but a slow or failing delivery holds up
  its own group only, not every group.
- A Unix socket path longer than the platform allows (103 bytes, the macOS
  limit) is bound at `/tmp/agentconnect-<uid>/<hash>.sock`, in a 0700
  directory the runtime creates and checks; the CLI and the SDK derive the
  same path, from the resolved path, so a symlinked data directory finds
  it too. The socket's times are refreshed on every connection, so `/tmp`
  cleaners don't age it out while it's used. Separate-OS-user mode refuses
  such a path at startup instead.
- The multi-node harness runs every scenario on both hosts, the separate
  daemon and the embedded SDK, and the Python suite runs on all cores with
  pytest-xdist (`just test`, `just cov`).
- The planned A2A extension URI in SPEC §13 is
  `https://yggdrasill.network/ext/agentconnect/e2e/v0`. The project doesn't
  hold `agentconnect.dev`, so nothing refers to it any more.
- SPEC 10.2: the limits are maximums. Receivers may lower them, never raise
  them, and a `[policy]` value or group setting above one is an error.
  Per-sender rates count per instance, with a cap for all instances of one
  identity (`policy.identity_rate_multiple`, 3 times the per-sender rate),
  so replicas each get a rate but can't multiply their identity's budget.
  Receivers must not tell a sender that its message was dropped, held,
  rejected or expired. A new informative SPEC 10.6 describes local policy
  (approvals, framing, local limits).
- SDK: `msg.text` puts the SPEC 10.1 notice in front of the text while the
  group's `frame_text` is on (the default). The text alone is now
  `msg.raw_text`.
- `Daemon` no longer takes a `policy=` hook; `PolicyHook`,
  `PassThroughPolicy` and `PolicyDecision` are replaced by the safety policy.
- The `text` shorthand of `POST /v0/groups/{id}/messages` (and so `agentconnect
  send`) now sends an A2A v1.0 `Message` (`messageId`, `contextId`, `role`,
  `parts`) instead of a bare `{"text": ...}` body (SPEC 7.2).
- Adapter contract: messages and events are delivered **at least once**,
  each with a stable id; adapters deduplicate by `msg_id` and `event_id`.
  Every event now has an `event_id` derived from its cause, so one
  regenerated after a crash keeps its id, and it is recorded before the
  adapter hears of it and sent again on start and reconnect until
  `on_event` returns. A crash can no longer lose an event, security alerts
  included. `GET /v0/events` carries `event_id` too.
- README rewritten: what AgentConnect does, how it works, current status,
  quickstart, and the security model with what it does not protect against.
- Daemon: on a SAS mismatch the owner's last instance first commits an
  ownership transfer (to the lowest-index admin, else the lowest-index
  other member) and waits up to 10 s for the relay, then deletes its local
  state whatever the outcome; `sas_mismatch` reports the new owner and
  whether the transfer was confirmed. Once confirmed, the former owner
  proposes its own removal like any member. SPEC §9.2 and §11 describe
  this, including that a transfer from a forked view leaves the real group
  ownerless and its members must recreate it.
- Protocol (`SPEC.md`): the twelve daemon choices that were pending in §15
  are now normative, as the maintainer decided: the Update cadence counts
  both directions (§3.1); the approval timeout is silent and pre-Welcome
  traffic is parked, bounded and unacked (§6.2, §6.3); one pending approval
  per KeyPackageRef (§6.2); the epoch drop rule covers application
  messages and proposals while commits are merged and flagged (§7.1); the
  inner `reply_to` field (§7.2); `control.close` prompts the human
  (§7.3); the canonical `relay_host` (§8.1.1) and the `drained` frame
  (§8.2); replica triggering (§9.4); `trust_state` counts identities
  (§10.1); the reconnect-drain exemption (§10.2); `hop` checks against
  `reply_to` (§10.3); and an owner's SAS mismatch (§11). §15 keeps one new
  question: §9.2 doesn't let the remaining members remove that owner's leaf.
- Daemon: a proposal whose envelope epoch isn't the current epoch is
  dropped with `relay_misbehaviour` (`epoch_mismatch`), while a commit
  with a mismatched envelope epoch is still merged and flagged (SPEC
  §7.1). An owner's `control.close` raises a `close_requested` event
  for the human and never leaves on its own; a non-owner's is ignored.
- Relay and daemon: after `ready` and the flush of everything queued for
  the mailbox, the relay sends `{"t": "drained"}` (SPEC §8.2). Messages
  delivered before it, the reconnect drain, are exempt from the §10.2
  per-minute rates (at most 1000 per connection; size, kind and part
  limits still apply), so messages queued during an outage are no longer dropped
  while live floods still are.
- Protocol (`SPEC.md`): now normative, as decided by the maintainer:
  pending leaves are committed by the lowest-index leaf that isn't leaving
  (§9.2); `trust_state.self` is `verified` only when every other current
  member is, and `require_verified` holds deliveries until then (§10.1,
  §10.4); `moderated` triggers only the moderator until floor control
  exists (§9.3); v0 is single-relay and an invite for another relay is
  rejected (§4.4). Also normative, as implied by the existing text:
  malformed envelopes are dropped before processing (§7.1), and control
  messages from senders §7.3 doesn't allow (an agent's `control.resume`)
  are ignored. Twelve further choices the daemon makes are listed in §15
  as pending a maintainer decision, each with a recommendation.
- Daemon: relay `rate_limited` and `internal` replies to a commit are
  retried with backoff under the same bytes and `msg_id` instead of
  discarding the commit (and failing an approved join). A message or commit
  that finally fails raises `send_failed{msg_id, code}` or
  `commit_failed{intent, code}`. REST transport errors and non-JSON
  replies become `RelayError` (`relay_unreachable`, `internal`), and a
  failed invite registration never leaves its secret behind.
- Daemon: core errors are classified. Storage, RNG and internal errors and
  core panics are transient: the frame is neither recorded nor acked and is
  retried in order with backoff (`processing_failed` after 8 attempts,
  redelivered on the next reconnect). A commit for the current or a later
  epoch that can't be merged marks the group `out_of_sync`
  (`commit_rejected`) instead of leaving the member silently forked.
- Protocol: `SPEC.md` now states as normative text what the core does
  where it was silent: when HPKE key lengths are checked and that parent
  nodes are included (§3.1), canonical JCS with no unknown fields for
  policy, meta and certificates (§3.2, §3.3), invite URL parsing rules
  (§4.1), the fingerprint format (§2), single-use KeyPackages (§6.2),
  own-commit confirmation, pending-commit handling and the grace window
  (§8.3), the envelope epoch check (§7.1), policy defaults and the floor
  switch (§9.1), and Add/Remove authorisation (§9.2). Open questions that
  need a decision are listed in §15.
- Relay: the frame limit is now 2 MiB (SPEC §8.3), so an application
  message padded to the 1 MiB bucket fits once base64url-encoded in an
  envelope. Before, anything above about 786 KiB was refused as
  `too_large`.
- Protocol and core: the JoinRequest MAC now covers `display_name`, and
  every MAC field is length-prefixed (`u32be(len) ‖ bytes`, SPEC §6.1), so
  the relay can't rename the joiner the inviter approves. Display names
  with control characters are rejected. `testdata/invite-kdf.json` gains
  `display_name` and the exact `mac_input`.
- Core: `Group::add_member` borrows the `VerifiedJoinRequest`, and the
  Python `VerifiedJoinRequest` is no longer used up by a failed
  `add_member`, so an inviter can retry after `CommitPending` or an
  `epoch_conflict`.
- Protocol: `SPEC.md` states that KeyPackages have no lifetime cap beyond
  reuse tracking (§6.2) and records the maintainer's decisions on the
  former open questions (§15).
- Protocol and core: the owner must transfer ownership before it leaves
  (SPEC §9.2). `propose_leave` refuses the owner's last instance with
  `NotPermitted`, and receivers reject that leave proposal and any commit
  that removes the owner's last instance (`unauthorized_commit`), so a
  group can no longer end up ownerless. One of several owner instances may
  still leave, and a sole member still only deletes its state.
- Core: application messages in the one-epoch grace window are attributed
  to the sender as it was in the message's epoch, so a message from a
  member removed by the latest commit is delivered instead of dropped, and
  a re-used leaf can't be mistaken for its previous occupant.

### Fixed

- Core and protocol: the one-line text rule (SPEC §13.1.2) allows exactly
  one emoji presentation selector (U+FE0E or U+FE0F) right after a
  character with the Unicode `Emoji` property (Unicode 17.0.0), so a red
  heart (U+2764 U+FE0F) works in display names, group names, knock text
  and listings. It was refused as a `Default_Ignorable_Code_Point`. A
  selector anywhere else, a doubled one and every other ignorable
  character, the zero-width joiner included, are still refused.
- Policy: a sender that holds nothing in the approval queue is never
  charged a `hold_overflow` violation. With many senders waiting, or the
  caps at their minimums, the per-sender byte share fell below one message
  and a sender's first message counted against it; now a sender holding
  nothing is within its share, and a full queue drops its message as
  `hold_queue_full`, which is no violation. The group caps still bound the
  queue.
- CLI: a group, invite or request id that starts with `-` (base64url ids
  can) is read as the id, not as an unknown option, by every command that
  takes one positionally (`groups show`, `verify`, `leave`, `send`,
  `invite revoke`, `approvals approve`/`reject`).
- Local API: an invite for a different relay is refused with its own error,
  `400 wrong_relay`, instead of a generic `bad_request`; the CLI maps the
  code (not the message text) to exit code 3.
- Daemon: cancelling a task while it was cleaning up helper tasks (the wait
  for a winning commit, the ownership hand-over, `stop()`, and closing the
  webhook and SSE adapters) no longer swallows the cancellation; the task
  stops. `stop()` still releases its databases and data-directory lock,
  and a cancelled A2A adapter close still stops its facade and closes its
  deduplication store.
- Daemon: an application message or proposal whose envelope `epoch` or
  `group_id` disagrees with its MLS header is now dropped before the core
  processes it (SPEC §7.1), so it no longer consumes the message's key; a
  wrong `group_id` raises `relay_misbehaviour` (`group_mismatch`). The core
  and its bindings gain `peek_header`, which parses only the unprotected
  `PrivateMessage` header and touches no keys or storage.
- The daemon no longer freezes at 100% CPU when the relay connection closes
  while the outbox has work queued (on a relay drop or on shutdown). A send
  on the closed socket now takes the link down at once, so the outbox waits
  for the reconnect instead of retrying in a loop that never yielded to the
  event loop. Stopping the link also marks it down before closing the
  socket.
- A crash or an exception between the core processing a message and the
  daemon recording it no longer loses the message (ADR-004). The core's
  MLS state, its records and a new processing journal share one SQLCipher
  connection, so every operation is one transaction and the result
  (decrypted message, commit summary, joined group) is stored with the state
  change. The daemon records the effects of each result in one transaction
  of its own, then consumes the journal entry and acks the relay; on start it
  finishes any entry a crash left behind, and a redelivered frame gets its
  journalled result back instead of failing on a consumed key. This covers
  application messages, other members' commits, own-commit confirmations,
  leave proposals, Welcomes, removals and invite registration, and transient
  retries stay exactly-once at the adapter. A failed processing step now
  rolls back completely instead of leaving a half-written MLS state.
- The daemon database uses `synchronous=FULL`, so a power loss can't undo a
  transaction whose effects (frames sent, acks) already went out.

### Security

- Core, daemon and SPEC: an invite JoinRequest that was rejected, lapsed
  or dropped could be delivered again by the relay (or anyone holding the
  envelope) and passed every check again, so a request the human rejected
  could come back in front of them while a multi-use invite stayed open.
  The inviter now remembers every JoinRequest that passed its checks, by
  its envelope `msg_id` and its KeyPackageRef, until its invite's
  `expires_at` plus 300 s, and drops a replay silently: no approval, no
  event, nothing to the joiner, one audit row (`join_replay`). The approval
  timeout runs from receipt, so the invite's expiry is the bound a replay
  can't reset; after it the invite refuses the copy. The record is
  persisted in a new `join_ledger` table of the encrypted database in the
  transaction that records the approval, reloaded on start, bounded (when
  full, new requests are dropped as `join_ledger_full` and nothing live is
  evicted) and purged on the clock's current time. SPEC §6.2 states the
  rule ("Replays"), as §6.6.3 step 6 does for knocks. The core's replay
  ledger is shared by both: `agentconnect_core::ledger` (`ReplayLedger`,
  `MemoryLedger`, `LEDGER_GRACE_SECS`) replaces the knock-only
  `KnockLedger` and `MemoryKnockLedger`, with `Error::Replayed` and
  `Error::LedgerFull` for the `replay` and `busy` kinds;
  `VerifiedJoinRequest` gains `forget_after` and `remember_in`, and Python
  gets `ReplayLedger` (with `seen`, and `id_len=16` for knock ids) in
  place of `KnockLedger`. New daemon failpoints `join_request.in_tx` and
  `join_request.after_tx`; with `policy.auto_approve` the approval and its
  Add are recorded in the same transaction as the request, so a failure
  after it can't leave the approval waiting until it lapses.
  - A leaked invite link can't fill the ledger for every invite. Each entry
    records its invite; a revoked, expired or used-up (`exhausted`)
    invite's entries are forgotten
    at once (both are final, and step 1 refuses any copy); each invite holds
    at most max(4 × `max_uses`, 64) entries, at most the new
    `policy.join_ledger_per_invite` (default 1024, 64 to 1024), and at most
    the new `policy.max_pending_joins_per_invite` (default 32, 1 to 32)
    pending requests; requests being added or added don't count against the
    share. Past either, requests for that invite are dropped
    (`join_invite_quota`, `join_invite_full`), and the human gets a new
    `invite_flooded` event, once per invite and reason, which the agent token
    and the adapters never see, suggesting revoking the invite. Creating an
    invite fails with `409 too_many_invites` when the open invites' shares
    plus their uses would exceed the ledger's 65536 entries; if it fills
    anyway, requests are dropped as `join_ledger_full` and the human gets a
    daemon-wide `join_ledger_full` event (once a day, no invite named).
    Forgetting the expired invites of one pass rebuilds the ledger once.
    SPEC §6.2 allows forgetting at revocation, expiry and use-up, and
    recommends the per-invite bounds.
  - The ledgers load in full and purge only in the runtime's passes. The
    knock ledger's load used to purge on the start-time clock (since the
    knock ledger landed), so a clock that was ahead at start and put right
    before the next knock forgot live entries; the join ledger shared that
    load.
- Dependencies: RUSTSEC-2026-0329 (`libcrux-hmac-drbg` 0.0.1),
  RUSTSEC-2026-0330 and RUSTSEC-2026-0331 (`libcrux-kem` 0.0.9) are cleared
  and no longer ignored by `cargo deny`. `openmls_traits`,
  `openmls_libcrux_crypto`, `openmls_memory_storage` and the unbuilt
  `openmls_rust_crypto` are patched, here and in the three fuzz workspaces,
  to upstream OpenMLS commit `be2368a21ec5e0380abd568821addc57b79013ea`,
  which uses `libcrux-kem` 0.0.10, `libcrux-hmac-drbg` 0.0.2 and `hpke-rs`
  0.8; the rest of OpenMLS stays on crates.io (ADR-001 §2). The HPKE key
  length check stays.
  - `scripts/check_cargo_patch.py check` (in `just lint`) fails when a
    workspace lacks the root's exact patch table, when a patched git rev
    isn't a full commit SHA, or when any `Cargo.lock` holds `libcrux-kem`
    < 0.0.10 or `libcrux-hmac-drbg` < 0.0.2.
  - The nightly `audit` job runs `check_cargo_patch.py upstream`, which
    fails once crates.io has an `openmls_libcrux_crypto` release on the
    fixed libcrux crates that works with the pinned `openmls`: the
    condition for removing the patch.
- Relay and directory images: the runtime base is now
  `gcr.io/distroless/base-nossl-debian12:nonroot`, pinned by digest, instead
  of the floating `cc-debian12:nonroot`. The images no longer carry `libssl3`
  (CVE-2026-84782, no Debian fix yet), which neither binary links or loads.
  Dependabot keeps the digest current.
- Daemon: agent messages carry the `msg_id`s they reply to in a new inner
  `reply_to` field (SPEC §7.2, at most 16). A receiver that knows any of
  them treats the message's `hop` as at least one more than theirs, so a
  peer can't reset the loop guard by understating `hop`.
- Core, relay and daemon: the relay host signed into relay authentication
  has one canonical form (`canonical_relay_host`: no userinfo, ASCII
  lower-case, explicit port kept), applied inside the core's signing
  messages and to the relay's `AC_RELAY_HOST` and the daemon's config, so
  signer and verifier can't disagree on case or userinfo. Invalid hosts
  are refused. `testdata/relay-auth.json` gains the canonical-form cases;
  `Instance.sign_relay_request` now raises for an invalid host.
- Core and daemon: `VerifiedJoinRequest.key_package_ref` exposes the
  KeyPackageRef, and the inviter keeps one pending approval per
  KeyPackage, so a relay replaying a JoinRequest under fresh `msg_id`s no
  longer stacks up approvals for the human.
- Daemon: a peer's Agent Card, and the display name it sets, are kept only
  once the card's delivery has passed the `require_verified` gate and the
  policy hook, and `GET /v0/groups/{id}` returns each card as
  `{"untrusted": true, "card": {...}}` (SPEC §10.1). Previously cards
  were stored and served raw on receipt, ahead of the gate.
- Daemon API hardening: a request must arrive within 10 s (408), at most 64
  connections are served at once (503), the Unix socket is bound under a
  0077 umask and an existing non-socket file at its path is never
  replaced, token files must be owned by the user with mode 0600, and in
  TCP mode requests with an `Origin` header or a foreign `Host` are
  refused.
- Daemon: invite and join secrets no longer outlive their invites. An open
  invite past `expires_at` is marked expired and its secret deleted, and a
  pending join past its invite's expiry fails (`join_failed`, reason
  `expired`) and deletes the URL it kept. Frames parked for a pending
  join are deduplicated, capped per group and in total, and dropped once
  no join is pending, so a relay can't grow them without bound.
- Daemon API: `POST /v0/groups/{gid}/sas/mismatch` (human token only)
  records that the codes differ for the current epoch. Per SPEC §11 the
  daemon raises `sas_mismatch`, sends a leave proposal when one is
  allowed, and deletes its local group state. There was no way to act on a
  mismatch before.
- Daemon: an exclusive `flock` on `<data_dir>/daemon.lock` is taken
  before any key or database is touched, so a second daemon on the same
  data directory fails fast with a clear error instead of racing first-run
  key creation (which could leave `mls.sqlite3` under an overwritten key).
  Key files are written to a unique 0600 temporary file and `os.replace`d.
- Daemon: the SPEC §10.2 limits are enforced on receive and on send:
  messages of at most 256 KiB, 30 per minute per sender and 120 per group,
  and only `text` and `data` A2A parts (`file` parts are refused).
  Unknown kinds are ignored on receive (§7.2) and refused on send, instead
  of reaching the adapter. Over-limit API sends get 429 `rate_limited`.
- Daemon logging: every logger runs one fixed JSON chain regardless of the
  embedding application's structlog configuration. Tracebacks are plain
  (no local variables), content-like fields (`body`, `ct`, `env`,
  `inner`, `payload`, `url`, ...) are redacted, and the CLI turns off
  Typer's locals in pretty exceptions. Previously an embedded daemon used
  structlog's default console renderer, which printed every frame's locals
  (envelopes, plaintext, invite URLs) with each logged exception.
- Daemon: a malformed relay frame during authentication (a challenge
  without a 32-byte base64url nonce, a non-object challenge or `ready`)
  now causes a reconnect with backoff instead of ending the relay link
  task for good, and every daemon worker is supervised and restarted if it
  ever dies.
- Daemon: envelope fields the relay controls (`v`, `kind`, ids, `epoch`,
  `to`, `routing`) are type-checked before the core processes anything;
  a malformed envelope is dropped with `relay_misbehaviour`, and a dropped
  commit marks the group `out_of_sync`. After every merge the cached
  members, policy and epoch are re-read from the core first, and
  `require_verified` gating reads the core's policy. Previously a relay
  could replace `routing` with a string so that bookkeeping failed after
  the merge, leaving a stale policy that let unverified traffic through.
- Daemon: `max_uses` is enforced when a join is approved, not only by the
  relay's later `invite.consume`. Each approval reserves a use (a failed
  Add releases it), further JoinRequests for a used-up invite are dropped,
  and a human can't approve past the limit. Previously two redemptions of a
  single-use link, say the joiner and a link thief, were both added. A
  joiner whose pending join's invite is used up or revoked now gets
  `join_failed` with the SPEC §4.3 "already used" warning.
- Daemon: the SPEC §10.3 loop guard works. Agent messages carry `hop` =
  one more than the largest `hop` of the messages they reply to (named by
  `reply_to` msg_ids in the API and `adapter_send`, or else the last
  message that triggered this instance); human messages are 0. A message
  past `loop_guard.max_agent_turns` doesn't trigger the agent, and the
  daemon sends one `control.pause{reason: "loop_guard"}` and raises a
  `loop_guard` event. A human `control.resume` resets the counter, and
  an agent-originated one is ignored. Previously every message had hop 0.
- Daemon API: a message sent with the agent token now goes out as
  `origin: "agent"`, and only the human token can send
  `control.resume` (SPEC §7.3). Previously every API send claimed
  `origin: "human"`, so an agent could impersonate its human to peers,
  re-trigger everyone in `mention` mode and resume a paused loop.
- Daemon: `daemon.sqlite3` is now encrypted at rest (SQLCipher through
  `agentconnect_core.Database`, ADR-003). It previously was plain SQLite
  that kept every sent message's plaintext forever. Answered outbox rows now
  keep only their ids, delivered inbox rows drop their message, decided
  JoinRequests drop their body, and the daemon refuses to start if the
  keystore lost `db_key` while encrypted files exist.
- Core: `EncryptedDb` (Python: `agentconnect_core.Database`), a SQLCipher
  database with a caller-defined schema for the daemon's own records, keyed
  under `DbKey::derive` (HKDF-SHA256, label
  `agentconnect/v0/daemon-db-key`) so one keystore entry keys both files
  and no two share a key. `secure_delete` is on; a wrong key or a
  cleartext file fails with `Error::StorageKey` (ADR-003).
- Core and relay: the relay challenge nonce must be exactly 32 bytes
  (SPEC §8.2). `Instance.sign_relay_challenge` refuses any other length,
  and the relay never verifies one. The signed bytes don't delimit the
  host, so a longer nonce let a relay at `relay.test` obtain an `auth`
  signature valid at `x.relay.test`.
- The daemon's MLS state is now encrypted at rest. `SqliteStore` is a
  SQLCipher database (whole-file encryption with vendored OpenSSL, ADR-002)
  and `SqliteStore::open` requires a 32-byte `DbKey`; there is no
  unencrypted on-disk mode. A wrong key, or a cleartext file, fails with
  `Error::StorageKey`. `SqliteStore::rekey` re-encrypts a store under a new
  key. In Python, `Client(path, instance, db_key)` requires the key for an
  on-disk store, and `rekey_store(path, old_key, new_key)` rotates it.
- Core: integers in policy, metadata and instance-certificate JSON are
  capped at the I-JSON range (|n| ≤ 2^53 − 1, SPEC §3.2); anything outside
  it is neither written nor accepted.
- Core: a joiner rejects a Welcome whose GroupInfo carries any extension
  other than `ratchet_tree`, and checks that every KEM ciphertext in the
  Welcome is 1120 bytes before OpenMLS decapsulates it (new
  `Error::KemOutputLength`). UpdatePath ciphertexts are decapsulated
  inside OpenMLS, whose provider rejects other lengths; a test pins that
  (SPEC §3.1, §6.3).
- Core: the policy in a Welcome or a commit must be in range:
  `loop_guard.max_agent_turns` is now capped at 100, next to the existing
  `max_members` (1 to 50) and identity checks. The owner need not be a
  current member (SPEC §6.3, §9.1).
- Core: an own commit is confirmed only by the relay's `accepted` for its
  `msg_id` (`CommitOut.msg_id`, now required by `confirm_pending_commit`) or
  by the fan-out delivering the exact bytes sent. Previously any commit
  claiming the instance's leaf at the current epoch merged whatever commit
  was pending, so a stale own commit forked the instance and a malicious
  member could trigger a premature merge. A discarded own commit that comes
  back is reported as `OwnCommitLost` (re-sync needed).
- Core: KeyPackages are single-use. Every client records the KeyPackage
  refs of the Adds it merges and rejects a JoinRequest, a local Add or a
  received Add that reuses one, so a replayed JoinRequest can no longer
  re-add a departed member as a leaf nobody controls.
- Core and bindings: the instance key and invite secrets no longer pass
  through unzeroized copies (JSON values, base64 temporaries, by-value
  arrays). `InviteSecret::from_parts` takes the secret by reference.
- Python bindings: no panic crosses into Python. Every binding runs under
  `catch_unwind` and a panic raises the new `agentconnect_core.CoreError`
  (an `Exception`); the client drops its cached groups and reloads them
  from storage instead of failing with a poisoned lock forever. The test
  clock rejects out-of-range times instead of overflowing.
- Python bindings: seeded randomness (64-bit seeds give guessable keys)
  and the settable clock are only reachable through test-only entry points
  (`Identity._generate_for_testing`, `Identity._create_instance_for_testing`,
  `Client._for_testing`, `Client._set_time_for_testing`); the production
  constructors take no seed.
- Python bindings: `derive_join_key` and `derive_welcome_key` are removed;
  derived invite keys stay inside the core. `join_request_mac` now takes the
  invite id and secret.
- Dependency policy allows MPL-2.0 for the three `hpke-rs` crates only.
  Advisories RUSTSEC-2026-0329/0330/0331 in the OpenMLS libcrux provider are
  temporarily ignored, and releases are blocked until a fixed provider ships.
