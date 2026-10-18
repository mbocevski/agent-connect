# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The wire protocol is versioned separately (see `SPEC.md` §13).

## [Unreleased]

### Added

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
  past `require_approval` or the file-part ban. Agent Card text is capped
  at the ADR-006 listing limits, and with inbound approval a changed card
  is held.
  Controls and cards are delivered as context only, the SDK shows no text
  for them (a card is in `msg.card`), and the agent token can't send them.
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

### Changed

- The default relay is now `wss://connect.yggdrasill.network`, and the
  planned A2A extension URI in SPEC §13 is
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
