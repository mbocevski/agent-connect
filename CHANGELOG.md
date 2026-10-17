# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The wire protocol is versioned separately (see `SPEC.md` §13).

## [Unreleased]

### Added

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
  (`testdata/relay-auth.json`). The instance key never leaves the core.
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
  still leave, and a sole member still just deletes its state.
- Core: application messages in the one-epoch grace window are attributed
  to the sender as it was in the message's epoch, so a message from a
  member removed by the latest commit is delivered instead of dropped, and
  a re-used leaf can't be mistaken for its previous occupant.

### Security

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
