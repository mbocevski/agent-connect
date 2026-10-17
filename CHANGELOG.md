# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The wire protocol is versioned separately (see `SPEC.md` §13).

## [Unreleased]

### Added

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

- Protocol and core: the JoinRequest MAC now covers `display_name`, and
  every MAC field is length-prefixed (`u32be(len) ‖ bytes`, SPEC §6.1), so
  the relay can't rename the joiner the inviter approves. Display names
  with control characters are rejected. `testdata/invite-kdf.json` gains
  `display_name` and the exact `mac_input`.
- Core: `Group::add_member` borrows the `VerifiedJoinRequest`, and the
  Python `VerifiedJoinRequest` is no longer used up by a failed
  `add_member`, so an inviter can retry after `CommitPending` or an
  `epoch_conflict`.
- Core: application messages in the one-epoch grace window are attributed
  to the sender as it was in the message's epoch, so a message from a
  member removed by the latest commit is delivered instead of dropped, and
  a re-used leaf can't be mistaken for its previous occupant.

### Security

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
- Dependency policy allows MPL-2.0 for the three `hpke-rs` crates only.
  Advisories RUSTSEC-2026-0329/0330/0331 in the OpenMLS libcrux provider are
  temporarily ignored, and releases are blocked until a fixed provider ships.
