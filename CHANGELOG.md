# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The wire protocol is versioned separately (see `SPEC.md` §13).

## [Unreleased]

### Added

- Protocol specification v0 draft (`SPEC.md`): MLS groups with the X-Wing
  post-quantum ciphersuite, invite links, SAS verification, relay Delivery
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
- Tooling: justfile, prek hooks (pre-commit, commit-msg, pre-push), CI,
  nightly audit/mutation runs, reproducibility check, signed release workflow,
  and local merge gating (`just merge`).
