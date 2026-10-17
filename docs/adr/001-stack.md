# ADR-001: Tech stack, crypto and tooling

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** Marko Bocevski

## Context

AgentConnect is a security product with three kinds of component:

- **Crypto core:** MLS groups, invite binding, SAS.
- **Relay:** the MLS Delivery Service. It's a network service.
- **Endpoint software:** the daemon, CLI and SDK. It integrates with A2A
  agents and headless agent frameworks.

The audiences we target first are A2A-server agents and headless/SDK agents,
mostly written in Python.

The protocol must give end-to-end confidentiality across a relay we don't
trust, support groups from day one, and resist "harvest now, decrypt later"
attacks by future quantum computers. Versions below were checked against
crates.io and PyPI on 2026-10-17. Library APIs were confirmed against current
upstream docs.

## Decisions

### 1. Languages: Rust for the core and relay, Python for the daemon and SDK

- `core/` (Rust) implements all the cryptography and wire formats, once.
- `core-py/` exposes it to Python through **PyO3 0.30** and **maturin 1.15**.
- `relay/` is Rust (**axum 0.8**, **tokio 1.53**, **tokio-tungstenite 0.30**,
  **sqlx 0.9** with SQLite for development and Postgres for production).
- `daemon/` and `sdk/python/` are Python 3.14 (the SDK supports ≥ 3.12). They
  use the official **a2a-sdk 1.2.2**, which implements A2A 1.0 over JSON-RPC,
  HTTP+JSON and gRPC, client and server, with 0.3 compatibility.

**Why:**

- A memory-safe, single implementation of the crypto that every component
  shares.
- The Python A2A SDK is the most mature one.
- Most headless agent frameworks (Claude Agent SDK, LangGraph) are Python.

**Rejected:**

- *All Rust.* There's no mature Rust A2A SDK, and it's a worse fit for SDK
  users.
- *All Python.* We'd assemble the crypto from loosely coupled bindings, which
  is a weaker assurance story.

### 2. Crypto: MLS from day one, one post-quantum hybrid ciphersuite

- **OpenMLS 0.9.1** (MIT) with the **openmls_libcrux_crypto 0.4.0** provider
  (formally verified primitives from libcrux).
- Supporting crates:
  - `openmls_basic_credential` 0.6.0
  - `openmls_traits` 0.6.0
  - `openmls_sqlite_storage` 0.3.0 (alternatively `openmls_sqlx_storage`)
- **Ciphersuite:** `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`. X-Wing
  combines X25519 with ML-KEM-768. It is the only ciphersuite, with no
  negotiation, so there's no way to downgrade.
- A 1:1 conversation is a group of two. Group mode is a first-class v0
  feature.
- Small helper crates: `hkdf` 0.13, `zeroize` 1.9, `serde` 1.0, `clap` 4.6,
  `tracing` 0.1.

**Why:**

- One stack covers 1:1, groups and replicas of one agent.
- Post-quantum protection is renewed every epoch.
- The SAS comes for free from `epoch_authenticator`, and all members compare
  the same code.
- The relay maps directly onto MLS's Delivery Service role.

**Rejected:**

- *Noise (snow) + Olm (vodozemac).* Two crypto stacks once groups arrive. Olm
  isn't post-quantum. snow's post-quantum support is pre-standard Kyber1024
  only, and its last release was 2025-07.
- *libsignal.* AGPL-3.0, which we can't accept for a hosted service.
- *mls-rs.* X-Wing support isn't confirmed. Re-evaluate if OpenMLS stalls.

**Risks:**

- OpenMLS is pre-1.0, so its API will change. We pin it and wrap it behind
  the `core` API.
- The X-Wing codepoint is still in an IETF draft. The ciphersuite is fixed per
  protocol version.
- The libcrux provider is newer than the rust-crypto one.

`docs/spikes/mls-xwing.md` (task: *Spike: validate OpenMLS + X-Wing*)
validates all three before the core is built. If X-Wing proves unworkable,
the fallback is classical X25519 (`0x0003`) with post-quantum deferred. That
fallback needs the maintainer's sign-off.

### 3. Tooling

| Area | Choice | Version |
|---|---|---|
| Rust toolchain | stable, edition 2024, pinned in `rust-toolchain.toml` | 1.99.1 |
| Python env & packaging | uv (workspace) | 0.13.1 |
| Python build for bindings | maturin | 1.15.0 |
| Git hooks | **prek** (drop-in for pre-commit; uses `.pre-commit-config.yaml`) | 0.5.5 |
| Task runner | just | 1.59+ |
| Rust tests | cargo-nextest | 0.9.148 |
| Property tests | proptest / hypothesis | 1.12.0 / 6.170.1 |
| Snapshots | insta | 1.49.0 |
| Fuzzing | cargo-fuzz | 0.13.2 |
| Mutation testing | cargo-mutants (on `core/`) | latest at bootstrap |
| Coverage | cargo-llvm-cov / pytest-cov | latest / 7.1.0 |
| Python tests | pytest, pytest-asyncio, pytest-timeout | 9.1.1, 1.4.0, latest |
| Lint/format (Python) | ruff | 0.17.1 |
| Type check (Python) | **ty**, all rules set to error; pinned exactly because it's pre-1.0 | 0.0.89 |
| Lint (Rust) | clippy `-D warnings` (pedantic in core/relay), rustfmt, `cargo doc -D warnings` | toolchain |
| Unused Rust deps | cargo-shear | 1.14.0 |
| TOML format/lint | taplo (with schema catalogs) | 0.10.0 |
| Shell / workflows | shellcheck, actionlint | 0.11.0 / 1.7.12 |
| Dependency policy | cargo-deny (licence allowlist, advisories, duplicates); pip-audit | 0.20.2 |
| Python runtime deps | pydantic 2.14, websockets 17.2, httpx 0.28, typer 0.27, structlog 26.1, keyring 25.7 | — |

**Rejected:**

- *mypy.* Initially chosen because ty is pre-1.0. Revised on 2026-10-17 in
  favour of ty, to stay on the Astral toolchain (uv, ruff, ty) with a single
  fast checker. Mitigations: ty is pinned exactly, every rule is set to error,
  and upgrades go through Renovate PRs with CI.
- *pre-commit.* prek is faster, needs no Python environment, and reads the
  same config file.

### 4. Licence, hosting, process

- **Licence:** Apache-2.0. It includes a patent grant and matches A2A and most
  of our dependencies. Only MIT, Apache-2.0, BSD, ISC and Zlib licences are
  allowed in dependencies; `cargo-deny` enforces this. **AGPL and GPL are
  banned.**
- **Hosting:** a public repo on the maintainer's personal GitHub
  (`mbocevski/agent-connect`), open from the start.
  - Gating runs in two layers. Locally: hooks plus `just merge`, which
    refuses to merge unless every required check is green. Server-side: a
    GitHub ruleset on `main`, kept as code in `.github/rulesets/main.json`
    and applied with `just apply-ruleset`.
- **Versioning:** SemVer for packages. The protocol version (`v0`) is
  independent.
- **Process:**
  - Conventional Commits.
  - Keep a Changelog, enforced in CI.
  - Squash merges.
- **Supply chain:**
  - Reproducible builds.
  - Sigstore/cosign signing plus SLSA provenance via
    `actions/attest-build-provenance`.
  - GitHub Actions pinned by commit SHA.
  - Renovate for dependency updates.

## Consequences

- Contributors need both toolchains. `just setup` installs everything through
  rustup and uv.
- The PyO3 boundary is an API surface of its own. Contract tests in
  `testdata/` keep Rust and Python consistent.
- We accept the churn risk of pre-1.0 OpenMLS in exchange for groups and
  post-quantum protection from day one.
