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
  - `openmls_sqlite_storage` 0.3.0 (alternatively `openmls_sqlx_storage`),
    on SQLCipher through `rusqlite` 0.37's
    `bundled-sqlcipher-vendored-openssl` feature (OpenSSL 3.6 built from
    `openssl-src`, no system library). See ADR-002.
- **Ciphersuite:** `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`
  (TBD1 of `draft-ietf-mls-pq-ciphersuites`, provisional codepoint
  `0x004F`). Its hybrid KEM combines ML-KEM-768 with X25519. It is the only
  ciphersuite, with no negotiation, so there's no way to downgrade.
  - *Revised 2026-10-17 after the spike.* The original choice was the X-Wing
    suite `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (`0x004D`). It
    comes from an expired individual draft, isn't in the MLS WG draft, and
    upstream OpenMLS now calls it legacy.
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
- *mls-rs.* Support for the PQ hybrid suites isn't confirmed. Re-evaluate
  if OpenMLS stalls.

**Risks:**

- OpenMLS is pre-1.0, so its API will change. We pin it and wrap it behind
  the `core` API.
- The ciphersuite codepoint is provisional until IANA assigns it. The
  ciphersuite is fixed per protocol version, so a different final codepoint
  means a protocol version change.
- The libcrux provider is newer than the rust-crypto one.

**Spike outcome (2026-10-17): GO** (`docs/spikes/mls-xwing.md`). OpenMLS
covers everything v0 needs, so the classical fallback isn't needed.

**Accepted risk: provider advisories.** `openmls_libcrux_crypto` 0.4.0, the
only release, pins `libcrux-kem` 0.0.9 and `libcrux-hmac-drbg` 0.0.1.

- RUSTSEC-2026-0331 is reachable: a validly signed KeyPackage with a short
  hybrid key panics the inviter, so anyone holding an invite link can crash
  the inviter's daemon. RUSTSEC-2026-0329 and RUSTSEC-2026-0330 are also open.
- Fixed crates exist upstream, but no provider release ships them yet.
- Decision: build `core` on 0.4.0 now. `core` MUST check the length of every
  HPKE public key before handing it to OpenMLS, with a regression test. The
  advisories are ignored in `deny.toml` as **temporary**.
- **Release blocker:** no release and no public relay until a fixed provider
  is published and the ignores are removed.

### 3. Tooling

| Area | Choice | Version |
|---|---|---|
| Rust toolchain | stable, edition 2024, pinned in `rust-toolchain.toml` | 1.99.1 |
| Python env & packaging | uv (workspace) | 0.13.1 |
| Python build for bindings | maturin | 1.15.0 |
| Git hooks | **prek** (drop-in for pre-commit; uses `.pre-commit-config.yaml`) | 0.5.5 |
| Task runner | `just` | 1.59+ |
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
  and upgrades go through Dependabot PRs with CI.
- *pre-commit.* prek is faster, needs no Python environment, and reads the
  same config file.

### 4. Licence, hosting, process

- **Licence:** Apache-2.0. It includes a patent grant and matches A2A and most
  of our dependencies. Only MIT, Apache-2.0, BSD, ISC and Zlib licences are
  allowed in dependencies; `cargo-deny` enforces this. **AGPL and GPL are
  banned.**
  - **One scoped exception (approved 2026-10-17):** MPL-2.0 for `hpke-rs`,
    `hpke-rs-crypto` and `hpke-rs-libcrux`. They're the HPKE layer of both
    OpenMLS crypto providers, so OpenMLS can't be used without them. MPL-2.0
    is file-level copyleft. Using the crates unmodified is compatible with
    Apache-2.0 distribution and a hosted relay; if we ever modify their
    files, we must publish those files. MPL-2.0 stays banned for every other
    crate.
  - **Python dependencies follow the same allowlist**, in `licences-py.toml`
    (Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MIT, MIT-0, Unicode-3.0,
    Zlib, plus PSF-2.0 and Python-2.0 for stdlib-adjacent packages such as
    `typing_extensions`). `scripts/check_licences.py` (`just licences`) runs
    `pip-licenses` over the third-party packages in `uv.lock` and fails on
    any disallowed or unknown licence, in `just lint`, the CI `licences` job
    and the nightly audit. A policy exception that no package uses fails
    too, so the list can't go stale.
  - **Two scoped Python exceptions (approved 2026-10-17), MPL-2.0 for
    `certifi` only and `hypothesis` only.** `certifi` is the CA bundle used
    by `httpx` (a runtime dependency); we use it unmodified. `hypothesis` is
    a test-time dependency that isn't shipped. The same file-level copyleft
    reasoning as for `hpke-rs` applies, and MPL-2.0 stays banned for every
    other package.
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
  - Dependabot for dependency updates (cargo, uv, Actions, pre-commit
    hooks, Rust toolchain). It's built into GitHub, unlike Renovate, which
    needs an app installed.
  - CodeQL code scanning (default setup, extended suite), secret scanning
    with push protection, and Dependabot alerts and security updates.
  - Release tags `v*` are protected by a ruleset: no deletion, no moving.

### 5. Platforms

Tier 1 is Linux x86_64. Linux arm64 and macOS arm64 are supported too.
Intel Macs and Windows are not (the daemon uses `fcntl` locks and Unix
sockets).

| Platform | CI | Release artifacts | Reproducibility check |
|---|---|---|---|
| Linux x86_64 | `ci.yml`, required | relay, core wheel, Python packages | yes |
| Linux arm64 | `platforms`, `image`, not required | relay, core wheel | yes |
| macOS arm64 | `platforms`, not required | core wheel | no |

- **Native runners, no emulation.** arm64 builds use `ubuntu-24.04-arm`,
  macOS builds `macos-15`. QEMU would turn the OpenSSL and libcrux builds
  into a 30-minute job and add an emulator to the trust base.
- **Wheels.** `agentconnect-core` is one abi3 wheel (`abi3-py312`) per
  platform, built by maturin: manylinux 2.28 on Linux (in the maturin
  container for the runner's own architecture), a plain `macosx_*_arm64`
  wheel on macOS. The daemon and SDK are pure Python and ship once.
- **Container.** `relay/Dockerfile` is architecture-neutral. CI builds it for
  `linux/amd64` and `linux/arm64`, each on a native runner, and publishes
  nothing; releases don't publish images yet.
- **No system libraries.** SQLCipher, OpenSSL (vendored) and libcrux compile
  from source and link statically. On macOS CI runs `otool -L` on the relay
  and the extension module, prints the result, and fails if either links
  anything outside `/usr/lib` and `/System`.
- **Reproducibility.** The check runs on both Linux architectures. It does
  not cover macOS: the Apple linker and the Xcode toolchain on the runner
  image put host details into Mach-O files, and we can't pin them. macOS
  wheels are signed and attested like the others, but not claimed to be
  reproducible.
- **Gating.** The new jobs are not in `ci-ok`: they have no track record
  yet, and macOS runners queue unpredictably. They run on every pull request
  and nightly. Promote a job into `ci-ok` after about 20 consecutive green
  runs under 15 minutes.
- **Paths and secrets on macOS.** The daemon keeps XDG paths on every
  platform (`$XDG_DATA_HOME`, `$XDG_CONFIG_HOME`, overridable with
  `AC_DATA_DIR`). Moving to `~/Library/Application Support` is a follow-up.
  The keystore uses `keyring`, which talks to the login Keychain on macOS;
  the unit tests use an in-memory keyring, so CI runs
  `scripts/keychain_probe.py` to check a real Keychain round trip. The
  `auto` keystore falls back to 0600 files when it fails. The local API
  socket lives in the data directory; macOS limits Unix socket paths to 104
  bytes, so a long `AC_DATA_DIR` breaks the daemon there.

## Consequences

- Contributors need both toolchains. `just setup` installs everything through
  rustup and uv.
- The PyO3 boundary is an API surface of its own. Contract tests in
  `testdata/` keep Rust and Python consistent.
- We accept the churn risk of pre-1.0 OpenMLS in exchange for groups and
  post-quantum protection from day one.
