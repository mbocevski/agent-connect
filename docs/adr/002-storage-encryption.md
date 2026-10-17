# ADR-002: Encrypting the daemon's MLS state at rest

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** Marko Bocevski

## Context

`core`'s `SqliteStore` holds everything an attacker needs to read and
impersonate a member: epoch secrets, the secret tree, signature private keys,
HPKE private keys of unused KeyPackages and leaf nodes, the ratchet tree, and
`core`'s own records (pending commits, consumed KeyPackage refs, previous
members). Until now it wrote all of it to SQLite in the clear. SPEC §12 lists
"encrypted-at-rest storage" as the mitigation for a compromised host (a
stolen disk, a backup, another local user who can read the file), so a
cleartext store blocks any release.

The daemon already has a keystore that holds a 32-byte database key (the OS
keyring, or a 0600 file). `core` needed a way to apply it.

Constraints:

- The OpenMLS state goes through `openmls_sqlite_storage` 0.3.0, which owns
  its `rusqlite` 0.37 connection and its schema.
- Licences: MIT, Apache-2.0, BSD, ISC or Zlib only (`deny.toml`).
- Builds: `cargo build -p agentconnect-relay` and
  `uv build --all-packages --sdist --wheel` on ubuntu-24.04, in CI, the
  release workflow and the reproducibility check (two clean builds, same
  hashes). No system library at build or run time.

## Options

### A. SQLCipher (whole-database encryption)

`rusqlite`'s `bundled-sqlcipher-vendored-openssl` feature compiles the
SQLCipher amalgamation shipped inside `libsqlite3-sys` 0.35 and links a
statically built OpenSSL from `openssl-src`.

- **Coverage:** every page of the database, its rollback journal and its WAL
  is encrypted (AES-256-CBC) and authenticated (HMAC-SHA512 per page). Table
  names, the schema, key names, row counts and the SQLite header are hidden;
  the file is indistinguishable from random apart from its size. Temp tables
  stay in memory (`SQLITE_TEMP_STORE=2`).
- **Fit with OpenMLS:** `openmls_sqlite_storage::SqliteStorageProvider::new`
  takes a `rusqlite::Connection` we open ourselves, so we key it before
  handing it over. `core` adds `rusqlite` 0.37 as a direct dependency only to
  turn the feature on; `libsqlite3-sys` has `links = "sqlite3"`, so there is
  one SQLite in the graph and OpenMLS's connection is the SQLCipher one. No
  fork of the storage provider is needed.
- **Licences:** SQLCipher is BSD-3-Clause (Zetetic), shipped inside
  `libsqlite3-sys` (MIT). OpenSSL 3.x is Apache-2.0; `openssl-src`
  300.6.0+3.6.2 and `openssl-sys` 0.9.117 are MIT/Apache-2.0. `cargo deny
  check` passes with **no new exception**.
- **Crypto backend:** `libsqlite3-sys` supports OpenSSL/LibreSSL (system or
  vendored) and, on Apple targets only, CommonCrypto. It has no libtomcrypt
  option. We use the vendored OpenSSL, so neither build nor runtime needs a
  system `libcrypto`.
- **Rotation:** `PRAGMA rekey` re-encrypts the file in one transaction.
- **Costs:** a C dependency of roughly 500k lines (OpenSSL) in the daemon's
  and relay's builds; a clean build of `core` takes about a minute longer
  (OpenSSL's `Configure` and `make`, which need `perl` and `make`, both on
  ubuntu-24.04 runners and in `rust:*-bookworm`). SQLCipher's crypto is not
  the formally verified libcrux code the protocol uses.

### B. Application-level AEAD in `core`'s storage provider

Wrap OpenMLS's `StorageProvider` and encrypt every value with
ChaCha20-Poly1305 under a fresh random nonce, with the storage key and value
type in the AAD; optionally replace keys with `HMAC(db_key, key)`.

- **Pros:** pure Rust (RustCrypto, Apache-2.0/MIT), no C, no build-time
  tooling, our own AEAD with tests and vectors.
- **Cons:** OpenMLS's SQLite schema is fixed, so table names, row counts,
  column layout and (without HMAC) every key name stay visible: group ids,
  KeyPackage refs, epochs, which is metadata about membership and activity.
  The storage trait has about 60 methods; wrapping them all, plus re-keying
  every row for rotation, is a large surface of our own to get right and to
  keep in step with each OpenMLS release. Deletions by key would need the
  HMAC'd key to stay deterministic, and a rollback to an older copy of a
  single row would go unnoticed unless we also bound rows to an epoch.

## Decision

**Option A: SQLCipher, with vendored OpenSSL.** It worked cleanly in every
check, and it protects strictly more than B (schema, key names and row
counts as well as values) with far less code of our own.

- `core` depends on `rusqlite = "0.37.0"` with
  `bundled-sqlcipher-vendored-openssl`.
- `SqliteStore::open(path, &DbKey)`: the key is required. There is no
  unencrypted on-disk mode. `SqliteStore::open_in_memory()` (tests) never
  touches the disk.
- The key is a raw 32-byte SQLCipher key (`PRAGMA key = "x'…'"`), so there is
  no PBKDF2 step: it is already uniformly random. `DbKey` zeroizes on drop and
  prints as `DbKey(..)`; the hex `PRAGMA` text is built in a zeroizing buffer.
- Before keying, `core` checks `PRAGMA cipher_version` and refuses to open if
  the linked SQLite isn't SQLCipher, because plain SQLite ignores
  `PRAGMA key` and would write cleartext.
- A wrong key, or a file that isn't an encrypted store (including a legacy
  cleartext file), fails with `Error::StorageKey` and no panic.
- Rotation: `SqliteStore::rekey(path, old, new)` (`PRAGMA rekey`) on a store
  that isn't open elsewhere. Python: `agentconnect_core.rekey_store`.
- Python: `Client(path, instance, db_key)`; `db_key` (32 bytes) is required
  when `path` is set and refused when it isn't.

### Pipeline verification (2026-10-17)

- `cargo deny check`: advisories, bans, licences and sources pass with no new
  exception.
- `cargo build`, `cargo nextest`, `cargo llvm-cov` and `uv sync` / `pytest`
  on Linux x86_64: pass. The relay's tests pass unchanged.
- The release and reproducibility workflows' build steps (`cargo build
  --release -p agentconnect-relay` and `uv build --all-packages --sdist
  --wheel`, with `SOURCE_DATE_EPOCH` and `--remap-path-prefix`), run twice
  from clean copies of the tree: every artifact, the relay binary and the
  `agentconnect_core` wheel included, has the same hash both times. OpenSSL's
  build info honours `SOURCE_DATE_EPOCH`. Like the rest of the C code, its
  embedded source paths depend on the build directory, which the
  reproducibility workflow keeps fixed.
- `ldd` on the wheel's extension module and on the relay binary shows no
  `libcrypto` or `libsqlite3`: both are linked statically.

## Consequences

- **The relay links SQLCipher too.** `relay` depends on `core`, and Cargo
  builds one `libsqlite3-sys` per graph, so `sqlx` uses the SQLCipher build.
  The relay never sets a key, and SQLCipher without a key behaves as plain
  SQLite, so the relay's database is unchanged (it holds only ciphertext and
  routing data). Its binary grows by the static OpenSSL and its clean build
  is slower. If that becomes a problem, the relay can stop depending on
  `core`.
- **OpenSSL is now in our supply chain.** It's built from the pinned
  `openssl-src` sources at the version in `Cargo.lock`. OpenSSL advisories
  apply to us, though SQLCipher uses only its `libcrypto` primitives; cargo
  audit/deny tracks `openssl-src`. Dependabot updates it.
- **Cross-platform:** `openssl-src` supports macOS and Windows as well, so
  wheels for those platforms shouldn't need a system library either. This
  hasn't been verified: only Linux x86_64 is built and tested today. Windows
  builds of OpenSSL from source also need Perl and NASM.
- **Residual exposure:** file size and its growth, and modification times.
  The key exists in process memory while a store is open (SQLCipher keeps
  its derived key material; `cipher_memory_security` is left at its default,
  off, for performance), and a copy of the key's SQL text passes through
  SQLite's statement parser. A host attacker who can read the daemon's memory
  or its keystore reads the state: SPEC §12 keeps "that member fully, until
  removed" as the residual risk.
- **No migration from cleartext stores:** there are no releases, so a
  cleartext file from a development build is refused with
  `Error::StorageKey` and must be deleted.
