# ADR-003: Encrypting the daemon's own database at rest

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** Marko Bocevski

## Context

ADR-002 encrypted the core's MLS store (`mls.sqlite3`). The daemon keeps a
second database, `daemon.sqlite3`, with its own schema: groups (names and
purposes), members and display names, the human-set *verified* flags, peer
Agent Cards, JoinRequests awaiting approval, the event log (which carries
SAS values), and the durable outbox and inbox. The outbox holds every
outgoing message's inner plaintext until the relay answers it, and the inbox
holds every received message until the adapter accepts it.

That file was plain SQLite protected by file permissions, and outbox rows
were never scrubbed, so a copied data directory exposed every message the
daemon had ever sent. SPEC §12 promises "no unencrypted on-disk mode", so
this blocks any release.

Constraints:

- One SQLCipher build. `core` already links SQLCipher with a vendored,
  statically built OpenSSL (ADR-002), and it is in every wheel.
- Licences: MIT, Apache-2.0, BSD, ISC or Zlib only.
- No system library at build or run time; reproducible wheels.
- Keep derived keys out of Python where we can (the daemon already handles
  `db_key` itself as Python bytes).

## Options

### A. Route daemon storage through the core

Expose a small SQL database from `core` over the same SQLCipher build:
`EncryptedDb` (Rust) / `agentconnect_core.Database` (Python), opened and
keyed by the same code as `SqliteStore` (cipher check, raw key, wrong-key
detection), with `query`, `execute` and `execute_script`.

- **Coverage:** whole-file encryption, as ADR-002: every page, the journal
  and the WAL; schema, table names and row counts hidden.
- **Build:** no new dependency. The binding is about 150 lines of Rust and
  reuses `open_keyed`, so there is one keying path to review.
- **Key:** derived in the core, HKDF-SHA256(ikm = `db_key`, no salt,
  info = `agentconnect/v0/daemon-db-key`). The derived key never reaches
  Python, the keystore keeps a single entry, and no two files share a key.
- **Cost:** the daemon's `Store` switches from `sqlite3` to the binding (a
  thin facade keeps its SQL unchanged). Calls cross PyO3, which is cheap at
  the daemon's rates.

### B. App-level AEAD of sensitive columns

Seal payloads, display names, Agent Cards and JoinRequests with a
`core-py` seal/open helper and keep plain SQLite.

- **Cons:** the schema, row counts, group ids, timestamps, states and every
  unsealed column stay visible; each new column is a chance to forget the
  seal; deleted plaintext from before a column was sealed lingers in free
  pages and the WAL. Strictly less than A for more code.

### C. A Python SQLCipher binding (e.g. `sqlcipher3`)

- **Cons:** a second SQLCipher and a second OpenSSL in the wheel set, built
  and patched separately from the core's. Wheel availability and licences
  vary by package and platform (some bundle OpenSSL dynamically, some need
  a system `libsqlcipher`), which breaks the "no system library" and
  reproducibility constraints.

## Decision

**Option A.** It reuses the core's single SQLCipher build and keying code,
encrypts the whole file, and adds no dependency.

- `agentconnect_core.Database(path, db_key)` takes the keystore's 32-byte
  `db_key`; the core derives the file key. There is no unencrypted mode.
  A wrong key or a cleartext file raises `AgentConnectError` ("wrong
  database key, or not an encrypted store").
- `PRAGMA secure_delete = ON`, so removed rows are overwritten in the
  (encrypted) file rather than left in free pages.
- **Retention on top of encryption.** An outbox row keeps only its ids
  (`msg_id`, frame type) once the relay has answered it or the daemon gave
  up; an inbox row drops its delivery once the adapter accepted it (or it
  was dropped); a decided JoinRequest drops its body. The SSE adapter's feed
  (the only place delivered payloads stay) is written only when that adapter
  is enabled and is purged `sse.retention_secs` (default one hour) after each
  item was written. This limits what a
  host attacker with the keystore finds, too.
- **No silent re-keying.** If the keystore has no `db_key` but either
  database file exists, the daemon refuses to start instead of minting a
  key that could never open them.

## Consequences

- One key in the keystore protects both files, through independent keys.
  Rotating `db_key` means re-keying both files (`rekey_store` for the MLS
  store; a matching helper for the daemon database is future work, since
  there are no releases to migrate yet).
- A cleartext `daemon.sqlite3` from a development build is refused and must
  be deleted (no migration).
- The MLS state and the daemon's records still live in two files with two
  connections, so they don't share transactions. ADR-004 (the processing
  journal) closes that gap.
- Residual exposure is that of ADR-002: file sizes and modification times,
  and keys in process memory while the daemon runs. The daemon handles
  `db_key` (not the derived key) as Python `bytes`, which can't be zeroized.
