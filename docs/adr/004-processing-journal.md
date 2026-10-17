# ADR-004: A processing journal for crash-consistent receive and commit paths

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** Marko Bocevski

## Context

Processing an MLS message is one-shot. `Group::process` consumes the
message's ratchet key or merges a commit, and that state change is stored in
the core's SQLCipher store (`mls.sqlite3`). The daemon then records what the
message means in its own database (`daemon.sqlite3`, ADR-003): the inbox row
with the plaintext, the member and policy cache, the epoch, events, queued
Agent Cards. Only then does it ack the relay.

The two databases share no transaction. A crash, or any exception, between
the core's write and the daemon's loses the message for good: the relay
redelivers the unacked frame, and the core rejects it because its key is
already used. For a commit, the merge survives but the daemon's bookkeeping
doesn't, so its view of the group goes stale. The review of the daemon found
the same shape of gap in five more places:

1. **Welcome:** the core keeps the joined group, the daemon has no row for
   it, and the redelivered Welcome fails on the spent KeyPackage.
2. **Own-commit confirmation:** the merge on `accepted` happens before the
   daemon records it, and a resend after a restart can't be confirmed again.
3. **Leave/removal:** the core state was deleted before the daemon marked
   the group, so a crash left an "active" group with no MLS state.
4. **Invite creation:** the relay registered the invite before the daemon
   recorded it, which orphaned the secret.
5. `synchronous=NORMAL` in WAL mode: a power loss could undo daemon
   transactions whose effects (frames, acks) had already gone out.

The core was not atomic on its own either. OpenMLS's SQLite provider owned
its connection, so the core's records went through a second connection, and
a merge was a dozen separate autocommit writes. A crash in the middle could
leave a torn group.

## Options

### A. A processing journal in the core's store

The core writes the result of processing (the event with the decrypted
message, the commit summary, the joined group id) to a journal table **in the
same SQLite transaction** as the MLS state change, keyed by the caller's id
for the message (`sender/msg_id`) and bound to the SHA-256 of its bytes.
Processing the same bytes under the same key again returns the journalled
result instead of failing. The daemon records the result, consumes the
entry (its plaintext is deleted and its key and hash kept to recognise a
redelivery), and only then acks. On start it finishes every entry not yet
consumed.

### B. Two-phase stage/commit

`process` returns a staged result without storing anything. The daemon
records the result and then tells the core to commit.

- The crash window moves rather than closes: between the daemon's commit and
  the core's, the daemon has recorded a message whose key the core will
  reuse. After a restart the core decrypts it again, and the daemon must
  deduplicate it anyway (its inbox does), so B needs most of A's
  bookkeeping.
- OpenMLS writes to storage *during* `process_message` and
  `merge_staged_commit`. Staging would mean buffering every storage write in
  memory and replaying it later, which is a second storage provider of our
  own.
- An application message would stay decryptable until the daemon commits,
  so the plaintext path depends on the daemon finishing promptly.

### C. Move the daemon's tables into the core's database

One file, one connection, so `process` and the inbox insert share a
transaction. That makes the core run the daemon's schema and SQL, crosses
the PyO3 boundary for every daemon query on the MLS connection, and still
doesn't help with effects outside SQLite (keystore, relay). It would also
undo ADR-003's separation of keys.

## Decision

**Option A.**

### Core

- **One connection.** `SqliteStore` owns a single `rusqlite::Connection`.
  OpenMLS's state goes through `openmls_sqlite_storage::SqliteStorageProvider`
  over a *borrowed* `&Connection`, created per call by a thin delegating
  `StorageProvider` (`provider.rs`). The OpenMLS book's guidance is the same:
  the storage traits have no transaction API, so atomicity comes from the
  backing store, by running the provider against the connection that holds
  the transaction. A shared `Arc<Connection>` isn't possible
  (`Connection` is `Send` but not `Sync`, and the store must be `Send`), and
  the crate forbids `unsafe`, so delegation is the safe way to share it.
  Records and the journal (`agentconnect_journal`) use the same connection.
- **Every operation is a transaction** (a SQLite savepoint, so they nest):
  group creation, KeyPackage creation, every commit build, confirm, discard,
  seal, process, join and delete. On failure the transaction rolls back and
  the in-memory group is reloaded from the store, so a failed step leaves
  nothing behind and can be retried. Two failures commit on purpose: an own
  commit lost (SPEC §8.3: the pending commit is discarded) and a failed
  Welcome (SPEC §6.3: the KeyPackage is spent), unless the store itself
  failed. A panic rolls back too (the transaction guard runs on unwind).
- **The journal.** `Group::process_journaled`,
  `Group::confirm_pending_commit_journaled` and `Client::join_journaled`
  take a key and opaque caller context. `Client::journal_pending`,
  `journal_consume` and `journal_purge` complete the API. An own commit is
  journalled under the key its fan-out copy arrives under
  (`own mailbox/msg_id`), so whichever of `accepted` and the fan-out comes
  first confirms it and the other gets the same result. A key reused for
  other bytes is `JournalConflict`; a consumed key is `Duplicate`.
- `synchronous=FULL` and `secure_delete=ON` on the store, so consumed
  plaintext is overwritten.

### Daemon

- Every journalled result is finished by recording its effects (the inbox
  row, members, policy, epoch, events, queued sends) in **one** daemon
  transaction. The inbox row `(sender, msg_id)` is the marker that the entry
  was applied, so a replay after that transaction only consumes the entry.
  Events are recorded in the transaction; adapters are told after it
  commits. Effects outside SQLite (deleting the core's group state, the
  join secret) run after it and are swept on start if a crash skipped them.
- Who joined or left a group comes from the commit summary, not from a diff
  of the cache, so a replay emits the same events.
- On start (and on every reconnect) the inbound worker first finishes every
  pending journal entry. Transient failures are retried in order with the
  same key; a retry that finds the result journalled records it once, so
  delivery to the adapter stays exactly-once.
- A removal records the daemon's state first and deletes the core's after.
- Invites are recorded as `registering` before the relay hears of them; one
  left behind by a crash is revoked and its secret deleted on the next
  connect.
- The daemon database uses `synchronous=FULL`.

### Fault injection

Both sides have test-only failpoints at every step boundary (TESTING.md).
They are inert unless a test arms one: one atomic load (core) or one falsy
check (daemon) per point.

## Consequences

- Nothing visible to peers changes: no wire format, no relay behaviour.
  SPEC is unchanged.
- Plaintext lives in the encrypted core store from processing until the
  daemon has recorded it (normally the same event-loop step), then only in
  the daemon's inbox until the adapter takes it (ADR-003 retention).
- Journal tombstones (ids and hashes) are kept for the relay's message TTL
  (7 days) and purged after.
- Delivery to the adapter is exactly-once except for a crash between the
  adapter accepting a delivery and the daemon recording that: the delivery
  is then repeated with the same `msg_id`, which adapters can deduplicate.
- Adapter event notifications (`on_event`) are at most once: a crash after
  the events are recorded and before the adapter hears of them leaves them
  in the local API's event log only.
- The delegating storage provider has to follow `openmls_sqlite_storage`'s
  trait when OpenMLS is upgraded (the compiler enforces the signatures).
