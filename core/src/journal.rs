//! The processing journal (ADR-004) and store transactions.
//!
//! Processing a message from the relay is one-shot: it consumes a ratchet
//! key or merges a commit. So the *result* of processing (the decrypted
//! message, the commit summary, the joined group) is written to the journal
//! in the same store transaction as the MLS state change. A caller that
//! crashes or fails before it has recorded the result itself processes the
//! same bytes again under the same key and gets the journalled result back
//! instead of an error, and on start it can list every entry it has not
//! consumed yet. Consuming an entry deletes its result (the plaintext) and
//! keeps its key and hash, so a later redelivery is recognised as a
//! duplicate until the entry is purged (after the relay's message TTL).

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::group::Event;
use crate::provider::{JournalRow, Store};

/// The journal scope of Welcome entries (a group message's scope is its
/// group id).
pub(crate) const WELCOME_SCOPE: &[u8] = b"";

/// A journalled operation's outcome.
#[derive(Debug)]
pub struct Journaled<T> {
    /// The result.
    pub value: T,
    /// Whether it came from the journal: the operation already ran under
    /// this key (before a crash or a failure of the caller), and this is
    /// its result again, not a second processing.
    pub replayed: bool,
}

/// What a journal entry holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum Stored {
    /// The event of a processed group message or a confirmed own commit.
    Event {
        /// The event.
        event: Event,
    },
    /// A processed Welcome; the entry's `group_id` is the joined group.
    Joined,
}

/// An entry not consumed yet, from [`crate::Client::journal_pending`].
#[derive(Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// The group (for a Welcome, the group it joined).
    pub group_id: Vec<u8>,
    /// The caller's key.
    pub key: String,
    /// Whether this is a Welcome entry (consume it with no group id).
    pub welcome: bool,
    /// The caller's context bytes, as given.
    pub context: Vec<u8>,
    /// The event; `None` for a Welcome.
    pub event: Option<Event>,
}

impl std::fmt::Debug for JournalEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The event can hold plaintext: show its kind only.
        f.debug_struct("JournalEntry")
            .field("key", &self.key)
            .field("welcome", &self.welcome)
            .field("event", &self.event.as_ref().map(Event::kind))
            .finish_non_exhaustive()
    }
}

pub(crate) fn encode(stored: &Stored) -> Result<Vec<u8>> {
    serde_json::to_vec(stored).map_err(|_| Error::Internal("journal encoding"))
}

fn decode(raw: &[u8]) -> Result<Stored> {
    serde_json::from_slice(raw).map_err(|_| Error::Storage("corrupt journal entry".into()))
}

/// Looks `key` up before processing. `Ok(None)`: not journalled, process
/// it. `Ok(Some(_))`: journalled and not consumed, here is the result.
///
/// # Errors
///
/// [`Error::Duplicate`] if the entry was consumed;
/// [`Error::JournalConflict`] if `hash` is given and differs from the
/// journalled bytes' hash (the same key for other bytes).
pub(crate) fn lookup<S: Store>(
    store: &S,
    scope: &[u8],
    key: &str,
    hash: Option<&str>,
) -> Result<Option<(JournalRow, Stored)>> {
    let Some(row) = store.journal_get(scope, key)? else {
        return Ok(None);
    };
    if hash.is_some_and(|h| h != row.hash) {
        return Err(Error::JournalConflict);
    }
    match &row.result {
        None => Err(Error::Duplicate),
        Some(raw) => {
            let stored = decode(raw)?;
            Ok(Some((row, stored)))
        }
    }
}

/// Writes a new entry (inside the caller's transaction).
#[allow(clippy::too_many_arguments)]
pub(crate) fn record<S: Store>(
    store: &S,
    scope: &[u8],
    group_id: &[u8],
    key: &str,
    hash: &str,
    context: &[u8],
    stored: &Stored,
    at: u64,
) -> Result<()> {
    store.journal_put(&JournalRow {
        scope: scope.to_vec(),
        key: key.to_owned(),
        group_id: group_id.to_vec(),
        hash: hash.to_owned(),
        at,
        result: Some(encode(stored)?),
        context: Some(context.to_vec()),
    })
}

pub(crate) fn entry(row: JournalRow) -> Result<JournalEntry> {
    let stored = decode(row.result.as_deref().unwrap_or_default())?;
    Ok(JournalEntry {
        welcome: row.scope == WELCOME_SCOPE,
        group_id: row.group_id,
        key: row.key,
        context: row.context.unwrap_or_default(),
        event: match stored {
            Stored::Event { event } => Some(event),
            Stored::Joined => None,
        },
    })
}

/// A store transaction: rolled back when dropped without
/// [`Tx::commit`], including while unwinding from a panic.
pub(crate) struct Tx<'a, S: Store> {
    store: &'a S,
    open: bool,
}

impl<'a, S: Store> Tx<'a, S> {
    pub(crate) fn begin(store: &'a S) -> Result<Self> {
        store.begin()?;
        Ok(Self { store, open: true })
    }

    pub(crate) fn commit(mut self) -> Result<()> {
        self.open = false;
        if let Err(e) = self.store.commit() {
            // Best effort: the error is what the caller needs.
            let _ = self.store.rollback();
            return Err(e);
        }
        Ok(())
    }
}

impl<S: Store> Drop for Tx<'_, S> {
    fn drop(&mut self) {
        if self.open {
            let _ = self.store.rollback();
        }
    }
}

/// Errors after which the work done so far is still committed: the
/// operation changed state on purpose before failing (an own commit lost,
/// SPEC §8.3; a Welcome that fails consumes the KeyPackage, SPEC §6.3).
/// Storage, internal (panic) and RNG failures always roll back.
pub(crate) fn keeps_state(e: &Error) -> bool {
    !matches!(
        e,
        Error::Storage(_) | Error::StorageKey | Error::Internal(_) | Error::Rng
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::sealed::Backend as _;
    use crate::provider::{MemoryStore, SqliteStore};

    fn exercise<S: Store>(store: &S) {
        let gid = b"group-id-16bytes";
        assert_eq!(lookup(store, gid, "k", None).unwrap(), None);
        let stored = Stored::Event {
            event: Event::OwnEcho,
        };
        // A rolled-back write leaves nothing.
        {
            let _tx = Tx::begin(store).unwrap();
            record(store, gid, gid, "k", "h", b"ctx", &stored, 10).unwrap();
        }
        assert_eq!(lookup(store, gid, "k", None).unwrap(), None);
        let tx = Tx::begin(store).unwrap();
        record(store, gid, gid, "k", "h", b"ctx", &stored, 10).unwrap();
        // Transactions nest.
        {
            let _inner = Tx::begin(store).unwrap();
            record(store, gid, gid, "k2", "h", b"", &stored, 11).unwrap();
        }
        tx.commit().unwrap();
        let (row, got) = lookup(store, gid, "k", Some("h")).unwrap().unwrap();
        assert_eq!(got, stored);
        assert_eq!(row.context.as_deref(), Some(&b"ctx"[..]));
        assert_eq!(lookup(store, gid, "k2", None).unwrap(), None);
        assert_eq!(
            lookup(store, gid, "k", Some("other")).unwrap_err(),
            Error::JournalConflict
        );
        record(
            store,
            WELCOME_SCOPE,
            gid,
            "w",
            "h",
            b"",
            &Stored::Joined,
            12,
        )
        .unwrap();
        let pending: Vec<JournalEntry> = store
            .journal_pending()
            .unwrap()
            .into_iter()
            .map(|r| entry(r).unwrap())
            .collect();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].event, Some(Event::OwnEcho));
        assert!(pending[1].welcome && pending[1].event.is_none());
        assert!(format!("{:?}", pending[0]).contains("own_echo"));
        // Consumed: a tombstone, purged once old enough.
        let mut consumed = row;
        consumed.result = None;
        consumed.context = None;
        store.journal_put(&consumed).unwrap();
        assert_eq!(lookup(store, gid, "k", None).unwrap_err(), Error::Duplicate);
        assert_eq!(store.journal_purge(10).unwrap(), 0);
        assert_eq!(store.journal_purge(11).unwrap(), 1);
        assert_eq!(lookup(store, gid, "k", None).unwrap(), None);
        store.journal_delete_group(gid).unwrap();
        assert_eq!(store.journal_pending().unwrap().len(), 0);
        store
            .journal_put(&JournalRow {
                result: Some(b"junk".to_vec()),
                ..consumed
            })
            .unwrap();
        assert!(matches!(
            lookup(store, gid, "k", None),
            Err(Error::Storage(_))
        ));
        assert!(keeps_state(&Error::MetaMismatch));
        assert!(!keeps_state(&Error::Storage(String::new())));
    }

    #[test]
    fn journal_round_trips_in_both_stores() {
        exercise(&MemoryStore::new());
        exercise(&SqliteStore::open_in_memory().unwrap());
    }

    #[test]
    fn unbalanced_memory_transactions_fail() {
        let store = MemoryStore::new();
        assert!(store.commit().is_err());
        assert!(store.rollback().is_err());
    }
}
