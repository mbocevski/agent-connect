//! Storage backends and the OpenMLS provider that combines them with
//! libcrux crypto and our [`Rng`].
//!
//! # Encryption at rest
//!
//! [`SqliteStore`] is a SQLCipher database (ADR-002): every page of the
//! file, its journal and its WAL is encrypted and authenticated under a
//! 32-byte [`DbKey`] that the daemon keeps in its keystore. There is no
//! unencrypted file mode. [`SqliteStore::open_in_memory`] and
//! [`MemoryStore`] never touch the disk and are for tests.
//!
//! Besides the OpenMLS state, a store keeps a few records of `core`'s own
//! (pending-commit confirmation data, consumed KeyPackage refs, the previous
//! epoch's members) in a small key-value table, and the processing journal
//! (ADR-004).
//!
//! # Transactions
//!
//! OpenMLS, `core`'s records and the journal share **one** SQLite
//! connection, so one transaction covers all of them: processing a message
//! changes the MLS state and writes its journal entry atomically, or not at
//! all. Transactions are SQLite savepoints, so they nest.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Mutex;

use hkdf::Hkdf;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};
use rusqlite::{ErrorCode, OpenFlags, OptionalExtension as _};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result, storage};
use crate::rng::Rng;

/// Length of a [`DbKey`] in bytes.
pub const DB_KEY_LEN: usize = 32;

/// The key that encrypts a [`SqliteStore`] at rest: 32 random bytes, used
/// as a raw SQLCipher key (no passphrase derivation). Zeroized on drop and
/// never printed.
#[derive(Clone)]
pub struct DbKey(Zeroizing<[u8; DB_KEY_LEN]>);

impl DbKey {
    /// A key from its 32 bytes (e.g. read from the daemon's keystore).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] unless `bytes` is exactly 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; DB_KEY_LEN]);
        if bytes.len() != DB_KEY_LEN {
            return Err(Error::Malformed("database key (must be 32 bytes)"));
        }
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// A fresh random key.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the RNG fails.
    pub fn generate(rng: &Rng) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; DB_KEY_LEN]);
        rng.fill(key.as_mut())?;
        Ok(Self(key))
    }

    /// The key bytes, for storing in a keystore.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; DB_KEY_LEN] {
        &self.0
    }

    /// A key for another database, derived from this one:
    /// HKDF-SHA256(ikm = this key, no salt, `info`, L = 32). Distinct `info`
    /// labels give independent keys, so one keystore entry can key several
    /// files without any two sharing a key (ADR-003).
    #[must_use]
    pub fn derive(&self, info: &[u8]) -> Self {
        let mut key = Zeroizing::new([0u8; DB_KEY_LEN]);
        // 32 bytes is far below HKDF-SHA256's 8160-byte limit, so this can't fail.
        if Hkdf::<Sha256>::new(None, self.0.as_slice())
            .expand(info, key.as_mut_slice())
            .is_err()
        {
            unreachable!("HKDF-SHA256 output of 32 bytes is always valid");
        }
        Self(key)
    }

    /// `PRAGMA <pragma> = "x'<hex>'";`, the raw-key form, in a buffer that
    /// is zeroized on drop.
    fn pragma(&self, pragma: &str) -> Zeroizing<String> {
        let mut sql = Zeroizing::new(String::with_capacity(32 + 2 * DB_KEY_LEN));
        sql.push_str("PRAGMA ");
        sql.push_str(pragma);
        sql.push_str(" = \"x'");
        for b in self.0.iter() {
            // Writing to a String can't fail.
            let _ = write!(sql, "{b:02X}");
        }
        sql.push_str("'\";");
        sql
    }
}

impl std::fmt::Debug for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DbKey(..)")
    }
}

pub(crate) mod sealed {
    /// One processing-journal entry (ADR-004). `result` and `context` are
    /// `None` once the entry is consumed: only the ids and the hash stay, to
    /// recognise a redelivery.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct JournalRow {
        /// The group for a group message; empty for a Welcome.
        pub scope: Vec<u8>,
        /// The caller's key (e.g. `sender/msg_id`).
        pub key: String,
        /// The group the entry belongs to (for a Welcome, the joined group).
        pub group_id: Vec<u8>,
        /// SHA-256 (hex) of the processed bytes.
        pub hash: String,
        /// When it was written (Unix seconds).
        pub at: u64,
        /// The processing result (JSON), until consumed.
        pub result: Option<Vec<u8>>,
        /// The caller's context bytes, until consumed.
        pub context: Option<Vec<u8>>,
    }

    /// OpenMLS over a connection we own, so that `core`'s records and the
    /// journal share it (and its transactions).
    pub struct SqliteMls {
        pub(crate) conn: rusqlite::Connection,
    }

    /// The OpenMLS storage behind a [`super::Store`], plus `core`'s own
    /// key-value records, the journal and transactions.
    pub trait Backend {
        /// The OpenMLS storage provider.
        type Inner: openmls::storage::StorageProvider;
        /// Borrows it.
        fn inner(&self) -> &Self::Inner;
        /// Reads one of `core`'s records.
        fn get_record(&self, key: &[u8]) -> crate::Result<Option<Vec<u8>>>;
        /// Writes (`Some`) or deletes (`None`) one of `core`'s records.
        fn put_record(&self, key: &[u8], value: Option<&[u8]>) -> crate::Result<()>;
        /// Opens a (nested) transaction over everything in the store.
        fn begin(&self) -> crate::Result<()>;
        /// Commits the innermost open transaction.
        fn commit(&self) -> crate::Result<()>;
        /// Rolls back the innermost open transaction.
        fn rollback(&self) -> crate::Result<()>;
        /// One journal entry.
        fn journal_get(&self, scope: &[u8], key: &str) -> crate::Result<Option<JournalRow>>;
        /// Inserts or replaces a journal entry.
        fn journal_put(&self, row: &JournalRow) -> crate::Result<()>;
        /// Every entry not yet consumed, oldest first.
        fn journal_pending(&self) -> crate::Result<Vec<JournalRow>>;
        /// Deletes every entry of a group (with the group).
        fn journal_delete_group(&self, group_id: &[u8]) -> crate::Result<()>;
        /// Deletes consumed entries written before `before`; returns how many.
        fn journal_purge(&self, before: u64) -> crate::Result<u64>;
        /// Deletes every OpenMLS row still keyed by the group, after
        /// `MlsGroup::delete`. That deletes the HPKE key pairs of the
        /// current epoch only, so a member that merged its own removal kept
        /// the previous epoch's (SR-61).
        fn delete_group_mls_rows(&self, group_id: &[u8]) -> crate::Result<()>;
    }
}

pub(crate) use sealed::JournalRow;
use sealed::SqliteMls;

/// A storage backend for MLS state. Implemented by [`MemoryStore`] (tests)
/// and [`SqliteStore`] (daemons).
pub trait Store: sealed::Backend + Send {}

/// In-memory storage, for tests. A transaction snapshots the whole store
/// and a rollback restores it.
#[derive(Debug, Default)]
pub struct MemoryStore {
    mls: MemoryStorage,
    records: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    journal: Mutex<BTreeMap<(Vec<u8>, String), JournalRow>>,
    snapshots: Mutex<Vec<Snapshot>>,
}

type Snapshot = (
    HashMap<Vec<u8>, Vec<u8>>,
    HashMap<Vec<u8>, Vec<u8>>,
    BTreeMap<(Vec<u8>, String), JournalRow>,
);

fn locked<T>(m: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| Error::Storage("memory store lock poisoned".into()))
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of the whole store: what an attacker who copies its state to
    /// try commits offline holds (SR-01). **Tests only.**
    #[cfg(test)]
    pub(crate) fn fork_for_testing(&self) -> Self {
        let copy = Self::default();
        if let (Ok(src), Ok(mut dst)) = (self.mls.values.read(), copy.mls.values.write()) {
            dst.clone_from(&src);
        }
        if let (Ok(src), Ok(mut dst)) = (self.records.lock(), copy.records.lock()) {
            dst.clone_from(&src);
        }
        if let (Ok(src), Ok(mut dst)) = (self.journal.lock(), copy.journal.lock()) {
            dst.clone_from(&src);
        }
        copy
    }

    /// How many MLS values the store holds (key packages, keys, groups).
    #[cfg(test)]
    pub(crate) fn mls_value_count(&self) -> usize {
        self.mls.values.read().map_or(0, |v| v.len())
    }

    fn mls_values(&self) -> Result<std::sync::RwLockWriteGuard<'_, HashMap<Vec<u8>, Vec<u8>>>> {
        self.mls
            .values
            .write()
            .map_err(|_| Error::Storage("memory store lock poisoned".into()))
    }
}

impl sealed::Backend for MemoryStore {
    type Inner = MemoryStorage;
    fn inner(&self) -> &MemoryStorage {
        &self.mls
    }

    fn get_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(locked(&self.records)?.get(key).cloned())
    }

    fn put_record(&self, key: &[u8], value: Option<&[u8]>) -> Result<()> {
        let mut records = locked(&self.records)?;
        match value {
            Some(v) => records.insert(key.to_vec(), v.to_vec()),
            None => records.remove(key),
        };
        Ok(())
    }

    fn begin(&self) -> Result<()> {
        let snap = (
            self.mls_values()?.clone(),
            locked(&self.records)?.clone(),
            locked(&self.journal)?.clone(),
        );
        locked(&self.snapshots)?.push(snap);
        Ok(())
    }

    fn commit(&self) -> Result<()> {
        locked(&self.snapshots)?
            .pop()
            .map(drop)
            .ok_or(Error::Internal("commit without a transaction"))
    }

    fn rollback(&self) -> Result<()> {
        let (mls, records, journal) = locked(&self.snapshots)?
            .pop()
            .ok_or(Error::Internal("rollback without a transaction"))?;
        *self.mls_values()? = mls;
        *locked(&self.records)? = records;
        *locked(&self.journal)? = journal;
        Ok(())
    }

    fn journal_get(&self, scope: &[u8], key: &str) -> Result<Option<JournalRow>> {
        Ok(locked(&self.journal)?
            .get(&(scope.to_vec(), key.to_owned()))
            .cloned())
    }

    fn journal_put(&self, row: &JournalRow) -> Result<()> {
        locked(&self.journal)?.insert((row.scope.clone(), row.key.clone()), row.clone());
        Ok(())
    }

    fn journal_pending(&self) -> Result<Vec<JournalRow>> {
        let mut rows: Vec<JournalRow> = locked(&self.journal)?
            .values()
            .filter(|r| r.result.is_some())
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.at);
        Ok(rows)
    }

    fn journal_delete_group(&self, group_id: &[u8]) -> Result<()> {
        locked(&self.journal)?.retain(|_, r| r.group_id != group_id);
        Ok(())
    }

    fn journal_purge(&self, before: u64) -> Result<u64> {
        let mut journal = locked(&self.journal)?;
        let n = journal.len();
        journal.retain(|_, r| r.result.is_some() || r.at >= before);
        Ok((n - journal.len()) as u64)
    }

    fn delete_group_mls_rows(&self, group_id: &[u8]) -> Result<()> {
        // Every entry keyed by the group has its serialised id in the key.
        let key = mls_group_key(group_id)?;
        self.mls_values()?
            .retain(|k, _| !k.windows(key.len()).any(|w| w == key.as_slice()));
        Ok(())
    }
}

/// A group id as both OpenMLS stores encode it in their keys (JSON).
fn mls_group_key(group_id: &[u8]) -> Result<Vec<u8>> {
    serde_json::to_vec(&openmls::group::GroupId::from_slice(group_id)).map_err(storage)
}

impl Store for MemoryStore {}

/// JSON codec for the SQLite storage provider.
#[derive(Debug, Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// Encrypted SQLite storage: a SQLCipher database with OpenMLS's schema, run
/// through its migrations.
///
/// OpenMLS, `core`'s records (table `agentconnect_records`) and the journal
/// (`agentconnect_journal`) share one connection, keyed before any other
/// statement runs, so one transaction covers all three.
pub struct SqliteStore {
    mls: SqliteMls,
}

const RECORDS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS agentconnect_records \
     (key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL); \
     CREATE TABLE IF NOT EXISTS agentconnect_journal \
     (scope BLOB NOT NULL, key TEXT NOT NULL, group_id BLOB NOT NULL, \
      hash TEXT NOT NULL, at INTEGER NOT NULL, result BLOB, context BLOB, \
      PRIMARY KEY (scope, key)); \
     CREATE INDEX IF NOT EXISTS agentconnect_journal_group \
     ON agentconnect_journal (group_id);";

const JOURNAL_COLUMNS: &str = "scope, key, group_id, hash, at, result, context";

fn journal_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<JournalRow> {
    Ok(JournalRow {
        scope: r.get(0)?,
        key: r.get(1)?,
        group_id: r.get(2)?,
        hash: r.get(3)?,
        at: r.get::<_, i64>(4)?.try_into().unwrap_or(0),
        result: r.get(5)?,
        context: r.get(6)?,
    })
}

/// The savepoint every [`sealed::Backend::begin`] opens.
const SAVEPOINT: &str = "agentconnect_tx";

/// OpenMLS's SQLite provider over our connection, borrowed for one call.
impl SqliteMls {
    fn provider(&self) -> SqliteStorageProvider<JsonCodec, &Connection> {
        SqliteStorageProvider::new(&self.conn)
    }
}

const V: u16 = CURRENT_VERSION;

/// Every method delegates to `openmls_sqlite_storage`'s provider over the
/// shared connection.
impl StorageProvider<V> for SqliteMls {
    type Error = rusqlite::Error;

    fn write_mls_join_config<
        GroupId: traits::GroupId<V>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<V>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_mls_join_config::<GroupId, MlsGroupJoinConfig>(group_id, config)
    }

    fn append_own_leaf_node<GroupId: traits::GroupId<V>, LeafNode: traits::LeafNode<V>>(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.provider()
            .append_own_leaf_node::<GroupId, LeafNode>(group_id, leaf_node)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<V>,
        ProposalRef: traits::ProposalRef<V>,
        QueuedProposal: traits::QueuedProposal<V>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        self.provider()
            .queue_proposal::<GroupId, ProposalRef, QueuedProposal>(
                group_id,
                proposal_ref,
                proposal,
            )
    }

    fn write_tree<GroupId: traits::GroupId<V>, TreeSync: traits::TreeSync<V>>(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_tree::<GroupId, TreeSync>(group_id, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<V>,
        InterimTranscriptHash: traits::InterimTranscriptHash<V>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_interim_transcript_hash::<GroupId, InterimTranscriptHash>(
                group_id,
                interim_transcript_hash,
            )
    }

    fn write_context<GroupId: traits::GroupId<V>, GroupContext: traits::GroupContext<V>>(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_context::<GroupId, GroupContext>(group_id, group_context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<V>,
        ConfirmationTag: traits::ConfirmationTag<V>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_confirmation_tag::<GroupId, ConfirmationTag>(group_id, confirmation_tag)
    }

    fn write_group_state<GroupState: traits::GroupState<V>, GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_group_state::<GroupState, GroupId>(group_id, group_state)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<V>,
        MessageSecrets: traits::MessageSecrets<V>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_message_secrets::<GroupId, MessageSecrets>(group_id, message_secrets)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<V>,
        ResumptionPskStore: traits::ResumptionPskStore<V>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_resumption_psk_store::<GroupId, ResumptionPskStore>(
                group_id,
                resumption_psk_store,
            )
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<V>,
        LeafNodeIndex: traits::LeafNodeIndex<V>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_own_leaf_index::<GroupId, LeafNodeIndex>(group_id, own_leaf_index)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<V>,
        GroupEpochSecrets: traits::GroupEpochSecrets<V>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_group_epoch_secrets::<GroupId, GroupEpochSecrets>(group_id, group_epoch_secrets)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<V>,
        SignatureKeyPair: traits::SignatureKeyPair<V>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_signature_key_pair::<SignaturePublicKey, SignatureKeyPair>(
                public_key,
                signature_key_pair,
            )
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<V>,
        HpkeKeyPair: traits::HpkeKeyPair<V>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_encryption_key_pair::<EncryptionKey, HpkeKeyPair>(public_key, key_pair)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<V>,
        EpochKey: traits::EpochKey<V>,
        HpkeKeyPair: traits::HpkeKeyPair<V>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_encryption_epoch_key_pairs::<GroupId, EpochKey, HpkeKeyPair>(
                group_id, epoch, leaf_index, key_pairs,
            )
    }

    fn write_key_package<
        HashReference: traits::HashReference<V>,
        KeyPackage: traits::KeyPackage<V>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.provider()
            .write_key_package::<HashReference, KeyPackage>(hash_ref, key_package)
    }

    fn write_psk<PskId: traits::PskId<V>, PskBundle: traits::PskBundle<V>>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.provider().write_psk::<PskId, PskBundle>(psk_id, psk)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<V>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.provider()
            .mls_group_join_config::<GroupId, MlsGroupJoinConfig>(group_id)
    }

    fn own_leaf_nodes<GroupId: traits::GroupId<V>, LeafNode: traits::LeafNode<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.provider()
            .own_leaf_nodes::<GroupId, LeafNode>(group_id)
    }

    fn queued_proposal_refs<GroupId: traits::GroupId<V>, ProposalRef: traits::ProposalRef<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.provider()
            .queued_proposal_refs::<GroupId, ProposalRef>(group_id)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<V>,
        ProposalRef: traits::ProposalRef<V>,
        QueuedProposal: traits::QueuedProposal<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        self.provider()
            .queued_proposals::<GroupId, ProposalRef, QueuedProposal>(group_id)
    }

    fn tree<GroupId: traits::GroupId<V>, TreeSync: traits::TreeSync<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.provider().tree::<GroupId, TreeSync>(group_id)
    }

    fn group_context<GroupId: traits::GroupId<V>, GroupContext: traits::GroupContext<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.provider()
            .group_context::<GroupId, GroupContext>(group_id)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<V>,
        InterimTranscriptHash: traits::InterimTranscriptHash<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.provider()
            .interim_transcript_hash::<GroupId, InterimTranscriptHash>(group_id)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<V>,
        ConfirmationTag: traits::ConfirmationTag<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.provider()
            .confirmation_tag::<GroupId, ConfirmationTag>(group_id)
    }

    fn group_state<GroupState: traits::GroupState<V>, GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.provider().group_state::<GroupState, GroupId>(group_id)
    }

    fn message_secrets<GroupId: traits::GroupId<V>, MessageSecrets: traits::MessageSecrets<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.provider()
            .message_secrets::<GroupId, MessageSecrets>(group_id)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<V>,
        ResumptionPskStore: traits::ResumptionPskStore<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.provider()
            .resumption_psk_store::<GroupId, ResumptionPskStore>(group_id)
    }

    fn own_leaf_index<GroupId: traits::GroupId<V>, LeafNodeIndex: traits::LeafNodeIndex<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.provider()
            .own_leaf_index::<GroupId, LeafNodeIndex>(group_id)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<V>,
        GroupEpochSecrets: traits::GroupEpochSecrets<V>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.provider()
            .group_epoch_secrets::<GroupId, GroupEpochSecrets>(group_id)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<V>,
        SignatureKeyPair: traits::SignatureKeyPair<V>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.provider()
            .signature_key_pair::<SignaturePublicKey, SignatureKeyPair>(public_key)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<V>,
        EncryptionKey: traits::EncryptionKey<V>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.provider()
            .encryption_key_pair::<HpkeKeyPair, EncryptionKey>(public_key)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<V>,
        EpochKey: traits::EpochKey<V>,
        HpkeKeyPair: traits::HpkeKeyPair<V>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        self.provider()
            .encryption_epoch_key_pairs::<GroupId, EpochKey, HpkeKeyPair>(
                group_id, epoch, leaf_index,
            )
    }

    fn key_package<KeyPackageRef: traits::HashReference<V>, KeyPackage: traits::KeyPackage<V>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.provider()
            .key_package::<KeyPackageRef, KeyPackage>(hash_ref)
    }

    fn psk<PskBundle: traits::PskBundle<V>, PskId: traits::PskId<V>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.provider().psk::<PskBundle, PskId>(psk_id)
    }

    fn remove_proposal<GroupId: traits::GroupId<V>, ProposalRef: traits::ProposalRef<V>>(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        self.provider()
            .remove_proposal::<GroupId, ProposalRef>(group_id, proposal_ref)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider().delete_own_leaf_nodes::<GroupId>(group_id)
    }

    fn delete_group_config<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider().delete_group_config::<GroupId>(group_id)
    }

    fn delete_tree<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider().delete_tree::<GroupId>(group_id)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider().delete_confirmation_tag::<GroupId>(group_id)
    }

    fn delete_group_state<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider().delete_group_state::<GroupId>(group_id)
    }

    fn delete_context<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider().delete_context::<GroupId>(group_id)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider()
            .delete_interim_transcript_hash::<GroupId>(group_id)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider().delete_message_secrets::<GroupId>(group_id)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider()
            .delete_all_resumption_psk_secrets::<GroupId>(group_id)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider().delete_own_leaf_index::<GroupId>(group_id)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider()
            .delete_group_epoch_secrets::<GroupId>(group_id)
    }

    fn clear_proposal_queue<GroupId: traits::GroupId<V>, ProposalRef: traits::ProposalRef<V>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.provider()
            .clear_proposal_queue::<GroupId, ProposalRef>(group_id)
    }

    fn delete_signature_key_pair<SignaturePublicKey: traits::SignaturePublicKey<V>>(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.provider()
            .delete_signature_key_pair::<SignaturePublicKey>(public_key)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<V>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.provider()
            .delete_encryption_key_pair::<EncryptionKey>(public_key)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<V>,
        EpochKey: traits::EpochKey<V>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        self.provider()
            .delete_encryption_epoch_key_pairs::<GroupId, EpochKey>(group_id, epoch, leaf_index)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<V>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.provider()
            .delete_key_package::<KeyPackageRef>(hash_ref)
    }

    fn delete_psk<PskKey: traits::PskId<V>>(&self, psk_id: &PskKey) -> Result<(), Self::Error> {
        self.provider().delete_psk::<PskKey>(psk_id)
    }
}

/// Maps "file is not a database", which is what SQLCipher reports for a
/// wrong key (or a file that isn't an encrypted database), to
/// [`Error::StorageKey`].
fn keyed_err(e: rusqlite::Error) -> Error {
    match e.sqlite_error_code() {
        Some(ErrorCode::NotADatabase) => Error::StorageKey,
        _ => storage(e),
    }
}

/// Applies `key` to a fresh connection and checks that it decrypts the file.
/// An empty (new) file accepts any key; it is encrypted on first write.
fn apply_key(conn: &Connection, key: &DbKey) -> Result<()> {
    // Fail closed if this build's SQLite isn't SQLCipher: without it,
    // `PRAGMA key` is silently ignored and the file would be plaintext.
    let cipher: Option<String> = conn
        .query_row("PRAGMA cipher_version", (), |r| r.get(0))
        .map_err(|_| Error::Internal("SQLite build without SQLCipher"))?;
    if cipher.is_none_or(|v| v.is_empty()) {
        return Err(Error::Internal("SQLite build without SQLCipher"));
    }
    conn.execute_batch(&key.pragma("key")).map_err(storage)?;
    conn.query_row("SELECT count(*) FROM sqlite_master", (), |r| {
        r.get::<_, i64>(0)
    })
    .map_err(keyed_err)?;
    Ok(())
}

/// The OpenMLS tables keyed by group id (every table of the provider's
/// schema with a `group_id` column), whatever its migrations added.
fn mls_group_tables(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT m.name FROM sqlite_master m, pragma_table_info(m.name) c \
             WHERE m.type = 'table' AND c.name = 'group_id' \
             AND m.name NOT LIKE 'agentconnect!_%' ESCAPE '!' ORDER BY m.name",
        )
        .map_err(storage)?;
    stmt.query_map((), |r| r.get(0))
        .map_err(storage)?
        .collect::<rusqlite::Result<Vec<String>>>()
        .map_err(storage)
}

/// Deletes the HPKE key pairs of groups that have no state left: what
/// deleting a group left behind before SR-61 was fixed. A group's state is
/// always written with its key pairs, so these belong to no group.
fn sweep_orphan_epoch_keys(conn: &Connection) -> Result<()> {
    conn.execute(
        "DELETE FROM openmls_epoch_keys_pairs \
         WHERE group_id NOT IN (SELECT group_id FROM openmls_group_data)",
        (),
    )
    .map(drop)
    .map_err(storage)
}

pub(crate) fn open_keyed(path: &Path, key: &DbKey, flags: OpenFlags) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, flags).map_err(storage)?;
    apply_key(&conn, key)?;
    Ok(conn)
}

impl SqliteStore {
    /// Opens or creates the encrypted database at `path` under `key`.
    ///
    /// # Errors
    ///
    /// - [`Error::StorageKey`] if `key` doesn't decrypt the file (a wrong
    ///   key, or a file that isn't an encrypted store).
    /// - [`Error::Storage`] on any other SQLite or migration error.
    pub fn open(path: &Path, key: &DbKey) -> Result<Self> {
        Self::from_connection(open_keyed(path, key, OpenFlags::default())?)
    }

    /// Re-encrypts the existing database at `path` from `old` to `new`
    /// (SQLCipher `PRAGMA rekey`). The store must not be open anywhere else
    /// while this runs. It's one transaction: if it fails, the file stays
    /// under `old`.
    ///
    /// # Errors
    ///
    /// - [`Error::StorageKey`] if `old` doesn't decrypt the file.
    /// - [`Error::Storage`] if the file doesn't exist or SQLite fails.
    pub fn rekey(path: &Path, old: &DbKey, new: &DbKey) -> Result<()> {
        let conn = open_keyed(path, old, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.execute_batch(&new.pragma("rekey"))
            .map_err(keyed_err)?;
        drop(conn);
        // Confirm the file now opens under `new`.
        open_keyed(path, new, OpenFlags::SQLITE_OPEN_READ_ONLY).map(drop)
    }

    /// A private in-memory SQLite database. It never touches the disk and
    /// is not encrypted. **Tests only.**
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] on any SQLite or migration error.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory().map_err(storage)?)
    }

    fn from_connection(mut conn: Connection) -> Result<Self> {
        // Durable commits (a crash never loses a committed journal entry)
        // and removed rows (consumed plaintext) overwritten in the file.
        conn.execute_batch("PRAGMA synchronous = FULL; PRAGMA secure_delete = ON;")
            .map_err(storage)?;
        SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut conn)
            .run_migrations()
            .map_err(storage)?;
        conn.execute_batch(RECORDS_SCHEMA).map_err(storage)?;
        sweep_orphan_epoch_keys(&conn)?;
        Ok(Self {
            mls: SqliteMls { conn },
        })
    }

    fn conn(&self) -> &Connection {
        &self.mls.conn
    }
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SqliteStore")
    }
}

impl sealed::Backend for SqliteStore {
    type Inner = SqliteMls;
    fn inner(&self) -> &Self::Inner {
        &self.mls
    }

    fn begin(&self) -> Result<()> {
        self.conn()
            .execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))
            .map_err(storage)
    }

    fn commit(&self) -> Result<()> {
        self.conn()
            .execute_batch(&format!("RELEASE {SAVEPOINT}"))
            .map_err(storage)
    }

    fn rollback(&self) -> Result<()> {
        self.conn()
            .execute_batch(&format!("ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT}"))
            .map_err(storage)
    }

    fn journal_get(&self, scope: &[u8], key: &str) -> Result<Option<JournalRow>> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {JOURNAL_COLUMNS} FROM agentconnect_journal \
                     WHERE scope = ?1 AND key = ?2"
                ),
                (scope, key),
                journal_row,
            )
            .optional()
            .map_err(storage)
    }

    fn journal_put(&self, row: &JournalRow) -> Result<()> {
        self.conn()
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO agentconnect_journal ({JOURNAL_COLUMNS}) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                ),
                (
                    &row.scope,
                    &row.key,
                    &row.group_id,
                    &row.hash,
                    i64::try_from(row.at).unwrap_or(i64::MAX),
                    &row.result,
                    &row.context,
                ),
            )
            .map(drop)
            .map_err(storage)
    }

    fn journal_pending(&self) -> Result<Vec<JournalRow>> {
        let mut stmt = self
            .conn()
            .prepare(&format!(
                "SELECT {JOURNAL_COLUMNS} FROM agentconnect_journal \
                 WHERE result IS NOT NULL ORDER BY at, rowid"
            ))
            .map_err(storage)?;
        stmt.query_map((), journal_row)
            .map_err(storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage)
    }

    fn journal_delete_group(&self, group_id: &[u8]) -> Result<()> {
        self.conn()
            .execute(
                "DELETE FROM agentconnect_journal WHERE group_id = ?1",
                (group_id,),
            )
            .map(drop)
            .map_err(storage)
    }

    fn journal_purge(&self, before: u64) -> Result<u64> {
        self.conn()
            .execute(
                "DELETE FROM agentconnect_journal WHERE result IS NULL AND at < ?1",
                (i64::try_from(before).unwrap_or(i64::MAX),),
            )
            .map(|n| n as u64)
            .map_err(storage)
    }

    fn delete_group_mls_rows(&self, group_id: &[u8]) -> Result<()> {
        let key = mls_group_key(group_id)?;
        for table in mls_group_tables(self.conn())? {
            self.conn()
                .execute(
                    &format!("DELETE FROM \"{table}\" WHERE group_id = ?1"),
                    (&key,),
                )
                .map_err(storage)?;
        }
        Ok(())
    }

    fn get_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn()
            .prepare_cached("SELECT value FROM agentconnect_records WHERE key = ?1")
            .map_err(storage)?;
        let mut rows = stmt.query((key,)).map_err(storage)?;
        match rows.next().map_err(storage)? {
            Some(row) => Ok(Some(row.get(0).map_err(storage)?)),
            None => Ok(None),
        }
    }

    fn put_record(&self, key: &[u8], value: Option<&[u8]>) -> Result<()> {
        match value {
            Some(v) => self.conn().execute(
                "INSERT INTO agentconnect_records (key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, v),
            ),
            None => self
                .conn()
                .execute("DELETE FROM agentconnect_records WHERE key = ?1", (key,)),
        }
        .map(|_| ())
        .map_err(storage)
    }
}

impl Store for SqliteStore {}

/// libcrux crypto + [`Rng`] + a [`Store`].
pub(crate) struct Provider<S: Store> {
    crypto: CryptoProvider,
    rand: Rng,
    store: S,
}

impl<S: Store> Provider<S> {
    pub(crate) fn new(store: S, rand: Rng) -> Result<Self> {
        Ok(Self {
            crypto: CryptoProvider::new().map_err(|_| Error::Rng)?,
            rand,
            store,
        })
    }

    pub(crate) fn rng(&self) -> &Rng {
        &self.rand
    }

    pub(crate) fn records(&self) -> &S {
        &self.store
    }
}

impl<S: Store> OpenMlsProvider for Provider<S> {
    type CryptoProvider = CryptoProvider;
    type RandProvider = Rng;
    type StorageProvider = S::Inner;

    fn storage(&self) -> &Self::StorageProvider {
        self.store.inner()
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::clock::FakeClock;
    use crate::group::Client;
    use crate::identity::Identity;
    use crate::invite::{Invite, InviteMeta};

    const MESSAGE: &str = "PLAINTEXT-MARKER-at-rest-message";
    const DISPLAY_NAME: &str = "PLAINTEXT-MARKER-display-name";

    fn key(label: &str) -> DbKey {
        DbKey::generate(&Rng::for_test(label)).unwrap()
    }

    fn client<S: Store>(store: S, seed: &str, clock: &Arc<FakeClock>) -> Client<S> {
        let rng = Rng::for_test(seed);
        let inst = Identity::generate(&rng)
            .unwrap()
            .create_instance(&rng, clock.as_ref())
            .unwrap();
        Client::new(
            store,
            Rng::for_test(&format!("{seed}-client")),
            inst,
            clock.clone(),
        )
        .unwrap()
    }

    /// A creates a group in memory, B joins it with state in `store`, and A
    /// sends B a message. Returns the group id.
    fn populate<S: Store>(store: S) -> Vec<u8> {
        let clock = Arc::new(FakeClock::default());
        let a = client(MemoryStore::new(), "storage-a", &clock);
        let b = client(store, "storage-b", &clock);
        let mut ga = a.create_group("g", "p").unwrap();
        let inv = Invite::create(a.rng(), a.clock(), "r.example", Duration::from_secs(60)).unwrap();
        let req = b.create_join_request(inv.secret(), DISPLAY_NAME).unwrap();
        let v = a.verify_join_request(&req, &inv).unwrap();
        let out = ga.add_member(&a, &v, &inv, true).unwrap();
        ga.confirm_pending_commit(&a, &out.msg_id).unwrap();
        let meta = InviteMeta::expected(inv.secret().id(), "g", "p");
        let mut gb = b
            .join_from_wrapped_welcome(inv.secret(), &meta, out.welcome.as_ref().unwrap())
            .unwrap();
        let inner = serde_json::to_vec(&serde_json::json!({
            "v": 0,
            "seq": 1,
            "sender": a.instance().identity(),
            "instance_id": a.instance().cert().instance_id_hex(),
            "to": ["*"],
            "hop": 0,
            "origin": "agent",
            "kind": "a2a.message",
            "body": {"text": MESSAGE},
        }))
        .unwrap();
        let ct = ga.seal(&a, &inner).unwrap();
        assert_eq!(gb.open(&b, &ct).unwrap().plaintext, inner);
        gb.group_id().to_vec()
    }

    /// Every byte of every file in `dir` (database, journal, WAL).
    fn dir_bytes(dir: &Path) -> Vec<u8> {
        let mut all = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            all.extend(std::fs::read(entry.unwrap().path()).unwrap());
        }
        all
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The group id as the JSON codec writes it (`1,2,3`, without brackets).
    fn json_id(group_id: &[u8]) -> Vec<u8> {
        let a = serde_json::to_vec(group_id).unwrap();
        a[1..a.len() - 1].to_vec()
    }

    /// Byte patterns that give away the store's content when it's in the clear.
    fn markers(group_id: &[u8]) -> Vec<Vec<u8>> {
        vec![
            b"SQLite format 3".to_vec(),
            b"agentconnect_records".to_vec(),
            b"openmls".to_vec(),
            b"CREATE TABLE".to_vec(),
            MESSAGE.as_bytes().to_vec(),
            DISPLAY_NAME.as_bytes().to_vec(),
            group_id.to_vec(),
            json_id(group_id),
            crate::encoding::hex(group_id).into_bytes(),
            crate::encoding::b64(group_id).into_bytes(),
        ]
    }

    fn db(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("state.db")
    }

    fn unencrypted(dir: &tempfile::TempDir) -> SqliteStore {
        SqliteStore::from_connection(Connection::open(db(dir)).unwrap()).unwrap()
    }

    #[test]
    fn the_database_file_holds_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let k = key("db-key");
        let gid = populate(SqliteStore::open(&db(&dir), &k).unwrap());
        let bytes = dir_bytes(dir.path());
        assert!(bytes.len() > 4096, "the store was written");
        for m in markers(&gid) {
            assert!(!contains(&bytes, &m), "plaintext marker {m:?} on disk");
        }
        // The state is all there under the right key.
        let clock = Arc::new(FakeClock::default());
        let b = client(
            SqliteStore::open(&db(&dir), &k).unwrap(),
            "storage-b",
            &clock,
        );
        assert!(b.load_group(&gid).unwrap().is_some());
    }

    #[test]
    fn the_markers_do_show_up_in_an_unencrypted_file() {
        // Control for the test above: the same scenario on plain SQLite
        // connections leaves the markers on disk.
        let dir = tempfile::tempdir().unwrap();
        let gid = populate(unencrypted(&dir));
        let bytes = dir_bytes(dir.path());
        assert!(contains(&bytes, b"SQLite format 3"));
        assert!(contains(&bytes, b"agentconnect_records"));
        assert!(contains(&bytes, &json_id(&gid)));
    }

    #[test]
    fn a_wrong_key_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        populate(SqliteStore::open(&db(&dir), &key("right")).unwrap());
        assert_eq!(
            SqliteStore::open(&db(&dir), &key("wrong")).err(),
            Some(Error::StorageKey)
        );
        assert_eq!(
            SqliteStore::rekey(&db(&dir), &key("wrong"), &key("new")).err(),
            Some(Error::StorageKey)
        );
        // The failed attempts changed nothing.
        assert!(SqliteStore::open(&db(&dir), &key("right")).is_ok());
    }

    #[test]
    fn a_missing_key_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        populate(SqliteStore::open(&db(&dir), &key("right")).unwrap());
        // A reader that applies no key sees no database.
        let plain = Connection::open(db(&dir)).unwrap();
        let err = plain
            .query_row("SELECT count(*) FROM sqlite_master", (), |r| {
                r.get::<_, i64>(0)
            })
            .unwrap_err();
        assert_eq!(keyed_err(err), Error::StorageKey);
    }

    #[test]
    fn an_unencrypted_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        populate(unencrypted(&dir));
        assert_eq!(
            SqliteStore::open(&db(&dir), &key("any")).err(),
            Some(Error::StorageKey)
        );
    }

    #[test]
    fn rekey_moves_the_store_to_the_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = (key("old"), key("new"));
        let gid = populate(SqliteStore::open(&db(&dir), &old).unwrap());
        SqliteStore::rekey(&db(&dir), &old, &new).unwrap();
        assert_eq!(
            SqliteStore::open(&db(&dir), &old).err(),
            Some(Error::StorageKey)
        );
        let clock = Arc::new(FakeClock::default());
        let b = client(
            SqliteStore::open(&db(&dir), &new).unwrap(),
            "storage-b",
            &clock,
        );
        assert!(b.load_group(&gid).unwrap().is_some());
        drop(b);
        let bytes = dir_bytes(dir.path());
        for m in markers(&gid) {
            assert!(!contains(&bytes, &m), "plaintext marker {m:?} after rekey");
        }
    }

    #[test]
    fn rekey_needs_an_existing_store() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            SqliteStore::rekey(&db(&dir), &key("a"), &key("b")),
            Err(Error::Storage(_))
        ));
    }

    #[test]
    fn other_sqlite_errors_stay_storage_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(db(&dir)).unwrap();
        assert!(matches!(
            SqliteStore::open(&db(&dir), &key("a")),
            Err(Error::Storage(_))
        ));
    }

    /// One test type that stands in for every OpenMLS storage key and entity.
    #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct T(Vec<u8>);

    impl openmls_traits::storage::Key<V> for T {}
    impl openmls_traits::storage::Entity<V> for T {}
    macro_rules! storable {
        ($($t:ident),*) => { $(impl traits::$t<V> for T {})* };
    }
    storable!(
        GroupId,
        SignaturePublicKey,
        HashReference,
        PskId,
        EncryptionKey,
        EpochKey,
        QueuedProposal,
        TreeSync,
        GroupContext,
        InterimTranscriptHash,
        ConfirmationTag,
        SignatureKeyPair,
        PskBundle,
        HpkeKeyPair,
        GroupState,
        GroupEpochSecrets,
        LeafNodeIndex,
        MessageSecrets,
        ResumptionPskStore,
        KeyPackage,
        MlsGroupJoinConfig,
        LeafNode,
        ProposalRef
    );

    #[test]
    fn every_storage_call_reaches_the_shared_connection() {
        // The delegating provider writes through to OpenMLS's own SQLite
        // provider over the one connection: what one writes, the other
        // reads, and a rolled-back transaction undoes it.
        use sealed::Backend as _;
        let store = SqliteStore::open_in_memory().unwrap();
        let s = store.inner();
        let t = T(b"value".to_vec());
        store.begin().unwrap();
        s.write_tree(&t, &t).unwrap();
        store.rollback().unwrap();
        assert_eq!(s.tree::<T, T>(&t).unwrap(), None);
        s.write_tree(&t, &t).unwrap();
        assert_eq!(
            SqliteStorageProvider::<JsonCodec, &Connection>::new(&store.mls.conn)
                .tree::<T, T>(&t)
                .unwrap(),
            Some(t.clone())
        );
        s.write_mls_join_config::<T, T>(&t, &t).unwrap();
        s.append_own_leaf_node::<T, T>(&t, &t).unwrap();
        s.queue_proposal::<T, T, T>(&t, &t, &t).unwrap();
        s.write_tree::<T, T>(&t, &t).unwrap();
        s.write_interim_transcript_hash::<T, T>(&t, &t).unwrap();
        s.write_context::<T, T>(&t, &t).unwrap();
        s.write_confirmation_tag::<T, T>(&t, &t).unwrap();
        s.write_group_state::<T, T>(&t, &t).unwrap();
        s.write_message_secrets::<T, T>(&t, &t).unwrap();
        s.write_resumption_psk_store::<T, T>(&t, &t).unwrap();
        s.write_own_leaf_index::<T, T>(&t, &t).unwrap();
        s.write_group_epoch_secrets::<T, T>(&t, &t).unwrap();
        s.write_signature_key_pair::<T, T>(&t, &t).unwrap();
        s.write_encryption_key_pair::<T, T>(&t, &t).unwrap();
        s.write_encryption_epoch_key_pairs::<T, T, T>(&t, &t, 0, std::slice::from_ref(&t))
            .unwrap();
        s.write_key_package::<T, T>(&t, &t).unwrap();
        s.write_psk::<T, T>(&t, &t).unwrap();
        s.queued_proposal_refs::<T, T>(&t).unwrap();
        s.queued_proposals::<T, T, T>(&t).unwrap();
        assert!(
            s.mls_group_join_config::<T, T>(&t).is_ok(),
            "mls_group_join_config"
        );
        assert!(s.own_leaf_nodes::<T, T>(&t).is_ok(), "own_leaf_nodes");
        assert!(s.tree::<T, T>(&t).is_ok(), "tree");
        assert!(s.group_context::<T, T>(&t).is_ok(), "group_context");
        assert!(
            s.interim_transcript_hash::<T, T>(&t).is_ok(),
            "interim_transcript_hash"
        );
        assert!(s.confirmation_tag::<T, T>(&t).is_ok(), "confirmation_tag");
        assert!(s.group_state::<T, T>(&t).is_ok(), "group_state");
        assert!(s.message_secrets::<T, T>(&t).is_ok(), "message_secrets");
        assert!(
            s.resumption_psk_store::<T, T>(&t).is_ok(),
            "resumption_psk_store"
        );
        assert!(s.own_leaf_index::<T, T>(&t).is_ok(), "own_leaf_index");
        assert!(
            s.group_epoch_secrets::<T, T>(&t).is_ok(),
            "group_epoch_secrets"
        );
        assert!(
            s.signature_key_pair::<T, T>(&t).is_ok(),
            "signature_key_pair"
        );
        assert!(
            s.encryption_key_pair::<T, T>(&t).is_ok(),
            "encryption_key_pair"
        );
        assert!(
            s.encryption_epoch_key_pairs::<T, T, T>(&t, &t, 0).is_ok(),
            "encryption_epoch_key_pairs"
        );
        assert!(s.key_package::<T, T>(&t).is_ok(), "key_package");
        assert!(s.psk::<T, T>(&t).is_ok(), "psk");
        s.remove_proposal::<T, T>(&t, &t).unwrap();
        s.delete_own_leaf_nodes::<T>(&t).unwrap();
        s.delete_group_config::<T>(&t).unwrap();
        s.delete_tree::<T>(&t).unwrap();
        s.delete_confirmation_tag::<T>(&t).unwrap();
        s.delete_group_state::<T>(&t).unwrap();
        s.delete_context::<T>(&t).unwrap();
        s.delete_interim_transcript_hash::<T>(&t).unwrap();
        s.delete_message_secrets::<T>(&t).unwrap();
        s.delete_all_resumption_psk_secrets::<T>(&t).unwrap();
        s.delete_own_leaf_index::<T>(&t).unwrap();
        s.delete_group_epoch_secrets::<T>(&t).unwrap();
        s.clear_proposal_queue::<T, T>(&t).unwrap();
        s.delete_signature_key_pair::<T>(&t).unwrap();
        s.delete_encryption_key_pair::<T>(&t).unwrap();
        s.delete_encryption_epoch_key_pairs::<T, T>(&t, &t, 0)
            .unwrap();
        s.delete_key_package::<T>(&t).unwrap();
        s.delete_psk::<T>(&t).unwrap();
        assert_eq!(s.tree::<T, T>(&t).unwrap(), None);
    }

    #[test]
    fn db_keys_are_32_bytes_and_never_printed() {
        let k = key("k");
        assert_eq!(
            DbKey::from_bytes(k.as_bytes()).unwrap().as_bytes(),
            k.as_bytes()
        );
        assert_eq!(
            DbKey::from_bytes(&k.as_bytes()[..31]).err(),
            Some(Error::Malformed("database key (must be 32 bytes)"))
        );
        assert!(DbKey::from_bytes(&[0u8; 33]).is_err());
        assert_eq!(format!("{k:?}"), "DbKey(..)");
        let sql = k.pragma("key");
        assert!(sql.starts_with("PRAGMA key = \"x'"));
        assert_eq!(sql.len(), "PRAGMA key = \"x''\";".len() + 64);
        assert!(sql.contains(&format!("{:02X}", k.as_bytes()[0])));
        assert_ne!(key("k2").as_bytes(), k.as_bytes());
    }

    fn rows(store: &SqliteStore, table: &str) -> i64 {
        store
            .conn()
            .query_row(&format!("SELECT count(*) FROM {table}"), (), |r| r.get(0))
            .unwrap()
    }

    /// Every table OpenMLS keeps state in.
    const MLS_TABLES: [&str; 8] = [
        "openmls_encryption_keys",
        "openmls_epoch_keys_pairs",
        "openmls_group_data",
        "openmls_key_packages",
        "openmls_own_leaf_nodes",
        "openmls_proposals",
        "openmls_psks",
        "openmls_signature_keys",
    ];

    #[test]
    fn old_keys_and_a_left_groups_secrets_leave_the_store() {
        // Forward secrecy through OpenMLS on the SQLite store: the used
        // KeyPackage, each previous epoch's keys, an update's fresh leaf key
        // and, once the group is deleted, all of its state are gone.
        use crate::group::Event;
        let clock = Arc::new(FakeClock::default());
        let a = client(MemoryStore::new(), "fs-a", &clock);
        let b = client(SqliteStore::open_in_memory().unwrap(), "fs-b", &clock);
        let bs = b.store_for_testing();
        let mut ga = a.create_group("g", "p").unwrap();
        let inv = Invite::create(a.rng(), a.clock(), "r.example", Duration::from_secs(60)).unwrap();
        let req = b.create_join_request(inv.secret(), "b").unwrap();
        assert_eq!(rows(bs, "openmls_key_packages"), 1);
        let v = a.verify_join_request(&req, &inv).unwrap();
        let out = ga.add_member(&a, &v, &inv, true).unwrap();
        ga.confirm_pending_commit(&a, &out.msg_id).unwrap();
        let meta = InviteMeta::expected(inv.secret().id(), "g", "p");
        let mut gb = b
            .join_from_wrapped_welcome(inv.secret(), &meta, out.welcome.as_ref().unwrap())
            .unwrap();
        assert_eq!(rows(bs, "openmls_key_packages"), 0, "the used KeyPackage");
        assert_eq!(rows(bs, "openmls_epoch_keys_pairs"), 1);

        // A's updates move the epoch: B keeps only the current epoch's keys.
        for _ in 0..3 {
            let up = ga.update(&a).unwrap();
            ga.confirm_pending_commit(&a, &up.msg_id).unwrap();
            assert!(matches!(
                gb.process(&b, &up.commit).unwrap(),
                Event::Commit(_)
            ));
            assert_eq!(gb.epoch(), ga.epoch());
            assert_eq!(
                rows(bs, "openmls_epoch_keys_pairs"),
                1,
                "epoch {}",
                gb.epoch()
            );
        }

        // B's own update: afterwards only the new epoch's keys are stored.
        let up = gb.update(&b).unwrap();
        gb.confirm_pending_commit(&b, &up.msg_id).unwrap();
        assert_eq!(
            rows(bs, "openmls_encryption_keys"),
            0,
            "the update's leaf key"
        );
        assert_eq!(rows(bs, "openmls_epoch_keys_pairs"), 1);
        assert!(matches!(
            ga.process(&a, &up.commit).unwrap(),
            Event::Commit(_)
        ));

        // A stored proposal doesn't outlive its epoch: a commit that doesn't
        // carry it drops it.
        gb.propose_leave(&b).unwrap();
        assert!(rows(bs, "openmls_proposals") > 0);
        let up = ga.update(&a).unwrap();
        ga.confirm_pending_commit(&a, &up.msg_id).unwrap();
        assert!(matches!(
            gb.process(&b, &up.commit).unwrap(),
            Event::Commit(_)
        ));
        assert_eq!(rows(bs, "openmls_proposals"), 0);

        // B leaves; once removed it deletes the group, and every row of it
        // goes, the leave proposal B still holds included.
        let leave = gb.propose_leave(&b).unwrap();
        assert!(matches!(
            ga.process(&a, &leave).unwrap(),
            Event::LeaveProposed(_)
        ));
        let rm = ga.commit_pending_proposals(&a).unwrap();
        ga.confirm_pending_commit(&a, &rm.msg_id).unwrap();
        assert!(matches!(
            gb.process(&b, &rm.commit).unwrap(),
            Event::Removed(_)
        ));
        assert!(rows(bs, "openmls_group_data") > 0);
        let gid = gb.group_id().to_vec();
        gb.delete(&b).unwrap();
        for table in MLS_TABLES {
            assert_eq!(rows(bs, table), 0, "{table} after the group is deleted");
        }
        assert!(b.load_group(&gid).unwrap().is_none());
    }

    // SR-61: deleting a group deletes all of its key material.

    /// How a group ends for B before B deletes it.
    #[derive(Clone, Copy, Debug)]
    enum End {
        /// Still a member, as when it's the sole member or the last one.
        Active,
        /// Its leave is pending, as when nobody committed it in time.
        LeavePending,
        /// Another member removed it.
        RemovedByOther,
        /// It proposed a leave and another member committed it.
        LeaveCommitted,
    }

    /// B joins A's group `name` through an invite.
    fn join<S: Store, T: Store>(
        a: &Client<S>,
        ga: &mut crate::group::Group,
        b: &Client<T>,
        name: &str,
    ) -> crate::group::Group {
        let inv = Invite::create(a.rng(), a.clock(), "r.example", Duration::from_secs(60)).unwrap();
        let req = b.create_join_request(inv.secret(), "b").unwrap();
        let v = a.verify_join_request(&req, &inv).unwrap();
        let out = ga.add_member(a, &v, &inv, true).unwrap();
        ga.confirm_pending_commit(a, &out.msg_id).unwrap();
        let meta = InviteMeta::expected(inv.secret().id(), name, "p");
        b.join_from_wrapped_welcome(inv.secret(), &meta, out.welcome.as_ref().unwrap())
            .unwrap()
    }

    /// A commits an update and B processes it.
    fn epoch_moves<S: Store, T: Store>(
        a: &Client<S>,
        ga: &mut crate::group::Group,
        b: &Client<T>,
        gb: &mut crate::group::Group,
    ) {
        let up = ga.update(a).unwrap();
        ga.confirm_pending_commit(a, &up.msg_id).unwrap();
        assert!(matches!(
            gb.process(b, &up.commit).unwrap(),
            crate::group::Event::Commit(_)
        ));
    }

    /// B joins a group of A's, the epoch moves and the group ends for
    /// B as `end` says. Returns B's group.
    fn ended<S: Store, T: Store>(a: &Client<S>, b: &Client<T>, end: End) -> crate::group::Group {
        use crate::group::Event;
        let mut ga = a.create_group("g", "p").unwrap();
        let mut gb = join(a, &mut ga, b, "g");
        epoch_moves(a, &mut ga, b, &mut gb);
        let rm = match end {
            End::Active => return gb,
            End::LeavePending => {
                gb.propose_leave(b).unwrap();
                return gb;
            }
            End::RemovedByOther => ga.remove(a, b.instance().identity()).unwrap(),
            End::LeaveCommitted => {
                let leave = gb.propose_leave(b).unwrap();
                assert!(matches!(
                    ga.process(a, &leave).unwrap(),
                    Event::LeaveProposed(_)
                ));
                ga.commit_pending_proposals(a).unwrap()
            }
        };
        ga.confirm_pending_commit(a, &rm.msg_id).unwrap();
        assert!(matches!(
            gb.process(b, &rm.commit).unwrap(),
            Event::Removed(_)
        ));
        gb
    }

    /// Byte strings that give a group id away: raw, as OpenMLS keys it
    /// (JSON) and as the JSON numbers inside any serialised value.
    fn id_forms(group_id: &[u8]) -> Vec<Vec<u8>> {
        vec![
            group_id.to_vec(),
            mls_group_key(group_id).unwrap(),
            json_id(group_id),
        ]
    }

    /// Every `table.column` of the SQLite store with a value that contains
    /// the group id in one of its forms.
    fn sqlite_references(store: &SqliteStore, group_id: &[u8]) -> Vec<String> {
        let conn = store.conn();
        let columns: Vec<(String, String)> = conn
            .prepare(
                "SELECT m.name, c.name FROM sqlite_master m, pragma_table_info(m.name) c \
                 WHERE m.type = 'table'",
            )
            .unwrap()
            .query_map((), |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(columns.len() > 20, "the schema is there");
        let mut found = Vec::new();
        for (table, column) in columns {
            for form in id_forms(group_id) {
                let n: i64 = conn
                    .query_row(
                        &format!(
                            "SELECT count(*) FROM \"{table}\" \
                             WHERE instr(CAST(\"{column}\" AS BLOB), ?1) > 0"
                        ),
                        (&form,),
                        |r| r.get(0),
                    )
                    .unwrap();
                if n > 0 {
                    found.push(format!("{table}.{column}"));
                }
            }
        }
        found
    }

    /// Every memory store entry whose key or value contains the group id in
    /// one of its forms.
    fn memory_references(store: &MemoryStore, group_id: &[u8]) -> usize {
        let forms = id_forms(group_id);
        let has = |bytes: &[u8]| forms.iter().any(|f| contains(bytes, f));
        let mls = store.mls.values.read().unwrap();
        let records = store.records.lock().unwrap();
        mls.iter()
            .chain(records.iter())
            .filter(|(k, v)| has(k) || has(v))
            .count()
            + store
                .journal
                .lock()
                .unwrap()
                .values()
                .filter(|r| r.group_id == group_id)
                .count()
    }

    #[test]
    fn a_removed_member_keeps_no_key_pairs_of_the_group() {
        // The SR-61 reproduction: OpenMLS's delete left the key pairs of the
        // epoch before the removal.
        let clock = Arc::new(FakeClock::default());
        let a = client(MemoryStore::new(), "sr61-a", &clock);
        let b = client(SqliteStore::open_in_memory().unwrap(), "sr61-b", &clock);
        let gb = ended(&a, &b, End::RemovedByOther);
        assert_eq!(rows(b.store_for_testing(), "openmls_epoch_keys_pairs"), 1);
        gb.delete(&b).unwrap();
        assert_eq!(rows(b.store_for_testing(), "openmls_epoch_keys_pairs"), 0);
    }

    /// Deletes B's group after `end` on SQLite: no row of any table
    /// references the group, and OpenMLS's tables are empty.
    fn deleted_on_sqlite(end: End) {
        let clock = Arc::new(FakeClock::default());
        let a = client(MemoryStore::new(), &format!("ref-a-{end:?}"), &clock);
        let b = client(
            SqliteStore::open_in_memory().unwrap(),
            &format!("ref-b-{end:?}"),
            &clock,
        );
        let gb = ended(&a, &b, end);
        let gid = gb.group_id().to_vec();
        assert_ne!(
            sqlite_references(b.store_for_testing(), &gid),
            Vec::<String>::new()
        );
        gb.delete(&b).unwrap();
        assert_eq!(
            sqlite_references(b.store_for_testing(), &gid),
            Vec::<String>::new()
        );
        for table in MLS_TABLES {
            assert_eq!(rows(b.store_for_testing(), table), 0, "{table}");
        }
        assert!(b.load_group(&gid).unwrap().is_none());
    }

    /// The same on the memory store: no entry references the group.
    fn deleted_in_memory(end: End) {
        let clock = Arc::new(FakeClock::default());
        let a = client(MemoryStore::new(), &format!("mref-a-{end:?}"), &clock);
        let b = client(MemoryStore::new(), &format!("mref-b-{end:?}"), &clock);
        let gb = ended(&a, &b, end);
        let gid = gb.group_id().to_vec();
        assert!(memory_references(b.store_for_testing(), &gid) > 0);
        gb.delete(&b).unwrap();
        assert_eq!(memory_references(b.store_for_testing(), &gid), 0);
    }

    #[test]
    fn deleting_an_active_group_leaves_no_row_that_references_it() {
        deleted_on_sqlite(End::Active);
        deleted_in_memory(End::Active);
    }

    #[test]
    fn deleting_a_group_with_a_pending_leave_leaves_no_row_that_references_it() {
        deleted_on_sqlite(End::LeavePending);
        deleted_in_memory(End::LeavePending);
    }

    #[test]
    fn deleting_a_group_one_was_removed_from_leaves_no_row_that_references_it() {
        deleted_on_sqlite(End::RemovedByOther);
        deleted_in_memory(End::RemovedByOther);
    }

    #[test]
    fn deleting_a_group_one_left_leaves_no_row_that_references_it() {
        deleted_on_sqlite(End::LeaveCommitted);
        deleted_in_memory(End::LeaveCommitted);
    }

    #[test]
    fn opening_a_store_sweeps_key_pairs_an_old_delete_left() {
        // A store written before the SR-61 fix: a removed member deleted the
        // group the old way. Opening it deletes the orphaned key pairs and
        // nothing of a group that is still there.
        let dir = tempfile::tempdir().unwrap();
        let k = key("sweep");
        let clock = Arc::new(FakeClock::default());
        let a = client(MemoryStore::new(), "sweep-a", &clock);
        let b = client(SqliteStore::open(&db(&dir), &k).unwrap(), "sweep-b", &clock);
        let mut live_a = a.create_group("live", "p").unwrap();
        let live_b = join(&a, &mut live_a, &b, "live");
        let live_id = live_b.group_id().to_vec();
        let gone = ended(&a, &b, End::RemovedByOther);
        let gone_id = gone.group_id().to_vec();
        gone.delete_before_sr61_for_testing(&b).unwrap();
        assert_eq!(rows(b.store_for_testing(), "openmls_epoch_keys_pairs"), 2);
        assert_ne!(
            sqlite_references(b.store_for_testing(), &gone_id),
            Vec::<String>::new()
        );
        drop((b, live_b));

        let b = client(SqliteStore::open(&db(&dir), &k).unwrap(), "sweep-b", &clock);
        assert_eq!(rows(b.store_for_testing(), "openmls_epoch_keys_pairs"), 1);
        assert_eq!(
            sqlite_references(b.store_for_testing(), &gone_id),
            Vec::<String>::new()
        );
        // The live group's keys are intact: B processes a commit whose path
        // is encrypted to them.
        let mut live_b = b.load_group(&live_id).unwrap().unwrap();
        epoch_moves(&a, &mut live_a, &b, &mut live_b);
        assert_eq!(live_b.epoch(), live_a.epoch());
    }
}
