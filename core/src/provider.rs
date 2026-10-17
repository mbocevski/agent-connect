//! Storage backends and the OpenMLS provider that combines them with
//! libcrux crypto and our [`Rng`].
//!
//! # Encryption at rest
//!
//! The stores hold MLS group secrets and HPKE private keys **in the clear**.
//! Protecting them at rest is the daemon's job: open [`SqliteStore`] on an
//! encrypted volume, or wrap it with a key from the OS keyring once a
//! SQLCipher-capable build is adopted. This module is the seam for that: a
//! new backend only needs to implement OpenMLS's storage trait and the
//! (sealed) [`Store`] trait.
//!
//! Besides the OpenMLS state, a store keeps a few records of `core`'s own
//! (pending-commit confirmation data, consumed KeyPackage refs, the previous
//! epoch's members) in a small key-value table.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use openmls_libcrux_crypto::CryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;

use crate::error::{Error, Result, storage};
use crate::rng::Rng;

pub(crate) mod sealed {
    /// The OpenMLS storage behind a [`super::Store`], plus `core`'s own
    /// key-value records.
    pub trait Backend {
        /// The OpenMLS storage provider.
        type Inner: openmls::storage::StorageProvider;
        /// Borrows it.
        fn inner(&self) -> &Self::Inner;
        /// Reads one of `core`'s records.
        fn get_record(&self, key: &[u8]) -> crate::Result<Option<Vec<u8>>>;
        /// Writes (`Some`) or deletes (`None`) one of `core`'s records.
        fn put_record(&self, key: &[u8], value: Option<&[u8]>) -> crate::Result<()>;
    }
}

/// A storage backend for MLS state. Implemented by [`MemoryStore`] (tests)
/// and [`SqliteStore`] (daemons).
pub trait Store: sealed::Backend + Send {}

/// In-memory storage, for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    mls: MemoryStorage,
    records: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl sealed::Backend for MemoryStore {
    type Inner = MemoryStorage;
    fn inner(&self) -> &MemoryStorage {
        &self.mls
    }

    fn get_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let records = self
            .records
            .lock()
            .map_err(|_| Error::Storage("record lock poisoned".into()))?;
        Ok(records.get(key).cloned())
    }

    fn put_record(&self, key: &[u8], value: Option<&[u8]>) -> Result<()> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| Error::Storage("record lock poisoned".into()))?;
        match value {
            Some(v) => records.insert(key.to_vec(), v.to_vec()),
            None => records.remove(key),
        };
        Ok(())
    }
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

/// SQLite storage (OpenMLS's schema, run through its migrations).
///
/// OpenMLS's provider owns its connection, so `core`'s records go through a
/// second connection to the same database file (table `agentconnect_records`).
pub struct SqliteStore {
    mls: SqliteStorageProvider<JsonCodec, Connection>,
    records: Connection,
}

const RECORDS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS agentconnect_records \
     (key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";

impl SqliteStore {
    /// Opens or creates the database at `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] on any SQLite or migration error.
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_connections(
            Connection::open(path).map_err(storage)?,
            Connection::open(path).map_err(storage)?,
        )
    }

    /// A private in-memory SQLite database.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] on any SQLite or migration error.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connections(
            Connection::open_in_memory().map_err(storage)?,
            Connection::open_in_memory().map_err(storage)?,
        )
    }

    fn from_connections(mls: Connection, records: Connection) -> Result<Self> {
        let mut provider = SqliteStorageProvider::new(mls);
        provider.run_migrations().map_err(storage)?;
        records.execute(RECORDS_SCHEMA, ()).map_err(storage)?;
        Ok(Self {
            mls: provider,
            records,
        })
    }
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SqliteStore")
    }
}

impl sealed::Backend for SqliteStore {
    type Inner = SqliteStorageProvider<JsonCodec, Connection>;
    fn inner(&self) -> &Self::Inner {
        &self.mls
    }

    fn get_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .records
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
            Some(v) => self.records.execute(
                "INSERT INTO agentconnect_records (key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, v),
            ),
            None => self
                .records
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
