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

use std::path::Path;

use openmls_libcrux_crypto::CryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;

use crate::error::{Error, Result, storage};
use crate::rng::Rng;

pub(crate) mod sealed {
    /// The OpenMLS storage behind a [`super::Store`].
    pub trait Backend {
        /// The OpenMLS storage provider.
        type Inner: openmls::storage::StorageProvider;
        /// Borrows it.
        fn inner(&self) -> &Self::Inner;
    }
}

/// A storage backend for MLS state. Implemented by [`MemoryStore`] (tests)
/// and [`SqliteStore`] (daemons).
pub trait Store: sealed::Backend + Send {}

/// In-memory storage, for tests.
#[derive(Debug, Default)]
pub struct MemoryStore(MemoryStorage);

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
        &self.0
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
pub struct SqliteStore(SqliteStorageProvider<JsonCodec, Connection>);

impl SqliteStore {
    /// Opens or creates the database at `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] on any SQLite or migration error.
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_connection(Connection::open(path).map_err(storage)?)
    }

    /// A private in-memory SQLite database.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] on any SQLite or migration error.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory().map_err(storage)?)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        let mut provider = SqliteStorageProvider::new(connection);
        provider.run_migrations().map_err(storage)?;
        Ok(Self(provider))
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
        &self.0
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
