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
//! epoch's members) in a small key-value table.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Mutex;

use hkdf::Hkdf;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::{ErrorCode, OpenFlags};
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

/// Encrypted SQLite storage: a SQLCipher database with OpenMLS's schema, run
/// through its migrations.
///
/// OpenMLS's provider owns its connection, so `core`'s records go through a
/// second connection to the same database file (table `agentconnect_records`).
/// Both connections are keyed before any other statement runs.
pub struct SqliteStore {
    mls: SqliteStorageProvider<JsonCodec, Connection>,
    records: Connection,
}

const RECORDS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS agentconnect_records \
     (key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";

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
        let flags = OpenFlags::default();
        Self::from_connections(open_keyed(path, key, flags)?, open_keyed(path, key, flags)?)
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
        let open = || Connection::open(db(dir)).unwrap();
        SqliteStore::from_connections(open(), open()).unwrap()
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
}
