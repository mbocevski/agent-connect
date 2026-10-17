//! An encrypted SQL database for a daemon's own records (ADR-003).
//!
//! The daemon keeps groups, members, Agent Cards, join requests, events and
//! its durable inbox and outbox (which hold message plaintext while a
//! message is in flight) in a SQLite schema of its own. [`EncryptedDb`] is
//! that database: a SQLCipher file keyed exactly like [`SqliteStore`]
//! (ADR-002), so every page, the journal and the WAL are encrypted and
//! authenticated and there is no unencrypted on-disk mode.
//!
//! Its key is derived from the store's [`DbKey`] with
//! [`DbKey::derive`] under [`DAEMON_DB_INFO`], so the daemon keeps one key in
//! its keystore and no two files share a key.
//!
//! [`SqliteStore`]: crate::SqliteStore

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, params_from_iter};

use crate::error::{Error, Result, storage};
use crate::provider::{DbKey, open_keyed};

/// HKDF `info` for the daemon database key, derived from the MLS store's
/// [`DbKey`].
pub const DAEMON_DB_INFO: &[u8] = b"agentconnect/v0/daemon-db-key";

/// A SQL value: `NULL`, a 64-bit integer, a float, UTF-8 text or a blob.
pub type SqlValue = Value;

/// The result of [`EncryptedDb::execute`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Executed {
    /// Rows changed by the statement (SQLite `changes()`).
    pub changes: u64,
    /// The rowid of the last successful `INSERT` on this connection.
    pub last_insert_rowid: i64,
}

/// A SQLCipher database with a schema chosen by the caller.
///
/// One connection behind a mutex, so it can be shared across threads.
/// `PRAGMA secure_delete` is on, so deleted rows are overwritten in the
/// (encrypted) file rather than left in free pages.
pub struct EncryptedDb {
    conn: Mutex<Option<Connection>>,
}

impl std::fmt::Debug for EncryptedDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptedDb")
    }
}

impl EncryptedDb {
    /// Opens or creates the encrypted database at `path` under `key`.
    ///
    /// # Errors
    ///
    /// - [`Error::StorageKey`] if `key` doesn't decrypt the file (a wrong
    ///   key, or a file that isn't an encrypted database, such as a
    ///   cleartext SQLite file).
    /// - [`Error::Storage`] on any other SQLite error.
    pub fn open(path: &Path, key: &DbKey) -> Result<Self> {
        let conn = open_keyed(path, key, OpenFlags::default())?;
        conn.execute_batch("PRAGMA secure_delete = ON;")
            .map_err(storage)?;
        Ok(Self {
            conn: Mutex::new(Some(conn)),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Option<Connection>>> {
        self.conn
            .lock()
            .map_err(|_| Error::Storage("database lock poisoned".into()))
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let guard = self.lock()?;
        let conn = guard
            .as_ref()
            .ok_or_else(|| Error::Storage("database is closed".into()))?;
        f(conn)
    }

    /// Runs one statement and returns every row it produces (none for most
    /// writes). `params` bind to `?` placeholders in order.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] on a SQL error, or if the database is closed.
    pub fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>> {
        self.with(|conn| {
            let mut stmt = conn.prepare_cached(sql).map_err(storage)?;
            let width = stmt.column_count();
            let mut rows = stmt.query(params_from_iter(params)).map_err(storage)?;
            let mut out = Vec::new();
            while let Some(row) = rows.next().map_err(storage)? {
                let mut values = Vec::with_capacity(width);
                for i in 0..width {
                    values.push(row.get::<_, Value>(i).map_err(storage)?);
                }
                out.push(values);
            }
            Ok(out)
        })
    }

    /// Runs one statement for its effect.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] on a SQL error, or if the database is closed.
    pub fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<Executed> {
        self.with(|conn| {
            let mut stmt = conn.prepare_cached(sql).map_err(storage)?;
            let mut rows = stmt.query(params_from_iter(params)).map_err(storage)?;
            while rows.next().map_err(storage)?.is_some() {}
            drop(rows);
            Ok(Executed {
                changes: conn.changes(),
                last_insert_rowid: conn.last_insert_rowid(),
            })
        })
    }

    /// Runs several `;`-separated statements without parameters (schema
    /// setup, pragmas).
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] on a SQL error, or if the database is closed.
    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        self.with(|conn| conn.execute_batch(sql).map_err(storage))
    }

    /// Closes the connection. Later calls fail with [`Error::Storage`].
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] if SQLite can't close the connection cleanly.
    pub fn close(&self) -> Result<()> {
        let conn = self.lock()?.take();
        match conn {
            Some(c) => c.close().map_err(|(_, e)| storage(e)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::rng::Rng;

    const MARKER: &str = "PLAINTEXT-MARKER-daemon-record";

    fn key(label: &str) -> DbKey {
        DbKey::generate(&Rng::for_test(label)).unwrap()
    }

    fn path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("daemon.db")
    }

    fn dir_bytes(dir: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            out.extend(std::fs::read(entry.unwrap().path()).unwrap());
        }
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn fill(db: &EncryptedDb) {
        db.execute_batch(
            "PRAGMA journal_mode = WAL; CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT, raw BLOB)",
        )
        .unwrap();
        for _ in 0..50 {
            db.execute(
                "INSERT INTO t (body, raw) VALUES (?, ?)",
                &[
                    Value::Text(MARKER.into()),
                    Value::Blob(MARKER.as_bytes().to_vec()),
                ],
            )
            .unwrap();
        }
    }

    #[test]
    fn rows_round_trip_with_every_value_type() {
        let dir = tempfile::tempdir().unwrap();
        let db = EncryptedDb::open(&path(&dir), &key("k")).unwrap();
        db.execute_batch("CREATE TABLE v (a, b, c, d, e)").unwrap();
        let row = vec![
            Value::Null,
            Value::Integer(-7),
            Value::Real(1.5),
            Value::Text("t".into()),
            Value::Blob(vec![1, 2]),
        ];
        let done = db
            .execute("INSERT INTO v VALUES (?, ?, ?, ?, ?)", &row)
            .unwrap();
        assert_eq!(
            done,
            Executed {
                changes: 1,
                last_insert_rowid: 1
            }
        );
        assert_eq!(db.query("SELECT * FROM v", &[]).unwrap(), vec![row]);
        assert_eq!(
            db.execute("UPDATE v SET a = 1", &[]).unwrap().changes,
            1,
            "changes are counted"
        );
        // A statement that returns rows can still be executed for effect.
        assert!(db.execute("PRAGMA journal_mode", &[]).is_ok());
        assert_eq!(format!("{db:?}"), "EncryptedDb");
    }

    #[test]
    fn the_file_holds_no_plaintext_and_reopens_under_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let k = key("daemon");
        let db = EncryptedDb::open(&path(&dir), &k).unwrap();
        fill(&db);
        let bytes = dir_bytes(dir.path());
        assert!(bytes.len() > 4096, "the database was written");
        assert!(!contains(&bytes, MARKER.as_bytes()));
        assert!(!contains(&bytes, b"CREATE TABLE"));
        db.close().unwrap();
        assert!(db.close().is_ok(), "closing twice is harmless");
        assert!(matches!(db.query("SELECT 1", &[]), Err(Error::Storage(_))));
        let again = EncryptedDb::open(&path(&dir), &k).unwrap();
        let n = again.query("SELECT count(*) FROM t", &[]).unwrap();
        assert_eq!(n, vec![vec![Value::Integer(50)]]);
    }

    #[test]
    fn the_markers_do_show_up_in_a_cleartext_file() {
        // The control for the test above: the same rows written by plain
        // SQLite (no key) are visible on disk.
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(path(&dir)).unwrap();
        let db = EncryptedDb {
            conn: Mutex::new(Some(conn)),
        };
        fill(&db);
        db.close().unwrap();
        assert!(contains(&dir_bytes(dir.path()), MARKER.as_bytes()));
        // And such a file is refused under a key.
        assert_eq!(
            EncryptedDb::open(&path(&dir), &key("k")).err(),
            Some(Error::StorageKey)
        );
    }

    #[test]
    fn a_wrong_key_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        fill(&EncryptedDb::open(&path(&dir), &key("right")).unwrap());
        assert_eq!(
            EncryptedDb::open(&path(&dir), &key("wrong")).err(),
            Some(Error::StorageKey)
        );
    }

    #[test]
    fn sql_errors_are_storage_errors() {
        let dir = tempfile::tempdir().unwrap();
        let db = EncryptedDb::open(&path(&dir), &key("k")).unwrap();
        for result in [
            db.execute("NOT SQL", &[]).map(drop),
            db.query("SELECT * FROM missing", &[]).map(drop),
            db.execute_batch("ALSO NOT SQL"),
        ] {
            assert!(matches!(result, Err(Error::Storage(_))));
        }
    }

    #[test]
    fn derived_keys_are_distinct_per_label_and_stable() {
        let k = key("root");
        let a = k.derive(DAEMON_DB_INFO);
        assert_eq!(a.as_bytes(), k.derive(DAEMON_DB_INFO).as_bytes());
        assert_ne!(a.as_bytes(), k.as_bytes());
        assert_ne!(a.as_bytes(), k.derive(b"agentconnect/v0/other").as_bytes());
        assert_ne!(
            a.as_bytes(),
            key("other-root").derive(DAEMON_DB_INFO).as_bytes()
        );
        // The derived key doesn't open a file keyed by the root key.
        let dir = tempfile::tempdir().unwrap();
        fill(&EncryptedDb::open(&path(&dir), &k).unwrap());
        assert_eq!(
            EncryptedDb::open(&path(&dir), &a).err(),
            Some(Error::StorageKey)
        );
    }
}
