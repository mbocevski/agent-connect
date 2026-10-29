//! `agentconnect-relay backup <path>`: an online copy of the relay's
//! database (`AC_RELAY_DB`) while it runs, through the relay's own SQLite
//! library and user. The image has no `sqlite3`, and a host `sqlite3` run
//! as root can leave `-wal` and `-shm` files the relay's user can't open.
//!
//! The copy is `VACUUM INTO` on a read-only connection: a consistent
//! snapshot of the last committed state, without the pages deletes freed,
//! and nothing in the live database changes. The target is created first,
//! empty and 0600, so the copy is never readable by others and an existing
//! file is never replaced.

use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions as _, Connection as _};

use crate::restart::database_path;

/// How long the copy waits for a write the relay holds.
const BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// Copy the database `db` names (a path or a `sqlite:` URL) to `target`,
/// a new file. Returns the size of the copy in bytes.
///
/// # Errors
///
/// A one-line reason: the database is in memory or missing, `target`
/// exists or can't be created, or SQLite can't make the copy (a failed
/// copy's empty target is removed).
pub async fn backup(db: &str, target: &Path) -> Result<u64, String> {
    let source = database_path(db)
        .ok_or_else(|| "the database is in memory: there is nothing to back up".to_owned())?;
    if !source.is_file() {
        return Err(format!("no database at {}", source.display()));
    }
    let target_text = target
        .to_str()
        .ok_or_else(|| "the backup path must be valid UTF-8".to_owned())?;
    let mut create = OpenOptions::new();
    create.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut create, 0o600);
    create.open(target).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{} exists; back up to a new path", target.display())
        } else {
            format!("cannot create {}: {e}", target.display())
        }
    })?;
    let copied = copy(&source, target_text).await;
    if copied.is_err() {
        let _ = std::fs::remove_file(target);
    }
    copied?;
    std::fs::metadata(target)
        .map(|m| m.len())
        .map_err(|e| format!("cannot read {}: {e}", target.display()))
}

async fn copy(source: &Path, target: &str) -> Result<(), String> {
    let mut conn = SqliteConnectOptions::new()
        .filename(source)
        .read_only(true)
        .create_if_missing(false)
        .busy_timeout(BUSY_TIMEOUT)
        .connect()
        .await
        .map_err(|e| format!("cannot open {}: {e}", source.display()))?;
    let done = sqlx::query("VACUUM INTO ?")
        .bind(target)
        .execute(&mut conn)
        .await
        .map(|_| ())
        .map_err(|e| format!("the copy failed: {e}"));
    let _ = conn.close().await;
    done
}
