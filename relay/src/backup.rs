//! `agentconnect-relay backup <path>`: an online copy of the relay's
//! database (`AC_RELAY_DB`) while it runs, through the relay's own SQLite
//! library and user. The image has no `sqlite3`, and a host `sqlite3` run
//! as root can leave `-wal` and `-shm` files the relay's user can't open.
//!
//! The copy is `VACUUM INTO` on a read-only connection: a consistent
//! snapshot of the last committed state, without the pages deletes freed,
//! and nothing in the live database changes. SQLite opens its output by
//! name and follows a symlink there, so the copy is written inside a fresh
//! 0700 directory next to `path` (nobody else can put anything in it),
//! then hard-linked to `path`, which fails if anything (a file, a symlink)
//! is there already, and the directory is removed. The copy is 0600.

use std::fs::{DirBuilder, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
/// exists or its directory can't be written, or SQLite can't make the copy.
/// Nothing is left behind on failure.
pub async fn backup(db: &str, target: &Path) -> Result<u64, String> {
    let source = database_path(db)
        .ok_or_else(|| "the database is in memory: there is nothing to back up".to_owned())?;
    if !source.is_file() {
        return Err(format!("no database at {}", source.display()));
    }
    if target.symlink_metadata().is_ok() {
        return Err(exists(target));
    }
    let private = private_dir(target)?;
    let copied = copy_and_place(&source, &private, target).await;
    let _ = std::fs::remove_dir_all(&private);
    copied
}

async fn copy_and_place(source: &Path, private: &Path, target: &Path) -> Result<u64, String> {
    let copy = private.join("backup.db");
    let mut create = OpenOptions::new();
    create.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut create, 0o600);
    create
        .open(&copy)
        .map_err(|e| format!("cannot create {}: {e}", copy.display()))?;
    let copy_text = copy
        .to_str()
        .ok_or_else(|| "the backup path must be valid UTF-8".to_owned())?;
    vacuum_into(source, copy_text).await?;
    place(&copy, target)?;
    std::fs::metadata(target)
        .map(|m| m.len())
        .map_err(|e| format!("cannot read {}: {e}", target.display()))
}

/// A new 0700 directory next to `target`, on the same file system.
fn private_dir(target: &Path) -> Result<PathBuf, String> {
    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut last = None;
    for attempt in 0..8u32 {
        let dir = parent.join(format!(
            ".agentconnect-backup-{}-{stamp}-{attempt}",
            std::process::id()
        ));
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(format!("cannot write in {}: {e}", parent.display())),
        }
    }
    Err(format!(
        "cannot make a private directory in {}: {}",
        parent.display(),
        last.map_or_else(String::new, |e| e.to_string())
    ))
}

/// Put `copy` at `target` without replacing anything there: a hard link
/// fails if `target` exists in any form, a symlink included.
pub(crate) fn place(copy: &Path, target: &Path) -> Result<(), String> {
    std::fs::hard_link(copy, target).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            exists(target)
        } else {
            format!("cannot create {}: {e}", target.display())
        }
    })
}

fn exists(target: &Path) -> String {
    format!("{} exists; back up to a new path", target.display())
}

async fn vacuum_into(source: &Path, copy: &str) -> Result<(), String> {
    let mut conn = SqliteConnectOptions::new()
        .filename(source)
        .read_only(true)
        .create_if_missing(false)
        .busy_timeout(BUSY_TIMEOUT)
        .connect()
        .await
        .map_err(|e| format!("cannot open {}: {e}", source.display()))?;
    let done = sqlx::query("VACUUM INTO ?")
        .bind(copy)
        .execute(&mut conn)
        .await
        .map(|_| ())
        .map_err(|e| format!("the copy failed: {e}"));
    let _ = conn.close().await;
    done
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placing_never_replaces_or_follows_what_is_at_the_target() {
        // The swap the private directory guards against, at the last step:
        // a symlink to a victim appears at the target. The link is refused
        // and the victim is untouched.
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("copy.db");
        std::fs::write(&copy, b"backup").unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let target = dir.path().join("backup.db");
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        assert!(place(&copy, &target).unwrap_err().contains("exists"));
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        std::fs::remove_file(&target).unwrap();
        place(&copy, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"backup");
    }
}
