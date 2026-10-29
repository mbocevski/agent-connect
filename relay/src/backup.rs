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
use std::path::{Component, Path, PathBuf};
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
    let target = absolute(target)?;
    let parent = target
        .parent()
        .ok_or_else(|| "the backup path needs a file name".to_owned())?
        .to_path_buf();
    let chain = secure_chain(&parent)?;
    let parent_id = dir_id(&chain[chain.len() - 1].1);
    let private = private_dir(&parent)?;
    let copy = private.join("backup.db");
    let mut create = OpenOptions::new();
    create.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut create, 0o600);
    let file = match create.open(&copy) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_dir(&private);
            return Err(format!("cannot create {}: {e}", copy.display()));
        }
    };
    // This process created the file: its owner is our user, from our own
    // handle. With every directory up to / ours or root's, nobody else can
    // rename the private directory, or any directory above it, from now on.
    if let Err(e) = owned_by_us_or_root(&chain, &file) {
        // Remove only what we made: the directory may not be ours any more.
        let _ = std::fs::remove_file(&copy);
        let _ = std::fs::remove_dir(&private);
        return Err(e);
    }
    drop(file);
    let copied = copy_and_place(&source, &copy, &target, &parent, parent_id).await;
    let _ = std::fs::remove_dir_all(&private);
    copied
}

/// `target` as an absolute path of plain components: the working directory
/// (as the kernel reports it, without symlinks) joined with a relative
/// path, and `..` refused, so the chain checked is the one written to.
fn absolute(target: &Path) -> Result<PathBuf, String> {
    let joined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot read the working directory: {e}"))?
            .join(target)
    };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                return Err(format!("{}: use a path without ..", target.display()));
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Every directory from / down to `parent`, each a real directory (lstat:
/// a symlink anywhere is refused) that only its owner can change entries
/// in: no group or other write, unless it is sticky (the OpenSSH rule for
/// key directories). Otherwise another user could rename the private
/// directory, or a directory above it, away and plant theirs before the
/// copy is written. Owners are checked once this process's user is known
/// ([`owned_by_us_or_root`]).
fn secure_chain(parent: &Path) -> Result<Vec<(PathBuf, std::fs::Metadata)>, String> {
    let mut chain = Vec::new();
    let mut at = PathBuf::new();
    for c in parent.components() {
        at.push(c);
        let meta = at
            .symlink_metadata()
            .map_err(|e| format!("cannot use {}: {e}", at.display()))?;
        if !meta.file_type().is_dir() {
            return Err(format!(
                "{} is not a directory (a symlink in the path is refused)",
                at.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = meta.permissions().mode();
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(format!(
                    "{} is writable by its group or others: back up into a directory \
                     only its owner can change, under directories only theirs can (or \
                     sticky ones)",
                    at.display()
                ));
            }
        }
        chain.push((at.clone(), meta));
    }
    if chain.is_empty() {
        return Err(format!(
            "{}: no directory to back up into",
            parent.display()
        ));
    }
    Ok(chain)
}

/// Every directory in `chain` belongs to this process's user (the owner of
/// `ours`, a file it just created) or to root.
#[cfg(unix)]
fn owned_by_us_or_root(
    chain: &[(PathBuf, std::fs::Metadata)],
    ours: &std::fs::File,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let me = ours
        .metadata()
        .map_err(|e| format!("cannot read the backup file: {e}"))?
        .uid();
    for (dir, meta) in chain {
        let owner = meta.uid();
        if owner != me && owner != 0 {
            return Err(format!(
                "{} belongs to user {owner}, not this one ({me}) or root: back up \
                 into a directory this user owns",
                dir.display()
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn owned_by_us_or_root(
    _chain: &[(PathBuf, std::fs::Metadata)],
    _ours: &std::fs::File,
) -> Result<(), String> {
    Ok(())
}

/// Which directory this is: device and inode.
#[cfg(unix)]
fn dir_id(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn dir_id(_meta: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}

async fn copy_and_place(
    source: &Path,
    copy: &Path,
    target: &Path,
    parent: &Path,
    parent_id: (u64, u64),
) -> Result<u64, String> {
    let copy_text = copy
        .to_str()
        .ok_or_else(|| "the backup path must be valid UTF-8".to_owned())?;
    vacuum_into(source, copy_text).await?;
    still_the_same(parent, parent_id)?;
    place(copy, target)?;
    std::fs::metadata(target)
        .map(|m| m.len())
        .map_err(|e| format!("cannot read {}: {e}", target.display()))
}

/// The backstop before the link: `parent` is still the directory checked
/// at the start (same device and inode), not one swapped in since.
pub(crate) fn still_the_same(parent: &Path, id: (u64, u64)) -> Result<(), String> {
    let now = parent
        .symlink_metadata()
        .map_err(|e| format!("cannot use {}: {e}", parent.display()))?;
    if now.file_type().is_dir() && dir_id(&now) == id {
        Ok(())
    } else {
        Err(format!(
            "{} was replaced during the backup; nothing was written there",
            parent.display()
        ))
    }
}

/// A new 0700 directory in `parent`, on the target's file system.
fn private_dir(parent: &Path) -> Result<PathBuf, String> {
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

    #[test]
    fn a_parent_swapped_during_the_copy_is_caught_before_the_link() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("out");
        std::fs::create_dir(&parent).unwrap();
        let id = dir_id(&parent.symlink_metadata().unwrap());
        still_the_same(&parent, id).unwrap();
        // Renamed away, and another directory put in its place.
        std::fs::rename(&parent, dir.path().join("moved")).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let err = still_the_same(&parent, id).unwrap_err();
        assert!(err.contains("was replaced"), "{err}");
    }
}
