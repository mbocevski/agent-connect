//! What a relay process tells the next one about the signed requests it
//! accepted (SPEC §8.1.1): on a clean shutdown it writes the highest `ts`
//! it let through to a marker file next to the database, and the next start
//! takes the marker (reads and deletes it). With a marker, the next process
//! refuses only requests up to that `ts`; without one (a crash, or a
//! database from before this version) it refuses up to its start plus
//! 300 s.

use std::io::Write as _;
use std::path::PathBuf;

/// The marker file's name: the database path plus this.
pub const MARKER_SUFFIX: &str = ".clean-shutdown";

/// The database file `db` names (a path or a `sqlite:` URL), or `None` for
/// an in-memory database.
#[must_use]
pub fn database_path(db: &str) -> Option<PathBuf> {
    if db.contains(":memory:") {
        return None;
    }
    let path = db
        .strip_prefix("sqlite://")
        .or_else(|| db.strip_prefix("sqlite:"))
        .unwrap_or(db);
    Some(PathBuf::from(path.split('?').next().unwrap_or(path)))
}

/// Whether `db` names a database file that exists already.
#[must_use]
pub fn existing_database(db: &str) -> bool {
    database_path(db).is_some_and(|p| p.exists())
}

fn marker_path(db: &str) -> Option<PathBuf> {
    database_path(db).map(|p| {
        let mut name = p.into_os_string();
        name.push(MARKER_SUFFIX);
        PathBuf::from(name)
    })
}

/// Read and delete the clean-shutdown marker: the highest `ts` the last
/// process accepted, if it shut down cleanly. A marker that can't be read
/// or parsed counts as none, and is deleted all the same, so a later crash
/// can't reuse it.
#[must_use]
pub fn take_marker(db: &str) -> Option<u64> {
    let path = marker_path(db)?;
    let text = std::fs::read_to_string(&path).ok();
    let _ = std::fs::remove_file(&path);
    text?.trim().strip_prefix("clean ")?.parse().ok()
}

/// Write the clean-shutdown marker with `highest_ts`, atomically (a
/// temporary file, then a rename), once the server has stopped taking
/// requests.
///
/// # Errors
///
/// File system failures.
pub fn write_marker(db: &str, highest_ts: u64) -> std::io::Result<()> {
    let Some(path) = marker_path(db) else {
        return Ok(());
    };
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    writeln!(f, "clean {highest_ts}")?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        // The rename itself, durably.
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// The floor for a relay that starts on `db` (see the module docs):
/// `Some(highest_ts)` after a clean shutdown, `None` for the start-time
/// guard, and `Some(0)` for a new database (nothing to guard).
#[must_use]
pub fn floor_at_start(db: &str) -> Option<u64> {
    let existed = existing_database(db);
    match take_marker(db) {
        Some(ts) => Some(ts),
        None if existed => None,
        None => Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_memory_databases() {
        assert_eq!(database_path("sqlite::memory:"), None);
        assert_eq!(
            database_path("sqlite://data/relay.db?mode=rwc"),
            Some(PathBuf::from("data/relay.db"))
        );
        assert_eq!(
            database_path("sqlite:relay.db"),
            Some(PathBuf::from("relay.db"))
        );
        assert_eq!(
            database_path("/var/relay.db"),
            Some(PathBuf::from("/var/relay.db"))
        );
        assert_eq!(
            marker_path("/var/relay.db"),
            Some(PathBuf::from("/var/relay.db.clean-shutdown"))
        );
        assert!(write_marker("sqlite::memory:", 5).is_ok());
        assert_eq!(take_marker("sqlite::memory:"), None);
        assert_eq!(floor_at_start("sqlite::memory:"), Some(0));
    }

    #[test]
    fn a_clean_shutdown_marker_is_taken_once() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("relay.db");
        let db = db.to_str().unwrap();
        // A new database: nothing to guard.
        assert_eq!(floor_at_start(db), Some(0));
        std::fs::write(db, b"").unwrap();
        // An existing database without a marker: a crash.
        assert_eq!(floor_at_start(db), None);
        write_marker(db, 1_234).unwrap();
        let marker = marker_path(db).unwrap();
        assert!(marker.exists());
        assert_eq!(floor_at_start(db), Some(1_234));
        // Taken: the next start after a crash guards again.
        assert!(!marker.exists());
        assert_eq!(floor_at_start(db), None);
        // A marker that isn't one counts as none, and goes.
        std::fs::write(&marker, b"dirty").unwrap();
        assert_eq!(take_marker(db), None);
        assert!(!marker.exists());
    }
}
