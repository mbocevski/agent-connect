//! `agentconnect-relay backup <path>`: an online copy of the relay's
//! database, taken through the relay's own SQLite library and user (the
//! image has no `sqlite3`, and a host `sqlite3` run as root can leave
//! `-wal` and `-shm` files the relay's user can't open).

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use agentconnect_relay::SqliteStore;
use agentconnect_relay::backup::backup;
use agentconnect_relay::store::{CreateGroupOutcome, Store};

#[tokio::test]
async fn a_backup_of_an_open_database_holds_what_was_written() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("relay.db");
    let db = db.to_str().unwrap();
    let store = SqliteStore::open(db).await.unwrap();
    assert!(matches!(
        store.create_group("g1", "alice", 1).await.unwrap(),
        CreateGroupOutcome::Created
    ));
    // The relay keeps the database open (WAL): the copy is taken anyway.
    let copy = dir.path().join("backup.db");
    let bytes = backup(db, &copy).await.unwrap();
    assert!(bytes > 0);
    assert_eq!(bytes, std::fs::metadata(&copy).unwrap().len());
    assert_eq!(
        std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
        0o600,
        "every queued ciphertext is in it"
    );
    assert_eq!(leftovers(dir.path()), Vec::<String>::new());
    drop(store);
    let restored = SqliteStore::open(copy.to_str().unwrap()).await.unwrap();
    assert!(matches!(
        restored.create_group("g1", "alice", 2).await.unwrap(),
        CreateGroupOutcome::Yours
    ));
}

#[tokio::test]
async fn an_existing_target_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("relay.db");
    let db = db.to_str().unwrap();
    let _store = SqliteStore::open(db).await.unwrap();
    let copy = dir.path().join("backup.db");
    std::fs::write(&copy, b"yesterday's backup").unwrap();
    let err = backup(db, &copy).await.unwrap_err();
    assert!(err.contains("exists"), "{err}");
    assert_eq!(std::fs::read(&copy).unwrap(), b"yesterday's backup");
    assert_eq!(leftovers(dir.path()), Vec::<String>::new());
}

#[tokio::test]
async fn only_a_directory_its_owner_alone_can_change_takes_a_backup() {
    // Anyone else who could rename entries there could swap the private
    // directory for theirs before the copy is written.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("relay.db");
    let db = db.to_str().unwrap();
    let _store = SqliteStore::open(db).await.unwrap();
    for (mode, refused) in [
        (0o775, true),
        (0o757, true),
        (0o1770, false),
        (0o755, false),
    ] {
        let out = dir.path().join(format!("out-{mode:o}"));
        std::fs::create_dir(&out).unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode)).unwrap();
        let copy = out.join("backup.db");
        let done = backup(db, &copy).await;
        if refused {
            let err = done.unwrap_err();
            assert!(
                err.contains("writable by its group or others"),
                "{mode:o}: {err}"
            );
            assert!(
                err.contains(out.to_str().unwrap()),
                "names the directory: {err}"
            );
            assert_eq!(
                std::fs::read_dir(&out).unwrap().count(),
                0,
                "nothing created"
            );
        } else {
            done.unwrap();
            assert!(copy.is_file(), "{mode:o}");
            assert_eq!(leftovers(&out), Vec::<String>::new());
        }
    }
    // A symlink to a fine directory is refused as the parent too.
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(dir.path().join("out-755"), &link).unwrap();
    let err = backup(db, &link.join("b2.db")).await.unwrap_err();
    assert!(err.contains("not a directory"), "{err}");
}

/// The private directories a backup left in `dir`: none, whatever happened.
fn leftovers(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".agentconnect-backup-"))
        .collect()
}

#[tokio::test]
async fn only_an_existing_database_file_is_backed_up() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("backup.db");
    let missing = dir.path().join("none.db");
    let err = backup(missing.to_str().unwrap(), &copy).await.unwrap_err();
    assert!(err.contains("no database"), "{err}");
    assert!(!missing.exists(), "not created by the backup");
    let err = backup("sqlite::memory:", &copy).await.unwrap_err();
    assert!(err.contains("in memory"), "{err}");
    assert!(!copy.exists());
}

/// Kills the relay when the test ends, however it ends.
struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run(args: &[&str], db: &std::path::Path) -> Output {
    let child = Command::new(env!("CARGO_BIN_EXE_agentconnect-relay"))
        .args(args)
        .env("AC_RELAY_DB", db)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A relay that ignored the arguments would serve forever: bounded.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || tx.send(child.wait_with_output()));
    rx.recv_timeout(Duration::from_secs(20))
        .expect("the command did not exit")
        .unwrap()
}

#[tokio::test]
async fn the_backup_subcommand_copies_a_running_relays_database() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("relay.db");
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentconnect-relay"))
        .env("AC_RELAY_ADDR", "127.0.0.1:0")
        .env("AC_RELAY_METRICS_ADDR", "127.0.0.1:0")
        .env("AC_RELAY_HOST", "relay.example.org")
        .env("AC_RELAY_DB", &db)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let _relay = Relay(child);
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    while !rx
        .recv_timeout(Duration::from_secs(20))
        .expect("relay did not start")
        .contains("relay listening")
    {}

    let copy = dir.path().join("backup.db");
    let out = run(&["backup", copy.to_str().unwrap()], &db);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("backup.db"));
    SqliteStore::open(copy.to_str().unwrap()).await.unwrap();

    let again = run(&["backup", copy.to_str().unwrap()], &db);
    assert_eq!(again.status.code(), Some(1), "{again:?}");
    let usage = run(&["backup"], &db);
    assert_eq!(usage.status.code(), Some(2), "{usage:?}");
}
