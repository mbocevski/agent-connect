//! The binary stops gracefully on SIGTERM, what docker, systemd and
//! Kubernetes send, as well as on SIGINT. As PID 1 in the image a process
//! that installs no SIGTERM handler ignores it, so `docker stop` waited out
//! its timeout and killed the directory. Integration tier (`just test-int`):
//! real process, real time.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use agentconnect_core::encoding::b64;
use agentconnect_core::listing::DirectoryKey;
use common::{HOST, RELAY, rng};

/// Start the directory on the in-memory store, wait until it listens, send
/// `signal` and return how it exited, or `None` if it was still running
/// after `limit`.
fn stop_with(signal: &str, limit: Duration) -> Option<ExitStatus> {
    let key = DirectoryKey::generate(&rng()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentconnect-directory"))
        .env("AC_DIRECTORY_ADDR", "127.0.0.1:0")
        .env("AC_DIRECTORY_HOST", HOST)
        .env("AC_DIRECTORY_RELAYS", RELAY)
        .env("AC_DIRECTORY_DB", "memory:")
        .env("AC_DIRECTORY_TOKEN_KEYS", b64(&key.public_key()))
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    while !lines
        .next()
        .expect("directory exited before listening")
        .unwrap()
        .contains("directory listening")
    {}
    // Keep draining stdout so the directory never blocks on it.
    std::thread::spawn(move || for _ in lines {});

    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args([signal, &pid])
            .status()
            .unwrap()
            .success()
    );
    let (tx, rx) = mpsc::channel();
    let id = child.id();
    let waiter = std::thread::spawn(move || {
        let _ = tx.send(child.wait().unwrap());
    });
    let status = rx.recv_timeout(limit).ok();
    if status.is_none() {
        let _ = Command::new("kill")
            .args(["-KILL", &id.to_string()])
            .status();
    }
    waiter.join().unwrap();
    status
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn sigterm_stops_the_directory_gracefully() {
    let status = stop_with("-TERM", Duration::from_secs(5)).expect("still running after 5 s");
    assert!(status.success(), "{status:?}");
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn sigint_stops_the_directory_gracefully() {
    let status = stop_with("-INT", Duration::from_secs(5)).expect("still running after 5 s");
    assert!(status.success(), "{status:?}");
}
