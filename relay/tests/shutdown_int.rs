//! A SIGTERM (what docker, systemd and Kubernetes send) or SIGINT that
//! arrives as soon as the relay reports "relay listening" stops it
//! gracefully: exit status 0 and the clean-shutdown marker written. With the
//! handlers installed only once a spawned task was first polled, a signal in
//! that gap got the default action: the relay died without the marker, and
//! the next start applied the crash replay floor (as PID 1 in a container
//! the signal was ignored instead). Integration tier (`just test-int`): real
//! processes, real time.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How many relays are started and signalled right away per signal. The
/// gap is a few microseconds wide: before the fix, 8 of 500 SIGTERMs and
/// 3 of 500 SIGINTs hit it.
const RUNS: usize = 300;

/// Start a relay on a fresh database, signal it the moment it listens and
/// check how it stopped.
fn stop_right_after_listening(signal: &str) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("relay.db");
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentconnect-relay"))
        .env("AC_RELAY_ADDR", "127.0.0.1:0")
        .env("AC_RELAY_METRICS_ADDR", "127.0.0.1:0")
        .env("AC_RELAY_HOST", common::HOST)
        .env("AC_RELAY_DB", &db)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    loop {
        let line = lines
            .next()
            .expect("relay exited before listening")
            .unwrap();
        if line.contains("relay listening") {
            break;
        }
    }
    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args([signal, &pid])
            .status()
            .unwrap()
            .success()
    );
    let (tx, rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _ = tx.send(child.wait().unwrap());
    });
    let status = rx.recv_timeout(Duration::from_secs(10));
    if status.is_err() {
        let _ = Command::new("kill").args(["-KILL", &pid]).status();
    }
    waiter.join().unwrap();
    let status = status.expect("still running after the signal");
    assert!(status.success(), "{signal}: {status:?}");
    let marker = dir.path().join("relay.db.clean-shutdown");
    assert!(marker.exists(), "{signal}: no clean-shutdown marker");
}

#[test]
#[ignore = "integration tier (just test-int): real processes and time"]
fn sigterm_right_after_listening_stops_the_relay_gracefully() {
    for _ in 0..RUNS {
        stop_right_after_listening("-TERM");
    }
}

#[test]
#[ignore = "integration tier (just test-int): real processes and time"]
fn sigint_right_after_listening_stops_the_relay_gracefully() {
    for _ in 0..RUNS {
        stop_right_after_listening("-INT");
    }
}
