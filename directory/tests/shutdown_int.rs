//! The binary stops gracefully on SIGTERM, what docker, systemd and
//! Kubernetes send, as well as on SIGINT. As PID 1 in the image a process
//! that installs no SIGTERM handler ignores it, so `docker stop` waited out
//! its timeout and killed the directory. Connections still open after
//! `AC_DIRECTORY_SHUTDOWN_GRACE_SECS` don't hold the exit up. Integration
//! tier (`just test-int`): real process, real time.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use agentconnect_core::encoding::b64;
use agentconnect_core::listing::DirectoryKey;
use common::{HOST, RELAY, rng};

/// The directory on the in-memory store, once it listens, and its address.
fn start(grace_secs: &str) -> (Child, String) {
    let key = DirectoryKey::generate(&rng()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentconnect-directory"))
        .env("AC_DIRECTORY_ADDR", "127.0.0.1:0")
        .env("AC_DIRECTORY_HOST", HOST)
        .env("AC_DIRECTORY_RELAYS", RELAY)
        .env("AC_DIRECTORY_DB", "memory:")
        .env("AC_DIRECTORY_TOKEN_KEYS", b64(&key.public_key()))
        .env("AC_DIRECTORY_SHUTDOWN_GRACE_SECS", grace_secs)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let addr = loop {
        let line = lines
            .next()
            .expect("directory exited before listening")
            .unwrap();
        if line.contains("directory listening") {
            let at = line.find("127.0.0.1:").expect("an address in the line");
            break line[at..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
                .collect();
        }
    };
    // Keep draining stdout so the directory never blocks on it.
    std::thread::spawn(move || for _ in lines {});
    (child, addr)
}

/// Send `signal` and return how the directory exited, or `None` if it was
/// still running after `limit` (it is killed then).
fn stop_with(mut child: Child, signal: &str, limit: Duration) -> Option<ExitStatus> {
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
    let status = rx.recv_timeout(limit).ok();
    if status.is_none() {
        let _ = Command::new("kill").args(["-KILL", &pid]).status();
    }
    waiter.join().unwrap();
    status
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn sigterm_stops_the_directory_gracefully() {
    let (child, _) = start("8");
    let status = stop_with(child, "-TERM", Duration::from_secs(5)).expect("still running");
    assert!(status.success(), "{status:?}");
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn sigint_stops_the_directory_gracefully() {
    let (child, _) = start("8");
    let status = stop_with(child, "-INT", Duration::from_secs(5)).expect("still running");
    assert!(status.success(), "{status:?}");
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn an_unfinished_request_holds_the_exit_up_only_for_the_grace() {
    let (child, addr) = start("2");
    // A request head that never ends.
    let mut held = TcpStream::connect(&addr).unwrap();
    held.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").unwrap();
    // The directory has the connection before the signal: a request on a
    // second connection is answered only once the first was accepted.
    let mut probe = TcpStream::connect(&addr).unwrap();
    probe
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut answer = String::new();
    BufReader::new(&probe).read_line(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1"), "{answer}");

    let started = Instant::now();
    let status = stop_with(child, "-TERM", Duration::from_secs(6)).expect("still running");
    assert!(status.success(), "{status:?}");
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "waited for the connection in flight"
    );
    drop(held);
}
