//! `agentconnect-directory healthcheck`: the probe a container health check
//! runs in the distroless image (no shell, no curl). It asks the
//! directory's listener (`AC_DIRECTORY_ADDR`) for `/healthz` and exits 0
//! or 1.

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use agentconnect_core::encoding::b64;
use common::{HOST, Harness, RELAY};

/// Kills the directory when the test ends, however it ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn directory(addr: &str, key: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentconnect-directory"));
    cmd.env("AC_DIRECTORY_ADDR", addr)
        .env("AC_DIRECTORY_HOST", HOST)
        .env("AC_DIRECTORY_RELAYS", RELAY)
        .env("AC_DIRECTORY_TOKEN_KEYS", key)
        .env("AC_DIRECTORY_DB", "memory:")
        .env("NO_COLOR", "1");
    cmd
}

/// `agentconnect-directory healthcheck` against a listener at `addr`.
fn healthcheck(addr: &str, key: &str) -> Output {
    let child = directory(addr, key)
        .arg("healthcheck")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A directory that ignored the argument would serve forever: bounded.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || tx.send(child.wait_with_output()));
    rx.recv_timeout(Duration::from_secs(20))
        .expect("healthcheck did not exit")
        .unwrap()
}

#[test]
fn healthcheck_exits_0_for_a_running_directory_and_1_otherwise() {
    let key = b64(&Harness::new().dk.public_key());
    let mut child = directory("127.0.0.1:0", &key)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let running = Running(child);
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let addr: SocketAddr = loop {
        let line = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("directory did not start");
        if line.contains("directory listening") {
            let at = line.find("127.0.0.1:").expect("listen address");
            let text: String = line[at..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
                .collect();
            break text.parse().unwrap();
        }
    };

    let healthy = healthcheck(&addr.to_string(), &key);
    assert_eq!(healthy.status.code(), Some(0), "{healthy:?}");
    let any = healthcheck(&format!("0.0.0.0:{}", addr.port()), &key);
    assert_eq!(any.status.code(), Some(0), "{any:?}");

    drop(running);
    let down = healthcheck(&addr.to_string(), &key);
    assert_eq!(down.status.code(), Some(1), "{down:?}");
    assert!(String::from_utf8_lossy(&down.stderr).contains("unhealthy"));
}
