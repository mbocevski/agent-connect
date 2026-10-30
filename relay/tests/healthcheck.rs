//! `agentconnect-relay healthcheck`: the probe a container health check runs
//! in the distroless image (no shell, no curl). It asks the operator
//! listener (`AC_RELAY_METRICS_ADDR`) for `/healthz` and exits 0 or 1.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Kills the relay when the test ends, however it ends.
struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The address after `marker` on the relay's log line that contains it.
fn address_from(rx: &mpsc::Receiver<String>, marker: &str) -> SocketAddr {
    loop {
        let line = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("relay did not start");
        if line.contains(marker) {
            let at = line.find("127.0.0.1:").expect("listen address");
            let addr: String = line[at..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
                .collect();
            return addr.parse().unwrap();
        }
    }
}

/// `agentconnect-relay healthcheck` with the operator listener at `metrics`.
fn healthcheck(metrics: &str) -> Output {
    let child = Command::new(env!("CARGO_BIN_EXE_agentconnect-relay"))
        .arg("healthcheck")
        .env("AC_RELAY_METRICS_ADDR", metrics)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A relay that ignored the argument would serve forever: bounded.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || tx.send(child.wait_with_output()));
    rx.recv_timeout(Duration::from_secs(20))
        .expect("healthcheck did not exit")
        .unwrap()
}

#[test]
fn healthcheck_exits_0_for_a_running_relay_and_1_otherwise() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentconnect-relay"))
        .env("AC_RELAY_ADDR", "127.0.0.1:0")
        .env("AC_RELAY_METRICS_ADDR", "127.0.0.1:0")
        .env("AC_RELAY_HOST", "relay.example.org")
        .env("AC_RELAY_DB", dir.path().join("relay.db"))
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let relay = Relay(child);
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let metrics = address_from(&rx, "metrics listening");
    let _public = address_from(&rx, "relay listening");

    let healthy = healthcheck(&metrics.to_string());
    assert_eq!(healthy.status.code(), Some(0), "{healthy:?}");
    // An unspecified address is probed on loopback, as in the image
    // (AC_RELAY_METRICS_ADDR=0.0.0.0:9091 there).
    let any = healthcheck(&format!("0.0.0.0:{}", metrics.port()));
    assert_eq!(any.status.code(), Some(0), "{any:?}");

    drop(relay);
    let down = healthcheck(&metrics.to_string());
    assert_eq!(down.status.code(), Some(1), "{down:?}");
    let reason = String::from_utf8_lossy(&down.stderr);
    assert!(reason.contains("unhealthy"), "{reason}");

    let bad = healthcheck("not an address");
    assert_eq!(bad.status.code(), Some(1), "{bad:?}");
}
