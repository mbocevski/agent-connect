//! The relay binary at `RUST_LOG=trace` (SR-14): its logs carry no `ct`, no
//! frame contents and no client address, whatever `RUST_LOG` asks of
//! `tungstenite`, `axum` and `hyper`.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use agentconnect_relay::proto::b64_encode;
use common::{Client, fresh_id, make_group, signing_key};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Kills the relay when the test ends, however it ends.
struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn trace_logs_carry_no_ct_and_no_client_address() {
    let dir = tempfile::tempdir().unwrap();
    let rust_log = "trace,tungstenite=trace,tokio_tungstenite=trace,axum=trace,axum::serve=trace,hyper=trace,hyper_util=trace";
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentconnect-relay"))
        .env("AC_RELAY_ADDR", "127.0.0.1:0")
        .env("AC_RELAY_METRICS_ADDR", "127.0.0.1:0")
        .env("AC_RELAY_HOST", common::HOST)
        .env("AC_RELAY_DB", dir.path().join("relay.db"))
        .env("RUST_LOG", rust_log)
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let relay = Relay(child);
    let (tx, rx) = mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut logs = Vec::new();
    let addr = loop {
        let line = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("relay did not start");
        logs.push(line.clone());
        if line.contains("relay listening") {
            let at = line.find("127.0.0.1:").expect("listen address");
            let addr: String = line[at..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
                .collect();
            break addr.parse::<std::net::SocketAddr>().unwrap();
        }
    };

    let mut client_ports = Vec::new();
    let marker = format!("ct-marker-{}", fresh_id());
    let mut a = Client::connect(addr, signing_key(1)).await;
    let b = Client::connect(addr, signing_key(2)).await;
    for c in [&a, &b] {
        if let tokio_tungstenite::MaybeTlsStream::Plain(tcp) = c.ws.get_ref() {
            client_ports.push(tcp.local_addr().unwrap().port());
        }
    }
    let gid = make_group(&mut a, &[&b]).await;
    let mut env = a.envelope("application", &gid, 1);
    env["ct"] = json!(b64_encode(marker.as_bytes()));
    assert_eq!(a.send(&env).await["t"], "accepted");
    let r = a.request(&json!({"t": "nonsense", "ct": marker})).await;
    assert_eq!(r["t"], "error");
    // A plain HTTP request too.
    let mut http = tokio::net::TcpStream::connect(addr).await.unwrap();
    client_ports.push(http.local_addr().unwrap().port());
    http.write_all(b"GET /healthz HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    http.read_to_end(&mut answer).await.unwrap();
    assert!(answer.starts_with(b"HTTP/1.1 200"));
    // Two signed-route requests through a proxy that sets forwarded-for
    // headers, with no client address header configured: one warning,
    // without the value.
    for _ in 0..2 {
        let mut proxied = tokio::net::TcpStream::connect(addr).await.unwrap();
        proxied
            .write_all(
                b"POST /v0/doors HTTP/1.1\r\nHost: relay.test\r\nX-Forwarded-For: 203.0.113.9\r\n\
                  Content-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut answer = Vec::new();
        proxied.read_to_end(&mut answer).await.unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 4"));
    }
    a.disconnect().await;
    b.disconnect().await;
    assert_eq!(client_ports.len(), 3);

    // Ends stdout, so the reader sees every line.
    drop(relay);
    reader.join().unwrap();
    logs.extend(rx.try_iter());
    let text = logs.join("\n");

    let warnings = logs
        .iter()
        .filter(|l| l.contains("AC_RELAY_CLIENT_IP_HEADER is not set"))
        .count();
    assert_eq!(warnings, 1, "{text}");
    assert!(!text.contains("203.0.113.9"), "forwarded address in logs");
    // The relay's own trace output gets through.
    assert!(text.contains("connected"), "{text}");
    assert!(text.contains("request rejected"), "{text}");
    for target in ["tungstenite", "hyper", "axum"] {
        assert!(!text.contains(target), "{target} logged:\n{text}");
    }
    assert!(!text.contains(&marker), "ct in logs");
    assert!(!text.contains(&b64_encode(marker.as_bytes())), "ct in logs");
    for port in client_ports {
        assert!(
            !text.contains(&format!("127.0.0.1:{port}")),
            "client address in logs"
        );
    }
    for line in logs.iter().filter(|l| l.contains("127.0.0.1")) {
        assert!(
            line.contains("relay listening") || line.contains("metrics listening"),
            "address in {line}"
        );
    }
}
