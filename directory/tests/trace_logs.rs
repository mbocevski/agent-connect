//! The directory binary at `RUST_LOG=trace` (SR-14): its logs carry no
//! request bodies, no listing tokens and no client addresses, whatever
//! `RUST_LOG` asks of `axum`, `hyper` and the MCP library.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentconnect_core::encoding::b64;
use common::{HOST, Harness, RELAY, identity};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Kills the directory when the test ends, however it ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One HTTP/1.1 request on its own connection; returns the client's port
/// and the status line.
async fn request(addr: std::net::SocketAddr, head: &str, body: &[u8]) -> (u16, String) {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let head = format!(
        "{head}\r\nHost: {HOST}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tcp.write_all(head.as_bytes()).await.unwrap();
    tcp.write_all(body).await.unwrap();
    let mut answer = Vec::new();
    tcp.read_to_end(&mut answer).await.unwrap();
    let text = String::from_utf8_lossy(&answer);
    (port, text.lines().next().unwrap_or_default().to_owned())
}

#[tokio::test]
async fn trace_logs_carry_no_bodies_tokens_or_client_addresses() {
    // A listing signed under an operator key the binary pins, on the
    // binary's clock.
    let h = Harness::new();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    h.clock.set(UNIX_EPOCH + now);
    let agent = identity();
    let mut spec = h.spec("trace-probe-name", &agent);
    spec.description = "zebra-body-marker in the listing".into();
    let built = h.build(&spec);
    let token_sig = b64(&built.token.sig);
    let token_id = b64(&built.token.token_id);

    let rust_log = "trace,axum=trace,axum::serve=trace,hyper=trace,hyper_util=trace,rmcp=trace,tower=trace,sqlx=trace";
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentconnect-directory"))
        .env("AC_DIRECTORY_ADDR", "127.0.0.1:0")
        .env("AC_DIRECTORY_HOST", HOST)
        .env("AC_DIRECTORY_RELAYS", RELAY)
        .env("AC_DIRECTORY_TOKEN_KEYS", b64(&h.dk.public_key()))
        .env("AC_DIRECTORY_DB", "memory:")
        .env("RUST_LOG", rust_log)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let running = Running(child);
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
            .expect("directory did not start");
        logs.push(line.clone());
        if line.contains("directory listening") {
            let at = line.find("127.0.0.1:").expect("listen address");
            let addr: String = line[at..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
                .collect();
            break addr.parse::<std::net::SocketAddr>().unwrap();
        }
    };

    let mut ports = Vec::new();
    let (port, status) = request(
        addr,
        "POST /v0/listings HTTP/1.1\r\nContent-Type: application/json",
        &built.bytes,
    )
    .await;
    assert!(status.starts_with("HTTP/1.1 201"), "{status}");
    ports.push(port);
    let (port, _) = request(addr, "GET /search?q=zebra-query-marker HTTP/1.1", b"").await;
    ports.push(port);
    let (port, _) = request(addr, "GET /a/trace-probe-name HTTP/1.1", b"").await;
    ports.push(port);
    // A client-chosen method is logged as `other`, never verbatim: it could
    // carry an address or a name (SR-21).
    let (port, _) = request(addr, "ME-203.0.113.9-zebra-method /healthz HTTP/1.1", b"").await;
    ports.push(port);
    let init = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "zebra-mcp-client", "version": "9.9"}}});
    let (port, _) = request(
        addr,
        "POST /mcp HTTP/1.1\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\nMcp-Protocol-Version: 2025-11-25",
        &serde_json::to_vec(&init).unwrap(),
    )
    .await;
    ports.push(port);

    // Ends stdout, so the reader sees every line.
    drop(running);
    reader.join().unwrap();
    logs.extend(rx.try_iter());
    let text = logs.join("\n");

    // The directory's own lines get through.
    assert!(text.contains("route=\"/v0/listings\""), "{text}");
    assert!(text.contains("route=\"/mcp\""), "{text}");
    assert!(text.contains("method=\"GET\""), "{text}");
    assert!(text.contains("method=\"other\""), "{text}");
    assert!(!text.contains("203.0.113.9"), "{text}");
    for target in ["axum", "hyper", "rmcp", "tower", "sqlx"] {
        assert!(!text.contains(target), "{target} logged:\n{text}");
    }
    for leak in [
        "zebra",
        "trace-probe-name",
        token_sig.as_str(),
        token_id.as_str(),
        agent.id().as_str(),
    ] {
        assert!(!text.contains(leak), "logs contain {leak:?}:\n{text}");
    }
    for port in ports {
        assert!(
            !text.contains(&format!("127.0.0.1:{port}")),
            "client address in logs"
        );
    }
    for line in logs.iter().filter(|l| l.contains("127.0.0.1")) {
        assert!(line.contains("directory listening"), "address in {line}");
    }
}
