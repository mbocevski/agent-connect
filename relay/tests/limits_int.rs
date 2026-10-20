//! The review probes as regressions against the real binary, on real time
//! (SR-06, SR-13 and the adversarial review of the connection limits). This
//! is the integration tier: `just test-int` runs them with `--run-ignored only`.
//! The fast tier covers the same rules on a manual clock in `ws_limits.rs` and
//! `review_limits.rs`.
//!
//! An attacker connects from 127.0.0.1 and an honest client from 127.0.0.2.
//! Both are loopback, but they are different sources to the relay.

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agentconnect_relay::auth::random_bytes;
use agentconnect_relay::proto::b64_encode;
use common::{Client, HOST, auth_frame, make_group, signing_key};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio_tungstenite::tungstenite::Message;

const ATTACKER: [u8; 4] = [127, 0, 0, 1];
const HONEST: [u8; 4] = [127, 0, 0, 2];

struct Relay {
    child: Child,
    addr: SocketAddr,
    metrics: SocketAddr,
    _dir: tempfile::TempDir,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn addr_in(line: &str) -> Option<SocketAddr> {
    let at = line.find("127.0.0.1:")?;
    let addr: String = line[at..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
        .collect();
    addr.parse().ok()
}

impl Relay {
    fn start(env: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentconnect-relay"));
        cmd.env("AC_RELAY_ADDR", "0.0.0.0:0")
            .env("AC_RELAY_METRICS_ADDR", "127.0.0.1:0")
            .env("AC_RELAY_HOST", HOST)
            .env("AC_RELAY_DB", dir.path().join("relay.db"))
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let (mut metrics, mut port) = (None, None);
        while metrics.is_none() || port.is_none() {
            let line = lines.next().expect("relay exited").unwrap();
            if line.contains("metrics listening") {
                metrics = addr_in(&line);
            } else if line.contains("relay listening") {
                port = line
                    .rsplit(':')
                    .next()
                    .and_then(|p| p.trim().parse::<u16>().ok());
            }
        }
        // Keep draining stdout so the relay never blocks on it.
        std::thread::spawn(move || for _ in lines {});
        Self {
            child,
            addr: SocketAddr::from((ATTACKER, port.unwrap())),
            metrics: metrics.unwrap(),
            _dir: dir,
        }
    }

    fn rss_kib(&self) -> u64 {
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.child.id())).unwrap();
        status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.split_whitespace().next())
            .unwrap()
            .parse()
            .unwrap()
    }

    async fn metric(&self, name: &str) -> u64 {
        let mut tcp = TcpStream::connect(self.metrics).await.unwrap();
        tcp.write_all(b"GET /metrics HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut body = String::new();
        tcp.read_to_string(&mut body).await.unwrap();
        body.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
            .unwrap_or_else(|| panic!("no {name}"))
            .parse()
            .unwrap()
    }

    /// Poll a metric until `ok` holds, for at most `limit` of real time.
    async fn wait_for(&self, name: &str, limit: Duration, ok: impl Fn(u64) -> bool) -> u64 {
        let end = Instant::now() + limit;
        loop {
            let v = self.metric(name).await;
            if ok(v) || Instant::now() > end {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// A TCP connection to the relay from `ip`.
async fn tcp_from(ip: [u8; 4], to: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((ip, 0)))?;
    socket.connect(SocketAddr::from((ip, to.port()))).await
}

type Ws = tokio_tungstenite::WebSocketStream<TcpStream>;

async fn ws_from(ip: [u8; 4], to: SocketAddr) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    let tcp = tcp_from(ip, to).await?;
    tokio_tungstenite::client_async(format!("ws://{HOST}/v0/ws"), tcp)
        .await
        .map(|(ws, _)| ws)
}

async fn next_json(ws: &mut Ws) -> Option<Value> {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .ok()??
        {
            Ok(Message::Text(t)) => return serde_json::from_str(t.as_str()).ok(),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

/// Upgrade from `ip` and authenticate as key `n`; the `ready` frame.
async fn authed_from(ip: [u8; 4], to: SocketAddr, n: u8) -> Option<(Ws, Value)> {
    let mut ws = ws_from(ip, to).await.ok()?;
    let challenge = next_json(&mut ws).await?;
    let auth = auth_frame(&signing_key(n), challenge["nonce"].as_str()?, HOST);
    ws.send(Message::text(auth.to_string())).await.ok()?;
    let ready = next_json(&mut ws).await?;
    Some((ws, ready))
}

async fn healthz_from(ip: [u8; 4], to: SocketAddr) -> String {
    let Ok(mut tcp) = tcp_from(ip, to).await else {
        return "connect failed".into();
    };
    let req = b"GET /healthz HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n";
    if tcp.write_all(req).await.is_err() {
        return "write failed".into();
    }
    let mut answer = Vec::new();
    match tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut answer)).await {
        Ok(Ok(_)) => String::from_utf8_lossy(&answer)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned(),
        _ => "no answer".into(),
    }
}

#[tokio::test]
#[ignore = "integration tier (just test-int): real time and process memory"]
async fn many_stalled_connections_for_a_full_mailbox_stay_within_memory() {
    let relay = Relay::start(&[("AC_RELAY_SEND_TIMEOUT_SECS", "3")]);
    let mut a = Client::connect(relay.addr, signing_key(1)).await;
    let b = Client::connect(relay.addr, signing_key(2)).await;
    let gid = make_group(&mut a, &[&b]).await;
    b.disconnect().await;
    // About 27 MiB queued for B, in 1.3 MiB messages.
    let ct = b64_encode(&random_bytes::<1_000_000>());
    for _ in 0..20 {
        let mut env = a.envelope("application", &gid, 1);
        env["ct"] = json!(ct);
        assert_eq!(a.send(&env).await["t"], "accepted");
    }
    let base = relay.rss_kib();

    // The probe: 20 connections for B that authenticate and never read.
    let mut stalled = Vec::new();
    for _ in 0..20 {
        let mut ws = common::raw_connect(relay.addr).await;
        let nonce = common::raw_recv(&mut ws).await.unwrap()["nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        common::raw_send(&mut ws, &auth_frame(&signing_key(2), &nonce, HOST)).await;
        stalled.push(ws);
    }
    let mut peak = base;
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end {
        peak = peak.max(relay.rss_kib());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Before the fix this grew by more than a gigabyte (each connection
    // loaded the whole queue); now a mailbox holds four connections and a
    // replaced one drops its batch before it tries to close.
    assert!(
        peak.saturating_sub(base) < 128 << 10,
        "RSS grew from {base} KiB to {peak} KiB"
    );
    assert_eq!(
        relay
            .metric("agentconnect_relay_connections_replaced_total")
            .await,
        16
    );
    let timeouts = relay
        .wait_for(
            "agentconnect_relay_connection_timeouts_total{kind=\"send\"}",
            Duration::from_secs(20),
            |v| v >= 4,
        )
        .await;
    assert!(timeouts >= 4, "{timeouts} send timeouts");
    drop(stalled);
}

#[tokio::test]
#[ignore = "integration tier (just test-int): real time"]
async fn unfinished_headers_and_silent_clients_are_dropped() {
    let relay = Relay::start(&[
        ("AC_RELAY_HEADER_TIMEOUT_SECS", "2"),
        ("AC_RELAY_PING_INTERVAL_SECS", "1"),
        ("AC_RELAY_IDLE_TIMEOUT_SECS", "3"),
    ]);
    // Slowloris: the request never finishes.
    let started = Instant::now();
    let mut tcp = TcpStream::connect(relay.addr).await.unwrap();
    tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), tcp.read_to_end(&mut rest))
        .await
        .expect("the half-sent request is still open")
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert_eq!(
        relay
            .metric("agentconnect_relay_connection_timeouts_total{kind=\"header\"}")
            .await,
        1
    );

    // An authenticated client that never reads, so never answers a ping.
    let silent = Client::connect(relay.addr, signing_key(3)).await;
    let idle = relay
        .wait_for(
            "agentconnect_relay_connection_timeouts_total{kind=\"idle\"}",
            Duration::from_secs(20),
            |v| v >= 1,
        )
        .await;
    assert_eq!(idle, 1);
    drop(silent);
}

#[tokio::test]
#[ignore = "integration tier (just test-int): real time"]
async fn stalled_http_requests_cannot_lock_out_other_clients() {
    // The review's finding 1: 512 requests whose body never comes, or whose
    // pipelined answers are never read, used to hold every HTTP slot.
    let relay = Relay::start(&[
        ("AC_RELAY_REQUEST_TIMEOUT_SECS", "2"),
        ("AC_RELAY_WRITE_TIMEOUT_SECS", "2"),
    ]);
    let mut held = Vec::new();
    for i in 0..80 {
        let Ok(mut tcp) = tcp_from(ATTACKER, relay.addr).await else {
            continue;
        };
        if i % 2 == 0 {
            let _ = tcp
                .write_all(b"POST /v0/invites HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{")
                .await;
        } else {
            let req = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n".repeat(4000);
            let _ = tokio::time::timeout(Duration::from_millis(200), tcp.write_all(&req)).await;
        }
        held.push(tcp);
    }
    // One source holds at most its share; the rest were closed at once.
    let open = relay
        .metric("agentconnect_relay_http_connections_open")
        .await;
    // 8 for the source, plus this metrics request on the operator's listener.
    assert!(open <= 9, "{open} HTTP connections open for one source");
    // The accept loop counts refusals as it gets to each connection.
    let refused = relay
        .wait_for(
            "agentconnect_relay_connections_refused_total{reason=\"http_source\"}",
            Duration::from_secs(5),
            |v| v >= 72,
        )
        .await;
    assert!(refused >= 72, "{refused} refused");
    // An honest client is served at once, WebSocket included.
    assert_eq!(healthz_from(HONEST, relay.addr).await, "HTTP/1.1 200 OK");
    let (_ws, ready) = authed_from(HONEST, relay.addr, 7)
        .await
        .expect("honest WebSocket");
    assert_eq!(ready["t"], "ready");
    // The stalled ones end at their deadlines.
    let left = relay
        .wait_for(
            "agentconnect_relay_http_connections_open",
            Duration::from_secs(15),
            |v| v <= 1,
        )
        .await;
    assert!(left <= 1, "stalled requests outlived their deadlines");
    assert!(
        relay
            .metric("agentconnect_relay_connection_timeouts_total{kind=\"request\"}")
            .await
            >= 1
    );
    drop(held);
}

#[tokio::test]
#[ignore = "integration tier (just test-int): real time"]
async fn many_sources_stalling_requests_cannot_lock_out_another() {
    // The verification's p1v: holders over 16 sources fill the HTTP cap and
    // keep reopening. Accepting doesn't pause at the cap; an honest client
    // from another source is served at once, within the header timeout.
    let relay = Relay::start(&[("AC_RELAY_MAX_HTTP_CONNECTIONS", "64")]);
    let mut held = Vec::new();
    for round in 0..2 {
        for src in 0..16_u8 {
            for _ in 0..8 {
                let Ok(mut tcp) = tcp_from([127, 0, 0, 10 + src], relay.addr).await else {
                    continue;
                };
                let _ = tcp
                    .write_all(
                        b"POST /v0/invites HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{",
                    )
                    .await;
                held.push(tcp);
            }
        }
        let started = Instant::now();
        assert_eq!(
            healthz_from(HONEST, relay.addr).await,
            "HTTP/1.1 200 OK",
            "round {round}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        let (_ws, ready) = authed_from(HONEST, relay.addr, 7 + round)
            .await
            .expect("honest WebSocket");
        assert_eq!(ready["t"], "ready");
    }
    assert!(
        relay
            .metric("agentconnect_relay_connections_evicted_total{cap=\"http\"}")
            .await
            >= 64
    );
    drop(held);
}

#[tokio::test]
#[ignore = "integration tier (just test-int): real time"]
async fn many_sources_cannot_fill_the_websocket_total() {
    // 4 sources fill the total with free mailboxes; an honest client from
    // another source still gets in, in the place of the busiest source's
    // oldest connection.
    let relay = Relay::start(&[("AC_RELAY_MAX_CONNECTIONS", "64")]);
    let mut held = Vec::new();
    for src in 0..4_u8 {
        for n in 0..16_u8 {
            if let Some((ws, ready)) =
                authed_from([127, 0, 0, 10 + src], relay.addr, 100 + src * 16 + n).await
                && ready["t"] == "ready"
            {
                held.push(ws);
            }
        }
    }
    assert_eq!(held.len(), 64);
    let (_honest, ready) = authed_from(HONEST, relay.addr, 7)
        .await
        .expect("honest WebSocket");
    assert_eq!(ready["t"], "ready");
    assert_eq!(
        relay
            .metric("agentconnect_relay_connections_evicted_total{cap=\"ws\"}")
            .await,
        1
    );
    drop(held);
}

#[tokio::test]
#[ignore = "integration tier (just test-int): real time"]
async fn one_source_cannot_fill_the_websocket_caps() {
    // The review's finding 2: free mailboxes from one attacker used to take
    // all 1024 WebSocket slots, authenticated or not.
    let relay = Relay::start(&[("AC_RELAY_AUTH_TIMEOUT_SECS", "2")]);
    let mut held = Vec::new();
    let mut refused = 0;
    for n in 0..40 {
        match authed_from(ATTACKER, relay.addr, 100 + n).await {
            Some((ws, ready)) if ready["t"] == "ready" => held.push(ws),
            _ => refused += 1,
        }
    }
    assert_eq!(held.len(), 32);
    assert_eq!(refused, 8);
    let (_honest, ready) = authed_from(HONEST, relay.addr, 7)
        .await
        .expect("honest WebSocket");
    assert_eq!(ready["t"], "ready");
    drop(held);
    relay
        .wait_for(
            "agentconnect_relay_ws_connections_open",
            Duration::from_secs(10),
            |v| v == 1,
        )
        .await;
    // Sockets that never authenticate: the same share, and only until the
    // auth deadline.
    let mut unauth = Vec::new();
    for _ in 0..40 {
        if let Ok(ws) = ws_from(ATTACKER, relay.addr).await {
            unauth.push(ws);
        }
    }
    assert_eq!(unauth.len(), 32);
    let (_honest2, ready) = authed_from(HONEST, relay.addr, 8)
        .await
        .expect("honest WebSocket");
    assert_eq!(ready["t"], "ready");
    let left = relay
        .wait_for(
            "agentconnect_relay_ws_connections_unauthenticated",
            Duration::from_secs(10),
            |v| v == 0,
        )
        .await;
    assert_eq!(left, 0);
}

/// A masked client frame with a zero mask key (payload unchanged).
fn frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = vec![if fin { 0x80 } else { 0 } | opcode];
    if len < 126 {
        out.push(0x80 | u8::try_from(len).unwrap());
    } else if len < 65536 {
        out.push(0x80 | 126);
        out.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
#[ignore = "integration tier (just test-int): real time and process memory"]
async fn unfinished_messages_stay_within_the_read_budget_and_go() {
    // The review's finding 4: connections that start a large message and
    // never finish it, kept alive with unsolicited pongs, used to hold about
    // 8 MiB each for good.
    let relay = Relay::start(&[
        ("AC_RELAY_READ_BUFFER_BYTES", "33554432"),
        ("AC_RELAY_PING_INTERVAL_SECS", "1"),
        ("AC_RELAY_IDLE_TIMEOUT_SECS", "3"),
    ]);
    let base = relay.rss_kib();
    let part = frame(1, false, &vec![b'a'; 2 << 20]);
    let mut held = Vec::new();
    for n in 0..32 {
        let Some((ws, _)) = authed_from(ATTACKER, relay.addr, 100 + n).await else {
            continue;
        };
        let mut tcp = ws.into_inner();
        let _ = tokio::time::timeout(Duration::from_secs(2), tcp.write_all(&part)).await;
        held.push(tcp);
    }
    let shed = relay
        .wait_for(
            "agentconnect_relay_connections_shed_total",
            Duration::from_secs(5),
            |v| v >= 1,
        )
        .await;
    assert!(shed >= 1, "nothing shed past the read budget");
    // The shed connections give their bytes back once they are gone.
    let held_now = relay
        .wait_for(
            "agentconnect_relay_read_bytes_held",
            Duration::from_secs(5),
            |v| v <= 32 << 20,
        )
        .await;
    assert!(held_now <= 32 << 20, "over the read budget: {held_now}");
    let grown = relay.rss_kib().saturating_sub(base);
    assert!(grown < 160 << 10, "RSS grew by {grown} KiB");
    for tcp in &mut held {
        let _ = tcp.write_all(&frame(0xA, true, b"")).await;
    }
    // The rest go at the upload check: no progress, unsolicited pongs only.
    let open = relay
        .wait_for(
            "agentconnect_relay_ws_connections_open",
            Duration::from_secs(15),
            |v| v == 0,
        )
        .await;
    assert_eq!(open, 0);
    assert_eq!(relay.metric("agentconnect_relay_read_bytes_held").await, 0);
}

#[tokio::test]
#[ignore = "integration tier (just test-int): real time"]
async fn sigterm_closes_websockets_and_exits_within_the_grace() {
    // The review's finding 7: SIGTERM skipped the graceful path, and one
    // stalled request kept SIGINT from ever finishing.
    let mut relay = Relay::start(&[("AC_RELAY_SHUTDOWN_GRACE_SECS", "2")]);
    let (mut ws, _) = authed_from(HONEST, relay.addr, 7).await.expect("WebSocket");
    while next_json(&mut ws)
        .await
        .is_some_and(|f| f["t"] != "drained")
    {}
    let mut stalled = TcpStream::connect(relay.addr).await.unwrap();
    stalled
        .write_all(b"POST /v0/doors HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    let pid = relay.child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    // The session is told.
    let close = loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Close(f)))) => break f,
            Ok(Some(Ok(_))) => {}
            other => panic!("no close frame: {other:?}"),
        }
    };
    assert_eq!(
        close.map(|f| f.reason.to_string()).as_deref(),
        Some("shutting_down")
    );
    let status = loop {
        if let Some(status) = relay.child.try_wait().unwrap() {
            break status;
        }
        assert!(started.elapsed() < Duration::from_secs(10), "still running");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(status.success(), "{status:?}");
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "waited for the request in flight"
    );
}
