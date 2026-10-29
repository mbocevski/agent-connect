//! What the HTTP phase's connection limits do for a request being served
//! and for an idle connection, on the manual timer: a request whose body is
//! in and that is being answered is not the connection a newcomer pushes
//! out, a source can protect two of them at most, a slow upload is not
//! protected at all, and an idle keep-alive connection has its own timeout,
//! longer than the header timeout.

mod common;

use std::net::IpAddr;
use std::time::Duration;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentconnect_relay::conn::SourceKey;
use agentconnect_relay::{Server, ServerLimits, SqliteStore};
use axum::Router;
use axum::body::Bytes;
use axum::routing::{get, post};
use common::Harness;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

const GUARD: Duration = Duration::from_secs(20);
/// The knock worker always waits on its next tick: one standing sleep.
const KNOCK_WORKER: usize = 1;
const OPEN: &str = "agentconnect_relay_http_connections_open";
const TIMEOUTS: &str = "agentconnect_relay_connection_timeouts_total";

fn metric(h: &Harness, name: &str) -> u64 {
    let text = h.relay.metrics().render();
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no metric {name} in\n{text}"))
        .parse()
        .unwrap()
}

async fn settle(h: &Harness, name: &str, want: u64) {
    tokio::time::timeout(GUARD, async {
        while metric(h, name) != want {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{name} stuck at {}, wanted {want}", metric(h, name)));
}

async fn yields(n: usize) {
    for _ in 0..n {
        tokio::task::yield_now().await;
    }
}

fn source(ip: &str) -> SourceKey {
    SourceKey::of(ip.parse::<IpAddr>().unwrap())
}

fn limits(total: usize, per_source: usize) -> ServerLimits {
    ServerLimits {
        max_http_connections: total,
        max_http_per_source: per_source,
        ..ServerLimits::default()
    }
}

const HEALTHZ: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n";

/// Handlers that take as long as the test lets them: `/slow` (a request
/// without a body) and `/slow-post` (one whose body has to be in) answer
/// "done" once the test opens the gate.
struct Gate {
    open: Notify,
    started: AtomicUsize,
}

impl Gate {
    fn router(self: &Arc<Self>) -> Router {
        let get_gate = Arc::clone(self);
        let post_gate = Arc::clone(self);
        Router::new()
            .route(
                "/slow",
                get(move || {
                    let gate = Arc::clone(&get_gate);
                    async move {
                        let open = gate.open.notified();
                        gate.started.fetch_add(1, Ordering::SeqCst);
                        open.await;
                        "done"
                    }
                }),
            )
            .route(
                "/slow-post",
                post(move |body: Bytes| {
                    let gate = Arc::clone(&post_gate);
                    async move {
                        let open = gate.open.notified();
                        gate.started.fetch_add(1, Ordering::SeqCst);
                        open.await;
                        format!("done {}", body.len())
                    }
                }),
            )
            .route("/fast", get(|| async { "ok" }))
    }

    /// Let every waiting handler answer.
    fn release(&self) {
        self.open.notify_waiters();
    }

    async fn started(&self, n: usize) {
        tokio::time::timeout(GUARD, async {
            while self.started.load(Ordering::SeqCst) < n {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the handlers did not start");
    }
}

fn gated(h: &Harness, limits: ServerLimits) -> (Server<SqliteStore>, Arc<Gate>) {
    let gate = Arc::new(Gate {
        open: Notify::new(),
        started: AtomicUsize::new(0),
    });
    let server = Server::with_router(h.relay.clone(), gate.router(), limits);
    (server, gate)
}

/// A connection from `ip` with a request being served: its handler is
/// working, waiting for the gate.
async fn serving(
    server: &Server<SqliteStore>,
    gate: &Gate,
    ip: &str,
    request: &[u8],
) -> DuplexStream {
    let started = gate.started.load(Ordering::SeqCst);
    let (mut client, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, source(ip)));
    client.write_all(request).await.unwrap();
    gate.started(started + 1).await;
    client
}

const SLOW: &[u8] = b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n";
const SLOW_POST: &[u8] = b"POST /slow-post HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";

/// The answer on `io`, which may stay open.
async fn drained_until_answer(io: &mut DuplexStream) -> String {
    let mut got = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let n = tokio::time::timeout(GUARD, io.read(&mut chunk))
            .await
            .expect("no answer")
            .unwrap();
        assert!(
            n > 0,
            "closed before the answer: {:?}",
            String::from_utf8_lossy(&got)
        );
        got.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&got).into_owned();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let wanted = head
                .to_ascii_lowercase()
                .split("content-length: ")
                .nth(1)
                .and_then(|v| v.split("\r\n").next()?.parse::<usize>().ok())
                .unwrap_or(0);
            if body.len() >= wanted {
                return text;
            }
        }
    }
}

/// What the relay sent on `io` until it closed it.
async fn drained(io: &mut DuplexStream) -> Vec<u8> {
    let mut out = Vec::new();
    tokio::time::timeout(GUARD, io.read_to_end(&mut out))
        .await
        .expect("the connection stayed open")
        .unwrap();
    out
}

/// A connection from `ip` that sends part of a request head and stops.
async fn silent(server: &Server<SqliteStore>, ip: &str) -> DuplexStream {
    let (mut client, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, source(ip)));
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    client
}

/// A connection from `ip` that sent a whole head and a little of a body.
async fn slow_upload(server: &Server<SqliteStore>, ip: &str) -> DuplexStream {
    let (mut client, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, source(ip)));
    client
        .write_all(b"POST /v0/invites HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{")
        .await
        .unwrap();
    client
}

/// What a newcomer from `ip` that asks for `path` gets back.
async fn newcomer(server: &Server<SqliteStore>, ip: &str, path: &str) -> Vec<u8> {
    let (mut client, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, source(ip)));
    // A refused newcomer is closed before it can write.
    let _ = client
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await;
    drained(&mut client).await
}

async fn answered(server: &Server<SqliteStore>, ip: &str, path: &str) -> bool {
    newcomer(server, ip, path)
        .await
        .starts_with(b"HTTP/1.1 200")
}

#[tokio::test]
async fn a_request_being_served_is_not_pushed_out() {
    let h = Harness::start().await;
    let (server, gate) = gated(&h, limits(4, 4));
    let mut honest = serving(&server, &gate, "198.51.100.1", SLOW).await;
    // Three more sources, one stalled head each: the HTTP phase is full.
    let mut stalled = Vec::new();
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        stalled.push(silent(&server, ip).await);
    }
    settle(&h, OPEN, 4).await;
    // A newcomer is answered: a stalled head made room, not the request
    // being served, though it is the oldest connection.
    assert!(answered(&server, "203.0.113.1", "/fast").await);
    gate.release();
    let reply = drained_until_answer(&mut honest).await;
    assert!(reply.ends_with("done"), "{reply}");
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connections_evicted_total{cap=\"http\"}"
        ),
        1
    );
}

#[tokio::test]
async fn a_request_is_protected_from_the_moment_its_body_is_in() {
    let h = Harness::start().await;
    let (server, gate) = gated(&h, limits(2, 2));
    // A request with a body that is all in, and a handler at work.
    let mut posting = serving(&server, &gate, "198.51.100.1", SLOW_POST).await;
    let _stalled = silent(&server, "192.0.2.1").await;
    settle(&h, OPEN, 2).await;
    assert!(answered(&server, "203.0.113.1", "/fast").await);
    gate.release();
    let reply = drained_until_answer(&mut posting).await;
    assert!(reply.ends_with("done 5"), "{reply}");
}

#[tokio::test]
async fn with_every_connection_a_protected_request_a_newcomer_is_refused() {
    let h = Harness::start().await;
    let (server, gate) = gated(&h, limits(2, 2));
    let mut a = serving(&server, &gate, "198.51.100.1", SLOW).await;
    let mut b = serving(&server, &gate, "198.51.100.2", SLOW).await;
    // Two sources each protecting one request fill a total of two: nothing
    // can make room, so the newcomer is closed.
    let out = newcomer(&server, "203.0.113.1", "/fast").await;
    assert!(out.is_empty(), "{:?}", String::from_utf8_lossy(&out));
    gate.release();
    assert!(drained_until_answer(&mut a).await.ends_with("done"));
    assert!(drained_until_answer(&mut b).await.ends_with("done"));
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connections_refused_total{reason=\"http_source\"}"
        ),
        1
    );
}

#[tokio::test]
async fn a_source_protects_at_most_two_requests_being_served() {
    let h = Harness::start().await;
    let (server, gate) = gated(&h, limits(3, 3));
    let mut first = serving(&server, &gate, "198.51.100.1", SLOW).await;
    let mut second = serving(&server, &gate, "198.51.100.1", SLOW).await;
    let mut third = serving(&server, &gate, "198.51.100.1", SLOW).await;
    // A newcomer from another source is answered: the oldest request of
    // the source holding three made room, the newest two stay.
    assert!(answered(&server, "203.0.113.1", "/fast").await);
    assert!(drained(&mut first).await.is_empty());
    gate.release();
    assert!(drained_until_answer(&mut second).await.ends_with("done"));
    assert!(drained_until_answer(&mut third).await.ends_with("done"));
}

#[tokio::test]
async fn slow_uploads_from_a_few_sources_do_not_lock_everyone_out() {
    let h = Harness::start().await;
    let server = Server::new(h.relay.clone(), limits(8, 8));
    let mut held = Vec::new();
    for ip in ["192.0.2.1", "192.0.2.2"] {
        for _ in 0..4 {
            held.push(slow_upload(&server, ip).await);
        }
    }
    settle(&h, OPEN, 8).await;
    // A body arriving at the client's pace doesn't shield its connection.
    for ip in ["203.0.113.1", "203.0.113.2", "203.0.113.3"] {
        assert!(
            answered(&server, ip, "/healthz").await,
            "{ip} was not answered"
        );
    }
}

/// One whole request and its answer on `io`, which stays open.
async fn exchange(io: &mut DuplexStream) -> String {
    io.write_all(HEALTHZ).await.unwrap();
    drained_until_answer(io).await
}

#[tokio::test]
async fn an_idle_keep_alive_connection_outlives_the_header_timeout() {
    let h = Harness::start().await;
    let mut io = h.duplex(1 << 16);
    assert!(exchange(&mut io).await.starts_with("HTTP/1.1 200"));
    settle(&h, OPEN, 1).await;
    // Past the header timeout, which covers a request head only: still open
    // and serving.
    let limits = ServerLimits::default();
    h.timer.advance(limits.header_timeout * 4);
    yields(50).await;
    assert_eq!(metric(&h, OPEN), 1);
    assert!(exchange(&mut io).await.starts_with("HTTP/1.1 200"));
    // The idle timeout closes it.
    h.timer.until_sleepers(KNOCK_WORKER + 1).await;
    h.timer.advance(limits.idle_timeout);
    settle(&h, OPEN, 0).await;
    assert_eq!(metric(&h, &format!("{TIMEOUTS}{{kind=\"http_idle\"}}")), 1);
    assert_eq!(metric(&h, &format!("{TIMEOUTS}{{kind=\"header\"}}")), 0);
}

#[tokio::test]
async fn the_header_timeout_starts_again_with_the_next_head() {
    let h = Harness::start().await;
    let mut io = h.duplex(1 << 16);
    assert!(exchange(&mut io).await.starts_with("HTTP/1.1 200"));
    // The first byte of the next head starts the header clock, not the idle one.
    io.write_all(b"G").await.unwrap();
    yields(50).await;
    h.timer.until_sleepers(KNOCK_WORKER + 1).await;
    h.timer.advance(ServerLimits::default().header_timeout);
    settle(&h, OPEN, 0).await;
    assert_eq!(metric(&h, &format!("{TIMEOUTS}{{kind=\"header\"}}")), 1);
    assert_eq!(metric(&h, &format!("{TIMEOUTS}{{kind=\"http_idle\"}}")), 0);
}
