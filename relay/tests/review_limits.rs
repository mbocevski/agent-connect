//! Regressions for the adversarial review of the connection limits, on the
//! manual timer: HTTP requests that stall after their headers, per-source
//! caps, the unauthenticated pool, the read budget, partial and slow
//! uploads, solicited pongs, knock and ack metrics, and shutdown.

mod common;

use std::net::IpAddr;
use std::time::Duration;

use agentconnect_relay::conn::SourceKey;
use agentconnect_relay::quota::{Cidr, ClientIp};
use agentconnect_relay::store::{NewMessage, Store};
use agentconnect_relay::{Server, ServerLimits, WsLimits};
use axum::http::HeaderName;
use common::{
    HOST, Harness, auth_frame, fresh_id, knock_frame, mailbox_of, open_door, queued, raw_connect,
    raw_recv, raw_send, roomy_quotas, signing_key, test_ws_limits,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const GUARD: Duration = Duration::from_secs(20);
/// The knock worker always waits on its next tick: one standing sleep.
const KNOCK_WORKER: usize = 1;

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

const TIMEOUT: &str = "agentconnect_relay_connection_timeouts_total";

fn timeouts(h: &Harness, kind: &str) -> u64 {
    metric(h, &format!("{TIMEOUT}{{kind=\"{kind}\"}}"))
}

async fn read_all(io: &mut DuplexStream) -> Vec<u8> {
    let mut out = Vec::new();
    tokio::time::timeout(GUARD, io.read_to_end(&mut out))
        .await
        .expect("the connection stayed open")
        .unwrap();
    out
}

/// A masked client frame with a zero mask key (payload unchanged).
fn frame(opcode: u8, fin: bool, len: usize, payload: &[u8]) -> Vec<u8> {
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

type Ws = WebSocketStream<DuplexStream>;

async fn next_json(ws: &mut Ws) -> Value {
    loop {
        match tokio::time::timeout(GUARD, ws.next()).await.unwrap() {
            Some(Ok(Message::Text(t))) => return serde_json::from_str(t.as_str()).unwrap(),
            Some(Ok(_)) => {}
            other => panic!("ended: {other:?}"),
        }
    }
}

async fn upgrade(h: &Harness, src: SourceKey) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    let io = h.duplex_from(4 << 20, src);
    tokio_tungstenite::client_async(format!("ws://{HOST}/v0/ws"), io)
        .await
        .map(|(ws, _)| ws)
}

/// Upgrade and authenticate as key `n`, read up to `drained`, then hand
/// back the raw stream (tungstenite has nothing buffered at that point).
async fn raw_authed(h: &Harness, n: u8) -> DuplexStream {
    raw_authed_from(h, SourceKey::unknown(), n).await
}

/// [`raw_authed`] from `src`.
async fn raw_authed_from(h: &Harness, src: SourceKey, n: u8) -> DuplexStream {
    let mut ws = upgrade(h, src).await.unwrap();
    let challenge = next_json(&mut ws).await;
    let auth = auth_frame(&signing_key(n), challenge["nonce"].as_str().unwrap(), HOST);
    ws.send(Message::text(auth.to_string())).await.unwrap();
    while next_json(&mut ws).await["t"] != "drained" {}
    ws.into_inner()
}

/// The bytes the relay has sent on a raw stream so far, without waiting
/// for more than the guard.
async fn received(io: &mut DuplexStream) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut buf = vec![0_u8; 1 << 16];
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(50), io.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&buf[..n]);
    }
    seen
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// --- 1. HTTP requests that stall after their headers -------------------------

#[tokio::test]
async fn a_request_body_that_never_arrives_gets_408_at_the_request_deadline() {
    let h = Harness::start().await;
    let mut io = h.duplex(1 << 16);
    io.write_all(b"POST /v0/doors HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{")
        .await
        .unwrap();
    settle(&h, "agentconnect_relay_http_connections_open", 1).await;
    // The handler waits for the body under the request deadline.
    h.timer.until_sleepers(KNOCK_WORKER + 1).await;
    h.timer.advance(ServerLimits::default().request_timeout);
    let answer = read_all(&mut io).await;
    assert!(
        answer.starts_with(b"HTTP/1.1 408"),
        "{:?}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(timeouts(&h, "request"), 1);
    settle(&h, "agentconnect_relay_http_connections_open", 0).await;
}

#[tokio::test]
async fn pipelined_responses_nobody_reads_end_at_the_write_timeout() {
    let h = Harness::start().await;
    let (mut reader, mut writer) = tokio::io::split(h.duplex(4096));
    // Many requests, never a byte of their answers read.
    tokio::spawn(async move {
        let req = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n".repeat(2000);
        let _ = writer.write_all(&req).await;
    });
    settle(&h, "agentconnect_relay_http_connections_open", 1).await;
    // The relay is blocked writing an answer, with its write deadline set.
    h.timer.until_sleepers(KNOCK_WORKER + 1).await;
    h.timer.advance(ServerLimits::default().write_timeout);
    settle(&h, "agentconnect_relay_http_connections_open", 0).await;
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(GUARD, reader.read_to_end(&mut rest)).await;
}

#[tokio::test]
async fn one_source_holds_at_most_its_share_of_http_connections() {
    let h = Harness::start().await;
    let server = Server::new(
        h.relay.clone(),
        ServerLimits {
            max_http_per_source: 2,
            ..ServerLimits::default()
        },
    );
    let attacker = source("192.0.2.1");
    let mut held = Vec::new();
    for _ in 0..2 {
        let (client, end) = tokio::io::duplex(4096);
        tokio::spawn(server.connection_from(end, attacker));
        held.push(client);
    }
    settle(&h, "agentconnect_relay_http_connections_open", 2).await;
    // A third from the same source is closed at once.
    let (mut third, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, attacker));
    assert!(read_all(&mut third).await.is_empty());
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connections_refused_total{reason=\"http_source\"}"
        ),
        1
    );
    // Another source is served.
    let (mut other, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, source("198.51.100.1")));
    other
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert!(read_all(&mut other).await.starts_with(b"HTTP/1.1 200"));
    // An IPv6 /64 is one source.
    let six = source("2001:db8:1:2::1");
    let (_a, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, six));
    let (_b, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, source("2001:db8:1:2:ffff::2")));
    let (mut c, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, six));
    assert!(read_all(&mut c).await.is_empty());
}

#[tokio::test]
async fn a_body_over_the_cap_gets_413() {
    let h = Harness::start().await;
    let mut io = h.duplex(1 << 20);
    let body = vec![b'x'; ServerLimits::default().max_body_bytes + 1];
    let head = format!(
        "POST /v0/invites HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    io.write_all(head.as_bytes()).await.unwrap();
    io.write_all(&body).await.unwrap();
    let answer = read_all(&mut io).await;
    assert!(
        answer.starts_with(b"HTTP/1.1 413"),
        "{:?}",
        String::from_utf8_lossy(&answer)
    );
}

#[tokio::test]
async fn at_the_http_cap_a_newcomer_closes_the_oldest_of_the_busiest_source() {
    // The verification's rolling lockout: several sources fill the HTTP
    // phase with stalled requests. Accepting doesn't pause; an honest
    // client from another source is served at once.
    let h = Harness::start().await;
    let server = Server::new(
        h.relay.clone(),
        ServerLimits {
            max_http_connections: 4,
            max_http_per_source: 2,
            ..ServerLimits::default()
        },
    );
    let stall = b"POST /v0/invites HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{";
    let mut held = Vec::new();
    for ip in ["192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.2"] {
        let (mut client, end) = tokio::io::duplex(4096);
        tokio::spawn(server.connection_from(end, source(ip)));
        client.write_all(stall).await.unwrap();
        held.push(client);
    }
    settle(&h, "agentconnect_relay_http_connections_open", 4).await;
    let (mut honest, end) = tokio::io::duplex(4096);
    tokio::spawn(server.connection_from(end, source("198.51.100.1")));
    honest
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    assert!(read_all(&mut honest).await.starts_with(b"HTTP/1.1 200"));
    // The oldest of the first busiest source made room.
    assert!(read_all(&mut held[0]).await.is_empty());
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connections_evicted_total{cap=\"http\"}"
        ),
        1
    );
}

// --- 2. One source filling the WebSocket caps -------------------------------

#[tokio::test]
async fn one_source_holds_at_most_its_share_of_websockets() {
    let h = Harness::with_ws_limits(WsLimits {
        max_per_source: 3,
        ..test_ws_limits()
    })
    .await;
    let attacker = source("192.0.2.1");
    let mut held = Vec::new();
    for _ in 0..3 {
        held.push(upgrade(&h, attacker).await.unwrap());
    }
    let refused = upgrade(&h, attacker).await.unwrap_err();
    let tokio_tungstenite::tungstenite::Error::Http(resp) = refused else {
        panic!("not an HTTP refusal: {refused:?}");
    };
    assert_eq!(resp.status(), 503);
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connections_refused_total{reason=\"source\"}"
        ),
        1
    );
    // An honest client elsewhere still gets in.
    let mut honest = upgrade(&h, source("198.51.100.1")).await.unwrap();
    assert_eq!(next_json(&mut honest).await["t"], "challenge");
}

#[tokio::test]
async fn behind_a_trusted_proxy_the_websocket_share_counts_the_forwarded_address() {
    let mut quotas = roomy_quotas();
    quotas.client_ip = ClientIp {
        header: Some(HeaderName::from_static("x-forwarded-for")),
        trusted_proxies: vec![Cidr::parse("127.0.0.1/32").unwrap()],
        hops: 1,
    };
    let h = Harness::with_quotas_and_ws(
        quotas,
        WsLimits {
            max_per_source: 1,
            ..test_ws_limits()
        },
    )
    .await;
    let via = |client: &str| {
        let mut req = format!("ws://{}/v0/ws", h.addr)
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("x-forwarded-for", client.parse().unwrap());
        tokio_tungstenite::connect_async(req)
    };
    let (mut first, _) = via("2001:db8:1:1::1").await.unwrap();
    assert_eq!(raw_recv(&mut first).await.unwrap()["t"], "challenge");
    // The same /64 as the first: its one share is taken.
    let refused = via("2001:db8:1:1::2").await.unwrap_err();
    assert!(
        matches!(refused, tokio_tungstenite::tungstenite::Error::Http(ref r) if r.status() == 503)
    );
    // Another client behind the same proxy has its own share.
    let (mut other, _) = via("203.0.113.7").await.unwrap();
    assert_eq!(raw_recv(&mut other).await.unwrap()["t"], "challenge");
}

#[tokio::test]
async fn unauthenticated_sockets_have_their_own_smaller_pool() {
    let h = Harness::with_ws_limits(WsLimits {
        max_unauthenticated: 2,
        ..test_ws_limits()
    })
    .await;
    let mut first = raw_connect(h.addr).await;
    let _second = raw_connect(h.addr).await;
    let refused = tokio_tungstenite::connect_async(format!("ws://{}/v0/ws", h.addr))
        .await
        .unwrap_err();
    assert!(
        matches!(refused, tokio_tungstenite::tungstenite::Error::Http(ref r) if r.status() == 503)
    );
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connections_refused_total{reason=\"unauthenticated\"}"
        ),
        1
    );
    assert_eq!(
        metric(&h, "agentconnect_relay_ws_connections_unauthenticated"),
        2
    );
    // Authenticating leaves the pool, and a new socket fits again.
    let nonce = raw_recv(&mut first).await.unwrap()["nonce"]
        .as_str()
        .unwrap()
        .to_owned();
    raw_send(&mut first, &auth_frame(&signing_key(1), &nonce, HOST)).await;
    assert_eq!(raw_recv(&mut first).await.unwrap()["t"], "ready");
    settle(&h, "agentconnect_relay_ws_connections_unauthenticated", 1).await;
    let _third = raw_connect(h.addr).await;
    // The pool's sockets go at the short auth deadline.
    h.timer.advance(WsLimits::default().auth_timeout);
    settle(&h, "agentconnect_relay_ws_connections_unauthenticated", 0).await;
}

#[tokio::test]
async fn past_the_total_a_socket_that_authenticates_is_refused() {
    let h = Harness::with_ws_limits(WsLimits {
        max_connections: 1,
        ..test_ws_limits()
    })
    .await;
    let mut a = raw_connect(h.addr).await;
    let mut b = raw_connect(h.addr).await;
    for (ws, n) in [(&mut a, 1), (&mut b, 2)] {
        let nonce = raw_recv(ws).await.unwrap()["nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        raw_send(ws, &auth_frame(&signing_key(n), &nonce, HOST)).await;
    }
    assert_eq!(raw_recv(&mut a).await.unwrap()["t"], "ready");
    let e = raw_recv(&mut b).await.unwrap();
    assert_eq!(e["code"], "rate_limited");
    assert_eq!(raw_recv(&mut b).await, None);
}

// --- 4. Read buffers ---------------------------------------------------------

#[tokio::test]
async fn past_the_read_budget_the_largest_partial_message_is_shed() {
    let h = Harness::with_ws_limits(WsLimits {
        read_buffer_bytes: 4 << 20,
        ..test_ws_limits()
    })
    .await;
    let mut small = raw_authed(&h, 1).await;
    let mut big = raw_authed(&h, 2).await;
    let mut third = raw_authed(&h, 3).await;
    let part = |n: usize| frame(1, false, n, &vec![b'a'; n]);
    small.write_all(&part(1 << 20)).await.unwrap();
    big.write_all(&part(2 << 20)).await.unwrap();
    settle(&h, "agentconnect_relay_connections_shed_total", 0).await;
    third.write_all(&part(1536 << 10)).await.unwrap();
    settle(&h, "agentconnect_relay_connections_shed_total", 1).await;
    assert!(contains(&received(&mut big).await, b"read_budget"));
    // What is left fits the budget, and the others stay open.
    assert!(metric(&h, "agentconnect_relay_read_bytes_held") <= 4 << 20);
    assert_eq!(metric(&h, "agentconnect_relay_ws_connections_open"), 2);
    assert!(!contains(&received(&mut small).await, b"read_budget"));
}

#[tokio::test]
async fn the_read_budget_sheds_the_busiest_source_not_the_largest_message() {
    // An honest client's one large upload must not be shed because one
    // attacker holds many smaller partial messages.
    let h = Harness::with_ws_limits(WsLimits {
        read_buffer_bytes: 4 << 20,
        ..test_ws_limits()
    })
    .await;
    let attacker = source("192.0.2.1");
    let mut welcome = raw_authed_from(&h, source("198.51.100.1"), 1).await;
    let mut partials = Vec::new();
    for n in 0..4 {
        partials.push(raw_authed_from(&h, attacker, 10 + n).await);
    }
    let part = |n: usize| frame(1, false, n, &vec![b'a'; n]);
    welcome.write_all(&part(2 << 20)).await.unwrap();
    for io in &mut partials {
        io.write_all(&part(768 << 10)).await.unwrap();
    }
    // 5 MiB against a 4 MiB budget: attacker partials go until it fits.
    tokio::time::timeout(GUARD, async {
        while metric(&h, "agentconnect_relay_read_bytes_held") > 4 << 20
            || metric(&h, "agentconnect_relay_connections_shed_total") == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!contains(&received(&mut welcome).await, b"read_budget"));
    let mut shed = 0;
    for io in &mut partials {
        if contains(&received(io).await, b"read_budget") {
            shed += 1;
        }
    }
    assert!(shed >= 2, "{shed} attacker connections shed");
    assert_eq!(
        metric(&h, "agentconnect_relay_connections_shed_total"),
        shed
    );
}

#[tokio::test]
async fn an_unfinished_fragmented_message_is_closed_at_the_upload_check() {
    // The review's probe: the first fragment of a message and then only
    // unsolicited pongs. Pongs nobody asked for are not activity, and the
    // message isn't arriving at the minimum rate.
    let limits = test_ws_limits();
    let h = Harness::with_ws_limits(limits.clone()).await;
    let mut io = raw_authed(&h, 1).await;
    let part = vec![b'a'; 3 << 19];
    io.write_all(&frame(1, false, part.len(), &part))
        .await
        .unwrap();
    for _ in 0..12 {
        if timeouts(&h, "upload") == 1 {
            break;
        }
        h.timer.advance(limits.ping_interval);
        let _ = io.write_all(&frame(0xA, true, 0, b"")).await;
        yields(200).await;
        let _ = received(&mut io).await;
    }
    assert_eq!(timeouts(&h, "upload"), 1);
    settle(&h, "agentconnect_relay_ws_connections_open", 0).await;
    assert_eq!(metric(&h, "agentconnect_relay_read_bytes_held"), 0);
}

#[tokio::test]
async fn unsolicited_pongs_do_not_keep_a_connection_alive() {
    let limits = test_ws_limits();
    let h = Harness::with_ws_limits(limits.clone()).await;
    let mut io = raw_authed(&h, 1).await;
    for _ in 0..8 {
        if timeouts(&h, "idle") == 1 {
            break;
        }
        h.timer.advance(limits.ping_interval);
        let _ = io.write_all(&frame(0xA, true, 4, b"nope")).await;
        yields(200).await;
        let _ = received(&mut io).await;
    }
    assert_eq!(timeouts(&h, "idle"), 1);
}

// --- 5. Slow uploads ---------------------------------------------------------

/// A 1 MiB text frame whose payload is one JSON object.
fn big_frame_parts() -> (Vec<u8>, Vec<u8>) {
    let len = 1 << 20;
    let head = br#"{"t":"nonsense","pad":""#;
    let mut payload = head.to_vec();
    payload.resize(len - 2, b'x');
    payload.extend_from_slice(b"\"}");
    let header = frame(1, true, len, b"");
    (header, payload)
}

#[tokio::test]
async fn a_large_message_trickled_above_the_minimum_rate_gets_through() {
    let limits = test_ws_limits();
    let h = Harness::with_ws_limits(limits.clone()).await;
    let mut io = raw_authed(&h, 1).await;
    let (header, payload) = big_frame_parts();
    io.write_all(&header).await.unwrap();
    // 64 KiB every 10 s: 6.5 KB/s, above the 4 KiB/s minimum; 160 s in all,
    // longer than the 90 s idle timeout.
    let mut seen = Vec::new();
    for chunk in payload.chunks(64 << 10) {
        h.timer.advance(Duration::from_secs(10));
        io.write_all(chunk).await.unwrap();
        yields(100).await;
        seen.extend(received(&mut io).await);
    }
    tokio::time::timeout(GUARD, async {
        while !contains(&seen, b"bad_request") {
            let mut buf = [0_u8; 4096];
            let n = io.read(&mut buf).await.unwrap();
            assert!(n > 0, "closed: {:?}", String::from_utf8_lossy(&seen));
            seen.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("an answer to the uploaded frame");
    assert_eq!(timeouts(&h, "idle"), 0);
    assert_eq!(timeouts(&h, "upload"), 0);
}

#[tokio::test]
async fn a_message_trickled_below_the_minimum_rate_is_closed() {
    let limits = test_ws_limits();
    let h = Harness::with_ws_limits(limits.clone()).await;
    let mut io = raw_authed(&h, 1).await;
    let (header, payload) = big_frame_parts();
    io.write_all(&header).await.unwrap();
    // 16 KiB every 30 s: about 550 bytes a second.
    for chunk in payload.chunks(16 << 10) {
        if timeouts(&h, "upload") == 1 {
            break;
        }
        h.timer.advance(Duration::from_secs(30));
        let _ = io.write_all(chunk).await;
        yields(100).await;
        let _ = received(&mut io).await;
    }
    assert_eq!(timeouts(&h, "upload"), 1);
    assert_eq!(timeouts(&h, "idle"), 0);
}

// --- 6. Metrics a knocker can move ---------------------------------------------

#[tokio::test]
async fn a_forwarded_knock_moves_no_byte_or_frame_metric() {
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    let mut owner = h.client(1).await;
    owner.drained().await;
    let mut knocker = h.client(2).await;
    let frame = knock_frame(&knocker.mailbox, &door);
    assert_eq!(knocker.request(&frame).await["t"], "accepted");
    let bytes = metric(&h, "agentconnect_relay_drain_bytes_total");
    let frames = metric(&h, "agentconnect_relay_frames_total");
    h.relay.flush_knocks().await;
    let got = owner.deliver().await;
    assert_eq!(got["kind"], "knock");
    owner.ack(got["msg_id"].as_str().unwrap()).await;
    tokio::time::timeout(GUARD, async {
        while !queued(&h, 1).await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Neither the delivery nor the owner's ack shows.
    assert_eq!(metric(&h, "agentconnect_relay_drain_bytes_total"), bytes);
    assert_eq!(metric(&h, "agentconnect_relay_drain_bytes_loaded"), 0);
    assert_eq!(metric(&h, "agentconnect_relay_frames_total"), frames);
}

#[tokio::test]
async fn ordinary_deliveries_still_count_their_bytes() {
    let h = Harness::start().await;
    let mailbox = mailbox_of(&signing_key(1));
    let msg = NewMessage {
        msg_id: fresh_id(),
        sender: mailbox_of(&signing_key(9)),
        json: json!({"v": 0, "kind": "application", "pad": "xyz"}).to_string(),
    };
    let size = msg.json.len() as u64;
    h.relay
        .store()
        .deliver_direct(&mailbox, &msg, h.relay.limits(), h.relay.now_ms())
        .await
        .unwrap();
    let mut c = h.client(1).await;
    c.deliver().await;
    assert_eq!(metric(&h, "agentconnect_relay_drain_bytes_total"), size);
}

// --- Knock queue shares ----------------------------------------------------------

/// Knock from mailbox `n` on `door` through the relay, and hand the accepted
/// knock to the queue as coming from `src`.
async fn knock_queued(h: &Harness, n: u8, door: &str, src: SourceKey) {
    use agentconnect_relay::proto::parse_client_frame;
    let mailbox = mailbox_of(&signing_key(n));
    let frame = knock_frame(&mailbox, door).to_string();
    let frame = parse_client_frame(&frame, agentconnect_relay::DEFAULT_FRAME_MAX).unwrap();
    let (reply, knock) = h.relay.handle_deferred(&mailbox, None, frame).await;
    assert_eq!(
        serde_json::to_value(reply.unwrap()).unwrap()["t"],
        "accepted"
    );
    h.relay.queue_knock(knock.unwrap(), src);
}

#[tokio::test]
async fn one_source_holds_at_most_its_share_of_the_knock_queue() {
    use agentconnect_relay::relay::KNOCK_QUEUE_PER_SOURCE;
    let h = Harness::start().await;
    let mut doors = Vec::new();
    for owner in [1, 2] {
        for _ in 0..4 {
            doors.push((owner, open_door(&h, owner).await));
        }
    }
    let attacker = source("192.0.2.1");
    // 70 knocks from one source, at most 10 per door: all forwarded by the
    // door limits, but the source's share of the queue stops at 64.
    for i in 0..70_u8 {
        let (_, door) = &doors[usize::from(i) % doors.len()];
        knock_queued(&h, 100 + i, door, attacker).await;
    }
    // Another source still gets in.
    knock_queued(&h, 99, &doors[0].1, source("198.51.100.1")).await;
    h.relay.flush_knocks().await;
    let written = queued(&h, 1).await.len() + queued(&h, 2).await.len();
    assert_eq!(written, KNOCK_QUEUE_PER_SOURCE + 1);
}

#[tokio::test]
async fn one_door_holds_at_most_its_share_of_the_knock_queue() {
    use agentconnect_relay::relay::KNOCK_QUEUE_PER_DOOR;
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    // 10 forwarded and 6 dropped by the door's own limit fill its share.
    for n in 0..u8::try_from(KNOCK_QUEUE_PER_DOOR).unwrap() {
        knock_queued(&h, 100 + n, &door, source(&format!("192.0.2.{n}"))).await;
    }
    // A minute later the door forwards again, but its share is full until
    // the worker's next round.
    h.clock.advance(Duration::from_secs(60));
    knock_queued(&h, 200, &door, source("198.51.100.1")).await;
    h.relay.flush_knocks().await;
    assert_eq!(queued(&h, 1).await.len(), 10);
    // After the round, it has room again.
    knock_queued(&h, 201, &door, source("198.51.100.1")).await;
    h.relay.flush_knocks().await;
    assert_eq!(queued(&h, 1).await.len(), 11);
}

// --- 7. Shutdown -------------------------------------------------------------

#[tokio::test]
async fn stopping_closes_websockets_and_writes_queued_knocks() {
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    let mut c = h.client(3).await;
    c.drained().await;
    let mut knocker = h.client(2).await;
    let frame = knock_frame(&knocker.mailbox, &door);
    assert_eq!(knocker.request(&frame).await["t"], "accepted");
    assert!(queued(&h, 1).await.is_empty());
    h.relay.stop();
    loop {
        match tokio::time::timeout(GUARD, c.ws.next()).await.unwrap() {
            Some(Ok(Message::Close(Some(f)))) => {
                assert_eq!(f.code, CloseCode::Away);
                assert_eq!(f.reason.as_str(), "shutting_down");
                break;
            }
            Some(Ok(_)) => {}
            other => panic!("no close frame: {other:?}"),
        }
    }
    // The knock worker writes what it held before it ends.
    tokio::time::timeout(GUARD, async {
        while queued(&h, 1).await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the queued knock was written at stop");
}

#[tokio::test]
async fn shutdown_returns_after_the_grace_even_with_a_stalled_request() {
    let h = Harness::start().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let limits = ServerLimits::default();
    let serving = tokio::spawn(Server::new(h.relay.clone(), limits.clone()).serve(
        listener,
        async {
            let _ = stop_rx.await;
        },
    ));
    let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
    stalled
        .write_all(b"POST /v0/doors HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{")
        .await
        .unwrap();
    settle(&h, "agentconnect_relay_http_connections_open", 1).await;
    stop_tx.send(()).unwrap();
    yields(200).await;
    assert!(!serving.is_finished(), "waits for the request in flight");
    h.timer.advance(limits.shutdown_grace);
    tokio::time::timeout(GUARD, serving)
        .await
        .expect("serve returned after the grace")
        .unwrap()
        .unwrap();
}
