//! Connection limits and deadlines (SR-06, SR-13, SR-05's frame rate): the
//! connection caps, byte-capped drains, stalled sends, pings and the idle
//! timeout, the header and auth timeouts, and the per-connection frame rate.
//! Deadlines run on the harness's manual timer, so nothing here waits for
//! real time.

mod common;

use std::time::Duration;

use agentconnect_relay::WsLimits;
use agentconnect_relay::store::{NewMessage, Store};
use common::{
    Client, HOST, Harness, auth_frame, fresh_id, mailbox_of, raw_connect, raw_recv, signing_key,
    test_ws_limits,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const GUARD: Duration = Duration::from_secs(20);
/// The knock worker always waits on its next tick: one standing sleep.
const KNOCK_WORKER: usize = 1;

/// The value of one metric line (`name` with its labels, if any).
fn metric(h: &Harness, name: &str) -> u64 {
    let text = h.relay.metrics().render();
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no metric {name} in\n{text}"))
        .parse()
        .unwrap()
}

/// Yield until a metric reaches `want` (the server works on its own tasks).
async fn settle(h: &Harness, name: &str, want: u64) {
    tokio::time::timeout(GUARD, async {
        while metric(h, name) != want {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{name} stuck at {}, wanted {want}", metric(h, name)));
}

/// Queue `n` messages of about `size` bytes for `mailbox`, straight into the
/// store; returns their ids in order.
async fn fill(h: &Harness, mailbox: &str, n: usize, size: usize) -> Vec<String> {
    let mut ids = Vec::new();
    for _ in 0..n {
        let id = fresh_id();
        let msg = NewMessage {
            msg_id: id.clone(),
            sender: mailbox_of(&signing_key(200)),
            json: json!({"msg_id": id, "pad": "x".repeat(size)}).to_string(),
        };
        h.relay
            .store()
            .deliver_direct(mailbox, &msg, h.relay.limits(), h.relay.now_ms())
            .await
            .unwrap();
        ids.push(id);
    }
    ids
}

type Duplex = WebSocketStream<DuplexStream>;

async fn duplex_ws(
    h: &Harness,
    buffer: usize,
    source: agentconnect_relay::conn::SourceKey,
) -> Duplex {
    let io = h.duplex_from(buffer, source);
    let (ws, _) = tokio_tungstenite::client_async(format!("ws://{HOST}/v0/ws"), io)
        .await
        .unwrap();
    ws
}

/// Upgrade from `source`, authenticate as key `n` and read up to `drained`.
async fn duplex_authed(h: &Harness, source: agentconnect_relay::conn::SourceKey, n: u8) -> Duplex {
    let mut ws = duplex_ws(h, 1 << 16, source).await;
    assert_eq!(authenticate(&mut ws, n).await["t"], "ready");
    while next_json(&mut ws).await["t"] != "drained" {}
    ws
}

async fn next_json<S>(ws: &mut WebSocketStream<S>) -> Value
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let msg = tokio::time::timeout(GUARD, ws.next())
            .await
            .expect("timed out waiting for a frame")
            .expect("connection ended")
            .unwrap();
        if let Message::Text(t) = msg {
            return serde_json::from_str(t.as_str()).unwrap();
        }
    }
}

/// Authenticate as key `n` and read `ready`.
async fn authenticate<S>(ws: &mut WebSocketStream<S>, n: u8) -> Value
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let challenge = next_json(ws).await;
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    let auth = auth_frame(&signing_key(n), &nonce, HOST);
    ws.send(Message::text(auth.to_string())).await.unwrap();
    next_json(ws).await
}

/// The close frame that ends the connection, skipping anything before it.
async fn close_frame(ws: &mut common::Ws) -> (CloseCode, String) {
    loop {
        let msg = tokio::time::timeout(GUARD, ws.next())
            .await
            .expect("timed out waiting for the close");
        match msg {
            Some(Ok(Message::Close(Some(f)))) => return (f.code, f.reason.to_string()),
            Some(Ok(_)) => {}
            other => panic!("ended without a close frame: {other:?}"),
        }
    }
}

#[tokio::test]
async fn at_the_total_cap_the_source_holding_the_most_makes_room() {
    // Many sources filling the total with free mailboxes: a newcomer from
    // another source takes the place of the oldest connection of the
    // source holding the most; a newcomer from that source is refused.
    let h = Harness::with_ws_limits(WsLimits {
        max_connections: 4,
        ..test_ws_limits()
    })
    .await;
    let src =
        |ip: &str| agentconnect_relay::conn::SourceKey::of(ip.parse::<std::net::IpAddr>().unwrap());
    let (a, b, c) = (src("192.0.2.1"), src("192.0.2.2"), src("198.51.100.1"));
    let mut a1 = duplex_authed(&h, a, 1).await;
    let _a2 = duplex_authed(&h, a, 2).await;
    let _a3 = duplex_authed(&h, a, 3).await;
    let _b1 = duplex_authed(&h, b, 4).await;
    // c is honest and new: a's oldest goes.
    let _c1 = duplex_authed(&h, c, 5).await;
    loop {
        match tokio::time::timeout(GUARD, a1.next()).await.unwrap() {
            Some(Ok(Message::Close(Some(f)))) => {
                assert_eq!(f.code, CloseCode::Again);
                assert_eq!(f.reason.as_str(), "relay_full");
                break;
            }
            Some(Ok(_)) => {}
            other => panic!("no close frame: {other:?}"),
        }
    }
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connections_evicted_total{cap=\"ws\"}"
        ),
        1
    );
    // a still holds the most; one more from a is refused, not let in at
    // someone else's expense.
    let mut ws = duplex_ws(&h, 1 << 16, a).await;
    let challenge = next_json(&mut ws).await;
    let auth = auth_frame(&signing_key(6), challenge["nonce"].as_str().unwrap(), HOST);
    ws.send(Message::text(auth.to_string())).await.unwrap();
    let e = next_json(&mut ws).await;
    assert_eq!(e["code"], "rate_limited");
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connections_refused_total{reason=\"total\"}"
        ),
        1
    );
}

#[tokio::test]
async fn a_new_connection_past_the_mailbox_cap_replaces_the_oldest() {
    // Finding 9: a daemon whose link flaps leaves half-open connections
    // behind. Four flaps fill the cap; the next connection, the one known to
    // be alive, takes the oldest one's place instead of being refused.
    let h = Harness::with_ws_limits(WsLimits {
        max_per_mailbox: 4,
        ..test_ws_limits()
    })
    .await;
    let mut zombies = Vec::new();
    for _ in 0..4 {
        let mut c = h.client(1).await;
        c.drained().await;
        zombies.push(c);
    }
    let mut live = h.client(1).await;
    live.drained().await;
    let (code, reason) = close_frame(&mut zombies[0].ws).await;
    assert_eq!(code, CloseCode::Normal);
    assert_eq!(reason, "replaced");
    assert_eq!(
        metric(&h, "agentconnect_relay_connections_replaced_total"),
        1
    );
    // The new connection works, and gets what is queued for the mailbox.
    assert_eq!(live.group_create(&fresh_id()).await["t"], "accepted");
    let ids = fill(&h, &mailbox_of(&signing_key(1)), 1, 10).await;
    h.relay.flush_knocks().await;
    let mut more = h.client(1).await;
    assert_eq!(more.deliver().await["msg_id"], ids[0]);
    let (_, reason) = close_frame(&mut zombies[1].ws).await;
    assert_eq!(reason, "replaced");
    // Other mailboxes are unaffected.
    let _other = h.client(2).await;
    assert_eq!(
        metric(&h, "agentconnect_relay_connections_replaced_total"),
        2
    );
}

#[tokio::test]
async fn the_drain_sends_the_whole_queue_in_byte_capped_batches() {
    let h = Harness::with_ws_limits(WsLimits {
        drain_batch_bytes: 3000,
        ..test_ws_limits()
    })
    .await;
    let mailbox = mailbox_of(&signing_key(1));
    let ids = fill(&h, &mailbox, 40, 1000).await;
    let mut c = h.client(1).await;
    let mut got = Vec::new();
    for _ in &ids {
        got.push(c.deliver().await["msg_id"].as_str().unwrap().to_owned());
    }
    assert_eq!(got, ids);
    assert_eq!(c.drained().await, ids.len());
    let stored: u64 = h
        .relay
        .store()
        .pending(&mailbox, 0, 1000, u64::MAX, h.relay.now_ms())
        .await
        .unwrap()
        .iter()
        .map(|m| m.json.len() as u64)
        .sum();
    assert_eq!(metric(&h, "agentconnect_relay_drain_bytes_total"), stored);
    assert_eq!(metric(&h, "agentconnect_relay_drain_bytes_loaded"), 0);
}

#[tokio::test]
async fn a_reader_that_stalls_holds_one_batch_and_is_dropped_after_the_send_timeout() {
    let cap = 250_000;
    let limits = WsLimits {
        drain_batch_bytes: cap,
        send_timeout: Duration::from_secs(30),
        ..test_ws_limits()
    };
    let h = Harness::with_ws_limits(limits.clone()).await;
    let mailbox = mailbox_of(&signing_key(1));
    let ids = fill(&h, &mailbox, 40, 100_000).await;

    // 64 KiB in flight, then the client stops reading.
    let mut slow = duplex_ws(&h, 64 << 10, agentconnect_relay::conn::SourceKey::unknown()).await;
    assert_eq!(authenticate(&mut slow, 1).await["t"], "ready");
    // The relay loads a batch and blocks sending it.
    tokio::time::timeout(GUARD, async {
        while metric(&h, "agentconnect_relay_drain_bytes_loaded") == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("no batch loaded");
    let loaded = metric(&h, "agentconnect_relay_drain_bytes_loaded");
    assert!(loaded <= cap, "{loaded} bytes loaded");

    // The send's deadline may not be set yet (and a sleep from the
    // handshake may still be counted), so keep moving time until the
    // stalled send gives up. Each step is one send timeout.
    tokio::time::timeout(GUARD, async {
        while metric(&h, "agentconnect_relay_ws_connections_open") != 0 {
            if h.timer.sleepers() <= KNOCK_WORKER {
                tokio::task::yield_now().await;
                continue;
            }
            h.timer.advance(limits.send_timeout);
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
        }
    })
    .await
    .expect("the stalled connection stayed open");
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connection_timeouts_total{kind=\"send\"}"
        ),
        1
    );
    assert_eq!(metric(&h, "agentconnect_relay_drain_bytes_loaded"), 0);
    drop(slow);

    // Nothing was acked: a client that reads gets the whole queue.
    let mut c = Client::connect(h.addr, signing_key(1)).await;
    for id in &ids {
        assert_eq!(c.deliver().await["msg_id"], *id);
    }
}

#[tokio::test]
async fn a_silent_client_is_closed_after_the_idle_timeout() {
    let limits = WsLimits {
        ping_interval: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(25),
        ..test_ws_limits()
    };
    let h = Harness::with_ws_limits(limits.clone()).await;
    let mut c = h.client(1).await;
    c.drained().await;
    h.timer.advance(limits.idle_timeout);
    let (code, reason) = close_frame(&mut c.ws).await;
    assert_eq!(code, CloseCode::Away);
    assert_eq!(reason, "idle_timeout");
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connection_timeouts_total{kind=\"idle\"}"
        ),
        1
    );
    settle(&h, "agentconnect_relay_ws_connections_open", 0).await;
}

#[tokio::test]
async fn a_client_that_answers_pings_stays_connected() {
    let limits = WsLimits {
        ping_interval: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(25),
        ..test_ws_limits()
    };
    let h = Harness::with_ws_limits(limits.clone()).await;
    let mut c = h.client(1).await;
    c.drained().await;
    for _ in 0..5 {
        h.timer.advance(limits.ping_interval);
        // Read up to the ping; tungstenite queues the pong, which goes out
        // ahead of the next frame. The reply to that frame means the relay
        // has read the pong too.
        loop {
            let msg = tokio::time::timeout(GUARD, c.ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if matches!(msg, Message::Ping(_)) {
                break;
            }
        }
        let r = c.group_create(&fresh_id()).await;
        assert_eq!(r["t"], "accepted", "{r}");
    }
    // 50 s on the relay's clock, twice the idle timeout, and still open.
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connection_timeouts_total{kind=\"idle\"}"
        ),
        0
    );
    assert_eq!(metric(&h, "agentconnect_relay_ws_connections_open"), 1);
}

#[tokio::test]
async fn an_unanswered_challenge_times_out() {
    let h = Harness::start().await;
    let mut ws = raw_connect(h.addr).await;
    assert_eq!(raw_recv(&mut ws).await.unwrap()["t"], "challenge");
    h.timer.advance(Duration::from_secs(10));
    let e = raw_recv(&mut ws).await.unwrap();
    assert_eq!(e["code"], "auth_failed");
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connection_timeouts_total{kind=\"auth\"}"
        ),
        1
    );
    assert_eq!(metric(&h, "agentconnect_relay_auth_failures_total"), 1);
    settle(&h, "agentconnect_relay_ws_connections_open", 0).await;
}

#[tokio::test]
async fn unfinished_request_headers_time_out() {
    let h = Harness::start().await;
    // A complete request on the same kind of connection is served.
    let mut ok = h.duplex(4096);
    ok.write_all(b"GET /healthz HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    ok.read_to_end(&mut answer).await.unwrap();
    assert!(
        answer.starts_with(b"HTTP/1.1 200"),
        "no 200 answer ({} bytes)",
        answer.len()
    );
    settle(&h, "agentconnect_relay_http_connections_open", 0).await;

    let mut slow = h.duplex(4096);
    slow.write_all(b"GET /healthz HTTP/1.1\r\nHost: relay.test\r\n")
        .await
        .unwrap();
    h.timer.until_sleepers(KNOCK_WORKER + 1).await;
    assert_eq!(metric(&h, "agentconnect_relay_http_connections_open"), 1);
    h.timer.advance(Duration::from_secs(10));
    let mut rest = Vec::new();
    tokio::time::timeout(GUARD, slow.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(!rest.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connection_timeouts_total{kind=\"header\"}"
        ),
        1
    );
    settle(&h, "agentconnect_relay_http_connections_open", 0).await;
}

#[tokio::test]
async fn frames_over_the_rate_are_refused_with_their_msg_id() {
    let h = Harness::with_ws_limits(WsLimits {
        frames_per_sec: 10,
        frame_burst: 5,
        ..test_ws_limits()
    })
    .await;
    let mut c = h.client(1).await;
    c.drained().await;
    for _ in 0..5 {
        assert_eq!(c.group_create(&fresh_id()).await["t"], "accepted");
    }
    // Time doesn't move, so the bucket is empty now.
    let id = fresh_id();
    let r = c
        .request(&json!({"t": "group.create", "group_id": id, "epoch": 0, "msg_id": "over"}))
        .await;
    assert_eq!(r["t"], "error");
    assert_eq!(r["code"], "rate_limited");
    assert_eq!(r["msg_id"], "over");
    // A malformed or binary frame over the rate is refused the same way.
    c.send_raw(&json!({"t": "nonsense"})).await;
    assert_eq!(c.reply().await["code"], "rate_limited");
    c.ws.send(Message::binary(vec![1, 2, 3])).await.unwrap();
    assert_eq!(c.reply().await["code"], "rate_limited");
    assert_eq!(
        metric(&h, "agentconnect_relay_frames_rate_limited_total"),
        3
    );
    // The refused group.create did nothing.
    h.timer.advance(Duration::from_secs(1));
    assert_eq!(c.group_create(&id).await["t"], "accepted");
}

#[tokio::test]
async fn acks_over_the_rate_wait_for_a_token_instead_of_being_dropped() {
    let h = Harness::with_ws_limits(WsLimits {
        frames_per_sec: 10,
        frame_burst: 2,
        ..test_ws_limits()
    })
    .await;
    let mailbox = mailbox_of(&signing_key(1));
    let ids = fill(&h, &mailbox, 3, 10).await;
    let mut c = h.client(1).await;
    for id in &ids {
        assert_eq!(c.deliver().await["msg_id"], *id);
    }
    c.drained().await;
    for id in &ids {
        c.ack(id).await;
    }
    // Two acks fit the burst; the third waits for its token. While it
    // waits, the connection's only deadline is that token.
    settle(&h, "agentconnect_relay_frames_rate_limited_total", 1).await;
    h.timer.until_sleepers(KNOCK_WORKER + 1).await;
    let left = h
        .relay
        .store()
        .pending(&mailbox, 0, 10, u64::MAX, h.relay.now_ms())
        .await
        .unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].msg_id, ids[2]);
    assert_eq!(
        metric(&h, "agentconnect_relay_frames_rate_limited_total"),
        1
    );
    h.timer.advance(Duration::from_secs(1));
    // A request after the ack: its reply means the ack went through.
    assert_eq!(c.group_create(&fresh_id()).await["t"], "accepted");
    assert!(
        h.relay
            .store()
            .pending(&mailbox, 0, 10, u64::MAX, h.relay.now_ms())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn new_metrics_carry_no_identifiers() {
    let h = Harness::start().await;
    let _c = h.client(1).await;
    let text = h.relay.metrics().render();
    for name in [
        "agentconnect_relay_connections_refused_total",
        "agentconnect_relay_connection_timeouts_total",
        "agentconnect_relay_frames_rate_limited_total",
        "agentconnect_relay_drain_bytes_total",
        "agentconnect_relay_drain_bytes_loaded",
        "agentconnect_relay_http_connections_open",
        "agentconnect_relay_connections_evicted_total",
    ] {
        assert!(text.contains(&format!("# TYPE {name} ")), "{name}");
    }
    let labels: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#') && l.contains('{'))
        .collect();
    for l in labels {
        assert!(
            l.contains("{code=\"")
                || l.contains("{reason=\"")
                || l.contains("{kind=\"")
                || l.contains("{cap=\""),
            "{l}"
        );
    }
    assert!(!text.contains(&mailbox_of(&signing_key(1))));
    assert!(!text.contains("127.0.0.1"));
}

#[tokio::test]
async fn at_the_accept_limit_a_new_connection_closes_the_oldest_stalled_one() {
    use agentconnect_relay::{Server, ServerLimits};
    let h = Harness::start().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Server::new(
        h.relay.clone(),
        ServerLimits {
            max_http_connections: 1,
            ..ServerLimits::default()
        },
    );
    tokio::spawn(server.serve(listener, std::future::pending()));

    // The first connection holds the only slot with half a request.
    let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
    first.write_all(b"GET /healthz HTTP/1.1\r\n").await.unwrap();
    settle(&h, "agentconnect_relay_http_connections_open", 1).await;

    // Accepting never pauses: the newcomer is served, and the stalled
    // connection makes room.
    let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
    second
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(GUARD, second.read_to_end(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert!(
        answer.starts_with(b"HTTP/1.1 200"),
        "no 200 answer ({} bytes)",
        answer.len()
    );
    let mut rest = Vec::new();
    tokio::time::timeout(GUARD, first.read_to_end(&mut rest))
        .await
        .expect("the stalled connection was closed")
        .unwrap();
    assert_eq!(
        metric(
            &h,
            "agentconnect_relay_connections_evicted_total{cap=\"http\"}"
        ),
        1
    );
}
