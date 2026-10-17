//! Shared harness: an in-process relay on a loopback port, a deterministic
//! clock and a minimal mailbox client. Nothing here sleeps; the only timer is
//! a generous guard so a hung test fails instead of blocking.

#![allow(dead_code, clippy::missing_panics_doc, clippy::must_use_candidate)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agentconnect_core::clock::FakeClock;
use agentconnect_relay::auth::{rest_auth_message, ws_auth_message};
use agentconnect_relay::proto::{b64_decode, b64_encode, mailbox_id_from_key};
use agentconnect_relay::{Limits, Relay, SqliteStore, app};
use axum::serve::ListenerExt;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use sha2::Digest;
use tokio_tungstenite::tungstenite::Message;

pub const HOST: &str = "relay.test";
const GUARD: Duration = Duration::from_secs(20);

pub struct Harness {
    pub addr: SocketAddr,
    pub relay: Arc<Relay<SqliteStore>>,
    pub clock: Arc<FakeClock>,
}

impl Harness {
    pub async fn start() -> Self {
        Self::with_limits(Limits {
            // Tests that care about the send rate set it explicitly.
            sends_per_sec: 100_000,
            ..Limits::default()
        })
        .await
    }

    pub async fn with_limits(limits: Limits) -> Self {
        Self::build(limits, None).await
    }

    pub async fn with_replay_cap(cap: usize) -> Self {
        Self::build(Limits::default(), Some(cap)).await
    }

    async fn build(limits: Limits, replay_cap: Option<usize>) -> Self {
        let clock = Arc::new(FakeClock::default());
        let store = SqliteStore::in_memory().await.unwrap();
        let mut relay = Relay::new(store, clock.clone(), HOST, limits);
        if let Some(cap) = replay_cap {
            relay = relay.with_replay_cap(cap);
        }
        let relay = Arc::new(relay);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = app(relay.clone());
        let listener = listener.tap_io(|tcp| {
            let _ = tcp.set_nodelay(true);
        });
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self { addr, relay, clock }
    }

    pub async fn client(&self, n: u8) -> Client {
        Client::connect(self.addr, signing_key(n)).await
    }

    pub fn now_secs(&self) -> u64 {
        self.relay.now_secs()
    }

    /// A timestamp inside the accepted window that differs on every call, so
    /// repeated signed requests are not replays of one another.
    pub fn ts(&self) -> u64 {
        self.now_secs() + NEXT_TS.fetch_add(1, Ordering::Relaxed) % 250
    }
}

/// Per-run key seed: `AC_TEST_SEED` when set (TESTING.md), otherwise random.
/// Keys are stable within a run (same `n`, same key) but never hard-coded.
static KEY_SEED: std::sync::LazyLock<[u8; 32]> =
    std::sync::LazyLock::new(|| match std::env::var("AC_TEST_SEED") {
        Ok(seed) => sha2::Sha256::digest(seed.as_bytes()).into(),
        Err(_) => agentconnect_relay::auth::random_bytes(),
    });

pub fn signing_key(n: u8) -> SigningKey {
    let secret: [u8; 32] = sha2::Sha256::digest([KEY_SEED.as_slice(), &[n]].concat()).into();
    SigningKey::from_bytes(&secret)
}

pub fn mailbox_of(key: &SigningKey) -> String {
    mailbox_id_from_key(key.verifying_key().as_bytes())
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_TS: AtomicU64 = AtomicU64::new(0);

/// A process-unique 16-byte id in base64url.
pub fn fresh_id() -> String {
    id_from(NEXT_ID.fetch_add(1, Ordering::Relaxed))
}

pub fn id_from(n: u64) -> String {
    let mut b = [0_u8; 16];
    b[8..].copy_from_slice(&n.to_be_bytes());
    b[0] = 0xAC;
    b64_encode(&b)
}

pub fn auth_frame(key: &SigningKey, nonce_b64: &str, host: &str) -> Value {
    let nonce = b64_decode(nonce_b64).unwrap();
    let sig = key.sign(&ws_auth_message(&nonce, host).unwrap());
    json!({
        "t": "auth",
        "sig_key": b64_encode(key.verifying_key().as_bytes()),
        "sig": b64_encode(&sig.to_bytes()),
    })
}

pub type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub async fn raw_connect(addr: SocketAddr) -> Ws {
    let (ws, _) =
        tokio_tungstenite::connect_async_with_config(format!("ws://{addr}/v0/ws"), None, true)
            .await
            .unwrap();
    ws
}

pub async fn raw_recv(ws: &mut Ws) -> Option<Value> {
    loop {
        let msg = tokio::time::timeout(GUARD, ws.next())
            .await
            .expect("timed out waiting for a frame")?;
        match msg.ok()? {
            Message::Text(t) => return Some(serde_json::from_str(t.as_str()).unwrap()),
            Message::Close(_) => return None,
            _ => {}
        }
    }
}

pub async fn raw_send(ws: &mut Ws, v: &Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

/// A connected, authenticated mailbox.
pub struct Client {
    pub ws: Ws,
    pub key: SigningKey,
    pub mailbox: String,
    delivers: VecDeque<Value>,
    replies: VecDeque<Value>,
    markers: VecDeque<Value>,
    /// `delivers.len()` when each `drained` frame arrived.
    pub drained_after: Vec<usize>,
    seen_delivers: usize,
}

impl Client {
    pub async fn connect(addr: SocketAddr, key: SigningKey) -> Self {
        let mut ws = raw_connect(addr).await;
        let challenge = raw_recv(&mut ws).await.unwrap();
        assert_eq!(challenge["t"], "challenge");
        let nonce = challenge["nonce"].as_str().unwrap();
        raw_send(&mut ws, &auth_frame(&key, nonce, HOST)).await;
        let ready = raw_recv(&mut ws).await.unwrap();
        assert_eq!(ready["t"], "ready", "{ready}");
        let mailbox = ready["mailbox_id"].as_str().unwrap().to_owned();
        assert_eq!(mailbox, mailbox_of(&key));
        Self {
            ws,
            key,
            mailbox,
            delivers: VecDeque::new(),
            replies: VecDeque::new(),
            markers: VecDeque::new(),
            drained_after: Vec::new(),
            seen_delivers: 0,
        }
    }

    pub async fn send_raw(&mut self, v: &Value) {
        raw_send(&mut self.ws, v).await;
    }

    async fn pump(&mut self) {
        let v = raw_recv(&mut self.ws).await.expect("connection closed");
        if v["t"] == "deliver" {
            self.seen_delivers += 1;
            self.delivers.push_back(v);
        } else if v["t"] == "drained" {
            self.drained_after.push(self.seen_delivers);
        } else if v["t"] == "queue_overflow" {
            self.markers.push_back(v);
        } else {
            self.replies.push_back(v);
        }
    }

    /// The next `accepted` or `error` frame.
    pub async fn reply(&mut self) -> Value {
        while self.replies.is_empty() {
            self.pump().await;
        }
        self.replies.pop_front().unwrap()
    }

    /// The next `queue_overflow` marker frame.
    pub async fn marker(&mut self) -> Value {
        while self.markers.is_empty() {
            self.pump().await;
        }
        self.markers.pop_front().unwrap()
    }

    /// Wait for the `drained` frame of this connection.
    pub async fn drained(&mut self) -> usize {
        while self.drained_after.is_empty() {
            self.pump().await;
        }
        self.drained_after[0]
    }

    /// The next `deliver` frame's envelope.
    pub async fn deliver(&mut self) -> Value {
        while self.delivers.is_empty() {
            self.pump().await;
        }
        self.delivers.pop_front().unwrap()["env"].clone()
    }

    /// `deliver` frames received but not yet taken with [`Client::deliver`].
    pub fn buffered_delivers(&self) -> usize {
        self.delivers.len()
    }

    /// Send an envelope and wait for the reply.
    pub async fn send(&mut self, env: &Value) -> Value {
        self.send_raw(&json!({"t": "send", "env": env})).await;
        self.reply().await
    }

    pub async fn ack(&mut self, msg_id: &str) {
        self.send_raw(&json!({"t": "ack", "msg_id": msg_id})).await;
    }

    /// Acknowledge, then round-trip a request so the ack is known processed.
    pub async fn ack_and_sync(&mut self, ids: &[String]) {
        for id in ids {
            self.ack(id).await;
        }
        let r = self
            .request(&json!({"t": "invite.consume", "invite_id": fresh_id()}))
            .await;
        assert_eq!(r["t"], "error");
    }

    pub async fn request(&mut self, v: &Value) -> Value {
        self.send_raw(v).await;
        self.reply().await
    }

    pub async fn group_create(&mut self, group_id: &str) -> Value {
        self.request(&json!({"t": "group.create", "group_id": group_id, "epoch": 0}))
            .await
    }

    /// Close and return only the mailbox key (to reconnect later).
    pub async fn disconnect(mut self) -> SigningKey {
        let _ = self.ws.close(None).await;
        self.key
    }

    pub fn envelope(&self, kind: &str, group_id: &str, epoch: u64) -> Value {
        envelope(kind, Some(group_id), Some(epoch), &self.mailbox)
    }
}

pub fn envelope(kind: &str, group_id: Option<&str>, epoch: Option<u64>, sender: &str) -> Value {
    let id = fresh_id();
    let mut e = json!({
        "v": 0,
        "kind": kind,
        "msg_id": id,
        "sender": sender,
        "ct": b64_encode(format!("ct-{id}").as_bytes()),
    });
    if let Some(g) = group_id {
        e["group_id"] = json!(g);
    }
    if let Some(ep) = epoch {
        e["epoch"] = json!(ep);
    }
    e
}

pub fn commit(c: &Client, group_id: &str, epoch: u64, add: &[&str], remove: &[&str]) -> Value {
    let mut e = c.envelope("commit", group_id, epoch);
    e["routing"] = json!({"add": add, "remove": remove});
    e
}

/// Create a group owned by `creator` and add every other client in one commit.
pub async fn make_group(creator: &mut Client, others: &[&Client]) -> String {
    let gid = fresh_id();
    assert_eq!(creator.group_create(&gid).await["t"], "accepted");
    if !others.is_empty() {
        let add: Vec<&str> = others.iter().map(|c| c.mailbox.as_str()).collect();
        let r = creator.send(&commit(creator, &gid, 0, &add, &[])).await;
        assert_eq!(r["t"], "accepted", "{r}");
    }
    gid
}

pub fn invite_body(
    inviter_mailbox: &str,
    invite_id: &str,
    expires_at: u64,
    max_uses: u32,
) -> Value {
    json!({
        "invite_id": invite_id,
        "group_name": "Ops",
        "inviter_name": "Alice",
        "purpose": "Coordinate deploys",
        "expires_at": expires_at,
        "max_uses": max_uses,
        "inviter_mailbox": inviter_mailbox,
        "protocol": 0,
    })
}

/// A signed REST request against the in-process router.
pub fn signed_request(
    key: &SigningKey,
    method: &str,
    path: &str,
    body: &[u8],
    ts: u64,
    host: &str,
) -> axum::http::Request<axum::body::Body> {
    let sig = key.sign(&rest_auth_message(method, path, ts, body, host).unwrap());
    let auth = format!(
        "AgentConnect-Ed25519 {}.{ts}.{}",
        b64_encode(key.verifying_key().as_bytes()),
        b64_encode(&sig.to_bytes())
    );
    axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", auth)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_vec()))
        .unwrap()
}
