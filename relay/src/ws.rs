//! WebSocket endpoint `/v0/ws` (SPEC §8.2).
//!
//! One task per connection. Connections are capped per source, while they
//! authenticate, in total and per mailbox. Every send to the client has a
//! deadline, the client is pinged and closed when it neither sends messages
//! nor answers pings, a message being received must keep arriving at a
//! minimum rate, its frames pass token buckets, the queue is sent in batches
//! capped by bytes, and what clients have read but not finished counts
//! against a relay-wide budget. So a client that stops reading holds at most
//! one batch and one write buffer, and one that stops sending holds what the
//! read budget allows, and only for a while.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Extension;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio::sync::{Notify, watch};

use crate::auth::{random_bytes, verify_ws_auth};
use crate::conn::{ConnCtx, Rx, SourceKey, SourceSlot, ws_wire_len};
use crate::proto::{ClientFrame, ErrorCode, ServerFrame, b64_encode, parse_client_frame};
use crate::relay::{ConnRefusal, Eviction, Relay, RelayError, Timeout, WsOpenGuard};
use crate::store::{DEFAULT_FRAME_MAX, Store};
use crate::timer::Timer;

/// Messages sent to a connection per storage round trip, at most.
const BATCH: u32 = 256;
/// How far a WebSocket message may go past the protocol frame limit
/// (`Limits::frame_max`) and still get a `too_large` error; a larger one
/// closes the connection.
const MESSAGE_SLACK: usize = 64 << 10;
/// Bytes the WebSocket buffers before writing to the socket.
const WRITE_BUFFER: usize = 128 << 10;
/// Bytes read past the last whole message above which the client counts as
/// sending a message (control frames are smaller).
const ASSEMBLING: u64 = 1024;
/// Frames up to this size are read to see whether they are acks (an ack
/// frame is well under it).
const SMALL_FRAME: usize = 256;
/// How long the relay tries to send the close frame of a connection it
/// ends.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
/// Close codes (RFC 6455 §7.4.1).
const CLOSE_NORMAL: u16 = 1000;
const CLOSE_GOING_AWAY: u16 = 1001;
const CLOSE_POLICY: u16 = 1008;
const CLOSE_TOO_BIG: u16 = 1009;
const CLOSE_TRY_AGAIN: u16 = 1013;

/// Connection limits for the WebSocket endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsLimits {
    /// Authenticated connections at once. Past it an upgrade gets HTTP 503,
    /// and a connection that authenticates gets `rate_limited` and is closed.
    pub max_connections: usize,
    /// Connections waiting to authenticate, at once. Past it an upgrade gets
    /// HTTP 503.
    pub max_unauthenticated: usize,
    /// Connections one source (an IPv4 address or an IPv6 /64) may hold,
    /// authenticated or not. Past it an upgrade gets HTTP 503.
    pub max_per_source: usize,
    /// Authenticated connections per mailbox. Past it the mailbox's oldest
    /// connection is closed to make room for the new one.
    pub max_per_mailbox: usize,
    /// How long a client has to answer the challenge.
    pub auth_timeout: Duration,
    /// Most bytes of queued envelopes loaded per batch (at least one
    /// message is always loaded).
    pub drain_batch_bytes: u64,
    /// How long one send to a client may take before the connection is
    /// dropped.
    pub send_timeout: Duration,
    /// How often the relay pings a client.
    pub ping_interval: Duration,
    /// How long a client may send no message and answer no ping before the
    /// connection is closed.
    pub idle_timeout: Duration,
    /// While a client sends a message, the slowest it may send, in bytes per
    /// second over each idle timeout.
    pub min_upload_rate: u64,
    /// Relay-wide bytes read from clients and not yet handed on as whole
    /// messages. Past it, the connections holding the most are closed.
    pub read_buffer_bytes: u64,
    /// Sustained client frames per second, per connection.
    pub frames_per_sec: u32,
    /// Frames a connection may send at once above the sustained rate.
    pub frame_burst: u32,
}

impl Default for WsLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_unauthenticated: 128,
            max_per_source: 32,
            max_per_mailbox: 4,
            auth_timeout: Duration::from_secs(5),
            drain_batch_bytes: 4 << 20,
            send_timeout: Duration::from_secs(30),
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            min_upload_rate: 4 << 10,
            read_buffer_bytes: 128 << 20,
            frames_per_sec: 100,
            frame_burst: 200,
        }
    }
}

fn refuse(detail: &str) -> Response {
    let body = serde_json::json!({
        "code": ErrorCode::RateLimited.as_str(),
        "detail": detail,
    });
    (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response()
}

/// Who is on the other end: the client's address and its source.
#[derive(Debug, Clone, Copy)]
struct Client {
    ip: Option<IpAddr>,
    source: SourceKey,
}

/// What a connection holds until it ends.
struct Slots {
    _open: WsOpenGuard,
    _source: SourceSlot,
    unauth: Option<WsOpenGuard>,
}

/// Upgrade handler.
pub async fn ws_handler<S: Store>(
    State(relay): State<Arc<Relay<S>>>,
    ctx: Option<Extension<ConnCtx>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let limits = relay.ws_limits();
    let metrics = relay.metrics();
    let ctx = ctx.map_or_else(
        || ConnCtx {
            source: SourceKey::unknown(),
            rx: relay.read_budget().counter(SourceKey::unknown()),
        },
        |Extension(ctx)| ctx,
    );
    // The client address: the peer, or what a trusted proxy reports
    // (`AC_RELAY_CLIENT_IP_HEADER`). It feeds `group.create`'s per-address
    // limit, and its /64 (`quota::address_key`) is the source every
    // per-source WebSocket limit counts by. Never logged.
    let ip = relay.client_ip(peer.map(|c| c.0.0.ip()), &headers);
    let from = match ip {
        Some(ip) => SourceKey::of(ip),
        None => ctx.source,
    };
    let Some(source) = relay.ws_sources().take(from, limits.max_per_source) else {
        metrics.refused(ConnRefusal::Source);
        return refuse("too many connections from this address");
    };
    let Some(unauth) = metrics.try_ws_unauth(limits.max_unauthenticated) else {
        metrics.refused(ConnRefusal::Unauthenticated);
        return refuse("too many connections");
    };
    let Some(open) = metrics.try_ws_open(usize::MAX) else {
        return refuse("too many connections");
    };
    let slots = Slots {
        _open: open,
        _source: source,
        unauth: Some(unauth),
    };
    let cap = relay.limits().frame_max.max(DEFAULT_FRAME_MAX) + MESSAGE_SLACK;
    let rx = ctx.rx;
    ws.max_message_size(cap)
        .max_frame_size(cap)
        .write_buffer_size(WRITE_BUFFER)
        .max_write_buffer_size(cap + WRITE_BUFFER)
        .on_upgrade(move |socket| session(relay, socket, slots, rx, Client { ip, source: from }))
}

/// A token bucket in its GCRA form: `tat` is when the bucket would be full
/// again. A frame is allowed while `tat` is at most `tolerance` ahead.
#[derive(Debug)]
struct Bucket {
    tat: Instant,
    interval: Duration,
    tolerance: Duration,
}

impl Bucket {
    fn new(limits: &WsLimits, now: Instant) -> Self {
        let interval = Duration::from_secs(1) / limits.frames_per_sec.max(1);
        Self {
            tat: now,
            interval,
            tolerance: interval * limits.frame_burst.saturating_sub(1),
        }
    }

    /// Take a token, or say when one will be there.
    fn take(&mut self, now: Instant) -> Result<(), Instant> {
        let tat = self.tat.max(now);
        let allowed_at = tat.checked_sub(self.tolerance).unwrap_or(now);
        if allowed_at <= now {
            self.tat = tat + self.interval;
            Ok(())
        } else {
            Err(allowed_at)
        }
    }
}

/// The few fields of a frame its `rate_limited` answer needs, read without
/// the full parse (`ct` is skipped, not decoded or checked).
#[derive(Deserialize)]
struct Peek<'a> {
    #[serde(borrow, default)]
    t: Option<Cow<'a, str>>,
    #[serde(default)]
    msg_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    invite_id: Option<String>,
    #[serde(default)]
    env: Option<PeekEnv>,
}

#[derive(Deserialize)]
struct PeekEnv {
    #[serde(default)]
    msg_id: Option<String>,
}

/// Whether `text` is an ack, and the `msg_id` its answer would carry
/// (SPEC §8.2), as far as a light read can tell.
fn peek(text: &str) -> (bool, Option<String>) {
    let Ok(p) = serde_json::from_str::<Peek<'_>>(text) else {
        return (false, None);
    };
    match p.t.as_deref() {
        Some("ack") => (true, None),
        Some("send" | "join" | "knock") => (false, p.env.and_then(|e| e.msg_id)),
        Some("group.create") => (false, p.msg_id.or(p.group_id)),
        Some("invite.consume") => (false, p.msg_id.or(p.invite_id)),
        _ => (false, None),
    }
}

/// True for a stored knock envelope (the relay writes envelopes with `v`
/// and `kind` first). Knock deliveries stay out of the byte metrics, which
/// would otherwise tell a forwarded knock from a dropped one (SPEC §8.3).
fn is_knock(json: &str) -> bool {
    json.starts_with(r#"{"v":0,"kind":"knock""#)
}

/// What to do after handling something.
#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

/// A message the client is in the middle of sending.
#[derive(Debug)]
struct Upload {
    started: Instant,
    window_start: Instant,
    read_at_window: u64,
}

/// One connection.
struct Conn<'r, S: Store> {
    relay: &'r Arc<Relay<S>>,
    limits: &'r WsLimits,
    timer: &'r Timer,
    socket: WebSocket,
    rx: Arc<Rx>,
    stop: watch::Receiver<bool>,
    mailbox: String,
    /// The client's address, for `group.create`'s per-address limit.
    ip: Option<IpAddr>,
    source: SourceKey,
    /// Fires when a connection from another source took this one's place at
    /// the total cap.
    kick: Arc<Notify>,
    last_seq: i64,
    /// When the client last sent a whole message or answered a ping.
    last_activity: Instant,
    /// When to check that the client is alive (idle, or sending fast enough).
    check_at: Instant,
    upload: Option<Upload>,
    next_ping: Instant,
    pings: u64,
    /// The payload of the ping waiting for its pong.
    outstanding: Option<[u8; 8]>,
    /// The close frame to send once the session has unwound.
    closing: Option<(u16, &'static str)>,
    /// Frames that get a reply, malformed ones and control frames: refused
    /// over the rate.
    requests: Bucket,
    /// Acks: delayed over the rate, so they never use up the requests'
    /// tokens and are never refused.
    acks: Bucket,
}

/// True if `notify` holds a stored wake-up (and takes it), without waiting.
async fn fired(notify: &Notify) -> bool {
    tokio::select! {
        biased;
        () = notify.notified() => true,
        () = std::future::ready(()) => false,
    }
}

impl<'r, S: Store> Conn<'r, S> {
    fn new(relay: &'r Arc<Relay<S>>, socket: WebSocket, rx: Arc<Rx>, client: Client) -> Self {
        let limits = relay.ws_limits();
        let timer = relay.timer();
        let now = timer.now();
        Self {
            relay,
            limits,
            timer,
            socket,
            rx,
            stop: relay.stopping(),
            mailbox: String::new(),
            ip: client.ip,
            source: client.source,
            kick: Arc::new(Notify::new()),
            last_seq: 0,
            last_activity: now,
            check_at: now + limits.idle_timeout,
            upload: None,
            next_ping: now + limits.ping_interval,
            pings: 0,
            outstanding: None,
            closing: None,
            requests: Bucket::new(limits, now),
            acks: Bucket::new(limits, now),
        }
    }

    /// Send one message; `false` if the connection is gone or the client
    /// didn't take it within the send timeout.
    async fn send(&mut self, msg: Message) -> bool {
        let sent = self
            .timer
            .timeout(self.limits.send_timeout, self.socket.send(msg))
            .await;
        if let Some(r) = sent {
            r.is_ok()
        } else {
            self.relay.metrics().timeout(Timeout::Send);
            tracing::debug!(reason = "send_timeout", "connection dropped");
            false
        }
    }

    async fn send_frame(&mut self, frame: &ServerFrame) -> bool {
        self.send(Message::text(frame.to_json())).await
    }

    async fn close(&mut self, code: u16, reason: &str) {
        let _ = self
            .send(Message::Close(Some(CloseFrame {
                code,
                reason: reason.into(),
            })))
            .await;
    }

    /// Run the challenge/response handshake; returns the authenticated
    /// mailbox.
    async fn authenticate(&mut self) -> Option<String> {
        let deadline = self.timer.now() + self.limits.auth_timeout;
        let nonce = random_bytes::<32>();
        let challenge = ServerFrame::Challenge {
            nonce: b64_encode(&nonce),
        };
        if !self.send_frame(&challenge).await {
            return None;
        }
        let first = tokio::select! {
            biased;
            m = self.socket.recv() => Some(m),
            () = self.timer.sleep_until(deadline) => None,
            () = self.rx.evict.notified() => Some(None),
        };
        let mailbox = match first {
            Some(Some(Ok(Message::Text(text)))) => {
                self.rx.consumed(ws_wire_len(text.len()));
                match parse_client_frame(text.as_str(), self.relay.limits().frame_max) {
                    Ok(ClientFrame::Auth { sig_key, sig }) => {
                        verify_ws_auth(&nonce, self.relay.host(), &sig_key, &sig)
                    }
                    _ => None,
                }
            }
            None => {
                self.relay.metrics().timeout(Timeout::Auth);
                None
            }
            _ => None,
        };
        if mailbox.is_none() {
            self.relay.metrics().auth_failure();
            let e = self.relay.error_frame(
                None,
                RelayError::new(ErrorCode::AuthFailed, "authentication failed"),
            );
            let _ = self.send_frame(&e).await;
            self.close(CLOSE_POLICY, "auth_failed").await;
        }
        mailbox
    }

    /// Send every queued message after `last_seq`, oldest first, one batch
    /// (at most [`BATCH`] messages and `drain_batch_bytes`) at a time.
    async fn flush(&mut self, registration: &crate::relay::Registration) -> bool {
        let cap = self.limits.drain_batch_bytes;
        // A batch cut short by the byte cap holds more than `cap` minus one
        // message (a frame at most); a smaller one means the queue is empty.
        let frame_max = u64::try_from(self.relay.limits().frame_max).unwrap_or(u64::MAX);
        let near_cap = cap.saturating_sub(frame_max);
        let len = |m: &crate::store::StoredMessage| u64::try_from(m.json.len()).unwrap_or(u64::MAX);
        loop {
            let batch = match self
                .relay
                .pending(&self.mailbox, self.last_seq, BATCH, cap)
                .await
            {
                Ok(b) => b,
                Err(e) => {
                    let f = self.relay.error_frame(None, e);
                    let _ = self.send_frame(&f).await;
                    return false;
                }
            };
            let count = batch.len();
            let bytes: u64 = batch.iter().map(len).sum();
            let counted: u64 = batch.iter().filter(|m| !is_knock(&m.json)).map(len).sum();
            let relay = self.relay;
            let mut loaded = relay.metrics().drain_loaded(counted);
            for m in batch {
                if self.between_messages(registration).await == Flow::Stop {
                    return false;
                }
                let size = len(&m);
                let knock = is_knock(&m.json);
                // The stored envelope JSON is forwarded verbatim; it is never
                // inspected or logged.
                let text = if m.marker {
                    m.json
                } else {
                    format!(r#"{{"t":"deliver","env":{}}}"#, m.json)
                };
                if !self.send(Message::text(text)).await {
                    return false;
                }
                if !knock {
                    loaded.sent(size);
                }
                self.last_seq = m.seq;
            }
            if count < BATCH as usize && bytes <= near_cap {
                return true;
            }
        }
    }

    /// Between two messages of a batch: handle a frame the client already
    /// sent (so pings are answered and acks keep up during a long drain),
    /// and do what the run loop would: notice a replacement, the read budget
    /// or a stop, check liveness and ping.
    async fn between_messages(&mut self, registration: &crate::relay::Registration) -> Flow {
        let ready = tokio::select! {
            biased;
            m = self.socket.recv() => Some(m),
            () = std::future::ready(()) => None,
        };
        if let Some(m) = ready
            && self.on_message(m).await == Flow::Stop
        {
            return Flow::Stop;
        }
        if fired(&registration.replaced).await {
            return self.replaced();
        }
        if fired(&self.kick).await {
            return self.evicted();
        }
        if fired(&self.rx.evict).await {
            return self.shed();
        }
        if *self.stop.borrow() {
            return self.stopping();
        }
        let now = self.timer.now();
        if now >= self.check_at && self.check_alive() == Flow::Stop {
            return Flow::Stop;
        }
        if now >= self.next_ping {
            return self.ping().await;
        }
        Flow::Continue
    }

    async fn ping(&mut self) -> Flow {
        self.next_ping = self.timer.now() + self.limits.ping_interval;
        self.pings += 1;
        let payload = self.pings.to_be_bytes();
        self.outstanding = Some(payload);
        let msg = Message::Ping(axum::body::Bytes::copy_from_slice(&payload));
        if self.send(msg).await {
            Flow::Continue
        } else {
            Flow::Stop
        }
    }

    /// The client sent a whole message or answered a ping.
    fn active(&mut self) {
        let now = self.timer.now();
        self.last_activity = now;
        self.upload = None;
        self.check_at = now + self.limits.idle_timeout;
    }

    /// Is the client alive? Idle unless it sends messages or answers pings;
    /// while it is in the middle of a message, that message must keep
    /// arriving at the minimum rate and be done by the assembly deadline.
    fn check_alive(&mut self) -> Flow {
        let now = self.timer.now();
        let window = self.limits.idle_timeout;
        if self.rx.pending() > ASSEMBLING {
            let read = self.rx.read();
            let Some(up) = &mut self.upload else {
                self.upload = Some(Upload {
                    started: now,
                    window_start: now,
                    read_at_window: read,
                });
                self.check_at = now + window;
                return Flow::Continue;
            };
            let secs = now.saturating_duration_since(up.window_start).as_secs();
            let needed = self.limits.min_upload_rate.saturating_mul(secs);
            let frame_max = u64::try_from(self.relay.limits().frame_max).unwrap_or(u64::MAX);
            let assembly =
                window + Duration::from_secs(frame_max / self.limits.min_upload_rate.max(1));
            if read.saturating_sub(up.read_at_window) < needed || now >= up.started + assembly {
                return self.timed_out(Timeout::Upload, "upload_too_slow");
            }
            up.window_start = now;
            up.read_at_window = read;
            self.check_at = now + window;
            return Flow::Continue;
        }
        self.upload = None;
        let idle_at = self.last_activity + window;
        if now >= idle_at {
            return self.timed_out(Timeout::Idle, "idle_timeout");
        }
        self.check_at = idle_at;
        Flow::Continue
    }

    /// End the connection with `code` and `reason`. The close frame goes
    /// out once the session has unwound, so a batch being drained is dropped
    /// first instead of held while a stalled client fails to take the frame.
    fn end(&mut self, code: u16, reason: &'static str) -> Flow {
        tracing::debug!(reason, "connection closed");
        self.closing = Some((code, reason));
        Flow::Stop
    }

    fn timed_out(&mut self, kind: Timeout, reason: &'static str) -> Flow {
        self.relay.metrics().timeout(kind);
        self.end(CLOSE_GOING_AWAY, reason)
    }

    fn replaced(&mut self) -> Flow {
        self.end(CLOSE_NORMAL, "replaced")
    }

    fn evicted(&mut self) -> Flow {
        self.end(CLOSE_TRY_AGAIN, "relay_full")
    }

    fn shed(&mut self) -> Flow {
        self.relay.metrics().shed();
        self.end(CLOSE_TOO_BIG, "read_budget")
    }

    fn stopping(&mut self) -> Flow {
        self.end(CLOSE_GOING_AWAY, "shutting_down")
    }

    /// Handle one thing read from the socket.
    async fn on_message(&mut self, incoming: Option<Result<Message, axum::Error>>) -> Flow {
        let msg = match incoming {
            Some(Ok(Message::Close(_)) | Err(_)) | None => return Flow::Stop,
            Some(Ok(m)) => m,
        };
        let now = self.timer.now();
        let reply = match msg {
            Message::Text(text) => {
                self.rx.consumed(ws_wire_len(text.len()));
                self.active();
                let frame_max = self.relay.limits().frame_max;
                // Size, then rate, then the full parse. Acks are small, so
                // only small frames are read to see whether they are one.
                if text.len() <= frame_max {
                    let ack = text.len() <= SMALL_FRAME && peek(text.as_str()).0;
                    // A refused ack would leave a delivered message queued,
                    // so acks wait for their token instead.
                    if ack {
                        if let Err(at) = self.acks.take(now) {
                            self.relay.metrics().frame_rate_limited();
                            self.timer.sleep_until(at).await;
                            let _ = self.acks.take(self.timer.now());
                        }
                    } else if self.requests.take(now).is_err() {
                        self.relay.metrics().frame_rate_limited();
                        let corr = peek(text.as_str()).1;
                        return self.rate_limited(corr).await;
                    }
                }
                match parse_client_frame(text.as_str(), frame_max) {
                    Ok(frame) => return self.handle(frame).await,
                    Err((code, detail)) => {
                        self.relay.error_frame(None, RelayError::new(code, detail))
                    }
                }
            }
            Message::Binary(data) => {
                self.rx.consumed(ws_wire_len(data.len()));
                self.active();
                if self.requests.take(now).is_err() {
                    self.relay.metrics().frame_rate_limited();
                    return self.rate_limited(None).await;
                }
                self.relay.error_frame(
                    None,
                    RelayError::new(ErrorCode::BadRequest, "text frames only"),
                )
            }
            Message::Pong(payload) => {
                self.rx.consumed(ws_wire_len(payload.len()));
                // Only the answer to our own ping shows the client is there.
                if self.outstanding.is_some_and(|p| payload.as_ref() == p) {
                    self.outstanding = None;
                    self.active();
                    return Flow::Continue;
                }
                return self.control_frame(now);
            }
            Message::Ping(payload) => {
                self.rx.consumed(ws_wire_len(payload.len()));
                return self.control_frame(now);
            }
            Message::Close(_) => return Flow::Continue,
        };
        self.reply(&reply).await
    }

    /// A ping, or a pong nobody asked for: allowed at the frame rate.
    fn control_frame(&mut self, now: Instant) -> Flow {
        if self.requests.take(now).is_ok() {
            return Flow::Continue;
        }
        self.relay.metrics().frame_rate_limited();
        self.end(CLOSE_POLICY, "frame_rate")
    }

    async fn rate_limited(&mut self, corr: Option<String>) -> Flow {
        let e = self.relay.error_frame(
            corr,
            RelayError::new(ErrorCode::RateLimited, "frame rate exceeded"),
        );
        self.reply(&e).await
    }

    async fn reply(&mut self, frame: &ServerFrame) -> Flow {
        if self.send_frame(frame).await {
            Flow::Continue
        } else {
            Flow::Stop
        }
    }

    async fn handle(&mut self, frame: ClientFrame) -> Flow {
        let (reply, knock) = self
            .relay
            .handle_deferred(&self.mailbox, self.ip, frame)
            .await;
        // An accepted knock, forwarded or dropped, goes to the knock worker,
        // which writes on its own clock: neither the answer nor the store's
        // load after it depends on which it was.
        if let Some(knock) = knock {
            self.relay.queue_knock(knock, self.source);
        }
        match reply {
            Some(reply) => self.reply(&reply).await,
            None => Flow::Continue,
        }
    }

    /// Live traffic, until the connection ends.
    async fn run(&mut self, registration: &crate::relay::Registration) {
        loop {
            let check_at = self.check_at;
            let next_ping = self.next_ping;
            let flow = tokio::select! {
                biased;
                incoming = self.socket.recv() => self.on_message(incoming).await,
                () = registration.replaced.notified() => self.replaced(),
                () = self.kick.notified() => self.evicted(),
                () = self.rx.evict.notified() => self.shed(),
                () = crate::relay::until_true(&mut self.stop) => self.stopping(),
                () = registration.notify.notified() => {
                    if self.flush(registration).await { Flow::Continue } else { Flow::Stop }
                }
                () = self.timer.sleep_until(check_at) => self.check_alive(),
                () = self.timer.sleep_until(next_ping) => self.ping().await,
            };
            if flow == Flow::Stop {
                break;
            }
        }
    }
}

/// Stops counting a connection's reads against the budget when it ends.
struct Untrack(Arc<Rx>);

impl Drop for Untrack {
    fn drop(&mut self) {
        self.0.untrack();
    }
}

async fn session<S: Store>(
    relay: Arc<Relay<S>>,
    socket: WebSocket,
    mut slots: Slots,
    rx: Arc<Rx>,
    client: Client,
) {
    let source = client.source;
    rx.track(source);
    // Sends have their own deadline here (`send_timeout`), counted as such.
    rx.stop_write_stall();
    let _untrack = Untrack(Arc::clone(&rx));
    relay.metrics().connection();
    let mut conn = Conn::new(&relay, socket, rx, client);
    let Some(mailbox) = conn.authenticate().await else {
        return;
    };
    slots.unauth = None;
    // At the total cap a newcomer takes the place of the oldest connection
    // of the source holding the most, unless that is its own.
    let admitted =
        relay
            .ws_auth()
            .admit(source, usize::MAX, conn.limits.max_connections, false, None);
    let Ok(auth) = admitted else {
        relay.metrics().refused(ConnRefusal::Total);
        let e = relay.error_frame(
            None,
            RelayError::new(ErrorCode::RateLimited, "too many connections"),
        );
        let _ = conn.send_frame(&e).await;
        conn.close(CLOSE_TRY_AGAIN, "too_many_connections").await;
        return;
    };
    if auth.evicted {
        relay.metrics().evicted(Eviction::Ws);
    }
    conn.kick = Arc::clone(&auth.kick);
    // Register before the first flush so nothing queued in between is
    // missed. Past the per-mailbox cap the oldest connection goes.
    let (registration, replaced) = relay.register(&mailbox, conn.limits.max_per_mailbox);
    if replaced {
        relay.metrics().replaced();
    }
    // No mailbox tag: connection lines sit next to the knock lines, which
    // must not be linkable to a mailbox (SPEC §8.3, "Logging").
    tracing::debug!("connected");
    conn.mailbox = mailbox.clone();
    conn.active();
    let ready = ServerFrame::Ready {
        mailbox_id: mailbox,
    };
    if conn.send_frame(&ready).await
        && conn.flush(&registration).await
        // SPEC §8.2: what follows is live traffic, not the reconnect drain.
        && conn.send_frame(&ServerFrame::Drained).await
    {
        conn.run(&registration).await;
    }
    // Off the hub first, so nothing more is drained for this connection.
    drop(registration);
    if let Some((code, reason)) = conn.closing.take() {
        // A client that stopped reading won't take it; don't wait long.
        let frame = Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }));
        let _ = conn
            .timer
            .timeout(CLOSE_TIMEOUT, conn.socket.send(frame))
            .await;
    }
    tracing::debug!("disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(rate: u32, burst: u32) -> WsLimits {
        WsLimits {
            frames_per_sec: rate,
            frame_burst: burst,
            ..WsLimits::default()
        }
    }

    #[test]
    fn the_bucket_allows_a_burst_then_the_rate() {
        let t0 = Instant::now();
        let mut b = Bucket::new(&limits(10, 3), t0);
        for _ in 0..3 {
            assert_eq!(b.take(t0), Ok(()));
        }
        let at = b.take(t0).unwrap_err();
        assert_eq!(at - t0, Duration::from_millis(100));
        // A refused frame takes nothing.
        assert_eq!(b.take(t0), Err(at));
        assert_eq!(b.take(at), Ok(()));
        assert!(b.take(at).is_err());
        // Idle time refills up to the burst, not beyond.
        let later = at + Duration::from_secs(60);
        for _ in 0..3 {
            assert_eq!(b.take(later), Ok(()));
        }
        assert!(b.take(later).is_err());
    }

    #[test]
    fn a_burst_of_one_is_the_plain_rate() {
        let t0 = Instant::now();
        let mut b = Bucket::new(&limits(2, 1), t0);
        assert_eq!(b.take(t0), Ok(()));
        assert_eq!(b.take(t0), Err(t0 + Duration::from_millis(500)));
    }

    #[test]
    fn peek_finds_what_the_answer_needs() {
        assert_eq!(peek(r#"{"t":"ack","msg_id":"m"}"#), (true, None));
        assert_eq!(
            peek(r#"{"t":"send","env":{"msg_id":"e","ct":"AAAA"}}"#),
            (false, Some("e".into()))
        );
        assert_eq!(
            peek(r#"{"t":"knock","door_id":"d","env":{"msg_id":"k"}}"#),
            (false, Some("k".into()))
        );
        assert_eq!(
            peek(r#"{"t":"group.create","group_id":"g","epoch":0}"#),
            (false, Some("g".into()))
        );
        assert_eq!(
            peek(r#"{"t":"group.create","group_id":"g","msg_id":"c"}"#),
            (false, Some("c".into()))
        );
        assert_eq!(
            peek(r#"{"t":"invite.consume","invite_id":"i"}"#),
            (false, Some("i".into()))
        );
        assert_eq!(peek(r#"{"t":"auth"}"#), (false, None));
        assert_eq!(peek("not json"), (false, None));
        assert_eq!(peek(r#"{"t":7}"#), (false, None));
    }

    #[test]
    fn knock_envelopes_are_recognised_as_stored() {
        assert!(is_knock(r#"{"v":0,"kind":"knock","door_id":"d"}"#));
        assert!(!is_knock(r#"{"v":0,"kind":"application"}"#));
        assert!(!is_knock(r#"{"t":"queue_overflow"}"#));
    }
}
