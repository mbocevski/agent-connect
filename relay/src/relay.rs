//! The relay service: Delivery Service rules, invite and door registries and
//! mailbox hub. Transport-agnostic; `ws.rs` and `rest.rs` are thin adapters.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use agentconnect_core::clock::Clock;
use axum::http::HeaderMap;
use serde::Deserialize;
use tokio::sync::{Notify, mpsc, watch};

use crate::auth::{REST_MAX_SKEW_SECS, RestCredentials};
use crate::conn::{Fair, ReadBudget, SourceCounts, SourceKey};
use crate::proto::{
    ClientFrame, Envelope, ErrorCode, Kind, ServerFrame, is_id16, is_mailbox_id, log_tag,
};
use crate::quota::{
    ACTIVITY_GRANULARITY, ClientIpWarning, LiveCounts, Quotas, Refusal, address_key, admit,
    creation_key,
};
use crate::replay::{Claim, ReplayCache};
use crate::store::{
    CloseDoorOutcome, ConsumeOutcome, CreateDoorOutcome, CreateGroupOutcome, CreateInviteOutcome,
    DirectOutcome, DoorRecord, GroupOutcome, GroupSend, InviteRecord, InviteStatus, Limits,
    NewMessage, PurgeStats, RevokeOutcome, Store, StoredMessage, Window,
};
use crate::timer::Timer;
use crate::ws::WsLimits;

/// Maximum length of `group_name` and `inviter_name`, in characters.
pub const MAX_NAME_CHARS: usize = 80;
/// Maximum length of `purpose`, in characters.
pub const MAX_PURPOSE_CHARS: usize = 500;
/// Upper bound on `max_uses` accepted by the registry.
pub const MAX_INVITE_USES: u32 = 1000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Counters exposed on `/metrics`. No identifiers, ever.
#[derive(Debug, Default)]
pub struct Metrics {
    connections: AtomicU64,
    auth_failures: AtomicU64,
    frames_in: AtomicU64,
    accepted: AtomicU64,
    duplicates: AtomicU64,
    delivered: AtomicU64,
    overflows: AtomicU64,
    commits: AtomicU64,
    joins_forwarded: AtomicU64,
    invites_created: AtomicU64,
    invites_consumed: AtomicU64,
    doors_registered: AtomicU64,
    doors_closed: AtomicU64,
    knocks_accepted: AtomicU64,
    idle_groups_deleted: AtomicU64,
    /// Gauges: invite rows and groups held, and their caps. The relay
    /// counts creations here and recounts from the store at each purge.
    invites_live: AtomicU64,
    invites_max: AtomicU64,
    groups_live: AtomicU64,
    groups_max: AtomicU64,
    /// Gauge: WebSocket connections open now. Only a [`WsOpenGuard`] moves it.
    ws_open: Arc<AtomicU64>,
    /// Gauge: WebSocket connections that haven't authenticated yet.
    ws_unauth: Arc<AtomicU64>,
    /// Gauge: TCP connections still speaking HTTP (not yet upgraded).
    http_open: Arc<AtomicU64>,
    evicted: [AtomicU64; Eviction::ALL.len()],
    refused: [AtomicU64; ConnRefusal::ALL.len()],
    replaced: AtomicU64,
    shed: AtomicU64,
    timeouts: [AtomicU64; Timeout::ALL.len()],
    frames_rate_limited: AtomicU64,
    drain_bytes: AtomicU64,
    /// Gauge: bytes of queued envelopes loaded into memory for sending.
    drain_loaded: AtomicU64,
    /// Gauge: bytes read and not yet handed on as messages (the read
    /// budget's total, shared with [`crate::conn::ReadBudget`]).
    pub(crate) read_held: Arc<AtomicU64>,
    /// Gauge: storage in use at the last maintenance run.
    storage_bytes: AtomicU64,
    /// Gauge: the storage high-water mark.
    storage_high_water: AtomicU64,
    /// Gauge: 1 while new messages are refused for storage.
    storage_full: AtomicU64,
    errors: [AtomicU64; ErrorCode::ALL.len()],
}

/// Why a connection was refused (the `reason` label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnRefusal {
    /// The relay-wide cap on authenticated WebSocket connections.
    Total,
    /// The cap on WebSocket connections that haven't authenticated yet.
    Unauthenticated,
    /// A source's WebSocket connection cap.
    Source,
    /// A source's cap on connections in the HTTP phase.
    HttpSource,
}

impl ConnRefusal {
    const ALL: [ConnRefusal; 4] = [
        ConnRefusal::Total,
        ConnRefusal::Unauthenticated,
        ConnRefusal::Source,
        ConnRefusal::HttpSource,
    ];

    fn as_str(self) -> &'static str {
        match self {
            ConnRefusal::Total => "total",
            ConnRefusal::Unauthenticated => "unauthenticated",
            ConnRefusal::Source => "source",
            ConnRefusal::HttpSource => "http_source",
        }
    }
}

/// Which total cap closed a connection to admit another (the `cap` label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Eviction {
    /// Connections in the HTTP phase.
    Http,
    /// Authenticated WebSocket connections.
    Ws,
}

impl Eviction {
    const ALL: [Eviction; 2] = [Eviction::Http, Eviction::Ws];

    fn as_str(self) -> &'static str {
        match self {
            Eviction::Http => "http",
            Eviction::Ws => "ws",
        }
    }
}

/// Which deadline closed a connection (the `kind` label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Timeout {
    /// The request headers didn't arrive in time.
    Header,
    /// A kept-alive HTTP connection sent no request for the idle timeout.
    HttpIdle,
    /// A request (its body, its handling) didn't finish in time.
    Request,
    /// The client didn't answer the WebSocket challenge in time.
    Auth,
    /// The client sent no message and answered no ping for the idle
    /// timeout.
    Idle,
    /// A message being received arrived slower than the minimum rate, or
    /// took longer than the assembly deadline.
    Upload,
    /// A send to the client didn't complete in time (a stalled reader).
    Send,
}

impl Timeout {
    const ALL: [Timeout; 7] = [
        Timeout::Header,
        Timeout::HttpIdle,
        Timeout::Request,
        Timeout::Auth,
        Timeout::Idle,
        Timeout::Upload,
        Timeout::Send,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Timeout::Header => "header",
            Timeout::HttpIdle => "http_idle",
            Timeout::Request => "request",
            Timeout::Auth => "auth",
            Timeout::Idle => "idle",
            Timeout::Upload => "upload",
            Timeout::Send => "send",
        }
    }
}

/// Counts one open connection on a gauge: up when created, down exactly
/// once when dropped, whichever way the connection ends.
#[derive(Debug)]
pub(crate) struct WsOpenGuard(Arc<AtomicU64>);

impl Drop for WsOpenGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Bytes of one batch held in memory; the gauge drops as they are sent and
/// for the rest when the batch is dropped.
#[derive(Debug)]
pub(crate) struct DrainLoaded<'a> {
    metrics: &'a Metrics,
    left: u64,
}

impl DrainLoaded<'_> {
    /// `bytes` of the batch went out.
    pub(crate) fn sent(&mut self, bytes: u64) {
        let bytes = bytes.min(self.left);
        self.left -= bytes;
        self.metrics
            .drain_loaded
            .fetch_sub(bytes, Ordering::Relaxed);
        self.metrics.drain_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Drop for DrainLoaded<'_> {
    fn drop(&mut self) {
        self.metrics
            .drain_loaded
            .fetch_sub(self.left, Ordering::Relaxed);
    }
}

fn try_gauge(gauge: &Arc<AtomicU64>, max: usize) -> Option<WsOpenGuard> {
    let max = u64::try_from(max).unwrap_or(u64::MAX);
    gauge
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < max).then_some(n + 1)
        })
        .ok()?;
    Some(WsOpenGuard(Arc::clone(gauge)))
}

impl Metrics {
    /// Count a WebSocket connection as open, unless `max` are open already.
    pub(crate) fn try_ws_open(&self, max: usize) -> Option<WsOpenGuard> {
        try_gauge(&self.ws_open, max)
    }

    /// Count a WebSocket connection as waiting to authenticate, unless
    /// `max` are waiting already.
    pub(crate) fn try_ws_unauth(&self, max: usize) -> Option<WsOpenGuard> {
        try_gauge(&self.ws_unauth, max)
    }

    pub(crate) fn replaced(&self) {
        Self::inc(&self.replaced);
    }

    pub(crate) fn shed(&self) {
        Self::inc(&self.shed);
    }

    /// Count a TCP connection as speaking HTTP until the guard drops.
    pub(crate) fn http_open(&self) -> WsOpenGuard {
        self.http_open.fetch_add(1, Ordering::Relaxed);
        WsOpenGuard(Arc::clone(&self.http_open))
    }

    pub(crate) fn evicted(&self, cap: Eviction) {
        if let Some(i) = Eviction::ALL.iter().position(|c| *c == cap) {
            Self::inc(&self.evicted[i]);
        }
    }

    pub(crate) fn refused(&self, why: ConnRefusal) {
        if let Some(i) = ConnRefusal::ALL.iter().position(|r| *r == why) {
            Self::inc(&self.refused[i]);
        }
    }

    pub(crate) fn timeout(&self, kind: Timeout) {
        if let Some(i) = Timeout::ALL.iter().position(|t| *t == kind) {
            Self::inc(&self.timeouts[i]);
        }
    }

    pub(crate) fn frame_rate_limited(&self) {
        Self::inc(&self.frames_rate_limited);
    }

    pub(crate) fn drain_loaded(&self, bytes: u64) -> DrainLoaded<'_> {
        self.drain_loaded.fetch_add(bytes, Ordering::Relaxed);
        DrainLoaded {
            metrics: self,
            left: bytes,
        }
    }

    fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn connection(&self) {
        Self::inc(&self.connections);
    }

    pub(crate) fn auth_failure(&self) {
        Self::inc(&self.auth_failures);
    }

    pub(crate) fn frame_in(&self) {
        Self::inc(&self.frames_in);
    }

    pub(crate) fn delivered(&self, n: usize) {
        self.delivered
            .fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn overflows(&self, n: usize) {
        self.overflows
            .fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn error(&self, code: ErrorCode) {
        if let Some(i) = ErrorCode::ALL.iter().position(|c| *c == code) {
            Self::inc(&self.errors[i]);
        }
    }

    /// The storage gauges (SPEC §8.3, "Limits").
    fn render_storage(&self, out: &mut String) {
        let mut gauge = |name: &str, help: &str, v: &AtomicU64| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}
# TYPE {name} gauge
{name} {}",
                v.load(Ordering::Relaxed)
            );
        };
        gauge(
            "agentconnect_relay_storage_bytes",
            "Bytes of database pages in use, as of the last periodic purge.",
            &self.storage_bytes,
        );
        gauge(
            "agentconnect_relay_storage_high_water_bytes",
            "The storage high-water mark: at or above it new messages are refused.",
            &self.storage_high_water,
        );
        gauge(
            "agentconnect_relay_storage_full",
            "1 while storage is at or above its high-water mark, else 0.",
            &self.storage_full,
        );
    }

    /// Prometheus text exposition.
    #[must_use]
    #[allow(clippy::too_many_lines, reason = "one call per counter")]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut counter = |name: &str, help: &str, v: &AtomicU64| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}",
                v.load(Ordering::Relaxed)
            );
        };
        counter(
            "agentconnect_relay_connections_total",
            "WebSocket connections opened.",
            &self.connections,
        );
        counter(
            "agentconnect_relay_auth_failures_total",
            "Failed WebSocket authentications.",
            &self.auth_failures,
        );
        counter(
            "agentconnect_relay_frames_total",
            "Client frames received.",
            &self.frames_in,
        );
        counter(
            "agentconnect_relay_accepted_total",
            "Sends accepted.",
            &self.accepted,
        );
        counter(
            "agentconnect_relay_duplicates_total",
            "Sends accepted as idempotent repeats.",
            &self.duplicates,
        );
        counter(
            "agentconnect_relay_deliveries_total",
            "Message copies queued for mailboxes.",
            &self.delivered,
        );
        counter(
            "agentconnect_relay_queue_overflows_total",
            "Mailbox queue overflow episodes started.",
            &self.overflows,
        );
        counter(
            "agentconnect_relay_commits_total",
            "Commits accepted.",
            &self.commits,
        );
        counter(
            "agentconnect_relay_joins_forwarded_total",
            "Join requests forwarded to inviters.",
            &self.joins_forwarded,
        );
        counter(
            "agentconnect_relay_invites_created_total",
            "Invites registered.",
            &self.invites_created,
        );
        counter(
            "agentconnect_relay_invites_consumed_total",
            "Invite uses consumed.",
            &self.invites_consumed,
        );
        counter(
            "agentconnect_relay_doors_registered_total",
            "Doors registered.",
            &self.doors_registered,
        );
        counter(
            "agentconnect_relay_doors_closed_total",
            "Door close requests accepted.",
            &self.doors_closed,
        );
        // Forwarded and silently dropped knocks are one number: /metrics is
        // public, and a split would tell a knocker what `accepted` hides.
        counter(
            "agentconnect_relay_knocks_accepted_total",
            "Knocks answered with accepted.",
            &self.knocks_accepted,
        );
        counter(
            "agentconnect_relay_idle_groups_deleted_total",
            "Groups deleted after the idle period.",
            &self.idle_groups_deleted,
        );
        let mut gauge = |name: &str, help: &str, v: &AtomicU64| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {}",
                v.load(Ordering::Relaxed)
            );
        };
        gauge(
            "agentconnect_relay_invites",
            "Invite rows held, open or not yet purged.",
            &self.invites_live,
        );
        gauge(
            "agentconnect_relay_invites_max",
            "The cap on invite rows held.",
            &self.invites_max,
        );
        gauge(
            "agentconnect_relay_groups",
            "Groups held.",
            &self.groups_live,
        );
        gauge(
            "agentconnect_relay_groups_max",
            "The cap on groups held.",
            &self.groups_max,
        );
        self.render_connections(&mut out);
        self.render_storage(&mut out);
        let _ = writeln!(
            out,
            "# HELP agentconnect_relay_errors_total Errors returned, by code.\n\
             # TYPE agentconnect_relay_errors_total counter"
        );
        for (code, n) in ErrorCode::ALL.iter().zip(&self.errors) {
            let _ = writeln!(
                out,
                "agentconnect_relay_errors_total{{code=\"{}\"}} {}",
                code.as_str(),
                n.load(Ordering::Relaxed)
            );
        }
        out
    }

    /// The connection limits' metrics (SR-06, SR-13): caps, deadlines,
    /// frame rate and drain bytes.
    fn render_connections(&self, out: &mut String) {
        let mut counter = |name: &str, help: &str, v: &AtomicU64| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}",
                v.load(Ordering::Relaxed)
            );
        };
        counter(
            "agentconnect_relay_frames_rate_limited_total",
            "Client frames over the per-connection frame rate (refused, or delayed for acks).",
            &self.frames_rate_limited,
        );
        counter(
            "agentconnect_relay_drain_bytes_total",
            "Bytes of queued messages other than knocks sent to connections.",
            &self.drain_bytes,
        );
        counter(
            "agentconnect_relay_connections_replaced_total",
            "Connections closed because a newer one for the same mailbox passed the per-mailbox cap.",
            &self.replaced,
        );
        counter(
            "agentconnect_relay_connections_shed_total",
            "Connections closed because the relay-wide read budget was exceeded.",
            &self.shed,
        );
        let mut gauge = |name: &str, help: &str, v: &AtomicU64| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {}",
                v.load(Ordering::Relaxed)
            );
        };
        gauge(
            "agentconnect_relay_ws_connections_open",
            "WebSocket connections open now.",
            &self.ws_open,
        );
        gauge(
            "agentconnect_relay_ws_connections_unauthenticated",
            "WebSocket connections open now that haven't authenticated.",
            &self.ws_unauth,
        );
        gauge(
            "agentconnect_relay_read_bytes_held",
            "Bytes read from WebSocket clients and not yet handed on as messages.",
            &self.read_held,
        );
        gauge(
            "agentconnect_relay_http_connections_open",
            "TCP connections open now that have not become WebSockets.",
            &self.http_open,
        );
        gauge(
            "agentconnect_relay_drain_bytes_loaded",
            "Bytes of queued messages other than knocks loaded into memory for sending now.",
            &self.drain_loaded,
        );
        let _ = writeln!(
            out,
            "# HELP agentconnect_relay_connections_refused_total Connections refused at a connection cap, by cap.\n\
             # TYPE agentconnect_relay_connections_refused_total counter"
        );
        for (why, n) in ConnRefusal::ALL.iter().zip(&self.refused) {
            let _ = writeln!(
                out,
                "agentconnect_relay_connections_refused_total{{reason=\"{}\"}} {}",
                why.as_str(),
                n.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            out,
            "# HELP agentconnect_relay_connections_evicted_total Connections closed at a total cap to admit one from another source, by cap.\n\
             # TYPE agentconnect_relay_connections_evicted_total counter"
        );
        for (cap, n) in Eviction::ALL.iter().zip(&self.evicted) {
            let _ = writeln!(
                out,
                "agentconnect_relay_connections_evicted_total{{cap=\"{}\"}} {}",
                cap.as_str(),
                n.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            out,
            "# HELP agentconnect_relay_connection_timeouts_total Connections closed by a deadline, by deadline.\n\
             # TYPE agentconnect_relay_connection_timeouts_total counter"
        );
        for (kind, n) in Timeout::ALL.iter().zip(&self.timeouts) {
            let _ = writeln!(
                out,
                "agentconnect_relay_connection_timeouts_total{{kind=\"{}\"}} {}",
                kind.as_str(),
                n.load(Ordering::Relaxed)
            );
        }
    }
}

/// Wakes connections when their mailbox has new messages.
#[derive(Debug, Default)]
struct Hub {
    next: AtomicU64,
    waiters: Mutex<Waiters>,
}

/// A registered connection: its wake-up, and its replacement signal.
#[derive(Debug)]
struct Waiter {
    id: u64,
    notify: Arc<Notify>,
    replaced: Arc<Notify>,
}

type Waiters = HashMap<String, Vec<Waiter>>;

/// A connection's registration for wake-ups; unregisters on drop.
#[derive(Debug)]
pub struct Registration {
    hub: Arc<Hub>,
    mailbox: String,
    id: u64,
    /// Fires when new messages are queued for the mailbox.
    pub notify: Arc<Notify>,
    /// Fires when a newer connection for the mailbox took this one's place.
    pub replaced: Arc<Notify>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut waiters = lock(&self.hub.waiters);
        if let Some(list) = waiters.get_mut(&self.mailbox) {
            list.retain(|w| w.id != self.id);
            if list.is_empty() {
                waiters.remove(&self.mailbox);
            }
        }
    }
}

/// Sliding-window rate limiter state, keyed by arbitrary strings. Held in
/// memory only; keys hold identifiers and are never logged.
#[derive(Debug, Default)]
struct Rates {
    /// key -> (window length in ms, event times in ms, oldest first).
    windows: HashMap<String, (u64, VecDeque<u64>)>,
}

impl Rates {
    /// The events for `key` that are still inside `window_ms`.
    fn current(&mut self, key: &str, window_ms: u64, now_ms: u64) -> &mut VecDeque<u64> {
        let (len, w) = self
            .windows
            .entry(key.to_owned())
            .or_insert_with(|| (window_ms, VecDeque::new()));
        *len = window_ms;
        while w
            .front()
            .is_some_and(|t| now_ms.saturating_sub(*t) >= window_ms)
        {
            w.pop_front();
        }
        w
    }

    fn allow(&mut self, key: &str, max: usize, window_ms: u64, now_ms: u64) -> bool {
        self.allow_all(&[(key, max, window_ms)], now_ms)
    }

    /// Record one event under every key if each has room; otherwise record
    /// nothing, so a refused request uses up no budget.
    fn allow_all(&mut self, checks: &[(&str, usize, u64)], now_ms: u64) -> bool {
        let room = checks
            .iter()
            .all(|(key, max, window_ms)| self.current(key, *window_ms, now_ms).len() < *max);
        if room {
            for (key, _, window_ms) in checks {
                self.current(key, *window_ms, now_ms).push_back(now_ms);
            }
        }
        room
    }

    /// Forget keys whose newest event has left that key's own window.
    fn sweep(&mut self, now_ms: u64) {
        self.windows
            .retain(|_, (len, w)| w.back().is_some_and(|t| now_ms.saturating_sub(*t) < *len));
    }
}

/// One less, never below zero: the purge may have recounted from the store
/// since the reservation that this gives back.
fn dec(c: &AtomicU64) {
    let _ = c.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(1))
    });
}

fn window_ms(w: Window) -> u64 {
    u64::try_from(w.per.as_millis()).unwrap_or(u64::MAX)
}

/// How often the purge looks for idle groups (SPEC §8.3, "Idle groups").
const IDLE_SWEEP_EVERY_MS: u64 = 3600 * 1000;
/// Groups read per page of the idle sweep.
const IDLE_SWEEP_PAGE: u32 = 500;

/// `POST /v0/invites` body: `InviteMeta` minus status and `uses_left`, plus
/// the inviter's mailbox (SPEC §8.1).
#[derive(Debug, Deserialize)]
pub struct NewInviteRequest {
    /// Public invite id (16 random bytes, base64url).
    pub invite_id: String,
    /// Group display name.
    pub group_name: String,
    /// Inviter display name.
    pub inviter_name: String,
    /// Group purpose.
    pub purpose: String,
    /// Expiry, unix seconds.
    pub expires_at: u64,
    /// Total uses (at least 1).
    pub max_uses: u32,
    /// Optional member count shown on the landing page.
    #[serde(default)]
    pub member_count: Option<u32>,
    /// The inviter's mailbox; must match the authenticated mailbox.
    pub inviter_mailbox: String,
    /// Protocol version, if given must be 0.
    #[serde(default)]
    pub protocol: Option<u32>,
}

/// `POST /v0/doors` body (ADR-006): the mapping and nothing else. Unknown
/// fields are refused, so a door key or card text can't end up stored here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewDoorRequest {
    /// Public door id (16 random bytes, base64url), chosen by the owner.
    pub door_id: String,
    /// Expiry, unix seconds; at most 7 days away.
    pub expires_at: u64,
    /// The owner's mailbox; must match the authenticated mailbox.
    pub owner_mailbox: String,
}

/// An error with its protocol code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayError {
    /// The SPEC §8.4 code.
    pub code: ErrorCode,
    /// A message safe to show the client.
    pub detail: String,
    /// For `epoch_conflict`: the group's current epoch.
    pub current_epoch: Option<u64>,
    /// For a refusal that ends at a known time: seconds until a retry
    /// (REST `Retry-After` and `retry_after`).
    pub retry_after: Option<u64>,
}

impl RelayError {
    /// An error without an epoch.
    #[must_use]
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            current_epoch: None,
            retry_after: None,
        }
    }
}

fn internal(e: &dyn std::fmt::Display) -> RelayError {
    tracing::error!(error = %e, "storage failure");
    RelayError::new(ErrorCode::Internal, "internal error")
}

/// One-line text (SPEC §4.2, §13.1.2) of at most `max_chars` characters;
/// may be empty.
fn text_ok(s: &str, max_chars: usize) -> bool {
    s.chars().count() <= max_chars && agentconnect_core::listing::is_text(s)
}

/// What a creation holds against the global and per-address caps.
#[derive(Debug, Clone, Copy)]
enum Held {
    Invite,
    Group,
}

/// The relay service.
pub struct Relay<S: Store> {
    store: S,
    clock: Arc<dyn Clock>,
    host: String,
    limits: Limits,
    quotas: Quotas,
    hub: Arc<Hub>,
    rates: Mutex<Rates>,
    replays: Mutex<ReplayCache>,
    /// Invites and groups created per creation key that the relay still
    /// holds. Memory only, never linked to the rows.
    live_invites: Mutex<LiveCounts>,
    live_groups: Mutex<LiveCounts>,
    /// Signed requests with a `ts` at or below this are refused (0: none):
    /// set after a restart, when the cache no longer holds what the last
    /// process accepted.
    replay_floor_secs: u64,
    /// Whether each [`ClientIpWarning`] was logged already.
    warned: [AtomicBool; 3],
    /// When the purge last looked for idle groups, unix ms. Starts at the
    /// start time, so members have an hour to reconnect after a restart.
    idle_swept_at: AtomicU64,
    metrics: Metrics,
    ws_limits: WsLimits,
    timer: Timer,
    read_budget: Arc<ReadBudget>,
    ws_sources: Arc<SourceCounts>,
    ws_auth: Arc<Fair>,
    knocks_tx: mpsc::Sender<(KnockForward, SourceKey)>,
    knocks_rx: tokio::sync::Mutex<mpsc::Receiver<(KnockForward, SourceKey)>>,
    knock_shares: Mutex<KnockShares>,
    knock_worker: AtomicBool,
    stopping: watch::Sender<bool>,
}

/// Accepted knocks waiting for the knock worker, at most. Past it a knock is
/// dropped behind its `accepted`, like one to a busy door.
pub const KNOCK_QUEUE: usize = 1024;

/// Of [`KNOCK_QUEUE`], the most one source may hold: 16 sources can't fill
/// it. A source's knocks past it are dropped silently.
pub const KNOCK_QUEUE_PER_SOURCE: usize = KNOCK_QUEUE / 16;

/// Of [`KNOCK_QUEUE`], the most one door may hold between two rounds of the
/// worker. A door forwards at most 10 knocks a minute anyway (SPEC §8.3).
pub const KNOCK_QUEUE_PER_DOOR: usize = 16;

/// Queued knocks per source and per door.
#[derive(Debug, Default)]
struct KnockShares {
    by_source: HashMap<SourceKey, usize>,
    by_door: HashMap<String, usize>,
}

impl KnockShares {
    fn release(&mut self, source: SourceKey, door: &str) {
        if let Some(n) = self.by_source.get_mut(&source) {
            *n -= 1;
            if *n == 0 {
                self.by_source.remove(&source);
            }
        }
        if let Some(n) = self.by_door.get_mut(door) {
            *n -= 1;
            if *n == 0 {
                self.by_door.remove(door);
            }
        }
    }
}

/// How often the knock worker writes the knocks accepted since its last
/// round. Knocks are written on this clock, not when they arrive, so the
/// store's load right after a knock doesn't depend on whether it was
/// forwarded or dropped.
pub const KNOCK_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// A knock answered `accepted`: queued with [`Relay::queue_knock`] whether
/// it is forwarded or dropped, so both take the same path; only the knock
/// worker tells them apart, when it writes.
#[derive(Debug)]
pub struct KnockForward {
    door: String,
    write: Option<(String, NewMessage)>,
}

impl KnockForward {
    /// True if the knock will be queued for the door's owner; false if it
    /// was dropped (a busy door).
    #[must_use]
    pub fn forwards(&self) -> bool {
        self.write.is_some()
    }
}

/// Resolves once `stop` turns true; never if its sender is gone.
pub(crate) async fn until_true(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow_and_update() {
            return;
        }
        if stop.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

impl<S: Store> Relay<S> {
    /// Build a relay. `host` is the string clients sign into their auth
    /// (the relay's public host name).
    pub fn new(store: S, clock: Arc<dyn Clock>, host: impl Into<String>, limits: Limits) -> Self {
        let started = clock.unix_millis();
        let metrics = Metrics::default();
        metrics
            .storage_high_water
            .store(limits.storage_high_water, Ordering::Relaxed);
        let read_budget = ReadBudget::new(
            WsLimits::default().read_buffer_bytes,
            Arc::clone(&metrics.read_held),
        );
        let (knocks_tx, knocks_rx) = mpsc::channel(KNOCK_QUEUE);
        Self {
            store,
            clock,
            host: host.into(),
            limits,
            quotas: Quotas::default(),
            hub: Arc::default(),
            rates: Mutex::default(),
            replays: Mutex::default(),
            live_invites: Mutex::default(),
            live_groups: Mutex::default(),
            replay_floor_secs: 0,
            warned: [
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ],
            idle_swept_at: AtomicU64::new(started),
            metrics,
            ws_limits: WsLimits::default(),
            timer: Timer::default(),
            read_budget,
            ws_sources: Arc::default(),
            ws_auth: Fair::new(),
            knocks_tx,
            knocks_rx: tokio::sync::Mutex::new(knocks_rx),
            knock_shares: Mutex::default(),
            knock_worker: AtomicBool::new(false),
            stopping: watch::Sender::new(false),
        }
        .with_quotas(Quotas::default())
    }

    fn over_budget() -> RelayError {
        RelayError::new(
            ErrorCode::OverBudget,
            "this mailbox has its budget of undelivered messages stored, in all or in this \
             group; retry later",
        )
    }

    fn storage_full(&self) -> RelayError {
        self.metrics.storage_full.store(1, Ordering::Relaxed);
        tracing::warn!("storage is above its high-water mark; message refused");
        RelayError::new(
            ErrorCode::StorageFull,
            "relay storage is above its high-water mark; retry later",
        )
    }

    /// Replace the abuse limits (defaults: [`Quotas::default`]).
    #[must_use]
    pub fn with_quotas(mut self, quotas: Quotas) -> Self {
        let n = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
        self.metrics
            .invites_max
            .store(n(quotas.max_invites), Ordering::Relaxed);
        self.metrics
            .groups_max
            .store(n(quotas.max_groups), Ordering::Relaxed);
        self.quotas = quotas;
        self
    }

    /// Set the WebSocket connection limits.
    #[must_use]
    pub fn with_ws_limits(mut self, limits: WsLimits) -> Self {
        self.read_budget = ReadBudget::new(
            limits.read_buffer_bytes,
            Arc::clone(&self.metrics.read_held),
        );
        self.ws_limits = limits;
        self
    }

    /// Set the timer for connection deadlines (tests use a manual one).
    #[must_use]
    pub fn with_timer(mut self, timer: Timer) -> Self {
        self.timer = timer;
        self
    }

    /// The WebSocket connection limits.
    #[must_use]
    pub fn ws_limits(&self) -> &WsLimits {
        &self.ws_limits
    }

    /// The timer for connection deadlines.
    #[must_use]
    pub fn timer(&self) -> &Timer {
        &self.timer
    }

    /// The relay-wide budget for bytes read and not yet handed on.
    #[must_use]
    pub fn read_budget(&self) -> &Arc<ReadBudget> {
        &self.read_budget
    }

    /// WebSocket connections per source.
    #[must_use]
    pub fn ws_sources(&self) -> &Arc<SourceCounts> {
        &self.ws_sources
    }

    /// Authenticated WebSocket connections, under the total cap.
    #[must_use]
    pub fn ws_auth(&self) -> &Arc<Fair> {
        &self.ws_auth
    }

    /// Tell connections and the knock worker that the relay is stopping.
    pub fn stop(&self) {
        self.stopping.send_replace(true);
    }

    /// Turns true when the relay is stopping.
    #[must_use]
    pub fn stopping(&self) -> watch::Receiver<bool> {
        self.stopping.subscribe()
    }

    /// Hand an accepted knock from `source` to the knock worker. Past the
    /// source's or the door's share of the queue, or with the queue full,
    /// it is dropped silently, as a busy door does.
    pub fn queue_knock(&self, knock: KnockForward, source: SourceKey) {
        let mut shares = lock(&self.knock_shares);
        let held_source = shares.by_source.get(&source).copied().unwrap_or(0);
        let held_door = shares.by_door.get(&knock.door).copied().unwrap_or(0);
        if held_source >= KNOCK_QUEUE_PER_SOURCE || held_door >= KNOCK_QUEUE_PER_DOOR {
            tracing::debug!(reason = "knock_queue_share", "knock dropped");
            return;
        }
        let door = knock.door.clone();
        if self.knocks_tx.try_send((knock, source)).is_err() {
            tracing::debug!(reason = "knock_queue_full", "knock dropped");
            return;
        }
        *shares.by_source.entry(source).or_default() += 1;
        *shares.by_door.entry(door).or_default() += 1;
    }

    /// Write every queued knock now: forwarded ones to their owners,
    /// dropped ones nowhere.
    pub async fn flush_knocks(&self) {
        let mut rx = self.knocks_rx.lock().await;
        while let Ok((knock, source)) = rx.try_recv() {
            lock(&self.knock_shares).release(source, &knock.door);
            self.forward_knock(knock).await;
        }
    }

    /// Start the knock worker, once: every [`KNOCK_FLUSH_INTERVAL`] it
    /// writes the queued knocks, and it writes what is left when the relay
    /// stops.
    pub fn start_knock_worker(self: &Arc<Self>) {
        if self.knock_worker.swap(true, Ordering::Relaxed) {
            return;
        }
        let relay = Arc::clone(self);
        tokio::spawn(async move {
            let mut stop = relay.stopping();
            let mut next = relay.timer.now() + KNOCK_FLUSH_INTERVAL;
            loop {
                tokio::select! {
                    () = relay.timer.sleep_until(next) => {}
                    () = until_true(&mut stop) => {
                        relay.flush_knocks().await;
                        return;
                    }
                }
                // Ticks missed while the store was busy are skipped, not run
                // back to back.
                next = (next + KNOCK_FLUSH_INTERVAL).max(relay.timer.now());
                relay.flush_knocks().await;
            }
        });
    }

    /// Refuse every signed request whose `ts` is from before this start
    /// plus the accepted skew (SPEC §8.1.1): the replay cache is per
    /// process, so this keeps a request accepted by an earlier process from
    /// being accepted again. For a relay that starts on an existing
    /// database after a crash; it refuses up to 300 s of signed requests.
    #[must_use]
    pub fn with_restart_guard(mut self) -> Self {
        self.replay_floor_secs = self.now_secs().saturating_add(REST_MAX_SKEW_SECS);
        self
    }

    /// After a clean shutdown: refuse every signed request whose `ts` is at
    /// most `highest_ts`, the highest the earlier process accepted
    /// (`crate::restart`).
    #[must_use]
    pub fn with_replay_floor(mut self, highest_ts: u64) -> Self {
        self.replay_floor_secs = highest_ts;
        self
    }

    /// The highest `ts` of a signed request this process accepted (0: none),
    /// to persist at a clean shutdown.
    #[must_use]
    pub fn highest_accepted_ts(&self) -> u64 {
        lock(&self.replays).highest_ts().max(self.replay_floor_secs)
    }

    /// Recount the invite rows and groups the store holds, for the global
    /// caps. The purge does it too; call it once at start.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn refresh_counts(&self) -> Result<(), RelayError> {
        let c = self.store.live_counts().await.map_err(|e| internal(&e))?;
        self.metrics
            .invites_live
            .store(c.invites, Ordering::Relaxed);
        self.metrics.groups_live.store(c.groups, Ordering::Relaxed);
        Ok(())
    }

    /// The abuse limits.
    #[must_use]
    pub fn quotas(&self) -> &Quotas {
        &self.quotas
    }

    /// The client address of a request: the peer, or what a trusted proxy
    /// reports ([`crate::quota::ClientIp`]). Logs once per kind when a
    /// request suggests a proxy setup the relay isn't configured for. The
    /// address itself is never logged.
    #[must_use]
    pub fn client_ip(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let (ip, warning) = self.quotas.client_ip.resolve(peer, headers);
        if let Some(w) = warning {
            let (i, msg) = match w {
                ClientIpWarning::HeaderNotConfigured => (
                    0,
                    "a request carries X-Forwarded-For or Forwarded, but \
                     AC_RELAY_CLIENT_IP_HEADER is not set: behind a proxy every client \
                     shares the proxy's per-address limits",
                ),
                ClientIpWarning::Unreadable => (
                    1,
                    "a trusted proxy's client-address header has no address at \
                     AC_RELAY_PROXY_HOPS from the right; the request counts as the proxy's",
                ),
                ClientIpWarning::UntrustedPeer => (
                    2,
                    "a request carries a client-address header (X-Forwarded-For or \
                     Forwarded) from a peer outside AC_RELAY_TRUSTED_PROXIES: the header is \
                     ignored, so every client behind that proxy shares its per-address \
                     limits; list the proxy's address as the relay sees it (behind Docker, \
                     the bridge gateway, not 127.0.0.1)",
                ),
            };
            if !self.warned[i].swap(true, Ordering::Relaxed) {
                tracing::warn!("{msg}");
            }
        }
        ip
    }

    /// Answer a signed request whose signature or timestamp failed with
    /// `refusal`, counted in `ip`'s bucket for such requests (SPEC
    /// §8.1.1). Past that bucket's rate the answer is `rate_limited`. The
    /// bucket refuses nothing else: a request whose signature verifies never
    /// looks at it.
    #[must_use]
    pub fn refuse_unverified(&self, ip: Option<IpAddr>, refusal: RelayError) -> RelayError {
        let w = self.quotas.rest_junk_per_address;
        let key = format!("rj:{}", address_key(ip));
        if self.rate_check(&key, w.max, window_ms(w)) {
            refusal
        } else {
            RelayError::new(
                ErrorCode::RateLimited,
                "too many failed signed requests from this address; retry later",
            )
        }
    }

    /// Record a signed request whose signature verified (SPEC §8.1.1):
    /// check its timestamp at the cache's own time and claim its
    /// `(mailbox, sig)` pair, in one step, before anything awaits. Returns
    /// whether it was recorded (it isn't when the cache as a whole is full).
    ///
    /// # Errors
    ///
    /// `auth_failed` for a repeat or a timestamp outside the window,
    /// `rate_limited` when the mailbox's share is full of live entries, or
    /// in the first 300 s after a restart for a request signed before it.
    pub fn claim_signed(&self, creds: &RestCredentials) -> Result<bool, RelayError> {
        if creds.ts <= self.replay_floor_secs {
            let wait = self
                .replay_floor_secs
                .saturating_add(1)
                .saturating_sub(self.now_secs())
                .max(1);
            return Err(RelayError {
                retry_after: Some(wait),
                ..RelayError::new(
                    ErrorCode::RateLimited,
                    "the relay restarted; sign the request again shortly",
                )
            });
        }
        let claim = lock(&self.replays).claim(
            creds,
            self.now_secs(),
            self.quotas.replay_per_mailbox,
            self.quotas.replay_max_entries,
        );
        match claim {
            Claim::Fresh => Ok(true),
            Claim::Unrecorded => Ok(false),
            Claim::Replay => Err(RelayError::new(
                ErrorCode::AuthFailed,
                "request already used",
            )),
            Claim::Expired => Err(RelayError::new(
                ErrorCode::AuthFailed,
                "timestamp outside the accepted window",
            )),
            Claim::Full => Err(RelayError::new(
                ErrorCode::RateLimited,
                "too many signed requests from this mailbox; retry later",
            )),
        }
    }

    /// Count an authorized signed request against its mailbox and, for a
    /// creation (`POST`), against its source address (SPEC §8.1.1).
    /// Revoking an invite and closing a door count only per mailbox, so no
    /// one sharing an address can stop them.
    ///
    /// # Errors
    ///
    /// `rate_limited` past either rate. A refused request keeps its entry
    /// in the replay cache.
    pub fn charge_signed(
        &self,
        creds: &RestCredentials,
        ip: Option<IpAddr>,
        creation: bool,
    ) -> Result<(), RelayError> {
        let m = self.quotas.rest_per_mailbox;
        let a = self.quotas.rest_per_address;
        let mailbox_key = format!("rm:{}", creds.mailbox);
        let address_key = format!("rv:{}", address_key(ip));
        let mut checks = vec![(mailbox_key.as_str(), m.max, window_ms(m))];
        if creation {
            checks.push((address_key.as_str(), a.max, window_ms(a)));
        }
        if lock(&self.rates).allow_all(&checks, self.now_ms()) {
            Ok(())
        } else {
            Err(RelayError::new(
                ErrorCode::RateLimited,
                "too many signed requests; retry later",
            ))
        }
    }

    /// Reserve one more of what a creation holds (invite rows or groups)
    /// in all and for `ip`'s creation key, until `until_ms`, under the fair
    /// admission of [`admit`]. `undo` gives it back if the creation fails.
    fn reserve(&self, what: Held, ip: Option<IpAddr>, until_ms: u64) -> Result<(), RelayError> {
        let (live, max, per_key, map, noun) = self.held(what);
        let max = u64::try_from(max).unwrap_or(u64::MAX);
        let key = creation_key(ip);
        let now = self.now_ms();
        let mut map = lock(map);
        let holds = map.holds(&key, now);
        let full = |detail: String| Err(RelayError::new(ErrorCode::QuotaExceeded, detail));
        match admit(
            live.load(Ordering::Relaxed),
            max,
            per_key,
            holds,
            map.keys(),
        ) {
            Ok(()) => {}
            Err(Refusal::Full) => {
                return full(format!(
                    "the relay holds as many {noun} as it takes; retry later"
                ));
            }
            Err(Refusal::Reserved) => {
                return full(format!(
                    "the relay is nearly full of {noun}; this address holds enough of them"
                ));
            }
            Err(Refusal::Key) => return full(format!("too many {noun} from this address")),
        }
        // Concurrent creations: the count, not the check, decides the cap.
        if live.fetch_add(1, Ordering::Relaxed) >= max {
            dec(live);
            return full(format!(
                "the relay holds as many {noun} as it takes; retry later"
            ));
        }
        map.push(&key, until_ms);
        Ok(())
    }

    fn undo(&self, what: Held, ip: Option<IpAddr>, until_ms: u64) {
        let (live, _, _, map, _) = self.held(what);
        dec(live);
        lock(map).remove(&creation_key(ip), until_ms);
    }

    fn held(&self, what: Held) -> (&AtomicU64, usize, usize, &Mutex<LiveCounts>, &'static str) {
        match what {
            Held::Invite => (
                &self.metrics.invites_live,
                self.quotas.max_invites,
                self.quotas.invites_per_address,
                &self.live_invites,
                "invites",
            ),
            Held::Group => (
                &self.metrics.groups_live,
                self.quotas.max_groups,
                self.quotas.groups_per_address,
                &self.live_groups,
                "groups",
            ),
        }
    }

    /// The host string signed into authentication.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The configured limits.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The metrics counters.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Current unix milliseconds from the relay clock.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.unix_millis()
    }

    /// Current unix seconds from the relay clock.
    #[must_use]
    pub fn now_secs(&self) -> u64 {
        self.now_ms() / 1000
    }

    /// Register a connection for wake-ups on `mailbox`. If `max` are
    /// registered already, the oldest is unregistered and told through its
    /// [`Registration::replaced`]: the newest connection is the one known to
    /// be alive, while an old one may be half-open. Returns whether one was
    /// replaced.
    pub fn register(&self, mailbox: &str, max: usize) -> (Registration, bool) {
        let id = self.hub.next.fetch_add(1, Ordering::Relaxed);
        let notify = Arc::new(Notify::new());
        let replaced = Arc::new(Notify::new());
        let mut waiters = lock(&self.hub.waiters);
        let list = waiters.entry(mailbox.to_owned()).or_default();
        let mut evicted = false;
        while !list.is_empty() && list.len() >= max.max(1) {
            let oldest = list.remove(0);
            oldest.replaced.notify_one();
            evicted = true;
        }
        list.push(Waiter {
            id,
            notify: Arc::clone(&notify),
            replaced: Arc::clone(&replaced),
        });
        drop(waiters);
        let registration = Registration {
            hub: Arc::clone(&self.hub),
            mailbox: mailbox.to_owned(),
            id,
            notify,
            replaced,
        };
        (registration, evicted)
    }

    fn wake<'a>(&self, mailboxes: impl IntoIterator<Item = &'a String>) {
        let waiters = lock(&self.hub.waiters);
        for m in mailboxes {
            for w in waiters.get(m).into_iter().flatten() {
                w.notify.notify_one();
            }
        }
    }

    /// Unexpired queued messages after `after_seq`, oldest first, capped at
    /// `limit` messages and `max_bytes` (at least one message).
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn pending(
        &self,
        mailbox: &str,
        after_seq: i64,
        limit: u32,
        max_bytes: u64,
    ) -> Result<Vec<StoredMessage>, RelayError> {
        self.store
            .pending(mailbox, after_seq, limit, max_bytes, self.now_ms())
            .await
            .map_err(|e| internal(&e))
    }

    fn rate_check(&self, key: &str, max: usize, window_ms: u64) -> bool {
        lock(&self.rates).allow(key, max, window_ms, self.now_ms())
    }

    /// Run periodic maintenance: expire rows, rate-limit windows and replay
    /// entries, refresh the storage gauges, and once an hour delete idle
    /// groups.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn purge(&self) -> Result<PurgeStats, RelayError> {
        let now = self.now_ms();
        lock(&self.rates).sweep(now);
        lock(&self.replays).sweep(now / 1000);
        lock(&self.live_invites).sweep(now);
        lock(&self.live_groups).sweep(now);
        let stats = self
            .store
            .purge_expired(now)
            .await
            .map_err(|e| internal(&e))?;
        let used = self.store.storage_bytes().await.map_err(|e| internal(&e))?;
        self.metrics.storage_bytes.store(used, Ordering::Relaxed);
        self.metrics.storage_full.store(
            u64::from(used >= self.limits.storage_high_water),
            Ordering::Relaxed,
        );
        let last = self.idle_swept_at.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= IDLE_SWEEP_EVERY_MS {
            self.idle_swept_at.store(now, Ordering::Relaxed);
            let deleted = self.sweep_idle_groups().await?;
            if deleted > 0 {
                tracing::info!(groups = deleted, "idle groups deleted");
            }
        }
        self.refresh_counts().await?;
        Ok(stats)
    }

    /// Whether any connection is authenticated as `mailbox` now.
    fn connected(&self, mailbox: &str) -> bool {
        lock(&self.hub.waiters).contains_key(mailbox)
    }

    /// Delete every group that is idle (SPEC §8.3, "Idle groups"): no
    /// accepted send for [`Quotas::group_idle`] plus
    /// [`ACTIVITY_GRANULARITY`] (the activity time is that coarse), and no
    /// member connected. Returns how many were deleted. Their ids are not
    /// kept.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn sweep_idle_groups(&self) -> Result<u64, RelayError> {
        let idle_ms = u64::try_from(
            self.quotas
                .group_idle
                .saturating_add(ACTIVITY_GRANULARITY)
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let Some(cutoff) = self.now_ms().checked_sub(idle_ms) else {
            return Ok(0);
        };
        let mut after = String::new();
        let mut deleted = 0;
        loop {
            let page = self
                .store
                .idle_groups(cutoff, &after, IDLE_SWEEP_PAGE)
                .await
                .map_err(|e| internal(&e))?;
            let full = page.len() == usize::try_from(IDLE_SWEEP_PAGE).unwrap_or(usize::MAX);
            for g in &page {
                // A connected member may still use the group.
                if g.members.iter().any(|m| self.connected(m)) {
                    continue;
                }
                if self
                    .store
                    .delete_idle_group(&g.group_id, cutoff)
                    .await
                    .map_err(|e| internal(&e))?
                {
                    deleted += 1;
                    Metrics::inc(&self.metrics.idle_groups_deleted);
                }
            }
            match page.last() {
                Some(last) if full => after.clone_from(&last.group_id),
                _ => return Ok(deleted),
            }
        }
    }

    /// Handle one authenticated client frame. Returns the reply frame, if
    /// any. An accepted knock is written at once (the WebSocket path queues
    /// it for the knock worker instead).
    pub async fn handle(&self, mailbox: &str, frame: ClientFrame) -> Option<ServerFrame> {
        let (reply, knock) = self.handle_deferred(mailbox, None, frame).await;
        if let Some(k) = knock {
            self.forward_knock(k).await;
        }
        reply
    }

    /// [`Relay::handle`] for a connection from `ip` (`None`: unknown), which
    /// `group.create`'s per-address limit counts by.
    pub async fn handle_from(
        &self,
        mailbox: &str,
        ip: Option<IpAddr>,
        frame: ClientFrame,
    ) -> Option<ServerFrame> {
        let (reply, knock) = self.handle_deferred(mailbox, ip, frame).await;
        if let Some(k) = knock {
            self.forward_knock(k).await;
        }
        reply
    }

    /// [`Relay::handle_from`], except that an accepted knock, forwarded or
    /// dropped, comes back to be queued with [`Relay::queue_knock`]. Both
    /// take the same path up to the knock worker's write, so neither the
    /// reply's timing nor the store's load right after it says which it was
    /// (SPEC §8.3).
    pub async fn handle_deferred(
        &self,
        mailbox: &str,
        ip: Option<IpAddr>,
        frame: ClientFrame,
    ) -> (Option<ServerFrame>, Option<KnockForward>) {
        let mut knock = None;
        let (corr, result) = match frame {
            ClientFrame::Ack { msg_id } => {
                // Not counted in frames_total: an owner's ack of a delivered
                // knock would tell a forwarded knock from a dropped one.
                if let Err(e) = self.store.ack(mailbox, &msg_id).await {
                    tracing::error!(error = %e, "ack failed");
                }
                return (None, None);
            }
            ClientFrame::Auth { .. } => (
                None,
                Err(RelayError::new(
                    ErrorCode::BadRequest,
                    "already authenticated",
                )),
            ),
            ClientFrame::Send { env } => {
                let id = env.msg_id.clone();
                (Some(id), self.send(mailbox, env).await)
            }
            ClientFrame::Join { invite_id, env } => {
                let id = env.msg_id.clone();
                (Some(id), self.join(mailbox, &invite_id, env).await)
            }
            ClientFrame::Knock { door_id, env } => {
                let id = env.msg_id.clone();
                let r = self.knock(mailbox, &door_id, env).await;
                (
                    Some(id),
                    r.map(|forward| {
                        knock = Some(forward);
                        String::new()
                    }),
                )
            }
            ClientFrame::GroupCreate {
                group_id,
                epoch,
                msg_id,
            } => {
                let corr = msg_id.unwrap_or_else(|| group_id.clone());
                let r = self.group_create(mailbox, ip, &group_id, epoch).await;
                (Some(corr), r.map(|()| String::new()))
            }
            ClientFrame::InviteConsume { invite_id, msg_id } => {
                let corr = msg_id.unwrap_or_else(|| invite_id.clone());
                let r = self.consume(mailbox, &invite_id).await;
                (Some(corr), r.map(|()| String::new()))
            }
        };
        self.metrics.frame_in();
        let reply = match result {
            Ok(_) => ServerFrame::Accepted {
                msg_id: corr.unwrap_or_default(),
            },
            Err(e) => self.error_frame(corr, e),
        };
        (Some(reply), knock)
    }

    /// Write a knock answered by [`Relay::handle_deferred`]: queue it for its
    /// door's owner, or nothing for a dropped one. A full owner queue or a
    /// repeated `msg_id` drops it silently.
    pub async fn forward_knock(&self, knock: KnockForward) {
        let Some((owner, msg)) = knock.write else {
            return;
        };
        match self
            .store
            .deliver_direct(Kind::Knock, &owner, &msg, &self.limits, self.now_ms())
            .await
        {
            Ok(DirectOutcome::Delivered) => {
                tracing::debug!("knock forwarded");
                self.wake([&owner]);
            }
            Ok(DirectOutcome::Duplicate) => tracing::debug!("knock repeated"),
            // Unlike `join`: the knocker was told `accepted` either way. A
            // knock isn't charged to its sender, so it is never over budget.
            Ok(DirectOutcome::QuotaExceeded | DirectOutcome::OverBudget) => {
                tracing::debug!(reason = "queue_full", "knock dropped");
            }
            Ok(DirectOutcome::StorageFull) => {
                self.metrics.storage_full.store(1, Ordering::Relaxed);
                tracing::debug!(reason = "storage_full", "knock dropped");
            }
            Err(e) => {
                let _ = internal(&e);
            }
        }
    }

    pub(crate) fn error_frame(&self, msg_id: Option<String>, e: RelayError) -> ServerFrame {
        self.metrics.error(e.code);
        tracing::debug!(code = e.code.as_str(), "request rejected");
        ServerFrame::Error {
            msg_id,
            code: e.code,
            detail: e.detail,
            current_epoch: e.current_epoch,
        }
    }

    async fn send(&self, mailbox: &str, env: Envelope) -> Result<String, RelayError> {
        use RelayError as E;
        if env.sender != mailbox {
            return Err(E::new(
                ErrorCode::BadRequest,
                "sender does not match the authenticated mailbox",
            ));
        }
        match env.kind {
            Kind::JoinRequest => return Err(E::new(ErrorCode::BadRequest, "use the join frame")),
            Kind::Knock => return Err(E::new(ErrorCode::BadRequest, "use the knock frame")),
            _ => {}
        }
        if !self.rate_check(&format!("mb:{mailbox}"), self.limits.sends_per_sec, 1000) {
            return Err(E::new(ErrorCode::RateLimited, "send rate exceeded"));
        }
        let json = serde_json::to_string(&env)
            .map_err(|_| E::new(ErrorCode::Internal, "internal error"))?;
        let msg = NewMessage {
            msg_id: env.msg_id.clone(),
            sender: mailbox.to_owned(),
            json,
        };
        let routing = env.routing.clone().unwrap_or_default();
        let group_id = env.group_id.as_deref().unwrap_or_default();
        let send = GroupSend {
            kind: env.kind,
            group_id,
            sender: mailbox,
            epoch: env.epoch.unwrap_or(0),
            add: &routing.add,
            remove: &routing.remove,
            to: &env.to,
            msg: &msg,
            ct_bytes: env.ct.len().saturating_mul(3) / 4,
        };
        let outcome = self
            .store
            .deliver_group(&send, &self.limits, self.now_ms())
            .await
            .map_err(|e| internal(&e))?;
        match outcome {
            GroupOutcome::Delivered {
                recipients,
                overflowed,
                ..
            } => {
                Metrics::inc(&self.metrics.accepted);
                if env.kind == Kind::Commit {
                    Metrics::inc(&self.metrics.commits);
                }
                self.metrics.delivered(recipients.len());
                tracing::debug!(
                    group = %log_tag(group_id),
                    sender = %log_tag(mailbox),
                    kind = ?env.kind,
                    recipients = recipients.len(),
                    "accepted"
                );
                if !overflowed.is_empty() {
                    self.metrics.overflows(overflowed.len());
                    tracing::warn!(
                        group = %log_tag(group_id),
                        members = overflowed.len(),
                        "mailbox queues full; overflow markers queued"
                    );
                }
                self.wake(recipients.iter().chain(&overflowed));
                Ok(env.msg_id)
            }
            GroupOutcome::Duplicate => {
                Metrics::inc(&self.metrics.duplicates);
                Ok(env.msg_id)
            }
            GroupOutcome::UnknownGroup => Err(E::new(ErrorCode::UnknownGroup, "unknown group")),
            GroupOutcome::NotMember => {
                Err(E::new(ErrorCode::NotMember, "not a member of the group"))
            }
            GroupOutcome::EpochConflict { current_epoch } => Err(E {
                current_epoch: Some(current_epoch),
                ..E::new(ErrorCode::EpochConflict, "epoch is not current")
            }),
            GroupOutcome::GroupFull => Err(E::new(
                ErrorCode::QuotaExceeded,
                format!("group is limited to {} instances", self.limits.group_max),
            )),
            GroupOutcome::NotAwaitingWelcome => Err(E::new(
                ErrorCode::BadRequest,
                "a Welcome goes only to a mailbox the sender's commit added, once",
            )),
            GroupOutcome::QueueFull => Err(E::new(
                ErrorCode::QuotaExceeded,
                "a recipient's queue is full; retry later",
            )),
            GroupOutcome::OverBudget => Err(Self::over_budget()),
            GroupOutcome::StorageFull => Err(self.storage_full()),
        }
    }

    async fn group_create(
        &self,
        mailbox: &str,
        ip: Option<IpAddr>,
        group_id: &str,
        epoch: u64,
    ) -> Result<(), RelayError> {
        use RelayError as E;
        if !is_id16(group_id) {
            return Err(E::new(ErrorCode::BadRequest, "malformed group_id"));
        }
        if epoch != 0 {
            return Err(E::new(
                ErrorCode::BadRequest,
                "a new group starts at epoch 0",
            ));
        }
        if !self.rate_check(&format!("mb:{mailbox}"), self.limits.sends_per_sec, 1000) {
            return Err(E::new(ErrorCode::RateLimited, "send rate exceeded"));
        }
        // A repeat by its creator (its `accepted` was lost) is accepted
        // again, and counts against no limit (SPEC §8.3).
        if self
            .store
            .group_creator(group_id)
            .await
            .map_err(|e| internal(&e))?
            .is_some_and(|by| by == mailbox)
        {
            return Ok(());
        }
        // A quota, not a rate: a daemon backs off from `rate_limited` for
        // seconds, and this one lasts up to a day.
        let quota = self.quotas.groups_per_mailbox;
        if !self.rate_check(&format!("gc:{mailbox}"), quota.max, window_ms(quota)) {
            return Err(E::new(
                ErrorCode::QuotaExceeded,
                format!(
                    "a mailbox creates at most {} groups per {} hours",
                    quota.max,
                    quota.per.as_secs() / 3600
                ),
            ));
        }
        // A group counts for its address for the idle period: an older one
        // is gone unless its members use it.
        let idle = u64::try_from(
            self.quotas
                .group_idle
                .saturating_add(ACTIVITY_GRANULARITY)
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let until = self.now_ms().saturating_add(idle);
        self.reserve(Held::Group, ip, until)?;
        let created = self
            .store
            .create_group(group_id, mailbox, self.now_ms())
            .await
            .map_err(|e| internal(&e));
        if !matches!(created, Ok(CreateGroupOutcome::Created)) {
            self.undo(Held::Group, ip, until);
        }
        match created? {
            CreateGroupOutcome::Created | CreateGroupOutcome::Yours => Ok(()),
            CreateGroupOutcome::Exists => {
                Err(E::new(ErrorCode::BadRequest, "group already exists"))
            }
        }
    }

    async fn consume(&self, mailbox: &str, invite_id: &str) -> Result<(), RelayError> {
        use RelayError as E;
        match self
            .store
            .consume_invite(invite_id, mailbox, self.now_ms())
            .await
            .map_err(|e| internal(&e))?
        {
            ConsumeOutcome::Consumed { .. } => {
                Metrics::inc(&self.metrics.invites_consumed);
                Ok(())
            }
            ConsumeOutcome::NotFound | ConsumeOutcome::NotOpen => {
                Err(E::new(ErrorCode::InviteNotOpen, "invite is not open"))
            }
            ConsumeOutcome::NotInviter => Err(E::new(
                ErrorCode::AuthFailed,
                "only the inviter mailbox may consume an invite",
            )),
        }
    }

    async fn join(
        &self,
        mailbox: &str,
        invite_id: &str,
        env: Envelope,
    ) -> Result<String, RelayError> {
        use RelayError as E;
        if env.kind != Kind::JoinRequest {
            return Err(E::new(
                ErrorCode::BadRequest,
                "join needs a join_request envelope",
            ));
        }
        if env.sender != mailbox {
            return Err(E::new(
                ErrorCode::BadRequest,
                "sender does not match the authenticated mailbox",
            ));
        }
        if !is_id16(invite_id) {
            return Err(E::new(ErrorCode::BadRequest, "malformed invite_id"));
        }
        if !self.rate_check(&format!("mb:{mailbox}"), self.limits.sends_per_sec, 1000) {
            return Err(E::new(ErrorCode::RateLimited, "send rate exceeded"));
        }
        let invite = self
            .store
            .get_invite(invite_id)
            .await
            .map_err(|e| internal(&e))?
            .filter(|i| i.status(self.now_secs()) == InviteStatus::Open)
            .ok_or_else(|| E::new(ErrorCode::InviteNotOpen, "invite is not open"))?;
        if !self.rate_check(
            &format!("inv:{invite_id}"),
            self.limits.joins_per_min,
            60_000,
        ) {
            return Err(E::new(
                ErrorCode::RateLimited,
                "too many join requests for this invite",
            ));
        }
        let msg = NewMessage {
            msg_id: env.msg_id.clone(),
            sender: mailbox.to_owned(),
            json: serde_json::to_string(&env)
                .map_err(|_| E::new(ErrorCode::Internal, "internal error"))?,
        };
        match self
            .store
            .deliver_direct(
                Kind::JoinRequest,
                &invite.inviter_mailbox,
                &msg,
                &self.limits,
                self.now_ms(),
            )
            .await
            .map_err(|e| internal(&e))?
        {
            DirectOutcome::Delivered => {
                Metrics::inc(&self.metrics.accepted);
                Metrics::inc(&self.metrics.joins_forwarded);
                self.metrics.delivered(1);
                tracing::debug!(invite = %log_tag(invite_id), "join forwarded");
                self.wake([&invite.inviter_mailbox]);
                Ok(env.msg_id)
            }
            DirectOutcome::Duplicate => {
                Metrics::inc(&self.metrics.duplicates);
                Ok(env.msg_id)
            }
            DirectOutcome::QuotaExceeded => Err(E::new(
                ErrorCode::QuotaExceeded,
                "the inviter queue is full",
            )),
            DirectOutcome::OverBudget => Err(Self::over_budget()),
            DirectOutcome::StorageFull => Err(self.storage_full()),
        }
    }

    /// Forward a sealed knock to its door's owner (ADR-006, "Relay rules for
    /// `knock`"). The knocker hears `accepted`, `door_not_open` or
    /// `rate_limited` and nothing else: a busy door or a full owner queue
    /// drops the knock behind an `accepted`. Nothing here is logged with an
    /// identifier. An accepted knock that isn't dropped comes back to be
    /// queued once the knocker has its answer ([`Relay::forward_knock`]).
    async fn knock(
        &self,
        mailbox: &str,
        door_id: &str,
        env: Envelope,
    ) -> Result<KnockForward, RelayError> {
        use RelayError as E;
        if env.kind != Kind::Knock {
            return Err(E::new(
                ErrorCode::BadRequest,
                "knock needs a knock envelope",
            ));
        }
        if env.sender != mailbox {
            return Err(E::new(
                ErrorCode::BadRequest,
                "sender does not match the authenticated mailbox",
            ));
        }
        if env.door_id.as_deref() != Some(door_id) {
            return Err(E::new(
                ErrorCode::BadRequest,
                "door_id does not match the envelope",
            ));
        }
        if !self.rate_check(&format!("mb:{mailbox}"), self.limits.sends_per_sec, 1000) {
            return Err(E::new(ErrorCode::RateLimited, "send rate exceeded"));
        }
        let door = self
            .store
            .get_door(door_id)
            .await
            .map_err(|e| internal(&e))?
            .filter(|d| d.is_open(self.now_secs()))
            .ok_or_else(|| E::new(ErrorCode::DoorNotOpen, "door is not open"))?;
        // Limits on the knocker's own behaviour: the only ones it is told of.
        let pair = self.limits.knocks_per_door_sender;
        let sender = self.limits.knocks_per_sender;
        let pair_key = format!("kp:{door_id}:{mailbox}");
        let sender_key = format!("ks:{mailbox}");
        if !lock(&self.rates).allow_all(
            &[
                (&pair_key, pair.max, window_ms(pair)),
                (&sender_key, sender.max, window_ms(sender)),
            ],
            self.now_ms(),
        ) {
            return Err(E::new(ErrorCode::RateLimited, "too many knocks"));
        }
        Metrics::inc(&self.metrics.accepted);
        Metrics::inc(&self.metrics.knocks_accepted);
        // Built before the busy check, so a dropped knock costs the same.
        let msg = NewMessage {
            msg_id: env.msg_id.clone(),
            sender: mailbox.to_owned(),
            json: serde_json::to_string(&env)
                .map_err(|_| E::new(ErrorCode::Internal, "internal error"))?,
        };
        let busy = self.limits.knocks_per_door;
        if !self.rate_check(&format!("kd:{door_id}"), busy.max, window_ms(busy)) {
            tracing::debug!(reason = "door_busy", "knock dropped");
            return Ok(KnockForward {
                door: door_id.to_owned(),
                write: None,
            });
        }
        Ok(KnockForward {
            door: door_id.to_owned(),
            write: Some((door.owner_mailbox, msg)),
        })
    }

    /// Register a door on behalf of the authenticated `mailbox` (ADR-006).
    ///
    /// # Errors
    ///
    /// `bad_request` for invalid fields or an id already registered,
    /// `auth_failed` if `owner_mailbox` is not the caller, `quota_exceeded`
    /// if the mailbox already holds the maximum number of open doors.
    pub async fn create_door(
        &self,
        mailbox: &str,
        req: NewDoorRequest,
    ) -> Result<DoorRecord, RelayError> {
        use RelayError as E;
        let bad = |d: &str| Err(E::new(ErrorCode::BadRequest, d));
        if !is_id16(&req.door_id) {
            return bad("malformed door_id");
        }
        if !is_mailbox_id(&req.owner_mailbox) {
            return bad("malformed owner_mailbox");
        }
        if req.owner_mailbox != mailbox {
            return Err(E::new(
                ErrorCode::AuthFailed,
                "owner_mailbox does not match the authenticated mailbox",
            ));
        }
        let now = self.now_secs();
        if req.expires_at <= now || req.expires_at > now + self.limits.door_max_ttl.as_secs() {
            return bad("expires_at must be in the future and at most 7 days away");
        }
        let door = DoorRecord {
            door_id: req.door_id,
            owner_mailbox: req.owner_mailbox,
            expires_at: req.expires_at,
            closed: false,
        };
        match self
            .store
            .create_door(&door, self.limits.doors_per_mailbox, self.now_ms())
            .await
            .map_err(|e| internal(&e))?
        {
            CreateDoorOutcome::Created => {
                Metrics::inc(&self.metrics.doors_registered);
                tracing::debug!("door registered");
                Ok(door)
            }
            CreateDoorOutcome::Exists => bad("door already exists"),
            CreateDoorOutcome::TooMany => Err(E::new(
                ErrorCode::QuotaExceeded,
                format!(
                    "a mailbox holds at most {} open doors",
                    self.limits.doors_per_mailbox
                ),
            )),
        }
    }

    /// Close a door on behalf of the authenticated `mailbox`, at once.
    ///
    /// # Errors
    ///
    /// `door_not_open` if unknown, `auth_failed` if not the owner.
    pub async fn close_door(&self, mailbox: &str, door_id: &str) -> Result<(), RelayError> {
        let unknown = || RelayError::new(ErrorCode::DoorNotOpen, "unknown door");
        if !is_id16(door_id) {
            return Err(unknown());
        }
        match self
            .store
            .close_door(door_id, mailbox)
            .await
            .map_err(|e| internal(&e))?
        {
            CloseDoorOutcome::Closed => {
                Metrics::inc(&self.metrics.doors_closed);
                tracing::debug!("door closed");
                Ok(())
            }
            CloseDoorOutcome::NotFound => Err(unknown()),
            CloseDoorOutcome::NotOwner => Err(RelayError::new(
                ErrorCode::AuthFailed,
                "only the owner mailbox may close a door",
            )),
        }
    }

    /// Register an invite on behalf of the authenticated `mailbox`.
    ///
    /// # Errors
    ///
    /// See [`Relay::create_invite_from`].
    pub async fn create_invite(
        &self,
        mailbox: &str,
        req: NewInviteRequest,
    ) -> Result<InviteRecord, RelayError> {
        self.create_invite_from(mailbox, None, req).await
    }

    /// Register an invite on behalf of the authenticated `mailbox`, from
    /// `ip` (`None`: unknown).
    ///
    /// # Errors
    ///
    /// `bad_request` for invalid fields (the three texts must be one-line
    /// text, SPEC §4.2) or a duplicate id, `auth_failed` if
    /// `inviter_mailbox` is not the caller, `quota_exceeded` if the mailbox
    /// already holds the maximum number of open invites, or the address or
    /// the relay as many invite rows as it takes.
    pub async fn create_invite_from(
        &self,
        mailbox: &str,
        ip: Option<IpAddr>,
        req: NewInviteRequest,
    ) -> Result<InviteRecord, RelayError> {
        use RelayError as E;
        let bad = |d: &str| Err(E::new(ErrorCode::BadRequest, d));
        if !is_id16(&req.invite_id) {
            return bad("malformed invite_id");
        }
        if !is_mailbox_id(&req.inviter_mailbox) {
            return bad("malformed inviter_mailbox");
        }
        if req.inviter_mailbox != mailbox {
            return Err(E::new(
                ErrorCode::AuthFailed,
                "inviter_mailbox does not match the authenticated mailbox",
            ));
        }
        if req.protocol.is_some_and(|p| p != 0) {
            return bad("unsupported protocol version");
        }
        if req.group_name.is_empty() || !text_ok(&req.group_name, MAX_NAME_CHARS) {
            return bad("invalid group_name");
        }
        if req.inviter_name.is_empty() || !text_ok(&req.inviter_name, MAX_NAME_CHARS) {
            return bad("invalid inviter_name");
        }
        if !text_ok(&req.purpose, MAX_PURPOSE_CHARS) {
            return bad("invalid purpose");
        }
        if req.max_uses == 0 || req.max_uses > MAX_INVITE_USES {
            return bad("max_uses out of range");
        }
        let now = self.now_secs();
        if req.expires_at <= now || req.expires_at > now + self.limits.invite_max_ttl.as_secs() {
            return bad("expires_at must be in the future and at most 7 days away");
        }
        let record = InviteRecord {
            invite_id: req.invite_id,
            group_name: req.group_name,
            inviter_name: req.inviter_name,
            purpose: req.purpose,
            expires_at: req.expires_at,
            max_uses: req.max_uses,
            uses_left: req.max_uses,
            member_count: req.member_count,
            inviter_mailbox: req.inviter_mailbox,
            revoked: false,
        };
        let max_open = self.quotas.open_invites_per_mailbox;
        // The row is held until `expires_at` plus the grace period.
        let until = record
            .expires_at
            .saturating_mul(1000)
            .saturating_add(crate::sqlite::INVITE_GRACE_MS);
        self.reserve(Held::Invite, ip, until)?;
        let created = self
            .store
            .create_invite(&record, max_open, self.now_ms())
            .await
            .map_err(|e| internal(&e));
        if !matches!(created, Ok(CreateInviteOutcome::Created)) {
            self.undo(Held::Invite, ip, until);
        }
        match created? {
            CreateInviteOutcome::Created => {}
            CreateInviteOutcome::Exists => return bad("invite already exists"),
            CreateInviteOutcome::TooMany => {
                return Err(E::new(
                    ErrorCode::QuotaExceeded,
                    format!("a mailbox holds at most {max_open} open invites; revoke one first"),
                ));
            }
        }
        Metrics::inc(&self.metrics.invites_created);
        Ok(record)
    }

    /// Look up a door, for authorizing a signed request on it.
    ///
    /// # Errors
    ///
    /// `door_not_open` if the relay doesn't hold it.
    pub async fn door(&self, door_id: &str) -> Result<DoorRecord, RelayError> {
        let unknown = || RelayError::new(ErrorCode::DoorNotOpen, "unknown door");
        if !is_id16(door_id) {
            return Err(unknown());
        }
        self.store
            .get_door(door_id)
            .await
            .map_err(|e| internal(&e))?
            .ok_or_else(unknown)
    }

    /// Look up an invite (public).
    ///
    /// # Errors
    ///
    /// `invite_not_open` if unknown.
    pub async fn invite(&self, invite_id: &str) -> Result<InviteRecord, RelayError> {
        if !is_id16(invite_id) {
            return Err(RelayError::new(ErrorCode::InviteNotOpen, "unknown invite"));
        }
        self.store
            .get_invite(invite_id)
            .await
            .map_err(|e| internal(&e))?
            .ok_or_else(|| RelayError::new(ErrorCode::InviteNotOpen, "unknown invite"))
    }

    /// Revoke an invite on behalf of the authenticated `mailbox`.
    ///
    /// # Errors
    ///
    /// `invite_not_open` if unknown, `auth_failed` if not the inviter.
    pub async fn revoke_invite(&self, mailbox: &str, invite_id: &str) -> Result<(), RelayError> {
        if !is_id16(invite_id) {
            return Err(RelayError::new(ErrorCode::InviteNotOpen, "unknown invite"));
        }
        match self
            .store
            .revoke_invite(invite_id, mailbox)
            .await
            .map_err(|e| internal(&e))?
        {
            RevokeOutcome::Revoked => Ok(()),
            RevokeOutcome::NotFound => {
                Err(RelayError::new(ErrorCode::InviteNotOpen, "unknown invite"))
            }
            RevokeOutcome::NotInviter => Err(RelayError::new(
                ErrorCode::AuthFailed,
                "only the inviter mailbox may revoke an invite",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_open_guards_count_up_and_each_drop_counts_down_once() {
        let m = Metrics::default();
        let value = |m: &Metrics| m.ws_open.load(Ordering::Relaxed);
        let a = m.try_ws_open(usize::MAX).unwrap();
        let b = m.try_ws_open(usize::MAX).unwrap();
        assert_eq!(value(&m), 2);
        drop(a);
        assert_eq!(value(&m), 1);
        drop(b);
        assert_eq!(value(&m), 0);
    }

    #[test]
    fn a_count_given_back_after_a_recount_stays_at_zero() {
        let c = AtomicU64::new(1);
        dec(&c);
        dec(&c);
        assert_eq!(c.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_window_refills_only_after_its_own_length() {
        let mut r = Rates::default();
        assert!(r.allow("k", 1, 600_000, 0));
        assert!(!r.allow("k", 1, 600_000, 1));
        // A sweep at two minutes keeps a ten-minute window.
        r.sweep(120_000);
        assert!(!r.allow("k", 1, 600_000, 599_999));
        assert!(r.allow("k", 1, 600_000, 600_000));
        r.sweep(1_200_000);
        assert!(r.windows.is_empty());
    }

    #[test]
    fn a_refused_request_uses_up_no_budget() {
        let mut r = Rates::default();
        assert!(r.allow("b", 1, 1000, 0));
        // "a" has room, "b" does not: neither is charged.
        assert!(!r.allow_all(&[("a", 1, 1000), ("b", 1, 1000)], 1));
        assert!(r.allow("a", 1, 1000, 2));
        assert!(r.allow_all(&[("c", 1, 1000), ("b", 1, 1000)], 1000));
        assert!(!r.allow("c", 1, 1000, 1001));
    }
}
