//! The relay service: Delivery Service rules, invite and door registries and
//! mailbox hub. Transport-agnostic; `ws.rs` and `rest.rs` are thin adapters.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use agentconnect_core::clock::Clock;
use serde::Deserialize;
use tokio::sync::Notify;

use crate::proto::{
    ClientFrame, Envelope, ErrorCode, Kind, ServerFrame, is_id16, is_mailbox_id, log_tag,
};
use crate::store::{
    CloseDoorOutcome, ConsumeOutcome, CreateDoorOutcome, CreateGroupOutcome, DirectOutcome,
    DoorRecord, GroupOutcome, GroupSend, InviteRecord, InviteStatus, Limits, NewMessage,
    PurgeStats, RevokeOutcome, Store, StoredMessage, Window,
};

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
    errors: [AtomicU64; ErrorCode::ALL.len()],
}

impl Metrics {
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

    /// Prometheus text exposition.
    #[must_use]
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
}

/// Wakes connections when their mailbox has new messages.
#[derive(Debug, Default)]
struct Hub {
    next: AtomicU64,
    waiters: Mutex<Waiters>,
}

type Waiters = HashMap<String, Vec<(u64, Arc<Notify>)>>;

/// A connection's registration for wake-ups; unregisters on drop.
#[derive(Debug)]
pub struct Registration {
    hub: Arc<Hub>,
    mailbox: String,
    id: u64,
    /// Fires when new messages are queued for the mailbox.
    pub notify: Arc<Notify>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut waiters = lock(&self.hub.waiters);
        if let Some(list) = waiters.get_mut(&self.mailbox) {
            list.retain(|(id, _)| *id != self.id);
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

fn window_ms(w: Window) -> u64 {
    u64::try_from(w.per.as_millis()).unwrap_or(u64::MAX)
}

/// Maximum number of live entries in the REST replay cache.
pub const REPLAY_CACHE_CAP: usize = 10_000;

/// Signatures of recently accepted signed REST requests.
#[derive(Debug, Default)]
struct ReplayCache {
    /// (mailbox, signature) -> last second at which the request would still
    /// have been inside the accepted window.
    seen: HashMap<(String, String), u64>,
}

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
}

impl RelayError {
    /// An error without an epoch.
    #[must_use]
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            current_epoch: None,
        }
    }
}

fn internal(e: &dyn std::fmt::Display) -> RelayError {
    tracing::error!(error = %e, "storage failure");
    RelayError::new(ErrorCode::Internal, "internal error")
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

fn text_ok(s: &str, max_chars: usize) -> bool {
    s.chars().count() <= max_chars && !has_control(s)
}

/// The relay service.
pub struct Relay<S: Store> {
    store: S,
    clock: Arc<dyn Clock>,
    host: String,
    limits: Limits,
    hub: Arc<Hub>,
    rates: Mutex<Rates>,
    replays: Mutex<ReplayCache>,
    replay_cap: usize,
    metrics: Metrics,
}

impl<S: Store> Relay<S> {
    /// Build a relay. `host` is the string clients sign into their auth
    /// (the relay's public host name).
    pub fn new(store: S, clock: Arc<dyn Clock>, host: impl Into<String>, limits: Limits) -> Self {
        Self {
            store,
            clock,
            host: host.into(),
            limits,
            hub: Arc::default(),
            rates: Mutex::default(),
            replays: Mutex::default(),
            replay_cap: REPLAY_CACHE_CAP,
            metrics: Metrics::default(),
        }
    }

    /// Override the replay-cache capacity (tests).
    #[must_use]
    pub fn with_replay_cap(mut self, cap: usize) -> Self {
        self.replay_cap = cap;
        self
    }

    /// Record a verified signed REST request and refuse a repeat.
    ///
    /// Entries live until the request would have left the accepted window.
    /// Expired entries are evicted first; if the cache is still full the new
    /// request is refused rather than evicting a live entry.
    ///
    /// # Errors
    ///
    /// `auth_failed` for a replay, `rate_limited` when the cache is full.
    pub fn check_replay(&self, creds: &crate::auth::RestCredentials) -> Result<(), RelayError> {
        let now = self.now_secs();
        let mut cache = lock(&self.replays);
        let key = (creds.mailbox.clone(), creds.sig.clone());
        if cache.seen.get(&key).is_some_and(|until| *until >= now) {
            return Err(RelayError::new(
                ErrorCode::AuthFailed,
                "request already used",
            ));
        }
        if cache.seen.len() >= self.replay_cap {
            cache.seen.retain(|_, until| *until >= now);
            if cache.seen.len() >= self.replay_cap {
                return Err(RelayError::new(
                    ErrorCode::RateLimited,
                    "too many signed requests; retry later",
                ));
            }
        }
        cache.seen.insert(
            key,
            creds.ts.saturating_add(crate::auth::REST_MAX_SKEW_SECS),
        );
        Ok(())
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

    /// Register a connection for wake-ups on `mailbox`.
    #[must_use]
    pub fn register(&self, mailbox: &str) -> Registration {
        let id = self.hub.next.fetch_add(1, Ordering::Relaxed);
        let notify = Arc::new(Notify::new());
        lock(&self.hub.waiters)
            .entry(mailbox.to_owned())
            .or_default()
            .push((id, Arc::clone(&notify)));
        Registration {
            hub: Arc::clone(&self.hub),
            mailbox: mailbox.to_owned(),
            id,
            notify,
        }
    }

    fn wake<'a>(&self, mailboxes: impl IntoIterator<Item = &'a String>) {
        let waiters = lock(&self.hub.waiters);
        for m in mailboxes {
            for (_, n) in waiters.get(m).into_iter().flatten() {
                n.notify_one();
            }
        }
    }

    /// Unexpired queued messages after `after_seq`, oldest first.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn pending(
        &self,
        mailbox: &str,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<StoredMessage>, RelayError> {
        self.store
            .pending(mailbox, after_seq, limit, self.now_ms())
            .await
            .map_err(|e| internal(&e))
    }

    fn rate_check(&self, key: &str, max: usize, window_ms: u64) -> bool {
        lock(&self.rates).allow(key, max, window_ms, self.now_ms())
    }

    /// Run periodic maintenance: expire rows and rate-limit windows.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn purge(&self) -> Result<PurgeStats, RelayError> {
        let now = self.now_ms();
        lock(&self.rates).sweep(now);
        self.store
            .purge_expired(now)
            .await
            .map_err(|e| internal(&e))
    }

    /// Handle one authenticated client frame. Returns the reply frame, if any.
    pub async fn handle(&self, mailbox: &str, frame: ClientFrame) -> Option<ServerFrame> {
        self.metrics.frame_in();
        let (corr, result) = match frame {
            ClientFrame::Ack { msg_id } => {
                if let Err(e) = self.store.ack(mailbox, &msg_id).await {
                    tracing::error!(error = %e, "ack failed");
                }
                return None;
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
                (Some(id), self.knock(mailbox, &door_id, env).await)
            }
            ClientFrame::GroupCreate {
                group_id,
                epoch,
                msg_id,
            } => {
                let corr = msg_id.unwrap_or_else(|| group_id.clone());
                let r = self.group_create(mailbox, &group_id, epoch).await;
                (Some(corr), r.map(|()| String::new()))
            }
            ClientFrame::InviteConsume { invite_id, msg_id } => {
                let corr = msg_id.unwrap_or_else(|| invite_id.clone());
                let r = self.consume(mailbox, &invite_id).await;
                (Some(corr), r.map(|()| String::new()))
            }
        };
        Some(match result {
            Ok(_) => ServerFrame::Accepted {
                msg_id: corr.unwrap_or_default(),
            },
            Err(e) => self.error_frame(corr, e),
        })
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
        }
    }

    async fn group_create(
        &self,
        mailbox: &str,
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
        match self
            .store
            .create_group(group_id, mailbox, self.now_ms())
            .await
            .map_err(|e| internal(&e))?
        {
            CreateGroupOutcome::Created => Ok(()),
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
            .deliver_direct(&invite.inviter_mailbox, &msg, &self.limits, self.now_ms())
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
        }
    }

    /// Forward a sealed knock to its door's owner (ADR-006, "Relay rules for
    /// `knock`"). The knocker hears `accepted`, `door_not_open` or
    /// `rate_limited` and nothing else: a busy door or a full owner queue
    /// drops the knock behind an `accepted`. Nothing here is logged with an
    /// identifier.
    async fn knock(
        &self,
        mailbox: &str,
        door_id: &str,
        env: Envelope,
    ) -> Result<String, RelayError> {
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
        let busy = self.limits.knocks_per_door;
        if !self.rate_check(&format!("kd:{door_id}"), busy.max, window_ms(busy)) {
            tracing::debug!(reason = "door_busy", "knock dropped");
            return Ok(env.msg_id);
        }
        let msg = NewMessage {
            msg_id: env.msg_id.clone(),
            sender: mailbox.to_owned(),
            json: serde_json::to_string(&env)
                .map_err(|_| E::new(ErrorCode::Internal, "internal error"))?,
        };
        match self
            .store
            .deliver_direct(&door.owner_mailbox, &msg, &self.limits, self.now_ms())
            .await
            .map_err(|e| internal(&e))?
        {
            DirectOutcome::Delivered => {
                tracing::debug!("knock forwarded");
                self.wake([&door.owner_mailbox]);
            }
            DirectOutcome::Duplicate => tracing::debug!("knock repeated"),
            // Unlike `join`: a refusal would tell the knocker that the
            // owner's queue is full.
            DirectOutcome::QuotaExceeded => {
                tracing::debug!(reason = "queue_full", "knock dropped");
            }
        }
        Ok(env.msg_id)
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
    /// `bad_request` for invalid fields or a duplicate id, `auth_failed` if
    /// `inviter_mailbox` is not the caller.
    pub async fn create_invite(
        &self,
        mailbox: &str,
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
        if !self
            .store
            .create_invite(&record, self.now_ms())
            .await
            .map_err(|e| internal(&e))?
        {
            return bad("invite already exists");
        }
        Metrics::inc(&self.metrics.invites_created);
        Ok(record)
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
