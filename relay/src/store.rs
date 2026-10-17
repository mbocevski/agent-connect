//! Storage seam for the relay.
//!
//! Every method that decides something (commit ordering, invite consumption,
//! queue quota, `msg_id` idempotency) is a single atomic operation, so
//! implementations own the race-safety. SQLite is the shipped backend; a
//! Postgres backend only needs to implement this trait.

use std::future::Future;
use std::time::Duration;

use serde::Serialize;

use crate::proto::Kind;

/// A storage failure. Details are logged, never sent to clients.
#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage error: {}", self.0)
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError(e.to_string())
    }
}

impl From<sqlx::migrate::MigrateError> for StoreError {
    fn from(e: sqlx::migrate::MigrateError) -> Self {
        StoreError(e.to_string())
    }
}

/// Result alias for storage operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// Operating limits (SPEC §8.3 defaults).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum frame size in bytes.
    pub frame_max: usize,
    /// Maximum instances per group.
    pub group_max: usize,
    /// Maximum queued bytes per mailbox.
    pub queue_max_bytes: u64,
    /// Maximum sends per second per mailbox.
    pub sends_per_sec: usize,
    /// Maximum join requests per minute per invite.
    pub joins_per_min: usize,
    /// How long an unacked message is kept.
    pub message_ttl: Duration,
    /// The longest invite lifetime.
    pub invite_max_ttl: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_max: 1 << 20,
            group_max: 50,
            queue_max_bytes: 64 << 20,
            sends_per_sec: 50,
            joins_per_min: 10,
            message_ttl: Duration::from_hours(168),
            invite_max_ttl: Duration::from_hours(168),
        }
    }
}

/// Invite state (SPEC §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteStatus {
    /// Can still be joined.
    Open,
    /// All uses are consumed.
    Exhausted,
    /// Past its expiry.
    Expired,
    /// Revoked by the inviter.
    Revoked,
}

impl InviteStatus {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            InviteStatus::Open => "open",
            InviteStatus::Exhausted => "exhausted",
            InviteStatus::Expired => "expired",
            InviteStatus::Revoked => "revoked",
        }
    }
}

/// A stored invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRecord {
    /// Public invite id.
    pub invite_id: String,
    /// Group display name (attacker-controlled; escape before display).
    pub group_name: String,
    /// Inviter display name (attacker-controlled).
    pub inviter_name: String,
    /// Group purpose (attacker-controlled).
    pub purpose: String,
    /// Expiry, unix seconds.
    pub expires_at: u64,
    /// Total uses.
    pub max_uses: u32,
    /// Remaining uses.
    pub uses_left: u32,
    /// Member count at creation, if provided.
    pub member_count: Option<u32>,
    /// The mailbox that registered the invite.
    pub inviter_mailbox: String,
    /// Whether the inviter revoked it.
    pub revoked: bool,
}

impl InviteRecord {
    /// The status at `now_secs`. Revoked beats expired beats exhausted.
    #[must_use]
    pub fn status(&self, now_secs: u64) -> InviteStatus {
        if self.revoked {
            InviteStatus::Revoked
        } else if now_secs >= self.expires_at {
            InviteStatus::Expired
        } else if self.uses_left == 0 {
            InviteStatus::Exhausted
        } else {
            InviteStatus::Open
        }
    }
}

/// Outcome of consuming an invite use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// One use was consumed; this many remain.
    Consumed {
        /// Remaining uses.
        uses_left: u32,
    },
    /// No such invite.
    NotFound,
    /// The caller is not the inviter mailbox.
    NotInviter,
    /// Exhausted, expired or revoked.
    NotOpen,
}

/// Outcome of revoking an invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Revoked (or already revoked).
    Revoked,
    /// No such invite.
    NotFound,
    /// The caller is not the inviter mailbox.
    NotInviter,
}

/// Per-group Delivery Service state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState {
    /// The epoch the relay will accept the next commit for.
    pub current_epoch: u64,
    /// Member mailboxes, sorted.
    pub members: Vec<String>,
}

/// A message to enqueue. `json` is the serialised envelope; it is stored
/// opaquely and never logged.
#[derive(Debug, Clone)]
pub struct NewMessage {
    /// Idempotency key (scoped to the sender).
    pub msg_id: String,
    /// The sender's mailbox.
    pub sender: String,
    /// Serialised envelope.
    pub json: String,
}

/// A queued message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    /// Per-store monotonic sequence; delivery order.
    pub seq: i64,
    /// Message id.
    pub msg_id: String,
    /// Serialised envelope, or the `queue_overflow` frame for a marker.
    pub json: String,
    /// True for an overflow marker, which is sent as-is rather than wrapped
    /// in a `deliver` frame.
    pub marker: bool,
}

/// A group-bound send, decided atomically by the store.
#[derive(Debug, Clone)]
pub struct GroupSend<'a> {
    /// Message kind: commit, proposal, application or welcome.
    pub kind: Kind,
    /// The group.
    pub group_id: &'a str,
    /// Sender mailbox.
    pub sender: &'a str,
    /// Envelope epoch (ignored for welcome).
    pub epoch: u64,
    /// Commit hints: mailboxes added.
    pub add: &'a [String],
    /// Commit hints: mailboxes removed.
    pub remove: &'a [String],
    /// Welcome recipients.
    pub to: &'a [String],
    /// The message.
    pub msg: &'a NewMessage,
}

/// Outcome of a group-bound send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupOutcome {
    /// Accepted and queued for these mailboxes.
    Delivered {
        /// Recipients that received a copy.
        recipients: Vec<String>,
        /// Recipients whose queue was full and who got an overflow marker
        /// (first drop of an episode). Recipients already in an episode are
        /// in neither list.
        overflowed: Vec<String>,
        /// The group's epoch after the operation.
        epoch: u64,
    },
    /// A repeat of an already accepted `msg_id`; nothing was queued.
    Duplicate,
    /// No such group.
    UnknownGroup,
    /// The sender is not a member.
    NotMember,
    /// The epoch is not acceptable; `current_epoch` is the group's.
    EpochConflict {
        /// The group's current epoch.
        current_epoch: u64,
    },
    /// The commit would exceed the group size limit.
    GroupFull,
}

/// Outcome of a direct (non-group) send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectOutcome {
    /// Queued.
    Delivered,
    /// Already accepted before; nothing was queued.
    Duplicate,
    /// The recipient's queue would exceed its quota.
    QuotaExceeded,
}

/// Outcome of registering a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateGroupOutcome {
    /// Created.
    Created,
    /// A group with that id already exists.
    Exists,
}

/// Rows removed by [`Store::purge_expired`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeStats {
    /// Expired queued messages.
    pub messages: u64,
    /// Expired idempotency records.
    pub seen: u64,
    /// Long-expired invites.
    pub invites: u64,
}

/// The relay's persistent state. All times are unix milliseconds supplied by
/// the caller's `Clock`.
pub trait Store: Send + Sync + 'static {
    /// Insert an invite. Returns false if the id already exists.
    fn create_invite(
        &self,
        invite: &InviteRecord,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<bool>> + Send;

    /// Fetch an invite.
    fn get_invite(
        &self,
        invite_id: &str,
    ) -> impl Future<Output = StoreResult<Option<InviteRecord>>> + Send;

    /// Revoke an invite (inviter only).
    fn revoke_invite(
        &self,
        invite_id: &str,
        caller: &str,
    ) -> impl Future<Output = StoreResult<RevokeOutcome>> + Send;

    /// Atomically consume one use (inviter only, open invites only).
    fn consume_invite(
        &self,
        invite_id: &str,
        caller: &str,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<ConsumeOutcome>> + Send;

    /// Register a group at epoch 0 with `creator` as its only member.
    fn create_group(
        &self,
        group_id: &str,
        creator: &str,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<CreateGroupOutcome>> + Send;

    /// Read a group's state.
    fn get_group(
        &self,
        group_id: &str,
    ) -> impl Future<Output = StoreResult<Option<GroupState>>> + Send;

    /// Apply the Delivery Service rules (SPEC §8.3) to a group-bound send:
    /// check, queue for every recipient and (for commits) advance the epoch
    /// and apply the routing hints, all atomically.
    fn deliver_group(
        &self,
        send: &GroupSend<'_>,
        limits: &Limits,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<GroupOutcome>> + Send;

    /// Queue a message for one mailbox (join requests), idempotent on
    /// `(sender, msg_id)`.
    fn deliver_direct(
        &self,
        recipient: &str,
        msg: &NewMessage,
        limits: &Limits,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<DirectOutcome>> + Send;

    /// Unexpired messages for `mailbox` with `seq > after_seq`, oldest first.
    fn pending(
        &self,
        mailbox: &str,
        after_seq: i64,
        limit: u32,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<Vec<StoredMessage>>> + Send;

    /// Remove an acknowledged message from a mailbox.
    fn ack(&self, mailbox: &str, msg_id: &str) -> impl Future<Output = StoreResult<bool>> + Send;

    /// Delete expired rows.
    fn purge_expired(&self, now_ms: u64) -> impl Future<Output = StoreResult<PurgeStats>> + Send;
}
