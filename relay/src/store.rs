//! Storage seam for the relay.
//!
//! Every method that decides something (commit ordering, invite consumption,
//! queue quota, `msg_id` idempotency, the door cap) is a single atomic operation, so
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

/// Default frame limit (SPEC §8.3): 2 MiB. The largest padded application
/// message (the 1 MiB bucket) is about 1.4 MiB once base64url-encoded in an
/// envelope, so it fits with room to spare.
pub const DEFAULT_FRAME_MAX: usize = 2 << 20;

/// A sliding-window rate: at most `max` events per `per`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Events allowed in the window.
    pub max: usize,
    /// The window's length.
    pub per: Duration,
}

/// Operating limits (SPEC §8.3 and ADR-006 defaults).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum frame size in bytes.
    pub frame_max: usize,
    /// Maximum instances per group.
    pub group_max: usize,
    /// Maximum queued bytes per mailbox for group traffic: the groups the
    /// mailbox has sent in.
    pub queue_max_bytes: u64,
    /// Maximum queued bytes per mailbox for traffic from non-members:
    /// Welcomes, join requests, knocks, and the traffic of a group the
    /// mailbox hasn't sent in yet. Kept apart so it never displaces group
    /// traffic.
    pub non_member_queue_max_bytes: u64,
    /// Maximum bytes of undelivered payloads one sender may have stored,
    /// and at most half of it in one group. Knocks are not charged (their
    /// own limits apply).
    pub sender_max_bytes: u64,
    /// Storage high-water mark in bytes of used database pages: at or
    /// above it, new messages are refused.
    pub storage_high_water: u64,
    /// Bytes above the mark that commits adding nobody may still use (an
    /// Update, a removal), each with a `ct` of at most
    /// [`crate::proto::MAX_RESERVE_COMMIT_CT`].
    pub storage_reserve: u64,
    /// Maximum sends per second per mailbox.
    pub sends_per_sec: usize,
    /// Maximum join requests per minute per invite.
    pub joins_per_min: usize,
    /// How long an unacked message is kept.
    pub message_ttl: Duration,
    /// The longest invite lifetime.
    pub invite_max_ttl: Duration,
    /// The longest door lifetime.
    pub door_max_ttl: Duration,
    /// Open doors one mailbox may hold at once (so renewal can overlap).
    pub doors_per_mailbox: usize,
    /// Knocks per (door, sender mailbox); over it is `rate_limited`.
    pub knocks_per_door_sender: Window,
    /// Knocks per sender mailbox across all doors; over it is `rate_limited`.
    pub knocks_per_sender: Window,
    /// Knocks per door; over it the knock is accepted and dropped.
    pub knocks_per_door: Window,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_max: DEFAULT_FRAME_MAX,
            group_max: 50,
            queue_max_bytes: 64 << 20,
            non_member_queue_max_bytes: 16 << 20,
            sender_max_bytes: 128 << 20,
            storage_high_water: 4 << 30,
            storage_reserve: 64 << 20,
            sends_per_sec: 50,
            joins_per_min: 10,
            message_ttl: Duration::from_hours(168),
            invite_max_ttl: Duration::from_hours(168),
            door_max_ttl: Duration::from_hours(168),
            doors_per_mailbox: 4,
            knocks_per_door_sender: Window {
                max: 1,
                per: Duration::from_mins(10),
            },
            knocks_per_sender: Window {
                max: 20,
                per: Duration::from_hours(1),
            },
            knocks_per_door: Window {
                max: 10,
                per: Duration::from_mins(1),
            },
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

/// A registered door (ADR-006): a public handle mapped to its owner's
/// mailbox. The relay holds nothing else about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorRecord {
    /// Public door id (16 random bytes, base64url).
    pub door_id: String,
    /// The mailbox knocks are forwarded to.
    pub owner_mailbox: String,
    /// Expiry, unix seconds.
    pub expires_at: u64,
    /// Whether the owner closed it.
    pub closed: bool,
}

impl DoorRecord {
    /// True if the door takes knocks at `now_secs`.
    #[must_use]
    pub fn is_open(&self, now_secs: u64) -> bool {
        !self.closed && now_secs < self.expires_at
    }
}

/// Outcome of registering a door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateDoorOutcome {
    /// Registered.
    Created,
    /// A door with that id exists (open, closed or expired but not purged).
    Exists,
    /// The owner already holds the maximum number of open doors.
    TooMany,
}

/// Outcome of registering an invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateInviteOutcome {
    /// Registered.
    Created,
    /// An invite with that id exists.
    Exists,
    /// The inviter already holds the maximum number of open invites.
    TooMany,
}

/// Rows the store holds, for the relay's global caps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LiveCounts {
    /// Invite rows, open or not yet purged.
    pub invites: u64,
    /// Groups.
    pub groups: u64,
}

/// A group the idle sweep may delete: no accepted send since the cutoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleGroup {
    /// The group.
    pub group_id: String,
    /// Its member mailboxes, sorted.
    pub members: Vec<String>,
}

/// Outcome of closing a door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseDoorOutcome {
    /// Closed (or already closed).
    Closed,
    /// No such door.
    NotFound,
    /// The caller is not the owner mailbox.
    NotOwner,
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
    /// The envelope's `ct`, in decoded bytes (judged by its length).
    pub ct_bytes: usize,
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
    /// A Welcome names a mailbox that no commit of the sender's added, or
    /// one that already had its Welcome.
    NotAwaitingWelcome,
    /// A Welcome recipient's non-member queue can't take it. Nothing was
    /// queued; the sender may try again later.
    QueueFull,
    /// The sender's stored, undelivered payloads would pass its budget.
    OverBudget,
    /// Storage is at or above its high-water mark.
    StorageFull,
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
    /// The sender's stored, undelivered payloads would pass its budget.
    OverBudget,
    /// Storage is at or above its high-water mark.
    StorageFull,
}

/// Outcome of registering a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateGroupOutcome {
    /// Created.
    Created,
    /// A group with that id already exists.
    Exists,
    /// The caller registered that id already: a repeat.
    Yours,
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
    /// Expired doors.
    pub doors: u64,
    /// Added mailboxes whose Welcome never came.
    pub welcomes_due: u64,
}

/// The relay's persistent state. All times are unix milliseconds supplied by
/// the caller's `Clock`.
pub trait Store: Send + Sync + 'static {
    /// Insert an invite unless its id exists or `invite.inviter_mailbox`
    /// already holds `max_open` open invites (not revoked, expired or used
    /// up), atomically.
    fn create_invite(
        &self,
        invite: &InviteRecord,
        max_open: usize,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<CreateInviteOutcome>> + Send;

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

    /// Register a door unless its id exists or `door.owner_mailbox` already
    /// holds `max_open` open doors, atomically.
    fn create_door(
        &self,
        door: &DoorRecord,
        max_open: usize,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<CreateDoorOutcome>> + Send;

    /// Fetch a door.
    fn get_door(
        &self,
        door_id: &str,
    ) -> impl Future<Output = StoreResult<Option<DoorRecord>>> + Send;

    /// Close a door (owner only).
    fn close_door(
        &self,
        door_id: &str,
        caller: &str,
    ) -> impl Future<Output = StoreResult<CloseDoorOutcome>> + Send;

    /// The mailbox that registered a group, if the store knows it.
    fn group_creator(
        &self,
        group_id: &str,
    ) -> impl Future<Output = StoreResult<Option<String>>> + Send;

    /// Register a group at epoch 0 with `creator` as its only member, and
    /// record `creator` with it. A repeat by the same creator is `Yours`.
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
    /// check, queue for every recipient, (for commits) advance the epoch
    /// and apply the routing hints, and record the group's activity time
    /// (to within [`crate::quota::ACTIVITY_GRANULARITY`]), all atomically.
    ///
    /// The payload is stored once and charged to the sender's budget; each
    /// recipient's queue is charged its full size, in the member bucket if
    /// the recipient has sent in the group and in the non-member bucket
    /// otherwise (Welcomes always). A Welcome goes only to mailboxes that a
    /// commit of the sender's added and that haven't had theirs.
    fn deliver_group(
        &self,
        send: &GroupSend<'_>,
        limits: &Limits,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<GroupOutcome>> + Send;

    /// Queue a `join_request` or `knock` for one mailbox, in its non-member
    /// bucket, idempotent on `(sender, msg_id)`. A knock isn't charged to
    /// the sender's budget.
    fn deliver_direct(
        &self,
        kind: Kind,
        recipient: &str,
        msg: &NewMessage,
        limits: &Limits,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<DirectOutcome>> + Send;

    /// Bytes of storage in use, the measure the high-water mark applies to.
    fn storage_bytes(&self) -> impl Future<Output = StoreResult<u64>> + Send;

    /// Unexpired messages for `mailbox` with `seq > after_seq`, oldest first:
    /// at most `limit` of them, and no more than `max_bytes` of stored
    /// envelopes, except that the first message is returned whatever its
    /// size.
    fn pending(
        &self,
        mailbox: &str,
        after_seq: i64,
        limit: u32,
        max_bytes: u64,
        now_ms: u64,
    ) -> impl Future<Output = StoreResult<Vec<StoredMessage>>> + Send;

    /// Remove an acknowledged message from a mailbox.
    fn ack(&self, mailbox: &str, msg_id: &str) -> impl Future<Output = StoreResult<bool>> + Send;

    /// Delete expired rows, then let the backend reclaim what they used
    /// (SQLite: a WAL checkpoint).
    fn purge_expired(&self, now_ms: u64) -> impl Future<Output = StoreResult<PurgeStats>> + Send;

    /// How many invite rows and groups the store holds.
    fn live_counts(&self) -> impl Future<Output = StoreResult<LiveCounts>> + Send;

    /// Up to `limit` groups created and last used at or before `cutoff_ms`,
    /// ordered by id and after `after` (keyset paging), with their members.
    fn idle_groups(
        &self,
        cutoff_ms: u64,
        after: &str,
        limit: u32,
    ) -> impl Future<Output = StoreResult<Vec<IdleGroup>>> + Send;

    /// Delete a group and its memberships if it is still idle at
    /// `cutoff_ms`. Returns whether it was deleted.
    fn delete_idle_group(
        &self,
        group_id: &str,
        cutoff_ms: u64,
    ) -> impl Future<Output = StoreResult<bool>> + Send;
}
