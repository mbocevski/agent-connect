//! SQLite [`Store`] built on `sqlx`.
//!
//! Writes go through a pool of exactly one connection, so every write
//! transaction is serialised. That is what makes the check-then-write
//! sequences in this file race-free; a Postgres backend would use row locks
//! instead. Reads that decide nothing (draining a queue, looking up an
//! invite, a door or a group) use a separate pool of read-only connections,
//! which in WAL mode neither wait for the writer nor hold it up.
//!
//! Every quota is a counter kept in the transaction that changes what it
//! counts (`mailbox_usage` and `group_usage` for the queue parts and each
//! group's share of them, `sender_usage` and `sender_group_usage` for the
//! sender budget), so no check scans a queue. Deleted rows are overwritten
//! (`secure_delete`), and the periodic purge deletes in batches bounded by
//! bytes, then checkpoints and truncates the WAL, so acked ciphertext
//! doesn't stay readable in the files.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Row, SqlitePool};

use crate::proto::{Kind, ServerFrame};
use crate::store::{
    CloseDoorOutcome, ConsumeOutcome, CreateDoorOutcome, CreateGroupOutcome, CreateInviteOutcome,
    DirectOutcome, DoorRecord, GroupOutcome, GroupSend, GroupState, IdleGroup, InviteRecord,
    Limits, LiveCounts, NewMessage, PurgeStats, RevokeOutcome, Store, StoreError, StoreResult,
    StoredMessage,
};

/// How stale a group's `active_at` may get before a send rewrites it: the
/// idle period is days, so one write an hour per group is enough.
const TOUCH_EVERY_MS: u64 = 3600 * 1000;
const _: () = assert!(
    TOUCH_EVERY_MS as u128 == crate::quota::ACTIVITY_GRANULARITY.as_millis(),
    "the sweep's margin must cover the write interval"
);

/// Grace period during which an expired invite stays readable so its landing
/// page can still say "expired".
pub const INVITE_GRACE_MS: u64 = 7 * 24 * 3600 * 1000;

/// Read-only connections for queue drains and lookups.
const READERS: u32 = 4;

/// Rows considered per purge transaction.
const PURGE_BATCH: i64 = 2000;

/// Bytes of queue rows deleted per purge transaction. With `secure_delete`
/// a delete rewrites the pages it frees, so a batch of 16 MiB keeps the
/// writer, and the WAL, to about that much at a time (SPEC §8.3, "Storage").
const PURGE_BATCH_BYTES: u64 = 16 << 20;

/// A SQLite-backed store.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    /// The single writer connection.
    pool: SqlitePool,
    /// Read-only connections (the writer itself for an in-memory database,
    /// whose contents only that connection sees).
    reader: SqlitePool,
}

fn i64_of(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn u64_of(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn u32_of(v: i64) -> u32 {
    u32::try_from(v).unwrap_or(0)
}

fn len_of(s: &str) -> u64 {
    u64::try_from(s.len()).unwrap_or(u64::MAX)
}

fn is_memory(spec: &str) -> bool {
    spec.contains(":memory:") || spec.contains("mode=memory")
}

impl SqliteStore {
    /// Open (creating if needed) a database and run the migrations.
    ///
    /// `spec` is either a `sqlite:` URL (`sqlite::memory:`, `sqlite://x.db`)
    /// or a plain file path.
    ///
    /// # Errors
    ///
    /// Fails if the database cannot be opened or migrated.
    pub async fn open(spec: &str) -> StoreResult<Self> {
        let opts = if spec.starts_with("sqlite:") {
            SqliteConnectOptions::from_str(spec)?
        } else {
            SqliteConnectOptions::new().filename(spec)
        };
        let opts = opts
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            // Overwrite deleted content, so acked ciphertext and expired
            // mappings don't stay readable in the file (SPEC §8.3).
            .pragma("secure_delete", "on");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(opts.clone())
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        let reader = if is_memory(spec) {
            pool.clone()
        } else {
            SqlitePoolOptions::new()
                .max_connections(READERS)
                .min_connections(0)
                .connect_with(opts.create_if_missing(false).read_only(true))
                .await?
        };
        Ok(Self { pool, reader })
    }

    /// A private in-memory database (for tests).
    ///
    /// # Errors
    ///
    /// Fails if SQLite cannot be initialised.
    pub async fn in_memory() -> StoreResult<Self> {
        Self::open("sqlite::memory:").await
    }
}

/// The two parts of a mailbox's queue quota (SPEC §8.3, "Limits").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Bucket {
    /// Traffic of a group the mailbox has sent in.
    Member,
    /// Welcomes, join requests, knocks, and traffic of a group the mailbox
    /// hasn't sent in yet.
    NonMember,
}

impl Bucket {
    fn code(self) -> i64 {
        match self {
            Bucket::Member => 0,
            Bucket::NonMember => 1,
        }
    }

    fn of_code(code: i64) -> Self {
        if code == 0 {
            Bucket::Member
        } else {
            Bucket::NonMember
        }
    }

    fn cap(self, limits: &Limits) -> u64 {
        match self {
            Bucket::Member => limits.queue_max_bytes,
            Bucket::NonMember => limits.non_member_queue_max_bytes,
        }
    }
}

/// The most one group (or, for `''`, join requests and knocks together)
/// may hold of a part of a mailbox's queue, or of a sender's budget: half.
/// One group can then never take everything from the others.
fn share(cap: u64) -> u64 {
    cap / 2
}

/// Bytes of overflow markers a part may hold beyond its cap: about 1,700
/// markers, one per group that lost messages.
const MARKER_RESERVE: u64 = 256 * 1024;

/// Members of a group, each with whether it has sent in the group.
async fn members_of(
    tx: &mut SqliteConnection,
    group_id: &str,
) -> StoreResult<BTreeMap<String, bool>> {
    let rows = sqlx::query("SELECT mailbox, confirmed FROM group_members WHERE group_id = ?")
        .bind(group_id)
        .fetch_all(&mut *tx)
        .await?;
    rows.iter()
        .map(|r| Ok((r.try_get::<String, _>(0)?, r.try_get::<i64, _>(1)? != 0)))
        .collect()
}

async fn already_seen(
    tx: &mut SqliteConnection,
    msg: &NewMessage,
    now_ms: u64,
) -> StoreResult<bool> {
    let row = sqlx::query("SELECT 1 FROM seen WHERE sender = ? AND msg_id = ? AND expires_at > ?")
        .bind(&msg.sender)
        .bind(&msg.msg_id)
        .bind(i64_of(now_ms))
        .fetch_optional(&mut *tx)
        .await?;
    Ok(row.is_some())
}

/// Bytes of used database pages (free pages are reused, so they don't
/// count).
async fn storage_used(conn: &mut SqliteConnection) -> StoreResult<u64> {
    let row = sqlx::query(
        "SELECT (SELECT page_count FROM pragma_page_count()) \
              - (SELECT freelist_count FROM pragma_freelist_count()), \
                (SELECT page_size FROM pragma_page_size())",
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(u64_of(row.try_get(0)?).saturating_mul(u64_of(row.try_get(1)?)))
}

/// One counter's value; a missing row is zero.
async fn counter(
    tx: &mut SqliteConnection,
    sql: &'static str,
    keys: &[&str],
    bucket: Option<Bucket>,
) -> StoreResult<u64> {
    let mut q = sqlx::query(sql);
    for k in keys {
        q = q.bind(*k);
    }
    if let Some(b) = bucket {
        q = q.bind(b.code());
    }
    let row = q.fetch_optional(&mut *tx).await?;
    row.map_or(Ok(0), |r| Ok(u64_of(r.try_get(0)?)))
}

async fn bucket_bytes(
    tx: &mut SqliteConnection,
    mailbox: &str,
    bucket: Bucket,
) -> StoreResult<u64> {
    counter(
        tx,
        "SELECT bytes FROM mailbox_usage WHERE mailbox = ? AND bucket = ?",
        &[mailbox],
        Some(bucket),
    )
    .await
}

async fn group_bytes(
    tx: &mut SqliteConnection,
    mailbox: &str,
    group_id: &str,
    bucket: Bucket,
) -> StoreResult<u64> {
    counter(
        tx,
        "SELECT bytes FROM group_usage WHERE mailbox = ? AND group_id = ? AND bucket = ?",
        &[mailbox, group_id],
        Some(bucket),
    )
    .await
}

/// Add `delta` to a mailbox's counters for `bucket` and for `group_id` in
/// it; a counter that reaches zero goes, so the tables only hold what has
/// something queued.
async fn charge_mailbox(
    tx: &mut SqliteConnection,
    mailbox: &str,
    bucket: Bucket,
    group_id: &str,
    delta: i64,
) -> StoreResult<()> {
    sqlx::query(
        "INSERT INTO mailbox_usage (mailbox, bucket, bytes) VALUES (?, ?, ?) \
         ON CONFLICT (mailbox, bucket) DO UPDATE SET bytes = bytes + excluded.bytes",
    )
    .bind(mailbox)
    .bind(bucket.code())
    .bind(delta)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO group_usage (mailbox, bucket, group_id, bytes) VALUES (?, ?, ?, ?) \
         ON CONFLICT (mailbox, bucket, group_id) DO UPDATE SET bytes = bytes + excluded.bytes",
    )
    .bind(mailbox)
    .bind(bucket.code())
    .bind(group_id)
    .bind(delta)
    .execute(&mut *tx)
    .await?;
    if delta < 0 {
        sqlx::query("DELETE FROM mailbox_usage WHERE mailbox = ? AND bucket = ? AND bytes <= 0")
            .bind(mailbox)
            .bind(bucket.code())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM group_usage \
             WHERE mailbox = ? AND bucket = ? AND group_id = ? AND bytes <= 0",
        )
        .bind(mailbox)
        .bind(bucket.code())
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

/// Add `delta` to a sender's counters, in all and for `group_id` (`''`,
/// the uncharged sender, has none).
async fn charge_sender(
    tx: &mut SqliteConnection,
    sender: &str,
    group_id: &str,
    delta: i64,
) -> StoreResult<()> {
    if sender.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO sender_usage (sender, bytes) VALUES (?, ?) \
         ON CONFLICT (sender) DO UPDATE SET bytes = bytes + excluded.bytes",
    )
    .bind(sender)
    .bind(delta)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO sender_group_usage (sender, group_id, bytes) VALUES (?, ?, ?) \
         ON CONFLICT (sender, group_id) DO UPDATE SET bytes = bytes + excluded.bytes",
    )
    .bind(sender)
    .bind(group_id)
    .bind(delta)
    .execute(&mut *tx)
    .await?;
    if delta < 0 {
        sqlx::query("DELETE FROM sender_usage WHERE sender = ? AND bytes <= 0")
            .bind(sender)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM sender_group_usage WHERE sender = ? AND group_id = ? AND bytes <= 0",
        )
        .bind(sender)
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

/// How a message is let past the storage high-water mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    /// Refused at or above the mark.
    Ordinary,
    /// A commit that adds nobody, with a `ct` within
    /// [`crate::proto::MAX_RESERVE_COMMIT_CT`]: let past the mark up to
    /// [`Limits::storage_reserve`] above it.
    Reserve,
}

/// The checks every new message goes through before anything is written:
/// the storage high-water mark, then the sender's budget, in all and for
/// the message's group. `charged` is the sender the payload is charged to
/// (`''` for none).
async fn admit(
    tx: &mut SqliteConnection,
    charged: &str,
    group_id: &str,
    size: u64,
    mark: Mark,
    limits: &Limits,
) -> StoreResult<Result<(), Refusal>> {
    let used = storage_used(tx).await?;
    let ceiling = match mark {
        Mark::Ordinary => limits.storage_high_water,
        Mark::Reserve => limits
            .storage_high_water
            .saturating_add(limits.storage_reserve),
    };
    if used >= ceiling {
        return Ok(Err(Refusal::StorageFull));
    }
    if charged.is_empty() {
        return Ok(Ok(()));
    }
    let total = counter(
        tx,
        "SELECT bytes FROM sender_usage WHERE sender = ?",
        &[charged],
        None,
    )
    .await?;
    let in_group = counter(
        tx,
        "SELECT bytes FROM sender_group_usage WHERE sender = ? AND group_id = ?",
        &[charged, group_id],
        None,
    )
    .await?;
    if total.saturating_add(size) > limits.sender_max_bytes
        || in_group.saturating_add(size) > share(limits.sender_max_bytes)
    {
        return Ok(Err(Refusal::OverBudget));
    }
    Ok(Ok(()))
}

/// Why [`admit`] refused a message.
enum Refusal {
    StorageFull,
    OverBudget,
}

/// The idle sweep's clock (SPEC §8.3): a group's last accepted send, to
/// within `TOUCH_EVERY_MS`.
async fn record_activity(
    tx: &mut SqliteConnection,
    group_id: &str,
    now_ms: u64,
) -> StoreResult<()> {
    sqlx::query("UPDATE groups SET active_at = ? WHERE group_id = ? AND active_at <= ?")
        .bind(i64_of(now_ms))
        .bind(group_id)
        .bind(i64_of(now_ms.saturating_sub(TOUCH_EVERY_MS)))
        .execute(&mut *tx)
        .await?;
    Ok(())
}

/// Where a dropped group message came from, for the overflow marker.
struct MarkerInfo<'a> {
    group_id: &'a str,
    epoch: u64,
}

/// Recipients of a fan-out, split by what happened.
struct Fanout {
    delivered: Vec<String>,
    overflowed: Vec<String>,
}

/// One recipient's copy: its mailbox and the bucket it is charged to.
type Recipient = (String, Bucket);

/// What a fan-out stores and for which group (`''` for join requests and
/// knocks).
struct Outgoing<'a> {
    msg: &'a NewMessage,
    group_id: &'a str,
    /// The sender the payload is charged to (`''` for none).
    charged: &'a str,
}

async fn insert_payload(
    tx: &mut SqliteConnection,
    charged: &str,
    group_id: &str,
    json: &str,
) -> StoreResult<i64> {
    let size = i64_of(len_of(json));
    let id = sqlx::query(
        "INSERT INTO payloads (sender, group_id, env, size) VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(charged)
    .bind(group_id)
    .bind(json)
    .bind(size)
    .fetch_one(&mut *tx)
    .await?
    .try_get(0)?;
    charge_sender(tx, charged, group_id, size).await?;
    Ok(id)
}

struct QueueRow<'a> {
    mailbox: &'a str,
    bucket: Bucket,
    group_id: &'a str,
    msg_id: &'a str,
    payload: i64,
    size: u64,
    marker: bool,
    expires: i64,
}

async fn insert_row(tx: &mut SqliteConnection, row: &QueueRow<'_>) -> StoreResult<()> {
    let size = i64_of(row.size);
    sqlx::query(
        "INSERT INTO messages \
         (mailbox, msg_id, payload, group_id, size, bucket, marker, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(row.mailbox)
    .bind(row.msg_id)
    .bind(row.payload)
    .bind(row.group_id)
    .bind(size)
    .bind(row.bucket.code())
    .bind(i64::from(row.marker))
    .bind(row.expires)
    .execute(&mut *tx)
    .await?;
    charge_mailbox(tx, row.mailbox, row.bucket, row.group_id, size).await
}

/// True if `size` more bytes of `group_id`'s traffic fit `mailbox`'s
/// `bucket`: within the part's cap and within the group's share of it.
async fn has_room(
    tx: &mut SqliteConnection,
    mailbox: &str,
    bucket: Bucket,
    group_id: &str,
    size: u64,
    limits: &Limits,
) -> StoreResult<bool> {
    let cap = bucket.cap(limits);
    Ok(bucket_bytes(tx, mailbox, bucket)
        .await?
        .saturating_add(size)
        <= cap
        && group_bytes(tx, mailbox, group_id, bucket)
            .await?
            .saturating_add(size)
            <= share(cap))
}

/// Queue a message for each recipient, storing its payload once, and
/// record its idempotency key.
///
/// With a `marker`, a recipient without room is skipped and gets one
/// overflow marker per episode of that (mailbox, part, group), while the
/// part has [`MARKER_RESERVE`] left above its cap. Without one, a recipient
/// without room aborts before anything is written and `None` is returned.
async fn enqueue_all(
    tx: &mut SqliteConnection,
    recipients: &[Recipient],
    out: &Outgoing<'_>,
    limits: &Limits,
    now_ms: u64,
    marker: Option<&MarkerInfo<'_>>,
) -> StoreResult<Option<Fanout>> {
    let msg = out.msg;
    let size = len_of(&msg.json);
    let ttl = u64::try_from(limits.message_ttl.as_millis()).unwrap_or(u64::MAX);
    let expires = i64_of(now_ms.saturating_add(ttl));
    let mut room = Vec::with_capacity(recipients.len());
    for (r, bucket) in recipients {
        let fits = has_room(tx, r, *bucket, out.group_id, size, limits).await?;
        if !fits && marker.is_none() {
            return Ok(None);
        }
        room.push(fits);
    }
    let mut fanout = Fanout {
        delivered: Vec::new(),
        overflowed: Vec::new(),
    };
    let mut payload = None;
    for ((r, bucket), fits) in recipients.iter().zip(room) {
        let flagged =
            sqlx::query("SELECT 1 FROM overflow WHERE mailbox = ? AND bucket = ? AND group_id = ?")
                .bind(r)
                .bind(bucket.code())
                .bind(out.group_id)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
        if fits {
            if flagged {
                // The group's share has room again: the episode is over.
                sqlx::query(
                    "DELETE FROM overflow WHERE mailbox = ? AND bucket = ? AND group_id = ?",
                )
                .bind(r)
                .bind(bucket.code())
                .bind(out.group_id)
                .execute(&mut *tx)
                .await?;
            }
            let id = if let Some(id) = payload {
                id
            } else {
                let id = insert_payload(tx, out.charged, out.group_id, &msg.json).await?;
                payload = Some(id);
                id
            };
            let row = QueueRow {
                mailbox: r,
                bucket: *bucket,
                group_id: out.group_id,
                msg_id: &msg.msg_id,
                payload: id,
                size,
                marker: false,
                expires,
            };
            insert_row(tx, &row).await?;
            fanout.delivered.push(r.clone());
        } else if !flagged
            && let Some(info) = marker
            && queue_marker(tx, (r, *bucket), &msg.msg_id, info, limits, expires).await?
        {
            fanout.overflowed.push(r.clone());
        }
    }
    sqlx::query("INSERT INTO seen (sender, msg_id, expires_at) VALUES (?, ?, ?)")
        .bind(&msg.sender)
        .bind(&msg.msg_id)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
    Ok(Some(fanout))
}

/// Start an overflow episode of `info`'s group for the recipient and queue
/// its marker, naming the first dropped message. Markers are exempt from
/// the caps and charged to nobody, up to [`MARKER_RESERVE`] above the
/// part's cap; past that the drop goes unmarked and `false` is returned.
async fn queue_marker(
    tx: &mut SqliteConnection,
    (mailbox, bucket): (&str, Bucket),
    msg_id: &str,
    info: &MarkerInfo<'_>,
    limits: &Limits,
    expires: i64,
) -> StoreResult<bool> {
    let frame = ServerFrame::QueueOverflow {
        group_id: info.group_id.to_owned(),
        msg_id: msg_id.to_owned(),
        epoch: Some(info.epoch),
    }
    .to_json();
    let frame_size = len_of(&frame);
    let ceiling = bucket.cap(limits).saturating_add(MARKER_RESERVE);
    if bucket_bytes(tx, mailbox, bucket)
        .await?
        .saturating_add(frame_size)
        > ceiling
    {
        return Ok(false);
    }
    sqlx::query("INSERT INTO overflow (mailbox, bucket, group_id) VALUES (?, ?, ?)")
        .bind(mailbox)
        .bind(bucket.code())
        .bind(info.group_id)
        .execute(&mut *tx)
        .await?;
    let id = insert_payload(tx, "", info.group_id, &frame).await?;
    let row = QueueRow {
        mailbox,
        bucket,
        group_id: info.group_id,
        msg_id,
        payload: id,
        size: frame_size,
        marker: true,
        expires,
    };
    insert_row(tx, &row).await?;
    Ok(true)
}

/// A queue row that was just deleted: mailbox, bucket, group, size and
/// payload.
type Released = (String, i64, String, i64, i64);

/// Uncharge queue rows that were just deleted, and delete (and uncharge)
/// the payloads no row refers to any more.
async fn release(tx: &mut SqliteConnection, rows: &[Released]) -> StoreResult<()> {
    let mut per_group: HashMap<(&str, i64, &str), i64> = HashMap::new();
    let mut payloads = BTreeSet::new();
    for (mailbox, bucket, group_id, size, payload) in rows {
        *per_group
            .entry((mailbox.as_str(), *bucket, group_id.as_str()))
            .or_default() += size;
        payloads.insert(*payload);
    }
    for ((mailbox, bucket, group_id), bytes) in per_group {
        charge_mailbox(tx, mailbox, Bucket::of_code(bucket), group_id, -bytes).await?;
    }
    for id in payloads {
        let gone = sqlx::query(
            "DELETE FROM payloads WHERE id = ? \
             AND NOT EXISTS (SELECT 1 FROM messages WHERE payload = ?) \
             RETURNING sender, group_id, size",
        )
        .bind(id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(r) = gone {
            let sender: String = r.try_get(0)?;
            let group_id: String = r.try_get(1)?;
            charge_sender(tx, &sender, &group_id, -r.try_get::<i64, _>(2)?).await?;
        }
    }
    Ok(())
}

fn released_rows(rows: &[sqlx::sqlite::SqliteRow]) -> StoreResult<Vec<Released>> {
    rows.iter()
        .map(|r| {
            Ok((
                r.try_get(0)?,
                r.try_get(1)?,
                r.try_get(2)?,
                r.try_get(3)?,
                r.try_get(4)?,
            ))
        })
        .collect()
}

/// True if every `to` mailbox of a Welcome awaits one from its sender: a
/// commit of the sender's added it and it hasn't had its Welcome.
async fn welcomes_due(
    tx: &mut SqliteConnection,
    send: &GroupSend<'_>,
    now_ms: u64,
) -> StoreResult<bool> {
    for r in send.to {
        let due = sqlx::query(
            "SELECT 1 FROM welcome_due \
             WHERE group_id = ? AND mailbox = ? AND added_by = ? AND expires_at > ?",
        )
        .bind(send.group_id)
        .bind(r)
        .bind(send.sender)
        .bind(i64_of(now_ms))
        .fetch_optional(&mut *tx)
        .await?;
        if due.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Record that `mailbox` has sent in the group.
async fn confirm(tx: &mut SqliteConnection, group_id: &str, mailbox: &str) -> StoreResult<()> {
    sqlx::query("UPDATE group_members SET confirmed = 1 WHERE group_id = ? AND mailbox = ?")
        .bind(group_id)
        .bind(mailbox)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

/// True if a commit would take the group past its size limit.
fn too_big(send: &GroupSend<'_>, members: &BTreeMap<String, bool>, limits: &Limits) -> bool {
    let mut next: BTreeSet<&str> = members.keys().map(String::as_str).collect();
    for m in send.remove {
        next.remove(m.as_str());
    }
    next.extend(send.add.iter().map(String::as_str));
    next.len() > limits.group_max
}

/// A commit that adds nobody (an Update, a removal, a policy change) may
/// use the reserve above the high-water mark, if its ct is no bigger than
/// an honest one can be: a group can still shed a member and renew its
/// keys at the mark. It is charged to the sender's budget as any message.
fn mark_of(send: &GroupSend<'_>) -> Mark {
    if send.kind == Kind::Commit
        && send.add.is_empty()
        && send.ct_bytes <= crate::proto::MAX_RESERVE_COMMIT_CT
    {
        Mark::Reserve
    } else {
        Mark::Ordinary
    }
}

/// Who gets a group-bound send, and the bucket each copy is charged to.
fn recipients_of(send: &GroupSend<'_>, members: &BTreeMap<String, bool>) -> Vec<Recipient> {
    let bucket = |confirmed: bool| {
        if confirmed {
            Bucket::Member
        } else {
            Bucket::NonMember
        }
    };
    match send.kind {
        // Everyone who was a member when the commit was made, including
        // the sender (confirmation) and anyone it removes (so they learn
        // of it). New members get a Welcome instead.
        Kind::Commit => members
            .iter()
            .map(|(m, c)| (m.clone(), bucket(*c)))
            .collect(),
        Kind::Proposal | Kind::Application => members
            .iter()
            .filter(|(m, _)| m.as_str() != send.sender)
            .map(|(m, c)| (m.clone(), bucket(*c)))
            .collect(),
        Kind::WelcomeWrapped | Kind::JoinRequest | Kind::Knock => send
            .to
            .iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|m| (m.clone(), Bucket::NonMember))
            .collect(),
    }
}

/// Drop what is still queued for the members a commit removes, in that
/// group, with its charges: they are no longer members, and their unread
/// copies must not pin anyone's budget until the TTL. The commit itself
/// is queued for them afterwards.
async fn drop_removed(
    tx: &mut SqliteConnection,
    send: &GroupSend<'_>,
    members: &BTreeMap<String, bool>,
) -> StoreResult<()> {
    for m in send.remove.iter().filter(|m| members.contains_key(*m)) {
        let rows = sqlx::query(
            "DELETE FROM messages WHERE group_id = ? AND mailbox = ? \
             RETURNING mailbox, bucket, group_id, size, payload",
        )
        .bind(send.group_id)
        .bind(m)
        .fetch_all(&mut *tx)
        .await?;
        release(tx, &released_rows(&rows)?).await?;
        sqlx::query("DELETE FROM overflow WHERE mailbox = ? AND group_id = ?")
            .bind(m)
            .bind(send.group_id)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

/// Advance the epoch from `current` and apply a commit's routing hints.
/// Each mailbox it adds awaits a Welcome from the sender until `due_until`.
async fn apply_commit(
    tx: &mut SqliteConnection,
    send: &GroupSend<'_>,
    current: u64,
    due_until: i64,
) -> StoreResult<()> {
    let res = sqlx::query("UPDATE groups SET epoch = ? WHERE group_id = ? AND epoch = ?")
        .bind(i64_of(current + 1))
        .bind(send.group_id)
        .bind(i64_of(current))
        .execute(&mut *tx)
        .await?;
    if res.rows_affected() != 1 {
        return Err(StoreError("epoch changed during commit".into()));
    }
    for m in send.remove {
        sqlx::query("DELETE FROM group_members WHERE group_id = ? AND mailbox = ?")
            .bind(send.group_id)
            .bind(m)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM welcome_due WHERE group_id = ? AND mailbox = ?")
            .bind(send.group_id)
            .bind(m)
            .execute(&mut *tx)
            .await?;
    }
    for m in send.add {
        let added = sqlx::query(
            "INSERT OR IGNORE INTO group_members (group_id, mailbox, confirmed) VALUES (?, ?, 0)",
        )
        .bind(send.group_id)
        .bind(m)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if added {
            sqlx::query(
                "INSERT OR REPLACE INTO welcome_due (group_id, mailbox, added_by, expires_at) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(send.group_id)
            .bind(m)
            .bind(send.sender)
            .bind(due_until)
            .execute(&mut *tx)
            .await?;
        }
    }
    Ok(())
}

/// The end of the next purge batch: rows from the front of `sizes` (queue
/// rows oldest expiry first) adding up to at most `max_bytes`, and always
/// at least one. With `secure_delete` a delete rewrites what it frees, so
/// the batch is bounded by bytes, not rows.
fn purge_batch_len(sizes: &[i64], max_bytes: u64) -> usize {
    let mut total = 0_u64;
    for (i, size) in sizes.iter().enumerate() {
        total = total.saturating_add(u64_of(*size));
        if total > max_bytes {
            return i.max(1);
        }
    }
    sizes.len()
}

fn invite_from_row(r: &sqlx::sqlite::SqliteRow) -> StoreResult<InviteRecord> {
    Ok(InviteRecord {
        invite_id: r.try_get("invite_id")?,
        group_name: r.try_get("group_name")?,
        inviter_name: r.try_get("inviter_name")?,
        purpose: r.try_get("purpose")?,
        expires_at: u64_of(r.try_get("expires_at")?),
        max_uses: u32_of(r.try_get("max_uses")?),
        uses_left: u32_of(r.try_get("uses_left")?),
        member_count: r.try_get::<Option<i64>, _>("member_count")?.map(u32_of),
        inviter_mailbox: r.try_get("inviter_mailbox")?,
        revoked: r.try_get::<i64, _>("revoked")? != 0,
    })
}

fn door_from_row(r: &sqlx::sqlite::SqliteRow) -> StoreResult<DoorRecord> {
    Ok(DoorRecord {
        door_id: r.try_get("door_id")?,
        owner_mailbox: r.try_get("owner_mailbox")?,
        expires_at: u64_of(r.try_get("expires_at")?),
        closed: r.try_get::<i64, _>("closed")? != 0,
    })
}

impl Store for SqliteStore {
    async fn create_door(
        &self,
        door: &DoorRecord,
        max_open: usize,
        now_ms: u64,
    ) -> StoreResult<CreateDoorOutcome> {
        let mut tx = self.pool.begin().await?;
        let exists = sqlx::query("SELECT 1 FROM doors WHERE door_id = ?")
            .bind(&door.door_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if exists {
            return Ok(CreateDoorOutcome::Exists);
        }
        let open: i64 = sqlx::query(
            "SELECT COUNT(*) FROM doors WHERE owner_mailbox = ? AND closed = 0 AND expires_at > ?",
        )
        .bind(&door.owner_mailbox)
        .bind(i64_of(now_ms / 1000))
        .fetch_one(&mut *tx)
        .await?
        .try_get(0)?;
        if u64_of(open) >= u64::try_from(max_open).unwrap_or(u64::MAX) {
            return Ok(CreateDoorOutcome::TooMany);
        }
        sqlx::query(
            "INSERT INTO doors (door_id, owner_mailbox, expires_at, closed, created_at) \
             VALUES (?, ?, ?, 0, ?)",
        )
        .bind(&door.door_id)
        .bind(&door.owner_mailbox)
        .bind(i64_of(door.expires_at))
        .bind(i64_of(now_ms))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(CreateDoorOutcome::Created)
    }

    async fn get_door(&self, door_id: &str) -> StoreResult<Option<DoorRecord>> {
        let row = sqlx::query("SELECT * FROM doors WHERE door_id = ?")
            .bind(door_id)
            .fetch_optional(&self.reader)
            .await?;
        row.as_ref().map(door_from_row).transpose()
    }

    async fn close_door(&self, door_id: &str, caller: &str) -> StoreResult<CloseDoorOutcome> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT owner_mailbox FROM doors WHERE door_id = ?")
            .bind(door_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Ok(CloseDoorOutcome::NotFound);
        };
        if row.try_get::<String, _>(0)? != caller {
            return Ok(CloseDoorOutcome::NotOwner);
        }
        sqlx::query("UPDATE doors SET closed = 1 WHERE door_id = ?")
            .bind(door_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(CloseDoorOutcome::Closed)
    }

    async fn create_invite(
        &self,
        inv: &InviteRecord,
        max_open: usize,
        now_ms: u64,
    ) -> StoreResult<CreateInviteOutcome> {
        let mut tx = self.pool.begin().await?;
        let open: i64 = sqlx::query(
            "SELECT COUNT(*) FROM invites WHERE inviter_mailbox = ? AND expires_at > ? \
             AND revoked = 0 AND uses_left > 0",
        )
        .bind(&inv.inviter_mailbox)
        .bind(i64_of(now_ms / 1000))
        .fetch_one(&mut *tx)
        .await?
        .try_get(0)?;
        if u64_of(open) >= u64::try_from(max_open).unwrap_or(u64::MAX) {
            return Ok(CreateInviteOutcome::TooMany);
        }
        let res = sqlx::query(
            "INSERT OR IGNORE INTO invites (invite_id, group_name, inviter_name, purpose, \
             expires_at, max_uses, uses_left, member_count, inviter_mailbox, revoked, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
        )
        .bind(&inv.invite_id)
        .bind(&inv.group_name)
        .bind(&inv.inviter_name)
        .bind(&inv.purpose)
        .bind(i64_of(inv.expires_at))
        .bind(i64::from(inv.max_uses))
        .bind(i64::from(inv.uses_left))
        .bind(inv.member_count.map(i64::from))
        .bind(&inv.inviter_mailbox)
        .bind(i64_of(now_ms))
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() != 1 {
            return Ok(CreateInviteOutcome::Exists);
        }
        tx.commit().await?;
        Ok(CreateInviteOutcome::Created)
    }

    async fn get_invite(&self, invite_id: &str) -> StoreResult<Option<InviteRecord>> {
        let row = sqlx::query("SELECT * FROM invites WHERE invite_id = ?")
            .bind(invite_id)
            .fetch_optional(&self.reader)
            .await?;
        row.as_ref().map(invite_from_row).transpose()
    }

    async fn revoke_invite(&self, invite_id: &str, caller: &str) -> StoreResult<RevokeOutcome> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT inviter_mailbox FROM invites WHERE invite_id = ?")
            .bind(invite_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Ok(RevokeOutcome::NotFound);
        };
        if row.try_get::<String, _>(0)? != caller {
            return Ok(RevokeOutcome::NotInviter);
        }
        sqlx::query("UPDATE invites SET revoked = 1 WHERE invite_id = ?")
            .bind(invite_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(RevokeOutcome::Revoked)
    }

    async fn consume_invite(
        &self,
        invite_id: &str,
        caller: &str,
        now_ms: u64,
    ) -> StoreResult<ConsumeOutcome> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT * FROM invites WHERE invite_id = ?")
            .bind(invite_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Ok(ConsumeOutcome::NotFound);
        };
        let inv = invite_from_row(&row)?;
        if inv.inviter_mailbox != caller {
            return Ok(ConsumeOutcome::NotInviter);
        }
        if inv.status(now_ms / 1000) != crate::store::InviteStatus::Open {
            return Ok(ConsumeOutcome::NotOpen);
        }
        // The guard in the WHERE clause keeps the decrement correct even on a
        // backend with weaker isolation.
        let res = sqlx::query(
            "UPDATE invites SET uses_left = uses_left - 1 WHERE invite_id = ? AND uses_left > 0",
        )
        .bind(invite_id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() != 1 {
            return Ok(ConsumeOutcome::NotOpen);
        }
        tx.commit().await?;
        Ok(ConsumeOutcome::Consumed {
            uses_left: inv.uses_left - 1,
        })
    }

    async fn create_group(
        &self,
        group_id: &str,
        creator: &str,
        now_ms: u64,
    ) -> StoreResult<CreateGroupOutcome> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            "INSERT OR IGNORE INTO groups (group_id, epoch, created_at, created_by) \
             VALUES (?, 0, ?, ?)",
        )
        .bind(group_id)
        .bind(i64_of(now_ms))
        .bind(creator)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() != 1 {
            let by: Option<String> =
                sqlx::query_scalar("SELECT created_by FROM groups WHERE group_id = ?")
                    .bind(group_id)
                    .fetch_one(&mut *tx)
                    .await?;
            return Ok(if by.as_deref() == Some(creator) {
                CreateGroupOutcome::Yours
            } else {
                CreateGroupOutcome::Exists
            });
        }
        sqlx::query("INSERT INTO group_members (group_id, mailbox, confirmed) VALUES (?, ?, 1)")
            .bind(group_id)
            .bind(creator)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(CreateGroupOutcome::Created)
    }

    async fn get_group(&self, group_id: &str) -> StoreResult<Option<GroupState>> {
        let mut tx = self.reader.begin().await?;
        let row = sqlx::query("SELECT epoch FROM groups WHERE group_id = ?")
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else { return Ok(None) };
        let members = members_of(&mut tx, group_id).await?;
        Ok(Some(GroupState {
            current_epoch: u64_of(row.try_get(0)?),
            members: members.into_keys().collect(),
        }))
    }

    async fn deliver_group(
        &self,
        send: &GroupSend<'_>,
        limits: &Limits,
        now_ms: u64,
    ) -> StoreResult<GroupOutcome> {
        let mut tx = self.pool.begin().await?;
        if already_seen(&mut tx, send.msg, now_ms).await? {
            return Ok(GroupOutcome::Duplicate);
        }
        let row = sqlx::query("SELECT epoch FROM groups WHERE group_id = ?")
            .bind(send.group_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Ok(GroupOutcome::UnknownGroup);
        };
        let current = u64_of(row.try_get(0)?);
        let mut members = members_of(&mut tx, send.group_id).await?;
        if !members.contains_key(send.sender) {
            return Ok(GroupOutcome::NotMember);
        }
        let epoch_ok = match send.kind {
            Kind::Commit | Kind::Proposal => send.epoch == current,
            Kind::Application => {
                send.epoch == current || current.checked_sub(1) == Some(send.epoch)
            }
            Kind::WelcomeWrapped | Kind::JoinRequest | Kind::Knock => true,
        };
        if !epoch_ok {
            return Ok(GroupOutcome::EpochConflict {
                current_epoch: current,
            });
        }
        let ttl = u64::try_from(limits.message_ttl.as_millis()).unwrap_or(u64::MAX);
        let due_until = i64_of(now_ms.saturating_add(ttl));

        if send.kind == Kind::Commit && too_big(send, &members, limits) {
            return Ok(GroupOutcome::GroupFull);
        }
        if send.kind == Kind::WelcomeWrapped && !welcomes_due(&mut tx, send, now_ms).await? {
            return Ok(GroupOutcome::NotAwaitingWelcome);
        }
        let size = len_of(&send.msg.json);
        match admit(
            &mut tx,
            send.sender,
            send.group_id,
            size,
            mark_of(send),
            limits,
        )
        .await?
        {
            Ok(()) => {}
            Err(Refusal::StorageFull) => return Ok(GroupOutcome::StorageFull),
            Err(Refusal::OverBudget) => return Ok(GroupOutcome::OverBudget),
        }
        if send.kind == Kind::Commit {
            drop_removed(&mut tx, send, &members).await?;
        }

        // Sending in the group is what makes the sender's own queue count
        // the group's traffic as member traffic.
        if members.get(send.sender) == Some(&false) {
            confirm(&mut tx, send.group_id, send.sender).await?;
            members.insert(send.sender.to_owned(), true);
        }
        let recipients = recipients_of(send, &members);
        // A Welcome is all or nothing, like a direct send: a dropped one
        // can't be made up for by its recipient, and its sender retries.
        let marker = (send.kind != Kind::WelcomeWrapped).then_some(MarkerInfo {
            group_id: send.group_id,
            epoch: send.epoch,
        });
        let out = Outgoing {
            msg: send.msg,
            group_id: send.group_id,
            charged: send.sender,
        };
        let Some(fanout) =
            enqueue_all(&mut tx, &recipients, &out, limits, now_ms, marker.as_ref()).await?
        else {
            return Ok(GroupOutcome::QueueFull);
        };
        if send.kind == Kind::WelcomeWrapped {
            for r in send.to {
                sqlx::query("DELETE FROM welcome_due WHERE group_id = ? AND mailbox = ?")
                    .bind(send.group_id)
                    .bind(r)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        let mut epoch = current;
        if send.kind == Kind::Commit {
            epoch = current + 1;
            apply_commit(&mut tx, send, current, due_until).await?;
        }
        // In the same transaction, so a sweep can't delete a group right
        // after a send it accepted.
        record_activity(&mut tx, send.group_id, now_ms).await?;
        tx.commit().await?;
        Ok(GroupOutcome::Delivered {
            recipients: fanout.delivered,
            overflowed: fanout.overflowed,
            epoch,
        })
    }

    async fn deliver_direct(
        &self,
        kind: Kind,
        recipient: &str,
        msg: &NewMessage,
        limits: &Limits,
        now_ms: u64,
    ) -> StoreResult<DirectOutcome> {
        let mut tx = self.pool.begin().await?;
        if already_seen(&mut tx, msg, now_ms).await? {
            return Ok(DirectOutcome::Duplicate);
        }
        // A knock is charged to nobody: its budget would tell the knocker
        // when the owner acked it. The knock limits bound it instead.
        let charged = if kind == Kind::Knock {
            ""
        } else {
            msg.sender.as_str()
        };
        match admit(
            &mut tx,
            charged,
            "",
            len_of(&msg.json),
            Mark::Ordinary,
            limits,
        )
        .await?
        {
            Ok(()) => {}
            Err(Refusal::StorageFull) => return Ok(DirectOutcome::StorageFull),
            Err(Refusal::OverBudget) => return Ok(DirectOutcome::OverBudget),
        }
        let recipients = [(recipient.to_owned(), Bucket::NonMember)];
        let out = Outgoing {
            msg,
            group_id: "",
            charged,
        };
        if enqueue_all(&mut tx, &recipients, &out, limits, now_ms, None)
            .await?
            .is_none()
        {
            return Ok(DirectOutcome::QuotaExceeded);
        }
        tx.commit().await?;
        Ok(DirectOutcome::Delivered)
    }

    async fn storage_bytes(&self) -> StoreResult<u64> {
        let mut conn = self.reader.acquire().await?;
        storage_used(&mut conn).await
    }

    async fn pending(
        &self,
        mailbox: &str,
        after_seq: i64,
        limit: u32,
        max_bytes: u64,
        now_ms: u64,
    ) -> StoreResult<Vec<StoredMessage>> {
        // The running total runs over sizes only, so envelopes past the byte
        // cap are never read into memory.
        let rows = sqlx::query(
            "SELECT m.seq, m.msg_id, p.env, m.marker FROM messages m \
             JOIN payloads p ON p.id = m.payload \
             JOIN ( \
                 SELECT seq, SUM(size) OVER (ORDER BY seq) AS run, \
                        ROW_NUMBER() OVER (ORDER BY seq) AS n \
                 FROM (SELECT seq, size FROM messages \
                       WHERE mailbox = ?1 AND seq > ?2 AND expires_at > ?3 \
                       ORDER BY seq LIMIT ?4) \
             ) w ON m.seq = w.seq \
             WHERE w.n = 1 OR w.run <= ?5 ORDER BY m.seq",
        )
        .bind(mailbox)
        .bind(after_seq)
        .bind(i64_of(now_ms))
        .bind(i64::from(limit))
        .bind(i64_of(max_bytes))
        .fetch_all(&self.reader)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(StoredMessage {
                    seq: r.try_get(0)?,
                    msg_id: r.try_get(1)?,
                    json: r.try_get(2)?,
                    marker: r.try_get::<i64, _>(3)? != 0,
                })
            })
            .collect()
    }

    async fn ack(&self, mailbox: &str, msg_id: &str) -> StoreResult<bool> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "DELETE FROM messages WHERE mailbox = ? AND msg_id = ? \
             RETURNING mailbox, bucket, group_id, size, payload",
        )
        .bind(mailbox)
        .bind(msg_id)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            return Ok(false);
        }
        release(&mut tx, &released_rows(&rows)?).await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn purge_expired(&self, now_ms: u64) -> StoreResult<PurgeStats> {
        let now = i64_of(now_ms);
        let mut messages = 0;
        loop {
            let mut tx = self.pool.begin().await?;
            let sizes: Vec<i64> = sqlx::query_scalar(
                "SELECT size FROM messages WHERE expires_at <= ? \
                 ORDER BY expires_at, seq LIMIT ?",
            )
            .bind(now)
            .bind(PURGE_BATCH)
            .fetch_all(&mut *tx)
            .await?;
            if sizes.is_empty() {
                break;
            }
            let n = purge_batch_len(&sizes, PURGE_BATCH_BYTES);
            let rows = sqlx::query(
                "DELETE FROM messages WHERE seq IN \
                 (SELECT seq FROM messages WHERE expires_at <= ? \
                  ORDER BY expires_at, seq LIMIT ?) \
                 RETURNING mailbox, bucket, group_id, size, payload",
            )
            .bind(now)
            .bind(i64::try_from(n).unwrap_or(i64::MAX))
            .fetch_all(&mut *tx)
            .await?;
            release(&mut tx, &released_rows(&rows)?).await?;
            tx.commit().await?;
            messages += u64::try_from(rows.len()).unwrap_or(u64::MAX);
            // Let the WAL back into the database between batches, and let
            // the sends and acks waiting for the writer go first.
            sqlx::query("PRAGMA wal_checkpoint(PASSIVE)")
                .execute(&self.pool)
                .await?;
            tokio::task::yield_now().await;
        }
        let seen = sqlx::query("DELETE FROM seen WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        // `expires_at` is in seconds.
        let cutoff = i64_of(now_ms.saturating_sub(INVITE_GRACE_MS) / 1000);
        let invites = sqlx::query("DELETE FROM invites WHERE expires_at <= ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?
            .rows_affected();
        // Doors go as soon as they expire: the mapping is kept no longer
        // than a knock could use it.
        let doors = sqlx::query("DELETE FROM doors WHERE expires_at <= ?")
            .bind(i64_of(now_ms / 1000))
            .execute(&self.pool)
            .await?
            .rows_affected();
        let welcomes_due = sqlx::query("DELETE FROM welcome_due WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        // Copy the WAL into the database and truncate it, so the old page
        // images (deleted ciphertext among them) leave the WAL file too. A
        // busy checkpoint is retried at the next purge.
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await?;
        Ok(PurgeStats {
            messages,
            seen,
            invites,
            doors,
            welcomes_due,
        })
    }

    async fn group_creator(&self, group_id: &str) -> StoreResult<Option<String>> {
        let by: Option<Option<String>> =
            sqlx::query_scalar("SELECT created_by FROM groups WHERE group_id = ?")
                .bind(group_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(by.flatten())
    }

    async fn live_counts(&self) -> StoreResult<LiveCounts> {
        let row =
            sqlx::query("SELECT (SELECT COUNT(*) FROM invites), (SELECT COUNT(*) FROM groups)")
                .fetch_one(&self.pool)
                .await?;
        Ok(LiveCounts {
            invites: u64_of(row.try_get(0)?),
            groups: u64_of(row.try_get(1)?),
        })
    }

    async fn idle_groups(
        &self,
        cutoff_ms: u64,
        after: &str,
        limit: u32,
    ) -> StoreResult<Vec<IdleGroup>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT group_id FROM groups WHERE active_at <= ? AND created_at <= ? \
             AND group_id > ? ORDER BY group_id LIMIT ?",
        )
        .bind(i64_of(cutoff_ms))
        .bind(i64_of(cutoff_ms))
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let group_id: String = r.try_get(0)?;
            let members = members_of(&mut tx, &group_id).await?;
            out.push(IdleGroup {
                group_id,
                members: members.into_keys().collect(),
            });
        }
        Ok(out)
    }

    async fn delete_idle_group(&self, group_id: &str, cutoff_ms: u64) -> StoreResult<bool> {
        // Memberships go with the group (ON DELETE CASCADE).
        let res = sqlx::query(
            "DELETE FROM groups WHERE group_id = ? AND active_at <= ? AND created_at <= ?",
        )
        .bind(group_id)
        .bind(i64_of(cutoff_ms))
        .bind(i64_of(cutoff_ms))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_purge_batch_is_bounded_by_bytes_and_never_empty() {
        assert_eq!(purge_batch_len(&[], 100), 0);
        assert_eq!(purge_batch_len(&[40, 40, 40], 100), 2);
        assert_eq!(purge_batch_len(&[40, 60, 1], 100), 2);
        assert_eq!(purge_batch_len(&[10, 10], 100), 2);
        // One row bigger than a batch still goes, on its own.
        assert_eq!(purge_batch_len(&[500, 1], 100), 1);
        assert_eq!(share(64), 32);
    }
}
