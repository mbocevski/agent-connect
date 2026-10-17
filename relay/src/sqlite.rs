//! SQLite [`Store`] built on `sqlx`.
//!
//! The pool holds exactly one connection, so every operation (and every
//! transaction) is serialised. That is what makes the check-then-write
//! sequences in this file race-free; a Postgres backend would use row locks
//! instead.

use std::collections::BTreeSet;
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

use crate::proto::Kind;
use crate::store::{
    ConsumeOutcome, CreateGroupOutcome, DirectOutcome, GroupOutcome, GroupSend, GroupState,
    InviteRecord, Limits, NewMessage, PurgeStats, RevokeOutcome, Store, StoreError, StoreResult,
    StoredMessage,
};

/// Grace period during which an expired invite stays readable so its landing
/// page can still say "expired".
const INVITE_GRACE_MS: u64 = 7 * 24 * 3600 * 1000;

/// A SQLite-backed store.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
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
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(opts)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
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

async fn members_of(
    tx: &mut Transaction<'_, Sqlite>,
    group_id: &str,
) -> StoreResult<BTreeSet<String>> {
    let rows = sqlx::query("SELECT mailbox FROM group_members WHERE group_id = ?")
        .bind(group_id)
        .fetch_all(&mut **tx)
        .await?;
    rows.iter()
        .map(|r| r.try_get::<String, _>(0).map_err(StoreError::from))
        .collect()
}

async fn already_seen(
    tx: &mut Transaction<'_, Sqlite>,
    msg: &NewMessage,
    now_ms: u64,
) -> StoreResult<bool> {
    let row = sqlx::query("SELECT 1 FROM seen WHERE sender = ? AND msg_id = ? AND expires_at > ?")
        .bind(&msg.sender)
        .bind(&msg.msg_id)
        .bind(i64_of(now_ms))
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row.is_some())
}

async fn queue_bytes(
    tx: &mut Transaction<'_, Sqlite>,
    mailbox: &str,
    now_ms: u64,
) -> StoreResult<u64> {
    let row = sqlx::query(
        "SELECT COALESCE(SUM(size), 0) FROM messages WHERE mailbox = ? AND expires_at > ?",
    )
    .bind(mailbox)
    .bind(i64_of(now_ms))
    .fetch_one(&mut **tx)
    .await?;
    Ok(u64_of(row.try_get::<i64, _>(0)?))
}

/// Queue `msg` for each recipient and record its idempotency key. Returns
/// false (and writes nothing) if any queue would exceed its quota.
async fn enqueue_all(
    tx: &mut Transaction<'_, Sqlite>,
    recipients: &BTreeSet<String>,
    msg: &NewMessage,
    limits: &Limits,
    now_ms: u64,
) -> StoreResult<bool> {
    let size = u64::try_from(msg.json.len()).unwrap_or(u64::MAX);
    for r in recipients {
        if queue_bytes(tx, r, now_ms).await?.saturating_add(size) > limits.queue_max_bytes {
            return Ok(false);
        }
    }
    let ttl = u64::try_from(limits.message_ttl.as_millis()).unwrap_or(u64::MAX);
    let expires = i64_of(now_ms.saturating_add(ttl));
    for r in recipients {
        sqlx::query(
            "INSERT INTO messages (mailbox, msg_id, env, size, expires_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(r)
        .bind(&msg.msg_id)
        .bind(&msg.json)
        .bind(i64_of(size))
        .bind(expires)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query("INSERT INTO seen (sender, msg_id, expires_at) VALUES (?, ?, ?)")
        .bind(&msg.sender)
        .bind(&msg.msg_id)
        .bind(expires)
        .execute(&mut **tx)
        .await?;
    Ok(true)
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

impl Store for SqliteStore {
    async fn create_invite(&self, inv: &InviteRecord, now_ms: u64) -> StoreResult<bool> {
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
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    async fn get_invite(&self, invite_id: &str) -> StoreResult<Option<InviteRecord>> {
        let row = sqlx::query("SELECT * FROM invites WHERE invite_id = ?")
            .bind(invite_id)
            .fetch_optional(&self.pool)
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
            "INSERT OR IGNORE INTO groups (group_id, epoch, created_at) VALUES (?, 0, ?)",
        )
        .bind(group_id)
        .bind(i64_of(now_ms))
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() != 1 {
            return Ok(CreateGroupOutcome::Exists);
        }
        sqlx::query("INSERT INTO group_members (group_id, mailbox) VALUES (?, ?)")
            .bind(group_id)
            .bind(creator)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(CreateGroupOutcome::Created)
    }

    async fn get_group(&self, group_id: &str) -> StoreResult<Option<GroupState>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT epoch FROM groups WHERE group_id = ?")
            .bind(group_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else { return Ok(None) };
        let members = members_of(&mut tx, group_id).await?;
        Ok(Some(GroupState {
            current_epoch: u64_of(row.try_get(0)?),
            members: members.into_iter().collect(),
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
        let members = members_of(&mut tx, send.group_id).await?;
        if !members.contains(send.sender) {
            return Ok(GroupOutcome::NotMember);
        }
        let epoch_ok = match send.kind {
            Kind::Commit | Kind::Proposal => send.epoch == current,
            Kind::Application => {
                send.epoch == current || current.checked_sub(1) == Some(send.epoch)
            }
            Kind::WelcomeWrapped | Kind::JoinRequest => true,
        };
        if !epoch_ok {
            return Ok(GroupOutcome::EpochConflict {
                current_epoch: current,
            });
        }

        let mut next_members = members.clone();
        let recipients: BTreeSet<String> = match send.kind {
            // Everyone who was a member when the commit was made, including
            // the sender (confirmation) and anyone it removes (so they learn
            // of it). New members get a Welcome instead.
            Kind::Commit => {
                for m in send.remove {
                    next_members.remove(m);
                }
                next_members.extend(send.add.iter().cloned());
                if next_members.len() > limits.group_max {
                    return Ok(GroupOutcome::GroupFull);
                }
                members.clone()
            }
            Kind::Proposal | Kind::Application => members
                .iter()
                .filter(|m| m.as_str() != send.sender)
                .cloned()
                .collect(),
            Kind::WelcomeWrapped | Kind::JoinRequest => send.to.iter().cloned().collect(),
        };
        if !enqueue_all(&mut tx, &recipients, send.msg, limits, now_ms).await? {
            return Ok(GroupOutcome::QuotaExceeded);
        }
        let mut epoch = current;
        if send.kind == Kind::Commit {
            epoch = current + 1;
            let res = sqlx::query("UPDATE groups SET epoch = ? WHERE group_id = ? AND epoch = ?")
                .bind(i64_of(epoch))
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
            }
            for m in send.add {
                sqlx::query(
                    "INSERT OR IGNORE INTO group_members (group_id, mailbox) VALUES (?, ?)",
                )
                .bind(send.group_id)
                .bind(m)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(GroupOutcome::Delivered {
            recipients: recipients.into_iter().collect(),
            epoch,
        })
    }

    async fn deliver_direct(
        &self,
        recipient: &str,
        msg: &NewMessage,
        limits: &Limits,
        now_ms: u64,
    ) -> StoreResult<DirectOutcome> {
        let mut tx = self.pool.begin().await?;
        if already_seen(&mut tx, msg, now_ms).await? {
            return Ok(DirectOutcome::Duplicate);
        }
        let recipients = BTreeSet::from([recipient.to_owned()]);
        if !enqueue_all(&mut tx, &recipients, msg, limits, now_ms).await? {
            return Ok(DirectOutcome::QuotaExceeded);
        }
        tx.commit().await?;
        Ok(DirectOutcome::Delivered)
    }

    async fn pending(
        &self,
        mailbox: &str,
        after_seq: i64,
        limit: u32,
        now_ms: u64,
    ) -> StoreResult<Vec<StoredMessage>> {
        let rows = sqlx::query(
            "SELECT seq, msg_id, env FROM messages \
             WHERE mailbox = ? AND seq > ? AND expires_at > ? ORDER BY seq LIMIT ?",
        )
        .bind(mailbox)
        .bind(after_seq)
        .bind(i64_of(now_ms))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(StoredMessage {
                    seq: r.try_get(0)?,
                    msg_id: r.try_get(1)?,
                    json: r.try_get(2)?,
                })
            })
            .collect()
    }

    async fn ack(&self, mailbox: &str, msg_id: &str) -> StoreResult<bool> {
        let res = sqlx::query("DELETE FROM messages WHERE mailbox = ? AND msg_id = ?")
            .bind(mailbox)
            .bind(msg_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn purge_expired(&self, now_ms: u64) -> StoreResult<PurgeStats> {
        let now = i64_of(now_ms);
        let messages = sqlx::query("DELETE FROM messages WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
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
        Ok(PurgeStats {
            messages,
            seen,
            invites,
        })
    }
}
