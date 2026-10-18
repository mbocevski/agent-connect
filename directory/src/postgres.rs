//! Postgres [`Store`] built on `sqlx`.
//!
//! Every deciding operation runs in one transaction that first takes a
//! transaction-scoped advisory lock on the listing name (or on the token id
//! for revocations), so concurrent publishes and withdrawals of one name are
//! serialised. Full-text search uses the generated `search_vec` column
//! (weights A: names, B: skills, C: description), `websearch_to_tsquery`
//! and `ts_rank`.

use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::store::{
    FeedEntry, GoneKind, ListingRecord, OwnerCheck, OwnerStatus, PublishOutcome, PurgeStats,
    REVOKED_TOKEN_TTL_SECS, RevokeOutcome, SEARCH_CANDIDATES, SearchDoc, SearchQuery, Store,
    StoreError, StoreResult, TOMBSTONE_TTL_SECS, Tombstone, WithdrawOutcome, WithdrawalRecord,
};

/// A Postgres-backed store.
#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
}

fn i64_of(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn u64_of(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

// A macro, not a const, so every query stays a string literal (`concat!`).
macro_rules! columns {
    () => {
        "name, identity, seq, token_id, owner_domain, owner_last, owner_checked_at, \
         owner_verified_at, door_expires_at, token_expires_at, published_at, key_changed_at, \
         bytes, sha256, search_title, search_skills, search_description, skill_keys"
    };
}

fn record(row: &PgRow) -> StoreResult<ListingRecord> {
    let last: String = row.try_get("owner_last")?;
    Ok(ListingRecord {
        name: row.try_get("name")?,
        identity: row.try_get("identity")?,
        seq: u64_of(row.try_get("seq")?),
        token_id: row.try_get("token_id")?,
        owner_domain: row.try_get("owner_domain")?,
        owner: OwnerStatus {
            last: OwnerCheck::parse(&last)
                .ok_or_else(|| StoreError("unknown owner state".to_owned()))?,
            checked_at: row
                .try_get::<Option<i64>, _>("owner_checked_at")?
                .map(u64_of),
            verified_at: row
                .try_get::<Option<i64>, _>("owner_verified_at")?
                .map(u64_of),
        },
        door_expires_at: row
            .try_get::<Option<i64>, _>("door_expires_at")?
            .map(u64_of),
        token_expires_at: u64_of(row.try_get("token_expires_at")?),
        published_at: u64_of(row.try_get("published_at")?),
        key_changed_at: row.try_get::<Option<i64>, _>("key_changed_at")?.map(u64_of),
        bytes: row.try_get("bytes")?,
        sha256: row.try_get("sha256")?,
        search: SearchDoc {
            title: row.try_get("search_title")?,
            skills: row.try_get("search_skills")?,
            description: row.try_get("search_description")?,
            skill_keys: row.try_get("skill_keys")?,
        },
    })
}

fn tombstone(row: &PgRow) -> StoreResult<Tombstone> {
    let kind: String = row.try_get("kind")?;
    Ok(Tombstone {
        name: row.try_get("name")?,
        identity: row.try_get("identity")?,
        seq: u64_of(row.try_get("seq")?),
        kind: GoneKind::parse(&kind).ok_or_else(|| StoreError("unknown tombstone".to_owned()))?,
        created_at: u64_of(row.try_get("created_at")?),
    })
}

async fn lock(tx: &mut Transaction<'_, Postgres>, key: &str) -> StoreResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn get_in(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
) -> StoreResult<Option<ListingRecord>> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM listings WHERE name = $1"
    ))
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?
    .as_ref()
    .map(record)
    .transpose()
}

async fn tombstone_in(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
) -> StoreResult<Option<Tombstone>> {
    sqlx::query("SELECT name, identity, seq, kind, created_at FROM tombstones WHERE name = $1")
        .bind(name)
        .fetch_optional(&mut **tx)
        .await?
        .as_ref()
        .map(tombstone)
        .transpose()
}

/// Delete a listing, raise its tombstone and append to the feed.
async fn bury(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
    identity: &str,
    seq: u64,
    kind: GoneKind,
    entry: &str,
    now: u64,
) -> StoreResult<()> {
    sqlx::query("DELETE FROM listings WHERE name = $1")
        .bind(name)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO tombstones (name, identity, seq, kind, created_at) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (name) DO UPDATE SET identity = EXCLUDED.identity, \
         seq = GREATEST(tombstones.seq, EXCLUDED.seq), kind = EXCLUDED.kind, \
         created_at = EXCLUDED.created_at",
    )
    .bind(name)
    .bind(identity)
    .bind(i64_of(seq))
    .bind(kind.as_str())
    .bind(i64_of(now))
    .execute(&mut **tx)
    .await?;
    append(tx, kind, entry, now).await
}

async fn append(
    tx: &mut Transaction<'_, Postgres>,
    kind: GoneKind,
    entry: &str,
    now: u64,
) -> StoreResult<()> {
    sqlx::query("INSERT INTO feed (kind, entry, created_at) VALUES ($1, $2, $3)")
        .bind(kind.as_str())
        .bind(entry)
        .bind(i64_of(now))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl PgStore {
    /// Connect to `url` (`postgres://...`) and run the migrations.
    ///
    /// # Errors
    ///
    /// Fails if the database cannot be reached or migrated.
    pub async fn open(url: &str) -> StoreResult<Self> {
        Self::open_with(PgConnectOptions::from_str(url)?).await
    }

    /// Connect with explicit options and run the migrations.
    ///
    /// # Errors
    ///
    /// Fails if the database cannot be reached or migrated.
    pub async fn open_with(opts: PgConnectOptions) -> StoreResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }
}

impl Store for PgStore {
    async fn get(&self, name: &str) -> StoreResult<Option<ListingRecord>> {
        sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM listings WHERE name = $1"
        ))
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .as_ref()
        .map(record)
        .transpose()
    }

    async fn tombstone(&self, name: &str) -> StoreResult<Option<Tombstone>> {
        sqlx::query("SELECT name, identity, seq, kind, created_at FROM tombstones WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(tombstone)
            .transpose()
    }

    async fn publish(&self, r: &ListingRecord) -> StoreResult<PublishOutcome> {
        let mut tx = self.pool.begin().await?;
        // Lock order everywhere: token, then name.
        lock(&mut tx, &format!("token:{}", r.token_id)).await?;
        lock(&mut tx, &format!("name:{}", r.name)).await?;
        let revoked = sqlx::query("SELECT 1 FROM revoked_tokens WHERE token_id = $1")
            .bind(&r.token_id)
            .fetch_optional(&mut *tx)
            .await?;
        if revoked.is_some() {
            return Ok(PublishOutcome::TokenRevoked);
        }
        let prev = get_in(&mut tx, &r.name).await?;
        if prev.as_ref().is_some_and(|p| p.sha256 == r.sha256) {
            return Ok(PublishOutcome::Unchanged);
        }
        let tomb = tombstone_in(&mut tx, &r.name).await?;
        let current = prev
            .as_ref()
            .map(|p| p.seq)
            .max(tomb.as_ref().map(|t| t.seq));
        if let Some(current) = current.filter(|c| r.seq <= *c) {
            return Ok(PublishOutcome::StaleSeq { current });
        }
        let prev_identity = prev
            .as_ref()
            .map(|p| p.identity.clone())
            .or_else(|| tomb.map(|t| t.identity));
        let key_changed = prev_identity.is_some_and(|i| i != r.identity);
        let key_changed_at = if key_changed {
            Some(r.published_at)
        } else {
            prev.and_then(|p| p.key_changed_at)
        };
        sqlx::query(concat!(
            "INSERT INTO listings (",
            columns!(),
            ") VALUES \
             ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
             ON CONFLICT (name) DO UPDATE SET identity = EXCLUDED.identity, seq = EXCLUDED.seq, \
             token_id = EXCLUDED.token_id, owner_domain = EXCLUDED.owner_domain, \
             owner_last = EXCLUDED.owner_last, owner_checked_at = EXCLUDED.owner_checked_at, \
             owner_verified_at = EXCLUDED.owner_verified_at, \
             door_expires_at = EXCLUDED.door_expires_at, \
             token_expires_at = EXCLUDED.token_expires_at, published_at = EXCLUDED.published_at, \
             key_changed_at = EXCLUDED.key_changed_at, bytes = EXCLUDED.bytes, \
             sha256 = EXCLUDED.sha256, search_title = EXCLUDED.search_title, \
             search_skills = EXCLUDED.search_skills, \
             search_description = EXCLUDED.search_description, skill_keys = EXCLUDED.skill_keys"
        ))
        .bind(&r.name)
        .bind(&r.identity)
        .bind(i64_of(r.seq))
        .bind(&r.token_id)
        .bind(&r.owner_domain)
        .bind(r.owner.last.as_str())
        .bind(r.owner.checked_at.map(i64_of))
        .bind(r.owner.verified_at.map(i64_of))
        .bind(r.door_expires_at.map(i64_of))
        .bind(i64_of(r.token_expires_at))
        .bind(i64_of(r.published_at))
        .bind(key_changed_at.map(i64_of))
        .bind(&r.bytes)
        .bind(&r.sha256)
        .bind(&r.search.title)
        .bind(&r.search.skills)
        .bind(&r.search.description)
        .bind(&r.search.skill_keys)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(PublishOutcome::Published { key_changed })
    }

    async fn withdraw(&self, w: &WithdrawalRecord<'_>, now: u64) -> StoreResult<WithdrawOutcome> {
        let mut tx = self.pool.begin().await?;
        lock(&mut tx, &format!("name:{}", w.name)).await?;
        let Some(listing) = get_in(&mut tx, w.name).await? else {
            let repeat = tombstone_in(&mut tx, w.name)
                .await?
                .is_some_and(|t| t.identity == w.identity && t.seq >= w.seq);
            return Ok(if repeat {
                WithdrawOutcome::Repeat
            } else {
                WithdrawOutcome::NotListed
            });
        };
        if listing.identity != w.identity {
            return Ok(WithdrawOutcome::WrongIdentity);
        }
        if w.seq < listing.seq {
            return Ok(WithdrawOutcome::StaleSeq);
        }
        bury(
            &mut tx,
            w.name,
            w.identity,
            w.seq,
            GoneKind::Withdrawal,
            w.entry,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(WithdrawOutcome::Withdrawn)
    }

    async fn revoke_token(
        &self,
        token_id: &str,
        entry: &str,
        now: u64,
    ) -> StoreResult<RevokeOutcome> {
        let mut tx = self.pool.begin().await?;
        lock(&mut tx, &format!("token:{token_id}")).await?;
        let inserted = sqlx::query(
            "INSERT INTO revoked_tokens (token_id, revoked_at) VALUES ($1, $2) \
             ON CONFLICT (token_id) DO NOTHING",
        )
        .bind(token_id)
        .bind(i64_of(now))
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted == 0 {
            return Ok(RevokeOutcome::Repeat);
        }
        let hit = sqlx::query("SELECT name FROM listings WHERE token_id = $1")
            .bind(token_id)
            .fetch_optional(&mut *tx)
            .await?;
        let mut withdrawn = None;
        if let Some(row) = hit {
            let name: String = row.try_get("name")?;
            lock(&mut tx, &format!("name:{name}")).await?;
            if let Some(l) = get_in(&mut tx, &name)
                .await?
                .filter(|l| l.token_id == token_id)
            {
                sqlx::query("DELETE FROM listings WHERE name = $1")
                    .bind(&name)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query(
                    "INSERT INTO tombstones (name, identity, seq, kind, created_at) \
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT (name) DO UPDATE SET \
                     identity = EXCLUDED.identity, seq = GREATEST(tombstones.seq, EXCLUDED.seq), \
                     kind = EXCLUDED.kind, created_at = EXCLUDED.created_at",
                )
                .bind(&name)
                .bind(&l.identity)
                .bind(i64_of(l.seq))
                .bind(GoneKind::TokenRevocation.as_str())
                .bind(i64_of(now))
                .execute(&mut *tx)
                .await?;
                withdrawn = Some((name, l.identity));
            }
        }
        append(&mut tx, GoneKind::TokenRevocation, entry, now).await?;
        tx.commit().await?;
        Ok(RevokeOutcome::Revoked { withdrawn })
    }

    async fn owner_revoked(
        &self,
        name: &str,
        sha256: &str,
        entry: &str,
        now: u64,
    ) -> StoreResult<bool> {
        let mut tx = self.pool.begin().await?;
        lock(&mut tx, &format!("name:{name}")).await?;
        let Some(l) = get_in(&mut tx, name).await?.filter(|l| l.sha256 == sha256) else {
            return Ok(false);
        };
        bury(
            &mut tx,
            name,
            &l.identity,
            l.seq,
            GoneKind::OwnerRevocation,
            entry,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn set_owner(&self, name: &str, sha256: &str, s: OwnerStatus) -> StoreResult<bool> {
        let n = sqlx::query(
            "UPDATE listings SET owner_last = $3, owner_checked_at = $4, owner_verified_at = $5 \
             WHERE name = $1 AND sha256 = $2",
        )
        .bind(name)
        .bind(sha256)
        .bind(s.last.as_str())
        .bind(s.checked_at.map(i64_of))
        .bind(s.verified_at.map(i64_of))
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(n > 0)
    }

    async fn due_owner_checks(
        &self,
        checked_before: u64,
        limit: u32,
    ) -> StoreResult<Vec<ListingRecord>> {
        sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM listings WHERE owner_domain IS NOT NULL \
             AND (owner_checked_at IS NULL OR owner_checked_at < $1) \
             ORDER BY COALESCE(owner_checked_at, 0), name LIMIT $2"
        ))
        .bind(i64_of(checked_before))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(record)
        .collect()
    }

    async fn by_identity(&self, identity: &str) -> StoreResult<Vec<ListingRecord>> {
        sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM listings WHERE identity = $1 ORDER BY name"
        ))
        .bind(identity)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(record)
        .collect()
    }

    async fn search(&self, q: &SearchQuery) -> StoreResult<Vec<ListingRecord>> {
        let rows = match &q.text {
            Some(text) => {
                sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM listings, websearch_to_tsquery('english', $1) query \
                     WHERE search_vec @@ query AND token_expires_at > $2 \
                     AND ($3::text IS NULL OR $3 = ANY(skill_keys)) \
                     ORDER BY ts_rank(search_vec, query) DESC, name LIMIT $4"
                ))
                .bind(text)
                .bind(i64_of(q.now))
                .bind(&q.skill)
                .bind(i64::from(SEARCH_CANDIDATES))
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query(concat!(
                    "SELECT ",
                    columns!(),
                    " FROM listings WHERE token_expires_at > $1 \
                     AND ($2::text IS NULL OR $2 = ANY(skill_keys)) ORDER BY name LIMIT $3"
                ))
                .bind(i64_of(q.now))
                .bind(&q.skill)
                .bind(i64::from(SEARCH_CANDIDATES))
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(record).collect()
    }

    async fn feed(&self, after: i64, limit: u32) -> StoreResult<Vec<FeedEntry>> {
        sqlx::query(
            "SELECT pos, kind, entry, created_at FROM feed WHERE pos > $1 ORDER BY pos LIMIT $2",
        )
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| {
            let kind: String = row.try_get("kind")?;
            Ok(FeedEntry {
                cursor: row.try_get("pos")?,
                kind: GoneKind::parse(&kind)
                    .ok_or_else(|| StoreError("unknown feed entry".to_owned()))?,
                entry: row.try_get("entry")?,
                created_at: u64_of(row.try_get("created_at")?),
            })
        })
        .collect()
    }

    async fn purge(&self, now: u64) -> StoreResult<PurgeStats> {
        let before = |ttl: u64| i64_of(now.saturating_sub(ttl));
        let tombstones = sqlx::query("DELETE FROM tombstones WHERE created_at <= $1")
            .bind(before(TOMBSTONE_TTL_SECS))
            .execute(&self.pool)
            .await?
            .rows_affected();
        let feed = sqlx::query("DELETE FROM feed WHERE created_at <= $1")
            .bind(before(TOMBSTONE_TTL_SECS))
            .execute(&self.pool)
            .await?
            .rows_affected();
        let revoked_tokens = sqlx::query("DELETE FROM revoked_tokens WHERE revoked_at <= $1")
            .bind(before(REVOKED_TOKEN_TTL_SECS))
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(PurgeStats {
            tombstones,
            feed,
            revoked_tokens,
        })
    }
}
