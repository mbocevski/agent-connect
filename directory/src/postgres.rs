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

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow, PgSslMode};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::owner::record_fetch;
use crate::store::{
    EXPIRED_GRACE_SECS, FEED_TTL_SECS, FeedEntry, GoneKind, ListingRecord, NameState, OwnerCheck,
    OwnerStatus, PublishGuard, PublishOutcome, PurgeStats, REVOKED_TOKEN_TTL_SECS, RevokeOutcome,
    SEARCH_CANDIDATES, SearchDoc, SearchQuery, Store, StoreError, StoreResult, Tombstone,
    WithdrawOutcome, WithdrawalRecord,
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
        "name, identity, seq, token_id, owner_domain, owner_latest, owner_checked_at, \
         owner_verified_at, owner_negative, owner_negative_at, door_expires_at, token_expires_at, \
         published_at, key_changed_at, \
         bytes, sha256, search_title, search_skills, search_description, skill_keys"
    };
}

fn record(row: &PgRow) -> StoreResult<ListingRecord> {
    let check = |kind: Option<String>, at: Option<i64>| -> StoreResult<Option<(u64, OwnerCheck)>> {
        match (kind, at) {
            (Some(k), Some(t)) => OwnerCheck::parse(&k)
                .map(|c| Some((u64_of(t), c)))
                .ok_or_else(|| StoreError("unknown owner check".to_owned())),
            _ => Ok(None),
        }
    };
    Ok(ListingRecord {
        name: row.try_get("name")?,
        identity: row.try_get("identity")?,
        seq: u64_of(row.try_get("seq")?),
        token_id: row.try_get("token_id")?,
        owner_domain: row.try_get("owner_domain")?,
        owner: OwnerStatus {
            latest: check(
                row.try_get("owner_latest")?,
                row.try_get("owner_checked_at")?,
            )?,
            verified_at: row
                .try_get::<Option<i64>, _>("owner_verified_at")?
                .map(u64_of),
            negative: check(
                row.try_get("owner_negative")?,
                row.try_get("owner_negative_at")?,
            )?,
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
        owner_domain: row.try_get("owner_domain")?,
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
    identity: &str,
) -> StoreResult<Option<Tombstone>> {
    sqlx::query(
        "SELECT name, identity, seq, kind, created_at, owner_domain FROM tombstones \
         WHERE name = $1 AND identity = $2",
    )
    .bind(name)
    .bind(identity)
    .fetch_optional(&mut **tx)
    .await?
    .as_ref()
    .map(tombstone)
    .transpose()
}

async fn name_state_in(tx: &mut Transaction<'_, Postgres>, name: &str) -> StoreResult<NameState> {
    let high_water = sqlx::query("SELECT issued_at, identity FROM name_marks WHERE name = $1")
        .bind(name)
        .fetch_optional(&mut **tx)
        .await?
        .map(|row| -> StoreResult<(u64, String)> {
            Ok((u64_of(row.try_get("issued_at")?), row.try_get("identity")?))
        })
        .transpose()?;
    let tombstones =
        sqlx::query("SELECT identity, seq FROM tombstones WHERE name = $1 ORDER BY identity")
            .bind(name)
            .fetch_all(&mut **tx)
            .await?
            .iter()
            .map(|row| -> StoreResult<(String, u64)> {
                Ok((row.try_get("identity")?, u64_of(row.try_get("seq")?)))
            })
            .collect::<StoreResult<Vec<_>>>()?;
    let owner_revoked = sqlx::query(
        "SELECT identity, revoked_at FROM owner_revocations WHERE name = $1 ORDER BY identity",
    )
    .bind(name)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(|row| -> StoreResult<(String, u64)> {
        Ok((row.try_get("identity")?, u64_of(row.try_get("revoked_at")?)))
    })
    .collect::<StoreResult<Vec<_>>>()?;
    Ok(NameState {
        high_water,
        tombstones,
        owner_revoked,
    })
}

/// The identity and claimed owner domain of the name's latest tombstone.
async fn latest_tombstone_holder(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
) -> StoreResult<Option<(String, Option<String>)>> {
    sqlx::query(
        "SELECT identity, owner_domain FROM tombstones WHERE name = $1 \
         ORDER BY created_at DESC, identity DESC LIMIT 1",
    )
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?
    .map(|row| -> StoreResult<(String, Option<String>)> {
        Ok((row.try_get("identity")?, row.try_get("owner_domain")?))
    })
    .transpose()
}

/// Delete a listing, raise its tombstone and append to the feed.
#[allow(clippy::too_many_arguments)]
async fn bury(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
    identity: &str,
    seq: u64,
    kind: GoneKind,
    owner_domain: Option<&str>,
    entry: &str,
    now: u64,
) -> StoreResult<()> {
    sqlx::query("DELETE FROM listings WHERE name = $1")
        .bind(name)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO tombstones (name, identity, seq, kind, created_at, owner_domain) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (name, identity) DO UPDATE SET \
         seq = GREATEST(tombstones.seq, EXCLUDED.seq), kind = EXCLUDED.kind, \
         created_at = EXCLUDED.created_at, owner_domain = EXCLUDED.owner_domain",
    )
    .bind(name)
    .bind(identity)
    .bind(i64_of(seq))
    .bind(kind.as_str())
    .bind(i64_of(now))
    .bind(owner_domain)
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

/// Whether `opts` reaches the server only on this machine: a Unix socket
/// or a loopback address literal (`127.0.0.0/8`, `::1`). The name
/// `localhost` doesn't count: the resolver decides what it means.
fn is_local(opts: &PgConnectOptions) -> bool {
    let host = opts.get_host();
    opts.get_socket().is_some()
        || host.starts_with('/')
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The connection options for `url`, with the TLS rule applied: a server
/// that isn't local is reached over TLS with `sslmode=verify-full`
/// (certificate and host name checked) unless `insecure` is set. A URL that
/// asks for a weaker mode is refused without `insecure`. Returns the options
/// and whether the connection runs without verified TLS to a remote host
/// (the caller logs a warning).
///
/// # Errors
///
/// A message for a malformed URL, or a weaker `sslmode` to a remote host.
pub fn connect_options(url: &str, insecure: bool) -> Result<(PgConnectOptions, bool), String> {
    let opts = PgConnectOptions::from_str(url)
        .map_err(|_| "AC_DIRECTORY_DB is not a valid postgres:// URL".to_owned())?;
    if is_local(&opts) || matches!(opts.get_ssl_mode(), PgSslMode::VerifyFull) {
        return Ok((opts, false));
    }
    if insecure {
        return Ok((opts, true));
    }
    if url.contains("sslmode=") {
        return Err(
            "AC_DIRECTORY_DB asks for an sslmode weaker than verify-full for a remote host; \
             use sslmode=verify-full, or set AC_DIRECTORY_DB_INSECURE=1"
                .to_owned(),
        );
    }
    Ok((opts.ssl_mode(PgSslMode::VerifyFull), false))
}

impl PgStore {
    /// Connect to `url` (`postgres://...`) under [`connect_options`] (TLS
    /// with `verify-full` unless the host is local) and run the migrations.
    ///
    /// # Errors
    ///
    /// Fails if the URL is refused, or the database cannot be reached or
    /// migrated.
    pub async fn open(url: &str) -> StoreResult<Self> {
        let (opts, _) = connect_options(url, false).map_err(StoreError)?;
        Self::open_with(opts).await
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

    async fn name_state(&self, name: &str) -> StoreResult<NameState> {
        let mut tx = self.pool.begin().await?;
        let state = name_state_in(&mut tx, name).await?;
        tx.commit().await?;
        Ok(state)
    }

    async fn record_owner_revocation(
        &self,
        name: &str,
        identity: &str,
        at: u64,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO owner_revocations (name, identity, revoked_at) VALUES ($1, $2, $3) \
             ON CONFLICT (name, identity) DO UPDATE SET \
             revoked_at = GREATEST(owner_revocations.revoked_at, EXCLUDED.revoked_at)",
        )
        .bind(name)
        .bind(identity)
        .bind(i64_of(at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn token_revoked(&self, token_id: &str) -> StoreResult<bool> {
        Ok(
            sqlx::query("SELECT 1 FROM revoked_tokens WHERE token_id = $1")
                .bind(token_id)
                .fetch_optional(&self.pool)
                .await?
                .is_some(),
        )
    }

    async fn tombstone(&self, name: &str) -> StoreResult<Option<Tombstone>> {
        sqlx::query(
            "SELECT name, identity, seq, kind, created_at, owner_domain FROM tombstones WHERE name = $1 \
             ORDER BY created_at DESC, identity DESC LIMIT 1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .as_ref()
        .map(tombstone)
        .transpose()
    }

    async fn tombstone_for(&self, name: &str, identity: &str) -> StoreResult<Option<Tombstone>> {
        sqlx::query(
            "SELECT name, identity, seq, kind, created_at, owner_domain FROM tombstones \
             WHERE name = $1 AND identity = $2",
        )
        .bind(name)
        .bind(identity)
        .fetch_optional(&self.pool)
        .await?
        .as_ref()
        .map(tombstone)
        .transpose()
    }

    async fn publish(
        &self,
        r: &ListingRecord,
        guard: &PublishGuard,
    ) -> StoreResult<PublishOutcome> {
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
        if prev.as_ref().map(|p| &p.sha256) != guard.prev_sha256.as_ref()
            || name_state_in(&mut tx, &r.name).await? != guard.name
        {
            return Ok(PublishOutcome::Conflict);
        }
        let before = match &prev {
            Some(p) => Some((p.identity.clone(), p.owner_domain.clone())),
            None => latest_tombstone_holder(&mut tx, &r.name).await?,
        };
        let key_changed = before
            .is_some_and(|(identity, domain)| identity != r.identity || domain != r.owner_domain);
        let key_changed_at = if key_changed {
            Some(r.published_at)
        } else {
            prev.and_then(|p| p.key_changed_at)
        };
        sqlx::query(concat!(
            "INSERT INTO listings (",
            columns!(),
            ") VALUES \
             ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, \
             $19, $20) \
             ON CONFLICT (name) DO UPDATE SET identity = EXCLUDED.identity, seq = EXCLUDED.seq, \
             token_id = EXCLUDED.token_id, owner_domain = EXCLUDED.owner_domain, \
             owner_latest = EXCLUDED.owner_latest, owner_checked_at = EXCLUDED.owner_checked_at, \
             owner_verified_at = EXCLUDED.owner_verified_at, \
             owner_negative = EXCLUDED.owner_negative, \
             owner_negative_at = EXCLUDED.owner_negative_at, \
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
        .bind(r.owner.latest.map(|(_, c)| c.as_str()))
        .bind(r.owner.latest.map(|(t, _)| i64_of(t)))
        .bind(r.owner.verified_at.map(i64_of))
        .bind(r.owner.negative.map(|(_, c)| c.as_str()))
        .bind(r.owner.negative.map(|(t, _)| i64_of(t)))
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
        if let Some((issued_at, identity)) = &guard.high_water {
            sqlx::query(
                "INSERT INTO name_marks (name, issued_at, identity) VALUES ($1, $2, $3) \
                 ON CONFLICT (name) DO UPDATE SET issued_at = EXCLUDED.issued_at, \
                 identity = EXCLUDED.identity",
            )
            .bind(&r.name)
            .bind(i64_of(*issued_at))
            .bind(identity)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(PublishOutcome::Published { key_changed })
    }

    async fn withdraw(&self, w: &WithdrawalRecord<'_>, now: u64) -> StoreResult<WithdrawOutcome> {
        let mut tx = self.pool.begin().await?;
        lock(&mut tx, &format!("name:{}", w.name)).await?;
        let Some(listing) = get_in(&mut tx, w.name).await? else {
            let repeat = tombstone_in(&mut tx, w.name, w.identity)
                .await?
                .is_some_and(|t| t.seq >= w.seq);
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
            w.tombstone_seq,
            GoneKind::Withdrawal,
            listing.owner_domain.as_deref(),
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
                    "INSERT INTO tombstones (name, identity, seq, kind, created_at, owner_domain) \
                     VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (name, identity) DO UPDATE SET \
                     seq = GREATEST(tombstones.seq, EXCLUDED.seq), \
                     kind = EXCLUDED.kind, created_at = EXCLUDED.created_at, \
                     owner_domain = EXCLUDED.owner_domain",
                )
                .bind(&name)
                .bind(&l.identity)
                .bind(i64_of(l.seq))
                .bind(GoneKind::TokenRevocation.as_str())
                .bind(i64_of(now))
                .bind(&l.owner_domain)
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
            l.owner_domain.as_deref(),
            entry,
            now,
        )
        .await?;
        sqlx::query(
            "INSERT INTO owner_revocations (name, identity, revoked_at) VALUES ($1, $2, $3) \
             ON CONFLICT (name, identity) DO UPDATE SET \
             revoked_at = GREATEST(owner_revocations.revoked_at, EXCLUDED.revoked_at)",
        )
        .bind(name)
        .bind(&l.identity)
        .bind(i64_of(now))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn record_owner_check(
        &self,
        name: &str,
        sha256: &str,
        at: u64,
        check: OwnerCheck,
    ) -> StoreResult<bool> {
        let mut tx = self.pool.begin().await?;
        lock(&mut tx, &format!("name:{name}")).await?;
        let Some(current) = get_in(&mut tx, name).await?.filter(|l| l.sha256 == sha256) else {
            return Ok(false);
        };
        let s: OwnerStatus = record_fetch(current.owner, at, check);
        sqlx::query(
            "UPDATE listings SET owner_latest = $3, owner_checked_at = $4, \
             owner_verified_at = $5, owner_negative = $6, owner_negative_at = $7 \
             WHERE name = $1 AND sha256 = $2",
        )
        .bind(name)
        .bind(sha256)
        .bind(s.latest.map(|(_, c)| c.as_str()))
        .bind(s.latest.map(|(t, _)| i64_of(t)))
        .bind(s.verified_at.map(i64_of))
        .bind(s.negative.map(|(_, c)| c.as_str()))
        .bind(s.negative.map(|(t, _)| i64_of(t)))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn due_owner_checks(
        &self,
        checked_before: u64,
        now: u64,
        limit: u32,
    ) -> StoreResult<Vec<ListingRecord>> {
        sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM listings WHERE owner_domain IS NOT NULL AND token_expires_at > $2 \
             AND (owner_checked_at IS NULL OR owner_checked_at < $1) \
             ORDER BY COALESCE(owner_checked_at, 0), name LIMIT $3"
        ))
        .bind(i64_of(checked_before))
        .bind(i64_of(now))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(record)
        .collect()
    }

    async fn by_identity(&self, identity: &str, now: u64) -> StoreResult<Vec<ListingRecord>> {
        sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM listings WHERE identity = $1 AND token_expires_at > $2 ORDER BY name"
        ))
        .bind(identity)
        .bind(i64_of(now))
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(record)
        .collect()
    }

    async fn listed_after(
        &self,
        after: &str,
        now: u64,
        limit: u32,
    ) -> StoreResult<Vec<ListingRecord>> {
        sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM listings WHERE name > $1 AND token_expires_at > $2 ORDER BY name LIMIT $3"
        ))
        .bind(after)
        .bind(i64_of(now))
        .bind(i64::from(limit))
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
        let expired_listings = sqlx::query("DELETE FROM listings WHERE token_expires_at <= $1")
            .bind(before(EXPIRED_GRACE_SECS))
            .execute(&self.pool)
            .await?
            .rows_affected();
        let feed = sqlx::query("DELETE FROM feed WHERE created_at <= $1")
            .bind(before(FEED_TTL_SECS))
            .execute(&self.pool)
            .await?
            .rows_affected();
        let revoked_tokens = sqlx::query("DELETE FROM revoked_tokens WHERE revoked_at <= $1")
            .bind(before(REVOKED_TOKEN_TTL_SECS))
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(PurgeStats {
            expired_listings,
            feed,
            revoked_tokens,
        })
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    fn mode(url: &str, insecure: bool) -> Result<(PgSslMode, bool), String> {
        connect_options(url, insecure).map(|(o, warn)| (o.get_ssl_mode(), warn))
    }

    #[test]
    fn remote_servers_need_verified_tls() {
        let remote = "postgres://u@db.example.org/directory";
        assert!(matches!(
            mode(remote, false),
            Ok((PgSslMode::VerifyFull, false))
        ));
        assert!(matches!(
            mode(&format!("{remote}?sslmode=verify-full"), false),
            Ok((PgSslMode::VerifyFull, false))
        ));
        for weak in ["disable", "prefer", "require", "verify-ca"] {
            assert!(
                mode(&format!("{remote}?sslmode={weak}"), false).is_err(),
                "{weak}"
            );
            assert!(
                matches!(
                    mode(&format!("{remote}?sslmode={weak}"), true),
                    Ok((_, true))
                ),
                "{weak}"
            );
        }
    }

    #[test]
    fn local_servers_may_go_without() {
        for url in [
            "postgres://u@127.0.0.1:5432/d?sslmode=disable",
            "postgres://u@[::1]/d?sslmode=disable",
            "postgres://u@%2Frun%2Fpostgresql/d",
        ] {
            assert!(matches!(mode(url, false), Ok((_, false))), "{url}");
        }
        assert!(connect_options("not a url", false).is_err());
        // `localhost` is a name, not a loopback literal.
        assert!(mode("postgres://u@localhost/d?sslmode=disable", false).is_err());
        assert!(matches!(
            mode("postgres://u@localhost/d", false),
            Ok((PgSslMode::VerifyFull, false))
        ));
    }
}
