//! Storage seam for the directory.
//!
//! It holds exactly what ADR-006 Decision 4 lists: per listing the canonical
//! bytes, their SHA-256, the indexed fields, the owner state and check times,
//! the door and token expiries and the publish time; tombstones and the
//! withdrawal feed (kept 30 days); and the revoked token ids. Nothing about
//! readers or searchers.
//!
//! Every method that decides something (the `seq` rules, withdrawal, token
//! revocation) is one atomic operation, so implementations own the
//! race-safety. [`MemoryStore`](crate::memory::MemoryStore) backs the fast
//! tests; [`PgStore`](crate::postgres::PgStore) is the shipped backend.

use std::future::Future;

/// How long feed entries are kept, in seconds (30 days). Tombstones are
/// never purged: SPEC §13.2.2 keeps them as long as the name.
pub const FEED_TTL_SECS: u64 = 30 * 86_400;
/// How long an expired listing is kept (answering 410) before it is purged.
pub const EXPIRED_GRACE_SECS: u64 = 30 * 86_400;
/// How long a revoked token id is kept: the longest token lifetime (90 days).
pub const REVOKED_TOKEN_TTL_SECS: u64 = 90 * 86_400;
/// Most candidates a search returns before the directory filters them.
pub const SEARCH_CANDIDATES: u32 = 200;

/// A storage failure. The text never contains stored values, so it is safe
/// to log.
#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage error: {}", self.0)
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        // Database messages can quote stored values; keep only the kind.
        let kind = match &e {
            sqlx::Error::Database(db) => {
                format!("database error {}", db.code().unwrap_or_default())
            }
            sqlx::Error::PoolTimedOut => "pool timed out".to_owned(),
            sqlx::Error::PoolClosed => "pool closed".to_owned(),
            sqlx::Error::Io(_) => "io error".to_owned(),
            sqlx::Error::Tls(_) => "tls error".to_owned(),
            sqlx::Error::RowNotFound => "row not found".to_owned(),
            _ => "query failed".to_owned(),
        };
        StoreError(kind)
    }
}

impl From<sqlx::migrate::MigrateError> for StoreError {
    fn from(_: sqlx::migrate::MigrateError) -> Self {
        StoreError("migration failed".to_owned())
    }
}

/// Result alias for storage operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// The result of one owner-file fetch (Decision 2), as the core names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerCheck {
    /// The file vouched for the identity.
    Vouched,
    /// The file doesn't vouch for the identity in this listing.
    NotVouched,
    /// The file revokes the identity.
    Revoked,
    /// No file was fetched, or it isn't a valid owner file.
    Failed,
}

impl OwnerCheck {
    /// The stored name (the core's `Vouch` and `FetchResult` names).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OwnerCheck::Vouched => "vouches",
            OwnerCheck::NotVouched => "does_not_vouch",
            OwnerCheck::Revoked => "revoked",
            OwnerCheck::Failed => "failed",
        }
    }

    /// Parse a stored name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "vouches" => OwnerCheck::Vouched,
            "does_not_vouch" => OwnerCheck::NotVouched,
            "revoked" => OwnerCheck::Revoked,
            "failed" => OwnerCheck::Failed,
            _ => return None,
        })
    }
}

/// The stored owner-check history: exactly what the core's `owner_state`
/// needs (`OwnerChecks`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OwnerStatus {
    /// The latest completed fetch and its time.
    pub latest: Option<(u64, OwnerCheck)>,
    /// When a fetch last vouched.
    pub verified_at: Option<u64>,
    /// The latest negative result (doesn't vouch, or revoked) and its time.
    /// It stays until a later fetch vouches.
    pub negative: Option<(u64, OwnerCheck)>,
}

impl OwnerStatus {
    /// No check yet.
    pub const PENDING: Self = Self {
        latest: None,
        verified_at: None,
        negative: None,
    };

    /// When the latest fetch completed.
    #[must_use]
    pub fn checked_at(&self) -> Option<u64> {
        self.latest.map(|(t, _)| t)
    }
}

/// The full-text fields of a listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchDoc {
    /// The listing name and the card name (weight A).
    pub title: String,
    /// Skill names and tags (weight B).
    pub skills: String,
    /// The description (weight C).
    pub description: String,
    /// Lower-cased skill ids, names and tags for `skill=`.
    pub skill_keys: Vec<String>,
}

/// A stored listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingRecord {
    /// `params.name`.
    pub name: String,
    /// `params.identity`.
    pub identity: String,
    /// `params.seq`.
    pub seq: u64,
    /// The embedded token's id.
    pub token_id: String,
    /// `params.owner_domain`.
    pub owner_domain: Option<String>,
    /// Owner state and check times.
    pub owner: OwnerStatus,
    /// `params.door.expires_at`.
    pub door_expires_at: Option<u64>,
    /// The embedded token's `expires_at`.
    pub token_expires_at: u64,
    /// Unix seconds when this version was published.
    pub published_at: u64,
    /// Unix seconds when the name last changed identity, for the 30-day
    /// "key changed" banner. Set by the store on publish.
    pub key_changed_at: Option<u64>,
    /// The exact canonical signed bytes.
    pub bytes: Vec<u8>,
    /// Lower-case hex SHA-256 of `bytes`.
    pub sha256: String,
    /// Full-text fields.
    pub search: SearchDoc,
}

/// Why a name is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoneKind {
    /// The owner withdrew it.
    Withdrawal,
    /// The operator revoked its token.
    TokenRevocation,
    /// The owner domain revoked the identity.
    OwnerRevocation,
}

impl GoneKind {
    /// The stored and wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GoneKind::Withdrawal => "withdrawal",
            GoneKind::TokenRevocation => "token_revocation",
            GoneKind::OwnerRevocation => "owner_revocation",
        }
    }

    /// Parse a stored name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "withdrawal" => GoneKind::Withdrawal,
            "token_revocation" => GoneKind::TokenRevocation,
            "owner_revocation" => GoneKind::OwnerRevocation,
            _ => return None,
        })
    }
}

/// The tombstone a withdrawal leaves for a (name, identity): the highest
/// withdrawn `seq`. `seq` belongs to (directory, name, identity), so another
/// identity's tombstone never blocks a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// The listing name.
    pub name: String,
    /// The identity that held it.
    pub identity: String,
    /// The highest `seq` withdrawn.
    pub seq: u64,
    /// Why.
    pub kind: GoneKind,
    /// Unix seconds.
    pub created_at: u64,
}

/// One entry of the withdrawal feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedEntry {
    /// Position in the feed; strictly increasing.
    pub cursor: i64,
    /// What kind of entry.
    pub kind: GoneKind,
    /// The signed object (or, for an owner revocation, the directory's
    /// record of it), as JSON text.
    pub entry: String,
    /// Unix seconds.
    pub created_at: u64,
}

/// What the directory keeps per name for the core's `NameRecord`: the newest
/// token `issued_at` ever accepted and the identity it was issued to (kept
/// for good, through withdrawal, expiry and revocation), and per identity
/// the highest tombstoned `seq`, sorted by identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameState {
    /// `(issued_at, identity)` of the newest accepted token.
    pub high_water: Option<(u64, String)>,
    /// `(identity, seq)`, sorted by identity.
    pub tombstones: Vec<(String, u64)>,
    /// `(identity, at)`: identities the owner domain revoked for this name,
    /// and when the directory saw it, sorted by identity. Such an identity
    /// may list the name again only under a token issued after `at`.
    pub owner_revoked: Vec<(String, u64)>,
}

/// What the caller saw when it decided that a listing may be stored, and
/// the name's high-water mark after accepting it. The store refuses the
/// write ([`PublishOutcome::Conflict`]) if what it saw has changed since, so
/// the decision and the write are atomic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishGuard {
    /// The SHA-256 of the listing stored under the name, if any.
    pub prev_sha256: Option<String>,
    /// The name's state the decision was taken on.
    pub name: NameState,
    /// The high-water mark to store with the listing.
    pub high_water: Option<(u64, String)>,
}

/// Outcome of [`Store::publish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Stored. `key_changed` is true when the name changed identity.
    Published {
        /// The name moved to a new identity.
        key_changed: bool,
    },
    /// The same bytes are already stored; nothing changed.
    Unchanged,
    /// The stored listing or the tombstone changed since the caller
    /// decided; decide again.
    Conflict,
    /// The token was revoked.
    TokenRevoked,
}

/// A withdrawal to apply.
#[derive(Debug, Clone)]
pub struct WithdrawalRecord<'a> {
    /// The listing name.
    pub name: &'a str,
    /// The signing identity.
    pub identity: &'a str,
    /// The highest `seq` withdrawn.
    pub seq: u64,
    /// The tombstone to leave for (name, identity): the core's
    /// `NameRecord::tombstone` of this withdrawal.
    pub tombstone_seq: u64,
    /// The signed withdrawal, for the feed.
    pub entry: &'a str,
}

/// Outcome of [`Store::withdraw`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawOutcome {
    /// Deleted, tombstoned and appended to the feed.
    Withdrawn,
    /// Already withdrawn at this `seq` or later; nothing changed.
    Repeat,
    /// Nothing is listed under the name.
    NotListed,
    /// The name is listed by another identity.
    WrongIdentity,
    /// The withdrawal's `seq` is below the listed `seq`.
    StaleSeq,
}

/// Outcome of [`Store::revoke_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Recorded. The listing that used the token, if any, was withdrawn.
    Revoked {
        /// The withdrawn listing's name and identity.
        withdrawn: Option<(String, String)>,
    },
    /// Already revoked; nothing changed.
    Repeat,
}

/// A search request.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    /// Free text (`websearch_to_tsquery` syntax).
    pub text: Option<String>,
    /// An exact skill id, name or tag, lower-cased.
    pub skill: Option<String>,
    /// Unix seconds; listings whose token has expired are left out.
    pub now: u64,
}

/// Rows removed by [`Store::purge`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeStats {
    /// Listings whose token expired more than 30 days ago.
    pub expired_listings: u64,
    /// Feed entries older than 30 days.
    pub feed: u64,
    /// Revoked token ids past every possible token lifetime.
    pub revoked_tokens: u64,
}

/// The directory's persistent state. Times are unix seconds from the
/// caller's clock.
pub trait Store: Send + Sync + 'static {
    /// The listing under `name`.
    fn get(&self, name: &str) -> impl Future<Output = StoreResult<Option<ListingRecord>>> + Send;

    /// The name's state: its high-water mark and per-identity tombstones.
    fn name_state(&self, name: &str) -> impl Future<Output = StoreResult<NameState>> + Send;

    /// Whether the operator revoked `token_id`.
    fn token_revoked(&self, token_id: &str) -> impl Future<Output = StoreResult<bool>> + Send;

    /// The latest tombstone of `name`, whichever identity it is for.
    fn tombstone(&self, name: &str) -> impl Future<Output = StoreResult<Option<Tombstone>>> + Send;

    /// The tombstone of (`name`, `identity`).
    fn tombstone_for(
        &self,
        name: &str,
        identity: &str,
    ) -> impl Future<Output = StoreResult<Option<Tombstone>>> + Send;

    /// Store a listing the caller decided may replace what `guard` saw
    /// (`SignedListing::replaces`, `tombstoned_by`), atomically: the token
    /// isn't revoked, the same bytes are idempotent, and the stored listing
    /// and the name's state are still what `guard` says; then it writes
    /// the listing and the name's new high-water mark. On a
    /// change of identity the store sets `key_changed_at` to
    /// `published_at`; otherwise it keeps the previous value.
    fn publish(
        &self,
        record: &ListingRecord,
        guard: &PublishGuard,
    ) -> impl Future<Output = StoreResult<PublishOutcome>> + Send;

    /// In one transaction: delete the listing (if it is the withdrawal's
    /// identity's, at a `seq` no higher), raise that (name, identity)'s
    /// tombstone and append the signed entry to the feed.
    fn withdraw(
        &self,
        w: &WithdrawalRecord<'_>,
        now: u64,
    ) -> impl Future<Output = StoreResult<WithdrawOutcome>> + Send;

    /// In one transaction: record the revoked token id, withdraw the listing
    /// that uses it (tombstone) and append the signed entry to the feed.
    fn revoke_token(
        &self,
        token_id: &str,
        entry: &str,
        now: u64,
    ) -> impl Future<Output = StoreResult<RevokeOutcome>> + Send;

    /// The owner domain revoked the identity: if `name` still holds the
    /// version `sha256`, withdraw it, tombstone it, record the revocation
    /// of (name, identity) at `now` and append `entry` to the feed. Returns
    /// whether it was withdrawn.
    fn owner_revoked(
        &self,
        name: &str,
        sha256: &str,
        entry: &str,
        now: u64,
    ) -> impl Future<Output = StoreResult<bool>> + Send;

    /// Fold one owner check that completed at `at` into the stored history
    /// of `name`, if it still holds the version `sha256`. The read and the
    /// write are atomic, so overlapping checks are recorded in the order
    /// they complete and none is lost.
    fn record_owner_check(
        &self,
        name: &str,
        sha256: &str,
        at: u64,
        check: OwnerCheck,
    ) -> impl Future<Output = StoreResult<bool>> + Send;

    /// Unexpired listings with an owner domain whose last check finished
    /// before `checked_before` (or never), oldest first.
    fn due_owner_checks(
        &self,
        checked_before: u64,
        now: u64,
        limit: u32,
    ) -> impl Future<Output = StoreResult<Vec<ListingRecord>>> + Send;

    /// Every unexpired listing of `identity`.
    fn by_identity(
        &self,
        identity: &str,
        now: u64,
    ) -> impl Future<Output = StoreResult<Vec<ListingRecord>>> + Send;

    /// Unexpired listings with a name after `after`, by name.
    fn listed_after(
        &self,
        after: &str,
        now: u64,
        limit: u32,
    ) -> impl Future<Output = StoreResult<Vec<ListingRecord>>> + Send;

    /// Listings matching the query, best first, at most
    /// [`SEARCH_CANDIDATES`]. With no text, by name. Listings whose token
    /// has expired are left out; owner-state filtering is the caller's.
    fn search(
        &self,
        q: &SearchQuery,
    ) -> impl Future<Output = StoreResult<Vec<ListingRecord>>> + Send;

    /// Feed entries with `cursor > after`, oldest first.
    fn feed(
        &self,
        after: i64,
        limit: u32,
    ) -> impl Future<Output = StoreResult<Vec<FeedEntry>>> + Send;

    /// Delete old feed entries, revoked token ids past every token lifetime,
    /// and listings expired for longer than the grace period. Tombstones,
    /// name marks and owner revocations are kept.
    fn purge(&self, now: u64) -> impl Future<Output = StoreResult<PurgeStats>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for c in [
            OwnerCheck::Vouched,
            OwnerCheck::NotVouched,
            OwnerCheck::Revoked,
            OwnerCheck::Failed,
        ] {
            assert_eq!(OwnerCheck::parse(c.as_str()), Some(c));
        }
        assert_eq!(OwnerCheck::parse("x"), None);
        assert_eq!(OwnerStatus::PENDING.checked_at(), None);
        for k in [
            GoneKind::Withdrawal,
            GoneKind::TokenRevocation,
            GoneKind::OwnerRevocation,
        ] {
            assert_eq!(GoneKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(GoneKind::parse("x"), None);
    }

    #[test]
    fn store_errors_never_quote_values() {
        let e = StoreError::from(sqlx::Error::RowNotFound);
        assert_eq!(e.to_string(), "storage error: row not found");
        for e in [
            sqlx::Error::PoolTimedOut,
            sqlx::Error::PoolClosed,
            sqlx::Error::Io(std::io::Error::other("secret")),
            sqlx::Error::Protocol("release-planner".into()),
        ] {
            let s = StoreError::from(e).to_string();
            assert!(
                !s.contains("secret") && !s.contains("release-planner"),
                "{s}"
            );
        }
        let m = StoreError::from(sqlx::migrate::MigrateError::VersionMissing(1));
        assert_eq!(m.0, "migration failed");
    }
}
