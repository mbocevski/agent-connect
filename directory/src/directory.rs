//! The directory service: publish, withdraw and revoke rules (ADR-006
//! Decision 6), owner checks (Decision 2), lookups and search.
//! Transport-agnostic; `http.rs` and `mcp.rs` are thin adapters.

use std::sync::Arc;

use agentconnect_core::clock::Clock;
use agentconnect_core::encoding::{b64, hex};
use agentconnect_core::identity::{fingerprint, parse_identity};
use agentconnect_core::listing::{MAX_LISTING_BYTES, NameRecord, PUBLISH_SKEW_SECS, SignedListing};

use crate::card::Card;
use crate::metrics::Metrics;
use crate::owner::{OwnerFetcher, OwnerState, RECHECK_EVERY_SECS, owner_state};
use crate::ratelimit::{Class, Limits, RateLimiter};
use crate::store::{
    FeedEntry, GoneKind, ListingRecord, NameState, OwnerCheck, OwnerStatus, PublishGuard,
    PublishOutcome, RevokeOutcome, SearchDoc, SearchQuery, Store, WithdrawOutcome,
    WithdrawalRecord,
};
use crate::verify::{OwnerVerdict, Rejection, TokenKey, Verifier};

/// How long the "key changed" banner shows (Decision 2).
pub const KEY_CHANGED_SECS: u64 = 30 * 86_400;
/// Most results a search returns.
pub const SEARCH_LIMIT: usize = 50;
/// Longest search text kept, in characters.
pub const MAX_QUERY_CHARS: usize = 200;
/// Listings read per store page when listing names.
pub const PAGE: u32 = 200;
/// Most names `llms.txt` lists.
pub const LLMS_LIMIT: usize = 10_000;
/// Most feed entries per page.
pub const FEED_PAGE: u32 = 100;
/// Owner checks run per maintenance pass.
pub const CHECKS_PER_PASS: u32 = 100;
/// Owner fetches in flight at once during a pass.
pub const CHECK_CONCURRENCY: usize = 8;

/// Whether `name` is a listing slug (the core's rule, SPEC §13.1.1).
pub use agentconnect_core::listing::is_listing_name as valid_name;

/// A refusal, with the HTTP status and a stable code. `detail` is a fixed
/// string: no request data is ever echoed back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirError {
    /// HTTP status.
    pub status: u16,
    /// Stable machine-readable code.
    pub code: &'static str,
    /// Human-readable reason.
    pub detail: &'static str,
    /// The core's error kind, for refusals the core decided.
    pub kind: Option<&'static str>,
}

impl DirError {
    const fn new(status: u16, code: &'static str, detail: &'static str) -> Self {
        Self {
            status,
            code,
            detail,
            kind: None,
        }
    }

    /// Storage failure.
    pub const INTERNAL: Self = Self::new(500, "internal", "internal error");
    /// Over the per-address rate limit.
    pub const RATE_LIMITED: Self = Self::new(429, "rate_limited", "too many requests");
    /// Body over the size limit.
    pub const TOO_LARGE: Self = Self::new(413, "too_large", "body too large");
    /// Unknown name.
    pub const NOT_FOUND: Self = Self::new(404, "not_found", "no listing has that name");
}

fn internal(e: &dyn std::fmt::Display) -> DirError {
    tracing::error!(error = %e, "storage failure");
    DirError::INTERNAL
}

/// The core's `NameRecord` for a name's stored state.
fn name_record(state: &NameState) -> NameRecord {
    NameRecord {
        high_water: state.high_water.clone(),
        tombstones: state.tombstones.clone(),
    }
}

/// The identity's owner domain revoked it for this name, and its token is
/// no newer than the revocation.
const OWNER_REVOKED: DirError = DirError::new(
    403,
    "owner_revoked",
    "the owner domain revoked this key for this name; it needs a token issued after that",
);

/// The refusal for a core [`Rejection`]: the code comes from the core's
/// error kind (`malformed` uses `malformed_code`), the detail is the core's
/// reason.
fn rejected(r: &Rejection, malformed_code: &'static str) -> DirError {
    use agentconnect_core::ErrorKind as K;
    let (status, code) = match r.kind {
        K::Signature => (403, "bad_signature"),
        K::UnknownKey => (403, "unknown_key"),
        K::Expired | K::NotYetValid | K::TokenMismatch => (403, "bad_token"),
        K::Revoked => (403, "token_revoked"),
        K::Superseded => (409, "name_held"),
        K::DoorExpired => (400, "bad_door"),
        K::WrongDirectory => (400, "wrong_directory"),
        K::StaleTimestamp => (400, "stale_ts"),
        _ => (400, malformed_code),
    };
    DirError {
        status,
        code,
        detail: r.reason,
        kind: Some(r.kind.as_str()),
    }
}

/// The door as a page shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoorState {
    /// Open until `expires_at`; `days` is whole days left, rounded down.
    Open {
        /// Whole days until expiry.
        days: u64,
        /// Unix seconds.
        expires_at: u64,
    },
    /// Absent or expired.
    Closed,
}

/// A listing as the pages, the Markdown copy, search and MCP show it.
#[derive(Debug, Clone)]
pub struct Listing {
    /// The stored record (including the exact signed bytes).
    pub record: ListingRecord,
    /// The card's display text (untrusted).
    pub card: Card,
    /// The owner state now.
    pub owner: OwnerState,
    /// The door state now.
    pub door: DoorState,
    /// The §2 fingerprint of the identity.
    pub fingerprint: String,
    /// When the key changed, if within the last 30 days.
    pub key_changed_at: Option<u64>,
}

/// Why a name answers 410.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoneReason {
    /// Withdrawn, revoked, or the owner domain revoked the key.
    Withdrawn(GoneKind),
    /// The listing token expired.
    TokenExpired,
}

/// The result of looking a name up.
#[derive(Debug, Clone)]
pub enum Lookup {
    /// Listed.
    Found(Box<Listing>),
    /// Gone (410) since `at`.
    Gone {
        /// Why.
        reason: GoneReason,
        /// Unix seconds.
        at: u64,
    },
    /// Never listed, or the tombstone has expired.
    Missing,
}

/// A publish that was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The listing name.
    pub name: String,
    /// Its `seq`.
    pub seq: u64,
    /// False for a repeat of the stored bytes.
    pub changed: bool,
    /// The owner state after the publish-time check.
    pub owner: OwnerState,
}

/// A withdrawal that was applied (or was a repeat).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawn {
    /// The listing name.
    pub name: String,
    /// The withdrawn `seq`.
    pub seq: u64,
    /// False for a repeat.
    pub changed: bool,
}

/// Static directory settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// This directory's host, canonical.
    pub host: String,
    /// Relays listings may point at; the first is shown on the site.
    pub relays: Vec<String>,
}

/// The directory.
pub struct Directory<S: Store> {
    store: S,
    verifier: Arc<dyn Verifier>,
    fetcher: Arc<dyn OwnerFetcher>,
    clock: Arc<dyn Clock>,
    settings: Settings,
    metrics: Metrics,
    limiter: RateLimiter,
    page: u32,
}

fn fingerprint_of(identity: &str) -> String {
    parse_identity(identity).map_or_else(|_| "unavailable".to_owned(), |k| fingerprint(&k))
}

impl<S: Store> Directory<S> {
    /// Build a directory.
    pub fn new(
        store: S,
        verifier: Arc<dyn Verifier>,
        fetcher: Arc<dyn OwnerFetcher>,
        clock: Arc<dyn Clock>,
        settings: Settings,
    ) -> Self {
        Self {
            store,
            verifier,
            fetcher,
            clock,
            settings,
            metrics: Metrics::default(),
            limiter: RateLimiter::new(Limits::default()),
            page: PAGE,
        }
    }

    /// Read `n` listings per store page when listing names (tests).
    #[must_use]
    pub fn with_page_size(mut self, n: u32) -> Self {
        self.page = n.max(1);
        self
    }

    /// Replace the rate limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limiter = RateLimiter::new(limits);
        self
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The counters.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The operator keys, for the well-known directory file.
    #[must_use]
    pub fn token_keys(&self) -> Vec<TokenKey> {
        self.verifier.token_keys()
    }

    /// Unix seconds from the directory clock.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.clock.unix_millis() / 1000
    }

    /// Count a request against the per-address limit.
    ///
    /// # Errors
    ///
    /// The seconds to wait.
    pub fn rate_check(&self, ip: Option<std::net::IpAddr>, class: Class) -> Result<(), u64> {
        self.limiter.check(ip, class, self.clock.unix_millis())
    }

    fn name_rate(&self, key: Option<std::net::IpAddr>, name: &str) -> Result<(), DirError> {
        self.limiter
            .check_name(key, name, self.clock.unix_millis())
            .map_err(|_| DirError::RATE_LIMITED)
    }

    /// The canonical URL of a listing's signed card.
    #[must_use]
    pub fn card_url(&self, name: &str) -> String {
        format!("https://{}/a/{name}.json", self.settings.host)
    }

    /// The knock argument for a listing.
    #[must_use]
    pub fn knock_ref(&self, name: &str) -> String {
        format!("{}/a/{name}", self.settings.host)
    }

    /// Whether a stored listing's token is under a key this directory pins
    /// now. After the operator rotates `DK`, knockers refuse a listing under
    /// the retired key, so it counts as expired (SR-24).
    fn token_pinned(&self, record: &ListingRecord) -> bool {
        let Ok(listing) = self.verifier.listing(&record.bytes) else {
            return false;
        };
        let key_id = b64(&listing.token().key_id);
        self.verifier
            .token_keys()
            .iter()
            .any(|k| k.key_id == key_id)
    }

    fn view(record: ListingRecord, now: u64) -> Option<Listing> {
        let card = Card::parse(&record.bytes).ok()?;
        let owner = owner_state(record.owner_domain.as_deref(), &record.owner, now);
        let door = match record.door_expires_at {
            Some(t) if t > now => DoorState::Open {
                days: (t - now) / 86_400,
                expires_at: t,
            },
            _ => DoorState::Closed,
        };
        let key_changed_at = record
            .key_changed_at
            .filter(|t| now.saturating_sub(*t) < KEY_CHANGED_SECS);
        Some(Listing {
            fingerprint: fingerprint_of(&record.identity),
            record,
            card,
            owner,
            door,
            key_changed_at,
        })
    }

    /// Look a name up.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn lookup(&self, name: &str) -> Result<Lookup, DirError> {
        if !valid_name(name) {
            return Ok(Lookup::Missing);
        }
        let now = self.now();
        if let Some(r) = self.store.get(name).await.map_err(|e| internal(&e))? {
            if r.token_expires_at <= now {
                return Ok(Lookup::Gone {
                    reason: GoneReason::TokenExpired,
                    at: r.token_expires_at,
                });
            }
            if !self.token_pinned(&r) {
                return Ok(Lookup::Gone {
                    reason: GoneReason::TokenExpired,
                    at: now,
                });
            }
            return Ok(Self::view(r, now).map_or(Lookup::Missing, |l| Lookup::Found(Box::new(l))));
        }
        Ok(
            match self.store.tombstone(name).await.map_err(|e| internal(&e))? {
                Some(t) => Lookup::Gone {
                    reason: GoneReason::Withdrawn(t.kind),
                    at: t.created_at,
                },
                None => Lookup::Missing,
            },
        )
    }

    /// Search: free text and/or an exact skill. Listings whose owner domain
    /// doesn't vouch for them (`failed`) are left out.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn search(
        &self,
        text: Option<&str>,
        skill: Option<&str>,
    ) -> Result<Vec<Listing>, DirError> {
        let now = self.now();
        let clean = |s: &str, max: usize| {
            let s: String = s.trim().chars().take(max).collect();
            (!s.is_empty()).then_some(s)
        };
        let q = SearchQuery {
            text: text.and_then(|t| clean(t, MAX_QUERY_CHARS)),
            skill: skill.and_then(|s| clean(s, 80)).map(|s| s.to_lowercase()),
            now,
        };
        let found = self.store.search(&q).await.map_err(|e| internal(&e))?;
        Ok(found
            .into_iter()
            .filter(|r| self.token_pinned(r))
            .filter_map(|r| Self::view(r, now))
            .filter(|l| l.owner != OwnerState::Failed)
            .take(SEARCH_LIMIT)
            .collect())
    }

    /// Listed (unexpired, not `failed`) listings by name, at most `limit`,
    /// paging past any run of hidden ones.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn listed(&self, limit: usize) -> Result<Vec<Listing>, DirError> {
        let now = self.now();
        let mut out = Vec::new();
        let mut after = String::new();
        while out.len() < limit {
            let page = self
                .store
                .listed_after(&after, now, self.page)
                .await
                .map_err(|e| internal(&e))?;
            let Some(last) = page.last() else {
                break;
            };
            after.clone_from(&last.name);
            let full = page.len() == self.page as usize;
            out.extend(
                page.into_iter()
                    .filter(|r| self.token_pinned(r))
                    .filter_map(|r| Self::view(r, now))
                    .filter(|l| l.owner != OwnerState::Failed),
            );
            if !full {
                break;
            }
        }
        out.truncate(limit);
        Ok(out)
    }

    /// Withdrawal feed entries after `after`, and the cursor to continue from.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn feed(&self, after: i64, limit: u32) -> Result<(Vec<FeedEntry>, i64), DirError> {
        let entries = self
            .store
            .feed(after, limit.clamp(1, FEED_PAGE))
            .await
            .map_err(|e| internal(&e))?;
        let next = entries.last().map_or(after, |e| e.cursor);
        Ok((entries, next))
    }

    /// Publish a listing (Decision 6). `bytes` is the request body.
    ///
    /// # Errors
    ///
    /// A [`DirError`] naming the first rule the listing breaks.
    pub async fn publish(&self, bytes: &[u8]) -> Result<Published, DirError> {
        self.publish_from(bytes, None).await
    }

    /// [`Directory::publish`] for a client under rate-limit key `key`: on
    /// top of the per-key write limit, writes are limited per (key, name).
    ///
    /// # Errors
    ///
    /// A [`DirError`].
    pub async fn publish_from(
        &self,
        bytes: &[u8],
        key: Option<std::net::IpAddr>,
    ) -> Result<Published, DirError> {
        let r = self.publish_inner(bytes, key).await;
        self.metrics.event(
            "publish",
            match &r {
                Ok(p) if p.changed => "published",
                Ok(_) => "unchanged",
                Err(e) => e.code,
            },
        );
        r
    }

    async fn publish_inner(
        &self,
        bytes: &[u8],
        key: Option<std::net::IpAddr>,
    ) -> Result<Published, DirError> {
        let bad = |code, detail| Err(DirError::new(400, code, detail));
        if bytes.len() > MAX_LISTING_BYTES {
            return Err(DirError::TOO_LARGE);
        }
        let now = self.now();
        let listing = self
            .verifier
            .listing(bytes)
            .map_err(|r| rejected(&r, "bad_listing"))?;
        let p = listing.params();
        self.name_rate(key, &p.name)?;
        if p.directory != self.settings.host {
            return bad("wrong_directory", "listing is for another directory");
        }
        if !self.settings.relays.contains(&p.relay) {
            return bad(
                "wrong_relay",
                "listing points at a relay this directory doesn't list",
            );
        }
        // Authorisation first: a listing without a valid token is refused
        // for that, whatever else is wrong with it.
        self.verifier
            .check_token(&listing, now)
            .map_err(|r| rejected(&r, "bad_token"))?;
        self.verifier
            .check_publish(&listing, now)
            .map_err(|r| rejected(&r, "bad_listing"))?;
        let token = listing.token();
        let card = Card::parse(bytes)
            .map_err(|_| DirError::new(400, "bad_listing", "card text is not readable"))?;
        let record = ListingRecord {
            name: p.name.clone(),
            identity: p.identity.clone(),
            seq: p.seq,
            token_id: b64(&token.token_id),
            owner_domain: p.owner_domain.clone(),
            owner: OwnerStatus::PENDING,
            door_expires_at: p.door.as_ref().map(|d| d.expires_at),
            token_expires_at: token.grant.expires_at,
            published_at: now,
            key_changed_at: None,
            bytes: bytes.to_vec(),
            sha256: hex(&listing.sha256()),
            search: SearchDoc {
                title: format!("{} {}", p.name.replace('-', " "), card.name),
                skills: card.skills_text(),
                description: card.description.clone(),
                skill_keys: card.skill_keys(),
            },
        };
        let changed = self.store_listing(&listing, &record).await?;
        if changed {
            self.check_owner(&record).await?;
        }
        let owner = match self
            .store
            .get(&record.name)
            .await
            .map_err(|e| internal(&e))?
        {
            Some(r) => owner_state(r.owner_domain.as_deref(), &r.owner, self.now()),
            None => OwnerState::Failed,
        };
        Ok(Published {
            name: record.name,
            seq: record.seq,
            changed,
            owner,
        })
    }

    /// Store `record` if `listing` may replace what is stored (the core's
    /// `replaces` and `tombstoned_by`). The store re-checks that nothing
    /// changed in between; on a race the decision is taken again.
    async fn store_listing(
        &self,
        listing: &SignedListing,
        record: &ListingRecord,
    ) -> Result<bool, DirError> {
        let p = listing.params();
        let revoked = DirError::new(403, "token_revoked", "token has been revoked");
        // A revoked token is refused as such, whatever else the name's
        // state says; the store checks it again atomically.
        if self
            .store
            .token_revoked(&record.token_id)
            .await
            .map_err(|e| internal(&e))?
        {
            return Err(revoked);
        }
        self.check_dropped_domain(listing).await?;
        for _ in 0..3 {
            let stored = self.store.get(&p.name).await.map_err(|e| internal(&e))?;
            let state = self
                .store
                .name_state(&p.name)
                .await
                .map_err(|e| internal(&e))?;
            if let Some((_, at)) = state.owner_revoked.iter().find(|(id, _)| *id == p.identity)
                && listing.token().grant.issued_at <= at.saturating_add(PUBLISH_SKEW_SECS)
            {
                // A token counts as issued after the revocation only past
                // the clock skew a token may claim (it can be dated up to
                // PUBLISH_SKEW_SECS ahead).
                return Err(OWNER_REVOKED);
            }
            let mut name = name_record(&state);
            // The same bytes again are idempotent; anything else must be
            // admitted by the core's name rules.
            if stored.as_ref().is_none_or(|s| s.sha256 != record.sha256) {
                let old = stored
                    .as_ref()
                    .and_then(|s| self.verifier.listing(&s.bytes).ok());
                name.admits(listing, old.as_ref())
                    .map_err(|e| rejected(&Rejection::from(&e), "bad_listing"))?;
                name.accept(listing);
            }
            let guard = PublishGuard {
                prev_sha256: stored.map(|s| s.sha256),
                name: state,
                high_water: name.high_water,
            };
            match self
                .store
                .publish(record, &guard)
                .await
                .map_err(|e| internal(&e))?
            {
                PublishOutcome::Published { .. } => return Ok(true),
                PublishOutcome::Unchanged => return Ok(false),
                PublishOutcome::Conflict => {}
                PublishOutcome::TokenRevoked => return Err(revoked),
            }
        }
        Err(DirError::new(
            409,
            "conflict",
            "the listing changed while it was published; retry",
        ))
    }

    /// The owner domain this identity last claimed for the name: on its
    /// stored listing, or on the tombstone its withdrawal left.
    async fn previous_domain(
        &self,
        name: &str,
        identity: &str,
    ) -> Result<Option<String>, DirError> {
        if let Some(stored) = self.store.get(name).await.map_err(|e| internal(&e))?
            && stored.identity == identity
        {
            return Ok(stored.owner_domain);
        }
        Ok(self
            .store
            .tombstone_for(name, identity)
            .await
            .map_err(|e| internal(&e))?
            .and_then(|t| t.owner_domain))
    }

    /// Whether `domain`'s owner file revokes `identity` for `name` now. A
    /// failed fetch is not a revocation.
    async fn domain_revokes(&self, domain: &str, identity: &str, name: &str) -> bool {
        match self.fetcher.fetch(domain).await {
            Ok(file) => matches!(
                self.verifier.owner_verdict(&file, identity, name),
                OwnerVerdict::Revoked { .. }
            ),
            Err(_) => false,
        }
    }

    /// Record a revocation `domain` publishes for (name, identity).
    async fn note_revocation(&self, name: &str, identity: &str) -> Result<(), DirError> {
        self.store
            .record_owner_revocation(name, identity, self.now())
            .await
            .map_err(|e| internal(&e))?;
        self.metrics.event("owner_check", "revoked");
        Ok(())
    }

    /// A listing that drops or changes the owner domain its identity last
    /// claimed for the name is checked against that domain first, so a key
    /// the domain revoked can't escape the revocation by leaving the domain.
    async fn check_dropped_domain(&self, listing: &SignedListing) -> Result<(), DirError> {
        let p = listing.params();
        let Some(previous) = self.previous_domain(&p.name, &p.identity).await? else {
            return Ok(());
        };
        if p.owner_domain.as_deref() == Some(previous.as_str()) {
            return Ok(());
        }
        // A revocation already on record keeps its first-seen time, so a
        // token issued after it can still relist; the publish check decides.
        let state = self
            .store
            .name_state(&p.name)
            .await
            .map_err(|e| internal(&e))?;
        if state.owner_revoked.iter().any(|(id, _)| *id == p.identity) {
            return Ok(());
        }
        if self.domain_revokes(&previous, &p.identity, &p.name).await {
            self.note_revocation(&p.name, &p.identity).await?;
            return Err(OWNER_REVOKED);
        }
        Ok(())
    }

    /// Withdraw a listing (Decision 6). `bytes` is the signed `Withdrawal`.
    ///
    /// # Errors
    ///
    /// A [`DirError`].
    pub async fn withdraw(&self, bytes: &[u8]) -> Result<Withdrawn, DirError> {
        self.withdraw_from(bytes, None).await
    }

    /// [`Directory::withdraw`] for a client under rate-limit key `key`.
    ///
    /// # Errors
    ///
    /// A [`DirError`].
    pub async fn withdraw_from(
        &self,
        bytes: &[u8],
        key: Option<std::net::IpAddr>,
    ) -> Result<Withdrawn, DirError> {
        let r = self.withdraw_inner(bytes, key).await;
        self.metrics.event(
            "withdraw",
            match &r {
                Ok(w) if w.changed => "withdrawn",
                Ok(_) => "repeat",
                Err(e) => e.code,
            },
        );
        r
    }

    async fn withdraw_inner(
        &self,
        bytes: &[u8],
        key: Option<std::net::IpAddr>,
    ) -> Result<Withdrawn, DirError> {
        let now = self.now();
        let w = self
            .verifier
            .withdrawal(bytes, now)
            .map_err(|r| rejected(&r, "bad_request"))?;
        self.name_rate(key, &w.name)?;
        let wrong_identity = DirError::new(
            403,
            "wrong_identity",
            "the name is listed by another identity",
        );
        let stale = DirError::new(409, "stale_seq", "seq is below the listed seq");
        // The core decides whether the withdrawal covers the listed version;
        // the store repeats the check atomically with the delete.
        let stored = self.store.get(&w.name).await.map_err(|e| internal(&e))?;
        if let Some(rec) = &stored
            && let Ok(listed) = self.verifier.listing(&rec.bytes)
            && !self.verifier.applies(&w, &listed)
        {
            return Err(if listed.params().identity == w.identity {
                stale
            } else {
                wrong_identity
            });
        }
        // Before the listing goes, its owner domain is checked (SPEC
        // §13.2.4): a key the domain has revoked can't withdraw ahead of the
        // recheck and come back without the domain.
        if let Some(rec) = &stored
            && rec.identity == w.identity
            && let Some(domain) = &rec.owner_domain
            && self.domain_revokes(domain, &w.identity, &w.name).await
        {
            self.note_revocation(&w.name, &w.identity).await?;
        }
        let entry = std::str::from_utf8(bytes)
            .map_err(|_| DirError::new(400, "bad_request", "malformed or not canonical"))?;
        // The tombstone this leaves, by the core's rule.
        let mut name = name_record(
            &self
                .store
                .name_state(&w.name)
                .await
                .map_err(|e| internal(&e))?,
        );
        name.tombstone(&w);
        let tombstone_seq = name
            .tombstones
            .iter()
            .find(|(id, _)| *id == w.identity)
            .map_or(w.seq, |(_, seq)| *seq);
        let rec = WithdrawalRecord {
            name: &w.name,
            identity: &w.identity,
            seq: w.seq,
            tombstone_seq,
            entry,
        };
        let changed = match self
            .store
            .withdraw(&rec, now)
            .await
            .map_err(|e| internal(&e))?
        {
            WithdrawOutcome::Withdrawn => true,
            WithdrawOutcome::Repeat => false,
            WithdrawOutcome::NotListed => return Err(DirError::NOT_FOUND),
            WithdrawOutcome::WrongIdentity => return Err(wrong_identity),
            WithdrawOutcome::StaleSeq => return Err(stale),
        };
        if changed {
            self.recheck_identity(&w.identity).await?;
        }
        Ok(Withdrawn {
            name: w.name,
            seq: w.seq,
            changed,
        })
    }

    /// Apply an operator `TokenRevocation`. Returns whether anything changed.
    ///
    /// # Errors
    ///
    /// A [`DirError`].
    pub async fn revoke(&self, bytes: &[u8]) -> Result<bool, DirError> {
        let r = self.revoke_inner(bytes).await;
        self.metrics.event(
            "revoke",
            match &r {
                Ok(true) => "revoked",
                Ok(false) => "repeat",
                Err(e) => e.code,
            },
        );
        r
    }

    async fn revoke_inner(&self, bytes: &[u8]) -> Result<bool, DirError> {
        let rev = self
            .verifier
            .revocation(bytes)
            .map_err(|r| rejected(&r, "bad_request"))?;
        let entry = std::str::from_utf8(bytes)
            .map_err(|_| DirError::new(400, "bad_request", "malformed or not canonical"))?;
        match self
            .store
            .revoke_token(&b64(&rev.token_id), entry, self.now())
            .await
            .map_err(|e| internal(&e))?
        {
            RevokeOutcome::Revoked { withdrawn } => {
                if let Some((_, identity)) = withdrawn {
                    self.recheck_identity(&identity).await?;
                }
                Ok(true)
            }
            RevokeOutcome::Repeat => Ok(false),
        }
    }

    async fn recheck_identity(&self, identity: &str) -> Result<(), DirError> {
        for r in self
            .store
            .by_identity(identity, self.now())
            .await
            .map_err(|e| internal(&e))?
        {
            self.check_owner(&r).await?;
        }
        Ok(())
    }

    /// Run the owner check for one stored version (Decision 2).
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn check_owner(&self, r: &ListingRecord) -> Result<(), DirError> {
        let Some(domain) = &r.owner_domain else {
            return Ok(());
        };
        let fetched = self.fetcher.fetch(domain).await;
        let now = self.now();
        let (check, outcome) = match fetched {
            Err(e) => {
                tracing::debug!(error = e.as_str(), "owner file fetch failed");
                (OwnerCheck::Failed, e.as_str())
            }
            Ok(file) => match self.verifier.owner_verdict(&file, &r.identity, &r.name) {
                OwnerVerdict::Vouched => (OwnerCheck::Vouched, "vouched"),
                OwnerVerdict::NotVouched => (OwnerCheck::NotVouched, "not_vouched"),
                OwnerVerdict::Unreadable => (OwnerCheck::Failed, "unreadable"),
                OwnerVerdict::Revoked { revoked_at, reason } => {
                    // A revoked key is withdrawn at once (Decision 2).
                    let entry = serde_json::json!({
                        "v": 0,
                        "directory": self.settings.host,
                        "name": r.name,
                        "identity": r.identity,
                        "owner_domain": domain,
                        "revoked_at": revoked_at,
                        "reason": reason,
                        "seq": r.seq,
                    });
                    let entry = serde_json::to_string(&entry).map_err(|_| DirError::INTERNAL)?;
                    self.store
                        .owner_revoked(&r.name, &r.sha256, &entry, now)
                        .await
                        .map_err(|e| internal(&e))?;
                    self.metrics.event("owner_check", "revoked");
                    return Ok(());
                }
            },
        };
        // The store folds the result into the history it holds now, so an
        // overlapping check can't overwrite this one.
        self.store
            .record_owner_check(&r.name, &r.sha256, now, check)
            .await
            .map_err(|e| internal(&e))?;
        self.metrics.event("owner_check", outcome);
        Ok(())
    }

    /// Re-check owners not checked for 6 hours. Returns how many ran.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn recheck_due(&self) -> Result<usize, DirError> {
        use futures_util::StreamExt as _;
        let now = self.now();
        let before = now.saturating_sub(RECHECK_EVERY_SECS);
        let due = self
            .store
            .due_owner_checks(before + 1, now, CHECKS_PER_PASS)
            .await
            .map_err(|e| internal(&e))?;
        let n = due.len();
        // Up to CHECK_CONCURRENCY fetches at a time, so slow owner domains
        // don't hold up the pass.
        let results: Vec<Result<(), DirError>> = futures_util::stream::iter(due)
            .map(|r| async move { self.check_owner(&r).await })
            .buffer_unordered(CHECK_CONCURRENCY)
            .collect()
            .await;
        results.into_iter().collect::<Result<(), DirError>>()?;
        Ok(n)
    }

    /// Forget idle rate-limit windows. Runs on its own timer.
    pub fn sweep_limits(&self) {
        self.limiter.sweep(self.clock.unix_millis());
    }

    /// Periodic maintenance: rate windows, old feed entries and expired
    /// listings, then owner re-checks.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn maintain(&self) -> Result<(), DirError> {
        self.limiter.sweep(self.clock.unix_millis());
        self.store
            .purge(self.now())
            .await
            .map_err(|e| internal(&e))?;
        self.recheck_due().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_slug_rule() {
        for ok in ["abc", "release-planner", "a1-b2", &"a".repeat(32)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "ab",
            "-abc",
            "abc-",
            "Abc",
            "a_b",
            "a.b",
            "äbc",
            &"a".repeat(33),
            "",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn rejections_map_to_stable_codes() {
        use agentconnect_core::ErrorKind as K;
        let code = |kind| {
            rejected(
                &Rejection {
                    kind,
                    reason: "why",
                },
                "bad_listing",
            )
        };
        for (kind, status, c) in [
            (K::Malformed, 400, "bad_listing"),
            (K::UnsupportedVersion, 400, "bad_listing"),
            (K::Signature, 403, "bad_signature"),
            (K::UnknownKey, 403, "unknown_key"),
            (K::Expired, 403, "bad_token"),
            (K::NotYetValid, 403, "bad_token"),
            (K::TokenMismatch, 403, "bad_token"),
            (K::Revoked, 403, "token_revoked"),
            (K::Superseded, 409, "name_held"),
            (K::DoorExpired, 400, "bad_door"),
            (K::WrongDirectory, 400, "wrong_directory"),
            (K::StaleTimestamp, 400, "stale_ts"),
        ] {
            let e = code(kind);
            assert_eq!((e.status, e.code, e.detail), (status, c, "why"));
            assert_eq!(e.kind, Some(kind.as_str()));
        }
        assert_eq!(fingerprint_of("nope"), "unavailable");
    }
}
