//! The directory service: publish, withdraw and revoke rules (ADR-006
//! Decision 6), owner checks (Decision 2), lookups and search.
//! Transport-agnostic; `http.rs` and `mcp.rs` are thin adapters.

use std::sync::Arc;

use agentconnect_core::clock::Clock;
use agentconnect_core::identity::{fingerprint, parse_identity};
use sha2::{Digest, Sha256};

use crate::card::Card;
use crate::metrics::Metrics;
use crate::owner::{OwnerFetcher, OwnerState, RECHECK_EVERY_SECS, owner_state};
use crate::ratelimit::{Class, Limits, RateLimiter};
use crate::store::{
    FeedEntry, GoneKind, ListingRecord, OwnerCheck, OwnerStatus, PublishOutcome, RevokeOutcome,
    SearchDoc, SearchQuery, Store, WithdrawOutcome, WithdrawalRecord,
};
use crate::verify::{OwnerVerdict, Rejection, TokenKey, Verifier};

/// Longest a door may stay open after `issued_at` (Decision 1).
pub const DOOR_MAX_SECS: u64 = 7 * 86_400;
/// Allowed clock skew for `issued_at` and withdrawal `ts` (Decision 6).
pub const SKEW_SECS: u64 = 300;
/// How long the "key changed" banner shows (Decision 2).
pub const KEY_CHANGED_SECS: u64 = 30 * 86_400;
/// Most results a search returns.
pub const SEARCH_LIMIT: usize = 50;
/// Longest search text kept, in characters.
pub const MAX_QUERY_CHARS: usize = 200;
/// Most feed entries per page.
pub const FEED_PAGE: u32 = 100;
/// Owner checks run per maintenance pass.
pub const CHECKS_PER_PASS: u32 = 100;

/// Whether `name` is a listing slug: 3 to 32 of `[a-z0-9-]`, starting and
/// ending with a letter or digit (Decision 1).
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    (3..=32).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b.first().is_some_and(u8::is_ascii_alphanumeric)
        && b.last().is_some_and(u8::is_ascii_alphanumeric)
}

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
}

impl DirError {
    const fn new(status: u16, code: &'static str, detail: &'static str) -> Self {
        Self {
            status,
            code,
            detail,
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

fn rejected(r: &Rejection, what: &'static str) -> DirError {
    match r {
        Rejection::Malformed(_) => DirError::new(400, what, "malformed or not canonical"),
        Rejection::BadSignature => DirError::new(403, "bad_signature", "signature does not verify"),
        Rejection::UnknownKey => DirError::new(
            403,
            "unknown_key",
            "not signed by a configured operator key",
        ),
        Rejection::Unavailable => {
            DirError::new(503, "unavailable", "verification is not available")
        }
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
}

fn sha256_hex(bytes: &[u8]) -> String {
    agentconnect_core::encoding::hex(&Sha256::digest(bytes))
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
        }
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
            .filter_map(|r| Self::view(r, now))
            .filter(|l| l.owner != OwnerState::Failed)
            .take(SEARCH_LIMIT)
            .collect())
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
        let r = self.publish_inner(bytes).await;
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

    /// Verify the embedded token and check its scope and lifetime.
    fn check_token(
        &self,
        listing: &crate::verify::VerifiedListing,
        now: u64,
    ) -> Result<crate::verify::ListingToken, DirError> {
        let token = self
            .verifier
            .verify_token(&listing.token)
            .map_err(|r| rejected(&r, "bad_token"))?;
        let bad_token = |detail| Err(DirError::new(403, "bad_token", detail));
        if token.directory != self.settings.host {
            return bad_token("token is for another directory");
        }
        if token.name != listing.name || token.identity != listing.identity {
            return bad_token("token is for another name or identity");
        }
        if token
            .owner_domain
            .as_ref()
            .is_some_and(|d| listing.owner_domain.as_ref() != Some(d))
        {
            return bad_token("token pins another owner domain");
        }
        if token.expires_at <= now {
            return bad_token("token has expired");
        }
        if token.issued_at > now + SKEW_SECS {
            return bad_token("token is not yet valid");
        }
        Ok(token)
    }

    async fn publish_inner(&self, bytes: &[u8]) -> Result<Published, DirError> {
        let bad = |code, detail| Err(DirError::new(400, code, detail));
        if bytes.len() > crate::card::MAX_CARD_BYTES {
            return Err(DirError::TOO_LARGE);
        }
        let now = self.now();
        let listing = self
            .verifier
            .verify_listing(bytes)
            .map_err(|r| rejected(&r, "bad_listing"))?;
        if !valid_name(&listing.name) {
            return bad("bad_listing", "invalid listing name");
        }
        if listing.directory != self.settings.host {
            return bad("wrong_directory", "listing is for another directory");
        }
        if !self.settings.relays.contains(&listing.relay) {
            return bad(
                "wrong_relay",
                "listing points at a relay this directory doesn't list",
            );
        }
        if listing.issued_at > now + SKEW_SECS {
            return bad("bad_listing", "issued_at is in the future");
        }
        if let Some(door) = &listing.door
            && (door.expires_at <= now || door.expires_at > listing.issued_at + DOOR_MAX_SECS)
        {
            return bad(
                "bad_door",
                "door must expire in the future and at most 7 days after issued_at",
            );
        }
        let token = self.check_token(&listing, now)?;
        let card = Card::parse(bytes)
            .map_err(|_| DirError::new(400, "bad_listing", "card text is not readable"))?;
        let record = ListingRecord {
            name: listing.name.clone(),
            identity: listing.identity.clone(),
            seq: listing.seq,
            token_id: token.token_id.clone(),
            owner_domain: listing.owner_domain.clone(),
            owner: OwnerStatus::PENDING,
            door_expires_at: listing.door.as_ref().map(|d| d.expires_at),
            token_expires_at: token.expires_at,
            published_at: now,
            key_changed_at: None,
            bytes: bytes.to_vec(),
            sha256: sha256_hex(bytes),
            search: SearchDoc {
                title: format!("{} {}", listing.name.replace('-', " "), card.name),
                skills: card.skills_text(),
                description: card.description.clone(),
                skill_keys: card.skill_keys(),
            },
        };
        let changed = match self
            .store
            .publish(&record)
            .await
            .map_err(|e| internal(&e))?
        {
            PublishOutcome::Published { .. } => true,
            PublishOutcome::Unchanged => false,
            PublishOutcome::StaleSeq { .. } => {
                return Err(DirError::new(
                    409,
                    "stale_seq",
                    "seq must be above every seq seen for this name",
                ));
            }
            PublishOutcome::TokenRevoked => {
                return Err(DirError::new(
                    403,
                    "token_revoked",
                    "token has been revoked",
                ));
            }
        };
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

    /// Withdraw a listing (Decision 6). `bytes` is the signed `Withdrawal`.
    ///
    /// # Errors
    ///
    /// A [`DirError`].
    pub async fn withdraw(&self, bytes: &[u8]) -> Result<Withdrawn, DirError> {
        let r = self.withdraw_inner(bytes).await;
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

    async fn withdraw_inner(&self, bytes: &[u8]) -> Result<Withdrawn, DirError> {
        let w = self
            .verifier
            .verify_withdrawal(bytes)
            .map_err(|r| rejected(&r, "bad_request"))?;
        let now = self.now();
        if w.directory != self.settings.host {
            return Err(DirError::new(
                400,
                "wrong_directory",
                "withdrawal is for another directory",
            ));
        }
        if w.ts.abs_diff(now) > SKEW_SECS {
            return Err(DirError::new(
                400,
                "stale_ts",
                "ts must be within 300 s of the directory clock",
            ));
        }
        let entry = std::str::from_utf8(bytes)
            .map_err(|_| DirError::new(400, "bad_request", "malformed or not canonical"))?;
        let rec = WithdrawalRecord {
            name: &w.name,
            identity: &w.identity,
            seq: w.seq,
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
            WithdrawOutcome::WrongIdentity => {
                return Err(DirError::new(
                    403,
                    "wrong_identity",
                    "the name is listed by another identity",
                ));
            }
            WithdrawOutcome::StaleSeq => {
                return Err(DirError::new(
                    409,
                    "stale_seq",
                    "seq is below the listed seq",
                ));
            }
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
            .verify_revocation(bytes)
            .map_err(|r| rejected(&r, "bad_request"))?;
        let entry = std::str::from_utf8(bytes)
            .map_err(|_| DirError::new(400, "bad_request", "malformed or not canonical"))?;
        match self
            .store
            .revoke_token(&rev.token_id, entry, self.now())
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
            .by_identity(identity)
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
        let status = |last| OwnerStatus {
            last,
            checked_at: Some(now),
            verified_at: if last == OwnerCheck::Vouched {
                Some(now)
            } else {
                r.owner.verified_at
            },
        };
        let outcome = match fetched {
            Err(e) => {
                tracing::debug!(error = e.as_str(), "owner file fetch failed");
                self.set_owner(r, status(OwnerCheck::Error)).await?;
                e.as_str()
            }
            Ok(file) => {
                let listing = self.knock_ref(&r.name);
                match self.verifier.owner_verdict(&file, &r.identity, &listing) {
                    OwnerVerdict::Vouched => {
                        self.set_owner(r, status(OwnerCheck::Vouched)).await?;
                        "vouched"
                    }
                    OwnerVerdict::NotVouched => {
                        self.set_owner(r, status(OwnerCheck::NotVouched)).await?;
                        "not_vouched"
                    }
                    OwnerVerdict::Invalid => {
                        self.set_owner(r, status(OwnerCheck::Error)).await?;
                        "invalid"
                    }
                    OwnerVerdict::Revoked { revoked_at, reason } => {
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
                        let entry = agentconnect_core::encoding::jcs(&entry)
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                            .ok_or(DirError::INTERNAL)?;
                        self.store
                            .owner_revoked(&r.name, &r.sha256, &entry, now)
                            .await
                            .map_err(|e| internal(&e))?;
                        "revoked"
                    }
                }
            }
        };
        self.metrics.event("owner_check", outcome);
        Ok(())
    }

    async fn set_owner(&self, r: &ListingRecord, s: OwnerStatus) -> Result<(), DirError> {
        self.store
            .set_owner(&r.name, &r.sha256, s)
            .await
            .map_err(|e| internal(&e))?;
        Ok(())
    }

    /// Re-check owners not checked for 6 hours. Returns how many ran.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn recheck_due(&self) -> Result<usize, DirError> {
        let before = self.now().saturating_sub(RECHECK_EVERY_SECS);
        let due = self
            .store
            .due_owner_checks(before + 1, CHECKS_PER_PASS)
            .await
            .map_err(|e| internal(&e))?;
        let n = due.len();
        for r in due {
            self.check_owner(&r).await?;
        }
        Ok(n)
    }

    /// Periodic maintenance: owner re-checks, expired tombstones and rate
    /// windows.
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
        assert_eq!(
            rejected(&Rejection::Malformed("x"), "bad_listing").code,
            "bad_listing"
        );
        assert_eq!(
            rejected(&Rejection::BadSignature, "bad_listing").status,
            403
        );
        assert_eq!(
            rejected(&Rejection::UnknownKey, "bad_token").code,
            "unknown_key"
        );
        assert_eq!(rejected(&Rejection::Unavailable, "bad_token").status, 503);
        assert_eq!(fingerprint_of("nope"), "unavailable");
    }
}
