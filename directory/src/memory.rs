//! In-memory [`Store`] for the fast test tier and throwaway runs.
//!
//! Full-text search approximates Postgres `websearch_to_tsquery` with
//! `ts_rank` weights A = 1.0, B = 0.4, C = 0.2: every query word (lower-cased,
//! split on non-alphanumerics, `-word` excludes) must occur somewhere, and
//! the score sums the weights of the fields each word occurs in. There is no
//! stemming and no stop-word list.

#![allow(
    clippy::unused_async_trait_impl,
    reason = "the Store trait is async; memory operations complete at once"
)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};

use crate::owner::record_fetch;
use crate::store::{
    EXPIRED_GRACE_SECS, FEED_TTL_SECS, FeedEntry, GoneKind, ListingRecord, NameState, OwnerCheck,
    PublishGuard, PublishOutcome, PurgeStats, REVOKED_TOKEN_TTL_SECS, RevokeOutcome,
    SEARCH_CANDIDATES, SearchQuery, Store, StoreResult, Tombstone, WithdrawOutcome,
    WithdrawalRecord,
};

#[derive(Debug, Default)]
struct State {
    listings: BTreeMap<String, ListingRecord>,
    tombstones: HashMap<(String, String), Tombstone>,
    feed: Vec<FeedEntry>,
    next_cursor: i64,
    revoked: HashMap<String, u64>,
    /// Per name, the newest accepted token's `(issued_at, identity)`.
    marks: HashMap<String, (u64, String)>,
    /// (name, identity) the owner domain revoked, and when.
    owner_revoked: HashMap<(String, String), u64>,
}

impl State {
    /// The latest tombstone of `name`, any identity.
    fn latest_tombstone(&self, name: &str) -> Option<&Tombstone> {
        self.tombstones
            .values()
            .filter(|t| t.name == name)
            .max_by_key(|t| (t.created_at, t.identity.clone()))
    }

    fn tombstone_seq(&self, name: &str, identity: &str) -> Option<u64> {
        self.tombstones
            .get(&(name.to_owned(), identity.to_owned()))
            .map(|t| t.seq)
    }

    fn name_state(&self, name: &str) -> NameState {
        let mut tombstones: Vec<(String, u64)> = self
            .tombstones
            .values()
            .filter(|t| t.name == name)
            .map(|t| (t.identity.clone(), t.seq))
            .collect();
        tombstones.sort();
        let mut owner_revoked: Vec<(String, u64)> = self
            .owner_revoked
            .iter()
            .filter(|((n, _), _)| n == name)
            .map(|((_, id), at)| (id.clone(), *at))
            .collect();
        owner_revoked.sort();
        NameState {
            high_water: self.marks.get(name).cloned(),
            tombstones,
            owner_revoked,
        }
    }

    fn append(&mut self, kind: GoneKind, entry: &str, now: u64) {
        self.next_cursor += 1;
        self.feed.push(FeedEntry {
            cursor: self.next_cursor,
            kind,
            entry: entry.to_owned(),
            created_at: now,
        });
    }

    fn tombstone(&mut self, name: &str, identity: &str, seq: u64, kind: GoneKind, now: u64) {
        let key = (name.to_owned(), identity.to_owned());
        let seq = self.tombstones.get(&key).map_or(seq, |t| t.seq.max(seq));
        self.tombstones.insert(
            key,
            Tombstone {
                name: name.to_owned(),
                identity: identity.to_owned(),
                seq,
                kind,
                created_at: now,
            },
        );
    }
}

/// A [`Store`] in process memory.
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: Mutex<State>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Score `r` for `text`, or `None` if it doesn't match.
fn score(r: &ListingRecord, text: &str) -> Option<f64> {
    let fields = [
        (words(&r.search.title), 1.0),
        (words(&r.search.skills), 0.4),
        (words(&r.search.description), 0.2),
    ];
    let mut total = 0.0;
    let mut any = false;
    for raw in text.split_whitespace() {
        let (negated, term) = match raw.strip_prefix('-') {
            Some(t) => (true, t),
            None => (false, raw),
        };
        for w in words(term) {
            if w == "or" {
                continue;
            }
            let s: f64 = fields
                .iter()
                .filter(|(f, _)| f.contains(&w))
                .map(|(_, weight)| weight)
                .sum();
            if negated {
                if s > 0.0 {
                    return None;
                }
            } else if s == 0.0 {
                return None;
            } else {
                any = true;
                total += s;
            }
        }
    }
    any.then_some(total)
}

impl Store for MemoryStore {
    async fn get(&self, name: &str) -> StoreResult<Option<ListingRecord>> {
        Ok(self.lock().listings.get(name).cloned())
    }

    async fn name_state(&self, name: &str) -> StoreResult<NameState> {
        Ok(self.lock().name_state(name))
    }

    async fn token_revoked(&self, token_id: &str) -> StoreResult<bool> {
        Ok(self.lock().revoked.contains_key(token_id))
    }

    async fn tombstone(&self, name: &str) -> StoreResult<Option<Tombstone>> {
        Ok(self.lock().latest_tombstone(name).cloned())
    }

    async fn tombstone_for(&self, name: &str, identity: &str) -> StoreResult<Option<Tombstone>> {
        Ok(self
            .lock()
            .tombstones
            .get(&(name.to_owned(), identity.to_owned()))
            .cloned())
    }

    async fn publish(
        &self,
        record: &ListingRecord,
        guard: &PublishGuard,
    ) -> StoreResult<PublishOutcome> {
        let mut st = self.lock();
        if st.revoked.contains_key(&record.token_id) {
            return Ok(PublishOutcome::TokenRevoked);
        }
        let prev = st.listings.get(&record.name).cloned();
        if prev.as_ref().is_some_and(|p| p.sha256 == record.sha256) {
            return Ok(PublishOutcome::Unchanged);
        }
        if prev.as_ref().map(|p| &p.sha256) != guard.prev_sha256.as_ref()
            || st.name_state(&record.name) != guard.name
        {
            return Ok(PublishOutcome::Conflict);
        }
        let prev_identity = prev.as_ref().map(|p| p.identity.clone()).or_else(|| {
            st.latest_tombstone(&record.name)
                .map(|t| t.identity.clone())
        });
        let key_changed = prev_identity.is_some_and(|i| i != record.identity);
        let mut stored = record.clone();
        stored.key_changed_at = if key_changed {
            Some(record.published_at)
        } else {
            prev.and_then(|p| p.key_changed_at)
        };
        st.listings.insert(record.name.clone(), stored);
        if let Some(hw) = &guard.high_water {
            st.marks.insert(record.name.clone(), hw.clone());
        }
        Ok(PublishOutcome::Published { key_changed })
    }

    async fn withdraw(&self, w: &WithdrawalRecord<'_>, now: u64) -> StoreResult<WithdrawOutcome> {
        let mut st = self.lock();
        let Some(listing) = st.listings.get(w.name).cloned() else {
            let repeat = st
                .tombstone_seq(w.name, w.identity)
                .is_some_and(|t| t >= w.seq);
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
        st.listings.remove(w.name);
        st.tombstone(
            w.name,
            w.identity,
            w.tombstone_seq,
            GoneKind::Withdrawal,
            now,
        );
        st.append(GoneKind::Withdrawal, w.entry, now);
        Ok(WithdrawOutcome::Withdrawn)
    }

    async fn revoke_token(
        &self,
        token_id: &str,
        entry: &str,
        now: u64,
    ) -> StoreResult<RevokeOutcome> {
        let mut st = self.lock();
        if st.revoked.contains_key(token_id) {
            return Ok(RevokeOutcome::Repeat);
        }
        st.revoked.insert(token_id.to_owned(), now);
        let hit = st
            .listings
            .values()
            .find(|l| l.token_id == token_id)
            .cloned();
        let withdrawn = hit.map(|l| {
            st.listings.remove(&l.name);
            st.tombstone(&l.name, &l.identity, l.seq, GoneKind::TokenRevocation, now);
            (l.name, l.identity)
        });
        st.append(GoneKind::TokenRevocation, entry, now);
        Ok(RevokeOutcome::Revoked { withdrawn })
    }

    async fn owner_revoked(
        &self,
        name: &str,
        sha256: &str,
        entry: &str,
        now: u64,
    ) -> StoreResult<bool> {
        let mut st = self.lock();
        let Some(l) = st
            .listings
            .get(name)
            .filter(|l| l.sha256 == sha256)
            .cloned()
        else {
            return Ok(false);
        };
        st.listings.remove(name);
        st.tombstone(name, &l.identity, l.seq, GoneKind::OwnerRevocation, now);
        st.owner_revoked
            .insert((name.to_owned(), l.identity.clone()), now);
        st.append(GoneKind::OwnerRevocation, entry, now);
        Ok(true)
    }

    async fn record_owner_check(
        &self,
        name: &str,
        sha256: &str,
        at: u64,
        check: OwnerCheck,
    ) -> StoreResult<bool> {
        let mut st = self.lock();
        match st.listings.get_mut(name).filter(|l| l.sha256 == sha256) {
            Some(l) => {
                l.owner = record_fetch(l.owner, at, check);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn due_owner_checks(
        &self,
        checked_before: u64,
        now: u64,
        limit: u32,
    ) -> StoreResult<Vec<ListingRecord>> {
        let st = self.lock();
        let mut due: Vec<ListingRecord> = st
            .listings
            .values()
            .filter(|l| l.owner_domain.is_some() && l.token_expires_at > now)
            .filter(|l| l.owner.checked_at().is_none_or(|t| t < checked_before))
            .cloned()
            .collect();
        due.sort_by_key(|l| (l.owner.checked_at().unwrap_or(0), l.name.clone()));
        due.truncate(limit as usize);
        Ok(due)
    }

    async fn by_identity(&self, identity: &str, now: u64) -> StoreResult<Vec<ListingRecord>> {
        Ok(self
            .lock()
            .listings
            .values()
            .filter(|l| l.identity == identity && l.token_expires_at > now)
            .cloned()
            .collect())
    }

    async fn listed_after(
        &self,
        after: &str,
        now: u64,
        limit: u32,
    ) -> StoreResult<Vec<ListingRecord>> {
        Ok(self
            .lock()
            .listings
            .range::<str, _>((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            .map(|(_, l)| l)
            .filter(|l| l.token_expires_at > now)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn search(&self, q: &SearchQuery) -> StoreResult<Vec<ListingRecord>> {
        let st = self.lock();
        let mut hits: Vec<(f64, &ListingRecord)> = st
            .listings
            .values()
            .filter(|l| l.token_expires_at > q.now)
            .filter(|l| {
                q.skill
                    .as_ref()
                    .is_none_or(|s| l.search.skill_keys.contains(s))
            })
            .filter_map(|l| match &q.text {
                Some(t) => score(l, t).map(|s| (s, l)),
                None => Some((0.0, l)),
            })
            .collect();
        hits.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));
        Ok(hits
            .into_iter()
            .take(SEARCH_CANDIDATES as usize)
            .map(|(_, l)| l.clone())
            .collect())
    }

    async fn feed(&self, after: i64, limit: u32) -> StoreResult<Vec<FeedEntry>> {
        Ok(self
            .lock()
            .feed
            .iter()
            .filter(|e| e.cursor > after)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn purge(&self, now: u64) -> StoreResult<PurgeStats> {
        let mut st = self.lock();
        let old = |t: u64, ttl: u64| now.saturating_sub(t) >= ttl;
        let (l0, f0, r0) = (st.listings.len(), st.feed.len(), st.revoked.len());
        st.listings
            .retain(|_, l| !old(l.token_expires_at, EXPIRED_GRACE_SECS));
        st.feed.retain(|e| !old(e.created_at, FEED_TTL_SECS));
        st.revoked.retain(|_, t| !old(*t, REVOKED_TOKEN_TTL_SECS));
        let gone = |a: usize, b: usize| u64::try_from(a - b).unwrap_or(u64::MAX);
        Ok(PurgeStats {
            expired_listings: gone(l0, st.listings.len()),
            feed: gone(f0, st.feed.len()),
            revoked_tokens: gone(r0, st.revoked.len()),
        })
    }
}
