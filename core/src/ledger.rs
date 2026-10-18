//! The owner's replay ledger (SPEC §6.2 "Replays", §6.6.3 step 6).
//!
//! Neither a JoinRequest nor a knock carries freshness the owner can check
//! beyond its own deadline, and the relay sees both. So the owner
//! remembers the id and the `KeyPackageRef` of every request that passed
//! its checks, whatever happened to it next, until no copy of it can pass
//! them again, and drops a request whose id or ref it remembers.
//!
//! [`ReplayLedger`] is the interface; [`MemoryLedger`] is a bounded
//! in-memory one that the daemon persists in its encrypted store. The
//! knock ledger and the join ledger are two of them: a knock is keyed by
//! its `knock_id` ([`crate::knock::VerifiedKnock::remember_in`]), a
//! JoinRequest by the id of the approval it waits in
//! ([`crate::VerifiedJoinRequest::remember_in`]).

use std::collections::HashMap;

use crate::error::{Error, Result};

/// How many requests a [`MemoryLedger`] holds by default. For knocks it is
/// well above 32 pending per door times the 4 doors a mailbox may hold,
/// times the knocks a door can take in its 65-minute window at the relay's
/// limits. For joins, anyone holding a leaked invite link can mint
/// requests, so the daemon also gives each invite a quota of its own and
/// forgets an invite's entries once it is revoked or ends.
pub const DEFAULT_LEDGER_CAPACITY: usize = 65_536;

/// How long past a request's own deadline it is still remembered. For a
/// knock it is the 300 s its `ts` may run ahead of the owner's clock (SPEC
/// §6.6.3 step 3). A JoinRequest has no such allowance: step 1 refuses it
/// at the invite's `expires_at` on the inviter's own clock (SPEC §6.2), so
/// for joins the same 300 s only absorbs a small backward step of that
/// clock between a purge and the next check.
pub const LEDGER_GRACE_SECS: u64 = crate::knock::KNOCK_FUTURE_SECS;

/// What an owner remembers about the requests it has seen: every id and
/// `KeyPackageRef` until its request's `forget_after`. The daemon backs it
/// with its encrypted store; [`MemoryLedger`] is an in-memory one.
pub trait ReplayLedger {
    /// Whether `id` or `key_package_ref` is remembered.
    ///
    /// # Errors
    ///
    /// The backing store's error.
    fn seen(&self, id: &[u8], key_package_ref: &[u8]) -> Result<bool>;

    /// Remembers both until `forget_after` (Unix seconds).
    ///
    /// # Errors
    ///
    /// The backing store's error, or [`Error::LedgerFull`].
    fn remember(&mut self, id: &[u8], key_package_ref: &[u8], forget_after: u64) -> Result<()>;
}

/// [`Error::Replayed`] if `ledger` has seen `id` or `key_package_ref`,
/// otherwise remembers both until `forget_after`.
pub(crate) fn remember_once(
    ledger: &mut impl ReplayLedger,
    id: &[u8],
    key_package_ref: &[u8],
    forget_after: u64,
) -> Result<()> {
    if ledger.seen(id, key_package_ref)? {
        return Err(Error::Replayed);
    }
    ledger.remember(id, key_package_ref, forget_after)
}

/// One remembered request, for persisting a ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    /// The request's id (a knock's `knock_id`, a join's request id).
    pub id: Vec<u8>,
    /// Its KeyPackage's `KeyPackageRef`.
    pub key_package_ref: Vec<u8>,
    /// Unix seconds after which it may be forgotten.
    pub forget_after: u64,
}

/// An in-memory [`ReplayLedger`] with a hard capacity. The daemon MUST
/// persist it (SPEC §6.2, §6.6.3 step 6): save [`MemoryLedger::entries`]
/// in its encrypted store and [`MemoryLedger::insert`] them back after a
/// restart, or a request seen before the restart could be replayed after
/// it.
///
/// It never evicts an entry that is still live: when it is full, a new
/// request is refused ([`Error::LedgerFull`], kind `busy`) until
/// [`MemoryLedger::purge`] frees expired entries. Refusing is safe;
/// forgetting early would reopen the replay window.
#[derive(Debug)]
pub struct MemoryLedger {
    ids: HashMap<Vec<u8>, (Vec<u8>, u64)>,
    refs: HashMap<Vec<u8>, u64>,
    capacity: usize,
}

impl Default for MemoryLedger {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_LEDGER_CAPACITY)
    }
}

impl MemoryLedger {
    /// An empty ledger that holds at most `capacity` requests.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ids: HashMap::new(),
            refs: HashMap::new(),
            capacity,
        }
    }

    /// The most requests it holds.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Forgets every request whose `forget_after` is before `now`. Callers
    /// pass the clock's current time on every call, never one kept from an
    /// earlier pass.
    pub fn purge(&mut self, now: u64) {
        self.ids.retain(|_, (_, until)| *until >= now);
        self.refs.retain(|_, until| *until >= now);
    }

    /// How many requests it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether it holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Every remembered request, for persisting.
    #[must_use]
    pub fn entries(&self) -> Vec<LedgerEntry> {
        let mut out: Vec<LedgerEntry> = self
            .ids
            .iter()
            .map(|(id, (kp_ref, until))| LedgerEntry {
                id: id.clone(),
                key_package_ref: kp_ref.clone(),
                forget_after: *until,
            })
            .collect();
        out.sort_by(|a, b| (a.forget_after, &a.id).cmp(&(b.forget_after, &b.id)));
        out
    }

    /// Restores one persisted request (or remembers a new one).
    ///
    /// # Errors
    ///
    /// [`Error::LedgerFull`] (kind `busy`) when it is at capacity and this
    /// id isn't in it yet.
    pub fn insert(
        &mut self,
        id: Vec<u8>,
        key_package_ref: Vec<u8>,
        forget_after: u64,
    ) -> Result<()> {
        if !self.ids.contains_key(&id) && self.ids.len() >= self.capacity {
            return Err(Error::LedgerFull);
        }
        let until = self
            .refs
            .entry(key_package_ref.clone())
            .or_insert(forget_after);
        *until = (*until).max(forget_after);
        let entry = self
            .ids
            .entry(id)
            .or_insert((key_package_ref, forget_after));
        entry.1 = entry.1.max(forget_after);
        Ok(())
    }
}

impl ReplayLedger for MemoryLedger {
    fn seen(&self, id: &[u8], key_package_ref: &[u8]) -> Result<bool> {
        Ok(self.ids.contains_key(id) || self.refs.contains_key(key_package_ref))
    }

    fn remember(&mut self, id: &[u8], key_package_ref: &[u8], forget_after: u64) -> Result<()> {
        self.insert(id.to_vec(), key_package_ref.to_vec(), forget_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::rng::Rng;

    fn ids(label: &str, n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        let rng = Rng::for_test(label);
        (0..n)
            .map(|_| {
                (
                    rng.array::<16>().unwrap().to_vec(),
                    rng.array::<32>().unwrap().to_vec(),
                )
            })
            .collect()
    }

    #[test]
    fn an_id_or_a_ref_seen_before_is_a_replay() {
        let r = ids("ledger-replay", 3);
        let mut ledger = MemoryLedger::default();
        remember_once(&mut ledger, &r[0].0, &r[0].1, 100).unwrap();
        // The same id with another ref, and the same ref under another id.
        assert_eq!(
            remember_once(&mut ledger, &r[0].0, &r[1].1, 100),
            Err(Error::Replayed)
        );
        assert_eq!(
            remember_once(&mut ledger, &r[1].0, &r[0].1, 100),
            Err(Error::Replayed)
        );
        assert_eq!(Error::Replayed.kind(), crate::ErrorKind::Replay);
        remember_once(&mut ledger, &r[2].0, &r[2].1, 200).unwrap();
        assert_eq!(ledger.len(), 2);
        // Kept through `forget_after`, forgotten after it.
        ledger.purge(100);
        assert_eq!(ledger.len(), 2);
        ledger.purge(101);
        assert_eq!(ledger.len(), 1);
        remember_once(&mut ledger, &r[0].0, &r[0].1, 300).unwrap();
        ledger.purge(301);
        assert!(ledger.is_empty());
    }

    #[test]
    fn a_full_ledger_refuses_and_never_evicts() {
        let r = ids("ledger-full", 3);
        let mut ledger = MemoryLedger::with_capacity(2);
        remember_once(&mut ledger, &r[0].0, &r[0].1, 100).unwrap();
        remember_once(&mut ledger, &r[1].0, &r[1].1, 200).unwrap();
        let e = remember_once(&mut ledger, &r[2].0, &r[2].1, 300).unwrap_err();
        assert_eq!(e, Error::LedgerFull);
        assert_eq!(e.kind(), crate::ErrorKind::Busy);
        for (id, kp_ref) in &r[..2] {
            assert!(ledger.seen(id, kp_ref).unwrap());
        }
        assert!(!ledger.seen(&r[2].0, &r[2].1).unwrap());
        // Re-inserting a known id is not a new entry, and keeps the later time.
        ledger.insert(r[0].0.clone(), r[0].1.clone(), 150).unwrap();
        assert_eq!(ledger.entries()[0].forget_after, 150);
        ledger.insert(r[0].0.clone(), r[0].1.clone(), 120).unwrap();
        assert_eq!(ledger.entries()[0].forget_after, 150);
        // Expired entries make room.
        ledger.purge(151);
        remember_once(&mut ledger, &r[2].0, &r[2].1, 300).unwrap();
        assert_eq!(MemoryLedger::default().capacity(), DEFAULT_LEDGER_CAPACITY);
    }

    #[test]
    fn entries_restore_a_ledger() {
        let r = ids("ledger-restore", 2);
        let mut ledger = MemoryLedger::with_capacity(2);
        remember_once(&mut ledger, &r[1].0, &r[1].1, 200).unwrap();
        remember_once(&mut ledger, &r[0].0, &r[0].1, 100).unwrap();
        let saved = ledger.entries();
        assert_eq!(
            saved.iter().map(|e| e.forget_after).collect::<Vec<_>>(),
            [100, 200]
        );
        let mut restarted = MemoryLedger::with_capacity(2);
        for e in &saved {
            restarted
                .insert(e.id.clone(), e.key_package_ref.clone(), e.forget_after)
                .unwrap();
        }
        assert_eq!(restarted.entries(), saved);
        for (id, kp_ref) in &r {
            assert_eq!(
                remember_once(&mut restarted, id, kp_ref, 300),
                Err(Error::Replayed)
            );
        }
    }
}
