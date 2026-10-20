//! The cache of signed REST requests (SPEC §8.1.1): which `(mailbox, sig)`
//! pairs this process accepted while they could still pass the timestamp
//! check.
//!
//! Time in the cache only moves forward: every operation uses the highest
//! clock reading it has seen, so an entry is dropped only once no request
//! with its timestamp can be accepted any more, whatever order concurrent
//! requests and sweeps take the lock in.

use std::collections::HashMap;

use crate::auth::{REST_MAX_SKEW_SECS, RestCredentials};

/// The cache: a bounded share per mailbox, and a bound on the whole.
#[derive(Debug, Default)]
pub(crate) struct ReplayCache {
    /// mailbox -> signature -> the last second at which the request still
    /// passes the timestamp check (`ts + 300`).
    by_mailbox: HashMap<String, HashMap<String, u64>>,
    /// Entries in all.
    total: usize,
    /// The highest clock reading seen, unix seconds.
    high_secs: u64,
    /// The highest `ts` of a request let through (recorded or not).
    highest_ts: u64,
}

/// What [`ReplayCache::claim`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Claim {
    /// Recorded now: the first use.
    Fresh,
    /// The cache as a whole is full: the request may go on, unrecorded.
    Unrecorded,
    /// A live entry holds this signature: a repeat.
    Replay,
    /// The timestamp is outside the window at the cache's time.
    Expired,
    /// The mailbox's share is full of live entries.
    Full,
}

impl ReplayCache {
    fn advance(&mut self, clock_secs: u64) -> u64 {
        self.high_secs = self.high_secs.max(clock_secs);
        self.high_secs
    }

    /// Check `creds`' timestamp and record it, in one step under the
    /// caller's lock.
    pub(crate) fn claim(
        &mut self,
        creds: &RestCredentials,
        clock_secs: u64,
        share: usize,
        max_total: usize,
    ) -> Claim {
        let now = self.advance(clock_secs);
        if creds.ts.saturating_add(REST_MAX_SKEW_SECS) < now
            || creds.ts > now.saturating_add(REST_MAX_SKEW_SECS)
        {
            return Claim::Expired;
        }
        let entries = self.by_mailbox.entry(creds.mailbox.clone()).or_default();
        let before = entries.len();
        entries.retain(|_, until| *until >= now);
        self.total -= before - entries.len();
        if entries.contains_key(&creds.sig) {
            return Claim::Replay;
        }
        if entries.len() >= share {
            return Claim::Full;
        }
        self.highest_ts = self.highest_ts.max(creds.ts);
        if self.total >= max_total {
            if entries.is_empty() {
                self.by_mailbox.remove(&creds.mailbox);
            }
            return Claim::Unrecorded;
        }
        entries.insert(
            creds.sig.clone(),
            creds.ts.saturating_add(REST_MAX_SKEW_SECS),
        );
        self.total += 1;
        Claim::Fresh
    }

    /// The highest `ts` of a request [`ReplayCache::claim`] let through.
    pub(crate) fn highest_ts(&self) -> u64 {
        self.highest_ts
    }

    /// Drop the entries whose requests can no longer pass the timestamp
    /// check, and mailboxes left without any.
    pub(crate) fn sweep(&mut self, clock_secs: u64) {
        let now = self.advance(clock_secs);
        self.by_mailbox.retain(|_, entries| {
            entries.retain(|_, until| *until >= now);
            !entries.is_empty()
        });
        self.total = self.by_mailbox.values().map(HashMap::len).sum();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(mailbox: &str, sig: &str, ts: u64) -> RestCredentials {
        RestCredentials {
            mailbox: mailbox.into(),
            sig: sig.into(),
            ts,
        }
    }

    #[test]
    fn live_entries_are_kept_and_each_mailbox_has_a_share() {
        let mut c = ReplayCache::default();
        assert_eq!(c.claim(&creds("a", "s1", 1000), 1000, 2, 10), Claim::Fresh);
        assert_eq!(c.claim(&creds("a", "s1", 1000), 1300, 2, 10), Claim::Replay);
        assert_eq!(c.claim(&creds("a", "s2", 1100), 1000, 2, 10), Claim::Fresh);
        assert_eq!(c.claim(&creds("a", "s3", 1000), 1000, 2, 10), Claim::Full);
        // Another mailbox has its own share.
        assert_eq!(c.claim(&creds("b", "s3", 1000), 1000, 2, 10), Claim::Fresh);
        // At 1301 `s1` has left the window and makes room; `s2` hasn't.
        assert_eq!(c.claim(&creds("a", "s3", 1001), 1301, 2, 10), Claim::Fresh);
        assert_eq!(c.claim(&creds("a", "s2", 1100), 1301, 2, 10), Claim::Replay);
        c.sweep(1400);
        assert_eq!(c.by_mailbox["a"].len(), 1, "only s2 is live");
        assert!(!c.by_mailbox.contains_key("b"));
        assert_eq!(c.len(), 1);
        c.sweep(1401);
        assert!(c.by_mailbox.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn a_stale_clock_reading_can_neither_drop_nor_pass_a_live_entry() {
        // Review probes P1 and P1b: a replay that read the clock at the
        // window's last second and takes the lock after a sweep (or after a
        // full share's retain) with a later reading.
        let mut c = ReplayCache::default();
        let first = creds("a", "s1", 1000);
        assert_eq!(c.claim(&first, 1000, 2, 10), Claim::Fresh);
        c.sweep(1301);
        assert_eq!(c.claim(&first, 1300, 2, 10), Claim::Expired);

        let mut c = ReplayCache::default();
        assert_eq!(c.claim(&first, 1000, 2, 10), Claim::Fresh);
        assert_eq!(c.claim(&creds("a", "s2", 1000), 1000, 2, 10), Claim::Fresh);
        assert_eq!(c.claim(&creds("a", "s3", 1301), 1301, 2, 10), Claim::Fresh);
        assert_eq!(c.claim(&first, 1300, 2, 10), Claim::Expired);
    }

    #[test]
    fn the_window_is_checked_at_the_caches_time() {
        let mut c = ReplayCache::default();
        assert_eq!(c.claim(&creds("a", "s", 1300), 1000, 2, 10), Claim::Fresh);
        assert_eq!(c.claim(&creds("a", "t", 1301), 1000, 2, 10), Claim::Expired);
        assert_eq!(c.claim(&creds("a", "u", 700), 1000, 2, 10), Claim::Fresh);
        assert_eq!(c.claim(&creds("a", "v", 699), 1000, 2, 10), Claim::Expired);
    }

    #[test]
    fn past_the_total_requests_go_unrecorded_and_shares_still_hold() {
        let mut c = ReplayCache::default();
        assert_eq!(c.claim(&creds("a", "s1", 1000), 1000, 2, 2), Claim::Fresh);
        assert_eq!(c.claim(&creds("b", "s1", 1000), 1000, 2, 2), Claim::Fresh);
        assert_eq!(
            c.claim(&creds("c", "s1", 1000), 1000, 2, 2),
            Claim::Unrecorded
        );
        assert!(!c.by_mailbox.contains_key("c"));
        assert_eq!(c.claim(&creds("a", "s1", 1000), 1000, 2, 2), Claim::Replay);
        assert_eq!(c.len(), 2);
        // Room again once entries leave the window; every request let
        // through raises the highest `ts`.
        assert_eq!(c.highest_ts(), 1000);
        c.sweep(1301);
        assert_eq!(c.claim(&creds("c", "s2", 1301), 1301, 2, 2), Claim::Fresh);
        assert_eq!(c.highest_ts(), 1301);
        assert_eq!(c.claim(&creds("c", "s3", 1200), 1301, 2, 2), Claim::Fresh);
        assert_eq!(c.highest_ts(), 1301);
    }
}
