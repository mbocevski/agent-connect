//! Per-address rate limits (ADR-006 Decision 4).
//!
//! Windows live in process memory only. Addresses are never logged, never
//! stored and never exported as metrics; an idle address is forgotten at the
//! next sweep, and the number of windows is capped: the key that arrived
//! first is evicted, in amortised constant time. The windows are sharded,
//! so a request locks only its own key's shard.
//! IPv6 clients are limited per /64, since one host usually holds a whole
//! prefix. Writes are limited per address and, separately, per (address,
//! listing name), so one busy client (or one proxy) can't use up every
//! name's budget.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

/// What a request costs against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Pages, cards, `llms.txt`, the feed.
    Read,
    /// `/search` and searches on the home page.
    Search,
    /// The MCP endpoint.
    Mcp,
    /// Publish, withdraw and revoke.
    Write,
    /// Publish and withdraw, per listing name.
    WriteName,
}

/// A limit: at most `max` requests per `window_secs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// Requests allowed in the window.
    pub max: usize,
    /// Window length in seconds.
    pub window_secs: u64,
}

/// The limits per class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// [`Class::Read`].
    pub read: Limit,
    /// [`Class::Search`].
    pub search: Limit,
    /// [`Class::Mcp`].
    pub mcp: Limit,
    /// [`Class::Write`], per address.
    pub write: Limit,
    /// [`Class::WriteName`], per (address, name).
    pub write_name: Limit,
    /// Most windows tracked at once.
    pub max_windows: usize,
}

impl Default for Limits {
    fn default() -> Self {
        let l = |max, window_secs| Limit { max, window_secs };
        Self {
            read: l(240, 60),
            search: l(60, 60),
            mcp: l(120, 60),
            write: l(120, 3600),
            write_name: l(20, 3600),
            max_windows: 100_000,
        }
    }
}

impl Limits {
    fn of(&self, class: Class) -> Limit {
        match class {
            Class::Read => self.read,
            Class::Search => self.search,
            Class::Mcp => self.mcp,
            Class::Write => self.write,
            Class::WriteName => self.write_name,
        }
    }
}

/// The key an address is limited under: the address for IPv4, the /64 for
/// IPv6 (IPv4-mapped addresses count as IPv4).
#[must_use]
pub fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let mut s = v6.segments();
            s[4..].fill(0);
            IpAddr::V6(s.into())
        }
    }
}

type Key = (Option<IpAddr>, Class, Option<String>);

/// Lock shards; a request locks only its key's shard.
pub const SHARDS: usize = 16;

/// One shard: the windows, and the order their keys arrived in, for
/// eviction in amortised constant time.
#[derive(Debug, Default)]
struct Shard {
    windows: HashMap<Key, VecDeque<u64>>,
    order: VecDeque<Key>,
}

/// Sliding-window limiter keyed by (address bucket, class, name), sharded
/// by key. When a shard is full, the key that arrived first is evicted
/// (amortised O(1): one pop per insert, plus skips of keys a sweep already
/// dropped).
#[derive(Debug)]
pub struct RateLimiter {
    limits: Limits,
    hasher: RandomState,
    per_shard: usize,
    shards: Vec<Mutex<Shard>>,
    probes: AtomicU64,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

fn lock(m: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl RateLimiter {
    /// A limiter with `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            hasher: RandomState::new(),
            per_shard: limits.max_windows.div_ceil(SHARDS).max(1),
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            probes: AtomicU64::new(0),
        }
    }

    /// Count a request from `ip` (`None`: no address known) at `now_ms`.
    ///
    /// # Errors
    ///
    /// The seconds to wait if it is over the limit.
    pub fn check(&self, ip: Option<IpAddr>, class: Class, now_ms: u64) -> Result<(), u64> {
        self.hit((ip.map(bucket), class, None), now_ms)
    }

    /// Count a write of listing `name` from `ip`.
    ///
    /// # Errors
    ///
    /// The seconds to wait if it is over the limit.
    pub fn check_name(&self, ip: Option<IpAddr>, name: &str, now_ms: u64) -> Result<(), u64> {
        self.hit(
            (ip.map(bucket), Class::WriteName, Some(name.to_owned())),
            now_ms,
        )
    }

    fn hit(&self, key: Key, now_ms: u64) -> Result<(), u64> {
        let limit = self.limits.of(key.1);
        let window_ms = limit.window_secs * 1000;
        let shard = usize::try_from(self.hasher.hash_one(&key)).unwrap_or(0) % SHARDS;
        let mut guard = lock(&self.shards[shard]);
        let Shard { windows, order } = &mut *guard;
        if !windows.contains_key(&key) {
            // Bounded memory: evict the key that arrived first.
            while windows.len() >= self.per_shard {
                let Some(oldest) = order.pop_front() else {
                    break;
                };
                self.probes.fetch_add(1, Ordering::Relaxed);
                windows.remove(&oldest);
            }
            order.push_back(key.clone());
        }
        let w = windows.entry(key).or_default();
        while w
            .front()
            .is_some_and(|t| now_ms.saturating_sub(*t) >= window_ms)
        {
            w.pop_front();
        }
        if w.len() >= limit.max {
            let oldest = w.front().copied().unwrap_or(now_ms);
            let wait_ms = window_ms.saturating_sub(now_ms.saturating_sub(oldest));
            return Err(wait_ms.div_ceil(1000).max(1));
        }
        w.push_back(now_ms);
        Ok(())
    }

    /// Forget windows with no request inside them.
    pub fn sweep(&self, now_ms: u64) {
        let limits = self.limits;
        for shard in &self.shards {
            let mut guard = lock(shard);
            let Shard { windows, order } = &mut *guard;
            windows.retain(|(_, class, _), w| {
                let window_ms = limits.of(*class).window_secs * 1000;
                w.back()
                    .is_some_and(|t| now_ms.saturating_sub(*t) < window_ms)
            });
            order.retain(|k| windows.contains_key(k));
        }
    }

    /// Number of tracked windows (tests).
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.shards.iter().map(|s| lock(s).windows.len()).sum()
    }

    /// The most windows held at once.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.per_shard * SHARDS
    }

    /// Keys examined by eviction so far (tests: eviction stays O(1) per
    /// insert).
    #[must_use]
    pub fn eviction_probes(&self) -> u64 {
        self.probes.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        s.parse().ok()
    }

    fn small() -> RateLimiter {
        let l = Limit {
            max: 2,
            window_secs: 10,
        };
        RateLimiter::new(Limits {
            read: l,
            search: l,
            mcp: l,
            write: l,
            write_name: l,
            max_windows: 1000,
        })
    }

    #[test]
    fn limits_per_address_and_class_and_slides() {
        let r = small();
        let a = ip("192.0.2.1");
        assert!(r.check(a, Class::Read, 0).is_ok());
        assert!(r.check(a, Class::Read, 1000).is_ok());
        assert_eq!(r.check(a, Class::Read, 2000), Err(8));
        assert!(r.check(a, Class::Search, 2000).is_ok());
        assert!(r.check(ip("192.0.2.2"), Class::Read, 2000).is_ok());
        assert!(r.check(a, Class::Read, 10_000).is_ok());
        assert!(r.check(None, Class::Write, 0).is_ok());
    }

    #[test]
    fn names_have_their_own_budget() {
        let r = small();
        let a = ip("192.0.2.1");
        assert!(r.check_name(a, "one", 0).is_ok());
        assert!(r.check_name(a, "one", 0).is_ok());
        assert!(r.check_name(a, "one", 0).is_err());
        assert!(r.check_name(a, "two", 0).is_ok());
        assert!(r.check_name(ip("192.0.2.2"), "one", 0).is_ok());
    }

    #[test]
    fn ipv6_is_limited_per_slash_64() {
        let r = small();
        assert!(r.check(ip("2001:db8:1:2::1"), Class::Read, 0).is_ok());
        assert!(r.check(ip("2001:db8:1:2::ffff"), Class::Read, 0).is_ok());
        assert!(r.check(ip("2001:db8:1:2:aaaa::1"), Class::Read, 0).is_err());
        assert!(r.check(ip("2001:db8:1:3::1"), Class::Read, 0).is_ok());
        assert_eq!(
            bucket("::ffff:192.0.2.9".parse().unwrap()),
            ip("192.0.2.9").unwrap()
        );
    }

    fn addr(i: u32) -> Option<IpAddr> {
        ip(&std::net::Ipv4Addr::from(0xC000_0200 + i).to_string())
    }

    fn capped(max_windows: usize) -> RateLimiter {
        let l = Limit {
            max: 5,
            window_secs: 60,
        };
        RateLimiter::new(Limits {
            read: l,
            search: l,
            mcp: l,
            write: l,
            write_name: l,
            max_windows,
        })
    }

    #[test]
    fn memory_is_bounded() {
        let r = capped(32);
        for i in 0..500 {
            r.check(addr(i), Class::Read, u64::from(i)).unwrap();
            assert!(r.tracked() <= r.capacity());
        }
        // The newest address is still tracked.
        for _ in 0..4 {
            r.check(addr(499), Class::Read, 1000).unwrap();
        }
        assert!(r.check(addr(499), Class::Read, 1000).is_err());
    }

    /// Eviction is O(1) per insert: filling past the cap examines at most
    /// one queued key per new key, plus keys a sweep already dropped.
    #[test]
    fn eviction_is_constant_time_per_insert() {
        let r = capped(1600);
        let cap = u64::try_from(r.capacity()).unwrap();
        for i in 0..20_000_u32 {
            r.check(addr(i), Class::Read, 0).unwrap();
        }
        let inserts_past_cap = 20_000 - cap;
        let probes = r.eviction_probes();
        assert!(probes <= 20_000, "{probes} probes for 20000 inserts");
        assert!(probes + u64::try_from(SHARDS).unwrap() >= inserts_past_cap / 2);
        // After a sweep drops everything, inserting again costs nothing.
        r.sweep(61_000);
        assert_eq!(r.tracked(), 0);
        let before = r.eviction_probes();
        for i in 0..100 {
            r.check(addr(i), Class::Read, 61_000).unwrap();
        }
        assert_eq!(r.eviction_probes(), before);
    }

    #[test]
    fn sweep_forgets_idle_addresses() {
        let r = small();
        r.check(ip("192.0.2.1"), Class::Read, 0).unwrap();
        r.check(ip("192.0.2.2"), Class::Write, 5000).unwrap();
        r.sweep(10_000);
        assert_eq!(r.tracked(), 1);
        r.sweep(20_000);
        assert_eq!(r.tracked(), 0);
        assert_eq!(Limits::default().of(Class::Mcp).max, 120);
    }
}
