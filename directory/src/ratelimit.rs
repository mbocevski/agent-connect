//! Per-address rate limits (ADR-006 Decision 4).
//!
//! Windows live in process memory only. Addresses are never logged, never
//! stored and never exported as metrics; an idle address is forgotten at the
//! next sweep. IPv6 clients are limited per /64, since one host usually
//! holds a whole prefix.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

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
    /// [`Class::Write`].
    pub write: Limit,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            read: Limit {
                max: 240,
                window_secs: 60,
            },
            search: Limit {
                max: 60,
                window_secs: 60,
            },
            mcp: Limit {
                max: 120,
                window_secs: 60,
            },
            write: Limit {
                max: 20,
                window_secs: 3600,
            },
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

type Windows = HashMap<(Option<IpAddr>, Class), VecDeque<u64>>;

/// Sliding-window limiter keyed by (address bucket, class).
#[derive(Debug, Default)]
pub struct RateLimiter {
    limits: Limits,
    windows: Mutex<Windows>,
}

impl RateLimiter {
    /// A limiter with `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            windows: Mutex::default(),
        }
    }

    /// Count a request from `ip` (`None`: no address known) at `now_ms`.
    ///
    /// # Errors
    ///
    /// The seconds to wait if it is over the limit.
    pub fn check(&self, ip: Option<IpAddr>, class: Class, now_ms: u64) -> Result<(), u64> {
        let limit = self.limits.of(class);
        let window_ms = limit.window_secs * 1000;
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let w = windows.entry((ip.map(bucket), class)).or_default();
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
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(_, class), w| {
                let window_ms = limits.of(*class).window_secs * 1000;
                w.back()
                    .is_some_and(|t| now_ms.saturating_sub(*t) < window_ms)
            });
    }

    /// Number of tracked windows (tests).
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
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
