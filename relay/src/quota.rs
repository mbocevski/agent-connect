//! Limits for a relay open to the public: signed REST requests, invites,
//! groups and idle groups (SPEC §8.1.1, §8.3), and the client address the
//! per-address limits count by.
//!
//! Every per-address count is in memory only: the relay stores no address,
//! and no address (or hash of one) is kept next to an invite or a group.
//! Addresses are never logged.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use axum::http::{HeaderMap, HeaderName};

use crate::store::Window;

/// How coarse a group's recorded activity time is: a send rewrites it only
/// once it is this old, and the idle sweep waits this much longer.
pub const ACTIVITY_GRANULARITY: Duration = Duration::from_hours(1);

/// The relay's abuse limits. The defaults suit a small public relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quotas {
    /// Signed REST requests whose signature or timestamp fails, per source
    /// address (IPv6: per /64). A full bucket refuses only such requests.
    pub rest_junk_per_address: Window,
    /// Validated signed `POST`s (creations) per source address.
    pub rest_per_address: Window,
    /// Validated signed REST requests per mailbox.
    pub rest_per_mailbox: Window,
    /// Live replay-cache entries one mailbox may hold.
    pub replay_per_mailbox: usize,
    /// Live replay-cache entries in all; past it requests are still served
    /// but no longer recorded (their effects are idempotent, SPEC §8.1.1).
    pub replay_max_entries: usize,
    /// Open invites one mailbox may hold at once.
    pub open_invites_per_mailbox: usize,
    /// Invite rows created from one source address that the relay still
    /// holds (until `expires_at` plus the 7-day grace period).
    pub invites_per_address: usize,
    /// Invite rows the relay holds in all, open or not yet purged.
    pub max_invites: usize,
    /// `group.create` frames accepted per mailbox.
    pub groups_per_mailbox: Window,
    /// Groups created from one source address within the idle period.
    pub groups_per_address: usize,
    /// Groups the relay holds in all.
    pub max_groups: usize,
    /// How long a group may go without an accepted send, and with no member
    /// connected, before the relay deletes it.
    pub group_idle: Duration,
    /// Where the client address comes from.
    pub client_ip: ClientIp,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            rest_junk_per_address: Window {
                max: 60,
                per: Duration::from_mins(1),
            },
            rest_per_address: Window {
                max: 60,
                per: Duration::from_mins(1),
            },
            rest_per_mailbox: Window {
                max: 30,
                per: Duration::from_mins(1),
            },
            replay_per_mailbox: 128,
            replay_max_entries: 100_000,
            open_invites_per_mailbox: 50,
            invites_per_address: 500,
            max_invites: 100_000,
            groups_per_mailbox: Window {
                max: 100,
                per: Duration::from_hours(24),
            },
            groups_per_address: 500,
            max_groups: 100_000,
            group_idle: Duration::from_hours(30 * 24),
            client_ip: ClientIp::default(),
        }
    }
}

/// How to find a request's client address: the TCP peer, or the address a
/// trusted reverse proxy put in a header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIp {
    /// The header the proxies write: `x-forwarded-for` (or another list of
    /// addresses in the same form) or `forwarded` (RFC 7239).
    pub header: Option<HeaderName>,
    /// The proxies whose header is believed.
    pub trusted_proxies: Vec<Cidr>,
    /// How many proxies append to the header: the client is the entry this
    /// many places from the right.
    pub hops: usize,
}

impl Default for ClientIp {
    fn default() -> Self {
        Self {
            header: None,
            trusted_proxies: Vec::new(),
            hops: 1,
        }
    }
}

/// Why [`ClientIp::resolve`] used the peer address although a request
/// named another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIpWarning {
    /// The request carries `X-Forwarded-For` or `Forwarded`, and no
    /// client-address header is configured: behind a proxy, every client
    /// shares the proxy's buckets.
    HeaderNotConfigured,
    /// The configured header came from a trusted proxy but has fewer
    /// entries than the hop count, or an entry that isn't an address.
    Unreadable,
    /// The request carries the client-address header (or `X-Forwarded-For`
    /// or `Forwarded`) but its peer is outside the trusted proxies: the
    /// header is ignored and the peer is the client. Behind a proxy whose
    /// address isn't listed, every client shares that proxy's buckets.
    UntrustedPeer,
}

impl ClientIp {
    /// The client address, and a warning when the request suggests a
    /// misconfiguration. Without a configured header, or from a peer that
    /// isn't a trusted proxy, it is the peer. Otherwise it is the entry
    /// [`ClientIp::hops`] places from the right of the header (each proxy
    /// appends the address it saw), so entries a client writes itself are
    /// never used, even by a client inside a trusted block. A header too
    /// short or unreadable at that place gives the peer.
    #[must_use]
    pub fn resolve(
        &self,
        peer: Option<IpAddr>,
        headers: &HeaderMap,
    ) -> (Option<IpAddr>, Option<ClientIpWarning>) {
        let Some(name) = &self.header else {
            let forwarded =
                headers.contains_key("x-forwarded-for") || headers.contains_key("forwarded");
            return (
                peer,
                forwarded.then_some(ClientIpWarning::HeaderNotConfigured),
            );
        };
        let trusted = |ip: IpAddr| self.trusted_proxies.iter().any(|c| c.contains(ip));
        if !peer.is_some_and(trusted) {
            // A peer outside the trusted blocks that still names a client
            // is, most likely, a proxy that isn't listed.
            let forwarded = headers.contains_key(name)
                || headers.contains_key("x-forwarded-for")
                || headers.contains_key("forwarded");
            let warning = (forwarded && peer.is_some()).then_some(ClientIpWarning::UntrustedPeer);
            return (peer, warning);
        }
        let rfc7239 = name.as_str() == "forwarded";
        let entries: Vec<&str> = headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .collect();
        let Some(entry) = entries
            .len()
            .checked_sub(self.hops)
            .and_then(|i| entries.get(i))
        else {
            return (peer, Some(ClientIpWarning::Unreadable));
        };
        let address = if rfc7239 {
            forwarded_for(entry)
        } else {
            Some(entry.trim())
        };
        match address.and_then(parse_node) {
            Some(ip) => (Some(ip), None),
            None => (peer, Some(ClientIpWarning::Unreadable)),
        }
    }
}

/// The `for=` value of one RFC 7239 element (`for=192.0.2.1;proto=https`).
fn forwarded_for(element: &str) -> Option<&str> {
    element.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        k.trim().eq_ignore_ascii_case("for").then(|| v.trim())
    })
}

/// An address as proxies write it: `192.0.2.1`, `192.0.2.1:443`,
/// `2001:db8::1`, `[2001:db8::1]` or `[2001:db8::1]:443`, optionally in
/// double quotes (RFC 7239).
fn parse_node(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_matches('"');
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (v6, tail) = rest.split_once(']')?;
        if !(tail.is_empty() || tail.strip_prefix(':').is_some_and(is_port)) {
            return None;
        }
        return v6.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6);
    }
    let (v4, port) = s.rsplit_once(':')?;
    if !is_port(port) {
        return None;
    }
    v4.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

fn is_port(s: &str) -> bool {
    !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit())
}

/// The key an address is limited under: the address for IPv4 (and IPv4
/// mapped into IPv6), its /64 for IPv6, since one host usually holds a whole
/// /64. `None` (no address known, as in tests) is one key of its own.
#[must_use]
pub fn address_key(ip: Option<IpAddr>) -> String {
    match ip.map(unmap) {
        None => "ra:-".to_owned(),
        Some(IpAddr::V4(v4)) => format!("ra:{v4}"),
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("ra:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// The key creations (invites, groups) are counted under: the address for
/// IPv4, its /48 for IPv6. A /48 is what one site is usually given, and a
/// /56 or a /64 is cheap to get many of, so per /64 a single site would
/// hold hundreds of keys (SPEC §8.3). Rates keep the /64 ([`address_key`]).
#[must_use]
pub fn creation_key(ip: Option<IpAddr>) -> String {
    match ip.map(unmap) {
        None => "ca:-".to_owned(),
        Some(IpAddr::V4(v4)) => format!("ca:{v4}"),
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("ca:{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// Above this share of a global creation cap, each key's limit drops to
/// its fair share of what is left.
pub const PRESSURE_PERCENT: u64 = 75;
/// The last share of a global creation cap, kept for keys that hold
/// almost nothing, so a light user can still start a conversation.
pub const RESERVE_PERCENT: u64 = 5;
/// A key's limit under pressure never drops below this.
pub const FAIR_SHARE_FLOOR: usize = 3;
/// Keys holding fewer than this may use the reserve.
pub const RESERVE_HOLDS_BELOW: usize = 2;

/// Why [`admit`] refused a creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The global cap is reached.
    Full,
    /// Only the reserve is left, and the key holds too much for it.
    Reserved,
    /// The key holds its limit (its fair share, under pressure).
    Key,
}

/// Whether one more creation is admitted for a key that `holds` rows, when
/// the relay holds `live` of at most `max` and `keys` keys hold some.
///
/// - At `max`, nothing is.
/// - In the last [`RESERVE_PERCENT`], only a key holding fewer than
///   [`RESERVE_HOLDS_BELOW`] is.
/// - Above [`PRESSURE_PERCENT`], a key's limit is the smaller of
///   `per_key` and its fair share: the room left below the reserve divided
///   by `keys`, never below [`FAIR_SHARE_FLOOR`].
/// - Otherwise a key is limited to `per_key`.
///
/// # Errors
///
/// Which limit refused it.
pub fn admit(
    live: u64,
    max: u64,
    per_key: usize,
    holds: usize,
    keys: usize,
) -> Result<(), Refusal> {
    if live >= max {
        return Err(Refusal::Full);
    }
    let soft = max - (max * RESERVE_PERCENT / 100).max(1).min(max);
    if live >= soft {
        return if holds < RESERVE_HOLDS_BELOW {
            Ok(())
        } else {
            Err(Refusal::Reserved)
        };
    }
    let mut limit = per_key;
    if live >= max * PRESSURE_PERCENT / 100 {
        let room = usize::try_from(soft - live).unwrap_or(usize::MAX);
        let fair = (room / keys.max(1)).max(FAIR_SHARE_FLOOR);
        limit = limit.min(fair);
    }
    if holds >= limit {
        return Err(Refusal::Key);
    }
    Ok(())
}

/// Things created per key that the relay still holds: each entry is the
/// time it stops counting. In memory only, and keyed by the address key
/// alone, so nothing links an address to what it created.
#[derive(Debug, Default)]
pub(crate) struct LiveCounts {
    by_key: HashMap<String, Vec<u64>>,
}

impl LiveCounts {
    /// How many `key` holds at `now_ms`.
    pub(crate) fn holds(&mut self, key: &str, now_ms: u64) -> usize {
        self.by_key.get_mut(key).map_or(0, |entries| {
            entries.retain(|t| *t > now_ms);
            entries.len()
        })
    }

    /// Keys that hold something (as of the last sweep).
    pub(crate) fn keys(&self) -> usize {
        self.by_key.len()
    }

    /// Count one more under `key`, until `until_ms`.
    pub(crate) fn push(&mut self, key: &str, until_ms: u64) {
        self.by_key
            .entry(key.to_owned())
            .or_default()
            .push(until_ms);
    }

    /// Give back one entry that [`LiveCounts::push`] made with `until_ms`.
    pub(crate) fn remove(&mut self, key: &str, until_ms: u64) {
        if let Some(entries) = self.by_key.get_mut(key) {
            if let Some(i) = entries.iter().position(|t| *t == until_ms) {
                entries.swap_remove(i);
            }
            if entries.is_empty() {
                self.by_key.remove(key);
            }
        }
    }

    /// Drop what stopped counting, and keys left with nothing.
    pub(crate) fn sweep(&mut self, now_ms: u64) {
        self.by_key.retain(|_, entries| {
            entries.retain(|t| *t > now_ms);
            !entries.is_empty()
        });
    }
}

/// An address block, `addr/prefix` (or a single address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `addr/prefix` or `addr`.
    ///
    /// # Errors
    ///
    /// A message for a bad address or prefix.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let net: IpAddr = addr
            .parse()
            .map_err(|_| format!("not an address block: {s}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("bad prefix length: {s}"))?,
            None => max,
        };
        Ok(Self { net, prefix })
    }

    /// Whether the block is broader than one operator's proxies plausibly
    /// need: shorter than /8 for IPv4 or /32 for IPv6 (so `/0` is too).
    #[must_use]
    pub fn is_broad(&self) -> bool {
        match self.net {
            IpAddr::V4(_) => self.prefix < 8,
            IpAddr::V6(_) => self.prefix < 32,
        }
    }

    /// Whether `ip` is in the block. A peer's IPv4-mapped IPv6 address is
    /// compared as IPv4, so write IPv4 proxies as IPv4 blocks.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let p = u32::from(self.prefix);
        match (self.net, unmap(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let m = u32::MAX.checked_shl(32 - p).unwrap_or(0);
                u32::from(n) & m == u32::from(a) & m
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let m = u128::MAX.checked_shl(128 - p).unwrap_or(0);
                u128::from(n) & m == u128::from(a) & m
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn headers(name: &'static str, values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(name, v.parse().unwrap());
        }
        h
    }

    fn behind(name: &'static str, blocks: &[&str], hops: usize) -> ClientIp {
        ClientIp {
            header: Some(HeaderName::from_static(name)),
            trusted_proxies: blocks.iter().map(|b| Cidr::parse(b).unwrap()).collect(),
            hops,
        }
    }

    const XFF: &str = "x-forwarded-for";

    #[test]
    fn without_a_header_the_peer_is_the_client_and_a_forwarded_request_warns() {
        let c = ClientIp::default();
        let peer = Some(ip("127.0.0.1"));
        assert_eq!(
            c.resolve(peer, &headers(XFF, &["203.0.113.9"])),
            (peer, Some(ClientIpWarning::HeaderNotConfigured))
        );
        assert_eq!(
            c.resolve(peer, &headers("forwarded", &["for=203.0.113.9"])),
            (peer, Some(ClientIpWarning::HeaderNotConfigured))
        );
        assert_eq!(c.resolve(peer, &HeaderMap::new()), (peer, None));
        assert_eq!(c.resolve(None, &HeaderMap::new()), (None, None));
    }

    #[test]
    fn the_header_is_believed_only_from_a_trusted_proxy() {
        let c = behind(XFF, &["127.0.0.1/32"], 1);
        let h = headers(XFF, &["203.0.113.9"]);
        assert_eq!(
            c.resolve(Some(ip("127.0.0.1")), &h),
            (Some(ip("203.0.113.9")), None)
        );
        // A client that reaches the port directly can't choose its key.
        assert_eq!(
            c.resolve(Some(ip("198.51.100.7")), &h),
            (
                Some(ip("198.51.100.7")),
                Some(ClientIpWarning::UntrustedPeer)
            )
        );
        // A trusted peer that sends no header is itself the client.
        assert_eq!(
            c.resolve(Some(ip("127.0.0.1")), &HeaderMap::new()),
            (Some(ip("127.0.0.1")), Some(ClientIpWarning::Unreadable))
        );
    }

    #[test]
    fn a_forwarded_header_from_an_untrusted_peer_warns() {
        // The proxy is at 172.17.0.1, the trusted block is 127.0.0.1: the
        // header is ignored, and the operator is told once.
        let c = behind(XFF, &["127.0.0.1/32"], 1);
        let proxy = Some(ip("172.17.0.1"));
        for (name, value) in [(XFF, "203.0.113.9"), ("forwarded", "for=203.0.113.9")] {
            assert_eq!(
                c.resolve(proxy, &headers(name, &[value])),
                (proxy, Some(ClientIpWarning::UntrustedPeer))
            );
        }
        // Another configured header counts too.
        let custom = behind("x-real-ip", &["127.0.0.1/32"], 1);
        assert_eq!(
            custom.resolve(proxy, &headers("x-real-ip", &["203.0.113.9"])),
            (proxy, Some(ClientIpWarning::UntrustedPeer))
        );
        // A request that names no client is no sign of a proxy.
        assert_eq!(c.resolve(proxy, &HeaderMap::new()), (proxy, None));
        assert_eq!(
            c.resolve(proxy, &headers("accept", &["*/*"])),
            (proxy, None)
        );
        // Nor is a request with no peer address (in-memory tests).
        assert_eq!(
            c.resolve(None, &headers(XFF, &["203.0.113.9"])),
            (None, None)
        );
        // A trusted peer is believed, with no warning.
        assert_eq!(
            c.resolve(Some(ip("127.0.0.1")), &headers(XFF, &["203.0.113.9"])),
            (Some(ip("203.0.113.9")), None)
        );
    }

    #[test]
    fn the_client_is_the_entry_the_hop_count_names_from_the_right() {
        let peer = Some(ip("10.0.0.1"));
        // One proxy: the client wrote the left entries itself, even from
        // inside a trusted block, and none of them is used.
        let one = behind(XFF, &["10.0.0.0/8"], 1);
        for n in 0..3 {
            let h = headers(XFF, &[&format!("198.51.100.{n}, 10.9.9.9")]);
            assert_eq!(one.resolve(peer, &h), (Some(ip("10.9.9.9")), None));
        }
        // Several header lines are one list.
        let h = headers(XFF, &["1.1.1.1", "203.0.113.9"]);
        assert_eq!(one.resolve(peer, &h), (Some(ip("203.0.113.9")), None));
        // Two proxies (a CDN, then nginx): the second entry from the right.
        let two = behind(XFF, &["10.0.0.0/8"], 2);
        let h = headers(XFF, &["1.1.1.1, 203.0.113.9, 192.0.2.80"]);
        assert_eq!(two.resolve(peer, &h), (Some(ip("203.0.113.9")), None));
        // Too short, or junk at that place: the peer, with a warning.
        let h = headers(XFF, &["203.0.113.9"]);
        assert_eq!(
            two.resolve(peer, &h),
            (peer, Some(ClientIpWarning::Unreadable))
        );
        let h = headers(XFF, &["203.0.113.9, junk"]);
        assert_eq!(
            one.resolve(peer, &h),
            (peer, Some(ClientIpWarning::Unreadable))
        );
    }

    #[test]
    fn ports_brackets_and_rfc_7239_are_read() {
        let peer = Some(ip("127.0.0.1"));
        let xff = behind(XFF, &["127.0.0.1/32"], 1);
        for (value, want) in [
            ("203.0.113.9:51234", "203.0.113.9"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
        ] {
            let h = headers(XFF, &[value]);
            assert_eq!(xff.resolve(peer, &h), (Some(ip(want)), None), "{value}");
        }
        for bad in [
            "203.0.113.9:",
            "203.0.113.9:123456",
            "[2001:db8::1]x",
            "host:80",
        ] {
            let h = headers(XFF, &[bad]);
            assert_eq!(xff.resolve(peer, &h).0, peer, "{bad}");
        }
        let fwd = behind("forwarded", &["127.0.0.1/32"], 1);
        for (value, want) in [
            ("for=203.0.113.9", "203.0.113.9"),
            (
                "For=\"[2001:db8:cafe::17]:4711\";proto=https",
                "2001:db8:cafe::17",
            ),
            (
                "for=1.1.1.1, proto=http;for=203.0.113.9:80;by=10.0.0.1",
                "203.0.113.9",
            ),
        ] {
            let h = headers("forwarded", &[value]);
            assert_eq!(fwd.resolve(peer, &h), (Some(ip(want)), None), "{value}");
        }
        // An obfuscated identifier or a missing `for=` isn't an address.
        for bad in ["for=unknown", "for=_hidden", "proto=https"] {
            let h = headers("forwarded", &[bad]);
            assert_eq!(
                fwd.resolve(peer, &h),
                (peer, Some(ClientIpWarning::Unreadable)),
                "{bad}"
            );
        }
    }

    #[test]
    fn ipv6_is_keyed_per_slash_64_and_mapped_ipv4_as_ipv4() {
        let a = address_key(Some(ip("2001:db8:1:2:aaaa::1")));
        let b = address_key(Some(ip("2001:db8:1:2:bbbb::2")));
        let other = address_key(Some(ip("2001:db8:1:3::1")));
        assert_eq!(a, b);
        assert_ne!(a, other);
        assert_eq!(
            address_key(Some(ip("::ffff:192.0.2.1"))),
            address_key(Some(ip("192.0.2.1")))
        );
        assert_ne!(
            address_key(Some(ip("192.0.2.1"))),
            address_key(Some(ip("192.0.2.2")))
        );
        assert_ne!(address_key(None), address_key(Some(ip("192.0.2.1"))));
    }

    #[test]
    fn live_counts_hold_until_their_entries_end() {
        let mut c = LiveCounts::default();
        c.push("k", 100);
        c.push("k", 200);
        assert_eq!(c.holds("k", 99), 2);
        assert_eq!(c.holds("other", 99), 0);
        assert_eq!(c.keys(), 1);
        // The first entry ends at 100.
        assert_eq!(c.holds("k", 100), 1);
        // Giving one back; an unknown one changes nothing.
        c.remove("k", 12345);
        c.remove("nobody", 300);
        c.remove("k", 200);
        assert_eq!(c.keys(), 0);
        c.push("k", 400);
        c.push("j", 300);
        c.sweep(300);
        assert_eq!(c.keys(), 1);
        c.sweep(400);
        assert_eq!(c.keys(), 0);
    }

    #[test]
    fn creations_count_per_slash_48_and_per_ipv4_address() {
        let k = |s: &str| creation_key(Some(ip(s)));
        assert_eq!(k("2001:db8:1:2::1"), k("2001:db8:1:ff00::9"));
        assert_ne!(k("2001:db8:1::1"), k("2001:db8:2::1"));
        assert_eq!(k("::ffff:192.0.2.1"), k("192.0.2.1"));
        assert_ne!(k("192.0.2.1"), k("192.0.2.2"));
        assert_ne!(creation_key(None), k("192.0.2.1"));
    }

    #[test]
    fn admission_tightens_under_pressure_and_keeps_a_reserve_for_light_keys() {
        // Below pressure: the per-key limit.
        assert_eq!(admit(0, 1000, 5, 4, 1), Ok(()));
        assert_eq!(admit(0, 1000, 5, 5, 1), Err(Refusal::Key));
        // Above 75%: the fair share of the room left below the reserve
        // (950 - 800 = 150 over 50 keys is 3), never below the floor.
        assert_eq!(admit(800, 1000, 5, 2, 50), Ok(()));
        assert_eq!(admit(800, 1000, 5, 3, 50), Err(Refusal::Key));
        assert_eq!(admit(940, 1000, 500, 2, 10_000), Ok(()));
        assert_eq!(admit(940, 1000, 500, 3, 10_000), Err(Refusal::Key));
        // The fair share never exceeds the per-key limit.
        assert_eq!(admit(800, 1000, 2, 2, 1), Err(Refusal::Key));
        // The last 5%: only keys holding fewer than two.
        assert_eq!(admit(950, 1000, 500, 0, 1), Ok(()));
        assert_eq!(admit(999, 1000, 500, 1, 1), Ok(()));
        assert_eq!(admit(950, 1000, 500, 2, 1), Err(Refusal::Reserved));
        // At the cap, nothing.
        assert_eq!(admit(1000, 1000, 500, 0, 1), Err(Refusal::Full));
        // A tiny cap still has a reserve of one.
        assert_eq!(admit(1, 2, 5, 0, 1), Ok(()));
        assert_eq!(admit(1, 2, 5, 2, 1), Err(Refusal::Reserved));
        assert_eq!(admit(0, 1, 5, 0, 1), Ok(()));
    }

    #[test]
    fn cidr_parsing_and_matching() {
        let v4 = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(v4.contains(ip("10.255.0.1")));
        assert!(v4.contains(ip("::ffff:10.1.1.1")));
        assert!(!v4.contains(ip("11.0.0.1")));
        assert!(!v4.contains(ip("::1")));
        let one = Cidr::parse("::1").unwrap();
        assert!(one.contains(ip("::1")));
        assert!(!one.contains(ip("::2")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().is_broad());
        assert!(Cidr::parse("2001:db8::/16").unwrap().is_broad());
        assert!(!Cidr::parse("2001:db8::/32").unwrap().is_broad());
        assert!(!v4.is_broad());
        for bad in ["nope", "10.0.0.0/33", "::/129", "10.0.0.0/x"] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }
}
