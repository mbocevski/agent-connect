//! Environment configuration.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use agentconnect_core::identity::canonical_relay_host;

/// Default listen address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8090";
/// The default relay.
pub const DEFAULT_RELAY: &str = "connect.yggdrasill.network";
/// `AC_DIRECTORY_DB` value for a throwaway in-memory store.
pub const MEMORY_DB: &str = "memory:";

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

    /// Whether `ip` is in the block (IPv4-mapped IPv6 counts as IPv4).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        };
        let p = u32::from(self.prefix);
        match (self.net, ip) {
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

/// Directory configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `AC_DIRECTORY_ADDR`: listen address.
    pub addr: SocketAddr,
    /// `AC_DIRECTORY_DB`: a `postgres://` URL, or `memory:`.
    pub db: String,
    /// `AC_DIRECTORY_DB_INSECURE=1`: allow a Postgres connection without
    /// verified TLS to a host that isn't loopback (logged as a warning).
    pub db_insecure: bool,
    /// `AC_DIRECTORY_HOST` (required): this directory's public host, in the
    /// SPEC §8.1.1 canonical form. Listings, tokens and withdrawals must
    /// name it.
    pub host: String,
    /// `AC_DIRECTORY_RELAYS`: comma-separated relay hosts listings may point
    /// at. The first is shown on the site.
    pub relays: Vec<String>,
    /// `AC_DIRECTORY_TOKEN_KEYS`: comma-separated operator token public keys
    /// (`DK.pub`, base64url): one, or two while rotating. Required.
    pub token_keys: Vec<String>,
    /// `AC_DIRECTORY_CLIENT_IP_HEADER`: a header a trusted reverse proxy
    /// sets to the client address. Honoured only on connections from
    /// `trusted_proxies`.
    pub client_ip_header: Option<String>,
    /// `AC_DIRECTORY_TRUSTED_PROXIES`: comma-separated address blocks of the
    /// reverse proxies whose client-address header is believed.
    pub trusted_proxies: Vec<Cidr>,
    /// `AC_DIRECTORY_STYLESHEET`: a CSS file served instead of the default
    /// stylesheet.
    pub stylesheet: Option<PathBuf>,
}

fn list(v: Option<String>) -> Vec<String> {
    v.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

impl Config {
    /// Read the configuration through `get` (normally the process
    /// environment).
    ///
    /// # Errors
    ///
    /// A message naming the variable that is missing or invalid.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let addr_text = get("AC_DIRECTORY_ADDR").unwrap_or_else(|| DEFAULT_ADDR.to_owned());
        let addr: SocketAddr = addr_text
            .parse()
            .map_err(|_| format!("AC_DIRECTORY_ADDR is not a socket address: {addr_text}"))?;
        let db = get("AC_DIRECTORY_DB")
            .filter(|d| !d.is_empty())
            .ok_or("AC_DIRECTORY_DB is required (a postgres:// URL, or memory:)")?;
        if db != MEMORY_DB && !db.starts_with("postgres://") && !db.starts_with("postgresql://") {
            return Err("AC_DIRECTORY_DB must be a postgres:// URL or memory:".to_owned());
        }
        let host = get("AC_DIRECTORY_HOST")
            .filter(|h| !h.is_empty())
            .ok_or("AC_DIRECTORY_HOST is required (this directory's public host)")?;
        let host = canonical_relay_host(&host)
            .map_err(|_| format!("AC_DIRECTORY_HOST is not a valid host: {host}"))?;
        let mut relays = Vec::new();
        for r in list(get("AC_DIRECTORY_RELAYS")) {
            relays.push(
                canonical_relay_host(&r)
                    .map_err(|_| format!("AC_DIRECTORY_RELAYS has an invalid host: {r}"))?,
            );
        }
        if relays.is_empty() {
            relays.push(DEFAULT_RELAY.to_owned());
        }
        let token_keys = list(get("AC_DIRECTORY_TOKEN_KEYS"));
        if token_keys.is_empty() || token_keys.len() > 2 {
            return Err("AC_DIRECTORY_TOKEN_KEYS takes one or two keys".to_owned());
        }
        let client_ip_header = get("AC_DIRECTORY_CLIENT_IP_HEADER")
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty());
        if let Some(h) = &client_ip_header
            && axum::http::HeaderName::from_bytes(h.as_bytes()).is_err()
        {
            return Err(format!(
                "AC_DIRECTORY_CLIENT_IP_HEADER is not a header name: {h}"
            ));
        }
        let trusted_proxies = list(get("AC_DIRECTORY_TRUSTED_PROXIES"))
            .iter()
            .map(|c| Cidr::parse(c).map_err(|e| format!("AC_DIRECTORY_TRUSTED_PROXIES: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        if client_ip_header.is_some() && trusted_proxies.is_empty() {
            return Err(
                "AC_DIRECTORY_CLIENT_IP_HEADER needs AC_DIRECTORY_TRUSTED_PROXIES".to_owned(),
            );
        }
        let flag = |k: &str| get(k).is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"));
        Ok(Self {
            addr,
            db,
            db_insecure: flag("AC_DIRECTORY_DB_INSECURE"),
            host,
            relays,
            token_keys,
            client_ip_header,
            trusted_proxies,
            stylesheet: get("AC_DIRECTORY_STYLESHEET")
                .filter(|p| !p.is_empty())
                .map(PathBuf::from),
        })
    }

    /// Read the configuration from the process environment.
    ///
    /// # Errors
    ///
    /// See [`Config::from_lookup`].
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    const DB: (&str, &str) = ("AC_DIRECTORY_DB", "memory:");
    const KEYS: (&str, &str) = ("AC_DIRECTORY_TOKEN_KEYS", "k");
    const HOST: (&str, &str) = ("AC_DIRECTORY_HOST", "directory.example.org");

    #[test]
    fn defaults() {
        let c = Config::from_lookup(lookup(&[DB, KEYS, HOST])).unwrap();
        assert_eq!(c.addr.to_string(), DEFAULT_ADDR);
        assert_eq!(c.host, "directory.example.org");
        assert_eq!(c.relays, [DEFAULT_RELAY]);
        assert_eq!(c.token_keys, ["k"]);
        assert!(c.client_ip_header.is_none());
        assert_eq!(c.trusted_proxies, Vec::new());
        assert!(!c.db_insecure);
        assert!(c.stylesheet.is_none());
    }

    #[test]
    fn overrides() {
        let c = Config::from_lookup(lookup(&[
            ("AC_DIRECTORY_ADDR", "0.0.0.0:9000"),
            ("AC_DIRECTORY_DB", "postgres://u@db.example.org/directory"),
            ("AC_DIRECTORY_DB_INSECURE", "1"),
            ("AC_DIRECTORY_HOST", "Directory.Example.org"),
            (
                "AC_DIRECTORY_RELAYS",
                "relay.example.org, other.example.org:8443",
            ),
            ("AC_DIRECTORY_TOKEN_KEYS", "a,b"),
            ("AC_DIRECTORY_CLIENT_IP_HEADER", "X-Forwarded-For"),
            ("AC_DIRECTORY_TRUSTED_PROXIES", "10.0.0.0/8, ::1"),
            ("AC_DIRECTORY_STYLESHEET", "/etc/directory/site.css"),
        ]))
        .unwrap();
        assert_eq!(c.addr.port(), 9000);
        assert_eq!(c.host, "directory.example.org");
        assert_eq!(c.relays, ["relay.example.org", "other.example.org:8443"]);
        assert_eq!(c.token_keys, ["a", "b"]);
        assert_eq!(c.client_ip_header.as_deref(), Some("x-forwarded-for"));
        assert_eq!(c.trusted_proxies.len(), 2);
        assert!(c.db_insecure);
        assert_eq!(c.stylesheet, Some(PathBuf::from("/etc/directory/site.css")));
    }

    #[test]
    fn rejects_bad_values() {
        for bad in [
            vec![KEYS, HOST],
            vec![DB, HOST],
            vec![DB, KEYS],
            vec![KEYS, HOST, ("AC_DIRECTORY_DB", "sqlite://x")],
            vec![DB, KEYS, HOST, ("AC_DIRECTORY_ADDR", "nope")],
            vec![DB, KEYS, ("AC_DIRECTORY_HOST", "a b")],
            vec![DB, KEYS, HOST, ("AC_DIRECTORY_RELAYS", "x/y")],
            vec![DB, HOST, ("AC_DIRECTORY_TOKEN_KEYS", "a,b,c")],
            vec![
                DB,
                KEYS,
                HOST,
                ("AC_DIRECTORY_CLIENT_IP_HEADER", "bad header"),
            ],
            // A client-address header without trusted proxies.
            vec![
                DB,
                KEYS,
                HOST,
                ("AC_DIRECTORY_CLIENT_IP_HEADER", "x-forwarded-for"),
            ],
            vec![
                DB,
                KEYS,
                HOST,
                ("AC_DIRECTORY_TRUSTED_PROXIES", "10.0.0.0/33"),
            ],
            vec![DB, KEYS, HOST, ("AC_DIRECTORY_TRUSTED_PROXIES", "nope")],
        ] {
            assert!(Config::from_lookup(lookup(&bad)).is_err(), "{bad:?}");
        }
        let _ = Config::from_env();
    }

    #[test]
    fn cidr_blocks() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(c.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!c.contains("10.2.0.1".parse().unwrap()));
        assert!(!c.contains("2001:db8::1".parse().unwrap()));
        let one = Cidr::parse("192.0.2.7").unwrap();
        assert!(one.contains("192.0.2.7".parse().unwrap()));
        assert!(!one.contains("192.0.2.8".parse().unwrap()));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        let all = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("203.0.113.9".parse().unwrap()));
        assert!(Cidr::parse("::/129").is_err());
    }
}
