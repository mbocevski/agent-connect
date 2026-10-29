//! Environment configuration.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use agentconnect_core::identity::canonical_relay_host;
use agentconnect_core::operator::{OperatorLinks, web_url};

/// Default listen address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8090";
/// `AC_DIRECTORY_DB` value for a throwaway in-memory store.
pub const MEMORY_DB: &str = "memory:";
/// Default `AC_DIRECTORY_SHUTDOWN_GRACE_SECS`: under Docker's 10 s stop
/// timeout, so `docker stop` ends in a clean exit, not a kill.
pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(8);
/// The longest shutdown grace accepted, in seconds.
pub const MAX_SHUTDOWN_GRACE_SECS: u64 = 3600;
/// Default `AC_DIRECTORY_HEADER_TIMEOUT_SECS`: how long a connection may
/// take to send a request head. The relay's default.
pub const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Default `AC_DIRECTORY_IDLE_TIMEOUT_SECS`: how long a connection may stay
/// open between requests. Above the usual reverse-proxy defaults (nginx
/// keeps an upstream connection for 60 s), so a proxy never reuses a
/// connection the directory is closing.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
/// Default `AC_DIRECTORY_REQUEST_TIMEOUT_SECS`: how long a request may take
/// from its head to its response, the body read included. The relay's
/// default.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest header, idle or request timeout accepted, in seconds.
pub const MAX_TIMEOUT_SECS: u64 = 3600;
/// Default `AC_DIRECTORY_MAX_CONNECTIONS`. The relay's default.
pub const DEFAULT_MAX_CONNECTIONS: usize = 512;
/// Default `AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE`. The relay's default.
pub const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: usize = 8;
/// The most connections a limit may allow.
pub const MAX_CONNECTION_LIMIT: usize = 1_000_000;

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
    /// compared as IPv4, so write IPv4 proxies as IPv4 blocks: an
    /// `::ffff:a.b.c.d/n` block never matches.
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

/// Longest operator name or home link label, in characters.
pub const MAX_SITE_TEXT: usize = 80;
/// Longest operator notice (`AC_DIRECTORY_NOTICE`), in characters.
pub const MAX_NOTICE: usize = 200;

/// Operator text shown on every page: trimmed, not empty, no control
/// characters, at most `max` characters.
fn site_text(var: &str, what: &str, value: &str, max: usize) -> Result<String, String> {
    let v = value.trim();
    if v.is_empty() {
        return Err(format!("{var} has an empty {what}"));
    }
    if v.chars().any(char::is_control) {
        return Err(format!("{var}: the {what} has a control character"));
    }
    if v.chars().count() > max {
        return Err(format!("{var}: the {what} is longer than {max} characters"));
    }
    Ok(v.to_owned())
}

/// The operator's home link in the header (`AC_DIRECTORY_HOME`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeLink {
    /// An absolute `https://` URL (`http://` for a loopback host only).
    pub url: String,
    /// The link text.
    pub label: String,
}

impl HomeLink {
    /// Parse `AC_DIRECTORY_HOME`: a URL, whitespace, then the label.
    ///
    /// # Errors
    ///
    /// A message for a missing label or an invalid URL.
    pub fn parse(value: &str) -> Result<Self, String> {
        const VAR: &str = "AC_DIRECTORY_HOME";
        let (url, label) = value
            .trim()
            .split_once(char::is_whitespace)
            .ok_or_else(|| format!("{VAR} needs a URL, whitespace, then a label"))?;
        let label = site_text(VAR, "label", label, MAX_SITE_TEXT)?;
        web_url(VAR, url)?;
        Ok(Self {
            url: url.to_owned(),
            label,
        })
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
    /// `AC_DIRECTORY_RELAYS` (required): comma-separated relay hosts listings may point
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
    /// `AC_DIRECTORY_FONT_DIR`: a directory of font files served under
    /// `/static/fonts/`; it also adds `font-src 'self'` to the CSP.
    pub font_dir: Option<PathBuf>,
    /// `AC_DIRECTORY_METRICS_ADDR`: serve `/metrics` on this address only
    /// (for example a private interface) instead of the public listener.
    pub metrics_addr: Option<SocketAddr>,
    /// `AC_DIRECTORY_NAME`: the operator's name for the site, shown as the
    /// home page's heading and the header's site name.
    pub name: Option<String>,
    /// `AC_DIRECTORY_HOME`: a link to the operator's home page in the
    /// header.
    pub home: Option<HomeLink>,
    /// `AC_DIRECTORY_NOTICE`: a one-line notice shown above every page.
    pub notice: Option<String>,
    /// `AC_DIRECTORY_TERMS` and `AC_DIRECTORY_ABUSE`: the operator's terms
    /// page and abuse contact, shown in every page's footer.
    pub links: OperatorLinks,
    /// `AC_DIRECTORY_SHUTDOWN_GRACE_SECS`: how long connections still open
    /// after SIGTERM or SIGINT may hold the exit up.
    pub shutdown_grace: Duration,
    /// The header timeout and the connection limits.
    pub connections: ConnectionConfig,
}

/// The public listener's limits on slow and many connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// `AC_DIRECTORY_HEADER_TIMEOUT_SECS`: how long a request head may
    /// take, from its first byte (from the connection's start, for the
    /// first request); a slower one is closed.
    pub header_timeout: Duration,
    /// `AC_DIRECTORY_IDLE_TIMEOUT_SECS`: how long a connection may stay
    /// open between a response and the next request.
    pub idle_timeout: Duration,
    /// `AC_DIRECTORY_REQUEST_TIMEOUT_SECS`: how long a request may take
    /// from its head to its response, the body read included; a slower
    /// one is answered 408.
    pub request_timeout: Duration,
    /// `AC_DIRECTORY_MAX_CONNECTIONS`: connections open at once. At the
    /// limit a new connection closes the oldest one of the source holding
    /// the most.
    pub max_connections: usize,
    /// `AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE`: connections open at once
    /// from one source (an IPv4 address or an IPv6 /64). Not applied to a
    /// connection from a trusted proxy, which only the total limits.
    pub max_per_source: usize,
}

impl ConnectionConfig {
    fn from_lookup(get: &impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        Ok(Self {
            header_timeout: timeout_secs(
                "AC_DIRECTORY_HEADER_TIMEOUT_SECS",
                get("AC_DIRECTORY_HEADER_TIMEOUT_SECS"),
                DEFAULT_HEADER_TIMEOUT,
            )?,
            idle_timeout: timeout_secs(
                "AC_DIRECTORY_IDLE_TIMEOUT_SECS",
                get("AC_DIRECTORY_IDLE_TIMEOUT_SECS"),
                DEFAULT_IDLE_TIMEOUT,
            )?,
            request_timeout: timeout_secs(
                "AC_DIRECTORY_REQUEST_TIMEOUT_SECS",
                get("AC_DIRECTORY_REQUEST_TIMEOUT_SECS"),
                DEFAULT_REQUEST_TIMEOUT,
            )?,
            max_connections: connection_limit(
                "AC_DIRECTORY_MAX_CONNECTIONS",
                get("AC_DIRECTORY_MAX_CONNECTIONS"),
                DEFAULT_MAX_CONNECTIONS,
            )?,
            max_per_source: connection_limit(
                "AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE",
                get("AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE"),
                DEFAULT_MAX_CONNECTIONS_PER_SOURCE,
            )?,
        })
    }
}

/// A timeout in whole seconds, 1 to [`MAX_TIMEOUT_SECS`].
fn timeout_secs(name: &str, v: Option<String>, default: Duration) -> Result<Duration, String> {
    let Some(v) = v else {
        return Ok(default);
    };
    v.parse::<u64>()
        .ok()
        .filter(|s| (1..=MAX_TIMEOUT_SECS).contains(s))
        .map(Duration::from_secs)
        .ok_or_else(|| format!("{name} must be 1 to {MAX_TIMEOUT_SECS} seconds: {v}"))
}

/// A connection limit: a whole number, 1 to [`MAX_CONNECTION_LIMIT`].
fn connection_limit(name: &str, v: Option<String>, default: usize) -> Result<usize, String> {
    let Some(v) = v else {
        return Ok(default);
    };
    v.parse::<usize>()
        .ok()
        .filter(|n| (1..=MAX_CONNECTION_LIMIT).contains(n))
        .ok_or_else(|| format!("{name} must be 1 to {MAX_CONNECTION_LIMIT}: {v}"))
}

/// `AC_DIRECTORY_SHUTDOWN_GRACE_SECS`: whole seconds, 1 to
/// [`MAX_SHUTDOWN_GRACE_SECS`].
fn shutdown_grace(v: Option<String>) -> Result<Duration, String> {
    let Some(v) = v else {
        return Ok(DEFAULT_SHUTDOWN_GRACE);
    };
    v.parse::<u64>()
        .ok()
        .filter(|s| (1..=MAX_SHUTDOWN_GRACE_SECS).contains(s))
        .map(Duration::from_secs)
        .ok_or_else(|| {
            format!(
                "AC_DIRECTORY_SHUTDOWN_GRACE_SECS must be 1 to {MAX_SHUTDOWN_GRACE_SECS} seconds: {v}"
            )
        })
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
            return Err(
                "AC_DIRECTORY_RELAYS is required (the relays listings may point at)".to_owned(),
            );
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
        let flag = |k: &str| get(k).is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"));
        let trusted_proxies = list(get("AC_DIRECTORY_TRUSTED_PROXIES"))
            .iter()
            .map(|c| Cidr::parse(c).map_err(|e| format!("AC_DIRECTORY_TRUSTED_PROXIES: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        if trusted_proxies.iter().any(Cidr::is_broad) && !flag("AC_DIRECTORY_TRUST_ANY_PROXY") {
            return Err(
                "AC_DIRECTORY_TRUSTED_PROXIES has a block broader than /8 (IPv4) or /32 (IPv6); \
                 set AC_DIRECTORY_TRUST_ANY_PROXY=1 if that is intended"
                    .to_owned(),
            );
        }
        if client_ip_header.is_some() && trusted_proxies.is_empty() {
            return Err(
                "AC_DIRECTORY_CLIENT_IP_HEADER needs AC_DIRECTORY_TRUSTED_PROXIES".to_owned(),
            );
        }
        let metrics_addr =
            match get("AC_DIRECTORY_METRICS_ADDR").filter(|a| !a.is_empty()) {
                Some(a) => Some(a.parse().map_err(|_| {
                    format!("AC_DIRECTORY_METRICS_ADDR is not a socket address: {a}")
                })?),
                None => None,
            };
        let name = get("AC_DIRECTORY_NAME")
            .map(|n| site_text("AC_DIRECTORY_NAME", "name", &n, MAX_SITE_TEXT))
            .transpose()?;
        let home = get("AC_DIRECTORY_HOME")
            .map(|h| HomeLink::parse(&h))
            .transpose()?;
        let notice = get("AC_DIRECTORY_NOTICE")
            .map(|n| site_text("AC_DIRECTORY_NOTICE", "notice", &n, MAX_NOTICE))
            .transpose()?;
        let links = OperatorLinks::from_lookup("AC_DIRECTORY", &get)?;
        let shutdown_grace = shutdown_grace(get("AC_DIRECTORY_SHUTDOWN_GRACE_SECS"))?;
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
            font_dir: get("AC_DIRECTORY_FONT_DIR")
                .filter(|p| !p.is_empty())
                .map(PathBuf::from),
            metrics_addr,
            name,
            home,
            notice,
            links,
            shutdown_grace,
            connections: ConnectionConfig::from_lookup(&get)?,
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
    const RELAYS: (&str, &str) = ("AC_DIRECTORY_RELAYS", "relay.example.org");

    #[test]
    fn defaults() {
        let c = Config::from_lookup(lookup(&[DB, KEYS, HOST, RELAYS])).unwrap();
        assert_eq!(c.addr.to_string(), DEFAULT_ADDR);
        assert_eq!(c.host, "directory.example.org");
        assert_eq!(c.relays, ["relay.example.org"]);
        assert_eq!(c.token_keys, ["k"]);
        assert!(c.client_ip_header.is_none());
        assert_eq!(c.trusted_proxies, Vec::new());
        assert!(!c.db_insecure);
        assert!(c.stylesheet.is_none());
        assert!(c.font_dir.is_none());
        assert!(c.metrics_addr.is_none());
    }

    #[test]
    fn relays_are_required() {
        for relays in [None, Some(("AC_DIRECTORY_RELAYS", ""))] {
            let mut vars = vec![DB, KEYS, HOST];
            vars.extend(relays);
            let err = Config::from_lookup(lookup(&vars)).unwrap_err();
            assert_eq!(
                err,
                "AC_DIRECTORY_RELAYS is required (the relays listings may point at)"
            );
        }
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
            ("AC_DIRECTORY_FONT_DIR", "/etc/directory/fonts"),
            ("AC_DIRECTORY_METRICS_ADDR", "127.0.0.1:9100"),
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
        assert_eq!(c.font_dir, Some(PathBuf::from("/etc/directory/fonts")));
        assert_eq!(c.metrics_addr.map(|a| a.port()), Some(9100));
    }

    #[test]
    fn rejects_bad_values() {
        for bad in [
            vec![KEYS, HOST, RELAYS],
            vec![DB, HOST, RELAYS],
            vec![DB, KEYS, RELAYS],
            vec![DB, KEYS, HOST],
            vec![DB, KEYS, HOST, ("AC_DIRECTORY_RELAYS", "")],
            vec![KEYS, HOST, RELAYS, ("AC_DIRECTORY_DB", "sqlite://x")],
            vec![DB, KEYS, HOST, RELAYS, ("AC_DIRECTORY_ADDR", "nope")],
            vec![DB, KEYS, RELAYS, ("AC_DIRECTORY_HOST", "a b")],
            vec![DB, KEYS, HOST, ("AC_DIRECTORY_RELAYS", "x/y")],
            vec![DB, HOST, RELAYS, ("AC_DIRECTORY_TOKEN_KEYS", "a,b,c")],
            vec![
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_CLIENT_IP_HEADER", "bad header"),
            ],
            // A client-address header without trusted proxies.
            vec![
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_CLIENT_IP_HEADER", "x-forwarded-for"),
            ],
            vec![
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_TRUSTED_PROXIES", "10.0.0.0/33"),
            ],
            vec![
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_TRUSTED_PROXIES", "nope"),
            ],
            vec![
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_METRICS_ADDR", "nope"),
            ],
            vec![
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_TRUSTED_PROXIES", "0.0.0.0/0"),
            ],
            vec![
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_TRUSTED_PROXIES", "::/0"),
            ],
            vec![
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_TRUSTED_PROXIES", "10.0.0.0/7"),
            ],
            vec![
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_TRUSTED_PROXIES", "2001:db8::/31"),
            ],
        ] {
            assert!(Config::from_lookup(lookup(&bad)).is_err(), "{bad:?}");
        }
        let _ = Config::from_env();
    }

    #[test]
    fn the_shutdown_grace_defaults_below_dockers_stop_timeout() {
        assert_eq!(with(&[]).unwrap().shutdown_grace, Duration::from_secs(8));
        let c = with(&[("AC_DIRECTORY_SHUTDOWN_GRACE_SECS", "3")]).unwrap();
        assert_eq!(c.shutdown_grace, Duration::from_secs(3));
        for bad in ["0", "-1", "x", "", "3601"] {
            let err = with(&[("AC_DIRECTORY_SHUTDOWN_GRACE_SECS", bad)]).unwrap_err();
            assert!(
                err.contains("AC_DIRECTORY_SHUTDOWN_GRACE_SECS"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn the_connection_limits_default_to_the_relays() {
        let c = with(&[]).unwrap();
        let d = c.connections;
        assert_eq!(d.header_timeout, Duration::from_secs(10));
        assert_eq!(d.idle_timeout, Duration::from_secs(75));
        assert_eq!(d.request_timeout, Duration::from_secs(30));
        assert_eq!((d.max_connections, d.max_per_source), (512, 8));
        let c = with(&[
            ("AC_DIRECTORY_HEADER_TIMEOUT_SECS", "3"),
            ("AC_DIRECTORY_IDLE_TIMEOUT_SECS", "90"),
            ("AC_DIRECTORY_REQUEST_TIMEOUT_SECS", "12"),
            ("AC_DIRECTORY_MAX_CONNECTIONS", "64"),
            ("AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE", "2"),
        ])
        .unwrap();
        let c = c.connections;
        assert_eq!(c.header_timeout, Duration::from_secs(3));
        assert_eq!(c.idle_timeout, Duration::from_secs(90));
        assert_eq!(c.request_timeout, Duration::from_secs(12));
        assert_eq!((c.max_connections, c.max_per_source), (64, 2));
    }

    #[test]
    fn bad_connection_limits_name_the_variable() {
        for name in [
            "AC_DIRECTORY_HEADER_TIMEOUT_SECS",
            "AC_DIRECTORY_IDLE_TIMEOUT_SECS",
            "AC_DIRECTORY_REQUEST_TIMEOUT_SECS",
            "AC_DIRECTORY_MAX_CONNECTIONS",
            "AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE",
        ] {
            for bad in ["0", "-1", "x", "", "1.5", "99999999999"] {
                let vars = [(name, bad)];
                let err = with(&vars).unwrap_err();
                assert!(err.contains(name), "{name}={bad}: {err}");
            }
        }
    }

    fn with(extra: &[(&'static str, &'static str)]) -> Result<Config, String> {
        let mut vars = vec![DB, KEYS, HOST, RELAYS];
        vars.extend_from_slice(extra);
        Config::from_lookup(lookup(&vars))
    }

    #[test]
    fn the_site_name_and_home_link_are_optional() {
        let c = with(&[]).unwrap();
        assert!(c.name.is_none() && c.home.is_none());
        let c = with(&[
            ("AC_DIRECTORY_NAME", "  Example directory "),
            (
                "AC_DIRECTORY_HOME",
                " https://example.org/about?x=1  Example  home ",
            ),
        ])
        .unwrap();
        assert_eq!(c.name.as_deref(), Some("Example directory"));
        assert_eq!(
            c.home,
            Some(HomeLink {
                url: "https://example.org/about?x=1".into(),
                label: "Example  home".into(),
            })
        );
        let name = "n".repeat(MAX_SITE_TEXT);
        assert_eq!(
            Config::from_lookup(lookup(&[
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_NAME", &name)
            ]))
            .unwrap()
            .name,
            Some(name.clone())
        );
        for ok in [
            "http://127.0.0.1:8080/ Local",
            "http://[::1]/ Local",
            "http://localhost:3000 Local",
            "https://example.org:8443/#top Example",
            "https://EXAMPLE.org Example",
        ] {
            assert!(HomeLink::parse(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn bad_site_names_are_startup_errors() {
        let long = "n".repeat(MAX_SITE_TEXT + 1);
        for (value, err) in [
            ("", "AC_DIRECTORY_NAME has an empty name"),
            ("   ", "AC_DIRECTORY_NAME has an empty name"),
            (
                "Example\u{7}directory",
                "AC_DIRECTORY_NAME: the name has a control character",
            ),
            (
                "Example\ndirectory",
                "AC_DIRECTORY_NAME: the name has a control character",
            ),
            (
                long.as_str(),
                "AC_DIRECTORY_NAME: the name is longer than 80 characters",
            ),
        ] {
            assert_eq!(
                Config::from_lookup(lookup(&[
                    DB,
                    KEYS,
                    HOST,
                    RELAYS,
                    ("AC_DIRECTORY_NAME", value)
                ]))
                .unwrap_err(),
                err,
                "{value:?}"
            );
        }
    }

    #[test]
    fn bad_home_links_are_startup_errors() {
        let long_label = format!("https://example.org {}", "n".repeat(MAX_SITE_TEXT + 1));
        for (value, err) in [
            (
                "",
                "AC_DIRECTORY_HOME needs a URL, whitespace, then a label",
            ),
            (
                "https://example.org",
                "AC_DIRECTORY_HOME needs a URL, whitespace, then a label",
            ),
            (
                "https://example.org   ",
                "AC_DIRECTORY_HOME needs a URL, whitespace, then a label",
            ),
            (
                "https://example.org Home\u{0}",
                "AC_DIRECTORY_HOME: the label has a control character",
            ),
            (
                long_label.as_str(),
                "AC_DIRECTORY_HOME: the label is longer than 80 characters",
            ),
            (
                "http://example.org Example",
                "AC_DIRECTORY_HOME: http:// is allowed for a loopback host only: http://example.org",
            ),
            (
                "http://10.0.0.1 Example",
                "AC_DIRECTORY_HOME: http:// is allowed for a loopback host only: http://10.0.0.1",
            ),
            (
                "example.org Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: example.org",
            ),
            (
                "/about Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: /about",
            ),
            (
                "javascript:alert(1) Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: javascript:alert(1)",
            ),
            (
                "https:// Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: https://",
            ),
            (
                "https://user@example.org Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: https://user@example.org",
            ),
            (
                "https://example.org/a\"b Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: https://example.org/a\"b",
            ),
            (
                "https://example.org/<x> Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: https://example.org/<x>",
            ),
            (
                "https://example.org/(x) Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: https://example.org/(x)",
            ),
            (
                "https://exämple.org Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: https://exämple.org",
            ),
            (
                "https://example.org:0 Example",
                "AC_DIRECTORY_HOME is not an absolute https:// URL: https://example.org:0",
            ),
        ] {
            assert_eq!(
                Config::from_lookup(lookup(&[
                    DB,
                    KEYS,
                    HOST,
                    RELAYS,
                    ("AC_DIRECTORY_HOME", value)
                ]))
                .unwrap_err(),
                err,
                "{value:?}"
            );
        }
    }

    #[test]
    fn the_notice_and_operator_links_are_optional() {
        let c = with(&[]).unwrap();
        assert!(c.notice.is_none() && c.links.is_empty());
        let notice = "n".repeat(MAX_NOTICE);
        let c = Config::from_lookup(lookup(&[
            DB,
            KEYS,
            HOST,
            RELAYS,
            ("AC_DIRECTORY_NOTICE", &format!("  {notice} ")),
            ("AC_DIRECTORY_TERMS", "https://example.org/terms"),
            ("AC_DIRECTORY_ABUSE", "mailto:abuse@example.org"),
        ]))
        .unwrap();
        assert_eq!(c.notice, Some(notice));
        assert_eq!(c.links.terms.as_deref(), Some("https://example.org/terms"));
        assert_eq!(c.links.abuse.as_deref(), Some("mailto:abuse@example.org"));
        let c = with(&[("AC_DIRECTORY_ABUSE", "https://example.org/abuse")]).unwrap();
        assert_eq!(c.links.abuse.as_deref(), Some("https://example.org/abuse"));
    }

    #[test]
    fn bad_notices_and_operator_links_are_startup_errors() {
        let long = "n".repeat(MAX_NOTICE + 1);
        for (var, value, err) in [
            (
                "AC_DIRECTORY_NOTICE",
                "",
                "AC_DIRECTORY_NOTICE has an empty notice",
            ),
            (
                "AC_DIRECTORY_NOTICE",
                "  ",
                "AC_DIRECTORY_NOTICE has an empty notice",
            ),
            (
                "AC_DIRECTORY_NOTICE",
                "Maintenance\ntonight",
                "AC_DIRECTORY_NOTICE: the notice has a control character",
            ),
            (
                "AC_DIRECTORY_NOTICE",
                "Maintenance\u{1b}[31m",
                "AC_DIRECTORY_NOTICE: the notice has a control character",
            ),
            (
                "AC_DIRECTORY_NOTICE",
                long.as_str(),
                "AC_DIRECTORY_NOTICE: the notice is longer than 200 characters",
            ),
            ("AC_DIRECTORY_TERMS", "", "AC_DIRECTORY_TERMS is empty"),
            (
                "AC_DIRECTORY_TERMS",
                "http://example.org/terms",
                "AC_DIRECTORY_TERMS: http:// is allowed for a loopback host only: \
http://example.org/terms",
            ),
            (
                "AC_DIRECTORY_TERMS",
                "https://example.org/terms)",
                "AC_DIRECTORY_TERMS is not an absolute https:// URL: https://example.org/terms)",
            ),
            (
                "AC_DIRECTORY_ABUSE",
                "mailto:abuse@example.org?bcc=x@example.org",
                "AC_DIRECTORY_ABUSE: a mailto: address takes no query or header fields (? or &): \
mailto:abuse@example.org?bcc=x@example.org",
            ),
            (
                "AC_DIRECTORY_ABUSE",
                "mailto:abuse@example.org\r\nBcc: x@example.org",
                "AC_DIRECTORY_ABUSE has a control character",
            ),
            (
                "AC_DIRECTORY_ABUSE",
                "mailto:abuse",
                "AC_DIRECTORY_ABUSE is not a valid mailto: address: mailto:abuse",
            ),
            (
                "AC_DIRECTORY_ABUSE",
                "abuse@example.org",
                "AC_DIRECTORY_ABUSE is not a mailto: address or an absolute https:// URL: \
abuse@example.org",
            ),
        ] {
            assert_eq!(
                Config::from_lookup(lookup(&[DB, KEYS, HOST, RELAYS, (var, value)])).unwrap_err(),
                err,
                "{var}={value:?}"
            );
        }
    }

    #[test]
    fn broad_proxy_blocks_need_an_explicit_flag() {
        let ok = |v: &str| {
            Config::from_lookup(lookup(&[
                DB,
                KEYS,
                HOST,
                RELAYS,
                ("AC_DIRECTORY_TRUSTED_PROXIES", v),
            ]))
            .is_ok()
        };
        assert!(ok("10.0.0.0/8"));
        assert!(ok("2001:db8::/32"));
        assert!(!ok("0.0.0.0/0"));
        let any = Config::from_lookup(lookup(&[
            DB,
            KEYS,
            HOST,
            RELAYS,
            ("AC_DIRECTORY_TRUSTED_PROXIES", "0.0.0.0/0"),
            ("AC_DIRECTORY_TRUST_ANY_PROXY", "1"),
        ]));
        assert!(any.is_ok());
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
