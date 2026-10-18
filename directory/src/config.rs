//! Environment configuration.

use std::net::SocketAddr;

use agentconnect_core::identity::canonical_relay_host;

/// Default listen address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8090";
/// The default directory host.
pub const DEFAULT_HOST: &str = "agents.yggdrasill.network";
/// The default relay, Ratatoskr.
pub const DEFAULT_RELAY: &str = "connect.yggdrasill.network";
/// `AC_DIRECTORY_DB` value for a throwaway in-memory store.
pub const MEMORY_DB: &str = "memory:";

/// Directory configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `AC_DIRECTORY_ADDR`: listen address.
    pub addr: SocketAddr,
    /// `AC_DIRECTORY_DB`: a `postgres://` URL, or `memory:`.
    pub db: String,
    /// `AC_DIRECTORY_HOST`: this directory's public host, in the SPEC
    /// §8.1.1 canonical form. Listings, tokens and withdrawals must name it.
    pub host: String,
    /// `AC_DIRECTORY_RELAYS`: comma-separated relay hosts listings may point
    /// at. The first is shown on the site.
    pub relays: Vec<String>,
    /// `AC_DIRECTORY_TOKEN_KEYS`: comma-separated operator token public keys
    /// (`DK.pub`, base64url): one, or two while rotating. Required.
    pub token_keys: Vec<String>,
    /// `AC_DIRECTORY_CLIENT_IP_HEADER`: a header set by a trusted reverse
    /// proxy that carries the client address (its last value is used), for
    /// rate limiting. Unset: the TCP peer address.
    pub client_ip_header: Option<String>,
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
            .unwrap_or_else(|| DEFAULT_HOST.to_owned());
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
        Ok(Self {
            addr,
            db,
            host,
            relays,
            token_keys,
            client_ip_header,
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

    #[test]
    fn defaults() {
        let c = Config::from_lookup(lookup(&[DB, KEYS])).unwrap();
        assert_eq!(c.addr.to_string(), DEFAULT_ADDR);
        assert_eq!(c.host, DEFAULT_HOST);
        assert_eq!(c.relays, [DEFAULT_RELAY]);
        assert_eq!(c.token_keys, ["k"]);
        assert!(c.client_ip_header.is_none());
    }

    #[test]
    fn overrides() {
        let c = Config::from_lookup(lookup(&[
            ("AC_DIRECTORY_ADDR", "0.0.0.0:9000"),
            ("AC_DIRECTORY_DB", "postgres://u@db/heimdall"),
            ("AC_DIRECTORY_HOST", "Agents.Example.org"),
            (
                "AC_DIRECTORY_RELAYS",
                "relay.example.org, other.example.org:8443",
            ),
            ("AC_DIRECTORY_TOKEN_KEYS", "a,b"),
            ("AC_DIRECTORY_CLIENT_IP_HEADER", "X-Forwarded-For"),
        ]))
        .unwrap();
        assert_eq!(c.addr.port(), 9000);
        assert_eq!(c.host, "agents.example.org");
        assert_eq!(c.relays, ["relay.example.org", "other.example.org:8443"]);
        assert_eq!(c.token_keys, ["a", "b"]);
        assert_eq!(c.client_ip_header.as_deref(), Some("x-forwarded-for"));
    }

    #[test]
    fn rejects_bad_values() {
        for bad in [
            vec![KEYS],
            vec![DB],
            vec![KEYS, ("AC_DIRECTORY_DB", "sqlite://x")],
            vec![DB, KEYS, ("AC_DIRECTORY_ADDR", "nope")],
            vec![DB, KEYS, ("AC_DIRECTORY_HOST", "a b")],
            vec![DB, KEYS, ("AC_DIRECTORY_RELAYS", "x/y")],
            vec![DB, ("AC_DIRECTORY_TOKEN_KEYS", "a,b,c")],
            vec![DB, KEYS, ("AC_DIRECTORY_CLIENT_IP_HEADER", "bad header")],
        ] {
            assert!(Config::from_lookup(lookup(&bad)).is_err(), "{bad:?}");
        }
        let _ = Config::from_env();
    }
}
