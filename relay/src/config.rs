//! Environment configuration.

use std::net::SocketAddr;

/// Default listen address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8080";
/// Default database file.
pub const DEFAULT_DB: &str = "agentconnect-relay.db";

/// Relay configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `AC_RELAY_ADDR`: listen address.
    pub addr: SocketAddr,
    /// `AC_RELAY_DB`: SQLite file path or `sqlite:` URL.
    pub db: String,
    /// `AC_RELAY_HOST`: the host string clients sign into their
    /// authentication (the relay's public host name, with port if not 443).
    pub host: String,
}

impl Config {
    /// Read the configuration through `get` (normally the process
    /// environment). `AC_RELAY_HOST` defaults to the listen address.
    ///
    /// # Errors
    ///
    /// Returns a message if `AC_RELAY_ADDR` is not a socket address.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let addr_text = get("AC_RELAY_ADDR").unwrap_or_else(|| DEFAULT_ADDR.to_owned());
        let addr: SocketAddr = addr_text
            .parse()
            .map_err(|_| format!("AC_RELAY_ADDR is not a socket address: {addr_text}"))?;
        let host = get("AC_RELAY_HOST")
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| addr_text.clone());
        Ok(Self {
            addr,
            db: get("AC_RELAY_DB").unwrap_or_else(|| DEFAULT_DB.to_owned()),
            host,
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

    #[test]
    fn defaults() {
        let c = Config::from_lookup(lookup(&[])).unwrap();
        assert_eq!(c.addr.to_string(), DEFAULT_ADDR);
        assert_eq!(c.db, DEFAULT_DB);
        assert_eq!(c.host, DEFAULT_ADDR);
    }

    #[test]
    fn overrides() {
        let c = Config::from_lookup(lookup(&[
            ("AC_RELAY_ADDR", "0.0.0.0:9000"),
            ("AC_RELAY_DB", "sqlite::memory:"),
            ("AC_RELAY_HOST", "relay.example.org"),
        ]))
        .unwrap();
        assert_eq!(c.addr.port(), 9000);
        assert_eq!(c.db, "sqlite::memory:");
        assert_eq!(c.host, "relay.example.org");
    }

    #[test]
    fn rejects_a_bad_address_and_ignores_an_empty_host() {
        assert!(Config::from_lookup(lookup(&[("AC_RELAY_ADDR", "nope")])).is_err());
        let c = Config::from_lookup(lookup(&[("AC_RELAY_HOST", "")])).unwrap();
        assert_eq!(c.host, DEFAULT_ADDR);
    }

    #[test]
    fn from_env_reads_the_process_environment() {
        // Only checks that it does not fail with whatever the runner exports.
        let _ = Config::from_env();
    }
}
