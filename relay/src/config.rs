//! Environment configuration.

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::HeaderName;

use crate::quota::{ACTIVITY_GRANULARITY, Cidr, ClientIp, Quotas};
use crate::store::{Limits, Window};

use agentconnect_core::operator::OperatorLinks;

/// Default listen address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8080";
/// Default database file.
pub const DEFAULT_DB: &str = "agentconnect-relay.db";
/// The longest idle period `AC_RELAY_GROUP_IDLE_DAYS` takes (100 years).
pub const MAX_IDLE_DAYS: u64 = 36_500;

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
    /// `AC_RELAY_TERMS` and `AC_RELAY_ABUSE`: the operator's terms page and
    /// abuse contact, shown in the invite landing page's footer.
    pub links: OperatorLinks,
    /// The abuse limits (`AC_RELAY_REST_*`, `AC_RELAY_REPLAY_*`,
    /// `AC_RELAY_*INVITES*`, `AC_RELAY_*GROUPS*`, `AC_RELAY_GROUP_IDLE_DAYS`,
    /// `AC_RELAY_CLIENT_IP_HEADER`, `AC_RELAY_TRUSTED_PROXIES`,
    /// `AC_RELAY_PROXY_HOPS`; relay/README.md).
    pub quotas: Quotas,
}

/// A positive integer from `var`, or `default` when unset.
fn count(
    get: &impl Fn(&str) -> Option<String>,
    var: &str,
    default: usize,
) -> Result<usize, String> {
    match get(var).filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| format!("{var} is not a positive integer: {v}")),
    }
}

fn quotas(get: &impl Fn(&str) -> Option<String>) -> Result<Quotas, String> {
    let d = Quotas::default();
    let per = |var: &str, w: Window| -> Result<Window, String> {
        Ok(Window {
            max: count(get, var, w.max)?,
            per: w.per,
        })
    };
    let idle_days = count(
        get,
        "AC_RELAY_GROUP_IDLE_DAYS",
        usize::try_from(d.group_idle.as_secs() / 86_400).unwrap_or(usize::MAX),
    )?;
    // At least the message TTL plus the margin the sweep adds for the
    // coarse activity time, so nothing is still queued for a deleted group.
    let min_idle = Limits::default().message_ttl + ACTIVITY_GRANULARITY;
    let idle = u64::try_from(idle_days)
        .ok()
        .filter(|d| *d <= MAX_IDLE_DAYS)
        .map(|d| Duration::from_hours(d * 24))
        .filter(|idle| *idle >= min_idle)
        .ok_or_else(|| {
            format!(
                "AC_RELAY_GROUP_IDLE_DAYS must be 8 to {MAX_IDLE_DAYS} (more than the 7-day \
                 message TTL): {idle_days}"
            )
        })?;
    let hops = count(get, "AC_RELAY_PROXY_HOPS", d.client_ip.hops)?;
    let header = match get("AC_RELAY_CLIENT_IP_HEADER").filter(|v| !v.is_empty()) {
        None => None,
        Some(v) => Some(
            HeaderName::try_from(v.trim().to_ascii_lowercase())
                .map_err(|_| format!("AC_RELAY_CLIENT_IP_HEADER is not a header name: {v}"))?,
        ),
    };
    let trusted_proxies = get("AC_RELAY_TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|c| Cidr::parse(c).map_err(|e| format!("AC_RELAY_TRUSTED_PROXIES: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    if trusted_proxies.iter().any(Cidr::is_broad) {
        return Err(
            "AC_RELAY_TRUSTED_PROXIES has a block broader than /8 (IPv4) or /32 (IPv6)".to_owned(),
        );
    }
    if header.is_some() == trusted_proxies.is_empty() {
        return Err(
            "AC_RELAY_CLIENT_IP_HEADER and AC_RELAY_TRUSTED_PROXIES must be set together"
                .to_owned(),
        );
    }
    if get("AC_RELAY_PROXY_HOPS").is_some_and(|v| !v.is_empty()) && header.is_none() {
        return Err("AC_RELAY_PROXY_HOPS needs AC_RELAY_CLIENT_IP_HEADER".to_owned());
    }
    Ok(Quotas {
        rest_junk_per_address: per(
            "AC_RELAY_REST_JUNK_PER_ADDRESS_PER_MIN",
            d.rest_junk_per_address,
        )?,
        rest_per_address: per("AC_RELAY_REST_PER_ADDRESS_PER_MIN", d.rest_per_address)?,
        rest_per_mailbox: per("AC_RELAY_REST_PER_MAILBOX_PER_MIN", d.rest_per_mailbox)?,
        replay_per_mailbox: count(get, "AC_RELAY_REPLAY_PER_MAILBOX", d.replay_per_mailbox)?,
        replay_max_entries: count(get, "AC_RELAY_REPLAY_MAX_ENTRIES", d.replay_max_entries)?,
        open_invites_per_mailbox: count(
            get,
            "AC_RELAY_OPEN_INVITES_PER_MAILBOX",
            d.open_invites_per_mailbox,
        )?,
        invites_per_address: count(get, "AC_RELAY_INVITES_PER_ADDRESS", d.invites_per_address)?,
        max_invites: count(get, "AC_RELAY_MAX_INVITES", d.max_invites)?,
        groups_per_mailbox: per("AC_RELAY_GROUPS_PER_MAILBOX_PER_DAY", d.groups_per_mailbox)?,
        groups_per_address: count(get, "AC_RELAY_GROUPS_PER_ADDRESS", d.groups_per_address)?,
        max_groups: count(get, "AC_RELAY_MAX_GROUPS", d.max_groups)?,
        group_idle: idle,
        client_ip: ClientIp {
            header,
            trusted_proxies,
            hops,
        },
    })
}

impl Config {
    /// Read the configuration through `get` (normally the process
    /// environment). `AC_RELAY_HOST` defaults to the listen address.
    ///
    /// # Errors
    ///
    /// Returns a message if `AC_RELAY_ADDR` is not a socket address,
    /// `AC_RELAY_HOST` is not a valid host, `AC_RELAY_TERMS` or
    /// `AC_RELAY_ABUSE` is set but invalid, or a limit is not a positive
    /// integer.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let addr_text = get("AC_RELAY_ADDR").unwrap_or_else(|| DEFAULT_ADDR.to_owned());
        let addr: SocketAddr = addr_text
            .parse()
            .map_err(|_| format!("AC_RELAY_ADDR is not a socket address: {addr_text}"))?;
        let host = get("AC_RELAY_HOST")
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| addr_text.clone());
        // The same canonical form the daemons sign (SPEC §8.1.1).
        let host = agentconnect_core::identity::canonical_relay_host(&host)
            .map_err(|_| format!("AC_RELAY_HOST is not a valid relay host: {host}"))?;
        let links = OperatorLinks::from_lookup("AC_RELAY", &get)?;
        Ok(Self {
            addr,
            db: get("AC_RELAY_DB").unwrap_or_else(|| DEFAULT_DB.to_owned()),
            host,
            links,
            quotas: quotas(&get)?,
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
        assert_eq!(c.quotas, Quotas::default());
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
    fn every_limit_is_configurable() {
        let c = Config::from_lookup(lookup(&[
            ("AC_RELAY_REST_JUNK_PER_ADDRESS_PER_MIN", "8"),
            ("AC_RELAY_REST_PER_ADDRESS_PER_MIN", "7"),
            ("AC_RELAY_REPLAY_MAX_ENTRIES", "11"),
            ("AC_RELAY_INVITES_PER_ADDRESS", "12"),
            ("AC_RELAY_MAX_INVITES", "13"),
            ("AC_RELAY_GROUPS_PER_ADDRESS", "14"),
            ("AC_RELAY_MAX_GROUPS", "15"),
            ("AC_RELAY_PROXY_HOPS", "2"),
            ("AC_RELAY_REST_PER_MAILBOX_PER_MIN", "6"),
            ("AC_RELAY_REPLAY_PER_MAILBOX", "5"),
            ("AC_RELAY_OPEN_INVITES_PER_MAILBOX", "4"),
            ("AC_RELAY_GROUPS_PER_MAILBOX_PER_DAY", "3"),
            ("AC_RELAY_GROUP_IDLE_DAYS", "9"),
            ("AC_RELAY_CLIENT_IP_HEADER", "X-Forwarded-For"),
            ("AC_RELAY_TRUSTED_PROXIES", "127.0.0.1/32, ::1"),
        ]))
        .unwrap();
        let q = c.quotas;
        assert_eq!(q.rest_junk_per_address.max, 8);
        assert_eq!(q.rest_per_address.max, 7);
        assert_eq!(q.replay_max_entries, 11);
        assert_eq!(q.invites_per_address, 12);
        assert_eq!(q.max_invites, 13);
        assert_eq!(q.groups_per_address, 14);
        assert_eq!(q.max_groups, 15);
        assert_eq!(q.client_ip.hops, 2);
        assert_eq!(q.rest_per_address.per, Duration::from_mins(1));
        assert_eq!(q.rest_per_mailbox.max, 6);
        assert_eq!(q.replay_per_mailbox, 5);
        assert_eq!(q.open_invites_per_mailbox, 4);
        assert_eq!(q.groups_per_mailbox.max, 3);
        assert_eq!(q.groups_per_mailbox.per, Duration::from_hours(24));
        assert_eq!(q.group_idle, Duration::from_hours(9 * 24));
        assert_eq!(q.client_ip.header.unwrap().as_str(), "x-forwarded-for");
        assert_eq!(q.client_ip.trusted_proxies.len(), 2);
    }

    #[test]
    fn bad_limits_are_refused() {
        for (var, value) in [
            ("AC_RELAY_REST_PER_ADDRESS_PER_MIN", "0"),
            ("AC_RELAY_REST_PER_MAILBOX_PER_MIN", "-1"),
            ("AC_RELAY_REPLAY_PER_MAILBOX", "many"),
            ("AC_RELAY_OPEN_INVITES_PER_MAILBOX", "1.5"),
            ("AC_RELAY_GROUPS_PER_MAILBOX_PER_DAY", "0"),
            // Not longer than the message TTL plus the sweep's margin: a
            // member could come back to queued messages for a group that is
            // gone.
            ("AC_RELAY_GROUP_IDLE_DAYS", "7"),
            // Refused, not a panic.
            ("AC_RELAY_GROUP_IDLE_DAYS", "300000000000000"),
            ("AC_RELAY_GROUP_IDLE_DAYS", "36501"),
            ("AC_RELAY_PROXY_HOPS", "1"),
            ("AC_RELAY_MAX_GROUPS", "0"),
            ("AC_RELAY_TRUSTED_PROXIES", "10.0.0.0/8"),
            ("AC_RELAY_CLIENT_IP_HEADER", "x-forwarded-for"),
        ] {
            assert!(
                Config::from_lookup(lookup(&[(var, value)])).is_err(),
                "{var}={value}"
            );
        }
        for proxies in ["0.0.0.0/0", "nope"] {
            let pairs = [
                ("AC_RELAY_CLIENT_IP_HEADER", "x-forwarded-for"),
                ("AC_RELAY_TRUSTED_PROXIES", proxies),
            ];
            assert!(Config::from_lookup(lookup(&pairs)).is_err(), "{proxies}");
        }
        let pairs = [
            ("AC_RELAY_CLIENT_IP_HEADER", "bad header"),
            ("AC_RELAY_TRUSTED_PROXIES", "127.0.0.1"),
        ];
        assert!(Config::from_lookup(lookup(&pairs)).is_err());
        let c = Config::from_lookup(lookup(&[("AC_RELAY_GROUP_IDLE_DAYS", "8")])).unwrap();
        assert_eq!(c.quotas.group_idle, Duration::from_hours(8 * 24));
        let c = Config::from_lookup(lookup(&[("AC_RELAY_GROUP_IDLE_DAYS", "36500")])).unwrap();
        assert_eq!(c.quotas.group_idle, Duration::from_hours(36_500 * 24));
    }

    #[test]
    fn rejects_a_bad_address_and_ignores_an_empty_host() {
        assert!(Config::from_lookup(lookup(&[("AC_RELAY_ADDR", "nope")])).is_err());
        let c = Config::from_lookup(lookup(&[("AC_RELAY_HOST", "")])).unwrap();
        assert_eq!(c.host, DEFAULT_ADDR);
    }

    #[test]
    fn operator_links_are_optional() {
        let c = Config::from_lookup(lookup(&[])).unwrap();
        assert!(c.links.is_empty());
        let c = Config::from_lookup(lookup(&[
            ("AC_RELAY_TERMS", " https://example.org/terms "),
            ("AC_RELAY_ABUSE", "mailto:abuse@example.org"),
        ]))
        .unwrap();
        assert_eq!(c.links.terms.as_deref(), Some("https://example.org/terms"));
        assert_eq!(c.links.abuse.as_deref(), Some("mailto:abuse@example.org"));
        let c = Config::from_lookup(lookup(&[("AC_RELAY_ABUSE", "https://example.org/abuse")]))
            .unwrap();
        assert_eq!(c.links.abuse.as_deref(), Some("https://example.org/abuse"));
    }

    #[test]
    fn bad_operator_links_are_startup_errors() {
        for (var, value, err) in [
            ("AC_RELAY_TERMS", "", "AC_RELAY_TERMS is empty"),
            (
                "AC_RELAY_TERMS",
                "https://example.org/\u{7}",
                "AC_RELAY_TERMS has a control character",
            ),
            (
                "AC_RELAY_TERMS",
                "http://example.org/terms",
                "AC_RELAY_TERMS: http:// is allowed for a loopback host only: \
http://example.org/terms",
            ),
            (
                "AC_RELAY_TERMS",
                "https://example.org/(terms)",
                "AC_RELAY_TERMS is not an absolute https:// URL: https://example.org/(terms)",
            ),
            (
                "AC_RELAY_ABUSE",
                "mailto:abuse@example.org?subject=x",
                "AC_RELAY_ABUSE: a mailto: address takes no query or header fields (? or &): \
mailto:abuse@example.org?subject=x",
            ),
            (
                "AC_RELAY_ABUSE",
                "mailto:abuse@example.org&cc=x@example.org",
                "AC_RELAY_ABUSE: a mailto: address takes no query or header fields (? or &): \
mailto:abuse@example.org&cc=x@example.org",
            ),
            (
                "AC_RELAY_ABUSE",
                "mailto:abuse@example.org\r\nBcc: x@example.org",
                "AC_RELAY_ABUSE has a control character",
            ),
            (
                "AC_RELAY_ABUSE",
                "mailto:a@example.org,b@example.org",
                "AC_RELAY_ABUSE: a mailto: link takes a single address: \
mailto:a@example.org,b@example.org",
            ),
            (
                "AC_RELAY_ABUSE",
                "mailto:abuse",
                "AC_RELAY_ABUSE is not a valid mailto: address: mailto:abuse",
            ),
            (
                "AC_RELAY_ABUSE",
                "abuse@example.org",
                "AC_RELAY_ABUSE is not a mailto: address or an absolute https:// URL: \
abuse@example.org",
            ),
        ] {
            assert_eq!(
                Config::from_lookup(lookup(&[(var, value)])).unwrap_err(),
                err,
                "{var}={value:?}"
            );
        }
    }

    #[test]
    fn from_env_reads_the_process_environment() {
        // Only checks that it does not fail with whatever the runner exports.
        let _ = Config::from_env();
    }
}
