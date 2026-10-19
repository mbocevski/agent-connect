//! Links an operator shows on the relay's and the directory's pages: a terms
//! page and an abuse contact (`AC_RELAY_TERMS`, `AC_RELAY_ABUSE`,
//! `AC_DIRECTORY_TERMS`, `AC_DIRECTORY_ABUSE`), and the URL rule the
//! directory's home link (`AC_DIRECTORY_HOME`) shares with them.
//!
//! The values are checked once, at start, so a page never holds a link that
//! could carry markup, end a Markdown link or add mail headers: an absolute
//! `https://` URL (`http://` for a loopback host only) of URL characters
//! without parentheses, or a `mailto:` link to one plain address.

use std::net::IpAddr;

use crate::identity::canonical_relay_host;

/// The label of the terms link.
pub const TERMS_LABEL: &str = "Terms";
/// The label of the abuse contact link.
pub const ABUSE_LABEL: &str = "Report abuse";

/// Characters a URL may hold after its scheme: RFC 3986 unreserved and
/// reserved characters and `%`, except the parentheses (they would end a
/// Markdown link).
fn url_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'*+,;=%".contains(c)
}

/// Whether a URL authority names a loopback host: `localhost` or a loopback
/// address literal.
fn is_loopback(host: &str) -> bool {
    let name = host
        .strip_prefix('[')
        .and_then(|h| h.split_once(']'))
        .map_or_else(|| host.split(':').next().unwrap_or_default(), |(h, _)| h);
    name.eq_ignore_ascii_case("localhost")
        || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Check that `url` is an absolute `https://` URL (`http://` for a loopback
/// host only) of URL characters without parentheses, whose authority is a
/// host and optional port with no userinfo. `var` names the setting in the
/// error.
///
/// # Errors
///
/// A message naming `var` and the URL.
pub fn web_url(var: &str, url: &str) -> Result<(), String> {
    let bad = || format!("{var} is not an absolute https:// URL: {url}");
    let (rest, https) = if let Some(r) = url.strip_prefix("https://") {
        (r, true)
    } else if let Some(r) = url.strip_prefix("http://") {
        (r, false)
    } else {
        return Err(bad());
    };
    if !rest.chars().all(url_char) {
        return Err(bad());
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    canonical_relay_host(host).map_err(|_| bad())?;
    if !https && !is_loopback(host) {
        return Err(format!(
            "{var}: http:// is allowed for a loopback host only: {url}"
        ));
    }
    Ok(())
}

/// Characters of a mailto local part that RFC 6068 lets stand unencoded,
/// less the delimiters `( ) , ; :` and with no `%`: so no percent-encoded
/// byte can turn into a header or a second address.
fn local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~!$'*+".contains(c)
}

fn dns_name(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    domain.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        && labels
            .last()
            .is_some_and(|tld| !tld.chars().all(|c| c.is_ascii_digit()))
}

/// Check that `value` is `mailto:` and one plain address: no query, so no
/// header fields (`?`, `&`), no second address and no percent-encoding.
/// `var` names the setting in the error.
///
/// # Errors
///
/// A message naming `var` and the value.
pub fn mailto(var: &str, value: &str) -> Result<(), String> {
    let bad = || format!("{var} is not a valid mailto: address: {value}");
    let addr = value.strip_prefix("mailto:").ok_or_else(bad)?;
    if addr.contains(['?', '&']) {
        return Err(format!(
            "{var}: a mailto: address takes no query or header fields (? or &): {value}"
        ));
    }
    if addr.contains([',', ';']) || addr.matches('@').count() > 1 {
        return Err(format!(
            "{var}: a mailto: link takes a single address: {value}"
        ));
    }
    let (local, domain) = addr.split_once('@').ok_or_else(bad)?;
    let local_ok = (1..=64).contains(&local.len())
        && local.chars().all(local_char)
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..");
    if !local_ok || !dns_name(domain) {
        return Err(bad());
    }
    Ok(())
}

/// The operator's terms page and abuse contact, each optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorLinks {
    /// `<PREFIX>_TERMS`: the terms page, an absolute `https://` URL.
    pub terms: Option<String>,
    /// `<PREFIX>_ABUSE`: where to report abuse, a `mailto:` address or an
    /// absolute `https://` URL.
    pub abuse: Option<String>,
}

/// A set value, trimmed: not empty and without control characters.
fn set_value(var: &str, value: &str) -> Result<String, String> {
    let v = value.trim();
    if v.is_empty() {
        return Err(format!("{var} is empty"));
    }
    if v.chars().any(char::is_control) {
        return Err(format!("{var} has a control character"));
    }
    Ok(v.to_owned())
}

impl OperatorLinks {
    /// Read `<prefix>_TERMS` and `<prefix>_ABUSE` through `get`.
    ///
    /// # Errors
    ///
    /// A message naming the variable that is empty or invalid.
    pub fn from_lookup(prefix: &str, get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let terms_var = format!("{prefix}_TERMS");
        let abuse_var = format!("{prefix}_ABUSE");
        let terms = get(&terms_var)
            .map(|v| {
                let v = set_value(&terms_var, &v)?;
                web_url(&terms_var, &v).map(|()| v)
            })
            .transpose()?;
        let abuse = get(&abuse_var)
            .map(|v| {
                let v = set_value(&abuse_var, &v)?;
                if v.starts_with("mailto:") {
                    mailto(&abuse_var, &v)?;
                } else if v.starts_with("https://") || v.starts_with("http://") {
                    web_url(&abuse_var, &v)?;
                } else {
                    return Err(format!(
                        "{abuse_var} is not a mailto: address or an absolute https:// URL: {v}"
                    ));
                }
                Ok(v)
            })
            .transpose()?;
        Ok(Self { terms, abuse })
    }

    /// Whether neither link is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.terms.is_none() && self.abuse.is_none()
    }

    /// The links that are set, as (label, URL): the terms, then the abuse
    /// contact.
    pub fn labelled(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [(TERMS_LABEL, &self.terms), (ABUSE_LABEL, &self.abuse)]
            .into_iter()
            .filter_map(|(label, url)| url.as_deref().map(|u| (label, u)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links(pairs: &[(&str, &str)]) -> Result<OperatorLinks, String> {
        OperatorLinks::from_lookup("AC_X", |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        })
    }

    #[test]
    fn unset_is_empty() {
        let l = links(&[]).unwrap();
        assert!(l.is_empty());
        assert_eq!(l, OperatorLinks::default());
        assert_eq!(l.labelled().count(), 0);
    }

    #[test]
    fn valid_links_are_kept_trimmed_and_labelled_in_order() {
        let l = links(&[
            ("AC_X_TERMS", "  https://example.org/terms?v=2#top "),
            ("AC_X_ABUSE", "mailto:abuse@example.org"),
        ])
        .unwrap();
        assert_eq!(
            l.terms.as_deref(),
            Some("https://example.org/terms?v=2#top")
        );
        assert_eq!(l.abuse.as_deref(), Some("mailto:abuse@example.org"));
        assert!(!l.is_empty());
        assert_eq!(
            l.labelled().collect::<Vec<_>>(),
            [
                ("Terms", "https://example.org/terms?v=2#top"),
                ("Report abuse", "mailto:abuse@example.org")
            ]
        );
        let l = links(&[("AC_X_ABUSE", "https://example.org/abuse")]).unwrap();
        assert_eq!(
            l.labelled().collect::<Vec<_>>(),
            [("Report abuse", "https://example.org/abuse")]
        );
        for ok in [
            "mailto:abuse+relay@mail.example.org",
            "mailto:o'brien@example.org",
            "mailto:A.B-c_d~e@Example-1.org",
            "http://127.0.0.1:8080/abuse",
            "http://localhost/abuse",
            "http://[::1]:8080/abuse",
        ] {
            assert!(links(&[("AC_X_ABUSE", ok)]).is_ok(), "{ok}");
        }
    }

    #[test]
    fn web_urls_follow_the_home_link_rule() {
        for ok in [
            "http://127.0.0.1:8080/",
            "http://[::1]/",
            "http://localhost:3000",
            "https://example.org:8443/#top",
            "https://EXAMPLE.org",
            "https://example.org/a?b=c&d=%20",
        ] {
            assert_eq!(web_url("V", ok), Ok(()), "{ok}");
        }
        for (url, err) in [
            (
                "http://example.org",
                "V: http:// is allowed for a loopback host only: http://example.org",
            ),
            (
                "http://10.0.0.1",
                "V: http:// is allowed for a loopback host only: http://10.0.0.1",
            ),
            (
                "example.org",
                "V is not an absolute https:// URL: example.org",
            ),
            ("/terms", "V is not an absolute https:// URL: /terms"),
            (
                "javascript:alert(1)",
                "V is not an absolute https:// URL: javascript:alert(1)",
            ),
            ("https://", "V is not an absolute https:// URL: https://"),
            (
                "https://user@example.org",
                "V is not an absolute https:// URL: https://user@example.org",
            ),
            (
                "https://example.org/(x)",
                "V is not an absolute https:// URL: https://example.org/(x)",
            ),
            (
                "https://example.org/a)b",
                "V is not an absolute https:// URL: https://example.org/a)b",
            ),
            (
                "https://example.org/<x>",
                "V is not an absolute https:// URL: https://example.org/<x>",
            ),
            (
                "https://example.org/a\"b",
                "V is not an absolute https:// URL: https://example.org/a\"b",
            ),
            (
                "https://example.org/a b",
                "V is not an absolute https:// URL: https://example.org/a b",
            ),
            (
                "https://exämple.org",
                "V is not an absolute https:// URL: https://exämple.org",
            ),
            (
                "https://example.org:0",
                "V is not an absolute https:// URL: https://example.org:0",
            ),
        ] {
            assert_eq!(web_url("V", url), Err(err.to_owned()), "{url}");
        }
    }

    #[test]
    fn bad_terms_are_errors() {
        for (value, err) in [
            ("", "AC_X_TERMS is empty"),
            ("   ", "AC_X_TERMS is empty"),
            (
                "https://example.org/\u{7}",
                "AC_X_TERMS has a control character",
            ),
            (
                "https://example.org/a\nb",
                "AC_X_TERMS has a control character",
            ),
            (
                "http://example.org/terms",
                "AC_X_TERMS: http:// is allowed for a loopback host only: http://example.org/terms",
            ),
            (
                "https://example.org/terms(1)",
                "AC_X_TERMS is not an absolute https:// URL: https://example.org/terms(1)",
            ),
            (
                "mailto:legal@example.org",
                "AC_X_TERMS is not an absolute https:// URL: mailto:legal@example.org",
            ),
        ] {
            assert_eq!(
                links(&[("AC_X_TERMS", value)]).unwrap_err(),
                err,
                "{value:?}"
            );
        }
    }

    #[test]
    fn bad_abuse_contacts_are_errors() {
        let long_local = format!("mailto:{}@example.org", "a".repeat(65));
        let long_label = format!("mailto:a@{}.org", "a".repeat(64));
        let not_mailto = |v: &str| format!("AC_X_ABUSE is not a valid mailto: address: {v}");
        let query = |v: &str| {
            format!("AC_X_ABUSE: a mailto: address takes no query or header fields (? or &): {v}")
        };
        let single = |v: &str| format!("AC_X_ABUSE: a mailto: link takes a single address: {v}");
        let mut cases = vec![
            (String::new(), "AC_X_ABUSE is empty".to_owned()),
            (
                "mailto:abuse@example.org\r\nBcc: x@example.org".to_owned(),
                "AC_X_ABUSE has a control character".to_owned(),
            ),
            (
                "mailto:abuse@example.org\nCc: x@example.org".to_owned(),
                "AC_X_ABUSE has a control character".to_owned(),
            ),
            (
                "abuse@example.org".to_owned(),
                "AC_X_ABUSE is not a mailto: address or an absolute https:// URL: \
abuse@example.org"
                    .to_owned(),
            ),
            (
                "MAILTO:abuse@example.org".to_owned(),
                "AC_X_ABUSE is not a mailto: address or an absolute https:// URL: \
MAILTO:abuse@example.org"
                    .to_owned(),
            ),
            (
                "ftp://example.org/abuse".to_owned(),
                "AC_X_ABUSE is not a mailto: address or an absolute https:// URL: \
ftp://example.org/abuse"
                    .to_owned(),
            ),
            (
                "http://example.org/abuse".to_owned(),
                "AC_X_ABUSE: http:// is allowed for a loopback host only: \
http://example.org/abuse"
                    .to_owned(),
            ),
            (
                "https://example.org/abuse(1)".to_owned(),
                "AC_X_ABUSE is not an absolute https:// URL: https://example.org/abuse(1)"
                    .to_owned(),
            ),
        ];
        for v in [
            "mailto:abuse@example.org?subject=x",
            "mailto:abuse@example.org?bcc=x@example.org",
            "mailto:abuse@example.org&cc=x@example.org",
            "mailto:?to=abuse@example.org",
        ] {
            cases.push((v.to_owned(), query(v)));
        }
        for v in [
            "mailto:a@example.org,b@example.org",
            "mailto:a@example.org;b@example.org",
            "mailto:a@b@example.org",
        ] {
            cases.push((v.to_owned(), single(v)));
        }
        for v in [
            "mailto:",
            "mailto:abuse",
            "mailto:@example.org",
            "mailto:abuse@",
            "mailto:abuse@localhost",
            "mailto:abuse@example.123",
            "mailto:abuse@[127.0.0.1]",
            "mailto:abuse@-example.org",
            "mailto:abuse@example-.org",
            "mailto:abuse@example..org",
            "mailto:abuse%0ACc:x@example.org",
            "mailto:abuse%40x@example.org",
            "mailto:ab use@example.org",
            "mailto:abuse(x)@example.org",
            "mailto:<abuse@example.org>",
            "mailto:\"abuse\"@example.org",
            "mailto:.abuse@example.org",
            "mailto:abuse.@example.org",
            "mailto:ab..use@example.org",
            "mailto:abuse#x@example.org",
            "mailto:abüse@example.org",
            "mailto:abuse@exämple.org",
            long_local.as_str(),
            long_label.as_str(),
        ] {
            cases.push((v.to_owned(), not_mailto(v)));
        }
        for (value, err) in cases {
            assert_eq!(
                links(&[("AC_X_ABUSE", &value)]).unwrap_err(),
                err,
                "{value:?}"
            );
        }
        assert!(mailto("V", "https://example.org").is_err());
        let long_domain = format!("mailto:a@{}.org", vec!["a".repeat(60); 5].join("."));
        assert!(mailto("V", &long_domain).is_err());
    }
}
