//! Counters exposed on `/metrics`. Labels are route templates, status codes
//! and fixed outcome names only: never a name, identity, domain, query or
//! address (ADR-006 Decision 4).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;

/// The directory's counters.
#[derive(Debug, Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<(&'static str, u16), u64>>,
    events: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
}

/// The route templates requests are counted under.
pub const ROUTES: &[&str] = &[
    "/",
    "/index.md",
    "/search",
    "/a/{name}",
    "/llms.txt",
    "/static/directory.css",
    "/.well-known/agentconnect-directory.json",
    "/v0/listings",
    "/v0/withdrawals",
    "/v0/revocations",
    "/mcp",
    "/healthz",
    "/metrics",
];

/// The template of an unmatched request.
pub const UNMATCHED: &str = "unmatched";

/// Map a matched path to one of [`ROUTES`] (or [`UNMATCHED`]), so a label can
/// never carry request data.
#[must_use]
pub fn template(matched: Option<&str>) -> &'static str {
    matched
        .and_then(|m| ROUTES.iter().copied().find(|r| *r == m))
        .unwrap_or(UNMATCHED)
}

impl Metrics {
    /// Count a finished request.
    pub fn request(&self, route: &'static str, status: u16) {
        *self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry((route, status))
            .or_default() += 1;
    }

    /// Count an event, e.g. `("publish", "published")`.
    pub fn event(&self, what: &'static str, outcome: &'static str) {
        *self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry((what, outcome))
            .or_default() += 1;
    }

    /// Prometheus text exposition.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from(
            "# HELP agentconnect_directory_requests_total HTTP requests, by route template and status.\n\
             # TYPE agentconnect_directory_requests_total counter\n",
        );
        for ((route, status), n) in self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            let _ = writeln!(
                out,
                "agentconnect_directory_requests_total{{route=\"{route}\",status=\"{status}\"}} {n}"
            );
        }
        out.push_str(
            "# HELP agentconnect_directory_events_total Directory operations, by kind and outcome.\n\
             # TYPE agentconnect_directory_events_total counter\n",
        );
        for ((what, outcome), n) in self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            let _ = writeln!(
                out,
                "agentconnect_directory_events_total{{kind=\"{what}\",outcome=\"{outcome}\"}} {n}"
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_with_fixed_labels_only() {
        let m = Metrics::default();
        m.request(template(Some("/a/{name}")), 200);
        m.request(template(Some("/a/{name}")), 200);
        m.request(template(Some("/a/release-planner")), 404);
        m.event("publish", "published");
        let text = m.render();
        assert!(
            text.contains("route=\"/a/{name}\",status=\"200\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("route=\"unmatched\",status=\"404\"} 1"),
            "{text}"
        );
        assert!(text.contains("kind=\"publish\",outcome=\"published\"} 1"));
        assert!(!text.contains("release-planner"));
        assert_eq!(template(None), UNMATCHED);
    }
}
