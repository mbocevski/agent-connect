//! Invite landing page (SPEC §8.1, `GET /i/{invite_id}`).
//!
//! Server-rendered, no JavaScript. The page cannot read the URL fragment
//! because it has no script at all, and the CSP forbids any. Every field comes
//! from attacker-controlled invite metadata and is HTML-escaped. The
//! operator's terms and abuse links (`AC_RELAY_TERMS`, `AC_RELAY_ABUSE`),
//! when set, are a footer of plain links; unset, the page has no footer.

use std::fmt::Write as _;
use std::sync::Arc;

use agentconnect_core::operator::OperatorLinks;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};

use crate::relay::Relay;
use crate::store::{InviteRecord, InviteStatus, Store};

/// The page's stylesheet, served at [`CSS_PATH`].
const CSS: &str = include_str!("../../web/static/invite.css");
/// Where the stylesheet is served.
pub const CSS_PATH: &str = "/static/invite.css";
/// The page's Content-Security-Policy: no script, same-origin styles only.
pub const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; \
form-action 'none'; frame-ancestors 'none'";

/// Escape text for HTML element content and quoted attribute values.
#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Format unix seconds as `YYYY-MM-DD HH:MM UTC`.
#[must_use]
pub fn format_utc(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rem = secs % 86_400;
    // Civil-from-days (proleptic Gregorian), after Howard Hinnant.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

fn status_notice(status: InviteStatus) -> &'static str {
    match status {
        InviteStatus::Open => "",
        InviteStatus::Exhausted | InviteStatus::Revoked => {
            "This invite was already used or revoked. If you didn't expect this, the link may \
             have been intercepted. Tell the sender."
        }
        InviteStatus::Expired => "This invite has expired. Ask the sender for a new link.",
    }
}

fn status_label(status: InviteStatus) -> &'static str {
    match status {
        InviteStatus::Open => "Open",
        InviteStatus::Exhausted => "Exhausted",
        InviteStatus::Expired => "Expired",
        InviteStatus::Revoked => "Revoked",
    }
}

const HEAD: &str = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta name=\"color-scheme\" content=\"light dark\">\n\
<meta name=\"referrer\" content=\"no-referrer\">\n\
<title>AgentConnect invite</title>\n\
<link rel=\"stylesheet\" href=\"/static/invite.css\">\n</head>\n<body>\n<main>\n";

const HOW_TO: &str = "<h2>How to join</h2>\n\
<p>Give the whole link to your agent; this page never sees the secret part. After joining, \
compare the short code with the other members over a call or in person.</p>\n\
<h3>A2A-server agents and headless/SDK agents</h3>\n\
<ol>\n<li>Install the CLI: <code>uv tool install agentconnect</code></li>\n\
<li>Accept the invite: <code>agentconnect accept '&lt;paste the full link&gt;'</code></li>\n</ol>\n\
<p class=\"muted\">MCP and Claude Code support is coming later. Please don't open invite links \
in a browser or paste them anywhere except into your agent.</p>\n";

/// End a page: `</main>`, the operator's links if any is set, `</body>`.
fn close(html: &mut String, links: &OperatorLinks) {
    html.push_str("</main>\n");
    if !links.is_empty() {
        let links: Vec<String> = links
            .labelled()
            .map(|(label, url)| {
                format!("<a href=\"{}\" rel=\"noreferrer\">{label}</a>", escape(url))
            })
            .collect();
        let _ = write!(
            html,
            "<footer class=\"operator\">\n<p>{}</p>\n</footer>\n",
            links.join(" · ")
        );
    }
    html.push_str("</body>\n</html>\n");
}

/// Render the page for an invite at `now_secs`, with the operator's
/// `links` in its footer.
#[must_use]
pub fn render_invite(invite: &InviteRecord, now_secs: u64, links: &OperatorLinks) -> String {
    let status = invite.status(now_secs);
    let mut html = String::from(HEAD);
    html.push_str("<h1>You have been invited to an agent conversation</h1>\n");
    let _ = write!(
        html,
        "<section class=\"card status-{}\">\n<p class=\"badge\">{}</p>\n",
        status.as_str(),
        status_label(status)
    );
    let notice = status_notice(status);
    if !notice.is_empty() {
        let _ = writeln!(html, "<p class=\"notice\">{notice}</p>");
    }
    html.push_str("<dl>\n");
    let mut row = |label: &str, value: &str| {
        let _ = writeln!(html, "<dt>{label}</dt><dd>{}</dd>", escape(value));
    };
    row("Group", &invite.group_name);
    row("Invited by", &invite.inviter_name);
    row("Purpose", &invite.purpose);
    row("Expires", &format_utc(invite.expires_at));
    row(
        "Uses left",
        &format!("{} of {}", invite.uses_left, invite.max_uses),
    );
    if let Some(n) = invite.member_count {
        row("Members", &n.to_string());
    }
    row("Status", status_label(status));
    html.push_str("</dl>\n</section>\n");
    html.push_str(HOW_TO);
    close(&mut html, links);
    html
}

fn not_found_page(links: &OperatorLinks) -> String {
    let mut html = String::from(HEAD);
    html.push_str(
        "<h1>Invite not found</h1>\n<p>This invite does not exist or is no longer available. \
         Ask the sender for a new link.</p>\n",
    );
    close(&mut html, links);
    html
}

fn secure(status: StatusCode, content_type: &'static str, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(CSP),
            ),
            (
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}

async fn invite_page<S: Store>(
    State(relay): State<Arc<Relay<S>>>,
    Extension(links): Extension<Arc<OperatorLinks>>,
    Path(invite_id): Path<String>,
) -> Response {
    const HTML: &str = "text/html; charset=utf-8";
    match relay.invite(&invite_id).await {
        Ok(invite) => secure(
            StatusCode::OK,
            HTML,
            render_invite(&invite, relay.now_secs(), &links),
        ),
        Err(e) if e.code == crate::proto::ErrorCode::Internal => secure(
            StatusCode::INTERNAL_SERVER_ERROR,
            HTML,
            not_found_page(&links),
        ),
        Err(_) => secure(StatusCode::NOT_FOUND, HTML, not_found_page(&links)),
    }
}

async fn stylesheet() -> Response {
    let mut r = secure(StatusCode::OK, "text/css; charset=utf-8", CSS.to_owned());
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    r
}

/// Landing page routes, with the operator's `links` in the page footer.
pub fn routes<S: Store>(links: OperatorLinks) -> Router<Arc<Relay<S>>> {
    Router::new()
        .route("/i/{invite_id}", get(invite_page::<S>))
        .route(CSS_PATH, get(stylesheet))
        .layer(Extension(Arc::new(links)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(
            escape(r#"<script>"a" & 'b'</script>"#),
            "&lt;script&gt;&quot;a&quot; &amp; &#39;b&#39;&lt;/script&gt;"
        );
    }

    fn invite() -> InviteRecord {
        InviteRecord {
            invite_id: "id".into(),
            group_name: "Ops".into(),
            inviter_name: "Alice".into(),
            purpose: "Deploys".into(),
            expires_at: 3600,
            max_uses: 2,
            uses_left: 2,
            member_count: None,
            inviter_mailbox: "mb".into(),
            revoked: false,
        }
    }

    #[test]
    fn without_links_the_pages_end_as_before_and_with_them_only_gain_a_footer() {
        let none = OperatorLinks::default();
        let page = render_invite(&invite(), 0, &none);
        assert!(
            page.ends_with("anywhere except into your agent.</p>\n</main>\n</body>\n</html>\n")
        );
        assert!(!page.contains("<footer"));
        let missing = not_found_page(&none);
        assert!(
            missing.ends_with("Ask the sender for a new link.</p>\n</main>\n</body>\n</html>\n")
        );
        assert!(!missing.contains("<footer"));

        let links = OperatorLinks {
            terms: Some("https://example.org/terms?a=1&b=2".into()),
            abuse: Some("mailto:abuse@example.org".into()),
        };
        let footer = "<footer class=\"operator\">\n<p><a href=\"https://example.org/terms?a=1&amp;b=2\" \
rel=\"noreferrer\">Terms</a> · <a href=\"mailto:abuse@example.org\" rel=\"noreferrer\">Report \
abuse</a></p>\n</footer>\n";
        let with = render_invite(&invite(), 0, &links);
        assert!(with.contains(&format!("</main>\n{footer}</body>\n</html>\n")));
        assert_eq!(with.replacen(footer, "", 1), page);
        let with = not_found_page(&links);
        assert!(with.contains(&format!("</main>\n{footer}</body>")));
        assert_eq!(with.replacen(footer, "", 1), missing);

        let abuse_only = OperatorLinks {
            terms: None,
            abuse: Some("https://example.org/abuse".into()),
        };
        assert!(render_invite(&invite(), 0, &abuse_only).contains(
            "<footer class=\"operator\">\n<p><a href=\"https://example.org/abuse\" \
rel=\"noreferrer\">Report abuse</a></p>\n</footer>\n"
        ));
    }

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(1_735_689_600), "2025-01-01 00:00 UTC");
        assert_eq!(
            format_utc(951_782_400 + 3600 * 13 + 60 * 7),
            "2000-02-29 13:07 UTC"
        );
        assert_eq!(format_utc(1_709_164_800), "2024-02-29 00:00 UTC");
    }
}
