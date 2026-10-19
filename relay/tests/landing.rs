//! Invite landing page: security headers, statuses, escaping (SPEC §8.1).

mod common;

use std::time::Duration;

use agentconnect_core::operator::OperatorLinks;
use agentconnect_relay::relay::NewInviteRequest;
use agentconnect_relay::{Store, app, app_with_links, landing};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use common::{Harness, fresh_id, invite_body, mailbox_of, signing_key};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn get(h: &Harness, path: &str) -> (StatusCode, HeaderMap, String) {
    let resp = app(h.relay.clone())
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

async fn register(h: &Harness, patch: Value) -> String {
    let id = fresh_id();
    let mailbox = mailbox_of(&signing_key(1));
    let mut body = invite_body(&mailbox, &id, h.now_secs() + 3600, 2);
    for (k, v) in patch.as_object().unwrap() {
        body[k] = v.clone();
    }
    let req: NewInviteRequest = serde_json::from_value(body).unwrap();
    h.relay.create_invite(&mailbox, req).await.unwrap();
    id
}

fn assert_secure(headers: &HeaderMap) {
    let csp = headers["content-security-policy"].to_str().unwrap();
    for directive in [
        "default-src 'none'",
        "style-src 'self'",
        "img-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ] {
        assert!(csp.contains(directive), "CSP lacks {directive}: {csp}");
    }
    assert!(
        !csp.contains("script-src") && !csp.contains("unsafe"),
        "{csp}"
    );
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert_eq!(headers["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn open_invite_page_has_security_headers_and_the_expected_content() {
    let h = Harness::start().await;
    let id = register(&h, json!({"member_count": 4})).await;
    let (status, headers, html) = get(&h, &format!("/i/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_secure(&headers);
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );

    for needle in [
        "Ops",
        "Alice",
        "Coordinate deploys",
        "2025-01-01 01:00 UTC",
        "2 of 2",
        "<dt>Members</dt><dd>4</dd>",
        "Open",
        "Give the whole link to your agent; this page never sees the secret part.",
        "compare the short code with the other members over a call or in person",
        "uv tool install agentconnect",
        "agentconnect accept '&lt;paste the full link&gt;'",
        "MCP and Claude Code support is coming later",
        "width=device-width",
    ] {
        assert!(html.contains(needle), "missing {needle:?}");
    }
}

#[tokio::test]
async fn the_page_has_no_script_and_never_touches_the_fragment() {
    let h = Harness::start().await;
    let id = register(&h, json!({})).await;
    let (_, _, html) = get(&h, &format!("/i/{id}")).await;
    let lower = html.to_lowercase();
    for banned in [
        "<script",
        "javascript:",
        "location",
        "hash",
        " onclick",
        " onerror",
        " onload",
        "<iframe",
        "<form",
        "<img",
        "<base",
    ] {
        assert!(!lower.contains(banned), "page contains {banned:?}");
    }
    assert_eq!(lower.matches("<link").count(), 1, "one stylesheet only");
    assert!(lower.contains(r#"href="/static/invite.css""#));
}

#[tokio::test]
async fn stylesheet_is_small_static_and_supports_light_dark_and_375px() {
    let h = Harness::start().await;
    let (status, headers, css) = get(&h, "/static/invite.css").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/css")
    );
    assert_secure(&headers);
    assert!(css.contains("prefers-color-scheme: dark"));
    assert!(css.len() < 6 * 1024, "keep the stylesheet small");
    assert!(
        !css.contains("@import") && !css.contains("url("),
        "no external loads"
    );
    // Phone layout is the default; wider layouts are an opt-in media query.
    assert!(css.contains("min-width"));
}

#[tokio::test]
async fn every_status_renders() {
    let h = Harness::start().await;

    let open = register(&h, json!({})).await;
    let exhausted = register(&h, json!({"max_uses": 1})).await;
    let revoked = register(&h, json!({})).await;
    let expiring = register(&h, json!({"expires_at": h.now_secs() + 60})).await;

    let mailbox = mailbox_of(&signing_key(1));
    let consumed = h
        .relay
        .store()
        .consume_invite(&exhausted, &mailbox, h.relay.now_ms())
        .await
        .unwrap();
    assert!(matches!(
        consumed,
        agentconnect_relay::store::ConsumeOutcome::Consumed { .. }
    ));
    h.relay.revoke_invite(&mailbox, &revoked).await.unwrap();
    h.clock.advance(Duration::from_secs(61));

    let warning = "This invite was already used or revoked. If you didn&#39;t expect this";
    let page = |id: String| {
        let h = &h;
        async move { get(h, &format!("/i/{id}")).await }
    };

    let (status, _, html) = page(open).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("status-open") && html.contains("<p class=\"badge\">Open</p>"));
    assert!(!html.contains("already used or revoked"));

    for (id, class, label) in [
        (exhausted, "status-exhausted", "Exhausted"),
        (revoked, "status-revoked", "Revoked"),
    ] {
        let (status, headers, html) = page(id).await;
        assert_eq!(status, StatusCode::OK);
        assert_secure(&headers);
        assert!(html.contains(class), "{class}");
        assert!(html.contains(&format!("<p class=\"badge\">{label}</p>")));
        assert!(
            html.contains("This invite was already used or revoked. If you didn't expect this")
                || html.contains(warning),
            "prominent warning missing for {label}"
        );
    }

    let (status, _, html) = page(expiring).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("status-expired") && html.contains("has expired"));
}

#[tokio::test]
async fn hostile_metadata_is_escaped() {
    let h = Harness::start().await;
    let id = register(
        &h,
        json!({
            "group_name": "<script>alert(1)</script>",
            "inviter_name": "\"><img src=x onerror=alert(1)>",
            "purpose": "' onmouseover='alert(1)' & <b>bold</b> </dd></dl><h1>pwned</h1>",
        }),
    )
    .await;
    let (status, headers, html) = get(&h, &format!("/i/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_secure(&headers);
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"));
    assert!(html.contains("&#39; onmouseover=&#39;alert(1)&#39; &amp; &lt;b&gt;bold&lt;/b&gt;"));
    let lower = html.to_lowercase();
    assert!(!lower.contains("<script"));
    assert!(!lower.contains("<img"));
    assert!(!lower.contains("<b>"));
    assert!(!lower.contains("<h1>pwned"));
    assert_eq!(lower.matches("<h1>").count(), 1);
}

fn operator_links() -> OperatorLinks {
    OperatorLinks {
        terms: Some("https://relay.example.org/terms?a=1&b=2".into()),
        abuse: Some("mailto:abuse@example.org".into()),
    }
}

const FOOTER: &str = "<footer class=\"operator\">\n<p><a \
href=\"https://relay.example.org/terms?a=1&amp;b=2\" rel=\"noreferrer\">Terms</a> · <a \
href=\"mailto:abuse@example.org\" rel=\"noreferrer\">Report abuse</a></p>\n</footer>\n";

async fn get_linked(h: &Harness, path: &str) -> (StatusCode, HeaderMap, String) {
    let resp = app_with_links(h.relay.clone(), operator_links())
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

#[tokio::test]
async fn operator_links_add_a_footer_and_nothing_else() {
    let h = Harness::start().await;
    let id = register(&h, json!({"member_count": 4})).await;
    for path in [format!("/i/{id}"), format!("/i/{}", fresh_id())] {
        let (plain_status, plain_headers, plain) = get(&h, &path).await;
        let (status, headers, html) = get_linked(&h, &path).await;
        assert_eq!(status, plain_status, "{path}");
        assert!(!plain.contains("<footer"), "{path}");
        assert!(
            html.ends_with(&format!("</main>\n{FOOTER}</body>\n</html>\n")),
            "{path}: {html}"
        );
        assert_eq!(html.replacen(FOOTER, "", 1), plain, "{path}");
        assert_secure(&headers);
        assert_eq!(
            headers["content-security-policy"], plain_headers["content-security-policy"],
            "{path}"
        );
        assert_eq!(headers["content-security-policy"], landing::CSP);
        let lower = html.to_lowercase();
        for banned in [
            "<script",
            "javascript:",
            "location",
            "hash",
            " onclick",
            "<form",
            "<iframe",
        ] {
            assert!(!lower.contains(banned), "{path} contains {banned:?}");
        }
        assert_eq!(lower.matches("<link").count(), 1);
    }
    assert_eq!(
        landing::CSP,
        "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; \
form-action 'none'; frame-ancestors 'none'"
    );
    let (_, _, css) = get_linked(&h, "/static/invite.css").await;
    assert!(css.contains("footer.operator"));
}

#[tokio::test]
async fn unknown_or_malformed_invites_are_404_with_the_same_headers() {
    let h = Harness::start().await;
    for path in [format!("/i/{}", fresh_id()), "/i/not-an-invite".to_owned()] {
        let (status, headers, html) = get(&h, &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_secure(&headers);
        assert!(html.contains("Invite not found"));
        assert!(!html.contains("not-an-invite"), "never echo the path");
    }
}
