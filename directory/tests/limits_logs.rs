//! Per-address rate limits. (The log-privacy test is `log_privacy.rs`.)

mod common;

use agentconnect_directory::ratelimit::{Limit, Limits};
use axum::body::Body;
use axum::http::{HeaderName, Request, StatusCode};
use common::{HOST, Harness};

fn tight() -> Limits {
    let l = |max| Limit {
        max,
        window_secs: 60,
    };
    Limits {
        read: l(3),
        search: l(2),
        mcp: l(1),
        write: l(2),
        write_name: l(2),
        max_windows: 10_000,
    }
}

#[tokio::test]
async fn reads_are_limited_per_address_and_recover() {
    let h = Harness::with(|d| d.with_limits(tight()));
    let a = "203.0.113.1".parse().unwrap();
    let b = "203.0.113.2".parse().unwrap();
    let req = || Request::get("/healthz").body(Body::empty()).unwrap();
    for _ in 0..3 {
        assert_eq!(h.send_from(req(), a).await.status, StatusCode::OK);
    }
    let limited = h.send_from(req(), a).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.json()["code"], "rate_limited");
    assert_eq!(limited.header("retry-after").as_deref(), Some("60"));
    assert_eq!(h.send_from(req(), b).await.status, StatusCode::OK);
    h.advance(60);
    assert_eq!(h.send_from(req(), a).await.status, StatusCode::OK);
}

#[tokio::test]
async fn searches_writes_and_mcp_have_their_own_budgets() {
    let h = Harness::with(|d| d.with_limits(tight()));
    for _ in 0..2 {
        assert_eq!(h.get("/search?q=x").await.status, StatusCode::OK);
    }
    assert_eq!(
        h.get("/search?q=x").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        h.get("/?q=x").await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "home searches count as searches"
    );
    assert_eq!(
        h.get("/").await.status,
        StatusCode::OK,
        "plain pages are reads"
    );
    for _ in 0..2 {
        assert_ne!(
            h.post("/v0/withdrawals", b"{}".to_vec()).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(
        h.post("/v0/listings", b"{}".to_vec()).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let mcp = || {
        Request::post("/mcp")
            .header("host", HOST)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            ))
            .unwrap()
    };
    assert_eq!(h.send(mcp()).await.status, StatusCode::OK);
    assert_eq!(h.send(mcp()).await.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_trusted_proxy_header_names_the_client() {
    let mut h = Harness::with(|d| d.with_limits(tight()));
    h.http.client_ip_header = Some(HeaderName::from_static("x-forwarded-for"));
    h.http.trusted_proxies =
        vec![agentconnect_directory::config::Cidr::parse(common::CLIENT).unwrap()];
    let from = |xff: &str| {
        Request::get("/healthz")
            .header("x-forwarded-for", xff)
            .body(Body::empty())
            .unwrap()
    };
    // The last value is the one the trusted proxy appended.
    for _ in 0..3 {
        assert_eq!(
            h.send(from("10.9.9.9, 192.0.2.50")).await.status,
            StatusCode::OK
        );
    }
    assert_eq!(
        h.send(from("1.1.1.1, 192.0.2.50")).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(h.send(from("192.0.2.51")).await.status, StatusCode::OK);
}
