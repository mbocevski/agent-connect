//! Per-address rate limits, and logs without identifiers.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use agentconnect_directory::ratelimit::{Limit, Limits};
use axum::body::Body;
use axum::http::{HeaderName, Request, StatusCode};
use common::{HOST, Harness, identity};

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

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn logs_carry_route_templates_and_no_identifiers() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("secret-agent-name", &id);
    s.owner_domain = Some("owner-domain.example".into());
    s.description = "zebra-description-word".into();
    h.fetcher.fail(
        "owner-domain.example",
        agentconnect_directory::owner::FetchError::Timeout,
    );
    h.publish(&s).await;
    let _ = h.get("/a/secret-agent-name").await;
    let _ = h.get("/a/secret-agent-name.json").await;
    let _ = h.get("/search?q=zebra-query-term&skill=yak-skill").await;
    let _ = h.get("/?q=zebra-query-term").await;
    let _ = h.get("/a/unknown-probe-name").await;
    let _ = h.get("/no/such/path-probe").await;
    let _ = h
        .post("/v0/withdrawals", h.withdrawal("secret-agent-name", &id, 1))
        .await;
    let _ = h.post("/v0/listings", b"garbage".to_vec()).await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("route=\"/a/{name}\""), "{logs}");
    assert!(logs.contains("route=\"/search\""), "{logs}");
    assert!(logs.contains("route=\"unmatched\""), "{logs}");
    for leak in [
        "secret-agent-name",
        id.as_str(),
        &agentconnect_core::identity::fingerprint(
            &agentconnect_core::identity::parse_identity(&id).unwrap(),
        ),
        "owner-domain.example",
        "zebra",
        "yak-skill",
        "unknown-probe-name",
        "path-probe",
        common::CLIENT,
        "?q=",
    ] {
        assert!(!logs.contains(leak), "logs contain {leak:?}:\n{logs}");
    }
}
