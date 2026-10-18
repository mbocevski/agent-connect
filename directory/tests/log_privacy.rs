//! Logs carry route templates and statuses, never request data. This is
//! its own test binary with a single test, so the subscriber it installs
//! isn't raced by other tests' threads (tracing caches callsite interest
//! per process).

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use agentconnect_directory::log_filter;
use axum::body::Body;
use axum::http::Request;
use common::{HOST, Harness, identity};
use serde_json::json;

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

fn mcp(host: &str, origin: Option<&str>, body: &serde_json::Value) -> Request<Body> {
    let mut b = Request::post("/mcp")
        .header("host", host)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25");
    if let Some(o) = origin {
        b = b.header("origin", o);
    }
    b.body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn logs_carry_route_templates_and_no_identifiers() {
    let capture = Capture::default();
    let writer = capture.clone();
    // The binary's filter, at its most verbose.
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(log_filter(Some("trace")))
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

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
    // MCP: a rejected Host, a rejected Origin, and client details.
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let _ = h.send(mcp("rebind-host.example", None, &list)).await;
    let _ = h
        .send(mcp(HOST, Some("https://evil-origin.example"), &list))
        .await;
    let init = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "zebra-reader-client", "version": "9.9"}}});
    let _ = h.send(mcp(HOST, None, &init)).await;
    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "search_agents", "arguments": {"q": "zebra-mcp-query"}}});
    let _ = h.send(mcp(HOST, None, &call)).await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("route=\"/a/{name}\""), "{logs}");
    assert!(logs.contains("route=\"/search\""), "{logs}");
    assert!(logs.contains("route=\"/mcp\""), "{logs}");
    assert!(logs.contains("route=\"unmatched\""), "{logs}");
    for leak in [
        "secret-agent-name",
        id.id().as_str(),
        &id.fingerprint(),
        "owner-domain.example",
        "zebra",
        "yak-skill",
        "unknown-probe-name",
        "path-probe",
        "rebind-host",
        "evil-origin",
        common::CLIENT,
        "?q=",
    ] {
        assert!(!logs.contains(leak), "logs contain {leak:?}:\n{logs}");
    }
}
