//! The directory tells the operator, once, when a request names a client
//! address (`X-Forwarded-For` or `Forwarded`) but comes from a peer outside
//! `AC_DIRECTORY_TRUSTED_PROXIES`: a wrong trusted-proxy address would
//! otherwise make every client one source without a word. The log line
//! holds no address.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use agentconnect_directory::config::Cidr;
use agentconnect_directory::{app, logging};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderName, Request};
use common::{HOST, Harness};
use tower::ServiceExt as _;
use tracing_subscriber::fmt::MakeWriter;

/// The log, captured.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Captured {
    type Writer = Captured;

    fn make_writer(&self) -> Captured {
        self.clone()
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn request(peer: &str, forwarded: Option<&str>) -> Request<Body> {
    let mut b = Request::get("/healthz").header("host", HOST);
    if let Some(client) = forwarded {
        b = b.header("x-forwarded-for", client);
    }
    let mut req = b.body(Body::empty()).unwrap();
    let ip: IpAddr = peer.parse().unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
    req
}

#[tokio::test]
async fn a_forwarded_header_from_an_untrusted_peer_is_logged_once() {
    let mut h = Harness::with(|d| d);
    h.http.client_ip_header = Some(HeaderName::from_static("x-forwarded-for"));
    h.http.trusted_proxies = vec![Cidr::parse("10.0.0.0/8").unwrap()];
    let logs = Captured::default();
    let _log =
        tracing::subscriber::set_default(logging::subscriber(Some("warn"), false, logs.clone()));
    // One router, as the binary serves: the warning is once per process.
    let router = app(h.dir.clone(), h.http.clone());
    // The proxy is at 172.17.0.1, not in the trusted block: its header is
    // ignored, and the operator is told.
    for _ in 0..3 {
        router
            .clone()
            .oneshot(request("172.17.0.1", Some("203.0.113.9")))
            .await
            .unwrap();
    }
    let text = logs.text();
    assert_eq!(
        text.matches("AC_DIRECTORY_TRUSTED_PROXIES").count(),
        1,
        "{text}"
    );
    assert!(
        !text.contains("172.17.0.1") && !text.contains("203.0.113.9"),
        "an address was logged: {text}"
    );
    // Neither a trusted proxy nor a request that names no client says more.
    router
        .clone()
        .oneshot(request("10.0.0.5", Some("203.0.113.9")))
        .await
        .unwrap();
    router
        .clone()
        .oneshot(request("172.17.0.1", None))
        .await
        .unwrap();
    assert_eq!(
        logs.text().matches("AC_DIRECTORY_TRUSTED_PROXIES").count(),
        1
    );
}

#[tokio::test]
async fn nothing_is_logged_without_a_configured_header() {
    let h = Harness::with(|d| d);
    let logs = Captured::default();
    let _log =
        tracing::subscriber::set_default(logging::subscriber(Some("warn"), false, logs.clone()));
    let router = app(h.dir.clone(), h.http.clone());
    router
        .oneshot(request("172.17.0.1", Some("203.0.113.9")))
        .await
        .unwrap();
    assert_eq!(logs.text(), "");
}
