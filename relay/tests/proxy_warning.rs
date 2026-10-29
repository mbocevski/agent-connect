//! The relay tells the operator, once, when a request names a client
//! address (`X-Forwarded-For` or `Forwarded`) but comes from a peer outside
//! `AC_RELAY_TRUSTED_PROXIES`: a wrong trusted-proxy address (127.0.0.1
//! where the proxy is the Docker bridge gateway) would otherwise make every
//! client one source without a word. The log line holds no address.

mod common;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use agentconnect_relay::logging;
use agentconnect_relay::quota::{Cidr, ClientIp};
use axum::http::{HeaderMap, HeaderName};
use common::{Harness, roomy_quotas};
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

fn forwarded(client: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", client.parse().unwrap());
    headers
}

#[tokio::test]
async fn a_forwarded_header_from_an_untrusted_peer_is_logged_once() {
    let mut quotas = roomy_quotas();
    quotas.client_ip = ClientIp {
        header: Some(HeaderName::from_static("x-forwarded-for")),
        trusted_proxies: vec![Cidr::parse("127.0.0.1/32").unwrap()],
        hops: 1,
    };
    let h = Harness::with_quotas(quotas).await;
    let logs = Captured::default();
    let _log = tracing::subscriber::set_default(logging::subscriber(Some("warn"), logs.clone()));
    let proxy: IpAddr = "172.17.0.1".parse().unwrap();
    // The proxy is at the Docker bridge gateway, not at the trusted
    // address: its header is ignored, and every request counts as its own.
    for _ in 0..3 {
        assert_eq!(
            h.relay.client_ip(Some(proxy), &forwarded("203.0.113.9")),
            Some(proxy)
        );
    }
    let text = logs.text();
    assert_eq!(
        text.matches("AC_RELAY_TRUSTED_PROXIES").count(),
        1,
        "{text}"
    );
    assert!(
        !text.contains("172.17.0.1") && !text.contains("203.0.113.9"),
        "an address was logged: {text}"
    );
    // Neither a trusted proxy nor a request that names no client says more.
    let trusted: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(
        h.relay.client_ip(Some(trusted), &forwarded("203.0.113.9")),
        Some("203.0.113.9".parse().unwrap())
    );
    assert_eq!(
        h.relay.client_ip(Some(proxy), &HeaderMap::new()),
        Some(proxy)
    );
    assert_eq!(logs.text().matches("AC_RELAY_TRUSTED_PROXIES").count(), 1);
}

#[tokio::test]
async fn no_warning_without_a_configured_header_names_the_other_setting() {
    // The neighbouring case is unchanged: no header configured at all.
    let h = Harness::with_quotas(roomy_quotas()).await;
    let logs = Captured::default();
    let _log = tracing::subscriber::set_default(logging::subscriber(Some("warn"), logs.clone()));
    let peer: IpAddr = "172.17.0.1".parse().unwrap();
    let _ = h.relay.client_ip(Some(peer), &forwarded("203.0.113.9"));
    let text = logs.text();
    assert!(text.contains("AC_RELAY_CLIENT_IP_HEADER"), "{text}");
    assert!(!text.contains("AC_RELAY_TRUSTED_PROXIES"), "{text}");
}
