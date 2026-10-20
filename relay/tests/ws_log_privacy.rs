//! What the relay logs about WebSocket connections at `RUST_LOG=trace`,
//! through the real subscriber (SR-14, SR-15): connection lines carry no
//! mailbox tag, door and knock traffic leaves no identifier of either side,
//! no `ct` and no frame contents get through (the client's tungstenite logs
//! whole frames at trace), and tags are keyed. Its own test binary with a
//! single test, because it installs the process-wide subscriber.

mod common;

use std::sync::{Arc, Mutex};

use agentconnect_relay::logging;
use agentconnect_relay::proto::{b64_encode, log_tag};
use common::{Harness, fresh_id, mailbox_of, make_group, open_door, signing_key};
use serde_json::json;
use sha2::Digest;
use tracing_subscriber::util::SubscriberInitExt as _;

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

fn unkeyed_tag(id: &str) -> String {
    sha2::Sha256::digest(id.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn connection_and_knock_logs_carry_no_mailbox_and_no_frame_contents() {
    let captured = Captured::default();
    let writer = captured.clone();
    logging::subscriber(Some("trace"), move || writer.clone())
        .try_init()
        .unwrap();

    let h = Harness::start().await;
    // A door owner and a knocker, over WebSockets.
    let door = open_door(&h, 1).await;
    let mut owner = h.client(1).await;
    owner.drained().await;
    let mut knocker = h.client(2).await;
    let frame = common::knock_frame(&knocker.mailbox, &door);
    assert_eq!(knocker.request(&frame).await["t"], "accepted");
    h.relay.flush_knocks().await;
    assert_eq!(owner.deliver().await["kind"], "knock");
    // Group traffic between two others, with a recognisable `ct`.
    let marker = format!("ct-marker-{}", fresh_id());
    let mut a = h.client(3).await;
    let b = h.client(4).await;
    let gid = make_group(&mut a, &[&b]).await;
    let mut env = a.envelope("application", &gid, 1);
    env["ct"] = json!(b64_encode(marker.as_bytes()));
    assert_eq!(a.send(&env).await["t"], "accepted");
    for c in [owner, knocker, a, b] {
        c.disconnect().await;
    }
    common::settle_open(&h, 0).await;

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    // The relay's own trace output does get through.
    assert!(logs.contains("connected"), "{logs}");
    assert!(logs.contains("knock forwarded"), "{logs}");
    assert!(logs.contains("accepted"), "{logs}");
    // Nothing from tungstenite (whole frames at trace) or the HTTP stack.
    for target in ["tungstenite", "hyper", "axum"] {
        assert!(!logs.contains(target), "{target} logged:\n{logs}");
    }
    assert!(!logs.contains(&marker));
    assert!(!logs.contains(&b64_encode(marker.as_bytes())));
    assert!(!logs.contains(&door));
    for n in 1..=4 {
        let id = mailbox_of(&signing_key(n));
        assert!(!logs.contains(&id), "raw mailbox id in logs");
        assert!(!logs.contains(&unkeyed_tag(&id)), "unkeyed tag in logs");
    }
    // The door owner and the knocker did nothing but connect and knock:
    // not even their keyed tags appear.
    for n in [1, 2] {
        let id = mailbox_of(&signing_key(n));
        assert!(!logs.contains(&log_tag(&id)), "door-side tag in logs");
    }
    for line in logs.lines().filter(|l| l.contains("connected")) {
        assert!(!line.contains("mailbox"), "{line}");
    }
}
