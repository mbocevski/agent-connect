//! The open-WebSocket gauge on `/metrics`.

mod common;

use common::{Harness, auth_frame, raw_connect, raw_recv, raw_send, signing_key};

const NAME: &str = "agentconnect_relay_ws_connections_open";

fn open(h: &Harness) -> u64 {
    let text = h.relay.metrics().render();
    let line = text
        .lines()
        .find(|l| l.starts_with(NAME) && !l.starts_with('#'))
        .expect("gauge line present");
    line.rsplit(' ').next().unwrap().parse().unwrap()
}

/// The server notices a closed connection on its own task; yield until it has.
/// No timer: a hang fails on the guard timeout instead.
async fn settle_at(h: &Harness, want: u64) {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while open(h) != want {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("gauge stuck at {}, wanted {want}", open(h)));
}

#[tokio::test]
async fn exposed_as_a_gauge_without_labels_or_identifiers() {
    let h = Harness::start().await;
    let _c = h.client(1).await;
    let text = h.relay.metrics().render();
    assert!(text.contains(&format!("# TYPE {NAME} gauge")));
    assert!(text.contains(&format!("# HELP {NAME} ")));
    assert!(text.contains(&format!("\n{NAME} 1\n")));
    assert!(!text.contains(&format!("{NAME}{{")));
    assert!(!text.contains(&common::mailbox_of(&signing_key(1))));
}

#[tokio::test]
async fn starts_at_zero() {
    let h = Harness::start().await;
    assert_eq!(open(&h), 0);
}

#[tokio::test]
async fn goes_up_on_connect_and_down_on_clean_close() {
    let h = Harness::start().await;
    let c = h.client(1).await;
    assert_eq!(open(&h), 1);
    c.disconnect().await;
    settle_at(&h, 0).await;
}

#[tokio::test]
async fn goes_down_when_the_client_drops_without_a_close_frame() {
    let h = Harness::start().await;
    let c = h.client(1).await;
    assert_eq!(open(&h), 1);
    drop(c);
    settle_at(&h, 0).await;
}

#[tokio::test]
async fn goes_down_after_an_auth_failure() {
    let h = Harness::start().await;
    let mut ws = raw_connect(h.addr).await;
    let nonce = raw_recv(&mut ws).await.unwrap()["nonce"]
        .as_str()
        .unwrap()
        .to_owned();
    // The connection counts as open while it awaits authentication.
    assert_eq!(open(&h), 1);
    raw_send(
        &mut ws,
        &auth_frame(&signing_key(1), &nonce, "evil.example"),
    )
    .await;
    assert_eq!(raw_recv(&mut ws).await.unwrap()["code"], "auth_failed");
    settle_at(&h, 0).await;
}

#[tokio::test]
async fn goes_down_when_the_client_drops_before_authenticating() {
    let h = Harness::start().await;
    let mut ws = raw_connect(h.addr).await;
    raw_recv(&mut ws).await.unwrap();
    assert_eq!(open(&h), 1);
    drop(ws);
    settle_at(&h, 0).await;
}

#[tokio::test]
async fn counts_concurrent_connections() {
    let h = Harness::start().await;
    let a = h.client(1).await;
    let b = h.client(2).await;
    let c = h.client(3).await;
    assert_eq!(open(&h), 3);
    b.disconnect().await;
    settle_at(&h, 2).await;
    drop(a);
    settle_at(&h, 1).await;
    // A second connection for the same mailbox is a separate connection.
    let c2 = h.client(3).await;
    assert_eq!(open(&h), 2);
    drop(c);
    drop(c2);
    settle_at(&h, 0).await;
}

#[tokio::test]
async fn never_goes_negative_across_failures_and_reconnects() {
    let h = Harness::start().await;
    for _ in 0..3 {
        let mut ws = raw_connect(h.addr).await;
        raw_recv(&mut ws).await.unwrap();
        raw_send(&mut ws, &serde_json::json!({"nonsense": true})).await;
        raw_recv(&mut ws).await;
        drop(ws);
        let c = h.client(1).await;
        c.disconnect().await;
    }
    settle_at(&h, 0).await;
    // Rendered as an unsigned integer: a wrapped counter would show up huge.
    assert!(!h.relay.metrics().render().contains(&format!("{NAME} -")));
    assert_eq!(open(&h), 0);
}
