//! Door and knock logs carry no identifiers, not even hashes of them. This
//! is its own test binary with a single test, so the subscriber it installs
//! isn't raced by other tests' threads (tracing caches callsite interest per
//! process, and under `cargo test` every test shares that process).

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentconnect_relay::Limits;
use agentconnect_relay::proto::log_tag;
use common::{
    Harness, WEEK, close_door, door_body, fresh_id, knock_as, mailbox_of, open_door, post_door,
    signing_key,
};

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

#[tokio::test]
async fn door_and_knock_logs_carry_no_identifiers() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    let h = Harness::with_limits(Limits {
        queue_max_bytes: 1500,
        sends_per_sec: 100_000,
        ..Limits::default()
    })
    .await;
    let door = open_door(&h, 1).await;
    let closed = open_door(&h, 1).await;
    close_door(&h, 2, &closed).await;
    close_door(&h, 1, &closed).await;
    post_door(&h, 1, &door_body(1, &fresh_id(), h.now_secs() + 2 * WEEK)).await;
    for n in 2..14 {
        knock_as(&h, n, &door).await;
    }
    knock_as(&h, 2, &door).await;
    knock_as(&h, 2, &closed).await;
    knock_as(&h, 3, &fresh_id()).await;
    h.clock.advance(Duration::from_secs(4000));
    h.relay.purge().await.unwrap();

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("knock"),
        "the door paths log something: {logs}"
    );
    let mut ids = vec![door, closed];
    ids.extend((1..14).map(|n| mailbox_of(&signing_key(n))));
    for id in &ids {
        assert!(!logs.contains(id.as_str()), "raw identifier in logs");
        assert!(!logs.contains(&log_tag(id)), "identifier tag in logs");
    }
}
