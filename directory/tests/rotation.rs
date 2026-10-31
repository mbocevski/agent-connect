//! SR-24: after the operator rotates `DK`, a stored listing whose token key
//! the directory no longer pins is treated as expired: knockers would
//! refuse it, so the directory stops serving it as a live listing.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use agentconnect_core::clock::FakeClock;
use agentconnect_core::encoding::b64;
use agentconnect_core::listing::{
    DirectoryKey, SignedListing, TokenRevocation, Withdrawal, directory_key_id,
};
use agentconnect_directory::Store as _;
use agentconnect_directory::verify::{CoreVerifier, OwnerVerdict, Rejection, TokenKey, Verifier};
use axum::http::StatusCode;
use common::{HOST, Harness, RELAY, identity, rng};

/// The pinned keys, one of which the operator can retire mid-test (as a
/// restart with the new configuration would).
struct Rotating {
    inner: CoreVerifier,
    old: String,
    retired: AtomicBool,
    /// How many listings were parsed and verified.
    verified: AtomicUsize,
}

impl Verifier for Rotating {
    fn listing(&self, bytes: &[u8]) -> Result<SignedListing, Rejection> {
        self.verified.fetch_add(1, Ordering::SeqCst);
        self.inner.listing(bytes)
    }
    fn check_publish(&self, l: &SignedListing, now: u64) -> Result<(), Rejection> {
        self.inner.check_publish(l, now)
    }
    fn check_token(&self, l: &SignedListing, now: u64) -> Result<(), Rejection> {
        self.inner.check_token(l, now)
    }
    fn withdrawal(&self, bytes: &[u8], now: u64) -> Result<Withdrawal, Rejection> {
        self.inner.withdrawal(bytes, now)
    }
    fn applies(&self, w: &Withdrawal, l: &SignedListing) -> bool {
        self.inner.applies(w, l)
    }
    fn revocation(&self, bytes: &[u8]) -> Result<TokenRevocation, Rejection> {
        self.inner.revocation(bytes)
    }
    fn owner_verdict(&self, file: &[u8], identity: &str, name: &str) -> OwnerVerdict {
        self.inner.owner_verdict(file, identity, name)
    }
    fn token_keys(&self) -> Vec<TokenKey> {
        let retired = self.retired.load(Ordering::SeqCst);
        self.inner
            .token_keys()
            .into_iter()
            .filter(|k| !(retired && k.key_id == self.old))
            .collect()
    }
}

#[tokio::test]
async fn a_listing_under_a_retired_token_key_is_expired() {
    let old = DirectoryKey::generate(&rng()).unwrap();
    let new = DirectoryKey::generate(&rng()).unwrap();
    let keys = [b64(&old.public_key()), b64(&new.public_key())];
    let verifier = Arc::new(Rotating {
        inner: CoreVerifier::new(HOST, &keys).unwrap(),
        old: b64(&directory_key_id(&old.public_key())),
        retired: AtomicBool::new(false),
        verified: AtomicUsize::new(0),
    });
    let mut h = Harness::verified_by(
        HOST,
        RELAY,
        verifier.clone(),
        Arc::new(FakeClock::default()),
        |d| d,
    );
    h.dk = old;
    h.publish(&h.spec("rotated", &identity())).await;
    h.dk = new;
    h.publish(&h.spec("renewed", &identity())).await;
    assert_eq!(h.get("/a/rotated").await.status, StatusCode::OK);

    // The key id is recorded at publish.
    let rotated = h.record("rotated").await.unwrap();
    assert_eq!(rotated.token_key_id, verifier.old);

    verifier.retired.store(true, Ordering::SeqCst);
    verifier.verified.store(0, Ordering::SeqCst);
    assert_eq!(h.get("/a/rotated").await.status, StatusCode::GONE);
    assert_eq!(h.get("/a/rotated.json").await.status, StatusCode::GONE);
    let search = h.get("/search?q=rotated").await.json();
    assert_eq!(search["results"], serde_json::json!([]));
    let names: Vec<String> = h.get("/search?q=renewed").await.json()["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["renewed"]);
    assert!(!h.get("/llms.txt").await.text().contains("rotated"));
    assert!(!h.get("/").await.text().contains("rotated"));
    // Serving reads the recorded key id: nothing is parsed or verified again.
    assert_eq!(verifier.verified.load(Ordering::SeqCst), 0);

    // A listing stored before key ids were recorded is checked once, by
    // maintenance, and then left out like the others.
    h.store()
        .set_token_key_id("rotated", &rotated.sha256, "")
        .await
        .unwrap();
    assert_eq!(h.get("/a/rotated").await.status, StatusCode::OK);
    h.dir.maintain().await.unwrap();
    assert_eq!(verifier.verified.load(Ordering::SeqCst), 1);
    assert_eq!(h.get("/a/rotated").await.status, StatusCode::GONE);
}
