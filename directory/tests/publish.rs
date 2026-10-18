//! Publish, withdraw and revoke (ADR-006 Decision 6), over HTTP.

mod common;

use agentconnect_core::encoding::jcs;
use axum::http::StatusCode;
use common::{DAY, HOST, Harness, identity, random_b64};
use serde_json::{Value, json};

#[tokio::test]
async fn publish_stores_the_exact_bytes_and_is_idempotent() {
    let h = Harness::new();
    let id = identity();
    let b = h.build(&h.spec("release-planner", &id));
    let r = h.post("/v0/listings", b.bytes.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    let body = r.json();
    assert_eq!(body["name"], "release-planner");
    assert_eq!(body["seq"], 1);
    assert_eq!(
        body["url"],
        format!("https://{HOST}/a/release-planner.json")
    );
    assert_eq!(body["owner_state"], "unclaimed");
    let again = h.post("/v0/listings", b.bytes.clone()).await;
    assert_eq!(again.status, StatusCode::OK);
    let card = h.get("/a/release-planner.json").await;
    assert_eq!(card.body, b.bytes);
}

async fn refused(h: &Harness, bytes: Vec<u8>, status: StatusCode, code: &str) {
    let r = h.post("/v0/listings", bytes).await;
    assert_eq!(r.status, status, "{}", r.text());
    assert_eq!(r.json()["code"], code, "{}", r.text());
}

#[tokio::test]
async fn bad_signatures_and_non_canonical_bytes_are_refused_by_the_verifier() {
    let h = Harness::new();
    let id = identity();
    let b = h.build(&h.spec("signed", &id));
    // Tampered text: still canonical, but not what was signed.
    let mut card: Value = serde_json::from_slice(&b.bytes).unwrap();
    card["description"] = json!("Now does something else.");
    refused(
        &h,
        jcs(&card).unwrap(),
        StatusCode::FORBIDDEN,
        "bad_signature",
    )
    .await;
    // Not canonical (pretty-printed): the canonical check fails first.
    let pretty = serde_json::to_vec_pretty(&card).unwrap();
    refused(&h, pretty, StatusCode::BAD_REQUEST, "bad_listing").await;
    refused(
        &h,
        b"not json".to_vec(),
        StatusCode::BAD_REQUEST,
        "bad_listing",
    )
    .await;
    // Over the 32 KiB card cap.
    refused(
        &h,
        vec![b' '; 33 * 1024],
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
    )
    .await;
    assert!(h.record("signed").await.is_none());
}

#[tokio::test]
async fn token_scope_and_lifetime_are_enforced() {
    let h = Harness::new();
    let id = identity();
    // A token the operator never issued (wrong key).
    let mut s = h.spec("tok", &id);
    s.token_id = random_b64(16);
    refused(&h, h.build(&s).bytes, StatusCode::FORBIDDEN, "unknown_key").await;
    // Issued for another name.
    let mut s = h.spec("tok", &id);
    s.token_name = Some("other-name".into());
    refused(&h, h.build(&s).bytes, StatusCode::FORBIDDEN, "bad_token").await;
    // Issued for another identity: the token embeds the spec's identity, so
    // sign a card whose params name a different one.
    let s = h.spec("tok", &id);
    let mut card = s.card();
    card["capabilities"]["extensions"][0]["params"]["token"]["identity"] = json!(identity());
    let bytes = jcs(&card).unwrap();
    h.verifier.sign(&bytes);
    refused(&h, bytes, StatusCode::FORBIDDEN, "bad_token").await;
    // For another directory.
    let mut s = h.spec("tok", &id);
    s.token_directory = "elsewhere.test".into();
    refused(&h, h.build(&s).bytes, StatusCode::FORBIDDEN, "bad_token").await;
    // Expired.
    let mut s = h.spec("tok", &id);
    s.token_expires_at = h.now();
    refused(&h, h.build(&s).bytes, StatusCode::FORBIDDEN, "bad_token").await;
    // Pins a domain the listing doesn't claim.
    let s = h.spec("tok", &id);
    let mut card = s.card();
    card["capabilities"]["extensions"][0]["params"]["token"]["owner_domain"] = json!("example.com");
    let bytes = jcs(&card).unwrap();
    h.verifier.sign(&bytes);
    refused(&h, bytes, StatusCode::FORBIDDEN, "bad_token").await;
    assert!(h.record("tok").await.is_none());
}

#[tokio::test]
async fn listing_params_are_checked_against_this_directory() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("params", &id);
    s.directory = "elsewhere.test".into();
    refused(
        &h,
        h.build(&s).bytes,
        StatusCode::BAD_REQUEST,
        "wrong_directory",
    )
    .await;
    let mut s = h.spec("params", &id);
    s.relay = "other-relay.test".into();
    refused(
        &h,
        h.build(&s).bytes,
        StatusCode::BAD_REQUEST,
        "wrong_relay",
    )
    .await;
    let mut s = h.spec("params", &id);
    s.issued_at = h.now() + 301;
    s.door_expires_at = Some(h.now() + DAY);
    refused(
        &h,
        h.build(&s).bytes,
        StatusCode::BAD_REQUEST,
        "bad_listing",
    )
    .await;
    let mut s = h.spec("params", &id);
    s.door_expires_at = Some(h.now());
    refused(&h, h.build(&s).bytes, StatusCode::BAD_REQUEST, "bad_door").await;
    let mut s = h.spec("params", &id);
    s.door_expires_at = Some(s.issued_at + 7 * DAY + 1);
    refused(&h, h.build(&s).bytes, StatusCode::BAD_REQUEST, "bad_door").await;
    let s = h.spec("Bad_Name", &id);
    refused(
        &h,
        h.build(&s).bytes,
        StatusCode::BAD_REQUEST,
        "bad_listing",
    )
    .await;
    // A closed door (no door at all) is fine.
    let mut s = h.spec("params", &id);
    s.door_expires_at = None;
    h.publish(&s).await;
}

#[tokio::test]
async fn seq_must_rise_across_versions_and_tombstones() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("seq-test", &id);
    s.seq = 5;
    h.publish(&s).await;
    for seq in [4, 5] {
        let mut older = s.clone();
        older.seq = seq;
        older.description = format!("version {seq}");
        refused(&h, h.build(&older).bytes, StatusCode::CONFLICT, "stale_seq").await;
    }
    let mut newer = s.clone();
    newer.seq = 6;
    h.publish(&newer).await;
    assert_eq!(h.record("seq-test").await.unwrap().seq, 6);
    // After a withdrawal, the withdrawn seq and anything below stay out.
    let w = h
        .post("/v0/withdrawals", h.withdrawal("seq-test", &id, 6))
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.text());
    refused(&h, h.build(&newer).bytes, StatusCode::CONFLICT, "stale_seq").await;
    let mut back = s.clone();
    back.seq = 7;
    h.publish(&back).await;
}

#[tokio::test]
async fn withdrawal_is_immediate_and_writes_a_tombstone_and_a_feed_entry() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("going", &id);
    s.seq = 3;
    h.publish(&s).await;
    assert_eq!(h.get("/a/going.json").await.status, StatusCode::OK);
    let wd = h.withdrawal("going", &id, 3);
    let r = h.post("/v0/withdrawals", wd.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["withdrawn"], "going");
    assert_eq!(r.json()["changed"], true);
    for path in ["/a/going", "/a/going.json", "/a/going.md"] {
        let g = h.get(path).await;
        assert_eq!(g.status, StatusCode::GONE, "{path}");
        assert_eq!(
            g.header("cache-control").as_deref(),
            Some("public, max-age=60")
        );
    }
    let search = h.get("/search?q=going").await.json();
    assert_eq!(search["results"], json!([]));
    // A repeat changes nothing.
    let again = h.post("/v0/withdrawals", wd.clone()).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json()["changed"], false);
    // The feed carries the signed entry, verbatim once canonicalised.
    let feed = h.get("/v0/withdrawals?after=0").await.json();
    assert_eq!(feed["entries"].as_array().unwrap().len(), 1);
    let entry = &feed["entries"][0];
    assert_eq!(entry["kind"], "withdrawal");
    assert_eq!(jcs(&entry["entry"]).unwrap(), wd);
    let cursor = feed["next"].as_i64().unwrap();
    let after = h
        .get(&format!("/v0/withdrawals?after={cursor}"))
        .await
        .json();
    assert_eq!(after["entries"], json!([]));
    assert_eq!(after["next"], cursor);
}

#[tokio::test]
async fn withdrawals_are_checked() {
    let h = Harness::new();
    let (id, other) = (identity(), identity());
    let mut s = h.spec("held", &id);
    s.seq = 4;
    h.publish(&s).await;
    let post = |b: Vec<u8>| h.post("/v0/withdrawals", b);
    // Unsigned (tampered after signing).
    let mut w: Value = serde_json::from_slice(&h.withdrawal("held", &id, 4)).unwrap();
    w["seq"] = json!(9);
    let r = post(jcs(&w).unwrap()).await;
    assert_eq!(
        (r.status, r.json()["code"].clone()),
        (StatusCode::FORBIDDEN, json!("bad_signature"))
    );
    // By another identity.
    let r = post(h.withdrawal("held", &other, 4)).await;
    assert_eq!(r.json()["code"], "wrong_identity");
    // Below the listed seq.
    let r = post(h.withdrawal("held", &id, 3)).await;
    assert_eq!(r.json()["code"], "stale_seq");
    // Unknown name.
    let r = post(h.withdrawal("nobody", &id, 1)).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // Stale timestamp.
    let old = h.withdrawal("held", &id, 4);
    h.advance(301);
    let r = post(old).await;
    assert_eq!(r.json()["code"], "stale_ts");
    // Another directory.
    let mut w: Value = serde_json::from_slice(&h.withdrawal("held", &id, 4)).unwrap();
    w["directory"] = json!("elsewhere.test");
    let bytes = jcs(&w).unwrap();
    h.verifier.sign(&bytes);
    assert_eq!(post(bytes).await.json()["code"], "wrong_directory");
    // Not canonical.
    let r = post(b"{ \"v\": 0 }".to_vec()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(h.record("held").await.is_some());
}

#[tokio::test]
async fn token_revocation_withdraws_the_listing_and_bars_the_token() {
    let h = Harness::new();
    let id = identity();
    let s = h.spec("revoked", &id);
    h.publish(&s).await;
    let rev = h.revocation(&s.token_id);
    let r = h.post("/v0/revocations", rev.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["changed"], true);
    assert_eq!(h.get("/a/revoked").await.status, StatusCode::GONE);
    let again = h.post("/v0/revocations", rev).await;
    assert_eq!(again.json()["changed"], false);
    let mut next = s.clone();
    next.seq = 2;
    let r = h.post("/v0/listings", h.build(&next).bytes).await;
    assert_eq!(r.json()["code"], "token_revoked");
    let feed = h.get("/v0/withdrawals").await.json();
    assert_eq!(feed["entries"][0]["kind"], "token_revocation");
    // An unsigned revocation is refused.
    let mut forged: Value = serde_json::from_slice(&h.revocation(&random_b64(16))).unwrap();
    forged["token_id"] = json!(random_b64(16));
    let r = h.post("/v0/revocations", jcs(&forged).unwrap()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expired_tokens_hide_the_listing() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("short-lived", &id);
    s.token_expires_at = h.now() + DAY;
    h.publish(&s).await;
    assert_eq!(h.get("/a/short-lived").await.status, StatusCode::OK);
    h.advance(DAY);
    assert_eq!(h.get("/a/short-lived").await.status, StatusCode::GONE);
    assert_eq!(h.get("/search").await.json()["results"], json!([]));
}

#[tokio::test]
async fn a_build_without_a_verifier_accepts_nothing() {
    use std::sync::Arc;

    use agentconnect_core::clock::FakeClock;
    use agentconnect_directory::verify::Unavailable;
    use agentconnect_directory::{Directory, MemoryStore, Settings};

    let h = Harness::new();
    let dir = Directory::new(
        MemoryStore::new(),
        Arc::new(Unavailable),
        h.fetcher.clone(),
        Arc::new(FakeClock::default()),
        Settings {
            host: HOST.into(),
            relays: vec![common::RELAY.into()],
        },
    );
    let b = h.build(&h.spec("anything", &identity()));
    let e = dir.publish(&b.bytes).await.unwrap_err();
    assert_eq!((e.status, e.code), (503, "unavailable"));
    assert_eq!(dir.withdraw(b"{}").await.unwrap_err().status, 503);
    assert_eq!(dir.revoke(b"{}").await.unwrap_err().status, 503);
}

#[tokio::test]
async fn the_well_known_file_lists_the_operator_keys() {
    let h = Harness::new();
    let r = h.get("/.well-known/agentconnect-directory.json").await;
    assert_eq!(r.status, StatusCode::OK);
    let v = r.json();
    assert_eq!(v["directory"], HOST);
    assert_eq!(v["relays"], json!([common::RELAY]));
    assert_eq!(v["token_keys"][0]["key_id"], "test-key");
}
