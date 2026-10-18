//! Publish, withdraw and revoke (ADR-006 Decision 6), over HTTP, with the
//! core verifier.

mod common;

use agentconnect_core::encoding::b64;
use agentconnect_core::listing::{DirectoryKey, Withdrawal};
use axum::http::StatusCode;
use common::{DAY, HOST, Harness, Issuer, identity, rng};
use serde_json::json;

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
    let rec = h.record("release-planner").await.unwrap();
    assert_eq!(rec.token_id, b64(&b.token.token_id));
    assert_eq!(rec.token_expires_at, b.token.grant.expires_at);
}

async fn refused(h: &Harness, bytes: Vec<u8>, status: StatusCode, code: &str) {
    let r = h.post("/v0/listings", bytes).await;
    assert_eq!(r.status, status, "{}", r.text());
    assert_eq!(r.code(), code, "{}", r.text());
}

#[tokio::test]
async fn tampered_and_malformed_bodies_are_refused() {
    let h = Harness::new();
    let b = h.build(&h.spec("signed", &identity()));
    let text = String::from_utf8(b.bytes.clone()).unwrap();
    let tampered = text.replacen("does things", "does others", 1);
    refused(
        &h,
        tampered.into_bytes(),
        StatusCode::FORBIDDEN,
        "bad_signature",
    )
    .await;
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&b.bytes).unwrap())
            .unwrap();
    refused(&h, pretty, StatusCode::BAD_REQUEST, "bad_listing").await;
    refused(
        &h,
        b"not json".to_vec(),
        StatusCode::BAD_REQUEST,
        "bad_listing",
    )
    .await;
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
    // Issued by a key this directory doesn't pin.
    let mut s = h.spec("tok", &id);
    s.issuer = Issuer::Stranger;
    refused(&h, h.build(&s).bytes, StatusCode::FORBIDDEN, "unknown_key").await;
    // Issued to another identity: a mismatch the core refuses at parse time.
    let mut s = h.spec("tok", &id);
    s.token_identity = Some(identity().id());
    assert!(
        h.try_build(&s).is_err(),
        "the core refuses to sign a mismatched token"
    );
    // A token for another directory can't be signed into a valid card.
    let mut s = h.spec("tok", &id);
    s.token_directory = "elsewhere.test".into();
    assert!(h.try_build(&s).is_err());
    // Expired.
    let mut s = h.spec("tok", &id);
    s.token_issued_at = h.now() - 10 * DAY;
    s.token_expires_at = h.now();
    refused(&h, h.build(&s).bytes, StatusCode::FORBIDDEN, "bad_token").await;
    // Pins a domain the listing doesn't claim.
    let mut s = h.spec("tok", &id);
    s.token_domain = Some("example.com".into());
    assert!(
        h.try_build(&s).is_err(),
        "the core refuses to sign a mismatched token"
    );
    // A token for another name can't even be signed into a valid card.
    let other = h.build(&h.spec("other-name", &id)).token;
    let mut s = h.spec("tok", &id);
    s.token = Some(other);
    assert!(h.try_build(&s).is_err());
    assert!(h.record("tok").await.is_none());
    // With the pinned domain claimed, it is accepted.
    let mut s = h.spec("tok", &id);
    s.token_domain = Some("example.com".into());
    s.owner_domain = Some("example.com".into());
    h.publish(&s).await;
}

#[tokio::test]
async fn listing_params_are_checked_against_this_directory() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("params", &id);
    s.directory = "elsewhere.test".into();
    s.token_directory = "elsewhere.test".into();
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
    refused(&h, h.build(&s).bytes, StatusCode::BAD_REQUEST, "stale_ts").await;
    // A door that has expired by the time it is published.
    let mut s = h.spec("params", &id);
    s.issued_at = h.now() - 2 * DAY;
    s.door_expires_at = Some(h.now());
    refused(&h, h.build(&s).bytes, StatusCode::BAD_REQUEST, "bad_door").await;
    // A door past 7 days can't be signed at all.
    let mut s = h.spec("params", &id);
    s.door_expires_at = Some(s.issued_at + 7 * DAY + 1);
    assert!(h.try_build(&s).is_err());
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
        refused(&h, h.build(&older).bytes, StatusCode::CONFLICT, "name_held").await;
    }
    let mut newer = s.clone();
    newer.seq = 6;
    let newer_bytes = h.publish(&newer).await.bytes;
    assert_eq!(h.record("seq-test").await.unwrap().seq, 6);
    // After a withdrawal, the withdrawn seq and anything below stay out.
    let w = h
        .post("/v0/withdrawals", h.withdrawal("seq-test", &id, 6))
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.text());
    refused(&h, newer_bytes, StatusCode::CONFLICT, "name_held").await;
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
    assert_eq!(h.get("/search?q=going").await.json()["results"], json!([]));
    let again = h.post("/v0/withdrawals", wd.clone()).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json()["changed"], false);
    // The feed entry re-encodes to the signed bytes, and the core verifies it.
    let feed = h.get("/v0/withdrawals?after=0").await.json();
    assert_eq!(feed["entries"].as_array().unwrap().len(), 1);
    let entry = &feed["entries"][0];
    assert_eq!(entry["kind"], "withdrawal");
    let bytes = agentconnect_core::encoding::jcs(&entry["entry"]).unwrap();
    assert_eq!(bytes, wd);
    Withdrawal::from_json(&bytes).unwrap();
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
    // Tampered after signing.
    let tampered = String::from_utf8(h.withdrawal("held", &id, 4))
        .unwrap()
        .replacen("\"seq\":4", "\"seq\":9", 1);
    let r = post(tampered.into_bytes()).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, json!("bad_signature"))
    );
    // By another identity.
    let r = post(h.withdrawal("held", &other, 4)).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, json!("wrong_identity"))
    );
    // Below the listed seq.
    let r = post(h.withdrawal("held", &id, 3)).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::CONFLICT, json!("stale_seq"))
    );
    // Unknown name.
    assert_eq!(
        post(h.withdrawal("nobody", &id, 1)).await.status,
        StatusCode::NOT_FOUND
    );
    // Stale timestamp.
    let old = h.withdrawal("held", &id, 4);
    h.advance(301);
    assert_eq!(post(old).await.code(), "stale_ts");
    // Another directory.
    let elsewhere = Withdrawal::sign(&id, "elsewhere.test", "held", 4, h.now())
        .unwrap()
        .to_json()
        .unwrap();
    assert_eq!(post(elsewhere).await.code(), "wrong_directory");
    // Not canonical.
    assert_eq!(
        post(b"{ \"v\": 0 }".to_vec()).await.status,
        StatusCode::BAD_REQUEST
    );
    assert!(h.record("held").await.is_some());
}

#[tokio::test]
async fn token_revocation_withdraws_the_listing_and_bars_the_token() {
    let h = Harness::new();
    let id = identity();
    let s = h.spec("revoked", &id);
    let b = h.publish(&s).await;
    let rev = h.revocation(&b.token);
    let r = h.post("/v0/revocations", rev.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["changed"], true);
    assert_eq!(h.get("/a/revoked").await.status, StatusCode::GONE);
    assert_eq!(
        h.post("/v0/revocations", rev).await.json()["changed"],
        false
    );
    let mut next = s.clone();
    next.seq = 2;
    next.token = Some(b.token.clone());
    refused(
        &h,
        h.build(&next).bytes,
        StatusCode::FORBIDDEN,
        "token_revoked",
    )
    .await;
    assert_eq!(
        h.get("/v0/withdrawals").await.json()["entries"][0]["kind"],
        "token_revocation"
    );
    // A revocation by a key this directory doesn't pin.
    let stranger = DirectoryKey::generate(&rng()).unwrap();
    let forged = stranger
        .revoke_token(&b.token.token_id, h.now(), "spam")
        .unwrap()
        .to_json()
        .unwrap();
    let r = h.post("/v0/revocations", forged).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, json!("unknown_key"))
    );
    // Tampered.
    let t = String::from_utf8(h.revocation(&b.token))
        .unwrap()
        .replacen("spam", "spam!", 1);
    let r = h.post("/v0/revocations", t.into_bytes()).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::FORBIDDEN, json!("bad_signature"))
    );
    assert_eq!(
        h.post("/v0/revocations", b"{}".to_vec()).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn expired_tokens_hide_the_listing() {
    let h = Harness::new();
    let mut s = h.spec("short-lived", &identity());
    s.token_expires_at = h.now() + DAY;
    h.publish(&s).await;
    assert_eq!(h.get("/a/short-lived").await.status, StatusCode::OK);
    h.advance(DAY);
    assert_eq!(h.get("/a/short-lived").await.status, StatusCode::GONE);
    assert_eq!(h.get("/search").await.json()["results"], json!([]));
}

#[tokio::test]
async fn the_well_known_file_lists_the_pinned_keys() {
    let h = Harness::new();
    let v = h
        .get("/.well-known/agentconnect-directory.json")
        .await
        .json();
    assert_eq!(v["directory"], HOST);
    assert_eq!(v["relays"], json!([common::RELAY]));
    assert_eq!(v["token_keys"][0]["public_key"], b64(&h.dk.public_key()));
    assert_eq!(v["token_keys"][0]["key_id"], b64(&h.dk.key_id()));
}
