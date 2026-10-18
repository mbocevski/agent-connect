//! The core's shared vectors, end to end through Heimdall: `listings.json`
//! and `withdrawals.json` through the HTTP publish and withdraw endpoints on
//! the in-memory store; `listing-tokens.json` through the revocation
//! endpoint and the verifier's token check; `owner-files.json` through the
//! verifier and the owner-state mapping. Keys come from the files.

mod common;

use agentconnect_core::encoding::{b64, hex};
use agentconnect_core::listing::{ListingToken, SignedListing};
use agentconnect_directory::Store;
use agentconnect_directory::owner::{OwnerState, owner_state};
use agentconnect_directory::store::{ListingRecord, OwnerCheck, OwnerStatus, SearchDoc};
use agentconnect_directory::verify::{CoreVerifier, OwnerVerdict, Rejection, Verifier};
use axum::http::StatusCode;
use common::{Harness, Resp};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn params(listing: &str) -> Value {
    let card: Value = serde_json::from_str(listing).unwrap();
    card["capabilities"]["extensions"][0]["params"].clone()
}

fn keys(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|k| s(k).to_owned())
        .collect()
}

/// A directory for `listing`'s host and relay pinning `keys`, at `now`.
fn harness(listing: &str, keys: &[String], now: u64) -> Harness {
    let p = params(listing);
    Harness::pinned(s(&p["directory"]), s(&p["relay"]), keys, Some(now), |d| d)
}

/// A freshly generated operator public key, base64url.
fn fresh_key() -> String {
    b64(
        &agentconnect_core::listing::DirectoryKey::generate(&common::rng())
            .unwrap()
            .public_key(),
    )
}

/// The core's message after its `"invalid <thing>: "` prefix.
fn reason(error: &str) -> &str {
    error.split_once(": ").map_or(error, |(_, r)| r)
}

fn assert_refused(r: &Resp, status: StatusCode, code: &str, detail: &str, name: &str) {
    assert_eq!(r.status, status, "{name}: {}", r.text());
    assert_eq!(r.code(), code, "{name}: {}", r.text());
    assert_eq!(r.json()["detail"], detail, "{name}");
}

#[tokio::test]
async fn the_valid_listing_publishes_and_is_served_byte_for_byte() {
    let v = load("listings.json");
    let valid = &v["valid"];
    let listing = s(&valid["listing"]);
    let h = harness(
        listing,
        &keys(&v["directory_keys"]),
        valid["now"].as_u64().unwrap(),
    );
    let r = h.post("/v0/listings", listing.as_bytes().to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    assert_eq!(r.json()["url"], valid["url"]);
    let name = s(&valid["name"]);
    let card = h.get(&format!("/a/{name}.json")).await;
    assert_eq!(card.body, listing.as_bytes());
    assert_eq!(
        card.header("etag").unwrap(),
        format!("\"{}\"", s(&valid["sha256"]))
    );
    let rec = h.record(name).await.unwrap();
    assert_eq!(rec.seq, valid["seq"].as_u64().unwrap());
    assert_eq!(rec.identity, s(&valid["identity"]));
    assert_eq!(rec.token_id, s(&valid["token_id"]));
    assert_eq!(rec.door_expires_at, valid["door_expires_at"].as_u64());
    let md = h.get(&format!("/a/{name}.md")).await.text();
    assert!(md.contains(s(&valid["fingerprint"])), "{md}");
    let found = h.get("/search?q=release").await.json();
    assert_eq!(
        found["results"].as_array().map(Vec::len),
        Some(0),
        "unverified owner: failed, out of search"
    );
}

#[tokio::test]
async fn every_invalid_listing_is_refused_with_the_cores_reason() {
    let v = load("listings.json");
    let now = v["valid"]["now"].as_u64().unwrap();
    let invalid = v["invalid"].as_array().unwrap();
    assert_eq!(invalid.len(), 14);
    for case in invalid {
        let name = s(&case["name"]);
        let listing = s(&case["listing"]);
        let h = harness(s(&v["valid"]["listing"]), &keys(&v["directory_keys"]), now);
        let r = h.post("/v0/listings", listing.as_bytes().to_vec()).await;
        let why = reason(s(&case["error"]));
        if why == "signature" {
            assert_refused(
                &r,
                StatusCode::FORBIDDEN,
                "bad_signature",
                "signature does not verify",
                name,
            );
        } else {
            assert_refused(&r, StatusCode::BAD_REQUEST, "bad_listing", why, name);
        }
        assert!(
            h.get("/search").await.json()["results"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn every_failed_publish_and_token_check_is_refused() {
    let v = load("listings.json");
    let checks = v["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 6);
    for case in checks {
        let name = s(&case["name"]);
        let listing = s(&case["listing"]);
        let now = case["now"].as_u64().unwrap();
        let why = reason(s(&case["error"]));
        // The unpinned-key case runs against the other operator key.
        let pinned = if why == "unknown key_id" {
            vec![s(&v["other_directory_key"]).to_owned()]
        } else {
            keys(&v["directory_keys"])
        };
        let h = harness(listing, &pinned, now);
        if let Some(revoked) = case["revoked"].as_str() {
            h.store().revoke_token(revoked, "{}", now).await.unwrap();
        }
        let r = h.post("/v0/listings", listing.as_bytes().to_vec()).await;
        match (s(&case["check"]), why) {
            ("publish", "door has expired") => {
                assert_refused(
                    &r,
                    StatusCode::BAD_REQUEST,
                    "bad_door",
                    "the door has expired",
                    name,
                );
            }
            ("publish", why) => {
                assert_refused(&r, StatusCode::BAD_REQUEST, "bad_listing", why, name)
            }
            ("token", "unknown key_id") => assert_refused(
                &r,
                StatusCode::FORBIDDEN,
                "unknown_key",
                "not signed by a pinned operator key",
                name,
            ),
            ("token", "revoked") => assert_refused(
                &r,
                StatusCode::FORBIDDEN,
                "token_revoked",
                "token has been revoked",
                name,
            ),
            ("token", why) => assert_refused(&r, StatusCode::FORBIDDEN, "bad_token", why, name),
            (check, _) => panic!("unknown check {check}"),
        }
        let p = params(listing);
        assert!(h.record(s(&p["name"])).await.is_none(), "{name}");
    }
}

#[tokio::test]
async fn token_vectors_go_through_the_verifier_and_the_revocation_endpoint() {
    let v = load("listing-tokens.json");
    let dir = s(&v["directory"]);
    let pinned = vec![s(&v["directory_key"]).to_owned()];
    let verifier = CoreVerifier::new(dir, &pinned).unwrap();
    assert_eq!(verifier.token_keys()[0].key_id, s(&v["key_id"]));
    let valid = &v["valid"];
    let token = ListingToken::from_json(s(&valid["token"]).as_bytes()).unwrap();
    let now = valid["now"].as_u64().unwrap();
    let owner = token.grant.owner_domain.clone();
    let binding = (
        dir,
        token.grant.name.as_str(),
        s(&valid["identity"]),
        owner.as_deref(),
    );
    assert_eq!(verifier.check_listing_token(&token, binding, now), Ok(()));

    for case in v["binding_invalid"].as_array().unwrap() {
        let b = (
            s(&case["directory"]),
            s(&case["listing_name"]),
            s(&case["identity"]),
            case["owner_domain"].as_str(),
        );
        assert_eq!(
            verifier.check_listing_token(&token, b, now),
            Err(Rejection::BadToken(reason_static(s(&case["error"])))),
            "{}",
            s(&case["name"])
        );
    }
    for case in v["verify_invalid"].as_array().unwrap() {
        let name = s(&case["name"]);
        let why = reason(s(&case["error"]));
        let parsed = ListingToken::from_json(s(&case["token"]).as_bytes());
        let Ok(t) = parsed else {
            // Encoding and lifetime errors are format errors of the token.
            assert!(matches!(why, "encoding" | "lifetime"), "{name}: {parsed:?}");
            continue;
        };
        let v2 = CoreVerifier::new(dir, &[s(&case["directory_key"]).to_owned()]).unwrap();
        let b = (
            dir,
            t.grant.name.as_str(),
            t.grant.identity.as_str(),
            t.grant.owner_domain.as_deref(),
        );
        let got = v2.check_listing_token(&t, b, case["now"].as_u64().unwrap());
        let want = if why == "unknown key_id" {
            Rejection::UnknownKey
        } else {
            Rejection::BadToken(reason_static(s(&case["error"])))
        };
        assert_eq!(got, Err(want), "{name}");
    }

    // The revocation through the HTTP endpoint.
    let rev = &v["revocation"];
    let h = Harness::pinned(dir, "relay.example", &pinned, Some(now), |d| d);
    let r = h
        .post("/v0/revocations", s(&rev["revocation"]).as_bytes().to_vec())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["changed"], true);
    let feed = h.get("/v0/withdrawals").await.json();
    assert_eq!(feed["entries"][0]["kind"], "token_revocation");
    let r = h
        .post("/v0/revocations", s(&rev["tampered"]).as_bytes().to_vec())
        .await;
    assert_eq!(reason(s(&rev["tampered_error"])), "revocation signature");
    assert_refused(
        &r,
        StatusCode::FORBIDDEN,
        "bad_signature",
        "signature does not verify",
        "tampered",
    );
}

/// The core's reasons are `&'static str`; find the one a vector names.
fn reason_static(error: &str) -> &'static str {
    const REASONS: &[&str] = &[
        "bound to another directory",
        "bound to another name",
        "bound to another identity",
        "bound to another owner domain",
        "signature",
        "expired",
        "lifetime",
        "encoding",
        "directory",
    ];
    let r = reason(error);
    REASONS
        .iter()
        .copied()
        .find(|x| *x == r)
        .unwrap_or_else(|| panic!("unknown reason {r}"))
}

/// Store the withdrawal vectors' listing as if published: its token is
/// signed by a key the file doesn't publish, so it can't go through
/// `POST /v0/listings`.
async fn seed(h: &Harness, listing: &str, now: u64) {
    let l = SignedListing::from_bytes(listing.as_bytes()).unwrap();
    let p = l.params();
    let rec = ListingRecord {
        name: p.name.clone(),
        identity: p.identity.clone(),
        seq: p.seq,
        token_id: b64(&l.token().token_id),
        owner_domain: p.owner_domain.clone(),
        owner: OwnerStatus::PENDING,
        door_expires_at: p.door.as_ref().map(|d| d.expires_at),
        token_expires_at: l.token().grant.expires_at,
        published_at: now,
        key_changed_at: None,
        bytes: l.bytes().to_vec(),
        sha256: hex(&l.sha256()),
        search: SearchDoc::default(),
    };
    h.store().publish(&rec).await.unwrap();
}

#[tokio::test]
async fn withdrawal_vectors_through_the_endpoint() {
    let v = load("withdrawals.json");
    let listing = s(&v["listing"]);
    let name = s(&params(listing)["name"]).to_owned();
    let valid = &v["valid"];
    let w = s(&valid["withdrawal"]).as_bytes().to_vec();
    let fresh = |t: &Value| t.as_u64().unwrap();
    // Withdrawals involve no token, so any pinned key will do.
    let keys = vec![fresh_key()];
    for at in valid["fresh_at"].as_array().unwrap() {
        let h = harness(listing, &keys, fresh(at));
        seed(&h, listing, fresh(at)).await;
        let r = h.post("/v0/withdrawals", w.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "at {at}: {}", r.text());
        assert_eq!(r.json()["changed"], true);
        assert_eq!(
            h.get(&format!("/a/{name}.json")).await.status,
            StatusCode::GONE
        );
    }
    for at in valid["stale_at"].as_array().unwrap() {
        let h = harness(listing, &keys, fresh(at));
        seed(&h, listing, fresh(at)).await;
        let r = h.post("/v0/withdrawals", w.clone()).await;
        assert_eq!(reason(s(&valid["stale_error"])), "ts not within 300 s");
        assert_refused(
            &r,
            StatusCode::BAD_REQUEST,
            "stale_ts",
            "ts must be within 300 s of the directory clock",
            "stale",
        );
        assert!(h.record(&name).await.is_some());
    }
    let at = fresh(&valid["fresh_at"][0]);
    for case in v["invalid"].as_array().unwrap() {
        let h = harness(listing, &keys, at);
        seed(&h, listing, at).await;
        let r = h
            .post(
                "/v0/withdrawals",
                s(&case["withdrawal"]).as_bytes().to_vec(),
            )
            .await;
        let why = reason(s(&case["error"]));
        if why == "signature" {
            assert_refused(
                &r,
                StatusCode::FORBIDDEN,
                "bad_signature",
                "signature does not verify",
                s(&case["name"]),
            );
        } else {
            assert_refused(
                &r,
                StatusCode::BAD_REQUEST,
                "bad_request",
                why,
                s(&case["name"]),
            );
        }
        assert!(h.record(&name).await.is_some());
    }
    // A withdrawal of an older seq doesn't apply to the listed version.
    assert_eq!(v["old_seq"]["applies"], false);
    let h = harness(listing, &keys, at);
    seed(&h, listing, at).await;
    let r = h
        .post(
            "/v0/withdrawals",
            s(&v["old_seq"]["withdrawal"]).as_bytes().to_vec(),
        )
        .await;
    assert_refused(
        &r,
        StatusCode::CONFLICT,
        "stale_seq",
        "seq is below the listed seq",
        "old seq",
    );
    assert!(h.record(&name).await.is_some());
}

#[test]
fn owner_file_vectors_through_the_verifier() {
    let v = load("owner-files.json");
    for f in v["files"].as_array().unwrap() {
        for r in f["results"].as_array().unwrap() {
            let verifier = CoreVerifier::new(s(&r["directory"]), &[fresh_key()]).unwrap();
            let got =
                verifier.owner_verdict(s(&f["file"]).as_bytes(), s(&r["identity"]), s(&r["name"]));
            let want = match s(&r["vouch"]) {
                "vouches" => matches!(got, OwnerVerdict::Vouched),
                "does_not_vouch" => matches!(got, OwnerVerdict::NotVouched),
                "revoked" => matches!(got, OwnerVerdict::Revoked { .. }),
                other => panic!("unknown vouch {other}"),
            };
            assert!(want, "{}: {got:?}", s(&f["name"]));
        }
    }
}

#[test]
fn owner_state_vectors_through_the_stored_history() {
    let v = load("owner-files.json");
    for case in v["states"].as_array().unwrap() {
        let last = match case["latest_result"].as_str() {
            None => OwnerCheck::Pending,
            Some("vouches") => OwnerCheck::Vouched,
            Some("does_not_vouch") => OwnerCheck::NotVouched,
            Some("failed") => OwnerCheck::Error,
            // A revocation withdraws the listing; it is never stored.
            Some("revoked") => continue,
            Some(other) => panic!("unknown result {other}"),
        };
        let status = OwnerStatus {
            last,
            checked_at: case["latest_at"].as_u64(),
            verified_at: case["last_vouched_at"].as_u64(),
        };
        let got = owner_state(
            case["owner_domain"].as_str(),
            &status,
            case["now"].as_u64().unwrap(),
        );
        let want = match s(&case["state"]) {
            "unchecked" => OwnerState::Checking,
            "verified" => OwnerState::Verified,
            "unclaimed" => OwnerState::Unclaimed,
            "stale" => OwnerState::Stale,
            "failed" => OwnerState::Failed,
            other => panic!("unknown state {other}"),
        };
        assert_eq!(got, want, "{case}");
    }
}

#[tokio::test]
async fn a_revoking_owner_file_withdraws_the_vector_listing() {
    let v = load("listings.json");
    let valid = &v["valid"];
    let listing = s(&valid["listing"]);
    let h = harness(
        listing,
        &keys(&v["directory_keys"]),
        valid["now"].as_u64().unwrap(),
    );
    let identity = s(&valid["identity"]);
    h.fetcher.serve(
        "example.com",
        &serde_json::json!({"v": 0, "revoked": [{"identity": identity, "reason": "compromised"}]}),
    );
    let r = h.post("/v0/listings", listing.as_bytes().to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    assert_eq!(h.get("/a/release-planner").await.status, StatusCode::GONE);
    let feed = h.get("/v0/withdrawals").await.json();
    assert_eq!(feed["entries"][0]["kind"], "owner_revocation");
    assert_eq!(feed["entries"][0]["entry"]["reason"], "compromised");
    // Vouched by the same file shape instead: verified.
    let h = harness(
        listing,
        &keys(&v["directory_keys"]),
        valid["now"].as_u64().unwrap(),
    );
    h.fetcher.vouch("example.com", identity);
    let r = h.post("/v0/listings", listing.as_bytes().to_vec()).await;
    assert_eq!(r.json()["owner_state"], "verified");
    let md = h.get("/a/release-planner.md").await.text();
    assert!(md.contains("owner verified · example.com"));
}
