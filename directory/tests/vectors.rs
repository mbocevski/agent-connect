//! The core's shared vectors, end to end through the directory's HTTP endpoints
//! on the in-memory store: `listings.json`, `listing-tokens.json`,
//! `withdrawals.json` and `owner-files.json`. Every key and secret comes
//! from the files; refusals are compared by the core's error kind.

mod common;

use agentconnect_core::encoding::b64;
use agentconnect_core::listing::{ListingToken, TokenGrant};
use axum::http::StatusCode;
use common::{Agent, Harness, Resp, Spec, agent_from_hex, directory_key_from_hex, identity, rng};
use serde_json::{Value, json};

fn load(name: &str) -> Value {
    let path = format!("{}/../testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

fn n(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("not an integer: {v}"))
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

/// The core's message after its `"invalid <thing>: "` prefix.
fn reason(error: &str) -> &str {
    error.split_once(": ").map_or(error, |(_, r)| r)
}

/// The HTTP status and code the directory answers for a core error kind.
fn expected(kind: &str, malformed: &'static str) -> (StatusCode, &'static str) {
    match kind {
        "signature" => (StatusCode::FORBIDDEN, "bad_signature"),
        "unknown_key" => (StatusCode::FORBIDDEN, "unknown_key"),
        "expired" | "not_yet_valid" | "token_mismatch" => (StatusCode::FORBIDDEN, "bad_token"),
        "revoked" => (StatusCode::FORBIDDEN, "token_revoked"),
        "superseded" => (StatusCode::CONFLICT, "name_held"),
        "door_expired" => (StatusCode::BAD_REQUEST, "bad_door"),
        "wrong_directory" => (StatusCode::BAD_REQUEST, "wrong_directory"),
        "stale_timestamp" => (StatusCode::BAD_REQUEST, "stale_ts"),
        "malformed" | "unsupported_version" => (StatusCode::BAD_REQUEST, malformed),
        other => panic!("unexpected kind {other}"),
    }
}

/// Assert a refusal of the core error `case` (with `kind` and `error`).
fn assert_core_refusal(r: &Resp, case: &Value, malformed: &'static str) {
    let name = case["name"].as_str().unwrap_or("case");
    let kind = s(&case["kind"]);
    let (status, code) = expected(kind, malformed);
    assert_eq!(r.status, status, "{name}: {}", r.text());
    let body = r.json();
    assert_eq!(body["code"], code, "{name}: {body}");
    if kind == "revoked" {
        // Revocation is the store's check, not the core's.
        assert_eq!(body["detail"], "token has been revoked", "{name}");
    } else {
        assert_eq!(body["kind"], kind, "{name}: {body}");
        assert_eq!(body["detail"], reason(s(&case["error"])), "{name}");
    }
}

/// The identity among `ids` (`{"identity", "ik_secret"}`) with id `id`.
fn agent(ids: &Value, id: &str) -> Agent {
    let e = ids
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["identity"] == id)
        .unwrap_or_else(|| panic!("no secret for {id}"));
    agent_from_hex(s(&e["ik_secret"]))
}

/// A listing spec on `h` for `agent` under `token`, with no door.
fn spec(h: &Harness, name: &str, agent: &Agent, token: ListingToken, issued_at: u64) -> Spec {
    let mut sp = h.spec(name, agent);
    sp.directory.clone_from(&token.grant.directory);
    sp.relay.clone_from(&h.dir.settings().relays[0]);
    sp.owner_domain.clone_from(&token.grant.owner_domain);
    sp.issued_at = issued_at;
    sp.door_expires_at = None;
    sp.token = Some(token);
    sp
}

fn grant(directory: &str, name: &str, identity: &str, issued_at: u64) -> TokenGrant {
    TokenGrant {
        directory: directory.to_owned(),
        name: name.to_owned(),
        identity: identity.to_owned(),
        owner_domain: Some("example.com".into()),
        issued_at,
        expires_at: issued_at + 30 * 86_400,
    }
}

// --- listings.json -------------------------------------------------------

#[tokio::test]
async fn the_valid_listing_publishes_and_is_served_byte_for_byte() {
    let v = load("listings.json");
    let valid = &v["valid"];
    let listing = s(&valid["listing"]);
    let h = harness(listing, &keys(&v["directory_keys"]), n(&valid["now"]));
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
    assert_eq!(rec.seq, n(&valid["seq"]));
    assert_eq!(rec.identity, s(&valid["identity"]));
    assert_eq!(rec.token_id, s(&valid["token_id"]));
    assert_eq!(rec.door_expires_at, valid["door_expires_at"].as_u64());
    let md = h.get(&format!("/a/{name}.md")).await.text();
    assert!(md.contains(s(&valid["fingerprint"])), "{md}");
    // Re-posting the same bytes is idempotent.
    let again = h.post("/v0/listings", listing.as_bytes().to_vec()).await;
    assert_eq!(again.status, StatusCode::OK);
}

#[tokio::test]
async fn every_invalid_listing_is_refused_with_the_cores_kind() {
    let v = load("listings.json");
    let invalid = v["invalid"].as_array().unwrap();
    assert_eq!(invalid.len(), 30);
    for case in invalid {
        let h = harness(
            s(&v["valid"]["listing"]),
            &keys(&v["directory_keys"]),
            n(&v["valid"]["now"]),
        );
        let r = h
            .post("/v0/listings", s(&case["listing"]).as_bytes().to_vec())
            .await;
        assert_core_refusal(&r, case, "bad_listing");
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
    let dk = directory_key_from_hex(s(&v["directory_key_secret"]));
    let checks = v["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 7);
    for case in checks {
        let name = s(&case["name"]);
        let listing = s(&case["listing"]);
        let now = n(&case["now"]);
        let h = harness(listing, &keys(&case["directory_keys"]), now);
        if let Some(revoked) = case["revoked"].as_str() {
            // The operator revokes the token through the endpoint first.
            let id: [u8; 16] =
                agentconnect_core::encoding::b64_decode_array(revoked, "token_id").unwrap();
            let rev = dk
                .revoke_token(&id, now, "spam")
                .unwrap()
                .to_json()
                .unwrap();
            let r = h.post("/v0/revocations", rev).await;
            assert_eq!(r.status, StatusCode::OK, "{name}: {}", r.text());
        }
        let r = h.post("/v0/listings", listing.as_bytes().to_vec()).await;
        assert_core_refusal(&r, case, "bad_listing");
        assert!(
            h.record(s(&params(listing)["name"])).await.is_none(),
            "{name}"
        );
    }
}

#[tokio::test]
async fn replacements_follow_seq_per_identity_and_later_tokens() {
    let v = load("listings.json");
    let stored = s(&v["stored_listing"]);
    let now = n(&v["valid"]["now"]) + 120;
    let name = s(&params(stored)["name"]).to_owned();
    for case in v["replacements"].as_array().unwrap() {
        let label = s(&case["name"]);
        let h = harness(stored, &keys(&v["directory_keys"]), now);
        let r = h.post("/v0/listings", stored.as_bytes().to_vec()).await;
        assert_eq!(r.status, StatusCode::CREATED, "{label}: {}", r.text());
        let new = s(&case["listing"]);
        let r = h.post("/v0/listings", new.as_bytes().to_vec()).await;
        let same_identity = params(new)["identity"] == params(stored)["identity"];
        if case["replaces"] == true {
            assert_eq!(r.status, StatusCode::CREATED, "{label}: {}", r.text());
            assert_eq!(h.get(&format!("/a/{name}.json")).await.body, new.as_bytes());
            let md = h.get(&format!("/a/{name}.md")).await.text();
            assert_eq!(
                md.contains("The key or owner domain changed on"),
                !same_identity,
                "{label}"
            );
        } else {
            assert_eq!(r.status, StatusCode::CONFLICT, "{label}: {}", r.text());
            assert_eq!(r.code(), "name_held", "{label}");
            assert_eq!(r.json()["kind"], "superseded", "{label}");
            assert_eq!(
                h.get(&format!("/a/{name}.json")).await.body,
                stored.as_bytes()
            );
        }
    }
}

#[tokio::test]
async fn tombstones_block_only_their_own_identity() {
    let v = load("listings.json");
    let stored = s(&v["stored_listing"]);
    let sp = params(stored);
    let now = n(&v["valid"]["now"]);
    let dk = directory_key_from_hex(s(&v["directory_key_secret"]));
    let name = s(&sp["name"]);
    let directory = s(&sp["directory"]);
    for case in v["tombstones"].as_array().unwrap() {
        let label = s(&case["name"]);
        let h = harness(stored, &keys(&v["directory_keys"]), now);
        let holder = agent(&v["identities"], s(&case["identity"]));
        let seq = n(&case["seq"]);
        // List the name as the tombstone's identity at its seq, under a token
        // no newer than the stored listing's, then withdraw it.
        let token = dk
            .issue_token(&rng(), &grant(directory, name, &holder.id(), now - 60))
            .unwrap();
        let mut first = spec(&h, name, &holder, token, now - 60);
        first.seq = seq;
        h.publish(&first).await;
        let w = h
            .post("/v0/withdrawals", h.withdrawal(name, &holder, seq))
            .await;
        assert_eq!(w.status, StatusCode::OK, "{label}: {}", w.text());
        let r = h.post("/v0/listings", stored.as_bytes().to_vec()).await;
        if case["blocked"] == true {
            assert_eq!(
                (r.status, r.code()),
                (StatusCode::CONFLICT, json!("name_held")),
                "{label}"
            );
        } else {
            assert_eq!(r.status, StatusCode::CREATED, "{label}: {}", r.text());
        }
    }
}

#[tokio::test]
async fn an_old_key_cant_take_a_rotated_name_back() {
    let v = load("listings.json");
    let stored = s(&v["stored_listing"]);
    let now = n(&v["valid"]["now"]) + 120;
    let h = harness(stored, &keys(&v["directory_keys"]), now);
    assert_eq!(
        h.post("/v0/listings", stored.as_bytes().to_vec())
            .await
            .status,
        StatusCode::CREATED
    );
    let rotated = v["replacements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["replaces"] == true
                && params(s(&c["listing"]))["identity"] != params(stored)["identity"]
        })
        .unwrap();
    let new = s(&rotated["listing"]);
    assert_eq!(
        h.post("/v0/listings", new.as_bytes().to_vec()).await.status,
        StatusCode::CREATED
    );
    // The new holder withdraws; the old key's listing, at a higher seq,
    // still can't come back under its older token.
    let holder = agent(&v["identities"], s(&params(new)["identity"]));
    let w = h
        .post(
            "/v0/withdrawals",
            h.withdrawal(s(&params(new)["name"]), &holder, 1),
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.text());
    let higher = v["replacements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| s(&c["name"]) == "same identity, higher seq")
        .unwrap();
    let r = h
        .post("/v0/listings", s(&higher["listing"]).as_bytes().to_vec())
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::CONFLICT, json!("name_held"))
    );
}

#[tokio::test]
async fn the_name_history_replays_through_publish_and_withdraw() {
    let v = load("listings.json");
    let steps = v["name_history"].as_array().unwrap();
    let first = s(&steps[0]["listing"]);
    let h = harness(first, &keys(&v["directory_keys"]), n(&v["valid"]["now"]));
    let set = |t: u64| {
        h.clock
            .set(std::time::UNIX_EPOCH + std::time::Duration::from_secs(t));
    };
    for step in steps {
        let label = s(&step["name"]);
        if let Some(w) = step["withdrawal"].as_str() {
            let wv: Value = serde_json::from_str(w).unwrap();
            set(n(&wv["ts"]));
            let r = h.post("/v0/withdrawals", w.as_bytes().to_vec()).await;
            assert_eq!(r.status, StatusCode::OK, "{label}: {}", r.text());
            continue;
        }
        let listing = s(&step["listing"]);
        let p = params(listing);
        set(n(&p["token"]["issued_at"]).max(n(&p["issued_at"])));
        let r = h.post("/v0/listings", listing.as_bytes().to_vec()).await;
        if step["accepted"] == true {
            assert_eq!(r.status, StatusCode::CREATED, "{label}: {}", r.text());
            assert_eq!(
                h.get(&format!("/a/{}.json", s(&p["name"]))).await.body,
                listing.as_bytes(),
                "{label}"
            );
        } else {
            assert_core_refusal(&r, step, "bad_listing");
        }
    }
}

// --- listing-tokens.json -------------------------------------------------

/// A listing for the token's grant, signed by its identity's vector key.
fn token_listing(h: &Harness, ids: &Value, token: ListingToken) -> Vec<u8> {
    let holder = agent(ids, &token.grant.identity);
    let name = token.grant.name.clone();
    let issued = token.grant.issued_at;
    h.build(&spec(h, &name, &holder, token, issued)).bytes
}

#[tokio::test]
async fn token_vectors_through_publish_and_revocation() {
    let v = load("listing-tokens.json");
    let dir = s(&v["directory"]);
    let pinned = vec![s(&v["directory_key"]).to_owned()];
    let now = n(&v["valid"]["now"]);
    let relay = "relay.example";
    let valid = ListingToken::from_json(s(&v["valid"]["token"]).as_bytes()).unwrap();

    // The valid token publishes; the operator's revocation then withdraws it.
    let h = Harness::pinned(dir, relay, &pinned, Some(now), |d| d);
    let listing = token_listing(&h, &v["identities"], valid.clone());
    let r = h.post("/v0/listings", listing.clone()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    let wk = h
        .get("/.well-known/agentconnect-directory.json")
        .await
        .json();
    assert_eq!(wk["token_keys"][0]["key_id"], v["key_id"]);
    let rev = &v["revocation"];
    let tampered = h
        .post("/v0/revocations", s(&rev["tampered"]).as_bytes().to_vec())
        .await;
    assert_core_refusal(
        &tampered,
        &json!({"name": "tampered revocation", "kind": rev["tampered_kind"], "error": rev["tampered_error"]}),
        "bad_request",
    );
    let r = h
        .post("/v0/revocations", s(&rev["revocation"]).as_bytes().to_vec())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(
        revocation_token_id(s(&rev["revocation"])),
        b64(&valid.token_id)
    );
    {
        assert_eq!(
            h.get(&format!("/a/{}", valid.grant.name)).await.status,
            StatusCode::GONE
        );
        let again = h.post("/v0/listings", listing).await;
        assert_eq!(again.code(), "token_revoked");
    }

    // Every verify failure, embedded in a listing its identity signed.
    for case in v["verify_invalid"].as_array().unwrap() {
        let h = Harness::pinned(
            dir,
            relay,
            &[s(&case["directory_key"]).to_owned()],
            Some(n(&case["now"])),
            |d| d,
        );
        // Tokens that don't parse come with the listing the vector signed
        // around them; the others are signed into a card here.
        let (listing, expect) = match case["listing"].as_str() {
            // The listing's own refusal is named next to the token's.
            Some(l) => (
                l.as_bytes().to_vec(),
                json!({"name": case["name"], "kind": case["listing_kind"], "error": case["listing_error"]}),
            ),
            None => {
                let token = ListingToken::from_json(s(&case["token"]).as_bytes()).unwrap();
                (token_listing(&h, &v["identities"], token), case.clone())
            }
        };
        let r = h.post("/v0/listings", listing).await;
        assert_core_refusal(&r, &expect, "bad_listing");
    }

    // A token bound to other params, in the listing the vector signed.
    for case in v["binding_invalid"].as_array().unwrap() {
        let h = Harness::pinned(dir, relay, &pinned, Some(now), |d| d);
        let r = h
            .post("/v0/listings", s(&case["listing"]).as_bytes().to_vec())
            .await;
        assert_core_refusal(&r, case, "bad_listing");
    }
}

fn revocation_token_id(json: &str) -> String {
    let v: Value = serde_json::from_str(json).unwrap();
    s(&v["token_id"]).to_owned()
}

// --- withdrawals.json ----------------------------------------------------

/// A directory with the vector listing published at `publish_at`, its clock
/// then moved to `at`.
async fn listed(listing: &str, pinned: &[String], publish_at: u64, at: u64) -> Harness {
    let h = harness(listing, pinned, publish_at);
    let r = h.post("/v0/listings", listing.as_bytes().to_vec()).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    h.clock
        .set(std::time::UNIX_EPOCH + std::time::Duration::from_secs(at));
    h
}

#[tokio::test]
async fn withdrawal_vectors_through_the_endpoint() {
    let v = load("withdrawals.json");
    let listing = s(&v["listing"]);
    let lp = params(listing);
    let name = s(&lp["name"]).to_owned();
    let publish_at = n(&lp["issued_at"]);
    let valid = &v["valid"];
    let w = s(&valid["withdrawal"]).as_bytes().to_vec();
    let pinned = keys(&v["directory_keys"]);
    for at in valid["fresh_at"].as_array().unwrap() {
        let h = listed(listing, &pinned, publish_at, n(at)).await;
        let r = h.post("/v0/withdrawals", w.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "at {at}: {}", r.text());
        assert_eq!(r.json()["changed"], true);
        assert_eq!(
            h.get(&format!("/a/{name}.json")).await.status,
            StatusCode::GONE
        );
        // The listed identity's key (from the file) can sign a repeat.
        let owner = agent_from_hex(s(&v["identity_secret"]));
        assert_eq!(owner.id(), s(&lp["identity"]));
        let again = h
            .post(
                "/v0/withdrawals",
                h.withdrawal(&name, &owner, n(&lp["seq"])),
            )
            .await;
        assert_eq!(again.json()["changed"], false);
    }
    for at in valid["stale_at"].as_array().unwrap() {
        let h = listed(listing, &pinned, publish_at, n(at)).await;
        let r = h.post("/v0/withdrawals", w.clone()).await;
        assert_core_refusal(
            &r,
            &json!({"name": "stale", "kind": valid["stale_kind"], "error": valid["stale_error"]}),
            "bad_request",
        );
        assert!(h.record(&name).await.is_some());
    }
    let at = n(&valid["fresh_at"][0]);
    for case in v["invalid"].as_array().unwrap() {
        let h = listed(listing, &pinned, publish_at, at).await;
        let r = h
            .post(
                "/v0/withdrawals",
                s(&case["withdrawal"]).as_bytes().to_vec(),
            )
            .await;
        assert_core_refusal(&r, case, "bad_request");
        assert!(h.record(&name).await.is_some());
    }
    // A withdrawal of an older seq doesn't apply to the listed version.
    assert_eq!(v["old_seq"]["applies"], false);
    let h = listed(listing, &pinned, publish_at, at).await;
    let r = h
        .post(
            "/v0/withdrawals",
            s(&v["old_seq"]["withdrawal"]).as_bytes().to_vec(),
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::CONFLICT, json!("stale_seq"))
    );
    assert!(h.record(&name).await.is_some());
    // The valid withdrawal sent to another directory.
    let wd = &v["wrong_directory"];
    let other = Harness::pinned(
        s(&wd["directory"]),
        s(&lp["relay"]),
        &keys(&v["directory_keys"]),
        Some(n(&wd["now"])),
        |d| d,
    );
    let r = other.post("/v0/withdrawals", w.clone()).await;
    assert_core_refusal(&r, wd, "bad_request");
}

// --- owner-files.json ----------------------------------------------------

/// A directory for `directory` pinning a fresh operator key, with
/// `identity`'s listing of `name` claiming `example.com` built at `at`.
fn owner_listing(
    directory: &str,
    agent: &Agent,
    name: &str,
    domain: Option<&str>,
    at: u64,
) -> (Harness, Vec<u8>) {
    let key = agentconnect_core::listing::DirectoryKey::generate(&rng()).unwrap();
    let h = Harness::pinned(
        directory,
        "relay.example",
        &[b64(&key.public_key())],
        Some(at),
        |d| d,
    );
    let mut g = grant(directory, name, &agent.id(), at - 60);
    g.owner_domain = domain.map(str::to_owned);
    let token = key.issue_token(&rng(), &g).unwrap();
    let bytes = h.build(&spec(&h, name, agent, token, at - 60)).bytes;
    (h, bytes)
}

fn shown_state(md: &str) -> &'static str {
    let line = md
        .lines()
        .find(|l| l.starts_with("- Owner: "))
        .unwrap_or_default();
    if line.contains("Owner: verified by") {
        "verified"
    } else if line.contains("last verified by") {
        "stale"
    } else if line.contains("not vouched for") {
        "failed"
    } else if line.contains("Owner: checking") {
        "checking"
    } else if line.contains("no owner domain claimed") {
        "unclaimed"
    } else {
        panic!("no owner line in {md}")
    }
}

#[tokio::test]
async fn owner_files_are_fetched_at_publish() {
    let v = load("owner-files.json");
    for f in v["files"].as_array().unwrap() {
        for r in f["results"].as_array().unwrap() {
            let label = format!("{} / {}", s(&f["name"]), s(&r["name"]));
            let holder = agent(&v["identities"], s(&r["identity"]));
            let (h, bytes) = owner_listing(
                s(&r["directory"]),
                &holder,
                s(&r["name"]),
                Some("example.com"),
                1_792_497_600,
            );
            h.fetcher
                .serve_bytes("example.com", s(&f["file"]).as_bytes().to_vec());
            let resp = h.post("/v0/listings", bytes).await;
            assert_eq!(resp.status, StatusCode::CREATED, "{label}: {}", resp.text());
            let page = h.get(&format!("/a/{}.md", s(&r["name"]))).await;
            match s(&r["fetch_result"]) {
                "vouches" => assert_eq!(resp.json()["owner_state"], "verified", "{label}"),
                "does_not_vouch" | "failed" => {
                    assert_eq!(resp.json()["owner_state"], "failed", "{label}");
                    assert_eq!(shown_state(&page.text()), "failed", "{label}");
                }
                "revoked" => {
                    assert_eq!(page.status, StatusCode::GONE, "{label}");
                    let e = &h.get("/v0/withdrawals").await.json()["entries"][0];
                    assert_eq!(e["kind"], "owner_revocation", "{label}");
                    assert_eq!(e["entry"]["reason"], r["reason"], "{label}");
                    assert_eq!(e["entry"]["revoked_at"], r["revoked_at"], "{label}");
                }
                other => panic!("{label}: unknown result {other}"),
            }
        }
    }
}

fn serve(h: &Harness, holder: &Agent, result: &str) {
    match result {
        "vouches" => h.fetcher.vouch("example.com", &holder.id()),
        "does_not_vouch" => h
            .fetcher
            .serve("example.com", &json!({"v": 0, "identities": []})),
        "revoked" => h.fetcher.serve(
            "example.com",
            &json!({"v": 0, "revoked": [{"identity": holder.id(), "reason": "compromised"}]}),
        ),
        "failed" => h.fetcher.fail(
            "example.com",
            agentconnect_directory::owner::FetchError::Timeout,
        ),
        other => panic!("unknown result {other}"),
    }
}

#[tokio::test]
async fn owner_state_vectors_through_publish_and_rechecks() {
    let v = load("owner-files.json");
    let name = "release-planner";
    for case in v["states"].as_array().unwrap() {
        let label = s(&case["name"]);
        let fetches = case["fetches"].as_array().unwrap();
        let want = s(&case["state"]);
        if !case["applies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "directory")
        {
            continue;
        }
        let holder = identity();
        let now = n(&case["now"]);
        let first = fetches.first().map_or(now, |f| n(&f["at"]));
        let domain = case["owner_domain"].as_str();
        let (h, bytes) = owner_listing("agents.example", &holder, name, domain, first);
        if fetches.is_empty() {
            // "Checking": seen while the publish-time fetch is in flight.
            let release = h.fetcher.hold();
            h.fetcher.vouch("example.com", &holder.id());
            let publish = h.post("/v0/listings", bytes);
            let observe = async {
                while h.fetcher.calls.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                    tokio::task::yield_now().await;
                }
                let md = h.get(&format!("/a/{name}.md")).await.text();
                assert_eq!(shown_state(&md), want, "{label}");
                let _ = release.send(());
            };
            let (r, ()) = tokio::join!(publish, observe);
            assert_eq!(r.status, StatusCode::CREATED);
            continue;
        }
        serve(&h, &holder, s(&fetches[0]["result"]));
        let r = h.post("/v0/listings", bytes).await;
        assert_eq!(r.status, StatusCode::CREATED, "{label}: {}", r.text());
        let mut withdrawn = s(&fetches[0]["result"]) == "revoked" && domain.is_some();
        for f in &fetches[1..] {
            if withdrawn {
                break;
            }
            h.clock
                .set(std::time::UNIX_EPOCH + std::time::Duration::from_secs(n(&f["at"])));
            serve(&h, &holder, s(&f["result"]));
            let rec = h.record(name).await.unwrap();
            h.dir.check_owner(&rec).await.unwrap();
            withdrawn = s(&f["result"]) == "revoked";
        }
        h.clock
            .set(std::time::UNIX_EPOCH + std::time::Duration::from_secs(now));
        let page = h.get(&format!("/a/{name}.md")).await;
        if withdrawn {
            // A directory withdraws a listing whose owner state becomes
            // revoked (SPEC §13.2.4): every URL answers 410.
            assert_eq!(page.status, StatusCode::GONE, "{label}");
            assert_eq!(want, "revoked", "{label}");
        } else {
            assert_eq!(shown_state(&page.text()), want, "{label}");
        }
    }
}
