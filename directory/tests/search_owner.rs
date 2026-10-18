//! Search over HTTP, and owner verification (ADR-006 Decision 2).

mod common;

use agentconnect_directory::owner::FetchError;
use axum::http::StatusCode;
use common::{DAY, Harness, identity};
use serde_json::{Value, json};

fn names(v: &Value) -> Vec<String> {
    v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_owned())
        .collect()
}

async fn seed(h: &Harness) {
    let mut a = h.spec("release-planner", &identity());
    a.card_name = "Release planner".into();
    a.description = "Plans release trains.".into();
    a.skills = vec![(
        "rp",
        "Release planning",
        &["release planning", "scheduling"],
    )];
    let mut b = h.spec("code-reviewer", &identity());
    b.card_name = "Code reviewer".into();
    b.description = "Reviews pull requests before a release.".into();
    b.skills = vec![("cr", "Code review", &["code review"])];
    let mut c = h.spec("pg-helper", &identity());
    c.card_name = "Postgres helper".into();
    c.description = "Tunes queries.".into();
    c.skills = vec![("pg", "Postgres", &["postgres"])];
    for s in [a, b, c] {
        h.publish(&s).await;
    }
}

#[tokio::test]
async fn search_ranks_names_above_descriptions_and_filters_by_skill() {
    let h = Harness::new();
    seed(&h).await;
    let r = h.get("/search?q=release").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.header("content-type").as_deref(),
        Some("application/json")
    );
    let v = r.json();
    assert_eq!(v["untrusted"], true);
    assert_eq!(names(&v), ["release-planner", "code-reviewer"]);
    let first = &v["results"][0];
    assert_eq!(
        first["card"]["skills"],
        json!(["release planning", "scheduling"])
    );
    assert_eq!(first["door"]["state"], "open");
    assert_eq!(first["owner"]["state"], "unclaimed");
    assert_eq!(first["fingerprint"].as_str().unwrap().len(), 39);
    assert!(
        first["knock"]
            .as_str()
            .unwrap()
            .starts_with("agentconnect knock directory.example.org/a/")
    );
    assert_eq!(
        names(&h.get("/search?skill=code+review").await.json()),
        ["code-reviewer"]
    );
    assert_eq!(
        names(&h.get("/search?skill=Postgres").await.json()),
        ["pg-helper"]
    );
    assert_eq!(
        names(&h.get("/search?q=release&skill=scheduling").await.json()),
        ["release-planner"]
    );
    assert_eq!(
        names(&h.get("/search?q=release+-planner").await.json()),
        ["code-reviewer"]
    );
    assert_eq!(
        names(&h.get("/search?q=nothingmatches").await.json()),
        Vec::<String>::new()
    );
    assert_eq!(names(&h.get("/search").await.json()).len(), 3);
    // The home page shows the same results.
    let home = h.get("/?skill=postgres").await.text();
    assert!(home.contains("pg-helper") && !home.contains("code-reviewer"));
    assert!(
        h.get("/?q=nothingmatches")
            .await
            .text()
            .contains("No listing matches.")
    );
    let md = h.get("/index.md?q=release").await.text();
    assert!(
        md.contains("- release-planner: https://directory.example.org/a/release-planner.md"),
        "{md}"
    );
}

#[tokio::test]
async fn a_verified_owner_shows_the_organization() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("owned", &id);
    s.owner_domain = Some("example.com".into());
    s.organization = Some("Example Ltd".into());
    h.fetcher.vouch("example.com", &id.id());
    let r = h.post("/v0/listings", h.build(&s).bytes).await;
    assert_eq!(r.json()["owner_state"], "verified");
    let v = h.get("/search?q=owned").await.json();
    assert_eq!(
        v["results"][0]["owner"],
        json!({"state": "verified", "domain": "example.com"})
    );
    assert_eq!(v["results"][0]["card"]["organization"], "Example Ltd");
}

#[tokio::test]
async fn owner_states_move_from_verified_to_stale_to_failed() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("aging", &id);
    s.owner_domain = Some("example.com".into());
    s.organization = Some("Example Ltd".into());
    h.fetcher.vouch("example.com", &id.id());
    h.publish(&s).await;
    let page = || async { h.get("/a/aging.md").await.text() };
    assert!(page().await.contains("verified by example.com"));
    // The domain stops answering: verified for 24 h, then stale.
    h.fetcher.fail("example.com", FetchError::Timeout);
    h.advance(6 * 3600);
    assert_eq!(h.dir.recheck_due().await.unwrap(), 1);
    assert!(page().await.contains("verified by example.com"));
    h.advance(19 * 3600);
    h.dir.recheck_due().await.unwrap();
    let md = page().await;
    assert!(
        md.contains("last verified by example.com on 2025-01-01"),
        "{md}"
    );
    assert!(
        !md.contains("Example Ltd"),
        "organization hidden unless verified"
    );
    assert_eq!(names(&h.get("/search?q=aging").await.json()), ["aging"]);
    // No success for 7 days: failed, out of search, still served.
    h.advance(6 * DAY);
    h.dir.recheck_due().await.unwrap();
    assert!(page().await.contains("not vouched for by example.com"));
    assert_eq!(
        names(&h.get("/search?q=aging").await.json()),
        Vec::<String>::new()
    );
    assert_eq!(h.get("/a/aging").await.status, StatusCode::OK);
    // It vouches again.
    h.fetcher.vouch("example.com", &id.id());
    h.advance(6 * 3600);
    h.dir.recheck_due().await.unwrap();
    assert!(page().await.contains("verified by example.com"));
}

#[tokio::test]
async fn a_file_that_does_not_list_the_key_fails_at_once() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("unvouched", &id);
    s.owner_domain = Some("example.com".into());
    h.fetcher.vouch("example.com", &identity().id());
    let r = h.post("/v0/listings", h.build(&s).bytes).await;
    assert_eq!(r.json()["owner_state"], "failed");
    assert!(
        h.get("/a/unvouched")
            .await
            .text()
            .contains("not vouched for by example.com")
    );
    assert_eq!(names(&h.get("/search").await.json()), Vec::<String>::new());
    // Scoped to other listings only.
    h.fetcher.serve(
        "example.com",
        &json!({"v": 0, "identities": [{"identity": id.id(), "listings": ["directory.example.org/a/other"]}]}),
    );
    h.advance(6 * 3600);
    h.dir.recheck_due().await.unwrap();
    assert!(
        h.get("/a/unvouched.md")
            .await
            .text()
            .contains("not vouched for")
    );
    h.fetcher.serve(
        "example.com",
        &json!({"v": 0, "identities": [{"identity": id.id(), "listings": ["directory.example.org/a/unvouched"]}]}),
    );
    h.advance(6 * 3600);
    h.dir.recheck_due().await.unwrap();
    assert!(
        h.get("/a/unvouched.md")
            .await
            .text()
            .contains("verified by example.com")
    );
}

#[tokio::test]
async fn a_failed_first_fetch_is_never_assumed_good() {
    let h = Harness::new();
    let mut s = h.spec("unreachable", &identity());
    s.owner_domain = Some("example.com".into());
    h.fetcher.fail("example.com", FetchError::Blocked);
    let r = h.post("/v0/listings", h.build(&s).bytes).await;
    assert_eq!(r.json()["owner_state"], "failed");
    // An invalid file counts as a failed check, too.
    h.fetcher.serve("example.com", &json!("not an object"));
    let id = identity();
    let mut s2 = h.spec("invalid-file", &id);
    s2.owner_domain = Some("example.com".into());
    let r = h.post("/v0/listings", h.build(&s2).bytes).await;
    assert_eq!(r.json()["owner_state"], "failed");
}

#[tokio::test]
async fn a_revoked_key_is_withdrawn_with_a_feed_entry() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("compromised", &id);
    s.owner_domain = Some("example.com".into());
    h.fetcher.vouch("example.com", &id.id());
    h.publish(&s).await;
    h.fetcher.serve(
        "example.com",
        &json!({"v": 0, "identities": [], "revoked": [{"identity": id.id(), "revoked_at": 1, "reason": "compromised"}]}),
    );
    h.advance(6 * 3600);
    h.dir.recheck_due().await.unwrap();
    for path in ["/a/compromised", "/a/compromised.json", "/a/compromised.md"] {
        assert_eq!(h.get(path).await.status, StatusCode::GONE, "{path}");
    }
    assert!(
        h.get("/a/compromised")
            .await
            .text()
            .contains("its owner domain revoked the key")
    );
    let feed = h.get("/v0/withdrawals").await.json();
    let e = &feed["entries"][0];
    assert_eq!(e["kind"], "owner_revocation");
    assert_eq!(e["entry"]["identity"], id.id());
    assert_eq!(e["entry"]["reason"], "compromised");
}

#[tokio::test]
async fn a_withdrawal_rechecks_the_identitys_other_listings() {
    let h = Harness::new();
    let id = identity();
    let mut a = h.spec("first-name", &id);
    a.owner_domain = Some("example.com".into());
    let mut b = h.spec("second-name", &id);
    b.owner_domain = Some("example.com".into());
    h.fetcher.vouch("example.com", &id.id());
    h.publish(&a).await;
    h.publish(&b).await;
    let before = h.fetcher.calls.load(std::sync::atomic::Ordering::Relaxed);
    let r = h
        .post("/v0/withdrawals", h.withdrawal("first-name", &id, 1))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // One fetch checks the withdrawn listing's own domain, one rechecks
    // the identity's other listing.
    assert_eq!(
        h.fetcher.calls.load(std::sync::atomic::Ordering::Relaxed),
        before + 2
    );
}

#[tokio::test]
async fn maintenance_keeps_tombstones() {
    let h = Harness::new();
    let id = identity();
    h.publish(&h.spec("purged", &id)).await;
    h.post("/v0/withdrawals", h.withdrawal("purged", &id, 1))
        .await;
    assert_eq!(h.get("/a/purged").await.status, StatusCode::GONE);
    h.advance(30 * DAY);
    h.dir.maintain().await.unwrap();
    assert_eq!(h.get("/a/purged").await.status, StatusCode::GONE);
}
