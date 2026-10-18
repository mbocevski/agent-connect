//! Regression tests for the PR #30 review findings (H1, M1-M3, L1-L9,
//! N1-N4).

mod common;

use std::net::IpAddr;

use agentconnect_directory::owner::{FetchError, OwnerState, owner_state};
use agentconnect_directory::ratelimit::{Limit, Limits};
use axum::body::Body;
use axum::http::{HeaderName, Request, StatusCode};
use common::{DAY, HOST, Harness, identity};
use serde_json::json;

fn revoking(id: &str) -> serde_json::Value {
    json!({"v": 0, "revoked": [{"identity": id, "revoked_at": 1, "reason": "compromised"}]})
}

/// H1: a withdrawn listing's public bytes stay refused for good.
#[tokio::test]
async fn h1_tombstones_outlive_maintenance() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("replayed", &id);
    s.door_expires_at = None;
    let b = h.publish(&s).await;
    let w = h
        .post("/v0/withdrawals", h.withdrawal("replayed", &id, 1))
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.text());
    h.advance(31 * DAY);
    h.dir.maintain().await.unwrap();
    let r = h.post("/v0/listings", b.bytes.clone()).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.text());
    assert_eq!(r.code(), "name_held");
    assert_ne!(h.get("/a/replayed").await.status, StatusCode::OK);
}

/// H1: the same after an owner-domain revocation, with the owner's server
/// down at replay time.
#[tokio::test]
async fn h1_owner_revoked_listing_stays_down_after_maintenance() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("ownrev", &id);
    s.door_expires_at = None;
    s.owner_domain = Some("owner.example".into());
    h.fetcher.vouch("owner.example", &id.id());
    let b = h.publish(&s).await;
    h.fetcher.serve("owner.example", &revoking(&id.id()));
    h.advance(7 * 3600);
    h.dir.maintain().await.unwrap();
    assert_eq!(h.get("/a/ownrev").await.status, StatusCode::GONE);
    h.advance(31 * DAY);
    h.dir.maintain().await.unwrap();
    h.fetcher.fail("owner.example", FetchError::Timeout);
    let r = h.post("/v0/listings", b.bytes.clone()).await;
    assert!(r.status.is_client_error(), "{} {}", r.status, r.text());
    assert_ne!(h.get("/a/ownrev").await.status, StatusCode::OK);
}

/// M1: an identity its owner domain revoked can't relist the name, with or
/// without `owner_domain`, until a token issued after the revocation.
#[tokio::test]
async fn m1_owner_revoked_identity_needs_a_later_token() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("relist", &id);
    s.owner_domain = Some("owner.example".into());
    h.fetcher.vouch("owner.example", &id.id());
    h.publish(&s).await;
    h.fetcher.serve("owner.example", &revoking(&id.id()));
    h.advance(7 * 3600);
    h.dir.maintain().await.unwrap();
    assert_eq!(h.get("/a/relist").await.status, StatusCode::GONE);
    for domain in [None, Some("other.example")] {
        let mut again = h.spec("relist", &id);
        again.seq = 2;
        again.owner_domain = domain.map(str::to_owned);
        let r = h.post("/v0/listings", h.build(&again).bytes).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{domain:?}: {}", r.text());
        assert_eq!(r.code(), "owner_revoked", "{domain:?}");
    }
    // N4: a token dated inside the publish skew of the revocation could
    // predate it, so it isn't newer.
    h.advance(60);
    let mut early = h.spec("relist", &id);
    early.seq = 3;
    early.token_issued_at = h.now();
    early.owner_domain = None;
    let r = h.post("/v0/listings", h.build(&early).bytes).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.text());
    assert_eq!(r.code(), "owner_revoked");
    // The operator issues a new token well after the revocation.
    h.advance(241);
    let mut fresh = h.spec("relist", &id);
    fresh.seq = 4;
    fresh.token_issued_at = h.now();
    fresh.owner_domain = None;
    let r = h.post("/v0/listings", h.build(&fresh).bytes).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
}

/// N1: withdrawing before the recheck doesn't escape the owner's
/// revocation: the withdrawal checks the domain and records it.
#[tokio::test]
async fn n1_withdrawing_first_keeps_the_revocation() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("dodge", &id);
    s.owner_domain = Some("owner.example".into());
    h.fetcher.vouch("owner.example", &id.id());
    h.publish(&s).await;
    h.fetcher.serve("owner.example", &revoking(&id.id()));
    let w = h
        .post("/v0/withdrawals", h.withdrawal("dodge", &id, 1))
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.text());
    // The owner's server is down when the key comes back: the recorded
    // revocation still holds, with or without a domain.
    h.fetcher.fail("owner.example", FetchError::Timeout);
    h.fetcher.vouch("attacker.example", &id.id());
    for domain in [None, Some("attacker.example")] {
        let mut again = h.spec("dodge", &id);
        again.seq = 2;
        again.owner_domain = domain.map(str::to_owned);
        let r = h.post("/v0/listings", h.build(&again).bytes).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{domain:?}: {}", r.text());
        assert_eq!(r.code(), "owner_revoked", "{domain:?}");
    }
}

/// N1: a replacement that drops or changes the owner domain is checked
/// against the previous domain first.
#[tokio::test]
async fn n1_dropping_the_domain_checks_it_first() {
    for domain in [None, Some("attacker.example")] {
        let h = Harness::new();
        let id = identity();
        let mut s = h.spec("leaver", &id);
        s.owner_domain = Some("owner.example".into());
        h.fetcher.vouch("owner.example", &id.id());
        h.fetcher.vouch("attacker.example", &id.id());
        h.publish(&s).await;
        h.fetcher.serve("owner.example", &revoking(&id.id()));
        let mut again = h.spec("leaver", &id);
        again.seq = 2;
        again.owner_domain = domain.map(str::to_owned);
        let r = h.post("/v0/listings", h.build(&again).bytes).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{domain:?}: {}", r.text());
        assert_eq!(r.code(), "owner_revoked", "{domain:?}");
        // Recorded: a later try with the owner down is refused too.
        h.fetcher.fail("owner.example", FetchError::Timeout);
        again.seq = 3;
        let r = h.post("/v0/listings", h.build(&again).bytes).await;
        assert_eq!(r.code(), "owner_revoked", "{domain:?}");
    }
}

/// N1: an unreachable previous domain isn't a revocation, and a change of
/// domain shows the banner.
#[tokio::test]
async fn n1_domain_changes_show_the_banner() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("mover", &id);
    s.door_expires_at = None;
    s.owner_domain = Some("old.example".into());
    h.fetcher.vouch("old.example", &id.id());
    h.fetcher.vouch("new.example", &id.id());
    h.publish(&s).await;
    assert!(
        !h.get("/a/mover")
            .await
            .text()
            .contains("The key or owner domain changed on")
    );
    h.fetcher.fail("old.example", FetchError::Timeout);
    s.seq = 2;
    s.owner_domain = Some("new.example".into());
    let r = h.post("/v0/listings", h.build(&s).bytes).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    let today = agentconnect_directory::render::date(h.now());
    let banner = format!("The key or owner domain changed on {today}.");
    assert!(h.get("/a/mover").await.text().contains(&banner));
    // Same domain again: no new change.
    h.advance(31 * DAY);
    s.seq = 3;
    s.token_issued_at = h.now();
    let r = h.post("/v0/listings", h.build(&s).bytes).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    assert!(!h.get("/a/mover").await.text().contains("changed on"));
}

const PROXY: &str = "10.0.0.5";

fn from(path: &str, xff: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path).header("host", HOST);
    if let Some(x) = xff {
        b = b.header("x-forwarded-for", x);
    }
    b.body(Body::empty()).unwrap()
}

fn tight() -> Limits {
    let l = |max| Limit {
        max,
        window_secs: 60,
    };
    Limits {
        read: l(2),
        search: l(2),
        mcp: l(2),
        write: l(5),
        write_name: l(2),
        max_windows: 10_000,
    }
}

/// M2: the client-address header is believed only from a trusted proxy.
#[tokio::test]
async fn m2_client_ip_header_only_from_trusted_proxies() {
    let mut h = Harness::with(|d| d.with_limits(tight()));
    h.http.client_ip_header = Some(HeaderName::from_static("x-forwarded-for"));
    h.http.trusted_proxies =
        vec![agentconnect_directory::config::Cidr::parse("10.0.0.0/8").unwrap()];
    let direct: IpAddr = "198.51.100.9".parse().unwrap();
    // A direct client can't pick its own bucket.
    for i in 0..2 {
        let r = h
            .send_from(from("/healthz", Some(&format!("203.0.113.{i}"))), direct)
            .await;
        assert_eq!(r.status, StatusCode::OK);
    }
    let r = h
        .send_from(from("/healthz", Some("203.0.113.99")), direct)
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // Through the proxy, each client has its own bucket.
    let proxy: IpAddr = PROXY.parse().unwrap();
    for client in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        let r = h.send_from(from("/healthz", Some(client)), proxy).await;
        assert_eq!(r.status, StatusCode::OK, "{client}");
    }
}

/// N3: behind a chain of trusted proxies the first untrusted hop from the
/// right is the client; entries a client prepends don't move its bucket.
#[tokio::test]
async fn n3_forwarded_chains_walk_past_trusted_proxies() {
    let mut h = Harness::with(|d| d.with_limits(tight()));
    h.http.client_ip_header = Some(HeaderName::from_static("x-forwarded-for"));
    h.http.trusted_proxies =
        vec![agentconnect_directory::config::Cidr::parse("10.0.0.0/8").unwrap()];
    let proxy: IpAddr = PROXY.parse().unwrap();
    for xff in [
        "203.0.113.7, 10.0.0.9",
        "198.51.100.1, 203.0.113.7, 10.0.0.9",
    ] {
        let r = h.send_from(from("/healthz", Some(xff)), proxy).await;
        assert_eq!(r.status, StatusCode::OK, "{xff}");
    }
    let r = h
        .send_from(
            from("/healthz", Some("192.0.2.200, 203.0.113.7, 10.0.0.9")),
            proxy,
        )
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // Another client behind the same chain has its own bucket.
    let r = h
        .send_from(from("/healthz", Some("203.0.113.8, 10.0.0.9")), proxy)
        .await;
    assert_eq!(r.status, StatusCode::OK);
}

/// M2: one client flooding one name doesn't block publishing other names.
#[tokio::test]
async fn m2_write_limits_are_per_name_too() {
    let h = Harness::with(|d| d.with_limits(tight()));
    let id = identity();
    for _ in 0..2 {
        let r = h
            .post("/v0/withdrawals", h.withdrawal("flooded", &id, 1))
            .await;
        assert_ne!(r.status, StatusCode::TOO_MANY_REQUESTS);
    }
    let r = h
        .post("/v0/withdrawals", h.withdrawal("flooded", &id, 1))
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let r = h
        .post(
            "/v0/listings",
            h.build(&h.spec("other-name", &identity())).bytes,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
}

/// M3: overlapping owner checks of one version can't lose a negative.
#[tokio::test]
async fn m3_concurrent_owner_checks_keep_the_negative() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("racy", &id);
    s.owner_domain = Some("owner.example".into());
    h.fetcher.vouch("owner.example", &id.id());
    h.publish(&s).await;
    h.advance(3600);
    let snap = h.record("racy").await.unwrap();
    h.fetcher.fail("owner.example", FetchError::Timeout);
    let gate = h.fetcher.hold();
    let dir = h.dir.clone();
    let a_snap = snap.clone();
    let a = tokio::spawn(async move { dir.check_owner(&a_snap).await });
    tokio::task::yield_now().await;
    h.fetcher
        .serve("owner.example", &json!({"v": 0, "identities": []}));
    h.dir.check_owner(&snap).await.unwrap();
    let _ = gate.send(());
    a.await.unwrap().unwrap();
    let end = h.record("racy").await.unwrap();
    assert_eq!(
        owner_state(Some("owner.example"), &end.owner, h.now()),
        OwnerState::Failed,
        "{:?}",
        end.owner
    );
}

/// L1: an expired listing is no longer owner-checked, and is purged.
#[tokio::test]
async fn l1_expired_listings_are_not_checked_and_are_purged() {
    let h = Harness::new();
    let id = identity();
    let mut s = h.spec("expiring", &id);
    s.owner_domain = Some("owner.example".into());
    s.token_expires_at = h.now() + 2 * DAY;
    h.fetcher.vouch("owner.example", &id.id());
    h.publish(&s).await;
    h.advance(10 * DAY);
    let before = h.fetcher.calls.load(std::sync::atomic::Ordering::Relaxed);
    h.dir.maintain().await.unwrap();
    h.advance(7 * 3600);
    h.dir.maintain().await.unwrap();
    assert_eq!(
        h.fetcher.calls.load(std::sync::atomic::Ordering::Relaxed),
        before
    );
    h.advance(31 * DAY);
    h.dir.maintain().await.unwrap();
    assert!(h.record("expiring").await.is_none());
}

/// L2: a search is a search however its query keys are spelled.
#[tokio::test]
async fn l2_encoded_query_keys_count_as_searches() {
    let h = Harness::with(|d| d.with_limits(tight()));
    for _ in 0..2 {
        assert_eq!(h.get("/?q=x").await.status, StatusCode::OK);
    }
    assert_eq!(h.get("/?%71=x").await.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        h.get("/index.md?%73kill=general").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// L4: the resolver asks for the name as an FQDN, and 6to4 relays are
/// blocked.
#[test]
fn l4_fqdn_lookup_and_6to4_relay_block() {
    assert_eq!(
        agentconnect_directory::owner::fqdn("owner.example"),
        "owner.example."
    );
    assert!(!agentconnect_core::net::is_public_ip(
        "192.88.99.1".parse().unwrap()
    ));
}

/// L5: Markdown only when it has the highest q, and a bad q is q=0.
#[tokio::test]
async fn l5_accept_q_values() {
    let h = Harness::new();
    h.publish(&h.spec("accepts", &identity())).await;
    for (accept, markdown) in [
        ("text/markdown;q=NaN", false),
        ("text/markdown;q=junk", false),
        ("text/html;q=1, text/markdown;q=0.01", false),
        ("text/markdown ;q=0", false),
        ("text/markdown, text/html;q=0.9", true),
        ("text/markdown;q=0.9, text/html;q=0.5", true),
    ] {
        let r = h.get_with("/a/accepts", &[("accept", accept)]).await;
        let ct = r.header("content-type").unwrap();
        assert_eq!(ct.starts_with("text/markdown"), markdown, "{accept}");
    }
    let etag = h.get("/a/accepts.json").await.header("etag").unwrap();
    let r = h
        .get_with(
            "/a/accepts.json",
            &[("if-none-match", &format!("W/{etag}"))],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_MODIFIED);
}

fn mcp(host: &str, origin: Option<&str>, body: &serde_json::Value) -> Request<Body> {
    let mut b = Request::post("/mcp")
        .header("host", host)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25");
    if let Some(o) = origin {
        b = b.header("origin", o);
    }
    b.body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// L6: MCP checks `Origin`; L7: bad arguments still answer `untrusted`.
#[tokio::test]
async fn l6_l7_mcp_origin_and_bad_arguments() {
    let h = Harness::new();
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "search_agents", "arguments": {"q": "x"}}});
    let r = h
        .send(mcp(HOST, Some("https://evil-origin.example"), &call))
        .await;
    assert!(r.status.is_client_error(), "{} {}", r.status, r.text());
    let r = h
        .send(mcp(HOST, Some(&format!("https://{HOST}")), &call))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let bad = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "get_card", "arguments": {"name": 5}}});
    let r = h.send(mcp(HOST, None, &bad)).await;
    let v = r.json();
    assert_eq!(v["result"]["structuredContent"]["untrusted"], true, "{v}");
}

/// L9: `llms.txt` lists every listed name, past any run of `failed` ones.
#[tokio::test]
async fn l9_llms_txt_lists_every_name() {
    let h = Harness::with(|d| d.with_page_size(4));
    // Failed listings sort first, more than a page of them...
    for i in 0..9 {
        let id = identity();
        let mut s = h.spec(&format!("aaa-failed-{i:02}"), &id);
        s.owner_domain = Some("owner.example".into());
        h.publish(&s).await;
    }
    // ...and one good listing after them.
    h.publish(&h.spec("zzz-good", &identity())).await;
    let t = h.get("/llms.txt").await.text();
    assert!(t.contains("[zzz-good]"), "{t}");
    let home = h.get("/").await.text();
    assert!(home.contains("zzz-good"));
}

/// L9: `/metrics` can move to its own (private) listener.
#[tokio::test]
async fn l9_metrics_on_a_separate_listener() {
    use tower::ServiceExt as _;
    let mut h = Harness::new();
    assert_eq!(h.get("/metrics").await.status, StatusCode::OK);
    h.http.hide_metrics = true;
    assert_eq!(h.get("/metrics").await.status, StatusCode::NOT_FOUND);
    let r = agentconnect_directory::http::metrics_app(h.dir.clone())
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // The sweep runs on its own timer and forgets idle windows.
    h.dir.sweep_limits();
}

/// L9: listing names pages through the store past a full page.
#[tokio::test]
async fn l9_listing_names_page_through_the_store() {
    let h = Harness::with(|d| d.with_page_size(4));
    for i in 0..9 {
        let id = identity();
        let mut s = h.spec(&format!("n-{i:03}"), &id);
        s.door_expires_at = None;
        // Straight to the directory, without the HTTP rate limits.
        h.dir.publish(&h.build(&s).bytes).await.unwrap();
    }
    let all = h.dir.listed(10_000).await.unwrap();
    assert_eq!(all.len(), 9);
    assert_eq!(all.last().unwrap().record.name, "n-008");
    assert_eq!(h.dir.listed(3).await.unwrap().len(), 3);
    // Withdrawal through the directory API as well.
    let id = identity();
    let s = h.spec("direct", &id);
    h.dir.publish(&h.build(&s).bytes).await.unwrap();
    let w = h
        .dir
        .withdraw(&h.withdrawal("direct", &id, 1))
        .await
        .unwrap();
    assert!(w.changed);
}
