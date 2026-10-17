//! REST API (SPEC §8.1) and the signed-request auth.

mod common;

use std::time::Duration;

use agentconnect_relay::app;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{HOST, Harness, fresh_id, invite_body, mailbox_of, signed_request, signing_key};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn call(h: &Harness, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app(h.relay.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn create(h: &Harness, key: u8, body: &Value) -> (StatusCode, Value) {
    let bytes = body.to_string().into_bytes();
    let req = signed_request(
        &signing_key(key),
        "POST",
        "/v0/invites",
        &bytes,
        h.now_secs(),
        HOST,
    );
    call(h, req).await
}

fn body_for(h: &Harness, key: u8, id: &str) -> Value {
    invite_body(&mailbox_of(&signing_key(key)), id, h.now_secs() + 3600, 2)
}

#[tokio::test]
async fn create_get_and_revoke_an_invite() {
    let h = Harness::start().await;
    let id = fresh_id();
    let (status, meta) = create(&h, 1, &body_for(&h, 1, &id)).await;
    assert_eq!(status, StatusCode::CREATED, "{meta}");
    assert_eq!(meta["status"], "open");
    assert_eq!(meta["uses_left"], 2);
    assert_eq!(meta["max_uses"], 2);
    assert_eq!(meta["protocol"], 0);
    assert!(
        meta.get("inviter_mailbox").is_none(),
        "inviter mailbox is not public"
    );
    assert!(meta.get("member_count").is_none());

    let path = format!("/v0/invites/{id}");
    let (status, got) = call(&h, Request::get(&path).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, meta);

    let del = |key: u8| signed_request(&signing_key(key), "DELETE", &path, b"", h.now_secs(), HOST);
    let (status, err) = call(&h, del(2)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err["code"], "auth_failed");
    let (status, _) = call(&h, del(1)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, got) = call(&h, Request::get(&path).body(Body::empty()).unwrap()).await;
    assert_eq!(got["status"], "revoked");
    // Revoking twice is fine.
    assert_eq!(call(&h, del(1)).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn member_count_is_passed_through() {
    let h = Harness::start().await;
    let mut body = body_for(&h, 1, &fresh_id());
    body["member_count"] = json!(3);
    let (status, meta) = create(&h, 1, &body).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(meta["member_count"], 3);
}

#[tokio::test]
async fn unknown_invites_are_404() {
    let h = Harness::start().await;
    for id in [fresh_id(), "not-an-id".to_owned()] {
        let path = format!("/v0/invites/{id}");
        let (status, err) = call(&h, Request::get(&path).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], "invite_not_open");
        let req = signed_request(&signing_key(1), "DELETE", &path, b"", h.now_secs(), HOST);
        assert_eq!(call(&h, req).await.0, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn status_follows_uses_and_the_clock() {
    let h = Harness::start().await;
    let id = fresh_id();
    create(&h, 1, &body_for(&h, 1, &id)).await;
    let path = format!("/v0/invites/{id}");
    let req = || Request::get(&path).body(Body::empty()).unwrap();
    assert_eq!(call(&h, req()).await.1["status"], "open");
    h.clock.advance(Duration::from_secs(3600));
    assert_eq!(call(&h, req()).await.1["status"], "expired");
}

#[tokio::test]
async fn requests_without_valid_auth_are_refused() {
    let h = Harness::start().await;
    let body = body_for(&h, 1, &fresh_id()).to_string().into_bytes();
    let key = signing_key(1);
    let ts = h.now_secs();

    let unsigned = Request::post("/v0/invites")
        .body(Body::from(body.clone()))
        .unwrap();
    assert_eq!(call(&h, unsigned).await.0, StatusCode::UNAUTHORIZED);

    let wrong_host = signed_request(&key, "POST", "/v0/invites", &body, ts, "evil.test");
    assert_eq!(call(&h, wrong_host).await.0, StatusCode::UNAUTHORIZED);

    let stale = signed_request(&key, "POST", "/v0/invites", &body, ts - 301, HOST);
    assert_eq!(call(&h, stale).await.0, StatusCode::UNAUTHORIZED);

    let other_path = signed_request(&key, "POST", "/v0/invites/x", &body, ts, HOST);
    let mut replayed_elsewhere = Request::post("/v0/invites")
        .body(Body::from(body.clone()))
        .unwrap();
    replayed_elsewhere.headers_mut().insert(
        "authorization",
        other_path.headers()["authorization"].clone(),
    );
    assert_eq!(
        call(&h, replayed_elsewhere).await.0,
        StatusCode::UNAUTHORIZED
    );

    let mut tampered = signed_request(&key, "POST", "/v0/invites", &body, ts, HOST);
    *tampered.body_mut() = Body::from(body_for(&h, 1, &fresh_id()).to_string());
    assert_eq!(call(&h, tampered).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn inviter_mailbox_must_be_the_caller() {
    let h = Harness::start().await;
    let body = body_for(&h, 2, &fresh_id());
    let (status, err) = create(&h, 1, &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err["code"], "auth_failed");
}

#[tokio::test]
async fn invalid_invites_are_rejected() {
    let h = Harness::start().await;
    let now = h.now_secs();
    let base = body_for(&h, 1, &fresh_id());
    let with = |k: &str, v: Value| {
        let mut b = base.clone();
        b[k] = v;
        b
    };
    let cases = [
        with("invite_id", json!("short")),
        with("inviter_mailbox", json!("short")),
        with("group_name", json!("")),
        with("group_name", json!("x".repeat(81))),
        with("group_name", json!("bad\u{7}name")),
        with("inviter_name", json!("")),
        with("inviter_name", json!("line\nbreak")),
        with("purpose", json!("p".repeat(501))),
        with("max_uses", json!(0)),
        with("max_uses", json!(1001)),
        with("expires_at", json!(now)),
        with("expires_at", json!(now + 7 * 24 * 3600 + 1)),
        with("protocol", json!(1)),
        with("max_uses", json!("many")),
    ];
    for c in cases {
        let (status, err) = create(&h, 1, &c).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{c} -> {err}");
        assert_eq!(err["code"], "bad_request");
    }
    // Boundaries that are fine.
    for ok in [
        with("group_name", json!("g".repeat(80))),
        with("purpose", json!("")),
        with("max_uses", json!(1000)),
        with("expires_at", json!(now + 7 * 24 * 3600)),
    ] {
        let mut ok = ok;
        ok["invite_id"] = json!(fresh_id());
        assert_eq!(create(&h, 1, &ok).await.0, StatusCode::CREATED, "{ok}");
    }
}

#[tokio::test]
async fn duplicate_invite_ids_and_malformed_bodies_are_bad_requests() {
    let h = Harness::start().await;
    let body = body_for(&h, 1, &fresh_id());
    assert_eq!(create(&h, 1, &body).await.0, StatusCode::CREATED);
    assert_eq!(create(&h, 1, &body).await.0, StatusCode::BAD_REQUEST);

    let junk = b"not json".to_vec();
    let req = signed_request(
        &signing_key(1),
        "POST",
        "/v0/invites",
        &junk,
        h.now_secs(),
        HOST,
    );
    assert_eq!(call(&h, req).await.0, StatusCode::BAD_REQUEST);

    let huge = vec![b' '; 32 * 1024];
    let req = signed_request(
        &signing_key(1),
        "POST",
        "/v0/invites",
        &huge,
        h.now_secs(),
        HOST,
    );
    assert_eq!(call(&h, req).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn healthz_and_metrics() {
    let h = Harness::start().await;
    let (status, body) = call(&h, Request::get("/healthz").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    let id = fresh_id();
    create(&h, 1, &body_for(&h, 1, &id)).await;
    let resp = app(h.relay.clone())
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let text = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(text.contains("# TYPE agentconnect_relay_invites_created_total counter"));
    assert!(text.contains("agentconnect_relay_invites_created_total 1"));
    assert!(!text.contains(&id));
    assert!(!text.contains(&mailbox_of(&signing_key(1))));
}
