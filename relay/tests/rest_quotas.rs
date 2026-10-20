//! Signed REST requests on a public relay (SPEC §8.1.1): the per-mailbox
//! replay cache, the per-address and per-mailbox rates, the open-invite
//! quota and the one-line text rule for invite metadata (SPEC §4.2).
//! Regression tests for security review findings SR-02, SR-07, SR-19 and
//! SR-44.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use agentconnect_relay::Quotas;
use agentconnect_relay::quota::{Cidr, ClientIp};
use agentconnect_relay::relay::{NewDoorRequest, NewInviteRequest};
use agentconnect_relay::store::Window;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderName, Request, StatusCode};
use common::{
    HOST, Harness, call, door_body, fresh_id, invite_body, mailbox_of, roomy_quotas,
    signed_request, signing_key,
};
use serde_json::{Value, json};

fn quotas(edit: impl FnOnce(&mut Quotas)) -> Quotas {
    let mut q = roomy_quotas();
    edit(&mut q);
    q
}

fn invite_for(h: &Harness, key: u8, id: &str) -> Value {
    invite_body(&mailbox_of(&signing_key(key)), id, h.now_secs() + 3600, 1)
}

fn post_invite(key: u8, body: &[u8], ts: u64) -> Request<Body> {
    signed_request(&signing_key(key), "POST", "/v0/invites", body, ts, HOST)
}

fn delete(key: u8, path: &str, ts: u64) -> Request<Body> {
    signed_request(&signing_key(key), "DELETE", path, b"", ts, HOST)
}

/// Register an invite for `key`; returns its revoke path.
async fn registered(h: &Harness, key: u8) -> String {
    let id = fresh_id();
    let body = invite_for(h, key, &id).to_string().into_bytes();
    let (status, err) = call(h, post_invite(key, &body, h.now_secs())).await;
    assert_eq!(status, StatusCode::CREATED, "{err}");
    format!("/v0/invites/{id}")
}

/// Register an invite for `key` without a signed request, so the setup
/// takes no replay-cache slot; returns its revoke path.
async fn seeded(h: &Harness, key: u8) -> String {
    let id = fresh_id();
    let req: NewInviteRequest = serde_json::from_value(invite_for(h, key, &id)).unwrap();
    h.relay
        .create_invite(&mailbox_of(&signing_key(key)), req)
        .await
        .unwrap();
    format!("/v0/invites/{id}")
}

/// Register a door for `key` without a signed request; returns its path.
async fn seeded_door(h: &Harness, key: u8) -> String {
    let id = fresh_id();
    let req: NewDoorRequest =
        serde_json::from_value(door_body(key, &id, h.now_secs() + 3600)).unwrap();
    h.relay
        .create_door(&mailbox_of(&signing_key(key)), req)
        .await
        .unwrap();
    format!("/v0/doors/{id}")
}

fn from(mut req: Request<Body>, addr: &str) -> Request<Body> {
    let addr: SocketAddr = addr.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

// --- SR-02: the replay cache -----------------------------------------------

#[tokio::test]
async fn junk_signed_requests_from_one_mailbox_lock_nobody_out() {
    // The review's probe: a client sends signed POSTs with junk bodies, far
    // ahead of the clock, then a victim revokes its invite and registers a
    // door. The junk fills only the client's own share.
    let h = Harness::with_quotas(quotas(|q| q.replay_per_mailbox = 2)).await;
    let victim_invite = seeded(&h, 1).await;
    let ahead = h.now_secs() + 299;
    for n in 0..2 {
        let junk = format!("junk{n}").into_bytes();
        let (status, err) = call(&h, post_invite(2, &junk, ahead)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    }
    let junk = b"junk".to_vec();
    let (status, err) = call(&h, post_invite(2, &junk, ahead)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");

    let (status, err) = call(&h, delete(1, &victim_invite, h.now_secs())).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
    let door = door_body(1, &fresh_id(), h.now_secs() + 3600)
        .to_string()
        .into_bytes();
    let req = signed_request(&signing_key(1), "POST", "/v0/doors", &door, h.ts(), HOST);
    let (status, err) = call(&h, req).await;
    assert_eq!(status, StatusCode::CREATED, "{err}");
    let get = Request::get(&victim_invite).body(Body::empty()).unwrap();
    assert_eq!(call(&h, get).await.1["status"], "revoked");
}

#[tokio::test]
async fn a_full_share_refuses_only_its_mailbox_and_never_evicts_a_live_entry() {
    let h = Harness::with_quotas(quotas(|q| q.replay_per_mailbox = 2)).await;
    let paths = [
        seeded(&h, 3).await,
        seeded(&h, 3).await,
        seeded(&h, 3).await,
    ];
    let ahead = h.now_secs() + 299;
    assert_eq!(
        call(&h, delete(3, &paths[0], ahead)).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&h, delete(3, &paths[1], ahead)).await.0,
        StatusCode::NO_CONTENT
    );
    let (status, err) = call(&h, delete(3, &paths[2], ahead)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");
    assert_eq!(err["code"], "rate_limited");
    // Live entries are kept: the first request is still a replay.
    let (status, err) = call(&h, delete(3, &paths[0], ahead)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["code"], "auth_failed");
    // Another mailbox is not affected.
    let other = seeded(&h, 4).await;
    assert_eq!(
        call(&h, delete(4, &other, h.now_secs())).await.0,
        StatusCode::NO_CONTENT
    );
    // Once the entries expire (ahead + 300) the mailbox has room again.
    h.clock.advance(Duration::from_secs(299 + 300 + 1));
    h.relay.purge().await.unwrap();
    let (status, err) = call(&h, delete(3, &paths[2], h.now_secs())).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
}

#[tokio::test]
async fn a_validated_request_is_never_accepted_twice_inside_its_window() {
    let h = Harness::start().await;
    let path = registered(&h, 5).await;
    // Signed as far ahead as the window allows: accepted 300 s early.
    let ts = h.now_secs() + 300;
    let first = || delete(5, &path, ts);
    assert_eq!(call(&h, first()).await.0, StatusCode::NO_CONTENT);
    // Every second until the timestamp check refuses it, the cache does,
    // and a purge in between doesn't drop the live entry.
    for step in [1, 298, 1, 1, 298, 1] {
        h.clock.advance(Duration::from_secs(step));
        h.relay.purge().await.unwrap();
        let (status, err) = call(&h, first()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
        assert_eq!(err["code"], "auth_failed");
    }
    assert_eq!(h.now_secs(), ts + 300, "the last second of the window");
    // Past the window the timestamp check refuses it.
    h.clock.advance(Duration::from_secs(1));
    assert_eq!(call(&h, first()).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_refused_request_keeps_its_entry_and_cant_be_replayed_to_succeed() {
    // Verification probe V2: a request refused once (here: not the signer's
    // invite yet, and over the open-invite quota) is recorded all the same,
    // so a captured copy can't be applied later in its window.
    let h = Harness::with_quotas(quotas(|q| q.open_invites_per_mailbox = 1)).await;
    let first = seeded(&h, 6).await;
    let refused_id = fresh_id();
    let body = invite_for(&h, 6, &refused_id).to_string().into_bytes();
    let ts = h.ts();
    let (status, err) = call(&h, post_invite(6, &body, ts)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");
    assert_eq!(err["code"], "quota_exceeded");
    assert_eq!(
        call(&h, delete(6, &first, h.ts())).await.0,
        StatusCode::NO_CONTENT
    );
    h.clock.advance(Duration::from_secs(200));
    let (status, err) = call(&h, post_invite(6, &body, ts)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
    assert_eq!(err["detail"], "request already used");
    let get = Request::get(format!("/v0/invites/{refused_id}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&h, get).await.0, StatusCode::NOT_FOUND);

    // The same for a request that wasn't the signer's to make: a DELETE of
    // an id that doesn't exist yet can't close the door registered later.
    let door_id = fresh_id();
    let path = format!("/v0/doors/{door_id}");
    let ts = h.ts();
    assert_eq!(
        call(&h, delete(7, &path, ts)).await.0,
        StatusCode::NOT_FOUND
    );
    let req: NewDoorRequest =
        serde_json::from_value(door_body(7, &door_id, h.now_secs() + 3600)).unwrap();
    h.relay
        .create_door(&mailbox_of(&signing_key(7)), req)
        .await
        .unwrap();
    assert_eq!(
        call(&h, delete(7, &path, ts)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(h.relay.door(&door_id).await.unwrap().is_open(h.now_secs()));
}

// --- Rates per address and per mailbox --------------------------------------

#[tokio::test]
async fn failed_signatures_fill_only_their_own_bucket_per_address() {
    // Review finding 5: behind a proxy without a client-address header every
    // client shares one address, and junk must not lock out revokes, door
    // closes or valid creations.
    let h = Harness::with_quotas(quotas(|q| {
        q.rest_junk_per_address = Window {
            max: 3,
            per: Duration::from_mins(1),
        };
        q.rest_per_address = Window {
            max: 2,
            per: Duration::from_mins(1),
        };
    }))
    .await;
    let junk = || {
        Request::post("/v0/invites")
            .header("authorization", "AgentConnect-Ed25519 a.1.b")
            .body(Body::from("{}"))
            .unwrap()
    };
    let shared = "203.0.113.9:1000";
    for _ in 0..3 {
        assert_eq!(
            call(&h, from(junk(), shared)).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (status, err) = call(&h, from(junk(), shared)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");
    assert_eq!(err["code"], "rate_limited");
    // A request whose signature verifies never looks at that bucket.
    let victim = seeded(&h, 8).await;
    let (status, err) = call(&h, from(delete(8, &victim, h.ts()), shared)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
    let door = seeded_door(&h, 8).await;
    let (status, err) = call(&h, from(delete(8, &door, h.ts()), shared)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
    // Creations from one address are rated on their own (2 a minute here),
    let body = |k: u8| invite_for(&h, k, &fresh_id()).to_string().into_bytes();
    for _ in 0..2 {
        let (status, err) = call(&h, from(post_invite(9, &body(9), h.ts()), shared)).await;
        assert_eq!(status, StatusCode::CREATED, "{err}");
    }
    let (status, err) = call(&h, from(post_invite(10, &body(10), h.ts()), shared)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");
    // but revokes and door closes never are: only per mailbox.
    for _ in 0..3 {
        let path = seeded(&h, 11).await;
        let (status, err) = call(&h, from(delete(11, &path, h.ts()), shared)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
    }
    // Another address has its own buckets.
    let (status, err) = call(&h, from(post_invite(9, &body(9), h.ts()), "198.51.100.1:1")).await;
    assert_eq!(status, StatusCode::CREATED, "{err}");
    // IPv6 counts per /64.
    for host in [
        "[2001:db8:1:2::1]:1",
        "[2001:db8:1:2::2]:1",
        "[2001:db8:1:2::3]:1",
    ] {
        assert_eq!(
            call(&h, from(junk(), host)).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        call(&h, from(junk(), "[2001:db8:1:2::ffff]:1")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        call(&h, from(junk(), "[2001:db8:1:3::1]:1")).await.0,
        StatusCode::UNAUTHORIZED
    );
    // The windows refill.
    h.clock.advance(Duration::from_mins(1));
    assert_eq!(
        call(&h, from(junk(), shared)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, err) = call(&h, from(post_invite(10, &body(10), h.ts()), shared)).await;
    assert_eq!(status, StatusCode::CREATED, "{err}");
    // Reads are not counted.
    let get = Request::get(format!("/v0/invites/{}", fresh_id()))
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&h, from(get, shared)).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn behind_a_trusted_proxy_the_forwarded_address_is_counted() {
    let h = Harness::with_quotas(quotas(|q| {
        q.rest_junk_per_address = Window {
            max: 1,
            per: Duration::from_mins(1),
        };
        q.client_ip = ClientIp {
            header: Some(HeaderName::from_static("x-forwarded-for")),
            trusted_proxies: vec![Cidr::parse("127.0.0.1/32").unwrap()],
            hops: 1,
        };
    }))
    .await;
    let via = |client: &str| {
        let mut req = Request::delete(format!("/v0/doors/{}", fresh_id()))
            .header("x-forwarded-for", client)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:443".parse::<SocketAddr>().unwrap()));
        req
    };
    assert_eq!(
        call(&h, via("203.0.113.1")).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&h, via("203.0.113.2")).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&h, via("203.0.113.1")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Entries the client wrote further left don't pick a new bucket.
    assert_eq!(
        call(&h, via("198.51.100.9, 203.0.113.1")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // A client that writes the header itself, not through the proxy, is
    // counted by its own address.
    let mut direct = Request::delete(format!("/v0/doors/{}", fresh_id()))
        .header("x-forwarded-for", "203.0.113.3")
        .body(Body::empty())
        .unwrap();
    direct.extensions_mut().insert(ConnectInfo(
        "203.0.113.1:5000".parse::<SocketAddr>().unwrap(),
    ));
    assert_eq!(call(&h, direct).await.0, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn signed_requests_are_limited_per_mailbox_and_a_replay_uses_no_budget() {
    let h = Harness::with_quotas(quotas(|q| {
        q.rest_per_mailbox = Window {
            max: 2,
            per: Duration::from_mins(1),
        };
    }))
    .await;
    let body = |id: &str| invite_for(&h, 9, id).to_string().into_bytes();
    let first = body(&fresh_id());
    let ts = h.now_secs();
    assert_eq!(
        call(&h, post_invite(9, &first, ts)).await.0,
        StatusCode::CREATED
    );
    // A replay is refused as one and doesn't count.
    assert_eq!(
        call(&h, post_invite(9, &first, ts)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let second = body(&fresh_id());
    assert_eq!(
        call(&h, post_invite(9, &second, h.ts())).await.0,
        StatusCode::CREATED
    );
    let third = body(&fresh_id());
    let (status, err) = call(&h, post_invite(9, &third, h.ts())).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");
    assert_eq!(err["code"], "rate_limited");
    // Another mailbox has its own budget.
    let other = invite_for(&h, 10, &fresh_id()).to_string().into_bytes();
    assert_eq!(
        call(&h, post_invite(10, &other, h.ts())).await.0,
        StatusCode::CREATED
    );
    h.clock.advance(Duration::from_mins(1));
    let fourth = body(&fresh_id());
    assert_eq!(
        call(&h, post_invite(9, &fourth, h.ts())).await.0,
        StatusCode::CREATED
    );
}

// --- SR-07: open invites ------------------------------------------------------

#[tokio::test]
async fn a_mailbox_holds_a_bounded_number_of_open_invites() {
    let h = Harness::with_quotas(quotas(|q| q.open_invites_per_mailbox = 2)).await;
    let first = registered(&h, 11).await;
    registered(&h, 11).await;
    let body = invite_for(&h, 11, &fresh_id()).to_string().into_bytes();
    let (status, err) = call(&h, post_invite(11, &body, h.ts())).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");
    assert_eq!(err["code"], "quota_exceeded");
    // Others are not affected, and revoking one makes room.
    registered(&h, 12).await;
    assert_eq!(
        call(&h, delete(11, &first, h.ts())).await.0,
        StatusCode::NO_CONTENT
    );
    let (status, err) = call(&h, post_invite(11, &body, h.ts())).await;
    assert_eq!(status, StatusCode::CREATED, "{err}");
    // So does expiry.
    let body = invite_for(&h, 11, &fresh_id()).to_string().into_bytes();
    assert_eq!(
        call(&h, post_invite(11, &body, h.ts())).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    h.clock.advance(Duration::from_secs(3600));
    let body = invite_for(&h, 11, &fresh_id()).to_string().into_bytes();
    assert_eq!(
        call(&h, post_invite(11, &body, h.ts())).await.0,
        StatusCode::CREATED
    );
}

// --- SR-19: one-line text ------------------------------------------------------

#[tokio::test]
async fn invite_texts_must_be_one_line_text() {
    let h = Harness::start().await;
    let refused = [
        "\u{202E}gnp.exe",    // right-to-left override (Cf)
        "a\u{200B}b",         // zero-width space (Cf)
        "\u{FEFF}bom",        // byte order mark (Cf)
        "a\u{2066}b\u{2069}", // isolates (Cf)
        "a\u{2028}b",         // line separator (Zl)
        "a\u{00A0}b",         // no-break space (Zs other than U+0020)
        "a\u{E000}b",         // private use (Co)
        "e\u{0301}",          // not NFC
        "\u{0301}a",          // starts with a combining mark
        "a\u{3164}b",         // Hangul filler (default ignorable)
        "a\u{200D}b",         // zero-width joiner
    ];
    for field in ["group_name", "inviter_name", "purpose"] {
        for bad in refused {
            let mut body = invite_for(&h, 13, &fresh_id());
            body[field] = json!(bad);
            let bytes = body.to_string().into_bytes();
            let (status, err) = call(&h, post_invite(13, &bytes, h.ts())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field}={bad:?}: {err}");
            assert_eq!(err["code"], "bad_request");
        }
    }
    for ok in [
        "Ops \u{2764}\u{FE0F}",
        "\u{00E9}t\u{00E9}",
        "\u{05E9}\u{05DC}\u{05D5}\u{05DD}",
        "一",
    ] {
        let mut body = invite_for(&h, 13, &fresh_id());
        body["group_name"] = json!(ok);
        body["purpose"] = json!(ok);
        let bytes = body.to_string().into_bytes();
        let (status, err) = call(&h, post_invite(13, &bytes, h.ts())).await;
        assert_eq!(status, StatusCode::CREATED, "{ok:?}: {err}");
    }
}

// --- The relay API checks again what the REST layer checked -----------------

#[tokio::test]
async fn the_relay_api_refuses_what_the_rest_layer_refuses_first() {
    use agentconnect_relay::proto::ErrorCode;
    let h = Harness::start().await;
    let (owner, other) = (mailbox_of(&signing_key(20)), mailbox_of(&signing_key(21)));
    let invite = |mailbox: &str| -> NewInviteRequest {
        let mut body = invite_for(&h, 20, &fresh_id());
        body["inviter_mailbox"] = json!(mailbox);
        serde_json::from_value(body).unwrap()
    };
    let r = h.relay.create_invite(&owner, invite("short")).await;
    assert_eq!(r.unwrap_err().code, ErrorCode::BadRequest);
    let r = h.relay.create_invite(&owner, invite(&other)).await;
    assert_eq!(r.unwrap_err().code, ErrorCode::AuthFailed);

    let door = |mailbox: &str| -> NewDoorRequest {
        let mut body = door_body(20, &fresh_id(), h.now_secs() + 60);
        body["owner_mailbox"] = json!(mailbox);
        serde_json::from_value(body).unwrap()
    };
    let r = h.relay.create_door(&owner, door("short")).await;
    assert_eq!(r.unwrap_err().code, ErrorCode::BadRequest);
    let r = h.relay.create_door(&owner, door(&other)).await;
    assert_eq!(r.unwrap_err().code, ErrorCode::AuthFailed);
    let open = h.relay.create_door(&owner, door(&owner)).await.unwrap();
    for (who, id, code) in [
        (&other, open.door_id.as_str(), ErrorCode::AuthFailed),
        (&owner, "short", ErrorCode::DoorNotOpen),
        (&owner, &fresh_id(), ErrorCode::DoorNotOpen),
    ] {
        assert_eq!(h.relay.close_door(who, id).await.unwrap_err().code, code);
        if id != open.door_id {
            assert_eq!(h.relay.door(id).await.unwrap_err().code, code);
        }
    }

    let path = seeded(&h, 20).await;
    let id = path.trim_start_matches("/v0/invites/");
    for (who, id, code) in [
        (&other, id, ErrorCode::AuthFailed),
        (&owner, "short", ErrorCode::InviteNotOpen),
        (&owner, &fresh_id(), ErrorCode::InviteNotOpen),
    ] {
        assert_eq!(h.relay.revoke_invite(who, id).await.unwrap_err().code, code);
    }
}

// --- Review of PR 71: bounds that hold however many mailboxes ----------------

#[tokio::test]
async fn one_address_holds_a_bounded_number_of_invite_rows_whatever_its_mailboxes() {
    // Review probe P4: mailboxes are free, so the per-mailbox quota alone
    // bounds nothing; rows are counted per address while the relay holds them.
    let h = Harness::with_quotas(quotas(|q| q.invites_per_address = 3)).await;
    let addr = "203.0.113.50:4000";
    let mut paths = Vec::new();
    for k in 30..33 {
        let id = fresh_id();
        let body = invite_for(&h, k, &id).to_string().into_bytes();
        let (status, err) = call(&h, from(post_invite(k, &body, h.ts()), addr)).await;
        assert_eq!(status, StatusCode::CREATED, "{err}");
        paths.push((k, format!("/v0/invites/{id}")));
    }
    let body = invite_for(&h, 33, &fresh_id()).to_string().into_bytes();
    let (status, err) = call(&h, from(post_invite(33, &body, h.ts()), addr)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");
    assert_eq!(err["code"], "quota_exceeded");
    // Another address is not affected.
    let (status, _) = call(&h, from(post_invite(33, &body, h.ts()), "198.51.100.2:1")).await;
    assert_eq!(status, StatusCode::CREATED);
    // A revoked invite still holds its row; an invite purged after its
    // expiry and grace period does not.
    let (k, path) = &paths[0];
    assert_eq!(
        call(&h, from(delete(*k, path, h.ts()), addr)).await.0,
        StatusCode::NO_CONTENT
    );
    let body = invite_for(&h, 34, &fresh_id()).to_string().into_bytes();
    assert_eq!(
        call(&h, from(post_invite(34, &body, h.ts()), addr)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    h.clock
        .advance(Duration::from_secs(3600 + 7 * 24 * 3600 + 1));
    h.relay.purge().await.unwrap();
    let body = invite_for(&h, 34, &fresh_id()).to_string().into_bytes();
    let (status, err) = call(&h, from(post_invite(34, &body, h.ts()), addr)).await;
    assert_eq!(status, StatusCode::CREATED, "{err}");
}

#[tokio::test]
async fn the_relay_holds_a_bounded_number_of_invite_rows_and_says_so_in_metrics() {
    let h = Harness::with_quotas(quotas(|q| q.max_invites = 2)).await;
    registered(&h, 35).await;
    registered(&h, 36).await;
    let body = invite_for(&h, 37, &fresh_id()).to_string().into_bytes();
    let (status, err) = call(&h, post_invite(37, &body, h.ts())).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");
    assert_eq!(err["code"], "quota_exceeded");
    let dup = invite_for(&h, 37, &fresh_id());
    let metrics = h.relay.metrics().render();
    assert!(
        metrics.contains("agentconnect_relay_invites 2\n"),
        "{metrics}"
    );
    assert!(
        metrics.contains("agentconnect_relay_invites_max 2\n"),
        "{metrics}"
    );
    assert!(metrics.contains("# TYPE agentconnect_relay_invites gauge"));
    // The purge recounts from the store.
    h.clock
        .advance(Duration::from_secs(3600 + 7 * 24 * 3600 + 1));
    h.relay.purge().await.unwrap();
    assert!(
        h.relay
            .metrics()
            .render()
            .contains("agentconnect_relay_invites 0\n")
    );
    let ts = h.now_secs();
    let mut fresh = dup.clone();
    fresh["expires_at"] = json!(ts + 60);
    let fresh = fresh.to_string().into_bytes();
    assert_eq!(
        call(&h, post_invite(37, &fresh, ts)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&h, post_invite(37, &fresh, ts + 1)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert!(
        h.relay
            .metrics()
            .render()
            .contains("agentconnect_relay_invites 1\n")
    );
}

#[tokio::test]
async fn past_the_caches_bound_requests_are_served_unrecorded_and_stay_harmless() {
    // Review probe P5: the cache as a whole is bounded. Past the bound a
    // request is still served but not recorded; every signed effect is
    // idempotent, so a repeat of one changes nothing.
    let h = Harness::with_quotas(quotas(|q| q.replay_max_entries = 1)).await;
    let first = seeded(&h, 40).await;
    let second = seeded(&h, 41).await;
    let ts = h.now_secs();
    assert_eq!(
        call(&h, delete(40, &first, ts)).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&h, delete(41, &second, ts)).await.0,
        StatusCode::NO_CONTENT
    );
    // The first is recorded and refused again; the second is not recorded,
    // and its repeat revokes a revoked invite.
    assert_eq!(
        call(&h, delete(40, &first, ts)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&h, delete(41, &second, ts)).await.0,
        StatusCode::NO_CONTENT
    );
    let get = Request::get(&second).body(Body::empty()).unwrap();
    assert_eq!(call(&h, get).await.1["status"], "revoked");
    // A repeated creation finds its row: bad_request, nothing new.
    let id = fresh_id();
    let body = invite_for(&h, 42, &id).to_string().into_bytes();
    assert_eq!(
        call(&h, post_invite(42, &body, ts)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&h, post_invite(42, &body, ts)).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn after_a_restart_requests_signed_before_it_are_refused() {
    // Review finding 6: the cache is per process. A relay that starts on an
    // existing database refuses every request whose ts is not past its start
    // plus the window, so none signed before the start is accepted again.
    use agentconnect_core::clock::{Clock, FakeClock};
    use agentconnect_relay::{Limits, Relay, SqliteStore};
    let clock = std::sync::Arc::new(FakeClock::default());
    let relay = Relay::new(
        SqliteStore::in_memory().await.unwrap(),
        clock.clone(),
        HOST,
        Limits::default(),
    )
    .with_quotas(roomy_quotas())
    .with_restart_guard();
    let app = agentconnect_relay::app(std::sync::Arc::new(relay));
    let start = clock.unix_millis() / 1000;
    let send = |ts: u64| {
        let path = format!("/v0/invites/{}", fresh_id());
        let app = app.clone();
        async move {
            use tower::ServiceExt;
            app.oneshot(delete(43, &path, ts)).await.unwrap().status()
        }
    };
    for ts in [start - 300, start, start + 300] {
        assert_eq!(send(ts).await, StatusCode::TOO_MANY_REQUESTS, "{ts}");
    }
    // A second later a clock 300 s ahead passes; 300 s later every clock.
    clock.advance(Duration::from_secs(1));
    assert_eq!(send(start + 301).await, StatusCode::NOT_FOUND);
    clock.advance(Duration::from_secs(300));
    assert_eq!(send(start + 301).await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn many_slash_48s_up_to_the_invite_cap_leave_a_reserve_for_a_light_client() {
    // Verification probe V1, for invites: one /56 (one /48) is one key, and
    // a key-rich attacker stops at the reserve.
    let h = Harness::with_quotas(quotas(|q| {
        q.invites_per_address = 5;
        q.max_invites = 1_000;
    }))
    .await;
    let attacker = mailbox_of(&signing_key(60));
    let try_from = |ip: String| {
        let mut body = invite_for(&h, 60, &fresh_id());
        body["max_uses"] = json!(1);
        let req: NewInviteRequest = serde_json::from_value(body).unwrap();
        let relay = h.relay.clone();
        let attacker = attacker.clone();
        async move {
            relay
                .create_invite_from(&attacker, Some(ip.parse().unwrap()), req)
                .await
                .is_ok()
        }
    };
    let mut in_one = 0;
    for n in 0..256_u64 {
        if try_from(format!("2001:db8:0:{n:x}::1")).await {
            in_one += 1;
        }
    }
    assert_eq!(in_one, 5);
    let (mut live, mut key) = (in_one, 1_u64);
    while live < 950 {
        for _ in 0..5 {
            if try_from(format!("2001:db8:{key:x}::1")).await {
                live += 1;
            }
        }
        key += 1;
    }
    assert_eq!(live, 950);
    for n in 1..key {
        assert!(!try_from(format!("2001:db8:{n:x}::1")).await, "{n}");
    }
    let body = invite_for(&h, 61, &fresh_id()).to_string().into_bytes();
    let (status, err) = call(&h, from(post_invite(61, &body, h.ts()), "198.51.100.8:1")).await;
    assert_eq!(status, StatusCode::CREATED, "{err}");
}

#[tokio::test]
async fn after_a_clean_shutdown_only_what_the_last_process_could_accept_is_refused() {
    // Verification finding V3: the marker carries the highest ts the last
    // process accepted, so a clean restart refuses only up to it, and says
    // when to retry.
    use agentconnect_core::clock::{Clock, FakeClock};
    use agentconnect_relay::{Limits, Relay, SqliteStore};
    let clock = std::sync::Arc::new(FakeClock::default());
    let now = clock.unix_millis() / 1000;
    let relay = Relay::new(
        SqliteStore::in_memory().await.unwrap(),
        clock.clone(),
        HOST,
        Limits::default(),
    )
    .with_quotas(roomy_quotas())
    .with_replay_floor(now - 10);
    let relay = std::sync::Arc::new(relay);
    let app = agentconnect_relay::app(relay.clone());
    let send = |ts: u64| {
        let path = format!("/v0/invites/{}", fresh_id());
        let app = app.clone();
        async move {
            use http_body_util::BodyExt;
            use tower::ServiceExt;
            let resp = app.oneshot(delete(62, &path, ts)).await.unwrap();
            let status = resp.status();
            let retry = resp
                .headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap().to_owned());
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            (status, retry, body)
        }
    };
    let (status, retry, body) = send(now - 10).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(retry.as_deref(), Some("1"));
    assert_eq!(body["retry_after"], 1);
    // A request signed now goes through at once.
    assert_eq!(send(now).await.0, StatusCode::NOT_FOUND);
    assert_eq!(relay.highest_accepted_ts(), now);
}
