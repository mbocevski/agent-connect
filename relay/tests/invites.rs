//! Invite lifecycle over WebSocket: consume, join forwarding, rate limit,
//! expiry (SPEC §4.3, §8.3).

mod common;

use std::sync::Arc;
use std::time::Duration;

use agentconnect_relay::relay::NewInviteRequest;
use agentconnect_relay::store::{ConsumeOutcome, InviteStatus, Store};
use common::{Client, Harness, envelope, fresh_id, invite_body, signing_key};
use serde_json::{Value, json};

async fn register(h: &Harness, inviter: &Client, uses: u32, ttl_secs: u64) -> String {
    let id = fresh_id();
    let body = invite_body(&inviter.mailbox, &id, h.now_secs() + ttl_secs, uses);
    let req: NewInviteRequest = serde_json::from_value(body).unwrap();
    h.relay.create_invite(&inviter.mailbox, req).await.unwrap();
    id
}

fn join_frame(joiner: &Client, invite_id: &str) -> Value {
    let mut env = envelope("join_request", None, None, &joiner.mailbox);
    env["ct"] = json!(agentconnect_relay::proto::b64_encode(br#"{"v":0}"#));
    json!({"t": "join", "invite_id": invite_id, "env": env})
}

#[tokio::test]
async fn only_the_inviter_can_consume_and_uses_run_out() {
    let h = Harness::start().await;
    let mut inviter = h.client(1).await;
    let mut other = h.client(2).await;
    let id = register(&h, &inviter, 2, 3600).await;
    let consume = json!({"t": "invite.consume", "invite_id": id});

    assert_eq!(other.request(&consume).await["code"], "auth_failed");
    let r = inviter.request(&consume).await;
    assert_eq!(r["t"], "accepted");
    assert_eq!(r["msg_id"], id, "control frames echo the invite id");
    assert_eq!(inviter.request(&consume).await["t"], "accepted");
    assert_eq!(inviter.request(&consume).await["code"], "invite_not_open");
    let rec = h.relay.invite(&id).await.unwrap();
    assert_eq!(rec.uses_left, 0);
    assert_eq!(rec.status(h.now_secs()), InviteStatus::Exhausted);

    let unknown = json!({"t": "invite.consume", "invite_id": fresh_id()});
    assert_eq!(inviter.request(&unknown).await["code"], "invite_not_open");
}

#[tokio::test]
async fn consume_echoes_a_client_supplied_correlation_id() {
    let h = Harness::start().await;
    let mut inviter = h.client(1).await;
    let id = register(&h, &inviter, 1, 3600).await;
    let r = inviter
        .request(&json!({"t": "invite.consume", "invite_id": id, "msg_id": "corr-1"}))
        .await;
    assert_eq!(r, json!({"t": "accepted", "msg_id": "corr-1"}));
    let gid = fresh_id();
    let r = inviter
        .request(&json!({"t": "group.create", "group_id": gid, "epoch": 0, "msg_id": "corr-2"}))
        .await;
    assert_eq!(r["msg_id"], "corr-2");
}

#[tokio::test]
async fn two_concurrent_consumes_of_a_single_use_invite_have_one_winner() {
    let h = Harness::start().await;
    let mut first = h.client(1).await;
    // The same instance key connected twice (e.g. a reconnect overlapping).
    let mut second = Client::connect(h.addr, signing_key(1)).await;
    let id = register(&h, &first, 1, 3600).await;
    let consume = json!({"t": "invite.consume", "invite_id": id});
    let (a, b) = tokio::join!(first.request(&consume), second.request(&consume));
    let wins = [&a, &b].iter().filter(|r| r["t"] == "accepted").count();
    assert_eq!(wins, 1, "{a} / {b}");
    let loser = if a["t"] == "error" { &a } else { &b };
    assert_eq!(loser["code"], "invite_not_open");
    assert_eq!(h.relay.invite(&id).await.unwrap().uses_left, 0);
}

#[tokio::test]
async fn store_level_consume_is_race_free_under_contention() {
    let h = Harness::start().await;
    let inviter = h.client(1).await;
    let id = register(&h, &inviter, 5, 3600).await;
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let relay = Arc::clone(&h.relay);
        let (id, mb) = (id.clone(), inviter.mailbox.clone());
        tasks.push(tokio::spawn(async move {
            relay
                .store()
                .consume_invite(&id, &mb, relay.now_ms())
                .await
                .unwrap()
        }));
    }
    let mut consumed = 0;
    for t in tasks {
        if matches!(t.await.unwrap(), ConsumeOutcome::Consumed { .. }) {
            consumed += 1;
        }
    }
    assert_eq!(consumed, 5);
    assert_eq!(h.relay.invite(&id).await.unwrap().uses_left, 0);
}

#[tokio::test]
async fn invites_expire_with_the_clock() {
    let h = Harness::start().await;
    let mut inviter = h.client(1).await;
    let mut joiner = h.client(2).await;
    let id = register(&h, &inviter, 3, 3600).await;
    assert_eq!(
        h.relay.invite(&id).await.unwrap().status(h.now_secs()),
        InviteStatus::Open
    );

    h.clock.advance(Duration::from_secs(3599));
    assert_eq!(
        joiner.request(&join_frame(&joiner, &id)).await["t"],
        "accepted"
    );
    h.clock.advance(Duration::from_secs(1));
    let rec = h.relay.invite(&id).await.unwrap();
    assert_eq!(rec.status(h.now_secs()), InviteStatus::Expired);
    assert_eq!(
        joiner.request(&join_frame(&joiner, &id)).await["code"],
        "invite_not_open"
    );
    let consume = json!({"t": "invite.consume", "invite_id": id});
    assert_eq!(inviter.request(&consume).await["code"], "invite_not_open");
    assert_eq!(rec.uses_left, 3, "an expired invite keeps its unused count");
}

#[tokio::test]
async fn join_is_forwarded_to_the_inviter_mailbox() {
    let h = Harness::start().await;
    let mut inviter = h.client(1).await;
    let mut joiner = h.client(2).await;
    let id = register(&h, &inviter, 1, 3600).await;

    let frame = join_frame(&joiner, &id);
    let r = joiner.request(&frame).await;
    assert_eq!(r["t"], "accepted");
    assert_eq!(r["msg_id"], frame["env"]["msg_id"]);
    let got = inviter.deliver().await;
    assert_eq!(got["kind"], "join_request");
    assert_eq!(got["sender"], joiner.mailbox);
    assert_eq!(got["ct"], frame["env"]["ct"]);

    // Idempotent on msg_id.
    assert_eq!(joiner.request(&frame).await["t"], "accepted");
    let pending = h
        .relay
        .store()
        .pending(&inviter.mailbox, 0, 100, u64::MAX, h.relay.now_ms())
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
}

#[tokio::test]
async fn join_to_a_closed_invite_is_refused() {
    let h = Harness::start().await;
    let mut inviter = h.client(1).await;
    let mut joiner = h.client(2).await;

    let unknown = fresh_id();
    assert_eq!(
        joiner.request(&join_frame(&joiner, &unknown)).await["code"],
        "invite_not_open"
    );

    let used = register(&h, &inviter, 1, 3600).await;
    inviter
        .request(&json!({"t": "invite.consume", "invite_id": used}))
        .await;
    assert_eq!(
        joiner.request(&join_frame(&joiner, &used)).await["code"],
        "invite_not_open"
    );

    let revoked = register(&h, &inviter, 1, 3600).await;
    h.relay
        .revoke_invite(&inviter.mailbox, &revoked)
        .await
        .unwrap();
    assert_eq!(
        joiner.request(&join_frame(&joiner, &revoked)).await["code"],
        "invite_not_open"
    );
}

#[tokio::test]
async fn join_validates_its_envelope() {
    let h = Harness::start().await;
    let inviter = h.client(1).await;
    let mut joiner = h.client(2).await;
    let id = register(&h, &inviter, 1, 3600).await;

    let mut wrong_kind = join_frame(&joiner, &id);
    wrong_kind["env"]["kind"] = json!("application");
    wrong_kind["env"]["group_id"] = json!(fresh_id());
    wrong_kind["env"]["epoch"] = json!(0);
    assert_eq!(joiner.request(&wrong_kind).await["code"], "bad_request");

    let mut forged = join_frame(&joiner, &id);
    forged["env"]["sender"] = json!(inviter.mailbox);
    assert_eq!(joiner.request(&forged).await["code"], "bad_request");

    let mut bad_invite = join_frame(&joiner, &id);
    bad_invite["invite_id"] = json!("nope");
    assert_eq!(joiner.request(&bad_invite).await["code"], "bad_request");
}

#[tokio::test]
async fn joins_are_limited_to_ten_per_minute_per_invite() {
    let h = Harness::start().await;
    let inviter = h.client(1).await;
    let mut joiner = h.client(2).await;
    let id = register(&h, &inviter, 5, 3600).await;
    let other = register(&h, &inviter, 5, 3600).await;

    for i in 0..10 {
        let r = joiner.request(&join_frame(&joiner, &id)).await;
        assert_eq!(r["t"], "accepted", "join {i}");
    }
    assert_eq!(
        joiner.request(&join_frame(&joiner, &id)).await["code"],
        "rate_limited"
    );
    // The budget is per invite.
    assert_eq!(
        joiner.request(&join_frame(&joiner, &other)).await["t"],
        "accepted"
    );
    h.clock.advance(Duration::from_secs(59));
    assert_eq!(
        joiner.request(&join_frame(&joiner, &id)).await["code"],
        "rate_limited"
    );
    h.clock.advance(Duration::from_secs(1));
    assert_eq!(
        joiner.request(&join_frame(&joiner, &id)).await["t"],
        "accepted"
    );
}

#[tokio::test]
async fn inviter_queue_quota_applies_to_joins() {
    let h = Harness::with_limits(agentconnect_relay::Limits {
        non_member_queue_max_bytes: 1000,
        sends_per_sec: 100_000,
        joins_per_min: 1000,
        ..agentconnect_relay::Limits::default()
    })
    .await;
    let inviter = h.client(1).await;
    let mut joiner = h.client(2).await;
    let id = register(&h, &inviter, 5, 3600).await;
    let mut codes = Vec::new();
    for _ in 0..10 {
        let r = joiner.request(&join_frame(&joiner, &id)).await;
        codes.push(r["code"].as_str().unwrap_or("ok").to_owned());
    }
    assert_eq!(codes.first().unwrap(), "ok");
    assert_eq!(codes.last().unwrap(), "quota_exceeded");
}
