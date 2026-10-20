//! Storage quotas over the WebSocket (SPEC §8.3 "Limits"; security review
//! SR-03, SR-04, SR-17): the attacks of the review's probes, end to end.

mod common;

use agentconnect_relay::Limits;
use agentconnect_relay::proto::{MAX_JOIN_CT, MAX_WELCOME_CT, b64_encode, mailbox_id_from_key};
use agentconnect_relay::relay::NewInviteRequest;
use agentconnect_relay::store::Store;
use common::{
    Client, Harness, commit, envelope, fresh_id, invite_body, knock_as, make_group, open_door,
    queued,
};
use serde_json::{Value, json};

fn welcome(sender: &Client, gid: &str, to: &[String], ct_bytes: usize) -> Value {
    let mut w = envelope("welcome_wrapped", Some(gid), None, &sender.mailbox);
    w["to"] = json!(to);
    w["ct"] = json!(b64_encode(&vec![7_u8; ct_bytes]));
    w
}

fn made_up(n: u8) -> String {
    mailbox_id_from_key(&[n, 0xAB])
}

#[tokio::test]
async fn one_welcome_to_many_mailboxes_is_stored_once_and_only_for_mailboxes_just_added() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let gid = make_group(&mut a, &[]).await;
    let others: Vec<String> = (0..49).map(made_up).collect();
    let refs: Vec<&str> = others.iter().map(String::as_str).collect();
    assert_eq!(
        a.send(&commit(&a, &gid, 0, &refs, &[])).await["t"],
        "accepted"
    );
    a.deliver().await;

    // The review's 1.87 MB Welcome is over the cap.
    let r = a.send(&welcome(&a, &gid, &others, 1_400_000)).await;
    assert_eq!(r["code"], "too_large", "{r}");
    // A mailbox the commit didn't add is refused.
    let r = a.send(&welcome(&a, &gid, &[made_up(200)], 100)).await;
    assert_eq!(r["code"], "bad_request", "{r}");

    let before = h.relay.store().storage_bytes().await.unwrap();
    let r = a.send(&welcome(&a, &gid, &others, MAX_WELCOME_CT)).await;
    assert_eq!(r["t"], "accepted", "{r}");
    let grown = h.relay.store().storage_bytes().await.unwrap() - before;
    let one_copy = u64::try_from(MAX_WELCOME_CT * 4 / 3).unwrap();
    assert!(
        grown < 2 * one_copy,
        "49 recipients grew storage by {grown}"
    );
    for o in &others {
        assert_eq!(
            h.relay
                .store()
                .pending(o, 0, 10, u64::MAX, h.relay.now_ms())
                .await
                .unwrap()
                .len(),
            1
        );
    }
    // Each of them had its Welcome.
    let r = a.send(&welcome(&a, &gid, &others[..1], 100)).await;
    assert_eq!(r["code"], "bad_request", "{r}");
}

#[tokio::test]
async fn a_stranger_who_knows_a_mailbox_id_cannot_make_it_lose_group_traffic() {
    let h = Harness::with_limits(Limits {
        queue_max_bytes: 100 << 10,
        non_member_queue_max_bytes: 64 << 10,
        sends_per_sec: 100_000,
        joins_per_min: 100_000,
        ..Limits::default()
    })
    .await;
    // The victim's group with a friend; then the victim goes offline.
    let mut victim = h.client(1).await;
    let mut friend = h.client(2).await;
    let gid = make_group(&mut victim, &[&friend]).await;
    let victim_mailbox = victim.mailbox.clone();
    let victim_key = victim.disconnect().await;

    // The stranger: its own group with the victim added, a Welcome, group
    // traffic, join requests to the victim's invite and knocks on its door.
    let mut stranger = h.client(3).await;
    let sg = make_group(&mut stranger, &[]).await;
    let add = commit(&stranger, &sg, 0, &[&victim_mailbox], &[]);
    assert_eq!(stranger.send(&add).await["t"], "accepted");
    stranger.deliver().await;
    let r = stranger
        .send(&welcome(
            &stranger,
            &sg,
            std::slice::from_ref(&victim_mailbox),
            4000,
        ))
        .await;
    assert_eq!(r["t"], "accepted");
    for _ in 0..40 {
        let mut m = stranger.envelope("application", &sg, 1);
        m["ct"] = json!(b64_encode(&[1_u8; 4000]));
        assert_eq!(stranger.send(&m).await["t"], "accepted");
    }
    // Small ones fill what room is left, as the review's probe did.
    for _ in 0..100 {
        let m = stranger.envelope("application", &sg, 1);
        assert_eq!(stranger.send(&m).await["t"], "accepted");
    }
    let invite = fresh_id();
    let body = invite_body(&victim_mailbox, &invite, h.now_secs() + 3600, 5);
    let req: NewInviteRequest = serde_json::from_value(body).unwrap();
    h.relay.create_invite(&victim_mailbox, req).await.unwrap();
    let mut joins = Vec::new();
    for _ in 0..5 {
        let mut env = envelope("join_request", None, None, &stranger.mailbox);
        env["ct"] = json!(b64_encode(&[2_u8; 4000]));
        let r = stranger
            .request(&json!({"t": "join", "invite_id": invite, "env": env}))
            .await;
        joins.push(r["code"].as_str().unwrap_or("accepted").to_owned());
    }
    // Join requests have their own share of the non-member part, which the
    // stranger's group traffic can't take.
    assert!(joins.iter().all(|c| c == "accepted"), "{joins:?}");
    let door = open_door(&h, 1).await;
    assert_eq!(knock_as(&h, 30, &door).await["t"], "accepted");

    // The friend's real commit and message reach the victim.
    let c = commit(&friend, &gid, 1, &[], &[]);
    assert_eq!(friend.send(&c).await["t"], "accepted");
    let m = friend.envelope("application", &gid, 2);
    assert_eq!(friend.send(&m).await["t"], "accepted");

    let mut victim = Client::connect(h.addr, victim_key).await;
    let n = victim.drained().await;
    let mut got = Vec::new();
    for _ in 0..n {
        got.push(victim.deliver().await);
    }
    assert!(
        got.iter().any(|e| e["msg_id"] == c["msg_id"]),
        "the commit was dropped"
    );
    assert!(got.iter().any(|e| e["msg_id"] == m["msg_id"]));
    // The only marker is for the stranger's group.
    let marker = victim.marker().await;
    assert_eq!(marker["group_id"], sg);
    assert_eq!(victim.buffered_delivers(), 0);
}

#[tokio::test]
async fn join_requests_are_capped_and_charged_to_the_non_member_queue() {
    let h = Harness::with_limits(Limits {
        non_member_queue_max_bytes: 3000,
        queue_max_bytes: 3000,
        joins_per_min: 1000,
        sends_per_sec: 100_000,
        ..Limits::default()
    })
    .await;
    let mut inviter = h.client(1).await;
    let mut member = h.client(2).await;
    let gid = make_group(&mut inviter, &[&member]).await;
    inviter.deliver().await;
    let invite = fresh_id();
    let body = invite_body(&inviter.mailbox, &invite, h.now_secs() + 3600, 5);
    let req: NewInviteRequest = serde_json::from_value(body).unwrap();
    h.relay.create_invite(&inviter.mailbox, req).await.unwrap();

    let mut joiner = h.client(3).await;
    let joiner_mailbox = joiner.mailbox.clone();
    let join = |n: usize| {
        let mut env = envelope("join_request", None, None, &joiner_mailbox);
        env["ct"] = json!(b64_encode(&vec![3_u8; n]));
        json!({"t": "join", "invite_id": invite, "env": env})
    };
    let too_big = join(MAX_JOIN_CT + 1);
    assert_eq!(joiner.request(&too_big).await["code"], "too_large");
    let mut codes = Vec::new();
    for _ in 0..4 {
        let f = join(900);
        codes.push(joiner.request(&f).await["t"].as_str().unwrap().to_owned());
    }
    assert_eq!(codes.last().unwrap(), "error", "{codes:?}");
    // The member's message to the inviter still fits: the joins filled only
    // the non-member queue.
    let m = member.envelope("application", &gid, 1);
    assert_eq!(member.send(&m).await["t"], "accepted");
    let mut joins = 0;
    while inviter.deliver().await["kind"] == "join_request" {
        joins += 1;
    }
    assert_eq!(joins, codes.iter().filter(|c| *c == "accepted").count());
}

#[tokio::test]
async fn above_the_high_water_mark_messages_are_refused_and_metrics_say_so() {
    let h = Harness::with_limits(Limits {
        storage_high_water: 1,
        sends_per_sec: 100_000,
        ..Limits::default()
    })
    .await;
    let mut a = h.client(1).await;
    let gid = make_group(&mut a, &[]).await;
    let r = a.send(&a.envelope("application", &gid, 0)).await;
    assert_eq!(r["code"], "storage_full");
    assert_eq!(
        r["detail"],
        "relay storage is above its high-water mark; retry later"
    );
    let invite = fresh_id();
    let body = invite_body(&a.mailbox, &invite, h.now_secs() + 3600, 5);
    let req: NewInviteRequest = serde_json::from_value(body).unwrap();
    h.relay.create_invite(&a.mailbox, req).await.unwrap();
    let mut joiner = h.client(2).await;
    let env = envelope("join_request", None, None, &joiner.mailbox);
    let r = joiner
        .request(&json!({"t": "join", "invite_id": invite, "env": env}))
        .await;
    assert_eq!(r["code"], "storage_full");
    // A knock is answered as always, and dropped.
    let door = open_door(&h, 1).await;
    assert_eq!(knock_as(&h, 40, &door).await["t"], "accepted");
    assert!(queued(&h, 1).await.is_empty());

    h.relay.purge().await.unwrap();
    let text = h.relay.metrics().render();
    assert!(text.contains("agentconnect_relay_storage_full 1"), "{text}");
    assert!(text.contains("agentconnect_relay_storage_high_water_bytes 1\n"));
    assert!(text.contains("# TYPE agentconnect_relay_storage_bytes gauge"));
    assert!(!text.contains("agentconnect_relay_storage_bytes 0\n"));
    assert!(text.contains("agentconnect_relay_errors_total{code=\"storage_full\"} 2"));
}

#[tokio::test]
async fn a_sender_over_its_budget_is_told_so() {
    let h = Harness::with_limits(Limits {
        sender_max_bytes: 1500,
        sends_per_sec: 100_000,
        ..Limits::default()
    })
    .await;
    let mut a = h.client(1).await;
    let b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;
    let mut codes = Vec::new();
    for _ in 0..12 {
        let r = a.send(&a.envelope("application", &gid, 1)).await;
        codes.push(r);
    }
    let refused = codes.last().unwrap();
    assert_eq!(refused["code"], "over_budget");
    assert!(
        refused["detail"]
            .as_str()
            .unwrap()
            .contains("undelivered messages"),
        "{refused}"
    );
    // Another sender is not affected.
    let mut b = b;
    assert_eq!(
        b.send(&b.envelope("application", &gid, 1)).await["t"],
        "accepted"
    );
}
