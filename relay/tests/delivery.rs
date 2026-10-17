//! Delivery Service rules (SPEC §8.3).

mod common;

use std::time::Duration;

use agentconnect_relay::Limits;
use agentconnect_relay::proto::mailbox_id_from_key;
use agentconnect_relay::store::Store;
use common::{Client, Harness, commit, envelope, fresh_id, make_group, signing_key};
use serde_json::{Value, json};

async fn queued(h: &Harness, mailbox: &str) -> Vec<Value> {
    h.relay
        .store()
        .pending(mailbox, 0, 10_000, h.relay.now_ms())
        .await
        .unwrap()
        .into_iter()
        .map(|m| serde_json::from_str(&m.json).unwrap())
        .collect()
}

#[tokio::test]
async fn three_mailboxes_exchange_1000_messages_with_one_offline() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let c = h.client(3).await;
    let gid = make_group(&mut a, &[&b, &c]).await;
    // The add commit's fan-out set is the members before it: just A.
    assert_eq!(a.deliver().await["kind"], "commit");

    let c_key = c.disconnect().await;
    let mut sent_by_a = Vec::new();
    let mut sent_by_b = Vec::new();
    let mut order = Vec::new();
    for i in 0..500 {
        let ea = a.envelope("application", &gid, 1);
        let eb = b.envelope("application", &gid, 1);
        sent_by_a.push(ea["msg_id"].as_str().unwrap().to_owned());
        sent_by_b.push(eb["msg_id"].as_str().unwrap().to_owned());
        order.push(ea["msg_id"].as_str().unwrap().to_owned());
        order.push(eb["msg_id"].as_str().unwrap().to_owned());
        assert_eq!(a.send(&ea).await["t"], "accepted", "a#{i}");
        assert_eq!(b.send(&eb).await["t"], "accepted", "b#{i}");
    }

    // A and B each see the other's messages, in order.
    for expected in &sent_by_b {
        assert_eq!(a.deliver().await["msg_id"], *expected);
    }
    for expected in &sent_by_a {
        assert_eq!(b.deliver().await["msg_id"], *expected);
    }

    // C reconnects and the whole queue drains in acceptance order.
    let mut c = Client::connect(h.addr, c_key).await;
    let mut got = Vec::new();
    for _ in 0..1000 {
        got.push(c.deliver().await["msg_id"].as_str().unwrap().to_owned());
    }
    assert_eq!(got, order);

    // Nothing is acked yet, so a second reconnect replays it all, still in order.
    let c_key = c.disconnect().await;
    let mut c = Client::connect(h.addr, c_key).await;
    let mut again = Vec::new();
    for _ in 0..1000 {
        again.push(c.deliver().await["msg_id"].as_str().unwrap().to_owned());
    }
    assert_eq!(again, order);

    // Acks free the queue.
    c.ack_and_sync(&order).await;
    assert!(queued(&h, &c.mailbox).await.is_empty());
    assert_eq!(queued(&h, &a.mailbox).await.len(), 501, "A did not ack");
}

#[tokio::test]
async fn concurrent_commits_at_one_epoch_exactly_one_wins() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;
    a.deliver().await;

    let ca = commit(&a, &gid, 1, &[], &[]);
    let cb = commit(&b, &gid, 1, &[], &[]);
    let (ra, rb) = tokio::join!(a.send(&ca), b.send(&cb));
    let results = [&ra, &rb];
    let won = results.iter().filter(|r| r["t"] == "accepted").count();
    assert_eq!(won, 1, "{ra} / {rb}");
    let lost = results.iter().find(|r| r["t"] == "error").unwrap();
    assert_eq!(lost["code"], "epoch_conflict");
    assert_eq!(lost["current_epoch"], 2);

    let state = h.relay.store().get_group(&gid).await.unwrap().unwrap();
    assert_eq!(state.current_epoch, 2);
    // Both members see exactly the winning commit.
    let winner = if ra["t"] == "accepted" { &ca } else { &cb };
    assert_eq!(a.deliver().await["msg_id"], winner["msg_id"]);
    assert_eq!(b.deliver().await["msg_id"], winner["msg_id"]);

    // The loser rebuilds at the new epoch and succeeds.
    let (loser, epoch) = if ra["t"] == "accepted" {
        (&mut b, 2)
    } else {
        (&mut a, 2)
    };
    let retry = commit(loser, &gid, epoch, &[], &[]);
    assert_eq!(loser.send(&retry).await["t"], "accepted");
}

#[tokio::test]
async fn commit_fans_out_to_every_member_including_the_sender() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let mut c = h.client(3).await;
    let gid = make_group(&mut a, &[&b, &c]).await;
    a.deliver().await;
    let e = commit(&b, &gid, 1, &[], &[]);
    assert_eq!(b.send(&e).await["t"], "accepted");
    for client in [&mut a, &mut b, &mut c] {
        assert_eq!(client.deliver().await["msg_id"], e["msg_id"]);
    }
}

#[tokio::test]
async fn a_removed_member_gets_the_removing_commit_then_nothing() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let mut c = h.client(3).await;
    let gid = make_group(&mut a, &[&b, &c]).await;
    a.deliver().await;

    let remove = commit(&a, &gid, 1, &[], &[&b.mailbox]);
    assert_eq!(a.send(&remove).await["t"], "accepted");
    assert_eq!(b.deliver().await["msg_id"], remove["msg_id"]);
    assert_eq!(c.deliver().await["msg_id"], remove["msg_id"]);

    let state = h.relay.store().get_group(&gid).await.unwrap().unwrap();
    assert_eq!(state.current_epoch, 2);
    assert!(!state.members.contains(&b.mailbox));

    let before = queued(&h, &b.mailbox).await.len();
    let msg = a.envelope("application", &gid, 2);
    assert_eq!(a.send(&msg).await["t"], "accepted");
    assert_eq!(c.deliver().await["msg_id"], msg["msg_id"]);
    assert_eq!(
        queued(&h, &b.mailbox).await.len(),
        before,
        "B must not receive"
    );

    // And B can no longer send into the group.
    let r = b.send(&b.envelope("application", &gid, 2)).await;
    assert_eq!(r["code"], "not_member");
    let r = b.send(&commit(&b, &gid, 2, &[], &[])).await;
    assert_eq!(r["code"], "not_member");
}

#[tokio::test]
async fn routing_add_makes_a_mailbox_a_member() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let gid = make_group(&mut a, &[]).await;
    let r = b.send(&b.envelope("application", &gid, 0)).await;
    assert_eq!(r["code"], "not_member");
    assert_eq!(
        a.send(&commit(&a, &gid, 0, &[&b.mailbox], &[])).await["t"],
        "accepted"
    );
    let msg = a.envelope("application", &gid, 1);
    a.send(&msg).await;
    assert_eq!(b.deliver().await["msg_id"], msg["msg_id"]);
}

#[tokio::test]
async fn proposals_need_the_current_epoch_and_skip_the_sender() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;
    a.deliver().await;

    let p = b.envelope("proposal", &gid, 1);
    assert_eq!(b.send(&p).await["t"], "accepted");
    assert_eq!(a.deliver().await["msg_id"], p["msg_id"]);
    assert_eq!(queued(&h, &b.mailbox).await.len(), 0, "sender gets no copy");

    for stale in [0_u64, 2, 99] {
        let r = b.send(&b.envelope("proposal", &gid, stale)).await;
        assert_eq!(r["code"], "epoch_conflict", "epoch {stale}");
        assert_eq!(r["current_epoch"], 1);
    }
}

#[tokio::test]
async fn application_messages_get_a_one_epoch_grace_window() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;
    a.deliver().await;
    // Move to epoch 2.
    assert_eq!(
        a.send(&commit(&a, &gid, 1, &[], &[])).await["t"],
        "accepted"
    );
    a.deliver().await;
    b.deliver().await;

    for ok in [2_u64, 1] {
        let m = b.envelope("application", &gid, ok);
        assert_eq!(b.send(&m).await["t"], "accepted", "epoch {ok}");
        assert_eq!(a.deliver().await["msg_id"], m["msg_id"]);
    }
    for stale in [0_u64, 3, 100] {
        let r = b.send(&b.envelope("application", &gid, stale)).await;
        assert_eq!(r["code"], "epoch_conflict", "epoch {stale}");
        assert_eq!(r["current_epoch"], 2);
    }
    assert_eq!(
        queued(&h, &b.mailbox).await.len(),
        1,
        "only the commit; no self-copies"
    );
}

#[tokio::test]
async fn application_at_epoch_zero_has_no_grace_underflow() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let gid = make_group(&mut a, &[]).await;
    assert_eq!(
        a.send(&a.envelope("application", &gid, 0)).await["t"],
        "accepted"
    );
    assert_eq!(
        a.send(&a.envelope("application", &gid, 1)).await["code"],
        "epoch_conflict"
    );
}

#[tokio::test]
async fn unknown_group_and_non_member_errors() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let r = a.send(&a.envelope("commit", &fresh_id(), 0)).await;
    assert_eq!(r["code"], "unknown_group");
    let gid = make_group(&mut a, &[]).await;
    assert_eq!(
        b.send(&b.envelope("commit", &gid, 0)).await["code"],
        "not_member"
    );
    assert_eq!(
        b.group_create(&gid).await["code"],
        "bad_request",
        "group exists"
    );
}

#[tokio::test]
async fn duplicate_msg_id_is_accepted_but_not_redelivered() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;
    a.deliver().await;

    let m = a.envelope("application", &gid, 1);
    for _ in 0..3 {
        assert_eq!(a.send(&m).await["t"], "accepted");
    }
    assert_eq!(queued(&h, &b.mailbox).await.len(), 1);
    assert_eq!(b.deliver().await["msg_id"], m["msg_id"]);

    // A retried commit is idempotent, not an epoch conflict.
    let c = commit(&a, &gid, 1, &[], &[]);
    assert_eq!(a.send(&c).await["t"], "accepted");
    assert_eq!(a.send(&c).await["t"], "accepted");
    let state = h.relay.store().get_group(&gid).await.unwrap().unwrap();
    assert_eq!(state.current_epoch, 2);
    assert_eq!(
        queued(&h, &a.mailbox).await.len(),
        2,
        "welcome-less: one commit each"
    );

    // The same msg_id from a different sender is a different message.
    assert_eq!(a.deliver().await["kind"], "commit");
    let mut other = m.clone();
    other["sender"] = json!(b.mailbox);
    assert_eq!(b.send(&other).await["t"], "accepted");
    assert_eq!(a.deliver().await["msg_id"], m["msg_id"]);
}

#[tokio::test]
async fn failed_sends_do_not_burn_the_msg_id() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;
    a.deliver().await;
    let late = commit(&b, &gid, 0, &[], &[]);
    assert_eq!(b.send(&late).await["code"], "epoch_conflict");
    // Same msg_id retried at the right epoch is processed, not swallowed.
    let mut fixed = late.clone();
    fixed["epoch"] = json!(1);
    assert_eq!(b.send(&fixed).await["t"], "accepted");
    assert_eq!(a.deliver().await["msg_id"], late["msg_id"]);
}

#[tokio::test]
async fn welcome_goes_to_the_named_mailbox_even_if_it_never_connected() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let gid = make_group(&mut a, &[]).await;
    let newcomer = mailbox_id_from_key(signing_key(9).verifying_key().as_bytes());

    let mut w = envelope("welcome_wrapped", Some(&gid), None, &a.mailbox);
    w["to"] = json!([newcomer]);
    assert_eq!(a.send(&w).await["t"], "accepted");
    assert_eq!(queued(&h, &newcomer).await.len(), 1);

    let mut late = common::Client::connect(h.addr, signing_key(9)).await;
    let got = late.deliver().await;
    assert_eq!(got["kind"], "welcome_wrapped");
    assert_eq!(got["msg_id"], w["msg_id"]);
    assert_eq!(got["ct"], w["ct"]);

    // Strangers cannot push welcomes, and unknown groups are refused.
    let mut stranger = h.client(8).await;
    let mut spam = envelope("welcome_wrapped", Some(&gid), None, &stranger.mailbox);
    spam["to"] = json!([newcomer]);
    assert_eq!(stranger.send(&spam).await["code"], "not_member");
    let mut orphan = envelope("welcome_wrapped", Some(&fresh_id()), None, &a.mailbox);
    orphan["to"] = json!([newcomer]);
    assert_eq!(a.send(&orphan).await["code"], "unknown_group");
}

#[tokio::test]
async fn groups_are_limited_to_50_instances() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let others: Vec<String> = (0..49_u8).map(|i| mailbox_id_from_key(&[i, 7])).collect();
    let refs: Vec<&str> = others.iter().map(String::as_str).collect();
    let gid = fresh_id();
    a.group_create(&gid).await;
    // 1 + 49 = 50 is allowed.
    assert_eq!(
        a.send(&commit(&a, &gid, 0, &refs, &[])).await["t"],
        "accepted"
    );
    // One more is not, and the epoch does not move.
    let extra = mailbox_id_from_key(b"one-too-many");
    let r = a.send(&commit(&a, &gid, 1, &[&extra], &[])).await;
    assert_eq!(r["code"], "quota_exceeded");
    assert_eq!(
        h.relay
            .store()
            .get_group(&gid)
            .await
            .unwrap()
            .unwrap()
            .current_epoch,
        1
    );
    // Swapping one for another stays at 50.
    let r = a.send(&commit(&a, &gid, 1, &[&extra], &[&others[0]])).await;
    assert_eq!(r["t"], "accepted");
}

fn is_marker(e: &Value) -> bool {
    e["t"] == "queue_overflow"
}

async fn fill(a: &mut Client, gid: &str, n: usize) {
    for _ in 0..n {
        let m = a.envelope("application", gid, 1);
        assert_eq!(a.send(&m).await["t"], "accepted");
    }
}

async fn small_queue_harness() -> Harness {
    Harness::with_limits(Limits {
        queue_max_bytes: 3000,
        sends_per_sec: 100_000,
        ..Limits::default()
    })
    .await
}

#[tokio::test]
async fn a_full_member_does_not_block_the_others() {
    let h = small_queue_harness().await;
    let mut a = h.client(1).await;
    let b = h.client(2).await;
    let mut c = h.client(3).await;
    let gid = make_group(&mut a, &[&b, &c]).await;

    let mut sent = Vec::new();
    for _ in 0..40 {
        let m = a.envelope("application", &gid, 1);
        sent.push(m["msg_id"].as_str().unwrap().to_owned());
        // The sender always gets `accepted`.
        assert_eq!(a.send(&m).await["t"], "accepted");
        // C keeps up; B never acks.
        let got = c.deliver().await;
        c.ack(got["msg_id"].as_str().unwrap()).await;
    }
    let b_queue = queued(&h, &b.mailbox).await;
    let b_msgs: Vec<_> = b_queue.iter().filter(|e| !is_marker(e)).collect();
    let b_markers: Vec<_> = b_queue.iter().filter(|e| is_marker(e)).collect();
    assert!(!b_msgs.is_empty() && b_msgs.len() < sent.len());
    assert_eq!(b_markers.len(), 1, "one marker for the whole episode");

    // The marker names the first dropped message, right after the last queued.
    let first_dropped = &sent[b_msgs.len()];
    assert_eq!(b_markers[0]["msg_id"], *first_dropped);
    assert_eq!(b_markers[0]["group_id"], gid);
    assert_eq!(b_markers[0]["epoch"], 1);
    assert_eq!(
        h.relay
            .metrics()
            .render()
            .matches("queue_overflows_total 1")
            .count(),
        1
    );

    // B's connection receives the queued messages and then the marker.
    let mut b = b;
    for m in &b_msgs {
        assert_eq!(b.deliver().await["msg_id"], m["msg_id"]);
    }
    let marker = b.marker().await;
    assert_eq!(marker["t"], "queue_overflow");
    assert_eq!(marker["msg_id"], *first_dropped);
}

#[tokio::test]
async fn overflow_marker_is_sent_once_per_episode_and_delivery_resumes_after_drain() {
    let h = small_queue_harness().await;
    let mut a = h.client(1).await;
    let mut b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;

    let markers = |q: &[Value]| q.iter().filter(|e| is_marker(e)).count();
    fill(&mut a, &gid, 30).await;
    let q = queued(&h, &b.mailbox).await;
    assert_eq!(markers(&q), 1);
    fill(&mut a, &gid, 10).await;
    assert_eq!(
        markers(&queued(&h, &b.mailbox).await),
        1,
        "still the same episode"
    );

    // B drains everything, marker included.
    let ids: Vec<String> = queued(&h, &b.mailbox)
        .await
        .iter()
        .map(|e| e["msg_id"].as_str().unwrap().to_owned())
        .collect();
    b.ack_and_sync(&ids).await;
    assert!(queued(&h, &b.mailbox).await.is_empty());

    // Delivery resumes with ordinary copies and no marker.
    let m = a.envelope("application", &gid, 1);
    assert_eq!(a.send(&m).await["t"], "accepted");
    let q = queued(&h, &b.mailbox).await;
    assert_eq!((q.len(), markers(&q)), (1, 0));
    assert_eq!(q[0]["msg_id"], m["msg_id"]);

    // A second overflow is a new episode with its own marker.
    fill(&mut a, &gid, 40).await;
    let q = queued(&h, &b.mailbox).await;
    assert_eq!(markers(&q), 1);
    assert!(
        h.relay
            .metrics()
            .render()
            .contains("queue_overflows_total 2")
    );
}

#[tokio::test]
async fn an_overflowed_commit_still_advances_the_group() {
    let h = small_queue_harness().await;
    let mut a = h.client(1).await;
    let b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;
    for _ in 0..30 {
        a.send(&a.envelope("application", &gid, 1)).await;
    }
    let c = commit(&a, &gid, 1, &[], &[]);
    assert_eq!(a.send(&c).await["t"], "accepted");
    let g = h.relay.store().get_group(&gid).await.unwrap().unwrap();
    assert_eq!(g.current_epoch, 2);
    assert!(
        !queued(&h, &b.mailbox)
            .await
            .iter()
            .any(|e| e["msg_id"] == c["msg_id"]),
        "the dropped commit is not in B's queue"
    );
}

#[tokio::test]
async fn sends_are_limited_to_50_per_second_per_mailbox() {
    let h = Harness::with_limits(Limits::default()).await;
    let mut a = h.client(1).await;
    let gid = make_group(&mut a, &[]).await; // consumes 1 of the 50 (group.create)
    for i in 1..50 {
        let r = a.send(&a.envelope("application", &gid, 0)).await;
        assert_eq!(r["t"], "accepted", "send {i}");
    }
    let r = a.send(&a.envelope("application", &gid, 0)).await;
    assert_eq!(r["code"], "rate_limited");
    // Another mailbox is unaffected.
    let mut b = h.client(2).await;
    assert_eq!(b.group_create(&fresh_id()).await["t"], "accepted");
    // The window slides with the clock.
    h.clock.advance(Duration::from_millis(999));
    assert_eq!(
        a.send(&a.envelope("application", &gid, 0)).await["code"],
        "rate_limited"
    );
    h.clock.advance(Duration::from_millis(1));
    assert_eq!(
        a.send(&a.envelope("application", &gid, 0)).await["t"],
        "accepted"
    );
}

#[tokio::test]
async fn unacked_messages_expire_after_seven_days() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;
    a.deliver().await;
    a.send(&a.envelope("application", &gid, 1)).await;
    let b_mailbox = b.mailbox.clone();
    drop(b);

    h.clock.advance(Duration::from_secs(7 * 24 * 3600 - 1));
    assert_eq!(queued(&h, &b_mailbox).await.len(), 1);
    h.clock.advance(Duration::from_secs(1));
    assert!(queued(&h, &b_mailbox).await.is_empty());
    let purged = h.relay.purge().await.unwrap();
    assert!(purged.messages >= 1);
    assert!(purged.seen >= 1);
    // Idempotency records expire with the messages.
    let m = a.envelope("application", &gid, 1);
    assert_eq!(a.send(&m).await["t"], "accepted");
}

#[tokio::test]
async fn kind_specific_shape_errors_are_bad_requests() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let gid = make_group(&mut a, &[]).await;
    let cases = [
        envelope("join_request", None, None, &a.mailbox),
        {
            let mut e = envelope("welcome_wrapped", Some(&gid), None, &a.mailbox);
            e["to"] = json!([]);
            e
        },
        {
            let mut e = envelope("application", Some(&gid), Some(0), &a.mailbox);
            e["routing"] = json!({"add": [], "remove": []});
            e
        },
        envelope("commit", None, Some(0), &a.mailbox),
    ];
    for e in cases {
        assert_eq!(a.send(&e).await["code"], "bad_request", "{e}");
    }
}

#[tokio::test]
async fn metrics_count_without_identifiers() {
    let h = Harness::start().await;
    let mut a = h.client(1).await;
    let b = h.client(2).await;
    let gid = make_group(&mut a, &[&b]).await;
    a.send(&a.envelope("application", &gid, 1)).await;
    a.send(&a.envelope("application", &gid, 9)).await;
    let text = h.relay.metrics().render();
    assert!(
        text.contains("agentconnect_relay_commits_total 1"),
        "{text}"
    );
    assert!(text.contains("agentconnect_relay_errors_total{code=\"epoch_conflict\"} 1"));
    assert!(text.contains("agentconnect_relay_connections_total 2"));
    for needle in [&a.mailbox, &b.mailbox, &gid] {
        assert!(
            !text.contains(needle.as_str()),
            "metrics leak an identifier"
        );
    }
}
