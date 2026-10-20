//! Doors and knocks (ADR-006 Decision 3, "Relay interactions"): the door
//! registry over signed REST, knock forwarding to the owner's mailbox, the
//! knocker and per-door limits, and the silent drops.

mod common;

use std::sync::Arc;
use std::time::Duration;

use agentconnect_relay::Limits;
use agentconnect_relay::proto::{MAX_KNOCK_CT, b64_encode};
use agentconnect_relay::store::{CreateDoorOutcome, DoorRecord, Store};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{
    Client, HOST, Harness, WEEK, call, close_door, door_body, envelope, fresh_id, knock_as,
    knock_env, knock_frame, knock_frame_as, mailbox_of, open_door, post_door, queued,
    signed_request, signing_key,
};
use serde_json::{Value, json};

// --- Registration -----------------------------------------------------------

#[tokio::test]
async fn a_door_is_registered_by_its_owner_and_never_readable() {
    let h = Harness::start().await;
    let id = fresh_id();
    let expires = h.now_secs() + 3600;
    let (status, body) = post_door(&h, 1, &door_body(1, &id, expires)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body, json!({"door_id": id, "expires_at": expires}));

    // There is no GET for doors: nothing about one can be read back.
    let path = format!("/v0/doors/{id}");
    let (status, _) = call(&h, Request::get(&path).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _) = call(&h, Request::get("/v0/doors").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn renewal_overlaps_and_a_mailbox_holds_at_most_four_open_doors() {
    let h = Harness::start().await;
    let doors: Vec<String> = [0; 4].iter().map(|_| fresh_id()).collect();
    for d in &doors {
        let (status, body) = post_door(&h, 1, &door_body(1, d, h.now_secs() + WEEK)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let fifth = fresh_id();
    let (status, err) = post_door(&h, 1, &door_body(1, &fifth, h.now_secs() + 60)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(err["code"], "quota_exceeded");
    // The cap is per mailbox.
    assert_eq!(
        post_door(&h, 2, &door_body(2, &fifth, h.now_secs() + 60))
            .await
            .0,
        StatusCode::CREATED
    );

    // Old and new doors are open at the same time, so cached listings of
    // the previous door still work during renewal.
    for (i, d) in doors.iter().enumerate() {
        let r = knock_as(&h, 10 + u8::try_from(i).unwrap(), d).await;
        assert_eq!(r["t"], "accepted", "{r}");
    }
    assert_eq!(queued(&h, 1).await.len(), 4);

    // A closed door frees its slot.
    assert_eq!(close_door(&h, 1, &doors[0]).await.0, StatusCode::NO_CONTENT);
    let sixth = fresh_id();
    let (status, _) = post_door(&h, 1, &door_body(1, &sixth, h.now_secs() + 60)).await;
    assert_eq!(status, StatusCode::CREATED);
    // And so does an expired one.
    h.clock.advance(Duration::from_secs(61));
    let seventh = fresh_id();
    let (status, _) = post_door(&h, 1, &door_body(1, &seventh, h.now_secs() + 60)).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn the_door_cap_holds_under_concurrent_registrations() {
    let h = Harness::start().await;
    let owner = mailbox_of(&signing_key(1));
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let relay = Arc::clone(&h.relay);
        let door = DoorRecord {
            door_id: fresh_id(),
            owner_mailbox: owner.clone(),
            expires_at: h.now_secs() + 60,
            closed: false,
        };
        tasks.push(tokio::spawn(async move {
            relay
                .store()
                .create_door(&door, 4, relay.now_ms())
                .await
                .unwrap()
        }));
    }
    let mut created = 0;
    for t in tasks {
        if t.await.unwrap() == CreateDoorOutcome::Created {
            created += 1;
        }
    }
    assert_eq!(created, 4);
}

#[tokio::test]
async fn invalid_door_registrations_are_rejected() {
    let h = Harness::start().await;
    let now = h.now_secs();
    let base = door_body(1, &fresh_id(), now + 3600);
    let with = |k: &str, v: Value| {
        let mut b = base.clone();
        b[k] = v;
        b
    };
    let mut no_owner = base.clone();
    no_owner.as_object_mut().unwrap().remove("owner_mailbox");
    let cases = [
        with("expires_at", json!(now + WEEK + 1)),
        with("expires_at", json!(now)),
        with("expires_at", json!(now - 1)),
        with("expires_at", json!("soon")),
        with("door_id", json!("short")),
        with("door_id", json!("!".repeat(22))),
        with("owner_mailbox", json!("short")),
        // The relay holds the mapping and nothing else: no key, no card.
        with("key", json!(b64_encode(b"door public key"))),
        no_owner,
    ];
    for c in cases {
        let (status, err) = post_door(&h, 1, &c).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{c} -> {err}");
        assert_eq!(err["code"], "bad_request");
    }
    let junk = b"not json".to_vec();
    let req = signed_request(&signing_key(1), "POST", "/v0/doors", &junk, h.ts(), HOST);
    assert_eq!(call(&h, req).await.0, StatusCode::BAD_REQUEST);

    // Exactly 7 days is fine.
    let (status, _) = post_door(&h, 1, &with("expires_at", json!(now + WEEK))).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn owner_mailbox_must_be_the_caller_and_ids_are_not_reusable() {
    let h = Harness::start().await;
    let id = fresh_id();
    let (status, err) = post_door(&h, 1, &door_body(2, &id, h.now_secs() + 60)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err["code"], "auth_failed");

    assert_eq!(
        post_door(&h, 1, &door_body(1, &id, h.now_secs() + 60))
            .await
            .0,
        StatusCode::CREATED
    );
    // A public door id can't be taken over by another mailbox, nor
    // re-registered by its owner (after closing it, say).
    let (status, err) = post_door(&h, 2, &door_body(2, &id, h.now_secs() + 60)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["code"], "bad_request");
    close_door(&h, 1, &id).await;
    assert_eq!(
        post_door(&h, 1, &door_body(1, &id, h.now_secs() + 60))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn unsigned_and_replayed_door_requests_are_refused() {
    let h = Harness::start().await;
    let key = signing_key(1);
    let id = fresh_id();
    let body = door_body(1, &id, h.now_secs() + 60)
        .to_string()
        .into_bytes();
    let ts = h.now_secs();

    let unsigned = Request::post("/v0/doors")
        .body(Body::from(body.clone()))
        .unwrap();
    let (status, err) = call(&h, unsigned).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err["code"], "auth_failed");

    let stale = signed_request(&key, "POST", "/v0/doors", &body, ts - 301, HOST);
    assert_eq!(call(&h, stale).await.0, StatusCode::UNAUTHORIZED);
    let wrong_host = signed_request(&key, "POST", "/v0/doors", &body, ts, "evil.test");
    assert_eq!(call(&h, wrong_host).await.0, StatusCode::UNAUTHORIZED);

    let post = || signed_request(&key, "POST", "/v0/doors", &body, ts, HOST);
    assert_eq!(call(&h, post()).await.0, StatusCode::CREATED);
    let (status, err) = call(&h, post()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err["code"], "auth_failed");

    let path = format!("/v0/doors/{id}");
    let unsigned = Request::delete(&path).body(Body::empty()).unwrap();
    assert_eq!(call(&h, unsigned).await.0, StatusCode::UNAUTHORIZED);
    // The door is still open after the refused delete.
    assert_eq!(knock_as(&h, 9, &id).await["t"], "accepted");

    let del = || signed_request(&key, "DELETE", &path, b"", ts + 1, HOST);
    assert_eq!(call(&h, del()).await.0, StatusCode::NO_CONTENT);
    let (status, err) = call(&h, del()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err["code"], "auth_failed");
}

// --- Closing ---------------------------------------------------------------

#[tokio::test]
async fn only_the_owner_can_close_a_door_and_it_closes_at_once() {
    let h = Harness::start().await;
    let id = open_door(&h, 1).await;

    let (status, err) = close_door(&h, 2, &id).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(err["code"], "auth_failed");
    assert_eq!(knock_as(&h, 3, &id).await["t"], "accepted");

    assert_eq!(close_door(&h, 1, &id).await.0, StatusCode::NO_CONTENT);
    let r = knock_as(&h, 4, &id).await;
    assert_eq!(r["code"], "door_not_open", "{r}");
    // Closing twice is fine.
    assert_eq!(close_door(&h, 1, &id).await.0, StatusCode::NO_CONTENT);

    for unknown in [fresh_id(), "not-an-id".to_owned()] {
        let (status, err) = close_door(&h, 1, &unknown).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], "door_not_open");
    }
}

// --- Knocks ----------------------------------------------------------------

#[tokio::test]
async fn a_knock_is_delivered_to_the_owner_and_the_knocker_learns_nothing_more() {
    let h = Harness::start().await;
    let mut owner = h.client(1).await;
    owner.drained().await;
    let mut knocker = h.client(2).await;
    let id = open_door(&h, 1).await;

    let frame = knock_frame(&knocker.mailbox, &id);
    let r = knocker.request(&frame).await;
    assert_eq!(
        r,
        json!({"t": "accepted", "msg_id": frame["env"]["msg_id"]})
    );
    // The knock worker writes on its own clock.
    h.relay.flush_knocks().await;

    let got = owner.deliver().await;
    assert_eq!(got, frame["env"], "forwarded verbatim");
    assert_eq!(got["kind"], "knock");
    assert!(got.get("group_id").is_none() && got.get("to").is_none());
    owner.ack(got["msg_id"].as_str().unwrap()).await;

    // No delivery receipt and no reject frame: after another round trip the
    // knocker has received nothing but its replies.
    let r = knocker
        .request(&json!({"t": "invite.consume", "invite_id": fresh_id()}))
        .await;
    assert_eq!(r["code"], "invite_not_open");
    assert_eq!(knocker.buffered_delivers(), 0);
}

#[tokio::test]
async fn a_knock_waits_for_an_offline_owner() {
    let h = Harness::start().await;
    let id = open_door(&h, 1).await;
    let mut knocker = h.client(2).await;
    let frame = knock_frame(&knocker.mailbox, &id);
    assert_eq!(knocker.request(&frame).await["t"], "accepted");
    h.relay.flush_knocks().await;

    // The owner connects later and gets it in the reconnect drain.
    h.clock.advance(Duration::from_secs(3 * 24 * 3600));
    let mut owner = h.client(1).await;
    assert_eq!(owner.drained().await, 1);
    let got = owner.deliver().await;
    assert_eq!(got["msg_id"], frame["env"]["msg_id"]);
    assert_eq!(got["door_id"], id);

    // Unacked, it is kept for the message TTL like any delivery.
    let key = owner.disconnect().await;
    let mut owner = Client::connect(h.addr, key).await;
    assert_eq!(owner.drained().await, 1);
    owner.deliver().await;
}

#[tokio::test]
async fn unknown_expired_and_closed_doors_are_not_open() {
    let h = Harness::start().await;
    let unknown = knock_as(&h, 2, &fresh_id()).await;
    assert_eq!(unknown["t"], "error");
    assert_eq!(unknown["code"], "door_not_open");
    assert_eq!(unknown["msg_id"].as_str().map(str::len), Some(22));

    let id = fresh_id();
    let expires = h.now_secs() + 600;
    assert_eq!(
        post_door(&h, 1, &door_body(1, &id, expires)).await.0,
        StatusCode::CREATED
    );
    h.clock.advance(Duration::from_secs(599));
    assert_eq!(knock_as(&h, 2, &id).await["t"], "accepted");
    h.clock.advance(Duration::from_secs(1));
    assert_eq!(knock_as(&h, 3, &id).await["code"], "door_not_open");

    let closed = open_door(&h, 1).await;
    close_door(&h, 1, &closed).await;
    assert_eq!(knock_as(&h, 4, &closed).await["code"], "door_not_open");
}

#[tokio::test]
async fn expired_doors_are_purged_and_closed_ones_kept_until_expiry() {
    let h = Harness::start().await;
    let short = fresh_id();
    post_door(&h, 1, &door_body(1, &short, h.now_secs() + 60)).await;
    let closed = open_door(&h, 1).await;
    close_door(&h, 1, &closed).await;
    let open = open_door(&h, 1).await;

    assert_eq!(h.relay.purge().await.unwrap().doors, 0);
    h.clock.advance(Duration::from_secs(60));
    assert_eq!(h.relay.purge().await.unwrap().doors, 1);
    assert!(h.relay.store().get_door(&short).await.unwrap().is_none());
    // The closed door's id stays taken until it would have expired.
    assert!(h.relay.store().get_door(&closed).await.unwrap().is_some());
    assert_eq!(knock_as(&h, 2, &open).await["t"], "accepted");

    h.clock.advance(Duration::from_secs(3600));
    assert_eq!(h.relay.purge().await.unwrap().doors, 2);
    assert!(h.relay.store().get_door(&open).await.unwrap().is_none());
}

#[tokio::test]
async fn one_knock_per_door_and_sender_per_ten_minutes() {
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    let other = open_door(&h, 1).await;

    assert_eq!(knock_as(&h, 2, &door).await["t"], "accepted");
    let r = knock_as(&h, 2, &door).await;
    assert_eq!(r["code"], "rate_limited", "{r}");
    // Other doors and other senders are unaffected.
    assert_eq!(knock_as(&h, 2, &other).await["t"], "accepted");
    assert_eq!(knock_as(&h, 3, &door).await["t"], "accepted");

    // Maintenance in between doesn't forget a window longer than a minute.
    h.clock.advance(Duration::from_secs(120));
    h.relay.purge().await.unwrap();
    h.clock.advance(Duration::from_secs(479));
    assert_eq!(knock_as(&h, 2, &door).await["code"], "rate_limited");
    h.clock.advance(Duration::from_secs(1));
    assert_eq!(knock_as(&h, 2, &door).await["t"], "accepted");
}

#[tokio::test]
async fn twenty_knocks_per_sender_per_hour_across_doors() {
    let h = Harness::start().await;
    // 4 doors per mailbox, so 6 owners hold 24 doors.
    let mut doors = Vec::new();
    for owner in 1..=6 {
        for _ in 0..4 {
            let id = fresh_id();
            let body = door_body(owner, &id, h.now_secs() + WEEK);
            assert_eq!(post_door(&h, owner, &body).await.0, StatusCode::CREATED);
            doors.push(id);
        }
    }
    assert_eq!(knock_as(&h, 50, &doors[0]).await["t"], "accepted");
    h.clock.advance(Duration::from_secs(3300));
    h.relay.purge().await.unwrap();
    for (i, d) in doors.iter().enumerate().take(20).skip(1) {
        assert_eq!(knock_as(&h, 50, d).await["t"], "accepted", "knock {i}");
    }
    let r = knock_as(&h, 50, &doors[20]).await;
    assert_eq!(r["code"], "rate_limited", "{r}");
    // The first knock leaves the hour's window; the refused one didn't use
    // up the pair budget, so the same door takes it 5 minutes later.
    h.clock.advance(Duration::from_secs(300));
    assert_eq!(knock_as(&h, 50, &doors[20]).await["t"], "accepted");
    assert_eq!(knock_as(&h, 50, &doors[21]).await["code"], "rate_limited");
    // Another sender has its own budget.
    assert_eq!(knock_as(&h, 51, &doors[22]).await["t"], "accepted");
}

#[tokio::test]
async fn per_door_overflow_is_accepted_and_dropped_silently() {
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    for n in 0..10 {
        assert_eq!(knock_as(&h, 100 + n, &door).await["t"], "accepted");
    }
    // The 11th in the minute looks the same to its sender but goes nowhere.
    let r = knock_as(&h, 110, &door).await;
    assert_eq!(r["t"], "accepted", "{r}");
    assert_eq!(queued(&h, 1).await.len(), 10);
    // The per-door budget refills after a minute.
    h.clock.advance(Duration::from_secs(60));
    assert_eq!(knock_as(&h, 111, &door).await["t"], "accepted");
    assert_eq!(queued(&h, 1).await.len(), 11);
    // A dropped knock still counts against its sender's own limits.
    assert_eq!(knock_as(&h, 110, &door).await["code"], "rate_limited");
}

#[tokio::test]
async fn forwarded_and_dropped_knocks_take_the_same_path_until_the_worker_writes() {
    use agentconnect_relay::proto::parse_client_frame;
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    let knock = |n: u8| {
        let mailbox = mailbox_of(&signing_key(n));
        let frame = knock_frame(&mailbox, &door).to_string();
        (
            mailbox,
            parse_client_frame(&frame, agentconnect_relay::DEFAULT_FRAME_MAX).unwrap(),
        )
    };
    // SR-16: the answer is ready and nothing is written yet. Both kinds of
    // knock come back to be queued for the knock worker.
    let (mailbox, frame) = knock(2);
    let (reply, forward) = h.relay.handle_deferred(&mailbox, None, frame).await;
    let reply = serde_json::to_value(reply.unwrap()).unwrap();
    assert_eq!(reply["t"], "accepted");
    let forward = forward.expect("an accepted knock goes to the worker");
    assert!(forward.forwards());
    h.relay
        .queue_knock(forward, agentconnect_relay::conn::SourceKey::unknown());
    assert!(queued(&h, 1).await.is_empty());
    h.relay.flush_knocks().await;
    assert_eq!(queued(&h, 1).await.len(), 1);
    // A busy door answers the same way and queues the same way; the worker
    // writes nothing for it.
    for n in 3..12 {
        assert_eq!(knock_as(&h, n, &door).await["t"], "accepted");
    }
    let (mailbox, frame) = knock(12);
    let (busy, forward) = h.relay.handle_deferred(&mailbox, None, frame).await;
    let busy = serde_json::to_value(busy.unwrap()).unwrap();
    assert_eq!(busy["t"], reply["t"]);
    let forward = forward.expect("a dropped knock goes to the worker too");
    assert!(!forward.forwards());
    h.relay
        .queue_knock(forward, agentconnect_relay::conn::SourceKey::unknown());
    h.relay.flush_knocks().await;
    assert_eq!(queued(&h, 1).await.len(), 10);
}

#[tokio::test]
async fn the_knock_worker_writes_on_its_own_tick() {
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    let mut knocker = h.client(2).await;
    let frame = knock_frame(&knocker.mailbox, &door);
    assert_eq!(knocker.request(&frame).await["t"], "accepted");
    // Answered, not written: the knocker's next frames never wait on it.
    assert!(queued(&h, 1).await.is_empty());
    h.timer
        .advance(agentconnect_relay::relay::KNOCK_FLUSH_INTERVAL);
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while queued(&h, 1).await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the worker wrote the knock at its tick");
}

#[tokio::test]
async fn a_full_owner_queue_is_answered_with_accepted() {
    let h = Harness::with_limits(Limits {
        non_member_queue_max_bytes: 1000,
        sends_per_sec: 100_000,
        ..Limits::default()
    })
    .await;
    let mut doors = Vec::new();
    for _ in 0..4 {
        doors.push(open_door(&h, 1).await);
    }
    let mut answers = Vec::new();
    for (n, d) in (20..30).zip(doors.iter().cycle()) {
        answers.push(knock_as(&h, n, d).await);
    }
    assert!(answers.iter().all(|r| r["t"] == "accepted"), "{answers:?}");
    let kept = queued(&h, 1).await;
    assert!(!kept.is_empty() && kept.len() < 10, "{}", kept.len());
    // No overflow marker either: the owner isn't told how many it missed.
    assert!(kept.iter().all(|m| m["kind"] == "knock"));
}

#[tokio::test]
async fn a_repeated_knock_is_not_delivered_twice() {
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    let mailbox = mailbox_of(&signing_key(2));
    let frame = knock_frame(&mailbox, &door);
    assert_eq!(knock_frame_as(&h, &mailbox, &frame).await["t"], "accepted");
    h.clock.advance(Duration::from_secs(600));
    assert_eq!(knock_frame_as(&h, &mailbox, &frame).await["t"], "accepted");
    assert_eq!(queued(&h, 1).await.len(), 1);
}

#[tokio::test]
async fn knock_ct_is_at_most_16_kib() {
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    let mut knocker = h.client(2).await;

    let mut frame = knock_frame(&knocker.mailbox, &door);
    frame["env"]["ct"] = json!(b64_encode(&vec![7_u8; MAX_KNOCK_CT + 1]));
    let r = knocker.request(&frame).await;
    assert_eq!(r["code"], "too_large", "{r}");

    let mut frame = knock_frame(&knocker.mailbox, &door);
    frame["env"]["ct"] = json!(b64_encode(&vec![7_u8; MAX_KNOCK_CT]));
    assert_eq!(knocker.request(&frame).await["t"], "accepted");
}

#[tokio::test]
async fn malformed_knocks_are_bad_requests() {
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    let mailbox = mailbox_of(&signing_key(2));
    let base = knock_frame(&mailbox, &door);
    let with = |path: &[&str], v: Value| {
        let mut f = base.clone();
        let mut at = &mut f;
        for p in &path[..path.len() - 1] {
            at = &mut at[*p];
        }
        at[path[path.len() - 1]] = v;
        f
    };
    let mut no_door = base.clone();
    no_door["env"].as_object_mut().unwrap().remove("door_id");
    let cases = [
        with(&["door_id"], json!(fresh_id())),
        with(&["door_id"], json!("short")),
        with(&["env", "door_id"], json!("short")),
        with(&["env", "sender"], json!(mailbox_of(&signing_key(3)))),
        with(&["env", "group_id"], json!(fresh_id())),
        with(&["env", "epoch"], json!(0)),
        with(&["env", "to"], json!([mailbox_of(&signing_key(1))])),
        with(&["env", "kind"], json!("join_request")),
        no_door,
    ];
    for c in cases {
        let r = knock_frame_as(&h, &mailbox, &c).await;
        assert_eq!(r["code"], "bad_request", "{c} -> {r}");
    }
    // A knock envelope only travels in a knock frame, and only to a door.
    let env = knock_env(&mailbox, &door);
    let send = knock_frame_as(&h, &mailbox, &json!({"t": "send", "env": env})).await;
    assert_eq!(send["code"], "bad_request");
    let join = json!({"t": "join", "invite_id": fresh_id(), "env": env});
    assert_eq!(
        knock_frame_as(&h, &mailbox, &join).await["code"],
        "bad_request"
    );
    // Other kinds can't carry a door id.
    let mut app_env = envelope("application", Some(&fresh_id()), Some(0), &mailbox);
    app_env["door_id"] = json!(door);
    let r = knock_frame_as(&h, &mailbox, &json!({"t": "send", "env": app_env})).await;
    assert_eq!(r["code"], "bad_request");
    assert!(queued(&h, 1).await.is_empty());
}

// --- Logs and metrics -------------------------------------------------------

#[tokio::test]
async fn door_metrics_count_outcomes_only() {
    let h = Harness::start().await;
    let door = open_door(&h, 1).await;
    for n in 0..11 {
        knock_as(&h, 30 + n, &door).await;
    }
    knock_as(&h, 30, &door).await;
    close_door(&h, 1, &door).await;
    knock_as(&h, 50, &door).await;

    let text = h.relay.metrics().render();
    assert!(
        text.contains("agentconnect_relay_doors_registered_total 1"),
        "{text}"
    );
    assert!(text.contains("agentconnect_relay_doors_closed_total 1"));
    // 10 forwarded and 1 dropped are one number, and knocks don't move the
    // delivery counter: /metrics is public and must not show what
    // `accepted` hides.
    assert!(text.contains("agentconnect_relay_knocks_accepted_total 11"));
    assert!(text.contains("agentconnect_relay_deliveries_total 0"));
    assert!(!text.contains("dropped"));
    assert!(text.contains("agentconnect_relay_errors_total{code=\"door_not_open\"} 1"));
    assert!(text.contains("agentconnect_relay_errors_total{code=\"rate_limited\"} 1"));
    assert!(!text.contains(&door));
    assert!(!text.contains(&mailbox_of(&signing_key(1))));
}
