//! Group quotas on a public relay (SPEC §8.3): `group.create` per mailbox,
//! and deleting idle groups. Regression tests for security review finding
//! SR-07.

mod common;

use std::time::Duration;

use agentconnect_relay::Quotas;
use agentconnect_relay::proto::parse_client_frame;
use agentconnect_relay::quota::ACTIVITY_GRANULARITY;
use agentconnect_relay::store::{Store, Window};
use agentconnect_relay::{DEFAULT_FRAME_MAX, Relay, SqliteStore};
use common::{Harness, envelope, fresh_id, mailbox_of, roomy_quotas, signing_key};
use serde_json::{Value, json};

const DAY: Duration = Duration::from_hours(24);
/// How coarse the recorded activity time is; the sweep waits this long more.
const MARGIN: Duration = ACTIVITY_GRANULARITY;

/// Handle `frame` as `mailbox` straight in the relay, with no connection
/// open: the mailbox counts as disconnected unless the test registers it.
async fn frame_as(relay: &Relay<SqliteStore>, mailbox: &str, frame: &Value) -> Value {
    let parsed = parse_client_frame(&frame.to_string(), DEFAULT_FRAME_MAX).unwrap();
    serde_json::to_value(relay.handle(mailbox, parsed).await.unwrap()).unwrap()
}

fn mailbox(n: u8) -> String {
    mailbox_of(&signing_key(n))
}

async fn create(h: &Harness, who: &str, gid: &str) -> Value {
    let frame = json!({"t": "group.create", "group_id": gid, "epoch": 0});
    frame_as(&h.relay, who, &frame).await
}

async fn send(h: &Harness, who: &str, gid: &str, kind: &str, epoch: u64, add: &[&str]) -> Value {
    let mut env = envelope(kind, Some(gid), Some(epoch), who);
    if kind == "commit" {
        env["routing"] = json!({"add": add, "remove": []});
    }
    frame_as(&h.relay, who, &json!({"t": "send", "env": env})).await
}

#[tokio::test]
async fn a_mailbox_creates_a_bounded_number_of_groups_per_day() {
    let h = Harness::with_quotas(Quotas {
        groups_per_mailbox: Window { max: 2, per: DAY },
        ..roomy_quotas()
    })
    .await;
    let (a, b) = (mailbox(1), mailbox(2));
    assert_eq!(create(&h, &a, &fresh_id()).await["t"], "accepted");
    assert_eq!(create(&h, &a, &fresh_id()).await["t"], "accepted");
    let r = create(&h, &a, &fresh_id()).await;
    assert_eq!(r["code"], "quota_exceeded", "{r}");
    assert_eq!(create(&h, &b, &fresh_id()).await["t"], "accepted");
    h.clock.advance(DAY);
    assert_eq!(create(&h, &a, &fresh_id()).await["t"], "accepted");
}

#[tokio::test]
async fn idle_groups_are_deleted_once_no_member_is_connected() {
    let h = Harness::with_quotas(Quotas {
        group_idle: 30 * DAY,
        ..roomy_quotas()
    })
    .await;
    let (a, b) = (mailbox(3), mailbox(4));
    let quiet = fresh_id();
    let busy = fresh_id();
    assert_eq!(create(&h, &a, &quiet).await["t"], "accepted");
    assert_eq!(
        send(&h, &a, &quiet, "commit", 0, &[&b]).await["t"],
        "accepted"
    );
    assert_eq!(create(&h, &a, &busy).await["t"], "accepted");

    h.clock.advance(20 * DAY);
    assert_eq!(
        send(&h, &a, &busy, "application", 0, &[]).await["t"],
        "accepted"
    );
    h.clock.advance(10 * DAY + MARGIN + Duration::from_secs(1));

    // `quiet` is idle, but its member b is connected.
    let b_online = h.relay.register(&b, usize::MAX).0;
    assert_eq!(h.relay.sweep_idle_groups().await.unwrap(), 0);
    drop(b_online);
    assert_eq!(h.relay.sweep_idle_groups().await.unwrap(), 1);
    assert!(h.relay.store().get_group(&quiet).await.unwrap().is_none());
    assert!(h.relay.store().get_group(&busy).await.unwrap().is_some());

    // A member that comes back hears that the group is unknown.
    for (kind, epoch) in [("application", 1), ("commit", 1), ("proposal", 1)] {
        let r = send(&h, &b, &quiet, kind, epoch, &[]).await;
        assert_eq!(r["code"], "unknown_group", "{kind}: {r}");
    }

    // `busy` goes 30 days after its last send.
    h.clock.advance(20 * DAY);
    assert_eq!(h.relay.sweep_idle_groups().await.unwrap(), 1);
    assert!(h.relay.store().get_group(&busy).await.unwrap().is_none());

    let metrics = h.relay.metrics().render();
    assert!(
        metrics.contains("agentconnect_relay_idle_groups_deleted_total 2"),
        "{metrics}"
    );
}

#[tokio::test]
async fn the_periodic_purge_runs_the_idle_sweep_hourly() {
    let h = Harness::start().await;
    let (a, c) = (mailbox(5), mailbox(7));
    let first = fresh_id();
    let second = fresh_id();
    assert_eq!(create(&h, &a, &first).await["t"], "accepted");
    assert_eq!(create(&h, &c, &second).await["t"], "accepted");
    // Not in the first hour after the relay started: members reconnect.
    h.clock.advance(Duration::from_mins(59));
    h.relay.purge().await.unwrap();
    assert!(h.relay.store().get_group(&first).await.unwrap().is_some());

    h.clock.advance(h.relay.quotas().group_idle + MARGIN);
    let c_online = h.relay.register(&c, usize::MAX).0;
    h.relay.purge().await.unwrap();
    drop(c_online);
    assert!(h.relay.store().get_group(&first).await.unwrap().is_none());
    assert!(h.relay.store().get_group(&second).await.unwrap().is_some());

    // The next sweep waits an hour.
    h.clock.advance(Duration::from_mins(59));
    h.relay.purge().await.unwrap();
    assert!(h.relay.store().get_group(&second).await.unwrap().is_some());
    h.clock.advance(Duration::from_mins(1));
    h.relay.purge().await.unwrap();
    assert!(h.relay.store().get_group(&second).await.unwrap().is_none());
}

#[tokio::test]
async fn the_sweep_pages_through_many_idle_groups() {
    let h = Harness::start().await;
    let a = mailbox(6);
    let ids: Vec<String> = (0..501).map(|_| fresh_id()).collect();
    for id in &ids {
        assert_eq!(create(&h, &a, id).await["t"], "accepted");
    }
    h.clock
        .advance(h.relay.quotas().group_idle + MARGIN + Duration::from_secs(1));
    let online = h.relay.register(&a, usize::MAX).0;
    assert_eq!(h.relay.sweep_idle_groups().await.unwrap(), 0);
    drop(online);
    assert_eq!(h.relay.sweep_idle_groups().await.unwrap(), 501);
}

#[tokio::test]
async fn an_idle_period_longer_than_the_clock_deletes_nothing() {
    let h = Harness::with_quotas(Quotas {
        group_idle: Duration::MAX,
        ..roomy_quotas()
    })
    .await;
    let gid = fresh_id();
    assert_eq!(create(&h, &mailbox(8), &gid).await["t"], "accepted");
    h.clock.advance(400 * DAY);
    assert_eq!(h.relay.sweep_idle_groups().await.unwrap(), 0);
    assert!(h.relay.store().get_group(&gid).await.unwrap().is_some());
}

#[tokio::test]
async fn a_group_is_kept_for_the_whole_idle_period_after_its_last_send() {
    // Review probe P2: a send within the hour of the last recorded one
    // isn't written, so the sweep waits that hour more.
    let h = Harness::with_quotas(Quotas {
        group_idle: 30 * DAY,
        ..roomy_quotas()
    })
    .await;
    let a = mailbox(9);
    let gid = fresh_id();
    assert_eq!(create(&h, &a, &gid).await["t"], "accepted");
    h.clock.advance(Duration::from_mins(61));
    assert_eq!(
        send(&h, &a, &gid, "application", 0, &[]).await["t"],
        "accepted"
    );
    h.clock.advance(Duration::from_mins(59));
    assert_eq!(
        send(&h, &a, &gid, "application", 0, &[]).await["t"],
        "accepted"
    );
    // The last send was 30 days ago, less a second.
    h.clock.advance(30 * DAY - Duration::from_secs(1));
    assert_eq!(h.relay.sweep_idle_groups().await.unwrap(), 0);
    h.clock.advance(Duration::from_secs(1));
    assert_eq!(h.relay.sweep_idle_groups().await.unwrap(), 0);
    // An hour after the idle period from the recorded send, it goes.
    h.clock.advance(Duration::from_mins(2));
    assert_eq!(h.relay.sweep_idle_groups().await.unwrap(), 1);
}

async fn create_from(h: &Harness, who: &str, ip: &str, gid: &str) -> Value {
    let frame = json!({"t": "group.create", "group_id": gid, "epoch": 0});
    let parsed = parse_client_frame(&frame.to_string(), DEFAULT_FRAME_MAX).unwrap();
    let ip = Some(ip.parse().unwrap());
    serde_json::to_value(h.relay.handle_from(who, ip, parsed).await.unwrap()).unwrap()
}

#[tokio::test]
async fn one_address_creates_a_bounded_number_of_groups_whatever_its_mailboxes() {
    // Review finding 1: mailboxes are free, so groups count per address too,
    // for the idle period after their creation.
    let h = Harness::with_quotas(Quotas {
        groups_per_address: 2,
        ..roomy_quotas()
    })
    .await;
    for n in 20..22 {
        let r = create_from(&h, &mailbox(n), "203.0.113.7", &fresh_id()).await;
        assert_eq!(r["t"], "accepted", "{r}");
    }
    let r = create_from(&h, &mailbox(22), "203.0.113.7", &fresh_id()).await;
    assert_eq!(r["code"], "quota_exceeded", "{r}");
    // Another address is not affected.
    let r = create_from(&h, &mailbox(22), "2001:db8:1:2::1", &fresh_id()).await;
    assert_eq!(r["t"], "accepted", "{r}");
    // A refused creation (an existing id) holds nothing.
    let gid = fresh_id();
    assert_eq!(
        create_from(&h, &mailbox(23), "198.51.100.3", &gid).await["t"],
        "accepted"
    );
    // Another mailbox's claim on the id is refused; the creator's repeat
    // (its reply was lost) is accepted. Neither counts.
    let r = create_from(&h, &mailbox(24), "198.51.100.3", &gid).await;
    assert_eq!(r["code"], "bad_request");
    let r = create_from(&h, &mailbox(23), "198.51.100.3", &gid).await;
    assert_eq!(r["t"], "accepted", "{r}");
    let r = create_from(&h, &mailbox(23), "198.51.100.3", &fresh_id()).await;
    assert_eq!(r["t"], "accepted", "{r}");
    // After the idle period (and its margin) the address counts nothing.
    h.clock
        .advance(h.relay.quotas().group_idle + MARGIN + Duration::from_secs(1));
    let r = create_from(&h, &mailbox(22), "203.0.113.7", &fresh_id()).await;
    assert_eq!(r["t"], "accepted", "{r}");
}

#[tokio::test]
async fn the_relay_holds_a_bounded_number_of_groups() {
    let h = Harness::with_quotas(Quotas {
        max_groups: 2,
        ..roomy_quotas()
    })
    .await;
    assert_eq!(create(&h, &mailbox(24), &fresh_id()).await["t"], "accepted");
    assert_eq!(create(&h, &mailbox(25), &fresh_id()).await["t"], "accepted");
    let r = create(&h, &mailbox(26), &fresh_id()).await;
    assert_eq!(r["code"], "quota_exceeded", "{r}");
    let metrics = h.relay.metrics().render();
    assert!(
        metrics.contains("agentconnect_relay_groups 2\n"),
        "{metrics}"
    );
    assert!(
        metrics.contains("agentconnect_relay_groups_max 2\n"),
        "{metrics}"
    );
    // Idle groups go, and the purge recounts.
    h.clock
        .advance(h.relay.quotas().group_idle + MARGIN + Duration::from_secs(1));
    h.relay.purge().await.unwrap();
    assert!(
        h.relay
            .metrics()
            .render()
            .contains("agentconnect_relay_groups 0\n")
    );
    assert_eq!(create(&h, &mailbox(26), &fresh_id()).await["t"], "accepted");
}

/// The n-th /64 inside one /48 (and one /56).
fn slash_64_in_one_slash_48(n: u64) -> String {
    format!("2001:db8:0:{n:x}::1")
}

/// A host in the n-th /48.
fn in_slash_48(n: u64) -> String {
    format!("2001:db8:{n:x}::1")
}

#[tokio::test]
async fn one_slash_48_is_one_key_however_many_slash_64s() {
    // Verification probe V1: one /56 held 256 /64 keys, so 200 of them
    // filled the global cap. Creations count per /48.
    let h = Harness::with_quotas(Quotas {
        groups_per_address: 5,
        max_groups: 1_000,
        ..roomy_quotas()
    })
    .await;
    let attacker = mailbox(30);
    let mut accepted = 0;
    for n in 0..256 {
        let r = create_from(&h, &attacker, &slash_64_in_one_slash_48(n), &fresh_id()).await;
        if r["t"] == "accepted" {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 5);
    let r = create_from(&h, &mailbox(31), "198.51.100.7", &fresh_id()).await;
    assert_eq!(r["t"], "accepted", "{r}");
}

#[tokio::test]
async fn many_slash_48s_up_to_the_cap_leave_a_reserve_for_a_light_client() {
    // Verification probe V1 at scale: an attacker with enough /48s to reach
    // the cap. Under pressure each key gets only its fair share, and the
    // last 5% is kept for keys holding fewer than two groups.
    let h = Harness::with_quotas(Quotas {
        groups_per_address: 5,
        max_groups: 1_000,
        ..roomy_quotas()
    })
    .await;
    let attacker = mailbox(32);
    let soft = 950;
    let (mut live, mut keys) = (0, 0_u64);
    while live < soft {
        for _ in 0..5 {
            let r = create_from(&h, &attacker, &in_slash_48(keys), &fresh_id()).await;
            if r["t"] == "accepted" {
                live += 1;
            }
        }
        keys += 1;
    }
    assert_eq!(live, soft);
    // More than the 200 keys it took without fairness.
    assert!(keys > 200, "{keys}");
    // Every key the attacker holds groups with is refused now, and the
    // global count stays below the cap.
    for n in 0..keys {
        let r = create_from(&h, &attacker, &in_slash_48(n), &fresh_id()).await;
        assert_eq!(r["code"], "quota_exceeded", "{n}: {r}");
    }
    // A light, honest client still starts a conversation, and a second.
    let honest = mailbox(33);
    for _ in 0..2 {
        let r = create_from(&h, &honest, "198.51.100.7", &fresh_id()).await;
        assert_eq!(r["t"], "accepted", "{r}");
    }
    let r = create_from(&h, &honest, "198.51.100.7", &fresh_id()).await;
    assert_eq!(r["code"], "quota_exceeded", "{r}");
    // So does a client on IPv6, from its own /48.
    let r = create_from(&h, &mailbox(34), "2001:db9::1", &fresh_id()).await;
    assert_eq!(r["t"], "accepted", "{r}");
    assert!(
        h.relay
            .metrics()
            .render()
            .contains("agentconnect_relay_groups 953\n")
    );
}
