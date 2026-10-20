//! Mailbox storage (SPEC §8.3 "Storage" and "Limits"; security review
//! SR-03, SR-04, SR-05, SR-17, SR-18): payloads stored once, the Welcome
//! rule, the two queue buckets, the sender budget, the high-water mark,
//! the counters, `secure_delete` and the migration of an old database.

use std::path::{Path, PathBuf};

use agentconnect_relay::SqliteStore;
use agentconnect_relay::proto::Kind;
use agentconnect_relay::store::{
    DirectOutcome, GroupOutcome, GroupSend, Limits, NewMessage, PurgeStats, Store,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{AssertSqlSafe, Executor, Row};

const NOW: u64 = 1_735_689_600_000;
const GID: &str = "group-one-0000000000AA";
const OTHER: &str = "group-two-0000000000AA";

fn mb(n: u32) -> String {
    format!("mailbox-{n:0>14}")
}

fn msg(sender: &str, id: &str, bytes: usize) -> NewMessage {
    NewMessage {
        msg_id: id.into(),
        sender: sender.into(),
        json: format!(r#"{{"msg_id":"{id}","ct":"{}"}}"#, "x".repeat(bytes)),
    }
}

struct Send<'a> {
    kind: Kind,
    group: &'a str,
    sender: &'a str,
    epoch: u64,
    add: Vec<String>,
    remove: Vec<String>,
    to: Vec<String>,
}

impl<'a> Send<'a> {
    fn new(kind: Kind, group: &'a str, sender: &'a str, epoch: u64) -> Self {
        Self {
            kind,
            group,
            sender,
            epoch,
            add: Vec::new(),
            remove: Vec::new(),
            to: Vec::new(),
        }
    }

    async fn go(&self, s: &SqliteStore, m: &NewMessage, limits: &Limits, now: u64) -> GroupOutcome {
        let send = GroupSend {
            kind: self.kind,
            group_id: self.group,
            sender: self.sender,
            epoch: self.epoch,
            add: &self.add,
            remove: &self.remove,
            to: &self.to,
            msg: m,
            ct_bytes: m.json.len(),
        };
        s.deliver_group(&send, limits, now).await.unwrap()
    }
}

fn welcome<'a>(sender: &'a str, to: &[String], id: &str) -> (Send<'a>, NewMessage) {
    let mut w = Send::new(Kind::WelcomeWrapped, GID, sender, 0);
    w.to = to.to_vec();
    (w, msg(sender, id, 10))
}

fn delivered(o: &GroupOutcome) -> bool {
    matches!(o, GroupOutcome::Delivered { .. })
}

struct Db {
    _dir: tempfile::TempDir,
    path: PathBuf,
    store: SqliteStore,
}

async fn db() -> Db {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let store = SqliteStore::open(path.to_str().unwrap()).await.unwrap();
    Db {
        _dir: dir,
        path,
        store,
    }
}

async fn inspect(path: &Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(path).read_only(true))
        .await
        .unwrap()
}

/// `creator` creates `group` and one commit adds `added`; returns the
/// group's epoch after it.
async fn group(s: &SqliteStore, group: &str, creator: &str, added: &[String]) -> u64 {
    s.create_group(group, creator, NOW).await.unwrap();
    if added.is_empty() {
        return 0;
    }
    let mut c = Send::new(Kind::Commit, group, creator, 0);
    c.add = added.to_vec();
    let id = format!("add-{group}");
    assert!(delivered(
        &c.go(s, &msg(creator, &id, 10), &Limits::default(), NOW)
            .await
    ));
    s.ack(creator, &id).await.unwrap();
    1
}

/// The byte counters equal what they count, and no payload is orphaned.
async fn assert_counters(pool: &SqlitePool) {
    let rows = |q: &'static str| async move {
        pool.fetch_all(q)
            .await
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>(0),
                    r.get::<i64, _>(1),
                    r.get::<String, _>(2),
                    r.get::<i64, _>(3),
                )
            })
            .collect::<Vec<_>>()
    };
    let pairs = [
        (
            "SELECT mailbox, bucket, '', bytes FROM mailbox_usage ORDER BY 1, 2",
            "SELECT mailbox, bucket, '', SUM(size) FROM messages \
             GROUP BY mailbox, bucket ORDER BY 1, 2",
        ),
        (
            "SELECT mailbox, bucket, group_id, bytes FROM group_usage ORDER BY 1, 2, 3",
            "SELECT mailbox, bucket, group_id, SUM(size) FROM messages \
             GROUP BY mailbox, bucket, group_id ORDER BY 1, 2, 3",
        ),
        (
            "SELECT sender, 0, '', bytes FROM sender_usage ORDER BY 1",
            "SELECT sender, 0, '', SUM(size) FROM payloads WHERE sender != '' \
             GROUP BY sender ORDER BY 1",
        ),
        (
            "SELECT sender, 0, group_id, bytes FROM sender_group_usage ORDER BY 1, 3",
            "SELECT sender, 0, group_id, SUM(size) FROM payloads WHERE sender != '' \
             GROUP BY sender, group_id ORDER BY 1, 3",
        ),
    ];
    for (counters, rows_of) in pairs {
        assert_eq!(rows(counters).await, rows(rows_of).await, "{counters}");
    }
    let orphans: i64 = pool
        .fetch_one(
            "SELECT COUNT(*) FROM payloads p WHERE NOT EXISTS \
             (SELECT 1 FROM messages m WHERE m.payload = p.id)",
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(orphans, 0);
    let mixed: i64 = pool
        .fetch_one(
            "SELECT COUNT(*) FROM messages m JOIN payloads p ON p.id = m.payload \
             WHERE m.group_id != p.group_id",
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        mixed, 0,
        "a queue row and its payload name different groups"
    );
}

// --- SR-03: one payload, many recipients -------------------------------------

#[tokio::test]
async fn a_payload_is_stored_once_however_many_mailboxes_receive_it() {
    let d = db().await;
    let s = &d.store;
    let a = mb(0);
    let others: Vec<String> = (1..50).map(mb).collect();
    let epoch = group(s, GID, &a, &others).await;
    let before = s.storage_bytes().await.unwrap();

    // A Welcome to the 49 added mailboxes and an application message to
    // the 49 members, 200 KB each: stored once each, not 49 times.
    let mut w = Send::new(Kind::WelcomeWrapped, GID, &a, 0);
    w.to = others.clone();
    let big = 200_000;
    assert!(delivered(
        &w.go(s, &msg(&a, "w", big), &Limits::default(), NOW).await
    ));
    let app = Send::new(Kind::Application, GID, &a, epoch);
    assert!(delivered(
        &app.go(s, &msg(&a, "m", big), &Limits::default(), NOW).await
    ));
    let grown = s.storage_bytes().await.unwrap() - before;
    assert!(
        grown < 3 * big as u64,
        "grew {grown} bytes for two {big}-byte payloads"
    );

    // Every recipient reads the whole envelope, and is charged its size.
    for o in &others {
        let q = s.pending(o, 0, 10, u64::MAX, NOW).await.unwrap();
        assert_eq!(q.len(), 2);
        assert!(q.iter().all(|m| m.json.len() > big));
    }
    assert_counters(&inspect(&d.path).await).await;
}

// --- SR-03: the Welcome rule ------------------------------------------------

#[tokio::test]
async fn a_welcome_goes_only_to_mailboxes_the_senders_commit_added_and_once() {
    let d = db().await;
    let s = &d.store;
    let limits = Limits::default();
    let (a, b, c, stranger) = (mb(1), mb(2), mb(3), mb(9));
    group(s, GID, &a, std::slice::from_ref(&b)).await;

    // Never added.
    let (w, m) = welcome(&a, std::slice::from_ref(&stranger), "w0");
    assert_eq!(
        w.go(s, &m, &limits, NOW).await,
        GroupOutcome::NotAwaitingWelcome
    );
    // One added and one not: refused as a whole.
    let (w, m) = welcome(&a, &[b.clone(), stranger.clone()], "w1");
    assert_eq!(
        w.go(s, &m, &limits, NOW).await,
        GroupOutcome::NotAwaitingWelcome
    );
    assert!(
        s.pending(&b, 0, 10, u64::MAX, NOW)
            .await
            .unwrap()
            .is_empty()
    );
    // Added by A's commit: only A may welcome it. B is a member, not the adder.
    let (w, m) = welcome(&b, std::slice::from_ref(&b), "w2");
    assert_eq!(
        w.go(s, &m, &limits, NOW).await,
        GroupOutcome::NotAwaitingWelcome
    );
    let (w, m) = welcome(&a, std::slice::from_ref(&b), "w3");
    assert!(delivered(&w.go(s, &m, &limits, NOW).await));
    // The same Welcome again is an idempotent repeat; a new one is refused.
    assert_eq!(w.go(s, &m, &limits, NOW).await, GroupOutcome::Duplicate);
    let (w, m) = welcome(&a, std::slice::from_ref(&b), "w4");
    assert_eq!(
        w.go(s, &m, &limits, NOW).await,
        GroupOutcome::NotAwaitingWelcome
    );

    // Added, then removed before its Welcome: refused.
    let mut add = Send::new(Kind::Commit, GID, &a, 1);
    add.add = vec![c.clone()];
    assert!(delivered(
        &add.go(s, &msg(&a, "c1", 10), &limits, NOW).await
    ));
    let mut rm = Send::new(Kind::Commit, GID, &a, 2);
    rm.remove = vec![c.clone()];
    assert!(delivered(&rm.go(s, &msg(&a, "c2", 10), &limits, NOW).await));
    let (w, m) = welcome(&a, std::slice::from_ref(&c), "w5");
    assert_eq!(
        w.go(s, &m, &limits, NOW).await,
        GroupOutcome::NotAwaitingWelcome
    );

    // Added and never welcomed: the entry lapses with the message TTL.
    let mut add = Send::new(Kind::Commit, GID, &a, 3);
    add.add = vec![c.clone()];
    assert!(delivered(
        &add.go(s, &msg(&a, "c3", 10), &limits, NOW).await
    ));
    let ttl = u64::try_from(limits.message_ttl.as_millis()).unwrap();
    let later = NOW + ttl;
    let (w, m) = welcome(&a, std::slice::from_ref(&c), "w6");
    assert_eq!(
        w.go(s, &m, &limits, later).await,
        GroupOutcome::NotAwaitingWelcome
    );
    let stats = s.purge_expired(later).await.unwrap();
    assert_eq!(stats.welcomes_due, 1);
    assert_counters(&inspect(&d.path).await).await;
}

#[tokio::test]
async fn a_welcome_to_a_full_queue_is_refused_whole_and_can_be_sent_again() {
    let d = db().await;
    let s = &d.store;
    let limits = Limits {
        non_member_queue_max_bytes: 4000,
        ..Limits::default()
    };
    let (a, b, c) = (mb(1), mb(2), mb(3));
    let epoch = group(s, GID, &a, &[b.clone(), c.clone()]).await;
    // C has sent in the group; B hasn't, so the group's traffic to B takes
    // the group's share (half) of B's non-member part.
    let hello = Send::new(Kind::Application, GID, &c, epoch);
    assert!(delivered(
        &hello.go(s, &msg(&c, "hi", 10), &limits, NOW).await
    ));
    let app = Send::new(Kind::Application, GID, &a, epoch);
    assert!(delivered(
        &app.go(s, &msg(&a, "m", 1500), &limits, NOW).await
    ));
    let mut w = Send::new(Kind::WelcomeWrapped, GID, &a, 0);
    w.to = vec![b.clone(), c.clone()];
    let m = msg(&a, "w", 600);
    assert_eq!(w.go(s, &m, &limits, NOW).await, GroupOutcome::QueueFull);
    assert_eq!(
        s.pending(&c, 0, 10, u64::MAX, NOW).await.unwrap().len(),
        1,
        "all or nothing: C has only the message"
    );
    // B drains; the same Welcome (same msg_id) goes through.
    assert!(s.ack(&b, "m").await.unwrap());
    assert!(delivered(&w.go(s, &m, &limits, NOW).await));
    assert_eq!(s.pending(&c, 0, 10, u64::MAX, NOW).await.unwrap().len(), 2);
    assert_counters(&inspect(&d.path).await).await;
}

// --- SR-04, SR-17, review F3 and F4: the queue parts and group shares ------

#[tokio::test]
async fn non_member_traffic_never_displaces_group_traffic() {
    let d = db().await;
    let s = &d.store;
    let limits = Limits {
        queue_max_bytes: 20_000,
        non_member_queue_max_bytes: 5_000,
        ..Limits::default()
    };
    let (victim, friend, stranger) = (mb(1), mb(2), mb(3));
    // The victim's real group: it created it, so it counts as a member.
    let epoch = group(s, GID, &victim, std::slice::from_ref(&friend)).await;
    // The stranger's group, with the victim added by a routing hint, a
    // Welcome, and group traffic: all of it lands in the non-member part,
    // and at most half of it.
    let sepoch = group(s, OTHER, &stranger, std::slice::from_ref(&victim)).await;
    let mut w = Send::new(Kind::WelcomeWrapped, OTHER, &stranger, 0);
    w.to = vec![victim.clone()];
    assert!(delivered(
        &w.go(s, &msg(&stranger, "w", 500), &limits, NOW).await
    ));
    let junk = Send::new(Kind::Application, OTHER, &stranger, sepoch);
    let mut marked = false;
    for i in 0..20 {
        if let GroupOutcome::Delivered { overflowed, .. } = junk
            .go(s, &msg(&stranger, &format!("s{i}"), 800), &limits, NOW)
            .await
        {
            marked |= !overflowed.is_empty();
        }
    }
    assert!(marked, "the stranger's traffic overflows its share");
    // Join requests and knocks still have their own share of the part.
    let j = s
        .deliver_direct(
            Kind::JoinRequest,
            &victim,
            &msg(&mb(7), "j", 800),
            &limits,
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(j, DirectOutcome::Delivered);
    let k = s
        .deliver_direct(Kind::Knock, &victim, &msg(&mb(8), "k", 800), &limits, NOW)
        .await
        .unwrap();
    assert_eq!(k, DirectOutcome::Delivered);

    // The friend's group traffic still reaches the victim in full.
    let real = Send::new(Kind::Commit, GID, &friend, epoch);
    match real.go(s, &msg(&friend, "real", 1000), &limits, NOW).await {
        GroupOutcome::Delivered {
            recipients,
            overflowed,
            ..
        } => {
            assert!(recipients.contains(&victim));
            assert!(overflowed.is_empty());
        }
        o => panic!("{o:?}"),
    }
    // And when the victim's own group overflows, that episode gets its own
    // marker: the stranger's episode doesn't use it up.
    let app = Send::new(Kind::Application, GID, &friend, epoch + 1);
    let mut marked = false;
    for i in 0..30 {
        if let GroupOutcome::Delivered { overflowed, .. } = app
            .go(s, &msg(&friend, &format!("f{i}"), 1000), &limits, NOW)
            .await
        {
            marked |= overflowed.contains(&victim);
        }
    }
    assert!(marked);
    let markers = markers_of(s, &victim).await;
    assert_eq!(markers.len(), 2, "{markers:?}");
    assert!(markers.iter().any(|m| m.contains(GID)));
    assert!(markers.iter().any(|m| m.contains(OTHER)));
    let q = s.pending(&victim, 0, 1000, u64::MAX, NOW).await.unwrap();
    assert!(q.iter().any(|m| m.msg_id == "real"));
    assert_counters(&inspect(&d.path).await).await;
}

async fn markers_of(s: &SqliteStore, mailbox: &str) -> Vec<String> {
    s.pending(mailbox, 0, 10_000, u64::MAX, NOW)
        .await
        .unwrap()
        .into_iter()
        .filter(|m| m.marker)
        .map(|m| m.json)
        .collect()
}

/// Review F3: a member that hasn't sent in its group yet shares the
/// non-member part with a stranger's junk. Each group has at most half of
/// the part and its own overflow episode, so the real group's message is
/// delivered, and when the real group does overflow it gets a marker of its
/// own.
#[tokio::test]
async fn a_strangers_flood_leaves_room_and_a_marker_for_a_group_the_member_has_not_sent_in() {
    let d = db().await;
    let s = &d.store;
    let limits = Limits {
        non_member_queue_max_bytes: 5_000,
        ..Limits::default()
    };
    let (adder, victim, stranger) = (mb(1), mb(2), mb(3));
    let real_epoch = group(s, GID, &adder, std::slice::from_ref(&victim)).await;
    let (w, m) = welcome(&adder, std::slice::from_ref(&victim), "w");
    assert!(delivered(&w.go(s, &m, &limits, NOW).await));
    s.ack(&victim, "w").await.unwrap();
    let junk_epoch = group(s, OTHER, &stranger, std::slice::from_ref(&victim)).await;
    let junk = Send::new(Kind::Application, OTHER, &stranger, junk_epoch);
    for i in 0..6 {
        junk.go(s, &msg(&stranger, &format!("j{i}"), 1000), &limits, NOW)
            .await;
    }
    let real = Send::new(Kind::Application, GID, &adder, real_epoch);
    match real.go(s, &msg(&adder, "real", 1000), &limits, NOW).await {
        GroupOutcome::Delivered { recipients, .. } => assert_eq!(recipients, vec![victim.clone()]),
        o => panic!("{o:?}"),
    }
    let mut marked = false;
    for i in 0..4 {
        if let GroupOutcome::Delivered { overflowed, .. } = real
            .go(s, &msg(&adder, &format!("r{i}"), 1000), &limits, NOW)
            .await
        {
            marked |= overflowed == vec![victim.clone()];
        }
    }
    assert!(marked, "the real group's drop is marked");
    let markers = markers_of(s, &victim).await;
    assert_eq!(markers.len(), 2, "{markers:?}");
    assert!(markers.iter().any(|m| m.contains(GID)));
    assert!(markers.iter().any(|m| m.contains(OTHER)));
    assert_counters(&inspect(&d.path).await).await;
}

/// Review F4: a co-member who floods one group takes at most half of the
/// victim's group part, so the victim's other groups go on, and each group
/// that overflows gets its own marker.
#[tokio::test]
async fn a_co_member_cannot_take_the_group_part_from_the_victims_other_groups() {
    let d = db().await;
    let s = &d.store;
    let limits = Limits {
        queue_max_bytes: 10_000,
        ..Limits::default()
    };
    let (victim, friend, peer) = (mb(1), mb(2), mb(3));
    let real_epoch = group(s, GID, &victim, std::slice::from_ref(&friend)).await;
    let peer_epoch = group(s, OTHER, &peer, std::slice::from_ref(&victim)).await;
    // The victim sends once in the peer's group (its card).
    let card = Send::new(Kind::Application, OTHER, &victim, peer_epoch);
    assert!(delivered(
        &card.go(s, &msg(&victim, "card", 100), &limits, NOW).await
    ));
    let flood = Send::new(Kind::Application, OTHER, &peer, peer_epoch);
    for i in 0..12 {
        flood
            .go(s, &msg(&peer, &format!("f{i}"), 1000), &limits, NOW)
            .await;
    }
    // The friend also has to send once to count as a member.
    let hello = Send::new(Kind::Application, GID, &friend, real_epoch);
    assert!(delivered(
        &hello.go(s, &msg(&friend, "hi", 10), &limits, NOW).await
    ));
    let real = Send::new(Kind::Application, GID, &friend, real_epoch);
    match real.go(s, &msg(&friend, "real", 1000), &limits, NOW).await {
        GroupOutcome::Delivered { recipients, .. } => assert_eq!(recipients, vec![victim.clone()]),
        o => panic!("{o:?}"),
    }
    let markers = markers_of(s, &victim).await;
    assert_eq!(markers.len(), 1, "{markers:?}");
    assert!(markers[0].contains(OTHER));
    assert_counters(&inspect(&d.path).await).await;
}

#[tokio::test]
async fn an_added_member_counts_as_one_once_it_has_sent_in_the_group() {
    let d = db().await;
    let s = &d.store;
    let limits = Limits {
        queue_max_bytes: 50_000,
        non_member_queue_max_bytes: 3_000,
        ..Limits::default()
    };
    let (a, b) = (mb(1), mb(2));
    let epoch = group(s, GID, &a, std::slice::from_ref(&b)).await;
    let app = Send::new(Kind::Application, GID, &a, epoch);
    // Until B sends, A's traffic to B takes the group's share of B's
    // non-member part: half of 3,000 bytes.
    let mut overflowed_at = None;
    for i in 0..5 {
        if let GroupOutcome::Delivered { overflowed, .. } = app
            .go(s, &msg(&a, &format!("m{i}"), 1000), &limits, NOW)
            .await
            && !overflowed.is_empty()
        {
            overflowed_at.get_or_insert(i);
        }
    }
    assert_eq!(overflowed_at, Some(1));
    // B sends in the group: from now on it is a member.
    let hello = Send::new(Kind::Application, GID, &b, epoch);
    assert!(delivered(
        &hello.go(s, &msg(&b, "hello", 10), &limits, NOW).await
    ));
    for i in 5..15 {
        match app
            .go(s, &msg(&a, &format!("m{i}"), 1000), &limits, NOW)
            .await
        {
            GroupOutcome::Delivered {
                recipients,
                overflowed,
                ..
            } => assert!(recipients == vec![b.clone()] && overflowed.is_empty()),
            o => panic!("{o:?}"),
        }
    }
    assert_counters(&inspect(&d.path).await).await;
}

// --- SR-03 and review F5: the sender budget --------------------------------

#[tokio::test]
async fn a_sender_budget_counts_stored_payloads_once_until_delivered_or_expired() {
    let d = db().await;
    let s = &d.store;
    let limits = Limits {
        sender_max_bytes: 6_000,
        ..Limits::default()
    };
    let (a, b, c, e) = (mb(1), mb(2), mb(3), mb(4));
    let epoch = group(s, GID, &a, &[b.clone(), c.clone()]).await;
    let other_epoch = group(s, OTHER, &a, std::slice::from_ref(&e)).await;
    let app = Send::new(Kind::Application, GID, &a, epoch);
    // Two recipients, one charge each time; one group has half the budget.
    for i in 0..2 {
        let o = app
            .go(s, &msg(&a, &format!("m{i}"), 1000), &limits, NOW)
            .await;
        assert!(delivered(&o), "{i}: {o:?}");
    }
    let m2 = msg(&a, "m2", 1000);
    assert_eq!(app.go(s, &m2, &limits, NOW).await, GroupOutcome::OverBudget);
    // The other half is there for the other groups and for joins.
    let other = Send::new(Kind::Application, OTHER, &a, other_epoch);
    for i in 0..2 {
        let o = other
            .go(s, &msg(&a, &format!("o{i}"), 1000), &limits, NOW)
            .await;
        assert!(delivered(&o), "{i}: {o:?}");
    }
    let join = |id: &str| msg(&a, id, 1000);
    assert_eq!(
        s.deliver_direct(Kind::JoinRequest, &mb(5), &join("j1"), &limits, NOW)
            .await
            .unwrap(),
        DirectOutcome::Delivered
    );
    // Now the budget in all is used up.
    assert_eq!(
        s.deliver_direct(Kind::JoinRequest, &mb(5), &join("j2"), &limits, NOW)
            .await
            .unwrap(),
        DirectOutcome::OverBudget
    );
    // A knock isn't charged.
    assert_eq!(
        s.deliver_direct(Kind::Knock, &mb(5), &msg(&a, "k", 1000), &limits, NOW)
            .await
            .unwrap(),
        DirectOutcome::Delivered
    );
    // One recipient's ack frees nothing; both free the payload.
    s.ack(&b, "m0").await.unwrap();
    assert_eq!(app.go(s, &m2, &limits, NOW).await, GroupOutcome::OverBudget);
    s.ack(&c, "m0").await.unwrap();
    assert!(delivered(&app.go(s, &m2, &limits, NOW).await));
    // Expiry frees the rest.
    let ttl = u64::try_from(limits.message_ttl.as_millis()).unwrap();
    s.purge_expired(NOW + ttl).await.unwrap();
    let m3 = msg(&a, "m3", 2900);
    assert!(delivered(&app.go(s, &m3, &limits, NOW + ttl).await));
    assert_counters(&inspect(&d.path).await).await;
}

/// Review F5: two members that never ack, each keeping half of a sender's
/// messages, used to pin its whole budget, so it was refused in every
/// group for seven days, removal or not. Now they pin at most the group's
/// half, and removing them releases what they held.
#[tokio::test]
async fn members_that_never_ack_pin_one_groups_share_until_they_are_removed() {
    let d = db().await;
    let s = &d.store;
    let limits = Limits {
        sender_max_bytes: 100_000,
        ..Limits::default()
    };
    let (sender, m1, m2, friend, other) = (mb(1), mb(2), mb(3), mb(4), mb(5));
    let e1 = group(s, GID, &sender, &[m1.clone(), m2.clone(), friend.clone()]).await;
    let e2 = group(s, OTHER, &sender, std::slice::from_ref(&other)).await;
    let g1 = Send::new(Kind::Application, GID, &sender, e1);
    let mut refused_at = None;
    for i in 0..20 {
        let id = format!("m{i}");
        let o = g1.go(s, &msg(&sender, &id, 9_000), &limits, NOW).await;
        if !delivered(&o) {
            assert_eq!(o, GroupOutcome::OverBudget);
            refused_at = Some(i);
            break;
        }
        s.ack(&friend, &id).await.unwrap();
        s.ack(if i % 2 == 0 { &m1 } else { &m2 }, &id)
            .await
            .unwrap();
    }
    assert_eq!(refused_at, Some(5), "half of 100 kB is five 9 kB messages");
    // The sender still reaches its other group.
    let g2 = Send::new(Kind::Application, OTHER, &sender, e2);
    assert!(delivered(
        &g2.go(s, &msg(&sender, "x", 9_000), &limits, NOW).await
    ));
    // Removing both releases what they kept.
    let mut rm = Send::new(Kind::Commit, GID, &sender, e1);
    rm.remove = vec![m1.clone(), m2.clone()];
    assert!(delivered(
        &rm.go(s, &msg(&sender, "rm", 10), &limits, NOW).await
    ));
    for q in [&m1, &m2] {
        let left: Vec<String> = s
            .pending(q, 0, 100, u64::MAX, NOW)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.msg_id)
            .collect();
        assert_eq!(left, vec!["rm".to_owned()], "only the removing commit");
    }
    let g1 = Send::new(Kind::Application, GID, &sender, e1 + 1);
    assert!(delivered(
        &g1.go(s, &msg(&sender, "y", 9_000), &limits, NOW).await
    ));
    assert_counters(&inspect(&d.path).await).await;
}

// --- SR-03 and review F1: the high-water mark and its reserve ---------------

#[tokio::test]
async fn above_the_high_water_mark_only_commits_that_add_nobody_use_the_reserve() {
    let d = db().await;
    let s = &d.store;
    let (a, b, c) = (mb(1), mb(2), mb(3));
    let epoch = group(s, GID, &a, &[b.clone(), c.clone()]).await;
    let used = s.storage_bytes().await.unwrap();
    let full = Limits {
        storage_high_water: used,
        ..Limits::default()
    };
    let app = Send::new(Kind::Application, GID, &a, epoch);
    let refused = |o: GroupOutcome| assert_eq!(o, GroupOutcome::StorageFull);
    refused(app.go(s, &msg(&a, "m", 10), &full, NOW).await);
    let mut w = Send::new(Kind::WelcomeWrapped, GID, &a, 0);
    w.to = vec![b.clone()];
    refused(w.go(s, &msg(&a, "w", 10), &full, NOW).await);
    for kind in [Kind::JoinRequest, Kind::Knock] {
        assert_eq!(
            s.deliver_direct(kind, &a, &msg(&mb(7), "d", 10), &full, NOW)
                .await
                .unwrap(),
            DirectOutcome::StorageFull
        );
    }
    let mut add = Send::new(Kind::Commit, GID, &a, epoch);
    add.add = vec![mb(98)];
    refused(add.go(s, &msg(&a, "c0", 10), &full, NOW).await);
    // A commit that adds nobody, but with a ct bigger than an honest one
    // can be, is refused.
    let update = Send::new(Kind::Commit, GID, &a, epoch);
    let big = msg(
        &a,
        "c1",
        agentconnect_relay::proto::MAX_RESERVE_COMMIT_CT + 1,
    );
    refused(update.go(s, &big, &full, NOW).await);
    // An Update and a removal use the reserve.
    assert!(delivered(
        &update.go(s, &msg(&a, "c2", 3000), &full, NOW).await
    ));
    let mut rm = Send::new(Kind::Commit, GID, &a, epoch + 1);
    rm.remove = vec![c.clone()];
    assert!(delivered(&rm.go(s, &msg(&a, "c3", 3000), &full, NOW).await));
    // Without a reserve, nothing.
    let none = Limits {
        storage_reserve: 0,
        ..full.clone()
    };
    let update = Send::new(Kind::Commit, GID, &a, epoch + 2);
    refused(update.go(s, &msg(&a, "c4", 10), &none, NOW).await);
    // Acks always work, and a refused msg_id is not used up.
    assert!(s.ack(&c, "c3").await.unwrap());
    let app = Send::new(Kind::Application, GID, &a, epoch + 2);
    assert!(delivered(
        &app.go(s, &msg(&a, "m", 10), &Limits::default(), NOW).await
    ));
    assert_counters(&inspect(&d.path).await).await;
}

/// Review F1: remove-only commits used to skip the sender budget as well
/// as the mark, without bound. They are charged as any message, their ct
/// is capped, and past the mark they stop at the reserve.
#[tokio::test]
async fn remove_only_commits_are_charged_capped_and_stop_at_the_reserve() {
    let d = db().await;
    let s = &d.store;
    let attacker = mb(1);
    let k = 40_u32;
    let gid = |g: u32| format!("group-{g:0>16}");
    for g in 0..k {
        group(s, &gid(g), &attacker, &[mb(1000 + g)]).await;
    }
    let used = s.storage_bytes().await.unwrap();
    let rm = |g: u32| {
        let mut c = Send::new(Kind::Commit, "", &attacker, 1);
        c.remove = vec![mb(1000 + g)];
        c
    };
    // A 1 MB "remove" commit is over the cap: refused at the mark.
    let full = Limits {
        storage_high_water: used,
        sender_max_bytes: 1 << 20,
        ..Limits::default()
    };
    let mut big = rm(0);
    let id0 = gid(0);
    big.group = &id0;
    let o = big
        .go(s, &msg(&attacker, "big", 1_000_000), &full, NOW)
        .await;
    assert_eq!(o, GroupOutcome::StorageFull);
    // Small ones are charged to the sender's budget.
    let mut accepted = 0_u64;
    let mut last = GroupOutcome::Duplicate;
    let ids: Vec<String> = (0..k).map(gid).collect();
    for g in 0..k {
        let mut c = rm(g);
        c.group = &ids[usize::try_from(g).unwrap()];
        last = c
            .go(s, &msg(&attacker, &format!("rm{g}"), 100_000), &full, NOW)
            .await;
        if !delivered(&last) {
            break;
        }
        s.ack(&attacker, &format!("rm{g}")).await.unwrap();
        accepted += 1;
    }
    assert_eq!(last, GroupOutcome::OverBudget);
    assert_eq!(accepted, 10, "1 MiB of 100 kB commits");
    let grown = s.storage_bytes().await.unwrap() - used;
    assert!(grown < 2 << 20, "grew {grown}");
    // With a budget that doesn't stop them, the reserve does.
    let reserve = Limits {
        storage_high_water: s.storage_bytes().await.unwrap(),
        storage_reserve: 300_000,
        sender_max_bytes: u64::MAX,
        ..Limits::default()
    };
    let mut refused = false;
    for g in accepted..u64::from(k) {
        let g = u32::try_from(g).unwrap();
        let mut c = rm(g);
        c.group = &ids[usize::try_from(g).unwrap()];
        let o = c
            .go(
                s,
                &msg(&attacker, &format!("rm{g}"), 100_000),
                &reserve,
                NOW,
            )
            .await;
        if o == GroupOutcome::StorageFull {
            refused = true;
            break;
        }
        assert!(delivered(&o), "{o:?}");
    }
    assert!(refused, "the reserve ran out");
    assert_counters(&inspect(&d.path).await).await;
}

// --- SR-05: counters, not scans ----------------------------------------------

#[tokio::test]
async fn quota_checks_and_acks_use_counters_and_indexes() {
    let d = db().await;
    let pool = inspect(&d.path).await;
    let plan = |q: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(AssertSqlSafe(format!("EXPLAIN QUERY PLAN {q}")))
                .fetch_all(&pool)
                .await
                .unwrap()
                .iter()
                .map(|r| r.get::<String, _>(3))
                .collect::<Vec<_>>()
                .join("; ")
        }
    };
    let ack = plan("DELETE FROM messages WHERE mailbox = 'm' AND msg_id = 'x'").await;
    assert!(ack.contains("messages_ack"), "{ack}");
    let usage = plan("SELECT bytes FROM mailbox_usage WHERE mailbox = 'm' AND bucket = 0").await;
    assert!(usage.contains("PRIMARY KEY"), "{usage}");
    let release = plan("SELECT 1 FROM messages WHERE payload = 1").await;
    assert!(release.contains("messages_payload"), "{release}");
}

#[derive(Debug, Clone)]
enum Op {
    App { from: usize, bytes: usize },
    Join { to: usize, bytes: usize },
    Knock { to: usize, bytes: usize },
    Ack { who: usize, nth: usize },
    Advance { hours: u64 },
    Purge,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..3_usize, 1..3000_usize).prop_map(|(from, bytes)| Op::App { from, bytes }),
        (0..3_usize, 1..3000_usize).prop_map(|(to, bytes)| Op::Join { to, bytes }),
        (0..3_usize, 1..3000_usize).prop_map(|(to, bytes)| Op::Knock { to, bytes }),
        (0..3_usize, 0..8_usize).prop_map(|(who, nth)| Op::Ack { who, nth }),
        (1..100_u64).prop_map(|hours| Op::Advance { hours }),
        Just(Op::Purge),
    ]
}

fn config() -> Config {
    let mut cfg = Config {
        cases: 24,
        failure_persistence: None,
        ..Config::default()
    };
    if let Some(seed) = std::env::var("AC_TEST_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        cfg.rng_algorithm = RngAlgorithm::ChaCha;
        cfg.rng_seed = RngSeed::Fixed(seed);
    }
    cfg
}

async fn run_ops(ops: Vec<Op>) {
    let d = db().await;
    let s = &d.store;
    let limits = Limits {
        queue_max_bytes: 8_000,
        non_member_queue_max_bytes: 6_000,
        sender_max_bytes: 12_000,
        ..Limits::default()
    };
    let members: Vec<String> = (0..3).map(mb).collect();
    let epoch = group(s, GID, &members[0], &members[1..]).await;
    let pool = inspect(&d.path).await;
    let mut now = NOW;
    for (i, op) in ops.into_iter().enumerate() {
        let id = format!("op{i}");
        match op {
            Op::App { from, bytes } => {
                let app = Send::new(Kind::Application, GID, &members[from], epoch);
                app.go(s, &msg(&members[from], &id, bytes), &limits, now)
                    .await;
            }
            Op::Join { to, bytes } => {
                let m = msg(&mb(10 + u32::try_from(i % 3).unwrap()), &id, bytes);
                s.deliver_direct(Kind::JoinRequest, &members[to], &m, &limits, now)
                    .await
                    .unwrap();
            }
            Op::Knock { to, bytes } => {
                let m = msg(&mb(20), &id, bytes);
                s.deliver_direct(Kind::Knock, &members[to], &m, &limits, now)
                    .await
                    .unwrap();
            }
            Op::Ack { who, nth } => {
                let q = s
                    .pending(&members[who], 0, 100, u64::MAX, now)
                    .await
                    .unwrap();
                if let Some(m) = q.get(nth) {
                    s.ack(&members[who], &m.msg_id).await.unwrap();
                }
            }
            Op::Advance { hours } => now += hours * 3_600_000,
            Op::Purge => {
                s.purge_expired(now).await.unwrap();
            }
        }
        assert_counters(&pool).await;
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn counters_always_equal_what_they_count(ops in prop::collection::vec(op(), 1..40)) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_ops(ops));
    }
}

/// The review's random walk over every path that changes the queue:
/// commits that add and remove (and drop what removed members held),
/// Welcomes, overflow markers in both parts, joins, knocks, acks, expiry
/// and purges, with the counters checked after every step. Seeded from
/// `AC_TEST_SEED` when set, else at random (and printed).
#[tokio::test]
async fn counters_survive_a_random_walk_of_commits_welcomes_and_markers() {
    let d = db().await;
    let s = &d.store;
    let pool = inspect(&d.path).await;
    let limits = Limits {
        queue_max_bytes: 6_000,
        non_member_queue_max_bytes: 3_000,
        sender_max_bytes: 20_000,
        ..Limits::default()
    };
    let owner = mb(0);
    s.create_group(GID, &owner, NOW).await.unwrap();
    let mut seed: u64 = std::env::var("AC_TEST_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| u64::from_le_bytes(agentconnect_relay::auth::random_bytes::<8>()))
        | 1;
    eprintln!("walk seed {seed}");
    let mut rnd = move |m: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        usize::try_from(seed % u64::try_from(m).unwrap()).unwrap()
    };
    let mut epoch = 0;
    let mut members: Vec<String> = vec![owner.clone()];
    let mut now = NOW;
    let mut seen = [0_usize; 4]; // commits, welcomes, markers, applications
    for i in 0..600 {
        let id = format!("op{i}");
        let sender = members[rnd(members.len())].clone();
        let bytes = 1 + rnd(1500);
        match rnd(9) {
            0 => {
                let new = mb(u32::try_from(1 + rnd(8)).unwrap());
                let mut c = Send::new(Kind::Commit, GID, &sender, epoch);
                if !members.contains(&new) {
                    c.add = vec![new];
                }
                if members.len() > 2 && rnd(2) == 0 {
                    c.remove = vec![members[1 + rnd(members.len() - 1)].clone()];
                }
                if let GroupOutcome::Delivered {
                    epoch: e,
                    overflowed,
                    ..
                } = c.go(s, &msg(&sender, &id, bytes), &limits, now).await
                {
                    seen[0] += 1;
                    seen[2] += overflowed.len();
                    epoch = e;
                    members.retain(|m| !c.remove.contains(m));
                    members.extend(c.add.iter().cloned());
                    if !c.add.is_empty() && rnd(3) != 0 {
                        let (w, m) = welcome(&sender, &c.add, &format!("w{i}"));
                        if delivered(&w.go(s, &m, &limits, now).await) {
                            seen[1] += 1;
                        }
                    }
                }
            }
            1..=3 => {
                let app = Send::new(Kind::Application, GID, &sender, epoch);
                if let GroupOutcome::Delivered { overflowed, .. } =
                    app.go(s, &msg(&sender, &id, bytes), &limits, now).await
                {
                    seen[2] += overflowed.len();
                    seen[3] += 1;
                }
            }
            4 => {
                let m = msg(&mb(50), &id, bytes);
                s.deliver_direct(Kind::JoinRequest, &sender, &m, &limits, now)
                    .await
                    .unwrap();
            }
            5 => {
                let m = msg(&mb(51), &id, bytes);
                s.deliver_direct(Kind::Knock, &sender, &m, &limits, now)
                    .await
                    .unwrap();
            }
            6 | 7 => {
                let who = mb(u32::try_from(rnd(9)).unwrap());
                let q = s.pending(&who, 0, 100, u64::MAX, now).await.unwrap();
                if !q.is_empty() {
                    s.ack(&who, &q[rnd(q.len())].msg_id).await.unwrap();
                }
            }
            _ => {
                now += u64::try_from(rnd(48)).unwrap() * 3_600_000;
                s.purge_expired(now).await.unwrap();
            }
        }
        assert_counters(&pool).await;
    }
    eprintln!("commits, welcomes, markers, applications: {seen:?}");
    assert!(seen.iter().all(|n| *n > 0), "{seen:?}");
}

// --- SR-18: deleted ciphertext leaves the files -----------------------------

fn files_contain(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().any(|e| {
        let bytes = std::fs::read(e.unwrap().path()).unwrap();
        bytes.windows(needle.len()).any(|w| w == needle)
    })
}

#[tokio::test]
async fn acked_and_expired_ciphertext_is_not_left_in_the_database_files() {
    let d = db().await;
    let s = &d.store;
    let dir = d.path.parent().unwrap();
    let (a, b) = (mb(1), mb(2));
    let epoch = group(s, GID, &a, std::slice::from_ref(&b)).await;
    let acked = format!(
        "REMNANT-ACKED-{}",
        agentconnect_relay::proto::b64_encode(&agentconnect_relay::auth::random_bytes::<12>())
    );
    let expired = format!(
        "REMNANT-EXPIRED-{}",
        agentconnect_relay::proto::b64_encode(&agentconnect_relay::auth::random_bytes::<12>())
    );
    let app = Send::new(Kind::Application, GID, &a, epoch);
    for (id, text) in [("acked", &acked), ("expired", &expired)] {
        let m = NewMessage {
            msg_id: id.into(),
            sender: a.clone(),
            json: format!(r#"{{"ct":"{}"}}"#, text.repeat(20)),
        };
        assert!(delivered(&app.go(s, &m, &Limits::default(), NOW).await));
    }
    assert!(files_contain(dir, acked.as_bytes()));
    assert!(s.ack(&b, "acked").await.unwrap());
    let ttl = u64::try_from(Limits::default().message_ttl.as_millis()).unwrap();
    let stats: PurgeStats = s.purge_expired(NOW + ttl).await.unwrap();
    assert_eq!(stats.messages, 1);
    assert!(
        !files_contain(dir, acked.as_bytes()),
        "acked ciphertext left on disk"
    );
    assert!(
        !files_contain(dir, expired.as_bytes()),
        "expired ciphertext left on disk"
    );
}

// --- Migration from the previous schema -------------------------------------

#[tokio::test]
async fn a_database_from_the_previous_schema_migrates_with_its_queues() {
    let dir = tempfile::tempdir().unwrap();
    let old_migrations = dir.path().join("migrations");
    std::fs::create_dir(&old_migrations).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for name in [
        "0001_init.sql",
        "0002_overflow.sql",
        "0003_doors.sql",
        "0004_idle_groups_and_invite_quota.sql",
    ] {
        std::fs::copy(src.join(name), old_migrations.join(name)).unwrap();
    }
    let path = dir.path().join("old.db");
    let (a, b, c) = (mb(1), mb(2), mb(3));
    {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&path)
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        sqlx::migrate::Migrator::new(old_migrations.as_path())
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
        let exp = i64::try_from(NOW + 3_600_000).unwrap();
        sqlx::raw_sql(AssertSqlSafe(format!(
                "INSERT INTO groups VALUES ('{GID}', 3, 0, 0, NULL); \
                 INSERT INTO group_members VALUES ('{GID}', '{a}'), ('{GID}', '{b}'); \
                 INSERT INTO messages (mailbox, msg_id, env, size, expires_at, marker) VALUES \
                 ('{b}', 'app', '{{\"kind\":\"application\",\"sender\":\"{a}\"}}', 41, {exp}, 0), \
                 ('{b}', 'welcome', '{{\"kind\":\"welcome_wrapped\",\"sender\":\"{a}\"}}', 45, {exp}, 0), \
                 ('{b}', 'app', '{{\"t\":\"queue_overflow\"}}', 22, {exp}, 1), \
                 ('{c}', 'gone', '{{\"kind\":\"application\",\"sender\":\"{a}\"}}', 41, {exp}, 0); \
                 DELETE FROM messages WHERE msg_id = 'gone'; \
                 INSERT INTO overflow VALUES ('{b}'); \
                 INSERT INTO seen VALUES ('{a}', 'app', {exp});"
            )))
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    let s = SqliteStore::open(path.to_str().unwrap()).await.unwrap();
    let q = s.pending(&b, 0, 10, u64::MAX, NOW).await.unwrap();
    let ids: Vec<(i64, &str, bool)> = q
        .iter()
        .map(|m| (m.seq, m.msg_id.as_str(), m.marker))
        .collect();
    assert_eq!(
        ids,
        vec![(1, "app", false), (2, "welcome", false), (3, "app", true)]
    );
    assert!(q[1].json.contains("welcome_wrapped"));
    let pool = inspect(&path).await;
    assert_counters(&pool).await;
    let buckets: Vec<(String, i64, i64)> = pool
        .fetch_all("SELECT mailbox, bucket, bytes FROM mailbox_usage ORDER BY bucket")
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    assert_eq!(buckets, vec![(b.clone(), 0, 63), (b.clone(), 1, 45)]);
    // Old members count as members; the idempotency record survived.
    let app = Send::new(Kind::Application, GID, &a, 3);
    assert_eq!(
        app.go(&s, &msg(&a, "app", 10), &Limits::default(), NOW)
            .await,
        GroupOutcome::Duplicate
    );
    let tiny = Limits {
        non_member_queue_max_bytes: 0,
        ..Limits::default()
    };
    match app.go(&s, &msg(&a, "new", 10), &tiny, NOW).await {
        GroupOutcome::Delivered { recipients, .. } => assert_eq!(recipients, vec![b.clone()]),
        o => panic!("{o:?}"),
    }
    // New rows get higher seq numbers than any the old table handed out.
    let q = s.pending(&b, 3, 10, u64::MAX, NOW).await.unwrap();
    assert_eq!(q.len(), 1);
    assert!(q[0].seq > 4, "seq {} reused", q[0].seq);
    // Acks release the migrated rows and their payloads.
    assert!(s.ack(&b, "app").await.unwrap());
    assert!(s.ack(&b, "welcome").await.unwrap());
    assert!(s.ack(&b, "new").await.unwrap());
    assert!(
        s.pending(&b, 0, 10, u64::MAX, NOW)
            .await
            .unwrap()
            .is_empty()
    );
    assert_counters(&pool).await;
}
