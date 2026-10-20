//! SQLite persistence, migrations and purging.

use agentconnect_relay::SqliteStore;
use agentconnect_relay::proto::Kind;
use agentconnect_relay::store::{
    CreateGroupOutcome, CreateInviteOutcome, DirectOutcome, GroupOutcome, GroupSend, InviteRecord,
    Limits, NewMessage, RevokeOutcome, Store,
};

const NOW: u64 = 1_735_689_600_000;
const GID: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const A: &str = "mailbox-a-0000000000";
const B: &str = "mailbox-b-0000000000";

fn invite(expires_at: u64) -> InviteRecord {
    InviteRecord {
        invite_id: "inv-1".into(),
        group_name: "g".into(),
        inviter_name: "i".into(),
        purpose: "p".into(),
        expires_at,
        max_uses: 3,
        uses_left: 3,
        member_count: Some(2),
        inviter_mailbox: A.into(),
        revoked: false,
    }
}

fn message(id: &str) -> NewMessage {
    NewMessage {
        msg_id: id.into(),
        sender: A.into(),
        json: format!(r#"{{"msg_id":"{id}"}}"#),
    }
}

#[tokio::test]
async fn state_survives_a_restart_and_migrations_are_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let spec = path.to_str().unwrap();
    let limits = Limits::default();
    {
        let s = SqliteStore::open(spec).await.unwrap();
        assert_eq!(
            s.create_invite(&invite(NOW / 1000 + 3600), 10, NOW)
                .await
                .unwrap(),
            CreateInviteOutcome::Created
        );
        assert_eq!(
            s.create_group(GID, A, NOW).await.unwrap(),
            CreateGroupOutcome::Created
        );
        let send = GroupSend {
            kind: Kind::Commit,
            group_id: GID,
            sender: A,
            epoch: 0,
            add: &[B.to_owned()],
            remove: &[],
            to: &[],
            msg: &message("m1"),
        };
        assert!(matches!(
            s.deliver_group(&send, &limits, NOW).await.unwrap(),
            GroupOutcome::Delivered { epoch: 1, .. }
        ));
    }
    let s = SqliteStore::open(spec).await.unwrap();
    assert_eq!(
        s.get_invite("inv-1").await.unwrap().unwrap(),
        invite(NOW / 1000 + 3600)
    );
    let g = s.get_group(GID).await.unwrap().unwrap();
    assert_eq!(g.current_epoch, 1);
    assert_eq!(g.members, vec![A.to_owned(), B.to_owned()]);
    let pending = s.pending(A, 0, 10, u64::MAX, NOW).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].msg_id, "m1");
    // Idempotency survives too.
    assert_eq!(
        s.deliver_direct(B, &message("m1"), &limits, NOW)
            .await
            .unwrap(),
        DirectOutcome::Duplicate
    );
}

#[tokio::test]
async fn sqlite_urls_are_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.path().join("u.db").display());
    let s = SqliteStore::open(&url).await.unwrap();
    assert!(s.get_group(GID).await.unwrap().is_none());
    assert!(
        SqliteStore::open("sqlite:///nonexistent-dir/x/y.db")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn purge_removes_only_expired_rows() {
    let s = SqliteStore::in_memory().await.unwrap();
    let limits = Limits::default();
    let ttl = limits.message_ttl.as_millis() as u64;
    s.deliver_direct(B, &message("old"), &limits, NOW)
        .await
        .unwrap();
    s.deliver_direct(B, &message("new"), &limits, NOW + ttl / 2)
        .await
        .unwrap();
    // Expired a week ago (plus the grace period) vs still readable.
    let long_gone = invite(NOW / 1000 - 10);
    let mut recent = invite(NOW / 1000 + 100);
    recent.invite_id = "inv-2".into();
    s.create_invite(&long_gone, 10, NOW).await.unwrap();
    s.create_invite(&recent, 10, NOW).await.unwrap();

    // The old message has expired; the invite grace period ends 7 days
    // before `t`, i.e. just after NOW.
    let t = NOW + ttl + 1000;
    let stats = s.purge_expired(t).await.unwrap();
    assert_eq!(stats.messages, 1);
    assert_eq!(stats.seen, 1);
    assert_eq!(stats.invites, 1);
    assert!(s.get_invite("inv-1").await.unwrap().is_none());
    assert!(s.get_invite("inv-2").await.unwrap().is_some());
    assert_eq!(s.pending(B, 0, 10, u64::MAX, t).await.unwrap().len(), 1);
    assert_eq!(s.purge_expired(t).await.unwrap(), Default::default());
}

#[tokio::test]
async fn revoke_and_duplicate_creates() {
    let s = SqliteStore::in_memory().await.unwrap();
    assert_eq!(
        s.create_invite(&invite(NOW / 1000 + 60), 10, NOW)
            .await
            .unwrap(),
        CreateInviteOutcome::Created
    );
    assert_eq!(
        s.create_invite(&invite(NOW / 1000 + 60), 10, NOW)
            .await
            .unwrap(),
        CreateInviteOutcome::Exists
    );
    assert_eq!(
        s.revoke_invite("inv-1", B).await.unwrap(),
        RevokeOutcome::NotInviter
    );
    assert_eq!(
        s.revoke_invite("nope", A).await.unwrap(),
        RevokeOutcome::NotFound
    );
    assert_eq!(
        s.revoke_invite("inv-1", A).await.unwrap(),
        RevokeOutcome::Revoked
    );
    assert!(s.get_invite("inv-1").await.unwrap().unwrap().revoked);
    assert_eq!(
        s.create_group(GID, A, NOW).await.unwrap(),
        CreateGroupOutcome::Created
    );
    assert_eq!(
        s.create_group(GID, B, NOW).await.unwrap(),
        CreateGroupOutcome::Exists
    );
}

#[tokio::test]
async fn ack_removes_only_the_acknowledged_mailbox_copy() {
    let s = SqliteStore::in_memory().await.unwrap();
    let limits = Limits::default();
    s.create_group(GID, A, NOW).await.unwrap();
    let to = [A.to_owned(), B.to_owned()];
    let m = message("w1");
    let send = GroupSend {
        kind: Kind::WelcomeWrapped,
        group_id: GID,
        sender: A,
        epoch: 0,
        add: &[],
        remove: &[],
        to: &to,
        msg: &m,
    };
    s.deliver_group(&send, &limits, NOW).await.unwrap();
    assert!(s.ack(A, "w1").await.unwrap());
    assert!(!s.ack(A, "w1").await.unwrap());
    assert!(s.pending(A, 0, 10, u64::MAX, NOW).await.unwrap().is_empty());
    assert_eq!(s.pending(B, 0, 10, u64::MAX, NOW).await.unwrap().len(), 1);
}

/// A message of exactly `size` stored bytes.
fn sized(id: &str, size: usize) -> NewMessage {
    let head = format!(r#"{{"msg_id":"{id}","pad":""#);
    let pad = "x".repeat(size - head.len() - 2);
    NewMessage {
        msg_id: id.into(),
        sender: A.into(),
        json: format!(r#"{head}{pad}"}}"#),
    }
}

#[tokio::test]
async fn pending_stops_at_the_byte_cap_but_returns_at_least_one_message() {
    let s = SqliteStore::in_memory().await.unwrap();
    let limits = Limits::default();
    for (i, size) in [400, 300, 300, 2000, 100].iter().enumerate() {
        let m = sized(&format!("m{i}"), *size);
        assert_eq!(m.json.len(), *size);
        assert_eq!(
            s.deliver_direct(B, &m, &limits, NOW).await.unwrap(),
            DirectOutcome::Delivered
        );
    }
    let ids = |b: &[agentconnect_relay::store::StoredMessage]| {
        b.iter().map(|m| m.msg_id.clone()).collect::<Vec<_>>()
    };
    // 400 + 300 + 300 fit in 1000; the 2000-byte message does not.
    let first = s.pending(B, 0, 10, 1000, NOW).await.unwrap();
    assert_eq!(ids(&first), ["m0", "m1", "m2"]);
    // 999 bytes: the third message would pass the cap.
    assert_eq!(
        ids(&s.pending(B, 0, 10, 999, NOW).await.unwrap()),
        ["m0", "m1"]
    );
    // A message larger than the cap still goes out, alone.
    let after = first.last().unwrap().seq;
    let big = s.pending(B, after, 10, 1000, NOW).await.unwrap();
    assert_eq!(ids(&big), ["m3"]);
    let rest = s.pending(B, big[0].seq, 10, 1000, NOW).await.unwrap();
    assert_eq!(ids(&rest), ["m4"]);
    // The count limit still applies under a large byte cap.
    assert_eq!(
        ids(&s.pending(B, 0, 2, u64::MAX, NOW).await.unwrap()),
        ["m0", "m1"]
    );
    assert!(
        s.pending(B, rest[0].seq, 10, 1000, NOW)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn only_open_invites_count_toward_the_per_mailbox_quota() {
    let s = SqliteStore::in_memory().await.unwrap();
    let numbered = |n: u32, expires_at: u64| InviteRecord {
        invite_id: format!("inv-{n}"),
        ..invite(expires_at)
    };
    let later = NOW / 1000 + 60;
    for n in 0..3 {
        assert_eq!(
            s.create_invite(&numbered(n, later), 3, NOW).await.unwrap(),
            CreateInviteOutcome::Created
        );
    }
    assert_eq!(
        s.create_invite(&numbered(3, later), 3, NOW).await.unwrap(),
        CreateInviteOutcome::TooMany
    );
    // Another mailbox has its own quota.
    let other = InviteRecord {
        inviter_mailbox: B.into(),
        ..numbered(4, later)
    };
    assert_eq!(
        s.create_invite(&other, 3, NOW).await.unwrap(),
        CreateInviteOutcome::Created
    );
    // Revoked, used up and expired invites are not open.
    s.revoke_invite("inv-0", A).await.unwrap();
    assert_eq!(
        s.create_invite(&numbered(5, later), 3, NOW).await.unwrap(),
        CreateInviteOutcome::Created
    );
    for _ in 0..3 {
        s.consume_invite("inv-1", A, NOW).await.unwrap();
    }
    assert_eq!(
        s.create_invite(&numbered(6, later), 3, NOW).await.unwrap(),
        CreateInviteOutcome::Created
    );
    let after_expiry = (later + 1) * 1000;
    assert_eq!(
        s.create_invite(&numbered(7, later + 600), 3, after_expiry)
            .await
            .unwrap(),
        CreateInviteOutcome::Created
    );
    // The quota is checked before the id: a full mailbox hears TooMany.
    assert_eq!(
        s.create_invite(&numbered(9, later), 0, NOW).await.unwrap(),
        CreateInviteOutcome::TooMany
    );
}

#[tokio::test]
async fn idle_groups_are_listed_by_last_use_and_deleted_only_while_idle() {
    const DAY: u64 = 24 * 3600 * 1000;
    let s = SqliteStore::in_memory().await.unwrap();
    let limits = Limits::default();
    let gid = |n: u8| format!("{GID:.21}{n}");
    for n in 0..4 {
        s.create_group(&gid(n), A, NOW).await.unwrap();
    }
    // Group 1 has a member besides its creator; group 2 is used later.
    let commit = message("c1");
    let send = GroupSend {
        kind: Kind::Commit,
        group_id: &gid(1),
        sender: A,
        epoch: 0,
        add: &[B.to_owned()],
        remove: &[],
        to: &[],
        msg: &commit,
    };
    s.deliver_group(&send, &limits, NOW).await.unwrap();
    used(&s, &gid(2), "a2", NOW + 10 * DAY).await;

    // Nothing is idle at its creation time.
    assert!(s.idle_groups(NOW - 1, "", 10).await.unwrap().is_empty());
    let cutoff = NOW + 5 * DAY;
    let idle = s.idle_groups(cutoff, "", 10).await.unwrap();
    let ids: Vec<_> = idle.iter().map(|g| g.group_id.clone()).collect();
    assert_eq!(ids, [gid(0), gid(1), gid(3)]);
    assert_eq!(idle[1].members, [A.to_owned(), B.to_owned()]);
    // Keyset paging.
    let page = s.idle_groups(cutoff, &gid(0), 1).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].group_id, gid(1));

    assert!(!s.delete_idle_group(&gid(2), cutoff).await.unwrap());
    used(&s, &gid(3), "a3", NOW + 6 * DAY).await;
    assert!(
        !s.delete_idle_group(&gid(3), cutoff).await.unwrap(),
        "used since"
    );

    assert!(s.delete_idle_group(&gid(1), cutoff).await.unwrap());
    assert!(s.get_group(&gid(1)).await.unwrap().is_none());
    assert!(!s.delete_idle_group(&gid(1), cutoff).await.unwrap());
    // Its memberships went with it, so the id starts afresh.
    assert_eq!(
        s.create_group(&gid(1), B, cutoff).await.unwrap(),
        CreateGroupOutcome::Created
    );
    assert_eq!(s.get_group(&gid(1)).await.unwrap().unwrap().members, [B]);
    let app = message("a1");
    let send = GroupSend {
        kind: Kind::Application,
        group_id: &gid(0),
        sender: A,
        epoch: 0,
        add: &[],
        remove: &[],
        to: &[],
        msg: &app,
    };
    assert!(s.delete_idle_group(&gid(0), cutoff).await.unwrap());
    assert_eq!(
        s.deliver_group(&send, &limits, cutoff).await.unwrap(),
        GroupOutcome::UnknownGroup
    );

    // A send within the hour of the last recorded one is not written: the
    // time is that coarse, which the relay's sweep allows for.
    used(&s, &gid(2), "a4", NOW + 10 * DAY + 1000).await;
    assert!(
        s.delete_idle_group(&gid(2), NOW + 10 * DAY + 500)
            .await
            .unwrap()
    );
}

/// An application message from `A`, accepted.
async fn used(s: &SqliteStore, group_id: &str, msg_id: &str, at: u64) {
    let m = message(msg_id);
    let send = GroupSend {
        kind: Kind::Application,
        group_id,
        sender: A,
        epoch: 0,
        add: &[],
        remove: &[],
        to: &[],
        msg: &m,
    };
    let out = s
        .deliver_group(&send, &Limits::default(), at)
        .await
        .unwrap();
    assert!(matches!(out, GroupOutcome::Delivered { .. }), "{out:?}");
}

#[tokio::test]
async fn a_send_between_the_sweeps_listing_and_its_delete_keeps_the_group() {
    // Review probe P8: the activity time is written in the send's own
    // transaction, so the delete's guard sees it.
    let s = SqliteStore::in_memory().await.unwrap();
    s.create_group(GID, A, NOW).await.unwrap();
    let cutoff = NOW + 1;
    assert_eq!(s.idle_groups(cutoff, "", 10).await.unwrap().len(), 1);
    used(&s, GID, "late", cutoff + 10).await;
    assert!(!s.delete_idle_group(GID, cutoff).await.unwrap());
    assert!(s.get_group(GID).await.unwrap().is_some());
}

#[tokio::test]
async fn the_upgrade_counts_every_existing_group_as_used_now() {
    // Review probe P3: before migration 0004 no activity was recorded. A
    // group created long ago and used the day before the upgrade must not
    // look idle after it.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
    let mut old = sqlx::migrate!("./migrations");
    old.migrations = old
        .migrations
        .iter()
        .filter(|m| m.version < 4)
        .cloned()
        .collect::<Vec<_>>()
        .into();
    old.run(&pool).await.unwrap();
    let long_ago = 1_000_000_000_000_i64; // 2001: far longer ago than any idle period
    sqlx::query("INSERT INTO groups (group_id, epoch, created_at) VALUES (?, 3, ?)")
        .bind(GID)
        .bind(long_ago)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let s = SqliteStore::open(path.to_str().unwrap()).await.unwrap();
    // Idle at the upgrade only by a cutoff after it: the group counts as
    // used when the migration ran.
    let at_upgrade = before - 1000;
    assert!(s.idle_groups(at_upgrade, "", 10).await.unwrap().is_empty());
    assert!(!s.delete_idle_group(GID, at_upgrade).await.unwrap());
    assert_eq!(s.get_group(GID).await.unwrap().unwrap().current_epoch, 3);
    // A group from before the creator was recorded has none.
    assert_eq!(s.group_creator(GID).await.unwrap(), None);
    assert_eq!(
        s.create_group(GID, A, before).await.unwrap(),
        CreateGroupOutcome::Exists
    );
}

#[tokio::test]
async fn a_group_records_its_creator_and_a_repeat_by_it_is_its_own() {
    // Verification finding V4: a lost `accepted` for group.create.
    let s = SqliteStore::in_memory().await.unwrap();
    assert_eq!(s.group_creator(GID).await.unwrap(), None);
    assert_eq!(
        s.create_group(GID, A, NOW).await.unwrap(),
        CreateGroupOutcome::Created
    );
    assert_eq!(s.group_creator(GID).await.unwrap().as_deref(), Some(A));
    assert_eq!(
        s.create_group(GID, A, NOW + 1).await.unwrap(),
        CreateGroupOutcome::Yours
    );
    assert_eq!(
        s.create_group(GID, B, NOW + 1).await.unwrap(),
        CreateGroupOutcome::Exists
    );
    assert_eq!(s.get_group(GID).await.unwrap().unwrap().members, [A]);
}
