//! SQLite persistence, migrations and purging.

use agentconnect_relay::SqliteStore;
use agentconnect_relay::proto::Kind;
use agentconnect_relay::store::{
    CreateGroupOutcome, DirectOutcome, GroupOutcome, GroupSend, InviteRecord, Limits, NewMessage,
    RevokeOutcome, Store,
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
        assert!(
            s.create_invite(&invite(NOW / 1000 + 3600), NOW)
                .await
                .unwrap()
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
    let pending = s.pending(A, 0, 10, NOW).await.unwrap();
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
    s.create_invite(&long_gone, NOW).await.unwrap();
    s.create_invite(&recent, NOW).await.unwrap();

    // The old message has expired; the invite grace period ends 7 days
    // before `t`, i.e. just after NOW.
    let t = NOW + ttl + 1000;
    let stats = s.purge_expired(t).await.unwrap();
    assert_eq!(stats.messages, 1);
    assert_eq!(stats.seen, 1);
    assert_eq!(stats.invites, 1);
    assert!(s.get_invite("inv-1").await.unwrap().is_none());
    assert!(s.get_invite("inv-2").await.unwrap().is_some());
    assert_eq!(s.pending(B, 0, 10, t).await.unwrap().len(), 1);
    assert_eq!(s.purge_expired(t).await.unwrap(), Default::default());
}

#[tokio::test]
async fn revoke_and_duplicate_creates() {
    let s = SqliteStore::in_memory().await.unwrap();
    assert!(
        s.create_invite(&invite(NOW / 1000 + 60), NOW)
            .await
            .unwrap()
    );
    assert!(
        !s.create_invite(&invite(NOW / 1000 + 60), NOW)
            .await
            .unwrap()
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
    assert!(s.pending(A, 0, 10, NOW).await.unwrap().is_empty());
    assert_eq!(s.pending(B, 0, 10, NOW).await.unwrap().len(), 1);
}
