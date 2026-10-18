//! Store conformance: every backend must pass these. The memory store runs
//! them in the fast tier (`tests/store_memory.rs`), Postgres in the
//! integration tier (`tests/store_postgres.rs`).
//!
//! The replacement rules themselves are the core's (`replaces`,
//! `tombstoned_by`); the store's part is the guarded, atomic write, the
//! per-(name, identity) tombstones and the per-name token mark.

use agentconnect_directory::Store;
use agentconnect_directory::store::{
    EXPIRED_GRACE_SECS, FEED_TTL_SECS, GoneKind, ListingRecord, NameState, OwnerCheck, OwnerStatus,
    PublishGuard, PublishOutcome, RevokeOutcome, SearchDoc, SearchQuery, WithdrawOutcome,
    WithdrawalRecord,
};

use super::{DAY, identity_id, random_b64};

pub const NOW: u64 = 1_735_689_600;

pub fn record(name: &str, identity: &str, seq: u64) -> ListingRecord {
    let bytes = format!(
        "{{\"name\":\"{name}\",\"seq\":{seq},\"r\":\"{}\"}}",
        random_b64(8)
    )
    .into_bytes();
    ListingRecord {
        name: name.to_owned(),
        identity: identity.to_owned(),
        seq,
        token_id: random_b64(16),
        owner_domain: None,
        owner: OwnerStatus::PENDING,
        door_expires_at: Some(NOW + DAY),
        token_expires_at: NOW + 90 * DAY,
        published_at: NOW,
        key_changed_at: None,
        sha256: agentconnect_core::encoding::hex(&<sha2::Sha256 as sha2::Digest>::digest(&bytes)),
        bytes,
        search: SearchDoc {
            title: name.replace('-', " "),
            skills: String::new(),
            description: String::new(),
            skill_keys: vec![],
        },
    }
}

fn with_text(
    mut r: ListingRecord,
    title: &str,
    skills: &str,
    description: &str,
    keys: &[&str],
) -> ListingRecord {
    r.search = SearchDoc {
        title: title.to_owned(),
        skills: skills.to_owned(),
        description: description.to_owned(),
        skill_keys: keys.iter().map(|k| (*k).to_owned()).collect(),
    };
    r
}

/// The guard for what is stored now, keeping the name's high-water mark.
pub async fn guard<S: Store>(s: &S, r: &ListingRecord) -> PublishGuard {
    let name = s.name_state(&r.name).await.unwrap();
    PublishGuard {
        prev_sha256: s.get(&r.name).await.unwrap().map(|p| p.sha256),
        high_water: name.high_water.clone(),
        name,
    }
}

/// Publish against the current state.
pub async fn put<S: Store>(s: &S, r: &ListingRecord) -> PublishOutcome {
    let g = guard(s, r).await;
    s.publish(r, &g).await.unwrap()
}

fn wd(name: &str, identity: &str, seq: u64) -> WithdrawalRecord<'static> {
    WithdrawalRecord {
        name: Box::leak(name.to_owned().into_boxed_str()),
        identity: Box::leak(identity.to_owned().into_boxed_str()),
        seq,
        tombstone_seq: seq,
        entry: "{\"w\":1}",
    }
}

pub async fn guarded_publish<S: Store>(s: &S) {
    let id = identity_id();
    let r1 = record("alpha", &id, 3);
    assert_eq!(
        s.publish(&r1, &PublishGuard::default()).await.unwrap(),
        PublishOutcome::Published { key_changed: false }
    );
    // The same bytes are idempotent whatever the guard says.
    assert_eq!(
        s.publish(&r1, &PublishGuard::default()).await.unwrap(),
        PublishOutcome::Unchanged
    );
    let r2 = record("alpha", &id, 4);
    // A guard that missed r1 is a conflict.
    assert_eq!(
        s.publish(&r2, &PublishGuard::default()).await.unwrap(),
        PublishOutcome::Conflict
    );
    assert_eq!(
        put(s, &r2).await,
        PublishOutcome::Published { key_changed: false }
    );
    assert_eq!(s.get("alpha").await.unwrap().unwrap(), r2);
    assert!(s.get("nobody").await.unwrap().is_none());
    // A guard that missed a tombstone is a conflict, too.
    s.withdraw(&wd("alpha", &id, 4), NOW).await.unwrap();
    let r3 = record("alpha", &id, 5);
    assert_eq!(
        s.publish(&r3, &PublishGuard::default()).await.unwrap(),
        PublishOutcome::Conflict
    );
    assert!(matches!(
        put(s, &r3).await,
        PublishOutcome::Published { .. }
    ));
}

pub async fn name_state_is_kept_and_guarded<S: Store>(s: &S) {
    let (a, b) = (identity_id(), identity_id());
    let first = record("marked", &a, 1);
    let mut g = guard(s, &first).await;
    g.high_water = Some((NOW, a.clone()));
    assert!(matches!(
        s.publish(&first, &g).await.unwrap(),
        PublishOutcome::Published { .. }
    ));
    s.withdraw(&wd("marked", &a, 1), NOW).await.unwrap();
    // The mark outlives the listing; the tombstones are per identity.
    let state = s.name_state("marked").await.unwrap();
    assert_eq!(state.high_water, Some((NOW, a.clone())));
    assert_eq!(state.tombstones, vec![(a.clone(), 1)]);
    // A decision taken on an older state of the name is a conflict.
    let other = record("marked", &b, 1);
    let stale = PublishGuard {
        prev_sha256: None,
        name: NameState::default(),
        high_water: Some((NOW + 1, b.clone())),
    };
    assert_eq!(
        s.publish(&other, &stale).await.unwrap(),
        PublishOutcome::Conflict
    );
    let mut fresh = guard(s, &other).await;
    fresh.high_water = Some((NOW + 1, b.clone()));
    assert!(matches!(
        s.publish(&other, &fresh).await.unwrap(),
        PublishOutcome::Published { key_changed: true }
    ));
    assert_eq!(
        s.name_state("marked").await.unwrap().high_water,
        Some((NOW + 1, b))
    );
    assert_eq!(s.name_state("nothing").await.unwrap(), NameState::default());
}

pub async fn key_change_is_recorded<S: Store>(s: &S) {
    let (a, b) = (identity_id(), identity_id());
    put(s, &record("rotating", &a, 1)).await;
    let mut new = record("rotating", &b, 1);
    new.published_at = NOW + 10;
    assert_eq!(
        put(s, &new).await,
        PublishOutcome::Published { key_changed: true }
    );
    assert_eq!(
        s.get("rotating").await.unwrap().unwrap().key_changed_at,
        Some(NOW + 10)
    );
    let mut again = record("rotating", &b, 2);
    again.published_at = NOW + 20;
    put(s, &again).await;
    assert_eq!(
        s.get("rotating").await.unwrap().unwrap().key_changed_at,
        Some(NOW + 10)
    );
}

pub async fn withdraw_rules<S: Store>(s: &S) {
    let (id, other) = (identity_id(), identity_id());
    put(s, &record("beta", &id, 5)).await;
    assert_eq!(
        s.withdraw(&wd("beta", &other, 5), NOW).await.unwrap(),
        WithdrawOutcome::WrongIdentity
    );
    assert_eq!(
        s.withdraw(&wd("beta", &id, 4), NOW).await.unwrap(),
        WithdrawOutcome::StaleSeq
    );
    assert_eq!(
        s.withdraw(&wd("beta", &id, 5), NOW).await.unwrap(),
        WithdrawOutcome::Withdrawn
    );
    assert_eq!(
        s.withdraw(&wd("beta", &id, 5), NOW).await.unwrap(),
        WithdrawOutcome::Repeat
    );
    assert_eq!(
        s.withdraw(&wd("beta", &id, 6), NOW).await.unwrap(),
        WithdrawOutcome::NotListed
    );
    assert_eq!(
        s.withdraw(&wd("beta", &other, 1), NOW).await.unwrap(),
        WithdrawOutcome::NotListed
    );
    assert!(s.get("beta").await.unwrap().is_none());
    let t = s.tombstone_for("beta", &id).await.unwrap().unwrap();
    assert_eq!((t.seq, t.kind), (5, GoneKind::Withdrawal));
    assert!(s.tombstone_for("beta", &other).await.unwrap().is_none());
    assert_eq!(s.tombstone("beta").await.unwrap().unwrap().identity, id);
    // A second identity's tombstone is its own; the latest names the page.
    put(s, &record("beta", &other, 1)).await;
    s.withdraw(&wd("beta", &other, 1), NOW + 5).await.unwrap();
    assert_eq!(s.tombstone_for("beta", &id).await.unwrap().unwrap().seq, 5);
    assert_eq!(s.tombstone("beta").await.unwrap().unwrap().identity, other);
    let feed = s.feed(0, 10).await.unwrap();
    assert_eq!(feed.len(), 2);
    assert_eq!(feed[0].entry, "{\"w\":1}");
}

pub async fn token_revocation<S: Store>(s: &S) {
    let id = identity_id();
    let r = record("gamma", &id, 1);
    put(s, &r).await;
    assert_eq!(
        s.revoke_token(&r.token_id, "{\"r\":1}", NOW).await.unwrap(),
        RevokeOutcome::Revoked {
            withdrawn: Some(("gamma".to_owned(), id.clone()))
        }
    );
    assert_eq!(
        s.revoke_token(&r.token_id, "{\"r\":1}", NOW).await.unwrap(),
        RevokeOutcome::Repeat
    );
    assert!(s.get("gamma").await.unwrap().is_none());
    assert_eq!(
        s.tombstone_for("gamma", &id).await.unwrap().unwrap().kind,
        GoneKind::TokenRevocation
    );
    let mut again = record("gamma", &id, 9);
    again.token_id.clone_from(&r.token_id);
    assert_eq!(put(s, &again).await, PublishOutcome::TokenRevoked);
    assert!(s.token_revoked(&r.token_id).await.unwrap());
    assert!(!s.token_revoked(&random_b64(16)).await.unwrap());
    let unused = random_b64(16);
    assert_eq!(
        s.revoke_token(&unused, "{}", NOW).await.unwrap(),
        RevokeOutcome::Revoked { withdrawn: None }
    );
    assert_eq!(s.feed(0, 10).await.unwrap().len(), 2);
}

pub async fn owner_updates<S: Store>(s: &S) {
    let id = identity_id();
    let mut r = record("delta", &id, 1);
    r.owner_domain = Some("example.com".to_owned());
    put(s, &r).await;
    // Checks are folded into the stored history in the order they land.
    for (at, check) in [
        (NOW - 10, OwnerCheck::Vouched),
        (NOW - 5, OwnerCheck::NotVouched),
        (NOW, OwnerCheck::Failed),
    ] {
        assert!(
            s.record_owner_check("delta", &r.sha256, at, check)
                .await
                .unwrap()
        );
    }
    assert!(
        !s.record_owner_check("delta", "other-version", NOW, OwnerCheck::Vouched)
            .await
            .unwrap()
    );
    let st = OwnerStatus {
        latest: Some((NOW, OwnerCheck::Failed)),
        verified_at: Some(NOW - 10),
        negative: Some((NOW - 5, OwnerCheck::NotVouched)),
    };
    assert_eq!(s.get("delta").await.unwrap().unwrap().owner, st);
    assert!(s.due_owner_checks(NOW, NOW, 10).await.unwrap().is_empty());
    assert_eq!(s.due_owner_checks(NOW + 1, NOW, 10).await.unwrap().len(), 1);
    // Expired listings are neither due nor listed for their identity.
    let token_end = s.get("delta").await.unwrap().unwrap().token_expires_at;
    assert!(
        s.due_owner_checks(NOW + 1, token_end, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let plain = record("no-domain", &id, 1);
    put(s, &plain).await;
    assert_eq!(s.due_owner_checks(NOW + 1, NOW, 10).await.unwrap().len(), 1);
    assert_eq!(s.by_identity(&id, NOW).await.unwrap().len(), 2);
    assert_eq!(s.by_identity(&id, token_end).await.unwrap().len(), 0);
    assert!(
        !s.owner_revoked("delta", "other-version", "{}", NOW)
            .await
            .unwrap()
    );
    assert!(
        s.owner_revoked("delta", &r.sha256, "{\"o\":1}", NOW)
            .await
            .unwrap()
    );
    assert_eq!(
        s.tombstone("delta").await.unwrap().unwrap().kind,
        GoneKind::OwnerRevocation
    );
    // The revocation is recorded against (name, identity).
    assert_eq!(
        s.name_state("delta").await.unwrap().owner_revoked,
        vec![(id.clone(), NOW)]
    );
    assert_eq!(
        s.feed(0, 10).await.unwrap()[0].kind,
        GoneKind::OwnerRevocation
    );
}

pub async fn search_ranking_and_filters<S: Store>(s: &S) {
    let id = identity_id();
    let a = with_text(
        record("release-planner", &id, 1),
        "release planner Release planner",
        "Release planning release scheduling",
        "Plans release trains.",
        &["rp", "release planning", "scheduling"],
    );
    let b = with_text(
        record("code-reviewer", &id, 1),
        "code reviewer Code reviewer",
        "Code review review",
        "Reviews pull requests before a release.",
        &["code review"],
    );
    let c = with_text(
        record("pg-helper", &id, 1),
        "pg helper Postgres helper",
        "Postgres postgres",
        "Tunes postgres queries.",
        &["postgres"],
    );
    let mut expired = with_text(
        record("old-release", &id, 1),
        "old release",
        "release",
        "release",
        &["release planning"],
    );
    expired.token_expires_at = NOW;
    for r in [&a, &b, &c, &expired] {
        put(s, r).await;
    }
    let q = |text: Option<&str>, skill: Option<&str>| SearchQuery {
        text: text.map(str::to_owned),
        skill: skill.map(str::to_owned),
        now: NOW,
    };
    let names = |v: Vec<ListingRecord>| v.into_iter().map(|r| r.name).collect::<Vec<_>>();
    assert_eq!(
        names(s.search(&q(Some("release"), None)).await.unwrap()),
        ["release-planner", "code-reviewer"]
    );
    assert_eq!(
        names(s.search(&q(Some("postgres"), None)).await.unwrap()),
        ["pg-helper"]
    );
    assert_eq!(
        names(s.search(&q(Some("release -planner"), None)).await.unwrap()),
        ["code-reviewer"]
    );
    assert!(
        s.search(&q(Some("nonexistentword"), None))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        names(s.search(&q(None, Some("code review"))).await.unwrap()),
        ["code-reviewer"]
    );
    assert_eq!(
        names(
            s.search(&q(Some("release"), Some("release planning")))
                .await
                .unwrap()
        ),
        ["release-planner"]
    );
    assert_eq!(
        names(s.search(&q(None, None)).await.unwrap()),
        ["code-reviewer", "pg-helper", "release-planner"]
    );
}

pub async fn feed_and_purge<S: Store>(s: &S) {
    let id = identity_id();
    for (i, name) in ["e1", "e2", "e3"].iter().enumerate() {
        put(s, &record(name, &id, 1)).await;
        let at = NOW + i as u64;
        s.withdraw(&wd(name, &id, 1), at).await.unwrap();
    }
    let all = s.feed(0, 10).await.unwrap();
    assert_eq!(all.len(), 3);
    assert!(all.windows(2).all(|w| w[0].cursor < w[1].cursor));
    let rest = s.feed(all[0].cursor, 10).await.unwrap();
    assert_eq!(rest.len(), 2);
    assert_eq!(s.feed(0, 1).await.unwrap().len(), 1);
    // An expired listing, purged after the grace period.
    let mut gone = record("expired", &id, 1);
    gone.token_expires_at = NOW + DAY;
    put(s, &gone).await;
    let later = NOW + FEED_TTL_SECS.max(EXPIRED_GRACE_SECS) + DAY + 1;
    let stats = s.purge(later).await.unwrap();
    assert_eq!((stats.feed, stats.expired_listings), (3, 1));
    assert!(s.get("expired").await.unwrap().is_none());
    // Tombstones are never purged (SPEC 13.2.2).
    for name in ["e1", "e2", "e3"] {
        assert!(s.tombstone(name).await.unwrap().is_some(), "{name}");
        assert_eq!(
            s.name_state(name).await.unwrap().tombstones,
            vec![(id.clone(), 1)]
        );
    }
}

pub async fn listed_after_pages_by_name<S: Store>(s: &S) {
    let id = identity_id();
    for name in ["c-three", "a-one", "b-two"] {
        put(s, &record(name, &id, 1)).await;
    }
    let names = |v: Vec<ListingRecord>| v.into_iter().map(|r| r.name).collect::<Vec<_>>();
    assert_eq!(
        names(s.listed_after("", NOW, 2).await.unwrap()),
        ["a-one", "b-two"]
    );
    assert_eq!(
        names(s.listed_after("b-two", NOW, 2).await.unwrap()),
        ["c-three"]
    );
    assert!(
        s.listed_after("", NOW + 91 * DAY, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Run the whole suite against fresh stores from `make`.
pub async fn run<S: Store, F: std::future::Future<Output = S>>(make: impl Fn() -> F) {
    guarded_publish(&make().await).await;
    name_state_is_kept_and_guarded(&make().await).await;
    key_change_is_recorded(&make().await).await;
    withdraw_rules(&make().await).await;
    token_revocation(&make().await).await;
    owner_updates(&make().await).await;
    search_ranking_and_filters(&make().await).await;
    feed_and_purge(&make().await).await;
    listed_after_pages_by_name(&make().await).await;
}
