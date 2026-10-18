//! Store conformance: every backend must pass these. The memory store runs
//! them in the fast tier (`tests/store_memory.rs`), Postgres in the
//! integration tier (`tests/store_postgres.rs`).

use agentconnect_directory::Store;
use agentconnect_directory::store::{
    GoneKind, ListingRecord, OwnerCheck, OwnerStatus, PublishOutcome, RevokeOutcome, SearchDoc,
    SearchQuery, TOMBSTONE_TTL_SECS, WithdrawOutcome, WithdrawalRecord,
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

pub async fn publish_rules<S: Store>(s: &S) {
    let id = identity_id();
    let r1 = record("alpha", &id, 3);
    assert_eq!(
        s.publish(&r1).await.unwrap(),
        PublishOutcome::Published { key_changed: false }
    );
    assert_eq!(s.publish(&r1).await.unwrap(), PublishOutcome::Unchanged);
    let stale = record("alpha", &id, 3);
    assert_eq!(
        s.publish(&stale).await.unwrap(),
        PublishOutcome::StaleSeq { current: 3 }
    );
    let lower = record("alpha", &id, 2);
    assert_eq!(
        s.publish(&lower).await.unwrap(),
        PublishOutcome::StaleSeq { current: 3 }
    );
    let r2 = record("alpha", &id, 4);
    assert_eq!(
        s.publish(&r2).await.unwrap(),
        PublishOutcome::Published { key_changed: false }
    );
    let got = s.get("alpha").await.unwrap().unwrap();
    assert_eq!(got, r2);
    assert!(s.get("nobody").await.unwrap().is_none());
}

pub async fn key_change_is_recorded<S: Store>(s: &S) {
    let (a, b) = (identity_id(), identity_id());
    s.publish(&record("rotating", &a, 1)).await.unwrap();
    let mut new = record("rotating", &b, 2);
    new.published_at = NOW + 10;
    assert_eq!(
        s.publish(&new).await.unwrap(),
        PublishOutcome::Published { key_changed: true }
    );
    assert_eq!(
        s.get("rotating").await.unwrap().unwrap().key_changed_at,
        Some(NOW + 10)
    );
    // A later version by the same key keeps the date.
    let mut again = record("rotating", &b, 3);
    again.published_at = NOW + 20;
    s.publish(&again).await.unwrap();
    assert_eq!(
        s.get("rotating").await.unwrap().unwrap().key_changed_at,
        Some(NOW + 10)
    );
}

pub async fn withdraw_rules<S: Store>(s: &S) {
    let (id, other) = (identity_id(), identity_id());
    s.publish(&record("beta", &id, 5)).await.unwrap();
    fn mk(identity: &str, seq: u64) -> WithdrawalRecord<'_> {
        WithdrawalRecord {
            name: "beta",
            identity,
            seq,
            entry: "{\"w\":1}",
        }
    }
    assert_eq!(
        s.withdraw(&mk(&other, 5), NOW).await.unwrap(),
        WithdrawOutcome::WrongIdentity
    );
    assert_eq!(
        s.withdraw(&mk(&id, 4), NOW).await.unwrap(),
        WithdrawOutcome::StaleSeq
    );
    assert_eq!(
        s.withdraw(&mk(&id, 5), NOW).await.unwrap(),
        WithdrawOutcome::Withdrawn
    );
    assert_eq!(
        s.withdraw(&mk(&id, 5), NOW).await.unwrap(),
        WithdrawOutcome::Repeat
    );
    assert_eq!(
        s.withdraw(&mk(&id, 6), NOW).await.unwrap(),
        WithdrawOutcome::NotListed
    );
    assert!(s.get("beta").await.unwrap().is_none());
    let t = s.tombstone("beta").await.unwrap().unwrap();
    assert_eq!(
        (t.seq, t.kind, t.identity.as_str()),
        (5, GoneKind::Withdrawal, id.as_str())
    );
    // The tombstone keeps lower seqs out; a higher one is accepted.
    assert_eq!(
        s.publish(&record("beta", &id, 5)).await.unwrap(),
        PublishOutcome::StaleSeq { current: 5 }
    );
    assert!(matches!(
        s.publish(&record("beta", &id, 6)).await.unwrap(),
        PublishOutcome::Published { .. }
    ));
    assert_eq!(
        s.withdraw(
            &WithdrawalRecord {
                name: "nothing",
                identity: &id,
                seq: 1,
                entry: "{}"
            },
            NOW
        )
        .await
        .unwrap(),
        WithdrawOutcome::NotListed
    );
    let feed = s.feed(0, 10).await.unwrap();
    assert_eq!(feed.len(), 1);
    assert_eq!(feed[0].entry, "{\"w\":1}");
}

pub async fn token_revocation<S: Store>(s: &S) {
    let id = identity_id();
    let r = record("gamma", &id, 1);
    s.publish(&r).await.unwrap();
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
        s.tombstone("gamma").await.unwrap().unwrap().kind,
        GoneKind::TokenRevocation
    );
    // A revoked token can't publish again, even at a higher seq.
    let mut again = record("gamma", &id, 9);
    again.token_id.clone_from(&r.token_id);
    assert_eq!(
        s.publish(&again).await.unwrap(),
        PublishOutcome::TokenRevoked
    );
    // Revoking an unused token is recorded with nothing withdrawn.
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
    s.publish(&r).await.unwrap();
    let st = OwnerStatus {
        last: OwnerCheck::Vouched,
        checked_at: Some(NOW),
        verified_at: Some(NOW),
    };
    assert!(s.set_owner("delta", &r.sha256, st).await.unwrap());
    assert!(!s.set_owner("delta", "other-version", st).await.unwrap());
    assert_eq!(s.get("delta").await.unwrap().unwrap().owner, st);
    assert!(s.due_owner_checks(NOW, 10).await.unwrap().is_empty());
    assert_eq!(s.due_owner_checks(NOW + 1, 10).await.unwrap().len(), 1);
    let mut plain = record("no-domain", &id, 1);
    plain.owner_domain = None;
    s.publish(&plain).await.unwrap();
    assert_eq!(s.due_owner_checks(NOW + 1, 10).await.unwrap().len(), 1);
    assert_eq!(s.by_identity(&id).await.unwrap().len(), 2);
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
        s.publish(r).await.unwrap();
    }
    let q = |text: Option<&str>, skill: Option<&str>| SearchQuery {
        text: text.map(str::to_owned),
        skill: skill.map(str::to_owned),
        now: NOW,
    };
    let names = |v: Vec<ListingRecord>| v.into_iter().map(|r| r.name).collect::<Vec<_>>();
    // A title match outranks a description-only match.
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
    // No text: everything unexpired, by name.
    assert_eq!(
        names(s.search(&q(None, None)).await.unwrap()),
        ["code-reviewer", "pg-helper", "release-planner"]
    );
}

pub async fn feed_and_purge<S: Store>(s: &S) {
    let id = identity_id();
    for (i, name) in ["e1", "e2", "e3"].iter().enumerate() {
        s.publish(&record(name, &id, 1)).await.unwrap();
        let at = NOW + i as u64;
        s.withdraw(
            &WithdrawalRecord {
                name,
                identity: &id,
                seq: 1,
                entry: "{}",
            },
            at,
        )
        .await
        .unwrap();
    }
    let all = s.feed(0, 10).await.unwrap();
    assert_eq!(all.len(), 3);
    assert!(all.windows(2).all(|w| w[0].cursor < w[1].cursor));
    let rest = s.feed(all[0].cursor, 10).await.unwrap();
    assert_eq!(rest.len(), 2);
    assert_eq!(s.feed(0, 1).await.unwrap().len(), 1);
    let stats = s.purge(NOW + TOMBSTONE_TTL_SECS + 1).await.unwrap();
    assert_eq!((stats.tombstones, stats.feed), (2, 2));
    assert!(s.tombstone("e1").await.unwrap().is_none());
    assert!(s.tombstone("e3").await.unwrap().is_some());
}

/// Run the whole suite against fresh stores from `make`.
pub async fn run<S: Store, F: std::future::Future<Output = S>>(make: impl Fn() -> F) {
    publish_rules(&make().await).await;
    key_change_is_recorded(&make().await).await;
    withdraw_rules(&make().await).await;
    token_revocation(&make().await).await;
    owner_updates(&make().await).await;
    search_ranking_and_filters(&make().await).await;
    feed_and_purge(&make().await).await;
}
