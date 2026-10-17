//! Crash consistency (ADR-004): every processing path is one store
//! transaction that also writes the result to the journal. A failure at any
//! step boundary (an injected error or panic at a failpoint, which is what a
//! crash before the commit amounts to) leaves the state untouched, so the
//! retry succeeds; a retry after success returns the journalled result
//! instead of failing on a consumed key; and the results survive a restart.

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;

use agentconnect_core::clock::{Clock as _, FakeClock};
use agentconnect_core::failpoint::{Action, POINTS};
use agentconnect_core::group::Event;
use agentconnect_core::{
    Client, DbKey, Error, Group, Identity, Instance, InviteLink, Rng, SqliteStore, Store,
};
use common::{assert_converged, clock, group_of, inner, invite, meta_for, peer};

const ACTIONS: [Action; 2] = [Action::Error, Action::Panic];

fn points(prefix: &str) -> Vec<&'static str> {
    POINTS
        .iter()
        .copied()
        .filter(|p| p.starts_with(prefix))
        .collect()
}

/// Runs `f` with `point` armed, expecting it to fail (error or panic).
/// After a panic the in-memory group may be ahead of the store, so it is
/// reloaded, as a restarted daemon would.
fn fails_at<S: Store, T: std::fmt::Debug>(
    client: &Client<S>,
    group: &mut Group,
    point: &str,
    action: Action,
    f: impl FnOnce(&mut Group) -> agentconnect_core::Result<T>,
) {
    client.failpoints().arm(point, action, 1).unwrap();
    match catch_unwind(AssertUnwindSafe(|| f(group))) {
        Ok(r) => assert_eq!(
            r.unwrap_err(),
            Error::Storage(format!("failpoint {point}")),
            "{point}"
        ),
        Err(_) => {
            assert_eq!(action, Action::Panic, "{point}");
            *group = client.load_group(group.group_id()).unwrap().unwrap();
        }
    }
    client.failpoints().clear();
}

#[test]
fn an_application_message_survives_a_failure_at_every_step() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let (head, tail) = groups.split_at_mut(1);
    let (ga, gb) = (&mut head[0], &mut tail[0]);
    let b = &peers[1].client;
    for point in points("process.") {
        if point == "process.after_merge" {
            continue; // commits only
        }
        for action in ACTIONS {
            let msg = inner(&peers[0], point);
            let ct = ga.seal(&peers[0].client, &msg).unwrap();
            let key = format!("a/{point}/{action:?}");
            fails_at(b, gb, point, action, |g| {
                g.process_journaled(b, &key, b"ctx", &ct)
            });
            assert!(b.journal_pending().unwrap().is_empty(), "{point}");
            // Nothing was consumed: the same bytes process now.
            let got = gb.process_journaled(b, &key, b"ctx", &ct).unwrap();
            assert!(!got.replayed);
            let Event::Application(m) = got.value else {
                panic!("not an application message");
            };
            assert_eq!(m.plaintext, msg);
            // A retry gets the journalled result back, not a key error.
            let again = gb.process_journaled(b, &key, b"ctx", &ct).unwrap();
            assert!(again.replayed);
            assert_eq!(again.value, Event::Application(m));
            assert!(b.journal_consume(Some(gb.group_id()), &key).unwrap());
        }
    }
}

#[test]
fn a_commit_survives_a_failure_at_every_step_and_the_sas_converges() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    for point in points("process.") {
        for action in ACTIONS {
            let out = groups[0].update(&peers[0].client).unwrap();
            groups[0]
                .confirm_pending_commit(&peers[0].client, &out.msg_id)
                .unwrap();
            let epoch = groups[1].epoch();
            let b = &peers[1].client;
            let key = format!("c/{point}/{action:?}");
            fails_at(b, &mut groups[1], point, action, |g| {
                g.process_journaled(b, &key, b"", &out.commit)
            });
            assert_eq!(groups[1].epoch(), epoch, "{point}: nothing merged");
            let got = groups[1]
                .process_journaled(b, &key, b"", &out.commit)
                .unwrap();
            assert!(matches!(got.value, Event::Commit(_)) && !got.replayed);
            let again = groups[1]
                .process_journaled(b, &key, b"", &out.commit)
                .unwrap();
            assert!(again.replayed && again.value == got.value);
            groups[2].process(&peers[2].client, &out.commit).unwrap();
            assert_converged(&groups);
        }
    }
}

#[test]
fn a_leave_proposal_survives_a_failure() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let proposal = groups[2].propose_leave(&peers[2].client).unwrap();
    let a = &peers[0].client;
    for action in ACTIONS {
        fails_at(a, &mut groups[0], "process.after_mls", action, |g| {
            g.process_journaled(a, "p", b"", &proposal)
        });
    }
    let got = groups[0].process_journaled(a, "p", b"", &proposal).unwrap();
    assert!(matches!(got.value, Event::LeaveProposed(_)));
    let out = groups[0].commit_pending_proposals(a).unwrap();
    groups[0].confirm_pending_commit(a, &out.msg_id).unwrap();
    assert_eq!(groups[0].members().unwrap().len(), 2);
}

#[test]
fn an_own_commit_confirmation_survives_a_failure_and_its_echo_is_the_same_entry() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let a = &peers[0].client;
    for (n, point) in points("confirm.").into_iter().enumerate() {
        for action in ACTIONS {
            let out = groups[0].update(a).unwrap();
            let epoch = groups[0].epoch();
            let key = format!("me/{}", out.msg_id);
            fails_at(a, &mut groups[0], point, action, |g| {
                g.confirm_pending_commit_journaled(a, &out.msg_id, &key, b"")
            });
            assert_eq!(groups[0].epoch(), epoch);
            assert!(groups[0].has_pending_commit(), "{point}: still pending");
            let (first, second) = if n % 2 == 0 {
                // `accepted` first, then the fan-out copy.
                let c = groups[0]
                    .confirm_pending_commit_journaled(a, &out.msg_id, &key, b"")
                    .unwrap();
                let e = groups[0]
                    .process_journaled(a, &key, b"", &out.commit)
                    .unwrap();
                assert!(!c.replayed && e.replayed);
                (Event::OwnCommitConfirmed(c.value), e.value)
            } else {
                // The fan-out copy first, then `accepted`.
                let e = groups[0]
                    .process_journaled(a, &key, b"", &out.commit)
                    .unwrap();
                let c = groups[0]
                    .confirm_pending_commit_journaled(a, &out.msg_id, &key, b"")
                    .unwrap();
                assert!(!e.replayed && c.replayed);
                (e.value, Event::OwnCommitConfirmed(c.value))
            };
            assert_eq!(first, second);
            assert_eq!(groups[0].epoch(), epoch + 1);
            groups[1].process(&peers[1].client, &out.commit).unwrap();
            assert_converged(&groups);
            assert!(a.journal_consume(Some(groups[0].group_id()), &key).unwrap());
            assert_eq!(
                groups[0]
                    .confirm_pending_commit_journaled(a, &out.msg_id, &key, b"")
                    .unwrap_err(),
                Error::Duplicate
            );
        }
    }
}

fn sqlite_client(
    path: &Path,
    key: &DbKey,
    inst: Instance,
    clock: &Arc<FakeClock>,
) -> Client<SqliteStore> {
    Client::new(
        SqliteStore::open(path, key).unwrap(),
        Rng::os().unwrap(),
        inst,
        clock.clone(),
    )
    .unwrap()
}

struct Joiner {
    dir: tempfile::TempDir,
    key: DbKey,
    instance: Vec<u8>,
}

impl Joiner {
    fn new(clock: &Arc<FakeClock>) -> Self {
        let rng = Rng::for_test("journal-joiner");
        let inst = Identity::generate(&rng)
            .unwrap()
            .create_instance(&rng, clock.as_ref())
            .unwrap();
        Self {
            dir: tempfile::tempdir().unwrap(),
            key: DbKey::generate(&Rng::for_test("journal-db-key")).unwrap(),
            instance: inst.to_secret_bytes().unwrap().to_vec(),
        }
    }

    /// Opens the client again on the same file: a restart.
    fn open(&self, clock: &Arc<FakeClock>) -> Client<SqliteStore> {
        sqlite_client(
            &self.dir.path().join("mls.db"),
            &self.key,
            Instance::from_secret_bytes(&self.instance).unwrap(),
            clock,
        )
    }
}

#[test]
fn a_welcome_survives_a_failure_at_every_step_and_a_restart() {
    let clock = clock();
    let a = peer(1, &clock);
    let mut ga = a
        .client
        .create_group(common::NAME, common::PURPOSE)
        .unwrap();
    let joiner = Joiner::new(&clock);
    let b = joiner.open(&clock);
    let inv = invite(&a);
    let link = InviteLink::parse(&inv.url()).unwrap();
    let req = b.create_join_request(link.secret(), "b").unwrap();
    let v = a.client.verify_join_request(&req, &inv).unwrap();
    let out = ga.add_member(&a.client, &v, &inv, true).unwrap();
    ga.confirm_pending_commit(&a.client, &out.msg_id).unwrap();
    let welcome = out.welcome.unwrap();
    let meta = meta_for(&inv);
    for point in points("join.") {
        for action in ACTIONS {
            b.failpoints().arm(point, action, 1).unwrap();
            let r = catch_unwind(AssertUnwindSafe(|| {
                b.join_journaled(link.secret(), &meta, &welcome, "w", b"ctx")
            }));
            // A panic inside OpenMLS's part is caught there (an internal
            // error); either way nothing was stored.
            if let Ok(r) = r {
                assert!(r.is_err(), "{point}");
            }
            b.failpoints().clear();
            assert!(b.journal_pending().unwrap().is_empty());
        }
    }
    let joined = b
        .join_journaled(link.secret(), &meta, &welcome, "w", b"ctx")
        .unwrap();
    assert!(!joined.replayed);
    let gid = joined.value.group_id().to_vec();
    drop(joined);
    // A crash before the caller recorded the join: after the restart the
    // entry is pending, and the redelivered Welcome gives the group back
    // instead of failing on the spent KeyPackage.
    drop(b);
    let b = joiner.open(&clock);
    let pending = b.journal_pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].welcome && pending[0].event.is_none());
    assert_eq!(
        (
            pending[0].group_id.as_slice(),
            pending[0].context.as_slice()
        ),
        (gid.as_slice(), &b"ctx"[..])
    );
    let again = b
        .join_journaled(link.secret(), &meta, &welcome, "w", b"ctx")
        .unwrap();
    assert!(again.replayed);
    assert_eq!(again.value.sas(), ga.sas());
    assert_eq!(
        b.join_journaled(link.secret(), &meta, b"other bytes", "w", b"")
            .unwrap_err(),
        Error::JournalConflict
    );
    // A failure while consuming leaves the entry pending.
    b.failpoints()
        .arm("consume.before_commit", Action::Error, 1)
        .unwrap();
    assert!(b.journal_consume(None, "w").is_err());
    assert_eq!(b.journal_pending().unwrap().len(), 1);
    assert!(b.journal_consume(None, "w").unwrap());
    assert!(b.journal_consume(None, "w").unwrap(), "idempotent");
    assert!(!b.journal_consume(None, "unknown").unwrap());
    assert!(b.journal_pending().unwrap().is_empty());
    assert_eq!(
        b.join_journaled(link.secret(), &meta, &welcome, "w", b"")
            .unwrap_err(),
        Error::Duplicate
    );
}

#[test]
fn journalled_messages_survive_a_restart_and_are_purged_after_consumption() {
    let clock = clock();
    let a = peer(1, &clock);
    let mut ga = a
        .client
        .create_group(common::NAME, common::PURPOSE)
        .unwrap();
    let joiner = Joiner::new(&clock);
    let b = joiner.open(&clock);
    let inv = invite(&a);
    let link = InviteLink::parse(&inv.url()).unwrap();
    let req = b.create_join_request(link.secret(), "b").unwrap();
    let v = a.client.verify_join_request(&req, &inv).unwrap();
    let out = ga.add_member(&a.client, &v, &inv, true).unwrap();
    ga.confirm_pending_commit(&a.client, &out.msg_id).unwrap();
    let gid = b
        .join_from_wrapped_welcome(
            link.secret(),
            &meta_for(&inv),
            out.welcome.as_ref().unwrap(),
        )
        .unwrap()
        .group_id()
        .to_vec();
    let msg = inner(&a, "kept");
    let ct = ga.seal(&a.client, &msg).unwrap();
    let mut gb = b.load_group(&gid).unwrap().unwrap();
    gb.process_journaled(&b, "a/1", b"env", &ct).unwrap();
    drop((gb, b));

    let b = joiner.open(&clock);
    let pending = b.journal_pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (pending[0].key.as_str(), pending[0].context.as_slice()),
        ("a/1", &b"env"[..])
    );
    let Some(Event::Application(m)) = &pending[0].event else {
        panic!("expected the application message");
    };
    assert_eq!(m.plaintext, msg);
    let mut gb = b.load_group(&gid).unwrap().unwrap();
    // Other bytes under the same key are refused, the same bytes replay.
    let other = ga.seal(&a.client, &inner(&a, "other")).unwrap();
    assert_eq!(
        gb.process_journaled(&b, "a/1", b"", &other).unwrap_err(),
        Error::JournalConflict
    );
    assert!(gb.process_journaled(&b, "a/1", b"", &ct).unwrap().replayed);
    assert!(b.journal_consume(Some(&gid), "a/1").unwrap());
    assert_eq!(
        gb.process_journaled(&b, "a/1", b"", &ct).unwrap_err(),
        Error::Duplicate
    );
    // The same bytes under another key are a replay that MLS refuses.
    assert!(matches!(
        gb.process_journaled(&b, "a/2", b"", &ct),
        Err(Error::Mls(_))
    ));
    // Tombstones go once old enough; so do a group's entries with it.
    let now = clock.unix_millis() / 1000;
    assert_eq!(b.journal_purge(now).unwrap(), 0);
    assert_eq!(b.journal_purge(now + 1).unwrap(), 1);
    gb.process_journaled(&b, "o/1", b"", &other).unwrap();
    gb.delete(&b).unwrap();
    assert!(b.journal_pending().unwrap().is_empty());
}
