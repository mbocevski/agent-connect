//! Group mode in the core (SPEC §9): the pinned floor and identity counting
//! for the floor switch, partial removal, leaves and policy diffs in commit
//! summaries, the policy-change dry run and the policy at creation. The
//! negative cases build commits with [`Group::commit_unchecked`], which
//! skips every local check, and every honest member must reject them.
#![allow(clippy::many_single_char_names)]

use std::collections::BTreeSet;
use std::time::Duration;

use super::*;
use crate::clock::FakeClock;
use crate::identity::Identity;
use crate::policy::{InvitePermission, RemovePermission};
use crate::provider::MemoryStore;

type C = Client<MemoryStore>;

/// No members.
const NONE: [MemberInfo; 0] = [];

const MAY_NOT_CHANGE: Error = Error::Unauthorized("committer may not change this policy");

fn identity(label: &str) -> Identity {
    Identity::generate(&Rng::for_test(&format!("group-mode-{label}-ik"))).unwrap()
}

fn instance_of(id: &Identity, label: &str, clock: &Arc<FakeClock>) -> C {
    let inst = id
        .create_instance(
            &Rng::for_test(&format!("group-mode-{label}")),
            clock.as_ref(),
        )
        .unwrap();
    Client::new(
        MemoryStore::new(),
        Rng::for_test(&format!("group-mode-{label}-client")),
        inst,
        clock.clone(),
    )
    .unwrap()
}

fn client(label: &str, clock: &Arc<FakeClock>) -> C {
    instance_of(&identity(label), label, clock)
}

/// A KeyPackage (TLS bytes) of `c`, unused so far.
fn key_package(c: &C) -> Vec<u8> {
    let inv = Invite::create(c.rng(), c.clock(), "r.example", Duration::from_secs(60)).unwrap();
    c.create_join_request(inv.secret(), "j")
        .unwrap()
        .key_package
}

/// The instances of one group, each with its own client and view. A member
/// that sent a commit the others rejected is on a fork of its own: it is
/// left out of later commits.
struct Members {
    cs: Vec<C>,
    gs: Vec<Group>,
    forked: BTreeSet<usize>,
}

impl Members {
    /// A group created by `owner` (member 0), with `policy` or the defaults.
    fn new(owner: C, policy: Option<&GroupPolicy>) -> Self {
        let g = match policy {
            Some(p) => owner.create_group_with_policy("g", "p", p).unwrap(),
            None => owner.create_group("g", "p").unwrap(),
        };
        Self {
            cs: vec![owner],
            gs: vec![g],
            forked: BTreeSet::new(),
        }
    }

    /// The default group of `labels.len()` identities, all added by the
    /// owner (`labels[0]`).
    fn of(labels: &[&str], clock: &Arc<FakeClock>) -> Self {
        let mut m = Self::new(client(labels[0], clock), None);
        for label in &labels[1..] {
            m.join(0, client(label, clock));
        }
        m
    }

    fn id(&self, i: usize) -> String {
        self.cs[i].instance().identity().to_owned()
    }

    fn policy(&self) -> GroupPolicy {
        self.gs[0].policy().unwrap()
    }

    /// `joiner` joins through an invite of member `by`. Returns the summary.
    fn join(&mut self, by: usize, joiner: C) -> CommitSummary {
        let inv = Invite::create(
            self.cs[by].rng(),
            self.cs[by].clock(),
            "r.example",
            Duration::from_secs(60),
        )
        .unwrap();
        let req = joiner.create_join_request(inv.secret(), "j").unwrap();
        let v = self.cs[by]
            .verify_join_request(&req, &inv, &req.mailbox_id)
            .unwrap();
        let out = self.gs[by]
            .add_member(&self.cs[by], &v, &inv, true)
            .unwrap();
        let summary = self.apply(by, &out);
        let meta = InviteMeta::expected(inv.secret().id(), "g", "p");
        let g = joiner
            .join_from_wrapped_welcome(inv.secret(), &meta, out.welcome.as_ref().unwrap())
            .unwrap();
        self.cs.push(joiner);
        self.gs.push(g);
        self.converged();
        summary
    }

    /// Member `by` built `out`: the relay confirms it and every other
    /// member still in the group processes it, with the same summary.
    fn apply(&mut self, by: usize, out: &CommitOut) -> CommitSummary {
        let own = self.gs[by]
            .confirm_pending_commit(&self.cs[by], &out.msg_id)
            .unwrap();
        for (i, g) in self.gs.iter_mut().enumerate() {
            if i == by || self.forked.contains(&i) || !g.is_active() {
                continue;
            }
            let s = match g.process(&self.cs[i], &out.commit).unwrap() {
                Event::Commit(s) | Event::Removed(s) => s,
                other => panic!("member {i}: {}", other.kind()),
            };
            assert_eq!(
                (&s.committer, &s.added, &s.removed, &s.left),
                (&own.committer, &own.added, &own.removed, &own.left),
                "member {i}"
            );
            assert_eq!(
                (s.policy_changed, &s.previous_policy, &s.policy),
                (own.policy_changed, &own.previous_policy, &own.policy),
                "member {i}"
            );
        }
        own
    }

    fn set_policy(&mut self, by: usize, policy: &GroupPolicy) -> CommitSummary {
        let out = self.gs[by].set_policy(&self.cs[by], policy).unwrap();
        self.apply(by, &out)
    }

    /// Every member still in the group is at the same epoch with the same
    /// SAS.
    fn converged(&self) {
        let honest: Vec<&Group> = self
            .gs
            .iter()
            .enumerate()
            .filter(|(i, g)| !self.forked.contains(i) && g.is_active())
            .map(|(_, g)| g)
            .collect();
        for g in &honest {
            assert_eq!(
                (g.epoch(), g.state_fingerprint()),
                (honest[0].epoch(), honest[0].state_fingerprint())
            );
        }
    }

    /// Member `from` commits without any local check. Every other member
    /// rejects the commit with `err`, before merging it, and stays at its
    /// epoch with its SAS; `from` alone moved on, so its SAS differs (a
    /// forked view).
    fn rejected(
        &mut self,
        from: usize,
        adds: &[Vec<u8>],
        removes: &[u32],
        meta: Option<&[u8]>,
        policy: Option<&GroupPolicy>,
        err: &Error,
    ) {
        let policy = policy.map(|p| p.to_json().unwrap());
        self.rejected_raw(from, adds, removes, meta, policy.as_deref(), err);
    }

    fn rejected_raw(
        &mut self,
        from: usize,
        adds: &[Vec<u8>],
        removes: &[u32],
        meta: Option<&[u8]>,
        policy: Option<&[u8]>,
        err: &Error,
    ) {
        let (epoch, sas) = (self.gs[from].epoch(), self.gs[from].state_fingerprint());
        let out = self.gs[from]
            .commit_unchecked(&self.cs[from], adds, removes, meta, policy)
            .unwrap();
        assert_eq!(out.epoch, epoch);
        assert_eq!(self.gs[from].epoch(), epoch + 1);
        assert_ne!(self.gs[from].state_fingerprint(), sas);
        // Its own fan-out copy is an echo for the sender.
        assert_eq!(
            self.gs[from].process(&self.cs[from], &out.commit),
            Ok(Event::OwnEcho)
        );
        self.forked.insert(from);
        let forked_sas = self.gs[from].state_fingerprint();
        for (i, g) in self.gs.iter_mut().enumerate() {
            if self.forked.contains(&i) || !g.is_active() {
                continue;
            }
            assert_eq!(g.epoch(), epoch, "member {i}");
            assert_eq!(
                g.process(&self.cs[i], &out.commit).as_ref(),
                Err(err),
                "member {i}"
            );
            assert_eq!(
                (g.epoch(), g.state_fingerprint()),
                (epoch, sas.clone()),
                "member {i}"
            );
            assert_ne!(g.state_fingerprint(), forked_sas);
        }
        self.converged();
    }

    /// Member `from`'s unchecked commit is accepted by every other member.
    fn accepted(&mut self, from: usize, adds: &[Vec<u8>], policy: Option<&GroupPolicy>) {
        let policy = policy.map(|p| p.to_json().unwrap());
        let out = self.gs[from]
            .commit_unchecked(&self.cs[from], adds, &[], None, policy.as_deref())
            .unwrap();
        for (i, g) in self.gs.iter_mut().enumerate() {
            if i == from || self.forked.contains(&i) {
                continue;
            }
            assert!(
                matches!(g.process(&self.cs[i], &out.commit), Ok(Event::Commit(_))),
                "member {i}"
            );
        }
        self.converged();
    }
}

/// A policy with `invite: members`, so that any member may add.
fn open(m: &Members) -> GroupPolicy {
    GroupPolicy {
        invite: InvitePermission::Members,
        ..m.policy()
    }
}

/// D3: a replica of B in a 1:1 (three instances, two identities) keeps the
/// floor `free`; the Add of a third identity switches it, in the same
/// commit, and the summary has the policy before and after.
#[test]
fn a_replica_keeps_a_one_to_one_free_and_a_third_identity_switches_it() {
    let clock = Arc::new(FakeClock::default());
    let b = identity("replica-b");
    let mut m = Members::new(client("replica-a", &clock), None);
    m.join(0, instance_of(&b, "replica-b1", &clock));
    // B adds its replica itself (allowed whatever `invite` says).
    let s = m.join(1, instance_of(&b, "replica-b2", &clock));
    assert!(!s.policy_changed);
    assert_eq!((s.previous_policy, s.policy), (None, None));
    assert_eq!(m.policy().floor, Floor::Free);
    assert_eq!(m.gs[0].members().unwrap().len(), 3);
    // The owner's replica too: four instances, still two identities.
    let a = m.cs[0].instance().identity().to_owned();
    let a_id = identity("replica-a");
    assert_eq!(a_id.id(), a);
    m.join(0, instance_of(&a_id, "replica-a2", &clock));
    assert_eq!(m.policy().floor, Floor::Free);

    let before = m.policy();
    let s = m.join(0, client("replica-c", &clock));
    assert!(s.policy_changed);
    assert_eq!(s.previous_policy.as_ref(), Some(&before));
    assert_eq!(
        s.policy,
        Some(GroupPolicy {
            floor: Floor::Mention,
            ..before
        })
    );
    assert_eq!(m.policy().floor, Floor::Mention);
}

/// D3 negative: a member that adds its own replica to a 1:1 and switches
/// the floor in the same commit is rejected; the same switch on the Add of
/// a third identity is accepted.
#[test]
fn the_floor_switch_on_a_replica_add_is_rejected() {
    let clock = Arc::new(FakeClock::default());
    let b = identity("switch-b");
    let mut m = Members::new(client("switch-a", &clock), None);
    m.join(0, instance_of(&b, "switch-b1", &clock));
    let p = open(&m);
    m.set_policy(0, &p);
    let switched = GroupPolicy {
        floor: Floor::Mention,
        ..m.policy()
    };
    let replica = key_package(&instance_of(&b, "switch-b2", &clock));
    m.rejected(1, &[replica], &[], None, Some(&switched), &MAY_NOT_CHANGE);

    // The positive control: a third identity, added by B.
    let mut m = Members::new(client("switch-a", &clock), None);
    m.join(0, instance_of(&b, "switch-b1", &clock));
    let p = open(&m);
    m.set_policy(0, &p);
    let switched = GroupPolicy {
        floor: Floor::Mention,
        ..m.policy()
    };
    let c = key_package(&client("switch-c", &clock));
    m.accepted(1, &[c], Some(&switched));
    assert_eq!(m.gs[0].policy().unwrap().floor, Floor::Mention);
}

/// D4: with `floor_pinned`, a third identity doesn't switch the floor, and
/// a member that commits the switch anyway is rejected.
#[test]
fn a_pinned_floor_is_not_switched() {
    let clock = Arc::new(FakeClock::default());
    let a = client("pinned-a", &clock);
    let pinned = GroupPolicy {
        floor_pinned: true,
        invite: InvitePermission::Members,
        ..GroupPolicy::default_for(a.instance().identity())
    };
    let mut m = Members::new(a, Some(&pinned));
    m.join(0, client("pinned-b", &clock));
    let s = m.join(1, client("pinned-c", &clock));
    assert!(!s.policy_changed);
    assert_eq!(m.policy(), pinned);

    let mut m = Members::new(client("pinned-a", &clock), Some(&pinned));
    m.join(0, client("pinned-b", &clock));
    let switched = GroupPolicy {
        floor: Floor::Mention,
        ..pinned.clone()
    };
    let c = key_package(&client("pinned-c", &clock));
    m.rejected(
        1,
        std::slice::from_ref(&c),
        &[],
        None,
        Some(&switched),
        &MAY_NOT_CHANGE,
    );
    // Unpinning in the same commit doesn't make it the switch either.
    let mut m = Members::new(client("pinned-a", &clock), Some(&pinned));
    m.join(0, client("pinned-b", &clock));
    let unpinned = GroupPolicy {
        floor_pinned: false,
        ..switched
    };
    m.rejected(1, &[c], &[], None, Some(&unpinned), &MAY_NOT_CHANGE);
}

/// D4: an admin may pin or unpin the floor, a plain member may not.
#[test]
fn floor_pinned_is_changed_by_the_owner_or_an_admin_only() {
    let clock = Arc::new(FakeClock::default());
    let mut m = Members::of(&["pin-a", "pin-b", "pin-c"], &clock);
    let p = GroupPolicy {
        admins: vec![m.id(1)],
        ..m.policy()
    };
    m.set_policy(0, &p);
    let pinned = GroupPolicy {
        floor_pinned: true,
        ..p.clone()
    };
    m.rejected(2, &[], &[], None, Some(&pinned), &MAY_NOT_CHANGE);
    m.set_policy(1, &pinned);
    assert!(m.policy().floor_pinned);
    m.set_policy(1, &p);
    assert!(!m.policy().floor_pinned);
    m.set_policy(0, &pinned);
    assert!(m.policy().floor_pinned);
    assert_eq!(
        m.gs[2].set_policy(&m.cs[2], &p),
        Err(MAY_NOT_CHANGE),
        "the member's own check"
    );
}

/// Every commit kind a plain member (or an admin beyond the floor) is not
/// allowed to make is rejected by every honest member before merging, and
/// the committer, alone at the next epoch, shows a different SAS.
#[test]
fn unauthorized_commits_are_rejected_and_fork_only_the_committer() {
    let clock = Arc::new(FakeClock::default());
    let labels = ["bad-a", "bad-b", "bad-c"];
    let fresh = || Members::of(&labels, &clock);

    // Remove(C) by a plain member.
    fresh().rejected(
        1,
        &[],
        &[2],
        None,
        None,
        &Error::Unauthorized("committer may not remove members"),
    );
    // Remove of the owner by a plain member.
    fresh().rejected(
        1,
        &[],
        &[0],
        None,
        None,
        &Error::Unauthorized("committer may not remove members"),
    );
    // An Add without invite permission.
    let d = key_package(&client("bad-d", &clock));
    fresh().rejected(
        1,
        &[d],
        &[],
        None,
        None,
        &Error::Unauthorized("committer may not invite"),
    );
    // A GCE that makes the member the owner.
    let m = fresh();
    let grab = GroupPolicy {
        owner: m.id(1),
        ..m.policy()
    };
    let mut m = m;
    m.rejected(1, &[], &[], None, Some(&grab), &MAY_NOT_CHANGE);
    // A GCE that makes the member an admin, or widens `invite`.
    let mut m = fresh();
    let admin = GroupPolicy {
        admins: vec![m.id(1)],
        ..m.policy()
    };
    m.rejected(1, &[], &[], None, Some(&admin), &MAY_NOT_CHANGE);
    // A GCE that changes ac_group_meta, even from the owner.
    let mut m = fresh();
    let meta = GroupMeta {
        purpose: "something else".into(),
        ..m.gs[0].meta().unwrap()
    }
    .to_json()
    .unwrap();
    m.rejected(
        0,
        &[],
        &[],
        Some(&meta),
        None,
        &Error::Unauthorized("ac_group_meta is immutable"),
    );
    // A malformed policy.
    let mut m = fresh();
    let bad = String::from_utf8(m.policy().to_json().unwrap())
        .unwrap()
        .replace(r#""max_members":50"#, r#""max_members":51"#);
    m.rejected_raw(
        0,
        &[],
        &[],
        None,
        Some(bad.as_bytes()),
        &Error::InvalidGroupContext("policy max_members"),
    );
    // An admin that changes more than the floor.
    let mut m = fresh();
    let p = GroupPolicy {
        admins: vec![m.id(1)],
        ..m.policy()
    };
    m.set_policy(0, &p);
    let wider = GroupPolicy {
        floor: Floor::Moderated,
        invite: InvitePermission::Admins,
        ..p
    };
    m.rejected(1, &[], &[], None, Some(&wider), &MAY_NOT_CHANGE);
}

/// SPEC §9.2: removing one dead replica. One's own other instances need no
/// permission; another identity's need `remove`; the owner's need the
/// owner; and the remaining instance of that identity stays.
#[test]
fn remove_instances_removes_only_the_named_leaves() {
    let clock = Arc::new(FakeClock::default());
    let b = identity("part-b");
    let mut m = Members::new(client("part-a", &clock), None);
    m.join(0, instance_of(&b, "part-b1", &clock));
    m.join(0, instance_of(&b, "part-b2", &clock));
    m.join(0, client("part-c", &clock));
    let (b1_leaf, b2_leaf) = (m.gs[1].own_leaf_index(), m.gs[2].own_leaf_index());

    // C (a plain member) may not remove B2.
    assert_eq!(
        m.gs[3].remove_instances(&m.cs[3], &[b2_leaf]),
        Err(Error::NotPermitted("this identity may not remove members"))
    );
    assert!(!m.gs[3].has_pending_commit());
    // Bad arguments.
    assert_eq!(
        m.gs[1].remove_instances(&m.cs[1], &[b1_leaf]),
        Err(Error::NotPermitted(
            "this instance's own leaf: propose a leave instead"
        ))
    );
    assert_eq!(
        m.gs[1].remove_instances(&m.cs[1], &[99]),
        Err(Error::UnknownMember)
    );
    assert_eq!(
        m.gs[1].remove_instances(&m.cs[1], &[]),
        Err(Error::UnknownMember)
    );

    // B1 removes its own dead replica B2; B1 stays.
    let b2 = m.gs[0]
        .members()
        .unwrap()
        .into_iter()
        .find(|x| x.leaf_index == b2_leaf)
        .unwrap();
    let out = m.gs[1]
        .remove_instances(&m.cs[1], &[b2_leaf, b2_leaf])
        .unwrap();
    assert_eq!(out.routing.remove, vec![b2.mailbox_id.clone()]);
    let s = m.apply(1, &out);
    assert_eq!(s.removed, vec![b2]);
    assert_eq!(s.left, NONE);
    assert!(!m.gs[2].is_active());
    let ids: Vec<String> = m.gs[0]
        .members()
        .unwrap()
        .into_iter()
        .map(|x| x.identity)
        .collect();
    assert_eq!(ids, vec![m.id(0), m.id(1), m.id(3)]);
    m.converged();
}

#[test]
fn remove_instances_of_others_needs_the_remove_permission() {
    let clock = Arc::new(FakeClock::default());
    let a = identity("perm-a");
    let b = identity("perm-b");
    let setup = || {
        let mut m = Members::new(instance_of(&a, "perm-a1", &clock), None);
        m.join(0, instance_of(&a, "perm-a2", &clock));
        m.join(0, instance_of(&b, "perm-b1", &clock));
        m.join(0, instance_of(&b, "perm-b2", &clock));
        m.join(0, client("perm-c", &clock));
        let p = GroupPolicy {
            admins: vec![m.id(4)],
            remove: RemovePermission::Admins,
            ..m.policy()
        };
        m.set_policy(0, &p);
        m
    };
    // Members: A1 (owner), A2, B1, B2, C (admin, remove: admins).
    let mut m = setup();
    let (a2, b2, c) = (
        m.gs[1].own_leaf_index(),
        m.gs[3].own_leaf_index(),
        m.gs[4].own_leaf_index(),
    );
    // The admin may not remove one of the owner's instances locally...
    assert_eq!(
        m.gs[4].remove_instances(&m.cs[4], &[a2]),
        Err(Error::NotPermitted("only the owner may remove the owner"))
    );
    // ...but may remove one of B's, and B1 stays.
    let out = m.gs[4].remove_instances(&m.cs[4], &[b2]).unwrap();
    let s = m.apply(4, &out);
    assert_eq!(s.removed.len(), 1);
    assert_eq!(s.removed[0].identity, m.id(3));
    assert!(m.gs[2].is_active());
    // A plain member (B1) removing another identity's instance is rejected.
    m.rejected(
        2,
        &[],
        &[c],
        None,
        None,
        &Error::Unauthorized("committer may not remove members"),
    );
    // So is the admin removing one of the owner's instances, at the
    // receivers.
    m.rejected(
        4,
        &[],
        &[a2],
        None,
        None,
        &Error::Unauthorized("only the owner may remove the owner"),
    );

    let mut m = setup();
    // A plain member removes one of its own other instances (B1 removes B2).
    let out = m.gs[2].remove_instances(&m.cs[2], &[b2]).unwrap();
    m.apply(2, &out);
    // B1 removing one of the owner's instances is rejected.
    m.rejected(
        2,
        &[],
        &[a2],
        None,
        None,
        &Error::Unauthorized("committer may not remove members"),
    );
    // A2, an instance of the owner's identity, removes as the owner.
    let out = m.gs[1].remove_instances(&m.cs[1], &[c]).unwrap();
    m.apply(1, &out);
    assert_eq!(
        m.gs[0]
            .members()
            .unwrap()
            .into_iter()
            .map(|x| x.identity)
            .collect::<Vec<_>>(),
        vec![m.id(0), m.id(1), m.id(2)]
    );
}

/// G1: `pending_leaves` lists the stored leave proposals (each leaf once),
/// on every member including the leaver, and the commit that carries them
/// reports them in `left` as well as `removed`. A removal is not a leave.
#[test]
fn leaves_are_pending_until_committed_and_then_reported_as_left() {
    let clock = Arc::new(FakeClock::default());
    let mut m = Members::of(&["leave-a", "leave-b", "leave-c", "leave-d"], &clock);
    assert_eq!(m.gs[0].pending_leaves().unwrap(), NONE);
    let c = m.gs[0].members().unwrap()[2].clone();
    for _ in 0..2 {
        let p = m.gs[2].propose_leave(&m.cs[2]).unwrap();
        for i in [0, 1, 3] {
            assert_eq!(
                m.gs[i].process(&m.cs[i], &p),
                Ok(Event::LeaveProposed(c.clone()))
            );
        }
    }
    for i in 0..4 {
        assert_eq!(m.gs[i].pending_leaves().unwrap(), vec![c.clone()], "{i}");
    }
    let out = m.gs[1].commit_pending_proposals(&m.cs[1]).unwrap();
    let s = m.apply(1, &out);
    assert_eq!(s.left, vec![c.clone()]);
    assert_eq!(s.removed, vec![c]);
    assert!(!s.policy_changed);
    assert_eq!(m.gs[0].pending_leaves().unwrap(), NONE);
    assert!(!m.gs[2].is_active());

    let d = m.id(3);
    let out = m.gs[0].remove(&m.cs[0], &d).unwrap();
    let s = m.apply(0, &out);
    assert_eq!(s.removed.len(), 1);
    assert_eq!(s.left, NONE);
}

/// A1 and A2 (the owner's two instances) and B. A1 and A2 each propose a
/// leave before seeing the other's.
fn owner_replicas_both_leaving(label: &str, clock: &Arc<FakeClock>) -> (Members, Vec<u8>, Vec<u8>) {
    let a = identity(&format!("{label}-a"));
    let mut m = Members::new(instance_of(&a, &format!("{label}-a1"), clock), None);
    m.join(0, instance_of(&a, &format!("{label}-a2"), clock));
    m.join(0, client(&format!("{label}-b"), clock));
    let p1 = m.gs[0].propose_leave(&m.cs[0]).unwrap();
    let p2 = m.gs[1].propose_leave(&m.cs[1]).unwrap();
    (m, p1, p2)
}

fn leave_leaves(m: &Members, i: usize) -> Vec<u32> {
    m.gs[i]
        .pending_leaves()
        .unwrap()
        .iter()
        .map(|x| x.leaf_index)
        .collect()
}

/// Review F1: two instances of the owner propose a leave at once. Every
/// member stores both proposals (each is valid on its own), and every
/// member agrees on the leaves the next commit carries, whatever order the
/// proposals arrive in: all but the owner instance with the lowest leaf
/// (A1), so the owner keeps an instance.
#[test]
fn review_concurrent_owner_replica_leaves_split_pending_leaves() {
    let clock = Arc::new(FakeClock::default());
    // (member, proposal) in delivery order: p1 first, then p2 first.
    let orders: [&[(usize, usize)]; 3] = [
        &[(2, 1), (1, 1), (2, 2), (0, 2)],
        &[(2, 2), (0, 2), (2, 1), (1, 1)],
        &[(1, 1), (0, 2), (2, 2), (2, 1)],
    ];
    for (n, order) in orders.iter().enumerate() {
        let (mut m, p1, p2) = owner_replicas_both_leaving(&format!("rvs{n}"), &clock);
        for &(i, p) in *order {
            let bytes = if p == 1 { &p1 } else { &p2 };
            assert!(
                matches!(
                    m.gs[i].process(&m.cs[i], bytes),
                    Ok(Event::LeaveProposed(_))
                ),
                "order {n}: member {i} <- p{p}"
            );
        }
        let a2 = m.gs[1].own_leaf_index();
        for i in 0..3 {
            assert_eq!(leave_leaves(&m, i), vec![a2], "order {n}: member {i}");
        }
    }
}

/// Review F1, then the commit: B commits the pending leaves; every member,
/// both leavers included, processes it. A2 is gone, A1 stays as the owner's
/// instance, and A1 and B share the epoch and SAS. A1's leave was not
/// carried: it can't leave again until it transfers ownership.
#[test]
fn review_concurrent_owner_replica_leaves_then_commit() {
    let clock = Arc::new(FakeClock::default());
    for (n, p1_first) in [true, false].into_iter().enumerate() {
        let (mut m, p1, p2) = owner_replicas_both_leaving(&format!("rvc{n}"), &clock);
        let (first, second) = if p1_first { (&p1, &p2) } else { (&p2, &p1) };
        for bytes in [first, second] {
            for i in 0..3 {
                // Each leaver gets only the other's proposal.
                let own = (i == 0 && bytes == &p1) || (i == 1 && bytes == &p2);
                if !own {
                    m.gs[i].process(&m.cs[i], bytes).unwrap();
                }
            }
        }
        let a2 = m.gs[0].members().unwrap()[1].clone();
        let out = m.gs[2].commit_pending_proposals(&m.cs[2]).unwrap();
        let s = m.apply(2, &out);
        assert_eq!(s.left, vec![a2.clone()], "order {n}");
        assert_eq!(s.removed, vec![a2], "order {n}");
        assert!(!m.gs[1].is_active(), "order {n}");
        assert!(m.gs[0].is_active(), "order {n}");
        assert_eq!(
            (m.gs[0].epoch(), m.gs[0].state_fingerprint()),
            (m.gs[2].epoch(), m.gs[2].state_fingerprint())
        );
        assert_eq!(
            m.gs[0].propose_leave(&m.cs[0]),
            Err(Error::NotPermitted(OWNER_MUST_TRANSFER))
        );
    }
}

/// Review F1: B commits after seeing only A1's leave; A2's arrives in the
/// next epoch and is stale. The commit carries A1's leave only, and A2
/// (which stored A1's proposal before the commit reached it) processes it.
#[test]
fn a_commit_between_two_owner_replica_leaves_converges() {
    let clock = Arc::new(FakeClock::default());
    let (mut m, p1, p2) = owner_replicas_both_leaving("rvm", &clock);
    m.gs[2].process(&m.cs[2], &p1).unwrap();
    let out = m.gs[2].commit_pending_proposals(&m.cs[2]).unwrap();
    m.gs[1].process(&m.cs[1], &p1).unwrap();
    m.gs[0].process(&m.cs[0], &p2).unwrap();
    let s = m.apply(2, &out);
    assert_eq!(s.left.len(), 1);
    assert!(!m.gs[0].is_active());
    assert!(m.gs[1].is_active());
    assert_eq!(m.gs[2].process(&m.cs[2], &p2), Err(Error::WrongEpoch));
    assert_eq!(
        (m.gs[1].state_fingerprint(), m.gs[1].epoch()),
        (m.gs[2].state_fingerprint(), m.gs[2].epoch())
    );
}

/// Review F1, the malicious committer: a commit that carries both owner
/// replicas' leaves removes the owner's last instance and is rejected.
#[test]
fn a_commit_carrying_every_owner_replica_leave_is_rejected() {
    let clock = Arc::new(FakeClock::default());
    let (mut m, p1, p2) = owner_replicas_both_leaving("rvx", &clock);
    m.gs[2].process(&m.cs[2], &p1).unwrap();
    m.gs[2].process(&m.cs[2], &p2).unwrap();
    m.gs[1].process(&m.cs[1], &p1).unwrap();
    m.gs[0].process(&m.cs[0], &p2).unwrap();
    // commit_unchecked carries every stored proposal.
    m.rejected(
        2,
        &[],
        &[],
        None,
        None,
        &Error::Unauthorized(OWNER_MUST_TRANSFER),
    );
}

/// Re-review R1: both owner instances are leaving, and a member that may
/// invite commits both leaves plus an Add of a KeyPackage of the owner's
/// identity it holds (and withholds the Welcome). The owner would be left
/// with only that new, never-joined instance: rejected. The owner must keep
/// an instance that was in the group before the commit.
#[test]
fn rr_both_owner_leaves_plus_new_owner_instance_is_rejected() {
    let clock = Arc::new(FakeClock::default());
    let a = identity("rr3-a");
    let mut m = Members::new(instance_of(&a, "rr3-a1", &clock), None);
    m.join(0, instance_of(&a, "rr3-a2", &clock));
    m.join(0, client("rr3-b", &clock));
    let p = GroupPolicy {
        invite: InvitePermission::Members,
        ..m.policy()
    };
    m.set_policy(0, &p);
    let p1 = m.gs[0].propose_leave(&m.cs[0]).unwrap();
    let p2 = m.gs[1].propose_leave(&m.cs[1]).unwrap();
    for (to, p) in [(1, &p1), (2, &p1), (0, &p2), (2, &p2)] {
        assert!(matches!(
            m.gs[to].process(&m.cs[to], p),
            Ok(Event::LeaveProposed(_))
        ));
    }
    let a3 = key_package(&instance_of(&a, "rr3-a3", &clock));
    m.rejected(
        2,
        &[a3],
        &[],
        None,
        None,
        &Error::Unauthorized(OWNER_MUST_TRANSFER),
    );
    assert!(m.gs[0].is_active() && m.gs[1].is_active());
}

/// R1, the same rule for a transfer: the new owner must be an instance that
/// was in the group before the commit, not one the commit adds.
#[test]
fn ownership_may_not_go_to_an_identity_the_same_commit_adds() {
    let clock = Arc::new(FakeClock::default());
    let mut m = Members::of(&["rrt-a", "rrt-b"], &clock);
    let d = client("rrt-d", &clock);
    let to_d = GroupPolicy {
        owner: d.instance().identity().to_owned(),
        ..m.policy()
    };
    let kp = key_package(&d);
    m.rejected(
        0,
        &[kp],
        &[],
        None,
        Some(&to_d),
        &Error::Unauthorized("new owner is not a member"),
    );
}

/// Review F4: removing a member whose leave is pending carries its own
/// proposal, so every member reports a leave (`left`), for `remove` and
/// `remove_instances` alike, and a plain member may commit it this way.
#[test]
fn removing_a_leaving_member_reports_a_leave() {
    let clock = Arc::new(FakeClock::default());
    for how in 0..3 {
        let mut m = Members::of(&["rl-a", "rl-b", "rl-c", "rl-d"], &clock);
        let p = m.gs[2].propose_leave(&m.cs[2]).unwrap();
        for i in [0, 1, 3] {
            m.gs[i].process(&m.cs[i], &p).unwrap();
        }
        let c = m.gs[0].members().unwrap()[2].clone();
        let (by, out) = match how {
            0 => (0, m.gs[0].remove(&m.cs[0], &c.identity).unwrap()),
            1 => (
                0,
                m.gs[0].remove_instances(&m.cs[0], &[c.leaf_index]).unwrap(),
            ),
            _ => (
                1,
                m.gs[1].remove_instances(&m.cs[1], &[c.leaf_index]).unwrap(),
            ),
        };
        let s = m.apply(by, &out);
        assert_eq!(s.left, vec![c.clone()], "{how}");
        assert_eq!(s.removed, vec![c], "{how}");
        // The others' removal still needs the permission.
        if how == 0 {
            let d = m.gs[0].members().unwrap()[2].clone();
            assert_eq!(
                m.gs[1].remove_instances(&m.cs[1], &[d.leaf_index]),
                Err(Error::NotPermitted("this identity may not remove members"))
            );
        }
    }
    // A leaving member together with a member that isn't leaving: one
    // leave, one removal.
    let mut m = Members::of(&["rl2-a", "rl2-b", "rl2-c", "rl2-d"], &clock);
    let p = m.gs[2].propose_leave(&m.cs[2]).unwrap();
    for i in [0, 1, 3] {
        m.gs[i].process(&m.cs[i], &p).unwrap();
    }
    let ms = m.gs[0].members().unwrap();
    let out = m.gs[0]
        .remove_instances(&m.cs[0], &[ms[2].leaf_index, ms[3].leaf_index])
        .unwrap();
    let s = m.apply(0, &out);
    assert_eq!(s.left, vec![ms[2].clone()]);
    assert_eq!(s.removed.len(), 2);
}

/// The owner's add of a third identity in a commit that also carries the
/// second identity's last leave keeps two identities, so no switch.
#[test]
fn the_floor_switch_counts_the_pending_leaves_of_the_commit() {
    let clock = Arc::new(FakeClock::default());
    let mut m = Members::of(&["pl-a", "pl-b"], &clock);
    let p = m.gs[1].propose_leave(&m.cs[1]).unwrap();
    assert!(matches!(
        m.gs[0].process(&m.cs[0], &p),
        Ok(Event::LeaveProposed(_))
    ));
    let s = m.join(0, client("pl-c", &clock));
    assert_eq!(s.left.len(), 1);
    assert!(!s.policy_changed);
    assert_eq!(m.policy().floor, Floor::Free);
}

/// ADR-004: summaries are journalled. One written before `left`,
/// `previous_policy` and `policy` existed still reads, with them empty.
#[test]
fn a_journalled_summary_without_the_new_fields_still_reads() {
    let clock = Arc::new(FakeClock::default());
    let mut m = Members::of(&["journal-a", "journal-b"], &clock);
    let p = GroupPolicy {
        require_verified: true,
        ..m.policy()
    };
    let s = m.set_policy(0, &p);
    assert!(s.policy.is_some() && s.previous_policy.is_some());
    let stored = crate::journal::Stored::Event {
        event: Event::Commit(s.clone()),
    };
    let mut v: serde_json::Value =
        serde_json::from_slice(&crate::journal::encode(&stored).unwrap()).unwrap();
    for key in ["left", "previous_policy", "policy"] {
        assert!(
            v["event"]["data"]
                .as_object_mut()
                .unwrap()
                .remove(key)
                .is_some()
        );
    }
    let old: crate::journal::Stored = serde_json::from_value(v).unwrap();
    let crate::journal::Stored::Event {
        event: Event::Commit(read),
    } = old
    else {
        panic!("not an event");
    };
    assert_eq!(
        read,
        CommitSummary {
            left: vec![],
            previous_policy: None,
            policy: None,
            ..s
        }
    );
}

/// G3: the dry run gives exactly what `set_policy` would, without building
/// or keeping a commit.
#[test]
fn check_policy_change_agrees_with_set_policy() {
    let clock = Arc::new(FakeClock::default());
    let mut m = Members::of(&["dry-a", "dry-b", "dry-c"], &clock);
    let base = GroupPolicy {
        admins: vec![m.id(1)],
        ..m.policy()
    };
    m.set_policy(0, &base);
    let outsider = identity("dry-outsider").id();
    let candidates = [
        base.clone(),
        GroupPolicy {
            require_verified: true,
            ..base.clone()
        },
        GroupPolicy {
            floor: Floor::Moderated,
            floor_moderator: Some(m.id(1)),
            floor_pinned: true,
            ..base.clone()
        },
        GroupPolicy {
            invite: InvitePermission::Members,
            ..base.clone()
        },
        GroupPolicy {
            owner: m.id(2),
            ..base.clone()
        },
        GroupPolicy {
            owner: outsider,
            ..base.clone()
        },
        GroupPolicy {
            max_members: 2,
            ..base.clone()
        },
        GroupPolicy {
            v: 1,
            ..base.clone()
        },
    ];
    let mut outcomes = BTreeSet::new();
    for i in 0..3 {
        for p in &candidates {
            let dry = m.gs[i].check_policy_change(&m.cs[i], p);
            let epoch = m.gs[i].epoch();
            let real = m.gs[i].set_policy(&m.cs[i], p).map(|_| ());
            if real.is_ok() {
                m.gs[i].discard_pending_commit(&m.cs[i]).unwrap();
            }
            assert_eq!(dry, real, "member {i}: {p:?}");
            assert_eq!(m.gs[i].epoch(), epoch);
            assert!(!m.gs[i].has_pending_commit());
            outcomes.insert(format!("{dry:?}"));
        }
    }
    // The cases cover acceptance and every kind of refusal.
    assert!(outcomes.len() >= 5, "{outcomes:?}");
    assert!(m.gs[0].check_policy_change(&m.cs[0], &base).is_ok());
    // A member that was removed has no say.
    let c = m.id(2);
    let out = m.gs[0].remove(&m.cs[0], &c).unwrap();
    m.apply(0, &out);
    assert_eq!(
        m.gs[2].check_policy_change(&m.cs[2], &base),
        Err(Error::NotMember)
    );
}

/// F2: with a leave pending, `set_policy` carries it (as every commit
/// does), and the dry run reasons about the same commit: an owner transfer
/// to the leaver is refused, a `max_members` that fits only after the
/// leave is accepted. The leaver's own dry run fails as its `set_policy`
/// does, and so does a dry run while a commit is pending.
#[test]
fn check_policy_change_agrees_with_set_policy_while_leaves_are_pending() {
    let clock = Arc::new(FakeClock::default());
    let mut m = Members::of(&["dryl-a", "dryl-b", "dryl-c", "dryl-d"], &clock);
    let base = GroupPolicy {
        admins: vec![m.id(1)],
        ..m.policy()
    };
    m.set_policy(0, &base);
    let p = m.gs[2].propose_leave(&m.cs[2]).unwrap();
    for i in [0, 1, 3] {
        assert!(matches!(
            m.gs[i].process(&m.cs[i], &p),
            Ok(Event::LeaveProposed(_))
        ));
    }
    let candidates = [
        base.clone(),
        GroupPolicy {
            owner: m.id(2),
            ..base.clone()
        },
        GroupPolicy {
            owner: m.id(3),
            ..base.clone()
        },
        GroupPolicy {
            max_members: 3,
            ..base.clone()
        },
        GroupPolicy {
            max_members: 2,
            ..base.clone()
        },
        GroupPolicy {
            floor: Floor::Moderated,
            floor_moderator: Some(m.id(1)),
            ..base.clone()
        },
        GroupPolicy {
            require_verified: true,
            ..base.clone()
        },
    ];
    let mut outcomes = BTreeSet::new();
    for i in 0..4 {
        for p in &candidates {
            let dry = m.gs[i].check_policy_change(&m.cs[i], p);
            let real = m.gs[i].set_policy(&m.cs[i], p).map(|_| ());
            if real.is_ok() {
                m.gs[i].discard_pending_commit(&m.cs[i]).unwrap();
            }
            assert_eq!(dry, real, "member {i}: {p:?}");
            assert!(!m.gs[i].has_pending_commit());
            outcomes.insert(format!("{dry:?}"));
        }
    }
    assert!(outcomes.len() >= 4, "{outcomes:?}");
    // The two cases the review found, by name.
    let to_leaver = GroupPolicy {
        owner: m.id(2),
        ..base.clone()
    };
    assert_eq!(
        m.gs[0].check_policy_change(&m.cs[0], &to_leaver),
        Err(Error::Unauthorized("new owner is not a member"))
    );
    let fits_after = GroupPolicy {
        max_members: 3,
        ..base.clone()
    };
    assert_eq!(m.gs[0].check_policy_change(&m.cs[0], &fits_after), Ok(()));
    // The leaver itself can't commit while its leave is pending.
    assert_eq!(
        m.gs[2].check_policy_change(&m.cs[2], &base),
        Err(Error::NotPermitted(OWN_LEAVE_PENDING))
    );
    // Nor can anyone while a commit of its own is pending.
    let out = m.gs[0].update(&m.cs[0]).unwrap();
    assert_eq!(
        m.gs[0].check_policy_change(&m.cs[0], &base),
        Err(Error::CommitPending)
    );
    assert_eq!(
        m.gs[0].set_policy(&m.cs[0], &base).map(|_| ()),
        Err(Error::CommitPending)
    );
    m.gs[0].discard_pending_commit(&m.cs[0]).unwrap();
    drop(out);
}

/// D15: the policy at creation is validated and must name the creator as
/// owner; it is in force from epoch 0 and every joiner sees it.
#[test]
fn a_group_is_created_with_a_policy() {
    let clock = Arc::new(FakeClock::default());
    let a = client("create-a", &clock);
    let me = a.instance().identity().to_owned();
    let other = identity("create-other").id();
    let p = GroupPolicy {
        floor: Floor::Mention,
        floor_pinned: true,
        invite: InvitePermission::Admins,
        admins: vec![other.clone()],
        max_members: 3,
        ..GroupPolicy::default_for(&me)
    };
    for (bad, err) in [
        (
            GroupPolicy {
                owner: other.clone(),
                ..p.clone()
            },
            Error::NotPermitted("the creator must be the owner"),
        ),
        (
            GroupPolicy {
                max_members: 0,
                ..p.clone()
            },
            Error::InvalidGroupContext("policy max_members"),
        ),
        (GroupPolicy { v: 1, ..p.clone() }, Error::UnsupportedVersion),
    ] {
        assert_eq!(a.create_group_with_policy("g", "p", &bad).unwrap_err(), err);
    }
    let mut m = Members::new(a, Some(&p));
    assert_eq!(m.gs[0].epoch(), 0);
    assert_eq!(m.policy(), p);
    m.join(0, client("create-b", &clock));
    assert_eq!(m.gs[1].policy().unwrap(), p);
    m.join(0, client("create-c", &clock));
    assert_eq!(m.policy(), p);
    // max_members 3 is in force for the owner's own Add.
    let d = client("create-d", &clock);
    let inv = Invite::create(m.cs[0].rng(), m.cs[0].clock(), "r", Duration::from_secs(60)).unwrap();
    let req = d.create_join_request(inv.secret(), "d").unwrap();
    let v = m.cs[0]
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    assert_eq!(
        m.gs[0].add_member(&m.cs[0], &v, &inv, true).unwrap_err(),
        Error::Unauthorized("group would exceed max_members")
    );
}

/// A group "g"/"p" of `owner` alone whose context holds `policy` as these
/// exact bytes, as a group created before `floor_pinned` existed would.
fn group_with_policy_bytes(owner: C, policy: &[u8]) -> Members {
    let meta = GroupMeta {
        v: 0,
        name: "g".into(),
        purpose: "p".into(),
        created_at: owner.now(),
        created_by: owner.instance().identity().to_owned(),
    };
    let exts = group_context_extensions(&meta.to_json().unwrap(), policy).unwrap();
    let id: [u8; 16] = owner.rng().array().unwrap();
    let mls = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(&id))
        .ciphersuite(CS)
        .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .with_capabilities(capabilities())
        .with_leaf_node_extensions(leaf_extensions(owner.instance.cert()).unwrap())
        .unwrap()
        .with_group_context_extensions(exts)
        .build(&owner.provider, &owner.signer(), owner.credential())
        .unwrap();
    Members {
        cs: vec![owner],
        gs: vec![Group { mls }],
        forked: BTreeSet::new(),
    }
}

/// `policy` encoded as it was before `floor_pinned` existed: no such key.
fn legacy_bytes(policy: &GroupPolicy) -> String {
    let old = String::from_utf8(policy.to_json().unwrap())
        .unwrap()
        .replace(&format!(r#""floor_pinned":{},"#, policy.floor_pinned), "");
    assert!(!old.contains("floor_pinned"));
    old
}

/// D4 compatibility: a group whose context still holds a policy written
/// before `floor_pinned` (the key absent) reads as unpinned, for its
/// members and for joiners (from the Welcome), and switches its floor with
/// a third identity. New policy commits carry the canonical encoding.
#[test]
fn a_policy_without_floor_pinned_in_the_group_context_reads_as_unpinned() {
    let clock = Arc::new(FakeClock::default());
    let a = client("old-a", &clock);
    let policy = GroupPolicy::default_for(a.instance().identity());
    let old = legacy_bytes(&policy);
    let mut m = group_with_policy_bytes(a, old.as_bytes());
    assert_eq!(m.policy(), policy);
    m.join(0, client("old-b", &clock));
    assert_eq!(m.gs[1].policy().unwrap(), policy);
    assert!(!m.gs[1].policy().unwrap().floor_pinned);
    let s = m.join(0, client("old-c", &clock));
    assert!(s.policy_changed);
    assert_eq!(s.previous_policy, Some(policy.clone()));
    assert_eq!(m.policy().floor, Floor::Mention);
    // The switch wrote the canonical encoding.
    let ctx = check_group_context(m.gs[2].mls.extensions()).unwrap();
    assert_eq!(ctx.policy.to_json().unwrap(), ctx.policy_bytes);
}

/// F3: each policy has exactly one encoding a commit may carry. A
/// GroupContextExtensions whose policy bytes parse to the current policy
/// but aren't its canonical encoding (a key left out: `floor_pinned`,
/// `floor_moderator`) is rejected, even from the owner and even as a
/// no-op.
#[test]
fn a_commit_with_a_non_canonical_policy_encoding_is_rejected() {
    let clock = Arc::new(FakeClock::default());
    let labels = ["enc-a", "enc-b", "enc-c"];
    let canonical =
        String::from_utf8(Members::of(&labels, &clock).policy().to_json().unwrap()).unwrap();
    for (from, bytes) in [
        (2, canonical.replace(r#""floor_pinned":false,"#, "")),
        (0, canonical.replace(r#""floor_pinned":false,"#, "")),
        (2, canonical.replace(r#""floor_moderator":null,"#, "")),
        (
            0,
            canonical
                .replace(r#""floor_moderator":null,"#, "")
                .replace(r#""floor_pinned":false,"#, "")
                .replace(r#""require_verified":false"#, r#""require_verified":true"#),
        ),
    ] {
        let mut m = Members::of(&labels, &clock);
        assert!(GroupPolicy::from_json(bytes.as_bytes()).is_ok(), "{bytes}");
        m.rejected_raw(
            from,
            &[],
            &[],
            None,
            Some(bytes.as_bytes()),
            &Error::InvalidGroupContext("policy not in canonical form"),
        );
    }
}

/// A client of identity `id` whose instance certificate repeats the
/// `instance_id` of `of` with a fresh key: what anyone holding `id`'s IK can
/// sign (SPEC §9.4).
fn twin_of(id: &Identity, of: &C, label: &str, clock: &Arc<FakeClock>) -> C {
    let fresh = id
        .create_instance(
            &Rng::for_test(&format!("group-mode-{label}")),
            clock.as_ref(),
        )
        .unwrap();
    let mut cert = fresh.cert().clone();
    cert.instance_id = of.instance().instance_id();
    cert.sig = id.sign(&cert.signing_input().unwrap());
    let secret: serde_json::Value =
        serde_json::from_slice(&fresh.to_secret_bytes().unwrap()).unwrap();
    let forged = serde_json::to_vec(&serde_json::json!({
        "cert": String::from_utf8(cert.to_json().unwrap()).unwrap(),
        "sk": secret["sk"],
        "v": 0,
    }))
    .unwrap();
    Client::new(
        MemoryStore::new(),
        Rng::for_test(&format!("group-mode-{label}-client")),
        crate::identity::Instance::from_secret_bytes(&forged).unwrap(),
        clock.clone(),
    )
    .unwrap()
}

#[test]
fn a_repeated_instance_id_is_refused_by_the_committer_and_every_member() {
    let clock = Arc::new(FakeClock::default());
    let x = identity("twin-x");
    let mut m = Members::new(client("twin-a", &clock), None);
    m.join(0, client("twin-b", &clock));
    m.join(0, instance_of(&x, "twin-x1", &clock));
    let twin = twin_of(&x, &m.cs[2], "twin-x2", &clock);
    assert_eq!(
        twin.instance().instance_id(),
        m.cs[2].instance().instance_id()
    );

    // The committer refuses to build it.
    let inv = Invite::create(
        m.cs[0].rng(),
        m.cs[0].clock(),
        "r.example",
        Duration::from_secs(60),
    )
    .unwrap();
    let req = twin.create_join_request(inv.secret(), "j").unwrap();
    let v = m.cs[0]
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    assert_eq!(
        m.gs[0].add_member(&m.cs[0], &v, &inv, true).map(|_| ()),
        Err(Error::Unauthorized(REPEATED_INSTANCE))
    );
    assert!(!m.gs[0].has_pending_commit());
    m.converged();

    // Every member rejects it from a committer that skipped the check, and
    // only that committer moves on (its SAS shows the fork).
    m.rejected(
        0,
        &[key_package(&twin)],
        &[],
        None,
        None,
        &Error::Unauthorized(REPEATED_INSTANCE),
    );
}

#[test]
fn an_instance_added_again_after_its_leaf_went_is_accepted() {
    let clock = Arc::new(FakeClock::default());
    let x = identity("again-x");
    let mut m = Members::new(client("again-a", &clock), None);
    m.join(0, instance_of(&x, "again-x1", &clock));
    m.join(0, instance_of(&x, "again-x2", &clock));
    let x1_leaf = m.gs[1].own_leaf_index();

    // The same commit removes X1's leaf and adds X1 again (a fresh
    // KeyPackage of the same instance).
    let again = key_package(&m.cs[1]);
    let out = m.gs[0]
        .commit_unchecked(&m.cs[0], &[again], &[x1_leaf], None, None)
        .unwrap();
    assert!(matches!(
        m.gs[2].process(&m.cs[2], &out.commit),
        Ok(Event::Commit(_))
    ));
    let ids = |g: &Group| -> Vec<u64> {
        let mut ids: Vec<u64> = g
            .members()
            .unwrap()
            .iter()
            .map(|mm| mm.instance_id)
            .collect();
        ids.sort_unstable();
        ids
    };
    assert_eq!(ids(&m.gs[0]), ids(&m.gs[2]));
    assert_eq!(m.gs[0].members().unwrap().len(), 3);

    // In a later commit, after its leaf went in an earlier one.
    let mut m = Members::new(client("later-a", &clock), None);
    m.join(0, instance_of(&x, "later-x1", &clock));
    m.join(0, instance_of(&x, "later-x2", &clock));
    let leaf = m.gs[1].own_leaf_index();
    let out = m.gs[2].remove_instances(&m.cs[2], &[leaf]).unwrap();
    m.apply(2, &out);
    let back = m.cs.remove(1);
    m.gs.remove(1).delete(&back).unwrap();
    m.join(0, back);
    let x_ids: Vec<u64> = m.gs[0]
        .members()
        .unwrap()
        .iter()
        .filter(|mm| mm.identity == m.id(1))
        .map(|mm| mm.instance_id)
        .collect();
    assert_eq!(x_ids.len(), 2);
    assert_ne!(x_ids[0], x_ids[1]);
}

/// Member `i` stages a self-update whose leaf carries `cert` (signed by its
/// identity) instead of its own; returns the commit's bytes.
fn self_update_with_cert(
    m: &mut Members,
    i: usize,
    cert: &crate::identity::InstanceCert,
) -> Vec<u8> {
    use openmls::prelude::LeafNodeParameters;
    let params = LeafNodeParameters::builder()
        .with_extensions(crate::mls::leaf_extensions(cert).unwrap())
        .build();
    let (c, g) = (&m.cs[i], &mut m.gs[i]);
    let signer = c.signer();
    let bundle = g
        .mls
        .commit_builder()
        .force_self_update(true)
        .leaf_node_parameters(params)
        .load_psks(c.provider.storage())
        .unwrap()
        .build(c.provider.rand(), c.provider.crypto(), &signer, |_| true)
        .unwrap()
        .stage_commit(&c.provider)
        .unwrap();
    wire(bundle.commit()).unwrap()
}

#[test]
fn an_update_may_not_change_its_instance_certificate() {
    let clock = Arc::new(FakeClock::default());
    let x = identity("upd-x");
    let mut m = Members::new(client("upd-a", &clock), None);
    m.join(0, client("upd-b", &clock));
    m.join(0, instance_of(&x, "upd-x1", &clock));
    m.join(0, instance_of(&x, "upd-x2", &clock));
    let (epoch, sas) = (m.gs[0].epoch(), m.gs[0].state_fingerprint());

    // X2 re-certifies its own key under X1's instance id (anyone holding
    // X's IK can sign that) and commits it as a self-update.
    let mut twin = m.cs[3].instance().cert().clone();
    twin.instance_id = m.cs[2].instance().instance_id();
    twin.sig = x.sign(&twin.signing_input().unwrap());
    // A newer cert for the same instance id changes nothing that matters,
    // and is refused all the same: a leaf's cert is fixed for its life.
    let mut renewed = m.cs[3].instance().cert().clone();
    renewed.created_at += 1;
    renewed.sig = x.sign(&renewed.signing_input().unwrap());
    for cert in [&twin, &renewed] {
        let bytes = self_update_with_cert(&mut m, 3, cert);
        // The committer's own check refuses it before it is sent...
        let staged = m.gs[3].mls.pending_commit().unwrap();
        assert_eq!(
            m.gs[3]
                .inspect_commit(&m.cs[3], staged, m.gs[3].mls.own_leaf_index())
                .map(|_| ()),
            Err(Error::Unauthorized(FIXED_CERT))
        );
        // ...and every honest member rejects it, at its epoch with its SAS.
        for i in 0..3 {
            assert_eq!(
                m.gs[i].process(&m.cs[i], &bytes).map(|e| e.kind()),
                Err(Error::Unauthorized(FIXED_CERT)),
                "member {i}"
            );
            assert_eq!(
                (m.gs[i].epoch(), m.gs[i].state_fingerprint()),
                (epoch, sas.clone()),
                "member {i}"
            );
        }
        m.gs[3].discard_pending_commit(&m.cs[3]).unwrap();
    }

    // A committer that merges it anyway is alone on its fork.
    let _ = self_update_with_cert(&mut m, 3, &twin);
    m.gs[3].mls.merge_pending_commit(&m.cs[3].provider).unwrap();
    assert_ne!(m.gs[3].state_fingerprint(), m.gs[0].state_fingerprint());
    let same = m.gs[3]
        .members()
        .unwrap()
        .iter()
        .filter(|mm| mm.instance_id == twin.instance_id)
        .count();
    assert_eq!(same, 2);
    m.forked.insert(3);

    // Honest updates (the cadence update included) keep the cert and pass.
    for i in 0..3 {
        let out = m.gs[i].update(&m.cs[i]).unwrap();
        m.apply(i, &out);
    }
    m.converged();
    assert_eq!(m.gs[0].epoch(), epoch + 3);
}

#[test]
fn a_welcome_whose_tree_repeats_an_instance_id_is_refused() {
    let clock = Arc::new(FakeClock::default());
    let x = identity("wtwin-x");
    let mut m = Members::new(client("wtwin-a", &clock), None);
    m.join(0, instance_of(&x, "wtwin-x1", &clock));
    let twin = twin_of(&x, &m.cs[1], "wtwin-x2", &clock);
    // A modified inviter adds the twin without its checks: its view is a fork.
    let out = m.gs[0]
        .commit_unchecked(&m.cs[0], &[key_package(&twin)], &[], None, None)
        .unwrap();
    m.forked.insert(0);
    assert_eq!(
        m.gs[1].process(&m.cs[1], &out.commit),
        Err(Error::Unauthorized(REPEATED_INSTANCE))
    );
    // It then invites a joiner into that view; the joiner refuses it.
    let joiner = client("wtwin-c", &clock);
    let inv = Invite::create(
        m.cs[0].rng(),
        m.cs[0].clock(),
        "r.example",
        Duration::from_secs(60),
    )
    .unwrap();
    let req = joiner.create_join_request(inv.secret(), "j").unwrap();
    let v = m.cs[0]
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    let (c, g) = (&m.cs[0], &mut m.gs[0]);
    let signer = c.signer();
    let bundle = g
        .mls
        .commit_builder()
        .propose_adds([v.key_package.clone()])
        .load_psks(c.provider.storage())
        .unwrap()
        .build(c.provider.rand(), c.provider.crypto(), &signer, |_| true)
        .unwrap()
        .stage_commit(&c.provider)
        .unwrap();
    let welcome = wire(&bundle.to_welcome_msg().unwrap()).unwrap();
    let wrapped = WelcomeWrap::Invite(&inv).wrap(c.rng(), &welcome).unwrap();
    let meta = InviteMeta::expected(inv.secret().id(), "g", "p");
    assert_eq!(
        joiner
            .join_from_wrapped_welcome(inv.secret(), &meta, &wrapped)
            .map(|_| ()),
        Err(Error::InvalidGroupContext(REPEATED_INSTANCE))
    );
}

/// The relay caps what it stores by envelope kind (SPEC 8.3, relay
/// `proto.rs`): a Welcome's `ct` at 256 KiB, a `join_request`'s at 16 KiB,
/// and a commit that may use the storage reserve (it adds nobody) at
/// 128 KiB. This builds the largest of each a full group makes: the
/// Welcome for the 50th member once every member has committed an update
/// path (the full ratchet tree), Updates in a sparse tree (a path secret
/// for every other member) and removals. Slow: `just nightly-relay-load`.
#[test]
#[ignore = "slow: just nightly-relay-load"]
fn wire_sizes_fit_the_relay_caps() {
    const WELCOME_CAP: usize = 256 * 1024;
    const JOIN_CAP: usize = 16 * 1024;
    const RESERVE_COMMIT_CAP: usize = 128 * 1024;
    let clock = Arc::new(FakeClock::default());
    let labels: Vec<String> = (0..49).map(|i| format!("w{i}")).collect();
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let mut m = Members::of(&refs, &clock);
    let mut commits = 0;
    for i in [1, 24, 48] {
        let out = m.gs[i].update(&m.cs[i]).unwrap();
        commits = commits.max(out.commit.len());
        m.apply(i, &out);
    }
    for i in 0..m.gs.len() {
        let out = m.gs[i].update(&m.cs[i]).unwrap();
        commits = commits.max(out.commit.len());
        m.apply(i, &out);
    }
    let joiner = client("w-last", &clock);
    let inv = Invite::create(
        m.cs[0].rng(),
        m.cs[0].clock(),
        "r.example",
        Duration::from_secs(60),
    )
    .unwrap();
    let req = joiner
        .create_join_request(inv.secret(), &"n".repeat(80))
        .unwrap();
    let join = req.to_json().unwrap().len();
    let v = m.cs[0]
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    let out = m.gs[0].add_member(&m.cs[0], &v, &inv, true).unwrap();
    let welcome = out.welcome.as_ref().unwrap().len();
    m.gs[0].discard_pending_commit(&m.cs[0]).unwrap();
    for k in (2..40).step_by(4) {
        let id = m.id(k);
        let out = m.gs[0].remove(&m.cs[0], &id).unwrap();
        commits = commits.max(out.commit.len());
        m.apply(0, &out);
    }
    println!(
        "wire sizes: Welcome {welcome} B, join_request {join} B, largest commit without adds {commits} B"
    );
    assert!(welcome <= WELCOME_CAP, "Welcome {welcome} B");
    assert!(join <= JOIN_CAP, "join_request {join} B");
    assert!(commits <= RESERVE_COMMIT_CAP, "commit {commits} B");
}
