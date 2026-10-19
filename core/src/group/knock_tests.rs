//! Approving a knock and joining from its Welcome (SPEC §6.6.4, §6.6.5):
//! the owner's `add_knocker` and the knocker's checks, including Welcomes
//! built with raw OpenMLS calls that a broken owner, or anyone holding a
//! leaked knock secret, could send.
#![allow(clippy::many_single_char_names)]

use openmls::prelude::{Extension, PreSharedKeyProposal, Proposal, UnknownExtension};
use openmls::schedule::PreSharedKeyId;

use super::*;
use crate::clock::FakeClock;
use crate::identity::Identity;
use crate::invite::InviteSecret;
use crate::knock::{Door, Knock, KnockExpectation, VerifiedKnock};
use crate::provider::MemoryStore;
use crate::provider::sealed::Backend as _;

type C = Client<MemoryStore>;

const NAME: &str = "release-planner";
const PURPOSE: &str = "Plans release trains";

fn instance_of(identity: &Identity, label: &str, clock: &Arc<FakeClock>) -> C {
    let rng = Rng::for_test(&format!("knock-group-{label}"));
    let inst = identity.create_instance(&rng, clock.as_ref()).unwrap();
    Client::new(
        MemoryStore::new(),
        Rng::for_test(&format!("knock-group-{label}-client")),
        inst,
        clock.clone(),
    )
    .unwrap()
}

fn client(label: &str, clock: &Arc<FakeClock>) -> C {
    let id = Identity::generate(&Rng::for_test(&format!("knock-group-{label}-ik"))).unwrap();
    instance_of(&id, label, clock)
}

struct Setup {
    clock: Arc<FakeClock>,
    owner: C,
    knocker: C,
    door: Door,
    now: u64,
}

fn setup(label: &str) -> Setup {
    let clock = Arc::new(FakeClock::default());
    let owner = client(&format!("{label}-owner"), &clock);
    let knocker = client(&format!("{label}-knocker"), &clock);
    let now = clock.unix_millis() / 1000;
    let door = Door::generate(
        &Rng::for_test(&format!("knock-group-{label}-door")),
        now + 7 * 24 * 3600,
    )
    .unwrap();
    Setup {
        clock,
        owner,
        knocker,
        door,
        now,
    }
}

impl Setup {
    /// A knock by `from`, verified by the owner.
    fn knock_from(&self, from: &C) -> (Knock, VerifiedKnock) {
        let (sealed, k) = from
            .create_knock(self.door.id(), self.door.public_key(), "bob", None)
            .unwrap();
        let opened = self
            .door
            .open_knock(self.door.id(), &sealed, self.now)
            .unwrap();
        (k, self.owner.verify_knock(opened).unwrap())
    }

    fn knock(&self) -> (Knock, VerifiedKnock) {
        self.knock_from(&self.knocker)
    }

    fn expect(&self) -> KnockExpectation {
        KnockExpectation {
            identity: self.owner.instance().identity().to_owned(),
            name: NAME.to_owned(),
        }
    }

    fn fresh_group(&self) -> Group {
        self.owner.create_group(NAME, PURPOSE).unwrap()
    }

    /// The owner approves `v`: a fresh group, the Add confirmed.
    fn approve(&self, v: &VerifiedKnock) -> (Group, CommitOut) {
        let mut g = self.fresh_group();
        let out = g.add_knocker(&self.owner, v).unwrap();
        g.confirm_pending_commit(&self.owner, &out.msg_id).unwrap();
        (g, out)
    }
}

fn inner(c: &C, text: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "v": 0, "seq": 1,
        "sender": c.instance().identity(),
        "instance_id": c.instance().cert().instance_id_hex(),
        "to": ["*"], "hop": 0, "origin": "agent", "kind": "a2a.message",
        "body": {"text": text},
    }))
    .unwrap()
}

#[test]
fn an_approved_knock_becomes_a_two_member_group() {
    let s = setup("ok");
    let (k, v) = s.knock();
    let (mut ga, out) = s.approve(&v);
    assert_eq!(out.routing.add, vec![s.knocker.instance().mailbox_id()]);
    assert_eq!(out.routing.remove, Vec::<String>::new());
    let wrapped = out.welcome.clone().unwrap();
    let mut gb = s
        .knocker
        .join_from_knock_welcome(&k, &s.expect(), &wrapped)
        .unwrap();
    assert_eq!(gb.group_id(), ga.group_id());
    assert_eq!(gb.epoch(), 1);
    let policy = gb.policy().unwrap();
    assert_eq!(policy.owner, s.owner.instance().identity());
    assert_eq!(policy.floor, Floor::Free);
    let meta = gb.meta().unwrap();
    assert_eq!(meta.name, NAME);
    assert_eq!(meta.purpose, PURPOSE);
    assert_eq!(meta.created_by, s.owner.instance().identity());
    let ids: BTreeSet<String> = gb
        .members()
        .unwrap()
        .into_iter()
        .map(|m| m.identity)
        .collect();
    assert_eq!(ids.len(), 2);
    assert_eq!(ga.state_fingerprint(), gb.state_fingerprint());
    // Messages both ways.
    let ct = ga.seal(&s.owner, &inner(&s.owner, "hi")).unwrap();
    assert_eq!(
        gb.open(&s.knocker, &ct).unwrap().sender.identity,
        s.owner.instance().identity()
    );
    let ct = gb.seal(&s.knocker, &inner(&s.knocker, "hello")).unwrap();
    assert_eq!(
        ga.open(&s.owner, &ct).unwrap().sender.identity,
        s.knocker.instance().identity()
    );
    // The Welcome is wrapped under the knock key, not the invite's.
    let ks = k.secret();
    let as_invite = InviteSecret::from_parts(*ks.knock_id(), ks.secret_for_vectors());
    assert_eq!(as_invite.unwrap_welcome(&wrapped), Err(Error::WelcomeAuth));
    assert!(ks.unwrap_welcome(&wrapped).is_ok());
    // The join used up the KeyPackage; forgetting the knock is harmless.
    s.knocker.forget_knock(&k).unwrap();
}

/// A wrong secret: another knock's, or the right knock's id with another
/// secret. The Welcome doesn't open, and the KeyPackage is not spent.
#[test]
fn a_welcome_under_another_knock_does_not_open() {
    let s = setup("wrong-secret");
    let (k, v) = s.knock();
    let (k2, _) = s.knock();
    let (_, out) = s.approve(&v);
    let wrapped = out.welcome.unwrap();
    assert_eq!(
        s.knocker
            .join_from_knock_welcome(&k2, &s.expect(), &wrapped)
            .unwrap_err(),
        Error::WelcomeAuth
    );
    let mut tampered = wrapped.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        s.knocker
            .join_from_knock_welcome(&k, &s.expect(), &tampered)
            .unwrap_err(),
        Error::WelcomeAuth
    );
    // Neither attempt spent the KeyPackage.
    s.knocker
        .join_from_knock_welcome(&k, &s.expect(), &wrapped)
        .unwrap();
}

/// Review L7: the deadlines are the client's clock, not the caller's.
#[test]
fn add_knocker_refuses_a_lapsed_knock_and_changes_nothing() {
    let s = setup("lapsed");
    let (_, v) = s.knock();
    let mut g = s.fresh_group();
    let lapses = v.knock().lapses_at();
    s.clock
        .advance(std::time::Duration::from_secs(lapses - s.now + 1));
    let e = g.add_knocker(&s.owner, &v).unwrap_err();
    assert_eq!(e, Error::InvalidKnock("lapsed"));
    assert_eq!(e.kind(), crate::ErrorKind::Expired);
    assert!(!g.has_pending_commit());
    assert_eq!(g.epoch(), 0);
    // At the deadline itself it is still in time, in the same group.
    s.clock
        .set(std::time::UNIX_EPOCH + std::time::Duration::from_secs(lapses));
    let out = g.add_knocker(&s.owner, &v).unwrap();
    assert!(out.welcome.is_some());
}

/// Review L7: a knock stamped further ahead of the owner's clock than check
/// 3 allows (opened against a caller's clock that ran ahead) isn't Added.
#[test]
fn add_knocker_refuses_a_knock_from_the_future() {
    let s = setup("future");
    let ahead = s.now + 1000;
    let (sealed, _) = s
        .knocker
        .create_knock_at(s.door.id(), s.door.public_key(), "bob", None, ahead)
        .unwrap();
    let v = s
        .owner
        .verify_knock(s.door.open_knock(s.door.id(), &sealed, ahead).unwrap())
        .unwrap();
    let mut g = s.fresh_group();
    let e = g.add_knocker(&s.owner, &v).unwrap_err();
    assert_eq!(e, Error::InvalidKnock("ts out of range"));
    assert_eq!(e.kind(), crate::ErrorKind::StaleTimestamp);
    assert!(!g.has_pending_commit());
    s.clock.advance(std::time::Duration::from_secs(700));
    g.add_knocker(&s.owner, &v).unwrap();
}

/// Review L7: the knocker joins only until `gives_up_at` on its own clock;
/// a later Welcome is refused before the unwrap, so nothing is spent. A
/// journalled join recorded in time still replays after it.
#[test]
fn a_knock_welcome_after_gives_up_at_is_refused() {
    let s = setup("late");
    let (k, v) = s.knock();
    let (g, out) = s.approve(&v);
    let w = out.welcome.unwrap();
    let late = std::time::UNIX_EPOCH + std::time::Duration::from_secs(k.gives_up_at() + 1);
    let in_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(k.gives_up_at());
    s.clock.set(late);
    let e = s
        .knocker
        .join_from_knock_welcome(&k, &s.expect(), &w)
        .unwrap_err();
    assert_eq!(e, Error::InvalidKnock("lapsed"));
    assert_eq!(e.kind(), crate::ErrorKind::Expired);
    s.clock.set(in_time);
    s.knocker
        .join_knock_journaled(&k, &s.expect(), &w, "key", b"")
        .unwrap();
    s.clock.set(late);
    let j = s
        .knocker
        .join_knock_journaled(&k, &s.expect(), &w, "key", b"")
        .unwrap();
    assert!(j.replayed);
    assert_eq!(j.value.group_id(), g.group_id());
}

#[test]
fn add_knocker_refuses_a_used_key_package() {
    let s = setup("used");
    let (_, v) = s.knock();
    s.approve(&v);
    // The same verified knock approved again (a replay past the ledger).
    let mut g = s.fresh_group();
    assert_eq!(
        g.add_knocker(&s.owner, &v).unwrap_err(),
        Error::KeyPackageReused
    );
    assert!(!g.has_pending_commit());
    let (_, v2) = s.knock();
    s.owner
        .mark_key_package_used_for_testing(v2.key_package_ref())
        .unwrap();
    assert_eq!(
        g.add_knocker(&s.owner, &v2).unwrap_err(),
        Error::KeyPackageReused
    );
}

#[test]
fn add_knocker_needs_a_fresh_group_of_this_identity() {
    let s = setup("fresh");
    let (_, v) = s.knock();
    // Two members: the knocker of an earlier approval is in it.
    let (_, v0) = s.knock();
    let (mut two, _) = s.approve(&v0);
    assert_eq!(
        two.add_knocker(&s.owner, &v).unwrap_err(),
        Error::NotPermitted("not a fresh group")
    );
    // One member, but past epoch 0.
    let mut later = s.fresh_group();
    let up = later.update(&s.owner).unwrap();
    later.confirm_pending_commit(&s.owner, &up.msg_id).unwrap();
    assert_eq!(
        later.add_knocker(&s.owner, &v).unwrap_err(),
        Error::NotPermitted("not a fresh group")
    );
    // Not owned by this identity.
    let other = Identity::generate(&Rng::for_test("knock-group-fresh-other")).unwrap();
    let mut given = forged_group(&s.owner, &other.id());
    assert_eq!(
        given.add_knocker(&s.owner, &v).unwrap_err(),
        Error::NotPermitted("not a group this identity created and owns")
    );
    // A floor other than free.
    let mut moderated = s.fresh_group();
    let policy = GroupPolicy {
        floor: Floor::Mention,
        ..moderated.policy().unwrap()
    };
    let out = moderated.set_policy(&s.owner, &policy).unwrap();
    moderated
        .confirm_pending_commit(&s.owner, &out.msg_id)
        .unwrap();
    assert_eq!(
        moderated.add_knocker(&s.owner, &v).unwrap_err(),
        Error::NotPermitted("the floor is not free")
    );
    // The knock is still good for a fresh group.
    s.approve(&v);
}

#[test]
fn add_knocker_refuses_a_knock_from_its_own_identity() {
    let s = setup("own");
    let ik = Identity::generate(&Rng::for_test("knock-group-own-shared-ik")).unwrap();
    let owner = instance_of(&ik, "own-a", &s.clock);
    let replica = instance_of(&ik, "own-b", &s.clock);
    let (sealed, _) = replica
        .create_knock(s.door.id(), s.door.public_key(), "me", None)
        .unwrap();
    let v = owner
        .verify_knock(s.door.open_knock(s.door.id(), &sealed, s.now).unwrap())
        .unwrap();
    let mut g = owner.create_group(NAME, PURPOSE).unwrap();
    assert_eq!(
        g.add_knocker(&owner, &v).unwrap_err(),
        Error::NotPermitted("a knock from this identity")
    );
}

/// The knocker's own end: a listing that names its own identity.
#[test]
fn joining_refuses_a_listing_of_its_own_identity() {
    let s = setup("self");
    let (k, v) = s.knock();
    let (_, out) = s.approve(&v);
    let mine = KnockExpectation {
        identity: s.knocker.instance().identity().to_owned(),
        name: NAME.to_owned(),
    };
    assert_eq!(
        s.knocker
            .join_from_knock_welcome(&k, &mine, out.welcome.as_ref().unwrap())
            .unwrap_err(),
        Error::NotPermitted("a knock on this identity's own listing")
    );
    // Nothing was spent.
    s.knocker
        .join_from_knock_welcome(&k, &s.expect(), out.welcome.as_ref().unwrap())
        .unwrap();
}

/// Joins `wrapped` with `expect` and checks the failure: `err`, the
/// KeyPackage spent (a retry under the right expectation fails too), and
/// no group kept.
fn refused(
    s: &Setup,
    k: &Knock,
    expect: &KnockExpectation,
    wrapped: &[u8],
    gid: &[u8],
    err: &Error,
) {
    let e = s
        .knocker
        .join_from_knock_welcome(k, expect, wrapped)
        .unwrap_err();
    assert_eq!(&e, err);
    assert!(s.knocker.load_group(gid).unwrap().is_none());
    assert!(
        s.knocker
            .join_from_knock_welcome(k, &s.expect(), wrapped)
            .is_err(),
        "the KeyPackage is spent"
    );
    assert!(s.knocker.load_group(gid).unwrap().is_none());
}

#[test]
fn a_welcome_for_another_name_is_refused() {
    let s = setup("name");
    let (k, v) = s.knock();
    let (g, out) = s.approve(&v);
    let other = KnockExpectation {
        name: "other-name".into(),
        ..s.expect()
    };
    let e = Error::KnockWelcome("name");
    assert_eq!(e.kind(), crate::ErrorKind::WelcomeMismatch);
    refused(
        &s,
        &k,
        &other,
        out.welcome.as_ref().unwrap(),
        g.group_id(),
        &e,
    );
}

#[test]
fn a_welcome_from_another_identity_than_the_listing_is_refused() {
    let s = setup("owner");
    let (k, v) = s.knock();
    let (g, out) = s.approve(&v);
    let stranger = Identity::generate(&Rng::for_test("knock-group-owner-stranger")).unwrap();
    let expect = KnockExpectation {
        identity: stranger.id(),
        ..s.expect()
    };
    refused(
        &s,
        &k,
        &expect,
        out.welcome.as_ref().unwrap(),
        g.group_id(),
        &Error::KnockWelcome("created_by"),
    );
}

/// The raw Welcome of an Add of `k`'s KeyPackage built by `$build`, wrapped
/// under the knock's key.
macro_rules! knock_welcome {
    ($s:expr, $g:expr, $c:expr, $v:expr, |$b:ident| $build:expr) => {
        knock_welcome!($s, $g, $c, $v, |$b| $build, |l| l)
    };
    ($s:expr, $g:expr, $c:expr, $v:expr, |$b:ident| $build:expr, |$l:ident| $loaded:expr) => {{
        let signer = $c.signer();
        let $b = $g
            .mls
            .commit_builder()
            .propose_adds([$v.key_package().clone()]);
        let $l = $build.load_psks($c.provider.storage()).unwrap();
        let bundle = $loaded
            .build($c.provider.rand(), $c.provider.crypto(), &signer, |_| true)
            .unwrap()
            .stage_commit(&$c.provider)
            .unwrap();
        let welcome = wire(&bundle.to_welcome_msg().unwrap()).unwrap();
        $g.mls.clear_pending_commit($c.provider.storage()).unwrap();
        $v.secret().wrap_welcome($c.rng(), &welcome).unwrap()
    }};
}

/// `ac_group_meta.created_by` is the listing's identity but the policy's
/// owner isn't (a broken owner moved ownership in the Add's commit).
#[test]
fn a_welcome_whose_owner_is_not_the_listing_identity_is_refused() {
    let s = setup("policy-owner");
    let (k, v) = s.knock();
    let mut g = s.fresh_group();
    let ctx = check_group_context(g.mls.extensions()).unwrap();
    let absent = Identity::generate(&Rng::for_test("knock-group-absent")).unwrap();
    let policy = GroupPolicy {
        owner: absent.id(),
        ..ctx.policy
    };
    let exts = group_context_extensions(&ctx.meta_bytes, &policy.to_json().unwrap()).unwrap();
    let wrapped = knock_welcome!(s, g, s.owner, v, |b| b
        .propose_group_context_extensions(exts)
        .unwrap());
    refused(
        &s,
        &k,
        &s.expect(),
        &wrapped,
        g.group_id(),
        &Error::KnockWelcome("owner"),
    );
}

#[test]
fn a_welcome_with_three_leaves_is_refused() {
    let s = setup("three");
    let (k, v) = s.knock();
    let third = client("three-third", &s.clock);
    let (_, v3) = s.knock_from(&third);
    let mut g = s.fresh_group();
    let out = g.add_knocker_unchecked(&s.owner, &v, &[&v3]).unwrap();
    assert_eq!(out.routing.add.len(), 2);
    refused(
        &s,
        &k,
        &s.expect(),
        out.welcome.as_ref().unwrap(),
        g.group_id(),
        &Error::KnockWelcome("not exactly two members"),
    );
}

/// A group `c` builds that names `created_by` and `owner` in its context,
/// which `create_group` would never write: what a holder of a leaked knock
/// secret could forge.
fn forged_group(c: &C, created_by: &str) -> Group {
    forged_group_with(c, created_by, &GroupPolicy::default_for(created_by))
}

/// [`forged_group`] with `policy` in its context.
fn forged_group_with(c: &C, created_by: &str, policy: &GroupPolicy) -> Group {
    let meta = GroupMeta {
        v: 0,
        name: NAME.to_owned(),
        purpose: PURPOSE.to_owned(),
        created_at: c.now(),
        created_by: created_by.to_owned(),
    };
    let exts =
        group_context_extensions(&meta.to_json().unwrap(), &policy.to_json().unwrap()).unwrap();
    let id: [u8; 16] = c.rng().array().unwrap();
    let mls = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(&id))
        .ciphersuite(CS)
        .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .with_capabilities(capabilities())
        .with_leaf_node_extensions(leaf_extensions(c.instance.cert()).unwrap())
        .unwrap()
        .with_group_context_extensions(exts)
        .build(&c.provider, &c.signer(), c.credential())
        .unwrap();
    Group { mls }
}

/// The knock secret leaked to Mallory, who forges a group that claims the
/// listing's identity as creator and owner. Its other leaf is Mallory's.
#[test]
fn a_welcome_whose_other_leaf_is_not_the_listing_identity_is_refused() {
    let s = setup("leaked");
    let (k, v) = s.knock();
    let mallory = client("leaked-mallory", &s.clock);
    let mut g = forged_group(&mallory, s.owner.instance().identity());
    let wrapped = knock_welcome!(s, g, mallory, v, |b| b);
    refused(
        &s,
        &k,
        &s.expect(),
        &wrapped,
        g.group_id(),
        &Error::KnockWelcome("the other member is not the listed identity"),
    );
}

/// The §6.3 checks run for knock Welcomes as for invite Welcomes.
#[test]
fn a_knock_welcome_with_a_group_info_extension_or_a_psk_is_refused() {
    let s = setup("exts");
    let (k, v) = s.knock();
    let mut g = s.fresh_group();
    let wrapped = knock_welcome!(s, g, s.owner, v, |b| b, |l| l
        .create_group_info_with_extensions([Extension::Unknown(
            0xF0B0,
            UnknownExtension(Vec::new()),
        )])
        .unwrap());
    refused(
        &s,
        &k,
        &s.expect(),
        &wrapped,
        g.group_id(),
        &Error::InvalidGroupContext("unexpected GroupInfo extension"),
    );

    // A PSK the knocker doesn't hold: OpenMLS can't process the Welcome.
    // One it holds (an external PSK both ends somehow share): the check
    // refuses it anyway.
    for shared in [false, true] {
        let (k, v) = s.knock();
        let mut g = s.fresh_group();
        let rng = Rng::for_test(&format!("knock-group-psk-{shared}"));
        let psk_id = PreSharedKeyId::external(
            rng.array::<16>().unwrap().to_vec(),
            rng.array::<32>().unwrap().to_vec(),
        );
        let psk: [u8; 32] = rng.array().unwrap();
        psk_id.store(&s.owner.provider, &psk).unwrap();
        if shared {
            psk_id.store(&s.knocker.provider, &psk).unwrap();
        }
        let wrapped = knock_welcome!(s, g, s.owner, v, |b| b.add_proposal(
            Proposal::PreSharedKey(Box::new(PreSharedKeyProposal::new(psk_id)))
        ));
        if shared {
            refused(
                &s,
                &k,
                &s.expect(),
                &wrapped,
                g.group_id(),
                &Error::InvalidGroupContext("PSKs are not used in v0"),
            );
        } else {
            let e = s
                .knocker
                .join_from_knock_welcome(&k, &s.expect(), &wrapped)
                .unwrap_err();
            assert!(matches!(e, Error::Mls(_)), "{e}");
            assert!(s.knocker.load_group(g.group_id()).unwrap().is_none());
        }
    }
}

#[test]
fn a_journalled_knock_join_replays_until_consumed() {
    let s = setup("journal");
    let (k, v) = s.knock();
    let (g, out) = s.approve(&v);
    let wrapped = out.welcome.unwrap();
    let j = s
        .knocker
        .join_knock_journaled(&k, &s.expect(), &wrapped, "mbox/msg-1", b"ctx")
        .unwrap();
    assert!(!j.replayed);
    assert_eq!(j.value.group_id(), g.group_id());
    let pending = s.knocker.journal_pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].welcome);
    assert_eq!(pending[0].context, b"ctx");
    // A crash before the caller recorded it: the same Welcome again.
    let again = s
        .knocker
        .join_knock_journaled(&k, &s.expect(), &wrapped, "mbox/msg-1", b"ctx")
        .unwrap();
    assert!(again.replayed);
    assert_eq!(again.value.group_id(), g.group_id());
    assert!(s.knocker.journal_consume(None, "mbox/msg-1").unwrap());
    assert_eq!(
        s.knocker
            .join_knock_journaled(&k, &s.expect(), &wrapped, "mbox/msg-1", b"ctx")
            .unwrap_err(),
        Error::Duplicate
    );
}

/// The knock group's short code is the same on both ends, and a relay that
/// confirms both of two concurrent commits forks the view: the codes differ.
#[test]
fn a_forked_knock_group_shows_a_different_short_code() {
    let s = setup("fork");
    let (k, v) = s.knock();
    let (mut ga, out) = s.approve(&v);
    let mut gb = s
        .knocker
        .join_from_knock_welcome(&k, &s.expect(), out.welcome.as_ref().unwrap())
        .unwrap();
    assert_eq!(ga.state_fingerprint(), gb.state_fingerprint());
    let a = ga.update(&s.owner).unwrap();
    let b = gb.update(&s.knocker).unwrap();
    ga.confirm_pending_commit(&s.owner, &a.msg_id).unwrap();
    gb.confirm_pending_commit(&s.knocker, &b.msg_id).unwrap();
    assert_eq!(ga.epoch(), gb.epoch());
    assert_ne!(ga.state_fingerprint(), gb.state_fingerprint());
    assert_ne!(ga.state_fingerprint(), gb.state_fingerprint());
}

// ---- Review regressions (L1-L3) ----

/// Review L1: a journal entry replays only for the knock, the listing and
/// the kind of join it was recorded for.
#[test]
fn a_journalled_knock_join_replays_only_for_its_own_knock_and_listing() {
    let s = setup("journal-bound");
    let (k, v) = s.knock();
    let (k2, _) = s.knock();
    let (g, out) = s.approve(&v);
    let w = out.welcome.unwrap();
    s.knocker
        .join_knock_journaled(&k, &s.expect(), &w, "key", b"")
        .unwrap();
    let stranger = Identity::generate(&Rng::for_test("knock-group-journal-bound-x")).unwrap();
    let other = KnockExpectation {
        identity: stranger.id(),
        name: "other-name".into(),
    };
    let mine = KnockExpectation {
        identity: s.knocker.instance().identity().to_owned(),
        name: NAME.into(),
    };
    // Another knock, another listing, the knocker's own identity: none of
    // them replays the entry.
    for (knock, expect) in [
        (&k2, &s.expect()),
        (&k, &other),
        (&k2, &other),
        (&k2, &mine),
    ] {
        assert_eq!(
            s.knocker
                .join_knock_journaled(knock, expect, &w, "key", b"")
                .unwrap_err(),
            Error::JournalConflict
        );
    }
    // An invite join under the same key doesn't replay it either.
    let ks = k.secret();
    let invite = InviteSecret::from_parts(*ks.knock_id(), ks.secret_for_vectors());
    let meta = InviteMeta::expected(invite.id(), NAME, PURPOSE);
    assert_eq!(
        s.knocker
            .join_journaled(&invite, &meta, &w, "key", b"")
            .unwrap_err(),
        Error::JournalConflict
    );
    // The right knock and listing still replay.
    let j = s
        .knocker
        .join_knock_journaled(&k, &s.expect(), &w, "key", b"")
        .unwrap();
    assert!(j.replayed);
    assert_eq!(j.value.group_id(), g.group_id());
}

/// Review L1: a knock join under a key an invite join used is a conflict.
#[test]
fn an_invite_journal_entry_does_not_replay_as_a_knock_join() {
    let s = setup("journal-invite");
    let (k, _) = s.knock();
    let mut ga = s.owner.create_group("g", "p").unwrap();
    let inv = Invite::create(
        s.owner.rng(),
        s.owner.clock(),
        "relay.example.org",
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let req = s.knocker.create_join_request(inv.secret(), "j").unwrap();
    let vr = s.owner.verify_join_request(&req, &inv).unwrap();
    let out = ga.add_member(&s.owner, &vr, &inv, true).unwrap();
    ga.confirm_pending_commit(&s.owner, &out.msg_id).unwrap();
    let w = out.welcome.unwrap();
    let meta = InviteMeta::expected(inv.secret().id(), "g", "p");
    s.knocker
        .join_journaled(inv.secret(), &meta, &w, "key", b"")
        .unwrap();
    assert_eq!(
        s.knocker
            .join_knock_journaled(&k, &s.expect(), &w, "key", b"")
            .unwrap_err(),
        Error::JournalConflict
    );
}

/// Review L1: a replayed knock join is checked against the listing again,
/// so a journal entry that names another group (a damaged store) is not
/// taken for the knock's.
#[test]
fn a_replayed_knock_join_is_checked_against_the_listing() {
    let s = setup("journal-recheck");
    let (k, v) = s.knock();
    let (_, out) = s.approve(&v);
    let w = out.welcome.unwrap();
    s.knocker
        .join_knock_journaled(&k, &s.expect(), &w, "key", b"")
        .unwrap();
    let elsewhere = s.knocker.create_group("other-name", "p").unwrap();
    let mut row = s
        .knocker
        .store()
        .journal_get(WELCOME_SCOPE, "key")
        .unwrap()
        .unwrap();
    row.group_id = elsewhere.group_id().to_vec();
    s.knocker.store().journal_put(&row).unwrap();
    assert_eq!(
        s.knocker
            .join_knock_journaled(&k, &s.expect(), &w, "key", b"")
            .unwrap_err(),
        Error::KnockWelcome("name")
    );
}

/// Review L2: while one group's Add of a knock is pending, no other group
/// can Add the same KeyPackage.
#[test]
fn one_knock_is_not_added_into_two_pending_groups() {
    let s = setup("double");
    let (k, v) = s.knock();
    let mut g1 = s.fresh_group();
    let o1 = g1.add_knocker(&s.owner, &v).unwrap();
    let mut g2 = s.fresh_group();
    assert_eq!(
        g2.add_knocker(&s.owner, &v).unwrap_err(),
        Error::KeyPackageReused
    );
    assert!(!g2.has_pending_commit());
    // Discarding the first Add releases the KeyPackage.
    g1.discard_pending_commit(&s.owner).unwrap();
    let o2 = g2.add_knocker(&s.owner, &v).unwrap();
    assert_eq!(
        g1.add_knocker(&s.owner, &v).unwrap_err(),
        Error::KeyPackageReused
    );
    g2.confirm_pending_commit(&s.owner, &o2.msg_id).unwrap();
    // Merged, it is used for good.
    let mut g3 = s.fresh_group();
    assert_eq!(
        g3.add_knocker(&s.owner, &v).unwrap_err(),
        Error::KeyPackageReused
    );
    s.knocker
        .join_from_knock_welcome(&k, &s.expect(), o2.welcome.as_ref().unwrap())
        .unwrap();
    assert!(o1.welcome.is_some());
}

/// Review L2: the same for a verified JoinRequest and `add_member`.
#[test]
fn one_join_request_is_not_added_into_two_pending_groups() {
    let s = setup("double-invite");
    let inv = Invite::create(
        s.owner.rng(),
        s.owner.clock(),
        "relay.example.org",
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let req = s.knocker.create_join_request(inv.secret(), "j").unwrap();
    let vr = s.owner.verify_join_request(&req, &inv).unwrap();
    let mut g1 = s.owner.create_group("g", "p").unwrap();
    let mut g2 = s.owner.create_group("g", "p").unwrap();
    g1.add_member(&s.owner, &vr, &inv, true).unwrap();
    assert_eq!(
        g2.add_member(&s.owner, &vr, &inv, true).unwrap_err(),
        Error::KeyPackageReused
    );
    g1.discard_pending_commit(&s.owner).unwrap();
    g2.add_member(&s.owner, &vr, &inv, true).unwrap();
}

/// Review L2: a pending Add that loses its epoch to another member's
/// commit releases its KeyPackage too.
#[test]
fn a_pending_add_that_loses_its_epoch_releases_the_key_package() {
    let s = setup("lost");
    let (k0, v0) = s.knock();
    let (mut ga, out) = s.approve(&v0);
    let mut gb = s
        .knocker
        .join_from_knock_welcome(&k0, &s.expect(), out.welcome.as_ref().unwrap())
        .unwrap();
    let third = client("lost-third", &s.clock);
    let inv = Invite::create(
        s.owner.rng(),
        s.owner.clock(),
        "relay.example.org",
        std::time::Duration::from_secs(60),
    )
    .unwrap();
    let req = third.create_join_request(inv.secret(), "t").unwrap();
    let vr = s.owner.verify_join_request(&req, &inv).unwrap();
    ga.add_member(&s.owner, &vr, &inv, false).unwrap();
    // The knocker's update wins the epoch at the relay.
    let up = gb.update(&s.knocker).unwrap();
    gb.confirm_pending_commit(&s.knocker, &up.msg_id).unwrap();
    match ga.process(&s.owner, &up.commit).unwrap() {
        Event::Commit(c) => assert!(c.discarded_own_pending),
        e => panic!("expected a commit, got {}", e.kind()),
    }
    let mut other = s.owner.create_group("g", "p").unwrap();
    other.add_member(&s.owner, &vr, &inv, true).unwrap();
}

/// Review L3: the knocker refuses a group that has a history: more than
/// the one Add commit, or a member removed before it joined.
#[test]
fn a_knock_welcome_into_a_group_with_history_is_refused() {
    let s = setup("history");
    let (k, v) = s.knock();
    let mut g = s.fresh_group();
    for _ in 0..3 {
        let up = g.update(&s.owner).unwrap();
        g.confirm_pending_commit(&s.owner, &up.msg_id).unwrap();
    }
    let wrapped = knock_welcome!(s, g, s.owner, v, |b| b);
    refused(
        &s,
        &k,
        &s.expect(),
        &wrapped,
        g.group_id(),
        &Error::KnockWelcome("not a fresh group"),
    );

    let (k, v) = s.knock();
    let third = client("history-third", &s.clock);
    let (k3, v3) = s.knock_from(&third);
    let mut g = s.fresh_group();
    let o3 = g.add_knocker(&s.owner, &v3).unwrap();
    g.confirm_pending_commit(&s.owner, &o3.msg_id).unwrap();
    third
        .join_from_knock_welcome(&k3, &s.expect(), o3.welcome.as_ref().unwrap())
        .unwrap();
    let rm = g.remove(&s.owner, third.instance().identity()).unwrap();
    g.confirm_pending_commit(&s.owner, &rm.msg_id).unwrap();
    let wrapped = knock_welcome!(s, g, s.owner, v, |b| b);
    refused(
        &s,
        &k,
        &s.expect(),
        &wrapped,
        g.group_id(),
        &Error::KnockWelcome("not a fresh group"),
    );
}

/// Review L3: the knocker refuses a floor other than `free` and roles for
/// anyone but the owner, which `add_knocker` never builds.
#[test]
fn a_knock_welcome_with_a_floor_or_roles_add_knocker_never_builds_is_refused() {
    let s = setup("roles");
    let absent = Identity::generate(&Rng::for_test("knock-group-roles-absent")).unwrap();
    let owner = s.owner.instance().identity().to_owned();
    let base = GroupPolicy::default_for(&owner);
    for (policy, err) in [
        (
            GroupPolicy {
                floor: Floor::Mention,
                ..base.clone()
            },
            "the floor is not free",
        ),
        (
            GroupPolicy {
                floor_pinned: true,
                ..base.clone()
            },
            "the floor is pinned",
        ),
        (
            GroupPolicy {
                admins: vec![absent.id()],
                ..base.clone()
            },
            "roles for another identity",
        ),
        (
            GroupPolicy {
                floor_moderator: Some(absent.id()),
                ..base.clone()
            },
            "roles for another identity",
        ),
    ] {
        let (k, v) = s.knock();
        let mut g = s.fresh_group();
        let ctx = check_group_context(g.mls.extensions()).unwrap();
        let exts = group_context_extensions(&ctx.meta_bytes, &policy.to_json().unwrap()).unwrap();
        let wrapped = knock_welcome!(s, g, s.owner, v, |b| b
            .propose_group_context_extensions(exts)
            .unwrap());
        refused(
            &s,
            &k,
            &s.expect(),
            &wrapped,
            g.group_id(),
            &Error::KnockWelcome(err),
        );
        // add_knocker refuses to build either, in a group created so.
        let (_, v) = s.knock();
        let mut forged = forged_group_with(&s.owner, &owner, &policy);
        assert_eq!(
            forged.add_knocker(&s.owner, &v).unwrap_err(),
            Error::NotPermitted(err)
        );
    }
    // The owner as its own admin or moderator is the same group.
    let (k, v) = s.knock();
    let policy = GroupPolicy {
        admins: vec![owner.clone()],
        floor_moderator: Some(owner.clone()),
        ..base
    };
    let mut g = forged_group_with(&s.owner, &owner, &policy);
    let out = g.add_knocker(&s.owner, &v).unwrap();
    g.confirm_pending_commit(&s.owner, &out.msg_id).unwrap();
    s.knocker
        .join_from_knock_welcome(&k, &s.expect(), out.welcome.as_ref().unwrap())
        .unwrap();
}
