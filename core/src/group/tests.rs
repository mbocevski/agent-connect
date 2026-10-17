//! Receiver-side enforcement: commits and proposals built with raw OpenMLS
//! calls, bypassing this crate's local checks, must be rejected by every
//! other member before they are merged (SPEC §3.1, §3.3, §9.2).

use std::time::Duration;

use openmls::prelude::{Extension, Extensions, LeafNodeParameters, UnknownExtension};

use super::*;
use crate::clock::FakeClock;
use crate::identity::Identity;
use crate::mls::{EXT_GROUP_META, EXT_GROUP_POLICY, required_capabilities};
use crate::policy::RemovePermission;
use crate::provider::MemoryStore;

type C = Client<MemoryStore>;

fn client(seed: u64, clock: &Arc<FakeClock>) -> C {
    let rng = Rng::for_test(&format!("seed-{seed}"));
    let id = Identity::generate(&rng).unwrap();
    let inst = id.create_instance(&rng, clock.as_ref()).unwrap();
    Client::new(
        MemoryStore::new(),
        Rng::for_test(&format!("seed-{}", seed + 7)),
        inst,
        clock.clone(),
    )
    .unwrap()
}

fn join(inviter: &C, group: &mut Group, joiner: &C) -> (Group, CommitOut) {
    let inv = Invite::create(
        inviter.rng(),
        inviter.clock(),
        "r.example",
        Duration::from_secs(60),
    )
    .unwrap();
    let req = joiner.create_join_request(inv.secret(), "j").unwrap();
    let v = inviter.verify_join_request(&req, &inv).unwrap();
    let out = group.add_member(inviter, v, &inv, true).unwrap();
    group.confirm_pending_commit(inviter).unwrap();
    let meta = InviteMeta::expected(inv.secret().id(), "g", "p");
    let g = joiner
        .join_from_wrapped_welcome(inv.secret(), &meta, out.welcome.as_ref().unwrap())
        .unwrap();
    (g, out)
}

/// A (owner), B and C, all at the same epoch.
fn trio() -> (Vec<C>, Vec<Group>) {
    let clock = Arc::new(FakeClock::default());
    let cs: Vec<C> = (1..=3).map(|i| client(i * 10, &clock)).collect();
    let mut ga = cs[0].create_group("g", "p").unwrap();
    let (gb, _) = join(&cs[0], &mut ga, &cs[1]);
    let mut gs = vec![ga, gb];
    let (gc, out) = join(&cs[0], &mut gs[0], &cs[2]);
    assert!(matches!(
        gs[1].process(&cs[1], &out.commit),
        Ok(Event::Commit(_))
    ));
    gs.push(gc);
    (cs, gs)
}

/// Builds a commit with raw OpenMLS calls, skipping `finish_commit`'s
/// checks, and leaves the sender's state untouched.
macro_rules! raw_commit {
    ($g:expr, $c:expr, |$b:ident| $build:expr) => {{
        let signer = $c.signer();
        let $b = $g.mls.commit_builder();
        let bundle = $build
            .load_psks($c.provider.storage())
            .unwrap()
            .build($c.provider.rand(), $c.provider.crypto(), &signer, |_| true)
            .unwrap()
            .stage_commit(&$c.provider)
            .unwrap();
        let bytes = wire(bundle.commit()).unwrap();
        $g.mls.clear_pending_commit($c.provider.storage()).unwrap();
        bytes
    }};
}

/// Every honest receiver rejects `bytes` with `err` and stays at its epoch.
fn all_reject(cs: &[C], gs: &mut [Group], from: usize, bytes: &[u8], err: &Error) {
    for (i, g) in gs.iter_mut().enumerate() {
        if i == from {
            continue;
        }
        let epoch = g.epoch();
        assert_eq!(g.process(&cs[i], bytes).as_ref(), Err(err), "member {i}");
        assert_eq!(g.epoch(), epoch);
    }
}

fn gce(meta: &[u8], policy: &GroupPolicy) -> Extensions<GroupContext> {
    group_context_extensions(meta, &policy.to_json().unwrap()).unwrap()
}

use openmls::prelude::GroupContext;

#[test]
fn member_removing_another_member_is_rejected() {
    let (cs, mut gs) = trio();
    let bytes = raw_commit!(gs[1], cs[1], |b| b
        .propose_removals([LeafNodeIndex::new(2)]));
    all_reject(
        &cs,
        &mut gs,
        1,
        &bytes,
        &Error::Unauthorized("committer may not remove members"),
    );
}

#[test]
fn admin_removing_the_owner_is_rejected() {
    let (cs, mut gs) = trio();
    let mut p = gs[0].policy().unwrap();
    p.remove = RemovePermission::Admins;
    p.admins = vec![cs[1].instance().identity().to_owned()];
    let out = gs[0].set_policy(&cs[0], &p).unwrap();
    gs[0].confirm_pending_commit(&cs[0]).unwrap();
    for i in [1, 2] {
        gs[i].process(&cs[i], &out.commit).unwrap();
    }
    // The admin may remove C...
    let ok = raw_commit!(gs[1], cs[1], |b| b
        .propose_removals([LeafNodeIndex::new(2)]));
    let mut a = gs.remove(0);
    assert!(matches!(a.process(&cs[0], &ok), Ok(Event::Commit(_))));
    gs.insert(0, a);
    // ...but not the owner.
    let (cs, mut gs) = (cs, gs);
    let bytes = raw_commit!(gs[1], cs[1], |b| b
        .propose_removals([LeafNodeIndex::new(0)]));
    assert_eq!(
        gs[2].process(&cs[2], &bytes),
        Err(Error::Unauthorized("only the owner may remove the owner"))
    );
}

#[test]
fn member_adding_without_invite_permission_is_rejected() {
    let (cs, mut gs) = trio();
    let clock = Arc::new(FakeClock::default());
    let d = client(99, &clock);
    let inv = Invite::create(d.rng(), d.clock(), "r.example", Duration::from_secs(60)).unwrap();
    let req = d.create_join_request(inv.secret(), "d").unwrap();
    let v = cs[1].verify_join_request(&req, &inv).unwrap();
    let bytes = raw_commit!(gs[1], cs[1], |b| b.propose_adds([v.key_package]));
    all_reject(
        &cs,
        &mut gs,
        1,
        &bytes,
        &Error::Unauthorized("committer may not invite"),
    );
}

#[test]
fn add_of_leaf_without_instance_cert_is_rejected() {
    let (cs, mut gs) = trio();
    let clock = Arc::new(FakeClock::default());
    let d = client(98, &clock);
    let kp = KeyPackage::builder()
        .leaf_node_capabilities(capabilities())
        .build(CS, &d.provider, &d.signer(), d.credential())
        .unwrap()
        .key_package()
        .clone();
    let bytes = raw_commit!(gs[0], cs[0], |b| b.propose_adds([kp]));
    all_reject(&cs, &mut gs, 0, &bytes, &Error::InvalidCert("missing"));
}

#[test]
fn update_that_drops_the_instance_cert_is_rejected() {
    let (cs, mut gs) = trio();
    let params = LeafNodeParameters::builder()
        .with_extensions(Extensions::empty())
        .build();
    let bytes = raw_commit!(gs[1], cs[1], |b| b
        .force_self_update(true)
        .leaf_node_parameters(params));
    all_reject(&cs, &mut gs, 1, &bytes, &Error::InvalidCert("missing"));
}

#[test]
fn non_owner_policy_change_is_rejected() {
    let (cs, mut gs) = trio();
    let ctx = check_group_context(gs[1].mls.extensions()).unwrap();
    let mut p = ctx.policy.clone();
    p.require_verified = true;
    let exts = gce(&ctx.meta_bytes, &p);
    let bytes = raw_commit!(gs[1], cs[1], |b| b
        .propose_group_context_extensions(exts)
        .unwrap());
    all_reject(
        &cs,
        &mut gs,
        1,
        &bytes,
        &Error::Unauthorized("committer may not change this policy"),
    );
}

#[test]
fn owner_changing_meta_is_rejected() {
    let (cs, mut gs) = trio();
    let ctx = check_group_context(gs[0].mls.extensions()).unwrap();
    let mut meta = ctx.meta.clone();
    meta.purpose = "something else entirely".into();
    let exts = gce(&meta.to_json().unwrap(), &ctx.policy);
    let bytes = raw_commit!(gs[0], cs[0], |b| b
        .propose_group_context_extensions(exts)
        .unwrap());
    all_reject(
        &cs,
        &mut gs,
        0,
        &bytes,
        &Error::Unauthorized("ac_group_meta is immutable"),
    );
}

#[test]
fn gce_missing_required_extension_is_rejected() {
    // OpenMLS itself refuses to drop RequiredCapabilities while unknown
    // extensions remain, so omit ac_group_meta instead.
    let (cs, mut gs) = trio();
    let ctx = check_group_context(gs[0].mls.extensions()).unwrap();
    let exts = Extensions::from_vec(vec![
        Extension::Unknown(
            EXT_GROUP_POLICY,
            UnknownExtension(ctx.policy.to_json().unwrap()),
        ),
        Extension::RequiredCapabilities(required_capabilities()),
    ])
    .unwrap();
    let bytes = raw_commit!(gs[0], cs[0], |b| b
        .propose_group_context_extensions(exts)
        .unwrap());
    all_reject(
        &cs,
        &mut gs,
        0,
        &bytes,
        &Error::InvalidGroupContext("missing required extension"),
    );
}

#[test]
fn gce_with_extra_extension_is_rejected() {
    let (cs, mut gs) = trio();
    let ctx = check_group_context(gs[0].mls.extensions()).unwrap();
    let exts = Extensions::from_vec(vec![
        Extension::Unknown(EXT_GROUP_META, UnknownExtension(ctx.meta_bytes.clone())),
        Extension::Unknown(
            EXT_GROUP_POLICY,
            UnknownExtension(ctx.policy.to_json().unwrap()),
        ),
        Extension::RequiredCapabilities(required_capabilities()),
        Extension::ExternalSenders(Vec::new()),
    ])
    .unwrap();
    let bytes = raw_commit!(gs[0], cs[0], |b| b
        .propose_group_context_extensions(exts)
        .unwrap());
    all_reject(
        &cs,
        &mut gs,
        0,
        &bytes,
        &Error::InvalidGroupContext("unexpected extension"),
    );
}

#[test]
fn gce_with_non_canonical_policy_is_rejected() {
    let (cs, mut gs) = trio();
    let ctx = check_group_context(gs[0].mls.extensions()).unwrap();
    let policy = String::from_utf8(ctx.policy.to_json().unwrap())
        .unwrap()
        .replace(':', ": ");
    let exts = group_context_extensions(&ctx.meta_bytes, policy.as_bytes()).unwrap();
    let bytes = raw_commit!(gs[0], cs[0], |b| b
        .propose_group_context_extensions(exts)
        .unwrap());
    all_reject(&cs, &mut gs, 0, &bytes, &Error::Malformed("group policy"));
}

#[test]
fn standalone_proposal_removing_someone_else_is_rejected() {
    let (cs, mut gs) = trio();
    let msg = gs[1]
        .mls
        .propose_remove_member(&cs[1].provider, &cs[1].signer(), LeafNodeIndex::new(2))
        .unwrap()
        .0;
    let bytes = wire(&msg).unwrap();
    assert_eq!(
        gs[0].process(&cs[0], &bytes),
        Err(Error::Unauthorized("only leave proposals are accepted"))
    );
}

#[test]
fn local_checks_reject_own_bad_commits_and_clear_them() {
    let (cs, mut gs) = trio();
    // B is not allowed to change policy; set_policy stages, inspects,
    // rejects and clears.
    let mut p = gs[1].policy().unwrap();
    p.max_members = 2;
    assert_eq!(
        gs[1].set_policy(&cs[1], &p),
        Err(Error::Unauthorized("committer may not change this policy"))
    );
    assert!(!gs[1].has_pending_commit());
    // Owner shrinking max_members below the current size is rejected too.
    assert_eq!(
        gs[0].set_policy(&cs[0], &p),
        Err(Error::Unauthorized("group would exceed max_members"))
    );
    let mut bad = p.clone();
    bad.v = 1;
    assert_eq!(
        gs[0].set_policy(&cs[0], &bad),
        Err(Error::UnsupportedVersion)
    );
}

#[test]
fn processing_after_eviction_and_public_messages() {
    let (cs, mut gs) = trio();
    let out = gs[0].remove(&cs[0], cs[2].instance().identity()).unwrap();
    gs[0].confirm_pending_commit(&cs[0]).unwrap();
    assert!(matches!(
        gs[2].process(&cs[2], &out.commit),
        Ok(Event::Removed(_))
    ));
    assert_eq!(gs[2].process(&cs[2], &out.commit), Err(Error::NotMember));
    assert_eq!(gs[2].update(&cs[2]).unwrap_err(), Error::NotMember);
    // A KeyPackage is not a protocol message.
    let kp = KeyPackage::builder()
        .build(CS, &cs[1].provider, &cs[1].signer(), cs[1].credential())
        .unwrap();
    let kp_msg = MlsMessageOut::from(kp.key_package().clone());
    assert_eq!(
        gs[1].process(&cs[1], &wire(&kp_msg).unwrap()),
        Err(Error::UnexpectedMessage("only PrivateMessage is accepted"))
    );
    assert_eq!(
        gs[1].open(&cs[1], &out.commit),
        Err(Error::UnexpectedMessage("not an application message"))
    );
    assert!(format!("{:?}", cs[0]).contains("Client"));
}

#[test]
fn wrong_epoch_is_reported() {
    let (cs, mut gs) = trio();
    // B moves to the next epoch; C hasn't seen the commit yet.
    let out = gs[0].update(&cs[0]).unwrap();
    gs[0].confirm_pending_commit(&cs[0]).unwrap();
    gs[1].process(&cs[1], &out.commit).unwrap();
    let ahead = gs[1].seal(&cs[1], &inner(&cs[1])).unwrap();
    assert_eq!(gs[2].process(&cs[2], &ahead), Err(Error::WrongEpoch));
    // After catching up, C reads it.
    gs[2].process(&cs[2], &out.commit).unwrap();
    assert!(gs[2].open(&cs[2], &ahead).is_ok());
}

fn inner(c: &C) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "v": 0,
        "sender": c.instance().identity(),
        "instance_id": c.instance().cert().instance_id_hex(),
    }))
    .unwrap()
}
