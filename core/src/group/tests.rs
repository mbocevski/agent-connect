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
    let out = group.add_member(inviter, &v, &inv, true).unwrap();
    group.confirm_pending_commit(inviter, &out.msg_id).unwrap();
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
    gs[0].confirm_pending_commit(&cs[0], &out.msg_id).unwrap();
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

/// Review F7, receiver side: a member that bypasses its own checks and
/// re-adds a KeyPackage already used in an earlier Add is rejected by the
/// others, who remember every KeyPackage they merged.
#[test]
fn re_add_of_a_used_key_package_is_rejected_by_receivers() {
    let (cs, mut gs) = trio();
    let clock = Arc::new(FakeClock::default());
    let d = client(97, &clock);
    let inv = Invite::create(
        cs[0].rng(),
        cs[0].clock(),
        "r.example",
        Duration::from_secs(60),
    )
    .unwrap();
    let req = d.create_join_request(inv.secret(), "d").unwrap();
    let v = cs[0].verify_join_request(&req, &inv).unwrap();
    let kp = v.key_package.clone();
    let out = gs[0].add_member(&cs[0], &v, &inv, true).unwrap();
    gs[0].confirm_pending_commit(&cs[0], &out.msg_id).unwrap();
    for i in [1, 2] {
        assert!(matches!(
            gs[i].process(&cs[i], &out.commit),
            Ok(Event::Commit(_))
        ));
    }
    // D is removed; A then commits a raw Add of D's old KeyPackage.
    let removal = gs[0].remove(&cs[0], d.instance().identity()).unwrap();
    gs[0]
        .confirm_pending_commit(&cs[0], &removal.msg_id)
        .unwrap();
    for i in [1, 2] {
        assert!(matches!(
            gs[i].process(&cs[i], &removal.commit),
            Ok(Event::Commit(_))
        ));
    }
    let bytes = raw_commit!(gs[0], cs[0], |b| b.propose_adds([kp]));
    all_reject(
        &cs,
        &mut gs,
        0,
        &bytes,
        &Error::Unauthorized("key package already used"),
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
    gs[0].confirm_pending_commit(&cs[0], &out.msg_id).unwrap();
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

/// Review F1, malicious member: any member can write sender data naming
/// another member's leaf. A has `Remove(B)` pending; a commit that claims
/// A's leaf but isn't the one A sent must neither merge A's pending commit
/// (A would believe B is gone while nobody else does) nor discard it.
#[test]
fn forged_own_commit_echo_neither_confirms_nor_discards() {
    let (cs, mut gs) = trio();
    // Bytes framed as a commit from A's leaf at the current epoch that A
    // never sent (built from A's state and thrown away, which is as good as
    // a forgery from A's point of view).
    let forged = raw_commit!(gs[0], cs[0], |b| b.force_self_update(true));
    let out = gs[0].remove(&cs[0], cs[1].instance().identity()).unwrap();
    let epoch = gs[0].epoch();
    assert_eq!(
        gs[0].process(&cs[0], &forged),
        Err(Error::Unauthorized(
            "commit claims this instance as sender but was not sent by it"
        ))
    );
    assert_eq!(gs[0].epoch(), epoch);
    assert!(gs[0].has_pending_commit());
    assert_eq!(gs[0].members().unwrap().len(), 3);
    // The relay's real confirmation still works.
    let s = gs[0].confirm_pending_commit(&cs[0], &out.msg_id).unwrap();
    assert_eq!(s.removed[0].identity, cs[1].instance().identity());
    assert!(matches!(
        gs[2].process(&cs[2], &out.commit),
        Ok(Event::Commit(_))
    ));
    assert_eq!(gs[0].sas(), gs[2].sas());
}

/// Review F3: one commit removes C and adds D, who takes C's leaf. C's
/// grace-window message must be attributed to C (the member in its epoch),
/// not to D (the current occupant of the leaf).
#[test]
fn grace_window_sender_is_resolved_in_its_own_epoch() {
    let (cs, mut gs) = trio();
    let clock = Arc::new(FakeClock::default());
    let d = client(96, &clock);
    let inv = Invite::create(
        cs[0].rng(),
        cs[0].clock(),
        "r.example",
        Duration::from_secs(60),
    )
    .unwrap();
    let req = d.create_join_request(inv.secret(), "d").unwrap();
    let kp = cs[0].verify_join_request(&req, &inv).unwrap().key_package;
    let ct = gs[2].seal(&cs[2], &inner(&cs[2])).unwrap();
    let bytes = raw_commit!(gs[0], cs[0], |b| b
        .propose_removals([LeafNodeIndex::new(2)])
        .propose_adds([kp]));
    assert!(matches!(
        gs[1].process(&cs[1], &bytes),
        Ok(Event::Commit(_))
    ));
    let now = gs[1].members().unwrap();
    assert_eq!(now[2].identity, d.instance().identity());
    let m = gs[1].open(&cs[1], &ct).unwrap();
    assert_eq!(m.sender.identity, cs[2].instance().identity());
    assert_eq!(m.sender.leaf_index, 2);
}

/// A grace-window message from a leaf that was not a member in the
/// message's epoch is rejected.
#[test]
fn grace_window_sender_must_have_been_a_member_then() {
    let (cs, mut gs) = trio();
    let ct1 = gs[2].seal(&cs[2], &inner(&cs[2])).unwrap();
    let ct2 = gs[2].seal(&cs[2], &inner(&cs[2])).unwrap();
    let out = gs[0].update(&cs[0]).unwrap();
    gs[0].confirm_pending_commit(&cs[0], &out.msg_id).unwrap();
    assert!(matches!(
        gs[1].process(&cs[1], &out.commit),
        Ok(Event::Commit(_))
    ));
    let records = cs[1].provider.records();
    let mut prev = PreviousMembers::load(records, gs[1].group_id())
        .unwrap()
        .unwrap();
    // A record naming someone else for C's leaf disagrees with the
    // credential OpenMLS verified the message against.
    prev.members[2].identity = cs[0].instance().identity().to_owned();
    prev.save(records, gs[1].group_id()).unwrap();
    assert_eq!(
        gs[1].open(&cs[1], &ct1),
        Err(Error::CredentialMismatch("sender != epoch member"))
    );
    // No member at C's leaf in that epoch.
    prev.members.retain(|m| m.leaf_index != 2);
    prev.save(records, gs[1].group_id()).unwrap();
    assert_eq!(gs[1].open(&cs[1], &ct2), Err(Error::UnknownMember));
}

#[test]
fn wrong_epoch_is_reported() {
    let (cs, mut gs) = trio();
    // B moves to the next epoch; C hasn't seen the commit yet.
    let out = gs[0].update(&cs[0]).unwrap();
    gs[0].confirm_pending_commit(&cs[0], &out.msg_id).unwrap();
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

/// SPEC §7.2, receiver side: B skips `seal` and sends an application
/// message whose inner header claims to be from A. Every receiver drops it.
#[test]
fn receivers_drop_inner_sender_that_is_not_the_mls_sender() {
    let (cs, mut gs) = trio();
    let spoofed = |gs: &mut Vec<Group>, body: serde_json::Value| {
        let msg = gs[1]
            .mls
            .create_message(
                &cs[1].provider,
                &cs[1].signer(),
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap();
        wire(&msg).unwrap()
    };
    let as_a = spoofed(
        &mut gs,
        serde_json::json!({
            "v": 0,
            "sender": cs[0].instance().identity(),
            "instance_id": cs[0].instance().cert().instance_id_hex(),
        }),
    );
    let wrong_instance = spoofed(
        &mut gs,
        serde_json::json!({
            "v": 0,
            "sender": cs[1].instance().identity(),
            "instance_id": cs[0].instance().cert().instance_id_hex(),
        }),
    );
    for i in [0, 2] {
        assert_eq!(
            gs[i].open(&cs[i], &as_a),
            Err(Error::CredentialMismatch("inner sender != MLS sender")),
            "member {i}"
        );
        assert_eq!(
            gs[i].open(&cs[i], &wrong_instance),
            Err(Error::CredentialMismatch("inner instance_id != MLS sender")),
            "member {i}"
        );
    }
}

fn vl(b: &[u8]) -> Vec<u8> {
    openmls::prelude::tls_codec::VLBytes::new(b.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

/// RFC 9420 `SignWithLabel`.
fn sign_with_label(c: &C, label: &str, content: &[u8]) -> Vec<u8> {
    let msg = [vl(format!("MLS 1.0 {label}").as_bytes()), vl(content)].concat();
    c.instance().sign(&msg).to_vec()
}

/// A KeyPackage from `c`, validly signed (leaf and package) by `c`'s
/// instance key, whose leaf HPKE encryption key is only 32 bytes: the
/// RUSTSEC-2026-0331 shape, as a malicious joiner would build it.
fn key_package_with_short_leaf_key(c: &C, inv: &Invite) -> KeyPackage {
    use openmls::prelude::tls_codec::VLBytes;
    let kp = c
        .create_join_request(inv.secret(), "evil")
        .unwrap()
        .key_package;
    let mut rest = &kp[4..];
    let skip = |rest: &mut &[u8]| {
        VLBytes::tls_deserialize(rest).unwrap();
    };
    let at = |rest: &[u8]| kp.len() - rest.len();
    skip(&mut rest); // init_key
    let leaf_start = at(rest);
    skip(&mut rest); // encryption_key
    let after_key = at(rest);
    skip(&mut rest); // signature_key
    rest = &rest[2..]; // credential_type (basic)
    skip(&mut rest); // identity
    for _ in 0..5 {
        skip(&mut rest); // capabilities: versions, suites, extensions, proposals, credentials
    }
    rest = &rest[1 + 16..]; // leaf_node_source = key_package, lifetime
    skip(&mut rest); // leaf extensions
    let leaf_tbs_end = at(rest);
    skip(&mut rest); // leaf signature
    let exts_start = at(rest);
    skip(&mut rest); // key package extensions
    let exts_end = at(rest);

    let short = Rng::for_test("short-leaf-key").array::<32>().unwrap();
    let leaf_tbs = [vl(&short), kp[after_key..leaf_tbs_end].to_vec()].concat();
    let leaf_sig = sign_with_label(c, "LeafNodeTBS", &leaf_tbs);
    let tbs = [
        kp[..leaf_start].to_vec(),
        leaf_tbs,
        vl(&leaf_sig),
        kp[exts_start..exts_end].to_vec(),
    ]
    .concat();
    let sig = sign_with_label(c, "KeyPackageTBS", &tbs);
    let evil = [tbs, vl(&sig)].concat();
    // The raw-byte precheck stops it at the inviter's JoinRequest check...
    assert_eq!(
        crate::mls::precheck_key_package(&evil),
        Err(Error::HpkeKeyLength)
    );
    // ...but OpenMLS itself accepts it, so a member that skips the
    // precheck can put it in a commit.
    openmls::prelude::KeyPackageIn::tls_deserialize_exact(evil.as_slice())
        .unwrap()
        .validate(
            c.provider.crypto(),
            openmls::prelude::ProtocolVersion::Mls10,
        )
        .unwrap()
}

/// Review F10: the receiver-side HPKE length check runs on a real commit.
/// A (the owner, so the Add is authorised) commits a raw Add of a
/// KeyPackage with a short leaf key; every other member rejects it with
/// `HpkeKeyLength` before merging, and nothing panics.
#[test]
fn receivers_reject_a_real_add_with_a_short_hpke_key() {
    let (cs, mut gs) = trio();
    let clock = Arc::new(FakeClock::default());
    let d = client(95, &clock);
    let inv = Invite::create(d.rng(), d.clock(), "r.example", Duration::from_secs(60)).unwrap();
    let evil = key_package_with_short_leaf_key(&d, &inv);
    let bytes = raw_commit!(gs[0], cs[0], |b| b.propose_adds([evil]));
    all_reject(&cs, &mut gs, 0, &bytes, &Error::HpkeKeyLength);
}

/// Review F10: the joiner's HPKE length check runs on a real Welcome. A
/// skips its own checks, merges an Add of a short-key leaf, then invites E:
/// the ratchet tree in E's Welcome carries the short key, and E refuses the
/// Welcome before OpenMLS stages it.
#[test]
fn joiner_rejects_a_real_welcome_whose_tree_has_a_short_hpke_key() {
    let clock = Arc::new(FakeClock::default());
    let a = client(10, &clock);
    let mut ga = a.create_group("g", "p").unwrap();
    let d = client(94, &clock);
    let inv_d = Invite::create(d.rng(), d.clock(), "r.example", Duration::from_secs(60)).unwrap();
    let evil = key_package_with_short_leaf_key(&d, &inv_d);
    let signer = a.signer();
    ga.mls
        .commit_builder()
        .propose_adds([evil])
        .load_psks(a.provider.storage())
        .unwrap()
        .build(a.provider.rand(), a.provider.crypto(), &signer, |_| true)
        .unwrap()
        .stage_commit(&a.provider)
        .unwrap();
    ga.mls.merge_pending_commit(&a.provider).unwrap();

    let e = client(93, &clock);
    let inv = Invite::create(a.rng(), a.clock(), "r.example", Duration::from_secs(60)).unwrap();
    let req = e.create_join_request(inv.secret(), "e").unwrap();
    let kp = a.verify_join_request(&req, &inv).unwrap().key_package;
    let bundle = ga
        .mls
        .commit_builder()
        .propose_adds([kp])
        .load_psks(a.provider.storage())
        .unwrap()
        .build(a.provider.rand(), a.provider.crypto(), &signer, |_| true)
        .unwrap()
        .stage_commit(&a.provider)
        .unwrap();
    let welcome = wire(&bundle.to_welcome_msg().unwrap()).unwrap();
    let wrapped = inv.secret().wrap_welcome(a.rng(), &welcome).unwrap();
    let meta = InviteMeta::expected(inv.secret().id(), "g", "p");
    assert_eq!(
        e.join_from_wrapped_welcome(inv.secret(), &meta, &wrapped)
            .unwrap_err(),
        Error::HpkeKeyLength
    );
}

/// Review F10: a GroupContextExtensions proposal that keeps all three
/// extensions but changes `RequiredCapabilities` is rejected.
#[test]
fn gce_modifying_required_capabilities_is_rejected() {
    use openmls::prelude::{ProposalType, RequiredCapabilitiesExtension};
    let (cs, mut gs) = trio();
    let ctx = check_group_context(gs[0].mls.extensions()).unwrap();
    let mut types = crate::mls::ac_extension_types();
    types.push(openmls::prelude::ExtensionType::RatchetTree);
    let exts = Extensions::from_vec(vec![
        Extension::Unknown(EXT_GROUP_META, UnknownExtension(ctx.meta_bytes.clone())),
        Extension::Unknown(
            EXT_GROUP_POLICY,
            UnknownExtension(ctx.policy.to_json().unwrap()),
        ),
        // Same extension types, plus a required proposal type every member
        // supports, so OpenMLS itself has no objection.
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &types,
            &[ProposalType::Add],
            &[],
        )),
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
        &Error::InvalidGroupContext("RequiredCapabilities"),
    );
}

/// SPEC §9.2: the owner skips its local check and proposes its own leave.
/// Receivers (C) refuse to store the proposal. A member (B) that bypasses
/// that is stopped by its own `commit_pending_proposals`, and if it commits
/// the leave with raw OpenMLS calls anyway, a receiver holding the proposal
/// (A, which stored its own) rejects the commit before merging it.
#[test]
fn commit_removing_the_owners_last_instance_is_rejected() {
    const OWNER: Error = Error::Unauthorized(OWNER_MUST_TRANSFER);
    let (cs, mut gs) = trio();
    let msg = gs[0]
        .mls
        .leave_group(&cs[0].provider, &cs[0].signer())
        .unwrap();
    let proposal = wire(&msg).unwrap();
    assert_eq!(gs[2].process(&cs[2], &proposal), Err(OWNER));
    assert!(gs[2].mls.pending_proposals().next().is_none());

    let ProcessedMessageContent::ProposalMessage(queued) = gs[1]
        .mls
        .process_message(&cs[1].provider, parse_protocol(&proposal).unwrap())
        .unwrap()
        .into_content()
    else {
        panic!("expected a proposal");
    };
    gs[1]
        .mls
        .store_pending_proposal(cs[1].provider.storage(), *queued)
        .unwrap();
    assert_eq!(gs[1].commit_pending_proposals(&cs[1]), Err(OWNER));
    assert!(!gs[1].has_pending_commit());
    let bytes = raw_commit!(gs[1], cs[1], |b| b);
    let epoch = gs[0].epoch();
    assert_eq!(gs[0].process(&cs[0], &bytes), Err(OWNER));
    assert_eq!(gs[0].epoch(), epoch);
    assert!(gs[0].is_active());
}

/// A solo group "g"/"p" owned by A, an invite from A and E's verified
/// KeyPackage for it.
fn solo_and_joiner() -> (C, Group, C, Invite, KeyPackage) {
    let clock = Arc::new(FakeClock::default());
    let a = client(10, &clock);
    let ga = a.create_group("g", "p").unwrap();
    let e = client(93, &clock);
    let inv = Invite::create(a.rng(), a.clock(), "r.example", Duration::from_secs(60)).unwrap();
    let req = e.create_join_request(inv.secret(), "e").unwrap();
    let kp = a.verify_join_request(&req, &inv).unwrap().key_package;
    (a, ga, e, inv, kp)
}

/// The TLS-serialised Welcome of a raw commit built by `$build` (which
/// must add someone). The sender's state is left untouched.
macro_rules! raw_welcome {
    ($g:expr, $c:expr, |$b:ident| $build:expr) => {
        raw_welcome!($g, $c, |$b| $build, |l| l)
    };
    ($g:expr, $c:expr, |$b:ident| $build:expr, |$l:ident| $loaded:expr) => {{
        let signer = $c.signer();
        let $b = $g.mls.commit_builder();
        let $l = $build.load_psks($c.provider.storage()).unwrap();
        let bundle = $loaded
            .build($c.provider.rand(), $c.provider.crypto(), &signer, |_| true)
            .unwrap()
            .stage_commit(&$c.provider)
            .unwrap();
        let welcome = wire(&bundle.to_welcome_msg().unwrap()).unwrap();
        $g.mls.clear_pending_commit($c.provider.storage()).unwrap();
        welcome
    }};
}

fn join_raw(e: &C, inv: &Invite, welcome: &[u8]) -> Result<Group> {
    let wrapped = inv.secret().wrap_welcome(e.rng(), welcome).unwrap();
    let meta = InviteMeta::expected(inv.secret().id(), "g", "p");
    e.join_from_wrapped_welcome(inv.secret(), &meta, &wrapped)
}

/// SPEC §6.3: a `GroupInfo` extension other than `ratchet_tree` (here an
/// unknown one, which OpenMLS itself accepts) makes the Welcome invalid.
#[test]
fn welcome_with_an_extra_group_info_extension_is_rejected() {
    let (a, mut ga, e, inv, kp) = solo_and_joiner();
    let welcome = raw_welcome!(ga, a, |b| b.propose_adds([kp]), |l| l
        .create_group_info_with_extensions([Extension::Unknown(
            0xF0B0,
            UnknownExtension(Vec::new()),
        )])
        .unwrap());
    assert_eq!(
        join_raw(&e, &inv, &welcome).unwrap_err(),
        Error::InvalidGroupContext("unexpected GroupInfo extension")
    );
}

/// SPEC §3.1: E's `kem_output` in the Welcome is cut to 1119 bytes (and,
/// separately, grown to 1121). E refuses it before OpenMLS decapsulates.
#[test]
fn welcome_with_a_wrong_length_kem_output_is_rejected() {
    use openmls::prelude::tls_codec::VLBytes;
    let (a, mut ga, e, inv, kp) = solo_and_joiner();
    let welcome = raw_welcome!(ga, a, |b| b.propose_adds([kp]));
    // MlsMessage = version(2) ‖ wire_format(2) ‖ Welcome, and
    // Welcome = cipher_suite(2) ‖ secrets<V> ‖ encrypted_group_info<V>.
    let mut rest = &welcome[6..];
    let secrets = VLBytes::tls_deserialize(&mut rest).unwrap();
    let group_info = rest.to_vec();
    let mut entry = secrets.as_slice();
    let new_member = VLBytes::tls_deserialize(&mut entry).unwrap();
    let kem_output = VLBytes::tls_deserialize(&mut entry).unwrap();
    assert_eq!(kem_output.as_slice().len(), crate::mls::KEM_CIPHERTEXT_LEN);
    let ciphertext = entry.to_vec();
    let tampered = |len: usize| {
        let mut kem = kem_output.as_slice().to_vec();
        kem.resize(len, kem[0]);
        let entry = [vl(new_member.as_slice()), vl(&kem), ciphertext.clone()].concat();
        [welcome[..6].to_vec(), vl(&entry), group_info.clone()].concat()
    };
    for len in [1119, 1121] {
        assert_eq!(
            join_raw(&e, &inv, &tampered(len)).unwrap_err(),
            Error::KemOutputLength,
            "{len}"
        );
    }
}

/// SPEC §6.3: the policy in a Welcome must be well-formed and in range.
/// A commits, with raw calls, a policy change together with E's Add.
#[test]
fn welcome_with_an_out_of_range_policy_is_rejected() {
    for (edit, err) in [
        (
            r#""max_agent_turns":101"#,
            Error::InvalidGroupContext("policy max_agent_turns"),
        ),
        (
            r#""max_members":0"#,
            Error::InvalidGroupContext("policy max_members"),
        ),
    ] {
        let (a, mut ga, e, inv, kp) = solo_and_joiner();
        let ctx = check_group_context(ga.mls.extensions()).unwrap();
        let key = edit.split(':').next().unwrap();
        let json = String::from_utf8(ctx.policy.to_json().unwrap()).unwrap();
        let start = json.find(key).unwrap();
        let end = start + json[start..].find([',', '}']).unwrap();
        let policy = format!("{}{edit}{}", &json[..start], &json[end..]);
        let exts = group_context_extensions(&ctx.meta_bytes, policy.as_bytes()).unwrap();
        let welcome = raw_welcome!(ga, a, |b| b
            .propose_adds([kp])
            .propose_group_context_extensions(exts)
            .unwrap());
        assert_eq!(join_raw(&e, &inv, &welcome).unwrap_err(), err, "{edit}");
    }
}

/// SPEC §6.3: the policy must name a valid owner, but the owner need not be
/// a current member.
#[test]
fn welcome_policy_must_list_an_owner_who_need_not_be_a_member() {
    let absent = Identity::generate(&Rng::for_test("seed-absent-owner"))
        .unwrap()
        .id();
    for (owner, expected) in [
        (
            "ac:v0:nope".to_owned(),
            Some(Error::InvalidGroupContext("policy owner")),
        ),
        (absent.clone(), None),
    ] {
        let (a, mut ga, e, inv, kp) = solo_and_joiner();
        let ctx = check_group_context(ga.mls.extensions()).unwrap();
        let policy = GroupPolicy {
            owner: owner.clone(),
            ..ctx.policy
        };
        let exts = gce(&ctx.meta_bytes, &policy);
        let welcome = raw_welcome!(ga, a, |b| b
            .propose_adds([kp])
            .propose_group_context_extensions(exts)
            .unwrap());
        match (join_raw(&e, &inv, &welcome), expected) {
            (Err(got), Some(err)) => assert_eq!(got, err),
            (Ok(g), None) => assert_eq!(g.policy().unwrap().owner, absent),
            (got, want) => panic!("{owner}: got {got:?}, want {want:?}"),
        }
    }
}
