//! Spike item 2: invite binding (SPEC §6.2–6.4).
//!
//! Part A: external PSK in the Add commit (SPEC §6.2) works mechanically, but
//! every *existing* member also needs the PSK to process that commit, which
//! conflicts with "only the creating instance holds the invite secret"
//! (SPEC §4.3). Part B: the AEAD-wrapped Welcome (SPEC §6.4) has no such
//! problem.

use agentconnect_spike_mls_xwing::*;
use openmls::prelude::*;
// PSK types are not in the prelude.
use openmls::schedule::{ExternalPsk, PreSharedKeyId, Psk};
use openmls_libcrux_crypto::Provider;
use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer, types::AeadType,
};

use std::sync::LazyLock;

// Random per run: the tests only compare derived values, and fixed bytes
// would be a hard-coded secret.
static INVITE_ID: LazyLock<[u8; 16]> = LazyLock::new(random_array);
static INVITE_SECRET: LazyLock<[u8; 32]> = LazyLock::new(random_array);

fn random_array<const N: usize>() -> [u8; N] {
    Provider::new()
        .expect("provider")
        .rand()
        .random_array()
        .expect("os rng")
}

fn kp(id: &Identity, p: &Provider) -> KeyPackage {
    id.key_package(p, ac_capabilities(), instance_cert_ext(b"{}"))
}

/// Joiner side: store `invite_psk` under `"ac:v0:invite:" ‖ invite_id`.
/// The nonce is not part of the storage key, so any nonce works here.
fn store_invite_psk(p: &Provider, secret: &[u8]) {
    PreSharedKeyId::external(invite_psk_id(&*INVITE_ID), vec![])
        .store(p, &invite_psk(secret, &*INVITE_ID))
        .unwrap();
}

/// Inviter side: commit `Add(kp)` + `PreSharedKey(invite psk)` in one commit.
fn commit_add_with_psk(
    group: &mut MlsGroup,
    p: &Provider,
    signer: &impl Signer,
    kp: KeyPackage,
) -> (Vec<u8>, Vec<u8>) {
    let psk_id = PreSharedKeyId::new(
        CS,
        p.rand(),
        Psk::External(ExternalPsk::new(invite_psk_id(&*INVITE_ID))),
    )
    .unwrap();
    psk_id
        .store(p, &invite_psk(&*INVITE_SECRET, &*INVITE_ID))
        .unwrap();
    let bundle = group
        .commit_builder()
        .propose_adds([kp])
        .add_proposal(Proposal::PreSharedKey(Box::new(PreSharedKeyProposal::new(
            psk_id,
        ))))
        .load_psks(p.storage())
        .unwrap()
        .build(p.rand(), p.crypto(), signer, |_| true)
        .unwrap()
        .stage_commit(p)
        .unwrap();
    group.merge_pending_commit(p).unwrap();
    (
        wire(bundle.commit()),
        wire(&bundle.to_welcome_msg().unwrap()),
    )
}

#[test]
fn psk_in_welcome_binds_join_to_invite_secret() {
    let pa = Provider::new().unwrap();
    let a = Identity::new("ac:v0:alice", &pa);
    let mut ga = MlsGroup::new(&pa, &a.signer, &create_config(), a.credential.clone()).unwrap();

    // Joiner without the PSK: the Welcome cannot be processed.
    let p_nopsk = Provider::new().unwrap();
    let nopsk = Identity::new("ac:v0:mallory", &p_nopsk);
    let (_, w) = commit_add_with_psk(&mut ga, &pa, &a.signer, kp(&nopsk, &p_nopsk));
    let err = join(&p_nopsk, &w).unwrap_err();
    assert!(matches!(err, WelcomeError::Psk(_)), "{err:?}");

    // Gotcha: the failed attempt already deleted the KeyPackage private key,
    // so storing the PSK afterwards and retrying does not work. The joiner
    // MUST store the PSK before processing (SPEC §6.1 already says so).
    store_invite_psk(&p_nopsk, &*INVITE_SECRET);
    let err = join(&p_nopsk, &w).unwrap_err();
    assert!(matches!(err, WelcomeError::NoMatchingKeyPackage), "{err:?}");

    // Joiner with a PSK derived from the wrong secret: rejected.
    let p_wrong = Provider::new().unwrap();
    let wrong = Identity::new("ac:v0:eve", &p_wrong);
    store_invite_psk(&p_wrong, b"not-the-invite-secret-0123456789");
    let (_, w) = commit_add_with_psk(&mut ga, &pa, &a.signer, kp(&wrong, &p_wrong));
    assert!(join(&p_wrong, &w).is_err());

    // Joiner with the right PSK: joins.
    let pb = Provider::new().unwrap();
    let b = Identity::new("ac:v0:bob", &pb);
    store_invite_psk(&pb, &*INVITE_SECRET);
    let (_, w) = commit_add_with_psk(&mut ga, &pa, &a.signer, kp(&b, &pb));
    let gb = join(&pb, &w).unwrap();
    assert_eq!(sas_bytes(&gb), sas_bytes(&ga));
}

#[test]
fn psk_commit_requires_psk_at_every_existing_member() {
    let pa = Provider::new().unwrap();
    let pb = Provider::new().unwrap();
    let pd = Provider::new().unwrap();
    let a = Identity::new("ac:v0:alice", &pa);
    let b = Identity::new("ac:v0:bob", &pb);
    let d = Identity::new("ac:v0:dave", &pd);
    let mut ga = MlsGroup::new(&pa, &a.signer, &create_config(), a.credential.clone()).unwrap();
    let (_, w, _) = ga
        .add_members(&pa, &a.signer, &[kp(&b, &pb), kp(&d, &pd)])
        .unwrap();
    ga.merge_pending_commit(&pa).unwrap();
    let mut gb = join(&pb, &wire(&w)).unwrap();
    let mut gd = join(&pd, &wire(&w)).unwrap();

    // A invites C with an invite only A knows. D was given the PSK out of
    // band beforehand (e.g. by A in an application message); B was not.
    let pc = Provider::new().unwrap();
    let c = Identity::new("ac:v0:carol", &pc);
    store_invite_psk(&pc, &*INVITE_SECRET);
    store_invite_psk(&pd, &*INVITE_SECRET);
    let (commit, w) = commit_add_with_psk(&mut ga, &pa, &a.signer, kp(&c, &pc));
    let gc = join(&pc, &w).unwrap();

    // B cannot process the commit: it would be stuck at the old epoch.
    let err = apply_commit(&mut gb, &pb, &commit).unwrap_err();
    assert!(format!("{err:?}").contains("Psk"), "{err:?}");

    // Gotcha: the failed attempt consumed the commit's decryption key, so
    // learning the PSK afterwards does not help. B is permanently forked off.
    store_invite_psk(&pb, &*INVITE_SECRET);
    let err = apply_commit(&mut gb, &pb, &commit).unwrap_err();
    assert!(format!("{err:?}").contains("SecretReuseError"), "{err:?}");

    // D, holding the PSK in advance, follows the group.
    apply_commit(&mut gd, &pd, &commit).unwrap();
    assert_eq!(sas_bytes(&gd), sas_bytes(&gc));
    assert_eq!(sas_bytes(&gd), sas_bytes(&ga));
}

/// SPEC §6.4: `nonce(12) ‖ ChaCha20-Poly1305(welcome_key, nonce, aad, welcome)`.
fn wrap_welcome(p: &Provider, secret: &[u8], welcome: &[u8]) -> Vec<u8> {
    let key = welcome_key(secret, &*INVITE_ID);
    let nonce: [u8; 12] = p.rand().random_array().unwrap();
    let aad = [b"agentconnect/v0/welcome".as_slice(), &*INVITE_ID].concat();
    let ct = p
        .crypto()
        .aead_encrypt(AeadType::ChaCha20Poly1305, &key, welcome, &nonce, &aad)
        .unwrap();
    [nonce.as_slice(), &ct].concat()
}

fn unwrap_welcome(p: &Provider, secret: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
    let key = welcome_key(secret, &*INVITE_ID);
    let (nonce, ct) = wrapped.split_at(12);
    let aad = [b"agentconnect/v0/welcome".as_slice(), &*INVITE_ID].concat();
    p.crypto()
        .aead_decrypt(AeadType::ChaCha20Poly1305, &key, ct, nonce, &aad)
        .ok()
}

#[test]
fn aead_wrapped_welcome_binds_join_without_touching_existing_members() {
    let pa = Provider::new().unwrap();
    let pb = Provider::new().unwrap();
    let a = Identity::new("ac:v0:alice", &pa);
    let b = Identity::new("ac:v0:bob", &pb);
    let mut ga = MlsGroup::new(&pa, &a.signer, &create_config(), a.credential.clone()).unwrap();
    let (_, w, _) = ga.add_members(&pa, &a.signer, &[kp(&b, &pb)]).unwrap();
    ga.merge_pending_commit(&pa).unwrap();
    let mut gb = join(&pb, &wire(&w)).unwrap();

    // Plain Add commit; only the Welcome is wrapped.
    let pc = Provider::new().unwrap();
    let c = Identity::new("ac:v0:carol", &pc);
    let (commit, w, _) = ga.add_members(&pa, &a.signer, &[kp(&c, &pc)]).unwrap();
    ga.merge_pending_commit(&pa).unwrap();
    let wrapped = wrap_welcome(&pa, &*INVITE_SECRET, &wire(&w));

    // B processes the commit with no invite material.
    apply_commit(&mut gb, &pb, &wire(&commit)).unwrap();

    // Wrong secret and tampering are rejected before MLS sees anything, so
    // the KeyPackage is not burned.
    assert!(unwrap_welcome(&pc, b"not-the-invite-secret-0123456789", &wrapped).is_none());
    let mut tampered = wrapped.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(unwrap_welcome(&pc, &*INVITE_SECRET, &tampered).is_none());

    let gc = join(
        &pc,
        &unwrap_welcome(&pc, &*INVITE_SECRET, &wrapped).unwrap(),
    )
    .unwrap();
    assert_eq!(sas_bytes(&gc), sas_bytes(&gb));
}
