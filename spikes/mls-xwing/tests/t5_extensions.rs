//! Spike item 5: custom GroupContext / LeafNode extensions and
//! `RequiredCapabilities` (SPEC §3.1, §3.2, §9.1).

use agentconnect_spike_mls_xwing::*;
use openmls::prelude::*;
use openmls_libcrux_crypto::Provider;

const POLICY: &[u8] = br#"{"floor":"free","invite":"owner","owner":"ac:v0:alice","v":0}"#;
const CERT_A: &[u8] = br#"{"identity":"ac:v0:alice","v":0}"#;
const CERT_B: &[u8] = br#"{"identity":"ac:v0:bob","v":0}"#;

fn ac_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CS)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .with_group_context_extensions(ac_group_context_extensions(POLICY))
        // Gotcha: capabilities must be set *before* leaf extensions, which
        // are checked against them.
        .capabilities(ac_capabilities())
        .with_leaf_node_extensions(instance_cert_ext(CERT_A))
        .unwrap()
        .build()
}

fn leaf_ext(group: &MlsGroup, leaf: LeafNodeIndex) -> Vec<u8> {
    group
        .public_group()
        .leaf(leaf)
        .unwrap()
        .extensions()
        .unknown(EXT_INSTANCE_CERT)
        .unwrap()
        .0
        .clone()
}

#[test]
fn extensions_round_trip_through_welcome_and_commit() {
    let pa = Provider::new().unwrap();
    let pb = Provider::new().unwrap();
    let a = Identity::new("ac:v0:alice", &pa);
    let b = Identity::new("ac:v0:bob", &pb);
    let mut ga = MlsGroup::new(&pa, &a.signer, &ac_config(), a.credential.clone()).unwrap();
    let kp = b.key_package(&pb, ac_capabilities(), instance_cert_ext(CERT_B));
    let (_, w, _) = ga.add_members(&pa, &a.signer, &[kp]).unwrap();
    ga.merge_pending_commit(&pa).unwrap();
    let mut gb = join(&pb, &wire(&w)).unwrap();

    // B sees the policy and both instance certs, authenticated by MLS.
    assert_eq!(gb.extensions().unknown(EXT_GROUP_POLICY).unwrap().0, POLICY);
    assert_eq!(leaf_ext(&gb, ga.own_leaf_index()), CERT_A);
    assert_eq!(leaf_ext(&ga, gb.own_leaf_index()), CERT_B);

    // Policy change via a GroupContextExtensions commit (SPEC §9.2). The
    // proposal replaces the whole set, so RequiredCapabilities must be resent.
    let new_policy = br#"{"floor":"mention","invite":"owner","owner":"ac:v0:alice","v":0}"#;
    let bundle = ga
        .commit_builder()
        .propose_group_context_extensions(ac_group_context_extensions(new_policy))
        .unwrap()
        .load_psks(pa.storage())
        .unwrap()
        .build(pa.rand(), pa.crypto(), &a.signer, |_| true)
        .unwrap()
        .stage_commit(&pa)
        .unwrap();
    ga.merge_pending_commit(&pa).unwrap();
    apply_commit(&mut gb, &pb, &wire(bundle.commit())).unwrap();
    assert_eq!(
        gb.extensions().unknown(EXT_GROUP_POLICY).unwrap().0,
        new_policy
    );
}

#[test]
fn member_without_required_capabilities_is_rejected() {
    let pa = Provider::new().unwrap();
    let a = Identity::new("ac:v0:alice", &pa);
    let mut ga = MlsGroup::new(&pa, &a.signer, &ac_config(), a.credential.clone()).unwrap();

    // C's leaf does not advertise the AgentConnect extensions.
    let pc = Provider::new().unwrap();
    let c = Identity::new("ac:v0:carol", &pc);
    let plain = Capabilities::builder().ciphersuites(vec![CS]).build();
    let kp = c.key_package(&pc, plain, Extensions::empty());
    let err = ga.add_members(&pa, &a.signer, &[kp]).unwrap_err();
    assert!(format!("{err:?}").contains("Capabilit"), "{err:?}");
}

#[test]
fn leaf_extension_not_in_own_capabilities() {
    // Gotcha: `KeyPackage::builder()` does not check that leaf extensions are
    // listed in the leaf's capabilities (RFC 9420 §7.2); the receiver does.
    let pc = Provider::new().unwrap();
    let c = Identity::new("ac:v0:carol", &pc);
    let plain = Capabilities::builder().ciphersuites(vec![CS]).build();
    let kp = c.key_package(&pc, plain, instance_cert_ext(CERT_B));

    let pa = Provider::new().unwrap();
    let a = Identity::new("ac:v0:alice", &pa);
    let mut ga = MlsGroup::new(&pa, &a.signer, &create_config(), a.credential.clone()).unwrap();
    let err = ga.add_members(&pa, &a.signer, &[kp]).unwrap_err();
    assert!(
        format!("{err:?}").contains("UnsupportedExtensions"),
        "{err:?}"
    );
}

#[test]
fn required_capabilities_do_not_require_presence() {
    // RequiredCapabilities only says "supports"; a leaf that advertises the
    // capability but carries no `ac_instance_cert` is accepted by OpenMLS.
    // The presence check (SPEC §3.1 MUST) is ours to do.
    let pa = Provider::new().unwrap();
    let a = Identity::new("ac:v0:alice", &pa);
    let mut ga = MlsGroup::new(&pa, &a.signer, &ac_config(), a.credential.clone()).unwrap();
    let pc = Provider::new().unwrap();
    let c = Identity::new("ac:v0:carol", &pc);
    let kp = c.key_package(&pc, ac_capabilities(), Extensions::empty());
    assert!(
        kp.leaf_node()
            .extensions()
            .unknown(EXT_INSTANCE_CERT)
            .is_none()
    );
    assert!(ga.add_members(&pa, &a.signer, &[kp]).is_ok());
}
