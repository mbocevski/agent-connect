//! Spike item 9: RUSTSEC-2026-0331 (libcrux-kem 0.0.9, "Panic on Decoding
//! Short Hybrid Keys") through the OpenMLS provider.
//!
//! A KeyPackage `init_key` or a leaf `encryption_key` is attacker-chosen
//! (the attacker signs its own KeyPackage), and the committer HPKE-seals to
//! it. With libcrux-kem 0.0.9, sealing to a short X-Wing key panicked, so a
//! malicious joiner could crash the inviter's daemon. With the fixed
//! libcrux-kem 0.0.10 (the provider patch in the workspace Cargo.toml) it is
//! an error.

use std::panic::{AssertUnwindSafe, catch_unwind};

use agentconnect_spike_mls_xwing::*;
use openmls::prelude::{tls_codec::*, *};
use openmls_libcrux_crypto::Provider;
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto, signatures::Signer};

/// A validly signed KeyPackage whose `init_key` is 32 bytes instead of 1216.
/// The attacker owns the signing key, so it can sign anything.
fn malicious_key_package(p: &Provider, id: &Identity) -> Vec<u8> {
    let kp = id.key_package(p, ac_capabilities(), instance_cert_ext(b"{}"));
    let bytes = kp.tls_serialize_detached().unwrap();
    // KeyPackage = version(2) ‖ suite(2) ‖ init_key<V> ‖ leaf_node ‖ extensions<V> ‖ signature<V>
    let mut rest = &bytes[4..];
    let _init_key = VLBytes::tls_deserialize(&mut rest).unwrap();
    let sig_len = VLBytes::new(vec![0; 64]).tls_serialized_len(); // 64-byte Ed25519 sig + varint
    let body = &rest[..rest.len() - sig_len];
    let tbs = [
        &bytes[..4],
        &VLBytes::new(vec![7u8; 32])
            .tls_serialize_detached()
            .unwrap(),
        body,
    ]
    .concat();
    // SignWithLabel(sk, "KeyPackageTBS", tbs) (RFC 9420 §5.1.2).
    let sign_content = [
        VLBytes::new(b"MLS 1.0 KeyPackageTBS".to_vec())
            .tls_serialize_detached()
            .unwrap(),
        VLBytes::new(tbs.clone()).tls_serialize_detached().unwrap(),
    ]
    .concat();
    let sig = id.signer.sign(&sign_content).unwrap();
    [tbs, VLBytes::new(sig).tls_serialize_detached().unwrap()].concat()
}

#[test]
fn malicious_key_package_is_an_error_not_a_crash() {
    let pm = Provider::new().unwrap();
    let mallory = Identity::new("ac:v0:mallory", &pm);
    let bytes = malicious_key_package(&pm, &mallory);

    let pa = Provider::new().unwrap();
    let a = Identity::new("ac:v0:alice", &pa);
    let mut ga = MlsGroup::new(&pa, &a.signer, &create_config(), a.credential.clone()).unwrap();

    // OpenMLS validation accepts it: the signature is valid and no key
    // length is checked.
    let kp = KeyPackageIn::tls_deserialize_exact(bytes)
        .unwrap()
        .validate(pa.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    assert_eq!(kp.hpke_init_key().as_slice().len(), 32);

    // Committing the Add seals the Welcome secrets to the short key.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        ga.add_members(&pa, &a.signer, &[kp]).map(|_| ())
    }));
    // RUSTSEC-2026-0331: libcrux-kem 0.0.9 panicked here. The fixed release
    // returns an error, so the inviter rejects the Add and keeps running.
    match outcome {
        Ok(Err(_)) => {}
        Ok(Ok(())) => panic!("committing an Add with a short init_key must fail"),
        Err(_) => panic!("RUSTSEC-2026-0331: sealing to a short init_key panics"),
    }
}

#[test]
fn hpke_seal_to_short_xwing_key() {
    let p = Provider::new().unwrap();
    let short_pk = [7u8; 32]; // an X-Wing public key is 1216 bytes
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        p.crypto()
            .hpke_seal(CS.hpke_config(), &short_pk, b"info", b"aad", b"secret")
    }));
    match outcome {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("sealing to a short key must not succeed"),
        Err(_) => panic!("RUSTSEC-2026-0331: sealing to a short key panics"),
    }
}

#[test]
fn wg_track_suite_0x004f_also_runs_on_libcrux() {
    // MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 (draft-ietf-mls-pq-ciphersuites
    // TBD1, OpenMLS provisional 0x004F) maps to the same X-Wing KEM in OpenMLS.
    // Since upstream openmls#2274 the provider also advertises it.
    let cs = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;
    let p = Provider::new().unwrap();
    assert!(p.crypto().supports(cs).is_ok());
    assert!(p.crypto().supported_ciphersuites().contains(&cs));
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(cs)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let a = Identity::new("ac:v0:alice", &p);
    assert!(MlsGroup::new(&p, &a.signer, &config, a.credential.clone()).is_ok());
}
