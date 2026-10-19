//! Malicious KeyPackages in JoinRequests (SPEC §3.1, §3.3, §6.2 step 3).
//!
//! The attacker holds the invite link (so the MAC is valid) and its own
//! signing key, so it can sign any KeyPackage it likes. Each one must be
//! rejected by `verify_join_request` with a typed error, never a panic.

mod common;

use agentconnect_core::encoding::b64_decode_array;
use agentconnect_core::join::join_request_mac;
use agentconnect_core::{EXT_INSTANCE_CERT, Error, HPKE_PUBLIC_KEY_LEN, Identity, Instance, Rng};
use common::*;
use ed25519_dalek::{Signer as _, SigningKey};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _, Size as _, VLBytes};
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialType, CredentialWithKey, Extension,
    ExtensionType, Extensions, KeyPackage, LeafNode, UnknownExtension,
};
use openmls_libcrux_crypto::Provider;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;

const CS: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;

struct TestSigner(SigningKey);

impl Signer for TestSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).to_bytes().to_vec())
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

fn signer_of(instance: &Instance) -> TestSigner {
    let json: serde_json::Value =
        serde_json::from_slice(&instance.to_secret_bytes().unwrap()).unwrap();
    let sk: [u8; 32] = b64_decode_array(json["sk"].as_str().unwrap(), "sk").unwrap();
    TestSigner(SigningKey::from_bytes(&sk))
}

fn ac_caps(cs: Ciphersuite) -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![cs])
        .extensions(vec![
            ExtensionType::Unknown(0xF0A1),
            ExtensionType::Unknown(0xF0A2),
            ExtensionType::Unknown(EXT_INSTANCE_CERT),
        ])
        .credentials(vec![CredentialType::Basic])
        .build()
}

fn cert_ext(instance: &Instance) -> Extensions<LeafNode> {
    Extensions::single(Extension::Unknown(
        EXT_INSTANCE_CERT,
        UnknownExtension(instance.cert().to_json().unwrap()),
    ))
    .unwrap()
}

/// What the attacker controls when building its KeyPackage.
struct Spec<'a> {
    cs: Ciphersuite,
    credential_identity: String,
    caps: Capabilities,
    leaf_exts: Extensions<LeafNode>,
    kp_exts: Extensions<KeyPackage>,
    last_resort: bool,
    signer: &'a Instance,
}

fn build(spec: &Spec) -> Vec<u8> {
    let p = Provider::new().unwrap();
    let signer = signer_of(spec.signer);
    let credential = CredentialWithKey {
        credential: BasicCredential::new(spec.credential_identity.as_bytes().to_vec()).into(),
        signature_key: spec.signer.public_key().to_vec().into(),
    };
    let mut builder = KeyPackage::builder()
        .leaf_node_capabilities(spec.caps.clone())
        .leaf_node_extensions(spec.leaf_exts.clone())
        .key_package_extensions(spec.kp_exts.clone());
    if spec.last_resort {
        builder = builder.mark_as_last_resort();
    }
    builder
        .build(spec.cs, &p, &signer, credential)
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}

fn honest(instance: &Instance) -> Spec<'_> {
    Spec {
        cs: CS,
        credential_identity: instance.identity().to_owned(),
        caps: ac_caps(CS),
        leaf_exts: cert_ext(instance),
        kp_exts: Extensions::empty(),
        last_resort: false,
        signer: instance,
    }
}

/// Re-signs `kp` with its `init_key` replaced by a 32-byte key (the
/// RUSTSEC-2026-0331 shape: validly signed, short hybrid key).
fn with_short_init_key(kp: &[u8], instance: &Instance) -> Vec<u8> {
    let mut rest = &kp[4..];
    let _init = VLBytes::tls_deserialize(&mut rest).unwrap();
    let sig_len = VLBytes::new(vec![0; 64]).tls_serialized_len();
    let body = &rest[..rest.len() - sig_len];
    let tbs = [
        &kp[..4],
        &VLBytes::new(
            Rng::for_test("short-init-key")
                .array::<32>()
                .unwrap()
                .to_vec(),
        )
        .tls_serialize_detached()
        .unwrap(),
        body,
    ]
    .concat();
    let content = [
        VLBytes::new(b"MLS 1.0 KeyPackageTBS".to_vec())
            .tls_serialize_detached()
            .unwrap(),
        VLBytes::new(tbs.clone()).tls_serialize_detached().unwrap(),
    ]
    .concat();
    let sig = signer_of(instance).sign(&content).unwrap();
    [tbs, VLBytes::new(sig).tls_serialize_detached().unwrap()].concat()
}

/// Submits `kp` with a valid MAC for a fresh invite and returns the result.
fn submit(kp: Vec<u8>, as_instance: &Instance) -> Result<(), Error> {
    let clock = clock();
    let inviter = peer(1, &clock);
    let inv = invite(&inviter);
    let mailbox_id = as_instance.mailbox_id();
    let mut req = agentconnect_core::JoinRequest {
        invite_id: *inv.secret().id(),
        display_name: "mallory".into(),
        mac: [0; 32],
        key_package: kp,
        mailbox_id,
    };
    req.mac = join_request_mac(&inv.secret().join_key(), &req.mac_input());
    inviter.client.verify_join_request(&req, &inv).map(|_| ())
}

fn mallory(seed: u64) -> (Identity, Instance) {
    let clock = clock();
    let id = Identity::generate(&Rng::for_test(&format!("seed-{seed}"))).unwrap();
    let inst = id
        .create_instance(
            &Rng::for_test(&format!("seed-{}", seed + 1)),
            clock.as_ref(),
        )
        .unwrap();
    (id, inst)
}

#[test]
fn honest_key_package_is_accepted() {
    let (_, m) = mallory(10);
    submit(build(&honest(&m)), &m).unwrap();
}

#[test]
fn short_hpke_init_key_is_rejected_without_panic() {
    // Regression test for RUSTSEC-2026-0331 (spikes/mls-xwing t9): this
    // KeyPackage passes OpenMLS validation. With libcrux-kem 0.0.9 it
    // crashed the committer; the fixed provider returns an error. The core
    // rejects it before OpenMLS either way (defence in depth, SPEC §3.1).
    let (_, m) = mallory(11);
    let kp = with_short_init_key(&build(&honest(&m)), &m);
    assert_eq!(submit(kp, &m), Err(Error::HpkeKeyLength));
    assert_eq!(HPKE_PUBLIC_KEY_LEN, 1216);
}

#[test]
fn wrong_ciphersuite_is_rejected() {
    let (_, m) = mallory(12);
    let classical = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let spec = Spec {
        cs: classical,
        caps: ac_caps(classical),
        ..honest(&m)
    };
    assert_eq!(submit(build(&spec), &m), Err(Error::WrongCiphersuite));
}

#[test]
fn missing_instance_cert_is_rejected() {
    let (_, m) = mallory(13);
    let spec = Spec {
        leaf_exts: Extensions::empty(),
        ..honest(&m)
    };
    assert_eq!(submit(build(&spec), &m), Err(Error::InvalidCert("missing")));
}

#[test]
fn invalid_instance_cert_is_rejected() {
    let (_, m) = mallory(14);
    let mut cert = String::from_utf8(m.cert().to_json().unwrap()).unwrap();
    // Flip one character of the signature.
    let at = cert.find("\"sig\":\"").unwrap() + 8;
    let c = if &cert[at..=at] == "A" { "B" } else { "A" };
    cert.replace_range(at..=at, c);
    let spec = Spec {
        leaf_exts: Extensions::single(Extension::Unknown(
            EXT_INSTANCE_CERT,
            UnknownExtension(cert.into_bytes()),
        ))
        .unwrap(),
        ..honest(&m)
    };
    assert!(matches!(
        submit(build(&spec), &m),
        Err(Error::InvalidCert(_))
    ));
}

#[test]
fn credential_identity_must_match_cert() {
    // Mallory signs with her own instance key and cert but claims Alice's
    // identity in the credential.
    let (_, m) = mallory(15);
    let (alice, _) = mallory(16);
    let spec = Spec {
        credential_identity: alice.id(),
        ..honest(&m)
    };
    assert_eq!(
        submit(build(&spec), &m),
        Err(Error::CredentialMismatch("cert identity != credential"))
    );
}

#[test]
fn leaf_key_must_match_cert() {
    // A certificate for another instance of the same identity.
    let (id, m) = mallory(17);
    let other = id
        .create_instance(&Rng::for_test("seed-99"), clock().as_ref())
        .unwrap();
    let spec = Spec {
        leaf_exts: cert_ext(&other),
        ..honest(&m)
    };
    assert_eq!(
        submit(build(&spec), &m),
        Err(Error::CredentialMismatch("cert sig_key != leaf key"))
    );
}

#[test]
fn non_ac_credential_identity_is_rejected() {
    let (_, m) = mallory(18);
    let spec = Spec {
        credential_identity: "mallory@example".into(),
        ..honest(&m)
    };
    assert_eq!(
        submit(build(&spec), &m),
        Err(Error::CredentialMismatch("credential identity"))
    );
}

#[test]
fn missing_capabilities_are_rejected() {
    let (_, m) = mallory(19);
    let spec = Spec {
        caps: Capabilities::builder().ciphersuites(vec![CS]).build(),
        leaf_exts: Extensions::empty(),
        ..honest(&m)
    };
    assert_eq!(
        submit(build(&spec), &m),
        Err(Error::InvalidKeyPackage("capabilities: extensions"))
    );
}

#[test]
fn extra_leaf_extension_is_rejected() {
    let (_, m) = mallory(20);
    let mut caps = ac_caps(CS);
    caps = Capabilities::builder()
        .ciphersuites(vec![CS])
        .extensions(
            caps.extensions()
                .iter()
                .copied()
                .chain([ExtensionType::Unknown(0xF0B0)])
                .collect(),
        )
        .credentials(vec![CredentialType::Basic])
        .build();
    let spec = Spec {
        caps,
        leaf_exts: Extensions::from_vec(vec![
            Extension::Unknown(
                EXT_INSTANCE_CERT,
                UnknownExtension(m.cert().to_json().unwrap()),
            ),
            Extension::Unknown(0xF0B0, UnknownExtension(vec![1])),
        ])
        .unwrap(),
        ..honest(&m)
    };
    assert_eq!(
        submit(build(&spec), &m),
        Err(Error::InvalidKeyPackage("unexpected leaf extension"))
    );
}

#[test]
fn key_package_extensions_are_rejected() {
    // SPEC §6.2: a KeyPackage carries no extensions of its own, last-resort
    // or any other.
    let (_, m) = mallory(22);
    let other = Spec {
        kp_exts: Extensions::single(Extension::Unknown(0xF0A1, UnknownExtension(vec![1]))).unwrap(),
        ..honest(&m)
    };
    // OpenMLS accepts the last-resort extension only if the leaf lists it.
    let last_resort = Spec {
        last_resort: true,
        caps: Capabilities::builder()
            .ciphersuites(vec![CS])
            .extensions(
                ac_caps(CS)
                    .extensions()
                    .iter()
                    .copied()
                    .chain([ExtensionType::LastResort])
                    .collect(),
            )
            .credentials(vec![CredentialType::Basic])
            .build(),
        ..honest(&m)
    };
    for spec in [other, last_resort] {
        assert_eq!(
            submit(build(&spec), &m),
            Err(Error::InvalidKeyPackage("unexpected key package extension"))
        );
    }
}

#[test]
fn tampered_or_truncated_key_package_is_rejected() {
    let (_, m) = mallory(21);
    let mut kp = build(&honest(&m));
    let at = kp.len() - 10;
    kp[at] ^= 1;
    assert_eq!(
        submit(kp.clone(), &m),
        Err(Error::InvalidKeyPackage("signature or lifetime"))
    );
    kp.truncate(kp.len() - 1);
    assert_eq!(submit(kp, &m), Err(Error::InvalidKeyPackage("encoding")));
}
