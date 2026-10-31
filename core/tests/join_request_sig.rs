//! The JoinRequest's `sig` (SPEC §6.1): it proves that the sender holds the
//! KeyPackage's private key, which the MAC doesn't. Anyone with the link can
//! MAC any KeyPackage, and a relay chooses the envelope's sender, so without
//! it a relay that got the link could have another identity added as a leaf
//! nobody controls. Each client here is a real one, so the check runs in its
//! place in `verify_join_request`, after the KeyPackage's.

mod common;

use agentconnect_core::encoding::b64_decode_array;
use agentconnect_core::join::join_request_mac;
use agentconnect_core::{Error, ErrorKind, Instance, JoinRequest};
use common::*;
use ed25519_dalek::{Signer as _, SigningKey};

fn signing_key(instance: &Instance) -> SigningKey {
    let json: serde_json::Value =
        serde_json::from_slice(&instance.to_secret_bytes().unwrap()).unwrap();
    SigningKey::from_bytes(&b64_decode_array(json["sk"].as_str().unwrap(), "sk").unwrap())
}

struct Setup {
    inviter: Peer,
    bob: Peer,
    mallory: Peer,
    invite: agentconnect_core::Invite,
    request: JoinRequest,
}

fn setup() -> Setup {
    let clock = clock();
    let inviter = peer(1, &clock);
    let bob = peer(2, &clock);
    let mallory = peer(3, &clock);
    let invite = invite(&inviter);
    let request = bob
        .client
        .create_join_request(invite.secret(), "bob")
        .unwrap();
    Setup {
        inviter,
        bob,
        mallory,
        invite,
        request,
    }
}

impl Setup {
    fn verify(&self, request: &JoinRequest) -> Result<bool, Error> {
        self.inviter
            .client
            .verify_join_request(request, &self.invite, &request.mailbox_id)
            .map(|v| v.possession_proven())
    }

    /// What a link holder can do: the MAC is valid over anything.
    fn remac(&self, request: &mut JoinRequest) {
        request.mac = join_request_mac(&self.invite.secret().join_key(), &request.mac_input());
    }
}

#[test]
fn a_joiner_signs_and_the_inviter_sees_possession_proven() {
    let s = setup();
    assert!(s.request.sig.is_some());
    assert!(s.verify(&s.request).unwrap());
}

#[test]
fn the_json_round_trip_keeps_the_signature() {
    let s = setup();
    let parsed = JoinRequest::from_json(&s.request.to_json().unwrap()).unwrap();
    assert_eq!(parsed.sig, s.request.sig);
    assert!(s.verify(&parsed).unwrap());
}

#[test]
fn a_request_without_a_signature_passes_but_proves_nothing() {
    let s = setup();
    let mut stripped = s.request.clone();
    stripped.sig = None;
    assert!(!s.verify(&stripped).unwrap());
    let json = stripped.to_json().unwrap();
    assert!(!String::from_utf8(json.clone()).unwrap().contains("\"sig\""));
    assert!(!s.verify(&JoinRequest::from_json(&json).unwrap()).unwrap());
}

#[test]
fn a_flipped_bit_fails_as_authentication() {
    let s = setup();
    let mut bad = s.request.clone();
    bad.sig.as_mut().unwrap()[0] ^= 1;
    let e = s.verify(&bad).unwrap_err();
    assert!(matches!(e, Error::BadJoinSignature), "{e}");
    assert_eq!(e.kind(), ErrorKind::Authentication);
}

#[test]
fn a_signature_by_another_key_fails() {
    let s = setup();
    let mut stolen = s.request.clone();
    let sig = signing_key(s.mallory.client.instance()).sign(&stolen.signing_input());
    stolen.sig = Some(sig.to_bytes());
    assert!(matches!(s.verify(&stolen), Err(Error::BadJoinSignature)));
}

#[test]
fn a_changed_field_with_a_new_mac_fails() {
    let s = setup();
    let mut renamed = s.request.clone();
    renamed.display_name = "alice".into();
    s.remac(&mut renamed);
    assert!(matches!(s.verify(&renamed), Err(Error::BadJoinSignature)));
}

#[test]
fn a_signature_from_another_request_of_the_same_joiner_fails() {
    let s = setup();
    let other = s
        .bob
        .client
        .create_join_request(s.invite.secret(), "bob")
        .unwrap();
    let mut spliced = s.request.clone();
    spliced.sig = other.sig;
    assert!(matches!(s.verify(&spliced), Err(Error::BadJoinSignature)));
}

#[test]
fn a_signature_for_another_invite_fails() {
    let s = setup();
    let elsewhere = invite(&s.inviter);
    let other = s
        .bob
        .client
        .create_join_request(elsewhere.secret(), "bob")
        .unwrap();
    let mut moved = other.clone();
    moved.invite_id = s.request.invite_id;
    s.remac(&mut moved);
    assert!(matches!(s.verify(&moved), Err(Error::BadJoinSignature)));
}

#[test]
fn a_stolen_key_package_cant_be_signed_for() {
    // The attack: the link and a copy of Bob's KeyPackage. The relay can set
    // the sender, so the sender check doesn't stop this; the signature does.
    let s = setup();
    let mut forged = s.request.clone();
    forged.sig = None;
    s.remac(&mut forged);
    assert!(
        !s.verify(&forged).unwrap(),
        "without a signature it must never read as proven"
    );
    let sig = signing_key(s.mallory.client.instance()).sign(&forged.signing_input());
    forged.sig = Some(sig.to_bytes());
    assert!(matches!(s.verify(&forged), Err(Error::BadJoinSignature)));
}

#[test]
fn a_signature_of_the_wrong_length_is_malformed() {
    let s = setup();
    let mut json: serde_json::Value =
        serde_json::from_slice(&s.request.to_json().unwrap()).unwrap();
    json["sig"] = serde_json::json!("c2hvcnQ");
    let e = JoinRequest::from_json(json.to_string().as_bytes()).unwrap_err();
    assert!(matches!(e, Error::Malformed(_)), "{e}");
}

#[test]
fn a_mac_failure_is_reported_before_the_signature() {
    let s = setup();
    let mut bad = s.request.clone();
    bad.mac[0] ^= 1;
    bad.sig.as_mut().unwrap()[0] ^= 1;
    assert!(matches!(s.verify(&bad), Err(Error::BadMac)));
}
