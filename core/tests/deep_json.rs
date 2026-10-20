//! JSON nested far deeper than any honest message (the v0 security review,
//! SR-11). Every parser of peer, relay or directory JSON refuses it without
//! running out of stack: `serde_json` stops at 128 levels, and nothing here
//! turns that limit off. An inner message (SPEC §7.2) is read by the core
//! only for its head (`v`, `sender`, `instance_id`), and the rest is
//! skipped without recursing, so a deep unknown field passes the core
//! unparsed and the receiver's own depth limit (SPEC §7.2, 64 levels) drops
//! it.

mod common;

use agentconnect_core::encoding::{from_jcs, parse_json_unique_keys};
use agentconnect_core::export::identity_export_identity;
use agentconnect_core::group::Event;
use agentconnect_core::knock::Knock;
use agentconnect_core::listing::{
    ListingCard, ListingContent, ListingToken, OwnerFile, SignedListing, TokenRevocation,
    Withdrawal,
};
use agentconnect_core::{GroupMeta, GroupPolicy, InstanceCert, InviteMeta, JoinRequest};
use common::{clock, group_of};

/// Just past `serde_json`'s limit, and far past it.
const DEPTHS: [usize; 2] = [129, 10_000];

fn arrays(depth: usize) -> Vec<u8> {
    [b"[".repeat(depth), b"]".repeat(depth)].concat()
}

fn objects(depth: usize) -> Vec<u8> {
    [br#"{"a":"#.repeat(depth), b"1".to_vec(), b"}".repeat(depth)].concat()
}

/// Deep JSON on its own, and as a field of an object the parser expects.
fn inputs(depth: usize) -> Vec<Vec<u8>> {
    let mut out = vec![arrays(depth), objects(depth)];
    for deep in [arrays(depth), objects(depth)] {
        out.push([br#"{"v":0,"x":"#.to_vec(), deep, b"}".to_vec()].concat());
    }
    out
}

#[test]
fn every_parser_refuses_deep_json() {
    for depth in DEPTHS {
        for data in inputs(depth) {
            assert!(parse_json_unique_keys(&data, "deep").is_err());
            assert!(from_jcs::<serde_json::Value>(&data, "deep").is_err());
            assert!(JoinRequest::from_json(&data).is_err());
            assert!(InviteMeta::from_json(&data).is_err());
            assert!(InstanceCert::from_json(&data).is_err());
            assert!(GroupMeta::from_json(&data).is_err());
            assert!(GroupPolicy::from_json(&data).is_err());
            assert!(identity_export_identity(&data).is_err());
            assert!(SignedListing::from_bytes(&data).is_err());
            assert!(ListingContent::from_json(&data).is_err());
            assert!(ListingCard::from_unsigned_json(&data).is_err());
            assert!(ListingToken::from_json(&data).is_err());
            assert!(TokenRevocation::from_json(&data).is_err());
            assert!(Withdrawal::from_json(&data).is_err());
            assert!(OwnerFile::parse(&data).is_err());
            assert!(Knock::from_json(&data).is_err());
        }
    }
}

#[test]
fn a_deep_unknown_field_in_an_inner_message_is_skipped_without_recursing() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let head = format!(
        r#"{{"v":0,"sender":"{}","instance_id":"{}","x":"#,
        peers[0].client.instance().identity(),
        peers[0].client.instance().cert().instance_id_hex(),
    );
    let depth = 200_000;
    let inner = [head.into_bytes(), arrays(depth), b"}".to_vec()].concat();
    let ct = groups[0].seal(&peers[0].client, &inner).unwrap();
    let (_, rest) = groups.split_at_mut(1);
    match rest[0].process(&peers[1].client, &ct).unwrap() {
        Event::Application(m) => assert_eq!(m.plaintext, inner),
        other => panic!("expected an application message, got {}", other.kind()),
    }
}
