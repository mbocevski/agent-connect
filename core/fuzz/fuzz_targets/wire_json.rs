//! Fuzz target: the JSON and binary objects a daemon reads off the wire
//! outside MLS: JoinRequests, invite links and metadata, instance
//! certificates, the group extensions, wrapped Welcomes and identity
//! exports.
#![no_main]

use agentconnect_core::export::{identity_export_identity, unwrap_identity_export};
use agentconnect_core::{
    GroupMeta, GroupPolicy, InstanceCert, InviteLink, InviteMeta, InviteSecret, JoinRequest,
};
use libfuzzer_sys::fuzz_target;

// The relay supplies JoinRequests, InviteMeta and wrapped Welcomes; a peer
// supplies certificates and extensions inside MLS; a human pastes links and
// export files. No parser may panic, and every canonical (JCS) parser
// accepts exactly its own encoding.
fuzz_target!(|data: &[u8]| {
    if let Ok(req) = JoinRequest::from_json(data) {
        let again = JoinRequest::from_json(&req.to_json().unwrap()).unwrap();
        assert_eq!(again, req);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(link) = InviteLink::parse(text) {
            let again = InviteLink::parse(&link.url()).unwrap();
            assert_eq!(again.url(), link.url());
        }
        if let Ok(code) = std::str::from_utf8(&data[..data.len().min(43)]) {
            let _ = unwrap_identity_export(data, code);
        }
    }
    let _ = InviteMeta::from_json(data);
    if let Ok(cert) = InstanceCert::from_json(data) {
        assert_eq!(cert.to_json().unwrap(), data);
    }
    if let Ok(meta) = GroupMeta::from_json(data) {
        assert_eq!(meta.to_json().unwrap(), data);
    }
    if let Ok(policy) = GroupPolicy::from_json(data) {
        // A policy written before `floor_pinned` existed still reads, so
        // only re-parsing is required to agree.
        assert_eq!(
            GroupPolicy::from_json(&policy.to_json().unwrap()).unwrap(),
            policy
        );
    }
    let _ = identity_export_identity(data);
    // The invite id and secret come from the input, so the fuzzer can't
    // learn one fixed key.
    if let (Some(id), Some(secret)) = (data.get(..16), data.get(16..48)) {
        let id: [u8; 16] = id.try_into().unwrap();
        let secret: [u8; 32] = secret.try_into().unwrap();
        let invite = InviteSecret::from_parts(id, &secret);
        let _ = invite.unwrap_welcome(&data[48..]);
    }
});
