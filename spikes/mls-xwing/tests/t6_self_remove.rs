//! Spike item 6: leaving a group (SPEC §9.2).
//!
//! OpenMLS 0.9 implements the SelfRemove proposal, but only as a
//! `PublicMessage`, which conflicts with the PrivateMessage-only policy of
//! SPEC §3.1. A Remove proposal of one's own leaf works under that policy.

use agentconnect_spike_mls_xwing::*;
use openmls::prelude::*;

/// Hand a proposal to `committer`, which commits it; everyone else applies.
fn commit_proposal(m: &mut [Peer], leaver: usize, committer: usize, proposal: &[u8]) {
    for (i, x) in m.iter_mut().enumerate() {
        if i == leaver {
            continue;
        }
        let processed = x
            .group
            .process_message(&x.provider, protocol_message(proposal))
            .unwrap();
        let ProcessedMessageContent::ProposalMessage(p) = processed.into_content() else {
            panic!("expected a proposal");
        };
        x.group
            .store_pending_proposal(x.provider.storage(), *p)
            .unwrap();
    }
    let c = &mut m[committer];
    let (commit, _, _) = c
        .group
        .commit_to_pending_proposals(&c.provider, &c.id.signer)
        .unwrap();
    c.group.merge_pending_commit(&c.provider).unwrap();
    let commit = wire(&commit);
    for (i, x) in m.iter_mut().enumerate() {
        if i != committer {
            apply_commit(&mut x.group, &x.provider, &commit).unwrap();
        }
    }
}

#[test]
fn self_remove_refused_under_pure_ciphertext() {
    let mut m = group_of(3, &create_config());
    let b = &mut m[1];
    let err = b
        .group
        .leave_group_via_self_remove(&b.provider, &b.id.signer)
        .unwrap_err();
    assert!(matches!(
        err,
        LeaveGroupError::CannotSelfRemoveWithPureCiphertext
    ));
}

#[test]
fn self_remove_works_with_plaintext_handshakes() {
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CS)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(ac_capabilities())
        .build();
    let mut m = group_of(3, &config);
    let b = &mut m[1];
    let proposal = wire(
        &b.group
            .leave_group_via_self_remove(&b.provider, &b.id.signer)
            .unwrap(),
    );
    commit_proposal(&mut m, 1, 0, &proposal);
    assert!(!m[1].group.is_active());
    assert_eq!(m[0].group.members().count(), 2);
    assert_eq!(sas_bytes(&m[0].group), sas_bytes(&m[2].group));
}

#[test]
fn remove_own_leaf_proposal_works_under_pure_ciphertext() {
    let mut m = group_of(3, &create_config());
    let b = &mut m[1];
    let proposal = wire(&b.group.leave_group(&b.provider, &b.id.signer).unwrap());
    commit_proposal(&mut m, 1, 2, &proposal);
    assert!(!m[1].group.is_active());
    assert_eq!(m[0].group.members().count(), 2);
    assert_eq!(sas_bytes(&m[0].group), sas_bytes(&m[2].group));
}
