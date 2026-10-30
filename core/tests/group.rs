//! Group lifecycle and negative tests (SPEC §5–§9, §11).

mod common;

use std::time::Duration;

use agentconnect_core::group::{Event, MessageHeader, MessageKind, peek_header};
use agentconnect_core::policy::{Floor, InvitePermission};
use agentconnect_core::{Error, InviteLink, InviteMeta, InviteSecret, SqliteStore};
use common::*;

#[test]
fn one_to_one_create_join_talk() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    assert_converged(&peers, &groups);
    assert_eq!(groups[0].epoch(), 1);
    assert_eq!(groups[1].meta().unwrap().purpose, PURPOSE);
    let members = groups[1].members().unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].identity, peers[0].identity.id());
    assert_eq!(
        members[1].mailbox_id,
        peers[1].client.instance().mailbox_id()
    );

    let ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "hi B"))
        .unwrap();
    let msg = groups[1].open(&peers[1].client, &ct).unwrap();
    assert_eq!(msg.plaintext, inner(&peers[0], "hi B"));
    assert_eq!(msg.sender.identity, peers[0].identity.id());
    assert_eq!(
        msg.sender.instance_id,
        peers[0].client.instance().instance_id()
    );
    assert!(
        !format!("{msg:?}").contains("hi B"),
        "Debug must not show bodies"
    );

    let ct = groups[1]
        .seal(&peers[1].client, &inner(&peers[1], "hi A"))
        .unwrap();
    let Event::Application(m) = groups[0].process(&peers[0].client, &ct).unwrap() else {
        panic!("expected an application message");
    };
    assert_eq!(m.sender.identity, peers[1].identity.id());
    // The owner is the creator; 1:1 groups keep floor "free".
    assert_eq!(groups[0].policy().unwrap().owner, peers[0].identity.id());
    assert_eq!(groups[0].policy().unwrap().floor, Floor::Free);
}

#[test]
fn third_member_switches_floor_and_converges() {
    let clock = clock();
    let (peers, groups) = group_of(3, &clock);
    assert_converged(&peers, &groups);
    for g in &groups {
        assert_eq!(g.policy().unwrap().floor, Floor::Mention);
        assert_eq!(g.members().unwrap().len(), 3);
    }
    assert_eq!(groups[2].own_leaf_index(), 2);
    drop(peers);
}

#[test]
fn commit_summary_and_routing_match() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let c = peer(30, &clock);
    let (gc, out) = join(&peers[0], &mut groups[0], &c);
    assert_eq!(out.routing.add, vec![c.client.instance().mailbox_id()]);
    assert_eq!(out.epoch, 1);
    let summary = expect_commit(groups[1].process(&peers[1].client, &out.commit).unwrap());
    assert_eq!(summary.routing(), out.routing);
    assert_eq!(summary.added[0].identity, c.identity.id());
    assert_eq!(summary.committer.identity, peers[0].identity.id());
    assert!(summary.policy_changed);
    assert!(!summary.discarded_own_pending);
    groups.push(gc);
    assert_converged(&[&peers[0], &peers[1], &c], &groups);
}

#[test]
fn removed_member_cannot_decrypt_next_epoch() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let out = groups[0]
        .remove(&peers[0].client, &peers[2].identity.id())
        .unwrap();
    assert_eq!(
        out.routing.remove,
        vec![peers[2].client.instance().mailbox_id()]
    );
    groups[0]
        .confirm_pending_commit(&peers[0].client, &out.msg_id)
        .unwrap();
    let s = expect_commit(groups[1].process(&peers[1].client, &out.commit).unwrap());
    assert_eq!(s.removed[0].identity, peers[2].identity.id());
    let Event::Removed(_) = groups[2].process(&peers[2].client, &out.commit).unwrap() else {
        panic!("expected removal");
    };
    assert!(!groups[2].is_active());

    let ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "secret"))
        .unwrap();
    groups[1].open(&peers[1].client, &ct).unwrap();
    assert_eq!(groups[2].open(&peers[2].client, &ct), Err(Error::NotMember));
    assert_eq!(
        groups[2].seal(&peers[2].client, &inner(&peers[2], "x")),
        Err(Error::NotMember)
    );
}

/// Review F3: an application message sent in epoch e by a member that the
/// e -> e+1 commit removed arrives after that commit. It is inside the
/// grace window and must be delivered, attributed to that member (it used
/// to fail with `UnknownMember`, looked up in the new tree).
#[test]
fn grace_window_message_from_a_just_removed_member_is_delivered() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let msg = inner(&peers[2], "last words");
    let ct = groups[2].seal(&peers[2].client, &msg).unwrap();
    let out = groups[0]
        .remove(&peers[0].client, &peers[2].identity.id())
        .unwrap();
    groups[0]
        .confirm_pending_commit(&peers[0].client, &out.msg_id)
        .unwrap();
    expect_commit(groups[1].process(&peers[1].client, &out.commit).unwrap());
    for i in [0, 1] {
        let m = groups[i].open(&peers[i].client, &ct).unwrap();
        assert_eq!(m.sender.identity, peers[2].identity.id());
        assert_eq!(m.sender.mailbox_id, peers[2].client.instance().mailbox_id());
        assert_eq!(m.epoch, out.epoch);
        assert_eq!(m.plaintext, msg);
    }
    // Messages of the current epoch still resolve against the current tree.
    let ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "x"))
        .unwrap();
    assert_eq!(
        groups[1]
            .open(&peers[1].client, &ct)
            .unwrap()
            .sender
            .identity,
        peers[0].identity.id()
    );
}

#[test]
fn member_that_missed_its_removal_cannot_decrypt_either() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let out = groups[0]
        .remove(&peers[0].client, &peers[2].identity.id())
        .unwrap();
    groups[0]
        .confirm_pending_commit(&peers[0].client, &out.msg_id)
        .unwrap();
    let ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "secret"))
        .unwrap();
    // C never sees the removal commit and has no next-epoch secrets.
    assert_eq!(
        groups[2].open(&peers[2].client, &ct),
        Err(Error::WrongEpoch)
    );
    drop(out);
}

#[test]
fn tampered_and_replayed_messages_are_rejected() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "once"))
        .unwrap();
    let mut tampered = ct.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        groups[1].open(&peers[1].client, &tampered),
        Err(Error::Mls(_))
    ));

    let ct2 = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "twice"))
        .unwrap();
    groups[1].open(&peers[1].client, &ct2).unwrap();
    // Replay: the generation's key is gone.
    assert!(matches!(
        groups[1].open(&peers[1].client, &ct2),
        Err(Error::Mls(_))
    ));

    // Garbage, and messages for another group.
    assert_eq!(
        groups[1].process(&peers[1].client, b"junk"),
        Err(Error::Malformed("MLS message"))
    );
    let other = peers[0].client.create_group("other", "x").unwrap();
    let mut other = other;
    let foreign = other
        .seal(&peers[0].client, &inner(&peers[0], "x"))
        .unwrap();
    assert_eq!(
        groups[1].process(&peers[1].client, &foreign),
        Err(Error::WrongGroup)
    );
}

#[test]
fn inner_sender_must_match_mls_sender() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    // A claims to be B in the inner message.
    assert_eq!(
        groups[0].seal(&peers[0].client, &inner(&peers[1], "spoof")),
        Err(Error::CredentialMismatch("inner sender != MLS sender"))
    );
    assert_eq!(
        groups[0].seal(&peers[0].client, b"not json"),
        Err(Error::Malformed("inner message"))
    );
    let mut v = serde_json::from_slice::<serde_json::Value>(&inner(&peers[0], "x")).unwrap();
    v["instance_id"] = "0000000000000000".into();
    assert_eq!(
        groups[0].seal(&peers[0].client, &serde_json::to_vec(&v).unwrap()),
        Err(Error::CredentialMismatch("inner instance_id != MLS sender"))
    );
    v["v"] = 1.into();
    assert_eq!(
        groups[0].seal(&peers[0].client, &serde_json::to_vec(&v).unwrap()),
        Err(Error::UnsupportedVersion)
    );
}

#[test]
fn wrong_invite_secret_fails_mac_and_welcome() {
    let clock = clock();
    let a = peer(1, &clock);
    let b = peer(2, &clock);
    let mut ga = a.client.create_group(NAME, PURPOSE).unwrap();
    let inv = invite(&a);
    let wrong_secret = agentconnect_core::Rng::for_test("wrong-secret")
        .array::<32>()
        .unwrap();
    let wrong = InviteSecret::from_parts(*inv.secret().id(), &wrong_secret);
    let req = b.client.create_join_request(&wrong, "b").unwrap();
    assert_eq!(
        a.client
            .verify_join_request(&req, &inv, &req.mailbox_id)
            .unwrap_err(),
        Error::BadMac
    );

    // Right MAC, but the joiner unwraps with the wrong secret: rejected
    // before MLS touches the KeyPackage, so a retry with the right secret works.
    let req = b.client.create_join_request(inv.secret(), "b").unwrap();
    let verified = a
        .client
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    assert_eq!(verified.identity(), b.identity.id());
    assert_eq!(verified.display_name(), "b");
    assert_eq!(verified.mailbox_id(), b.client.instance().mailbox_id());
    assert_eq!(verified.instance_id(), b.client.instance().instance_id());
    // The same request verified twice (a replay) has the same ref; another
    // request (fresh KeyPackage) has another.
    let again = a
        .client
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    assert_eq!(again.key_package_ref(), verified.key_package_ref());
    assert!(!verified.key_package_ref().is_empty());
    let other = b.client.create_join_request(inv.secret(), "b").unwrap();
    let other = a
        .client
        .verify_join_request(&other, &inv, &other.mailbox_id)
        .unwrap();
    assert_ne!(other.key_package_ref(), verified.key_package_ref());
    let out = ga.add_member(&a.client, &verified, &inv, true).unwrap();
    ga.confirm_pending_commit(&a.client, &out.msg_id).unwrap();
    let wrapped = out.welcome.unwrap();
    assert_eq!(
        b.client
            .join_from_wrapped_welcome(
                &wrong,
                &InviteMeta::expected(wrong.id(), NAME, PURPOSE),
                &wrapped
            )
            .unwrap_err(),
        Error::WelcomeAuth
    );
    let mut tampered = wrapped.clone();
    tampered[20] ^= 1;
    assert_eq!(
        b.client
            .join_from_wrapped_welcome(inv.secret(), &meta_for(&inv), &tampered)
            .unwrap_err(),
        Error::WelcomeAuth
    );
    let gb = b
        .client
        .join_from_wrapped_welcome(inv.secret(), &meta_for(&inv), &wrapped)
        .unwrap();
    assert!(same_view(&b.client, &gb, &a.client, &ga));
}

#[test]
fn join_request_for_another_invite_or_expired_is_rejected() {
    let clock = clock();
    let a = peer(1, &clock);
    let b = peer(2, &clock);
    let inv = invite(&a);
    let other = invite(&a);
    let req = b.client.create_join_request(other.secret(), "b").unwrap();
    assert_eq!(
        a.client
            .verify_join_request(&req, &inv, &req.mailbox_id)
            .unwrap_err(),
        Error::InviteMismatch
    );
    let req = b.client.create_join_request(inv.secret(), "b").unwrap();
    clock.advance(Duration::from_secs(3600));
    assert_eq!(
        a.client
            .verify_join_request(&req, &inv, &req.mailbox_id)
            .unwrap_err(),
        Error::InviteExpired
    );
    assert_eq!(
        b.client
            .create_join_request(inv.secret(), &"x".repeat(81))
            .unwrap_err(),
        Error::Malformed("display_name")
    );
}

/// Review F7: a JoinRequest replayed after its joiner left must not re-add
/// the joiner's certified identity as a leaf nobody controls.
#[test]
fn replayed_join_request_cannot_re_add_a_departed_member() {
    let clock = clock();
    let a = peer(1, &clock);
    let b = peer(2, &clock);
    let mut ga = a.client.create_group(NAME, PURPOSE).unwrap();
    let inv = invite(&a);
    let link = InviteLink::parse(&inv.url()).unwrap();
    let req = b.client.create_join_request(link.secret(), "b").unwrap();
    let v = a
        .client
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    let out = ga.add_member(&a.client, &v, &inv, true).unwrap();
    ga.confirm_pending_commit(&a.client, &out.msg_id).unwrap();
    let mut gb = b
        .client
        .join_from_wrapped_welcome(
            link.secret(),
            &meta_for(&inv),
            out.welcome.as_ref().unwrap(),
        )
        .unwrap();
    assert!(!ga.has_pending_proposals());
    let leave = gb.propose_leave(&b.client).unwrap();
    ga.process(&a.client, &leave).unwrap();
    assert!(ga.has_pending_proposals());
    let out = ga.commit_pending_proposals(&a.client).unwrap();
    ga.confirm_pending_commit(&a.client, &out.msg_id).unwrap();
    assert!(!ga.has_pending_proposals());
    assert_eq!(ga.members().unwrap().len(), 1);

    // The relay replays B's JoinRequest while the invite still has uses.
    assert_eq!(
        a.client
            .verify_join_request(&req, &inv, &req.mailbox_id)
            .unwrap_err(),
        Error::KeyPackageReused
    );
    // A copy verified before the first Add is refused as well.
    assert_eq!(
        ga.add_member(&a.client, &v, &inv, true).unwrap_err(),
        Error::KeyPackageReused
    );
    assert_eq!(ga.members().unwrap().len(), 1);
    assert!(!ga.has_pending_commit());
}

/// Review F8: a failed `add_member` must not use up the verified request.
#[test]
fn verified_join_request_survives_a_failed_add() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let c = peer(60, &clock);
    let inv = invite(&peers[0]);
    let req = c.client.create_join_request(inv.secret(), "c").unwrap();
    let v = peers[0]
        .client
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    groups[0].update(&peers[0].client).unwrap();
    assert_eq!(
        groups[0]
            .add_member(&peers[0].client, &v, &inv, true)
            .unwrap_err(),
        Error::CommitPending
    );
    groups[0].discard_pending_commit(&peers[0].client).unwrap();
    // The Add itself loses an epoch race and is rebuilt from the same request.
    groups[0]
        .add_member(&peers[0].client, &v, &inv, true)
        .unwrap();
    groups[0].discard_pending_commit(&peers[0].client).unwrap();
    let out = groups[0]
        .add_member(&peers[0].client, &v, &inv, true)
        .unwrap();
    groups[0]
        .confirm_pending_commit(&peers[0].client, &out.msg_id)
        .unwrap();
    expect_commit(groups[1].process(&peers[1].client, &out.commit).unwrap());
    let gc = c
        .client
        .join_from_wrapped_welcome(inv.secret(), &meta_for(&inv), out.welcome.as_ref().unwrap())
        .unwrap();
    groups.push(gc);
    assert_converged(&[&peers[0], &peers[1], &c], &groups);
}

/// The MAC covers `display_name` (SPEC §6.1): the relay can't rename the
/// joiner whose request the inviter's human approves.
#[test]
fn relay_cannot_rename_the_joiner() {
    let clock = clock();
    let a = peer(1, &clock);
    let b = peer(2, &clock);
    let inv = invite(&a);
    let req = b.client.create_join_request(inv.secret(), "bob").unwrap();
    let json = String::from_utf8(req.to_json().unwrap()).unwrap();
    let renamed = agentconnect_core::JoinRequest::from_json(
        json.replace("\"bob\"", "\"your admin\"").as_bytes(),
    )
    .unwrap();
    assert_eq!(
        a.client
            .verify_join_request(&renamed, &inv, &renamed.mailbox_id)
            .unwrap_err(),
        Error::BadMac
    );
    assert_eq!(
        b.client
            .create_join_request(inv.secret(), "bob\u{1b}[2J")
            .unwrap_err(),
        Error::Malformed("display_name")
    );
    assert_eq!(
        a.client
            .verify_join_request(&req, &inv, &req.mailbox_id)
            .unwrap()
            .display_name(),
        "bob"
    );
}

#[test]
fn mailbox_must_match_key_package() {
    let clock = clock();
    let a = peer(1, &clock);
    let b = peer(2, &clock);
    let inv = invite(&a);
    let mut req = b.client.create_join_request(inv.secret(), "b").unwrap();
    req.mailbox_id = a.client.instance().mailbox_id();
    req.mac = agentconnect_core::join::join_request_mac(&inv.secret().join_key(), &req.mac_input());
    assert_eq!(
        a.client
            .verify_join_request(&req, &inv, &req.mailbox_id)
            .unwrap_err(),
        Error::CredentialMismatch("mailbox_id != key package signature key")
    );
}

/// SPEC §6.2 step 3: a link holder who saw someone else's unused
/// KeyPackage (in a request to their own invite) re-MACs it under another
/// link. Every other check passes, so only the sender check stops the Add
/// of a leaf nobody controls.
#[test]
fn a_request_from_another_mailbox_is_refused() {
    let clock = clock();
    let c = peer(1, &clock); // the inviter
    let v = peer(2, &clock); // whose KeyPackage it is
    let m = peer(3, &clock); // the link holder
    let inv_m = invite(&m);
    let from_v = v.client.create_join_request(inv_m.secret(), "v").unwrap();
    let inv_c = invite(&c);
    let mut forged = from_v.clone();
    forged.invite_id = *inv_c.secret().id();
    forged.mac =
        agentconnect_core::join::join_request_mac(&inv_c.secret().join_key(), &forged.mac_input());
    let m_mailbox = m.client.instance().mailbox_id();
    assert_eq!(
        c.client
            .verify_join_request(&forged, &inv_c, &m_mailbox)
            .unwrap_err(),
        Error::CredentialMismatch("sender is not the request's mailbox_id")
    );
    // The check comes after the MAC: a request that fails both is a bad MAC.
    let mut both = forged.clone();
    both.mac[0] ^= 1;
    assert_eq!(
        c.client
            .verify_join_request(&both, &inv_c, &m_mailbox)
            .unwrap_err(),
        Error::BadMac
    );
    // From its own mailbox the same KeyPackage verifies.
    c.client
        .verify_join_request(&forged, &inv_c, &from_v.mailbox_id)
        .unwrap();
}

#[test]
fn welcome_meta_must_match_invite_meta() {
    let clock = clock();
    let a = peer(1, &clock);
    let b = peer(2, &clock);
    let mut ga = a.client.create_group(NAME, PURPOSE).unwrap();
    let inv = invite(&a);
    let req = b.client.create_join_request(inv.secret(), "b").unwrap();
    let verified = a
        .client
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    let out = ga.add_member(&a.client, &verified, &inv, true).unwrap();
    let wrong_meta = InviteMeta::expected(inv.secret().id(), NAME, "something else");
    assert_eq!(
        b.client
            .join_from_wrapped_welcome(inv.secret(), &wrong_meta, out.welcome.as_ref().unwrap())
            .unwrap_err(),
        Error::MetaMismatch
    );
    // Meta for a different invite id is refused outright.
    let foreign = InviteMeta::expected(&[0; 16], NAME, PURPOSE);
    assert_eq!(
        b.client
            .join_from_wrapped_welcome(inv.secret(), &foreign, out.welcome.as_ref().unwrap())
            .unwrap_err(),
        Error::InviteMismatch
    );
    // The KeyPackage was consumed by the failed attempt (SPEC §6.3).
    assert!(
        b.client
            .join_from_wrapped_welcome(inv.secret(), &meta_for(&inv), out.welcome.as_ref().unwrap())
            .is_err()
    );
}

#[test]
fn non_welcome_payload_is_rejected() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let inv = invite(&peers[0]);
    let ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "x"))
        .unwrap();
    let wrapped = inv
        .secret()
        .wrap_welcome(peers[0].client.rng(), &ct)
        .unwrap();
    assert_eq!(
        peers[1]
            .client
            .join_from_wrapped_welcome(inv.secret(), &meta_for(&inv), &wrapped)
            .unwrap_err(),
        Error::UnexpectedMessage("not a Welcome")
    );
    let wrapped = inv
        .secret()
        .wrap_welcome(peers[0].client.rng(), b"junk")
        .unwrap();
    assert_eq!(
        peers[1]
            .client
            .join_from_wrapped_welcome(inv.secret(), &meta_for(&inv), &wrapped)
            .unwrap_err(),
        Error::Malformed("welcome")
    );
}

#[test]
fn members_may_not_remove_or_change_policy_locally() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    assert_eq!(
        groups[1]
            .remove(&peers[1].client, &peers[2].identity.id())
            .unwrap_err(),
        Error::NotPermitted("this identity may not remove members")
    );
    let mut p = groups[1].policy().unwrap();
    p.require_verified = true;
    assert_eq!(
        groups[1].set_policy(&peers[1].client, &p).unwrap_err(),
        Error::Unauthorized("committer may not change this policy")
    );
    // The rejected commit was not left pending.
    assert!(!groups[1].has_pending_commit());
    assert_eq!(
        groups[0]
            .remove(&peers[0].client, "ac:v0:nobody")
            .unwrap_err(),
        Error::UnknownMember
    );
    // Member may not invite under the default policy.
    let c = peer(40, &clock);
    let inv = invite(&peers[1]);
    let req = c.client.create_join_request(inv.secret(), "c").unwrap();
    let v = peers[1]
        .client
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    assert_eq!(
        groups[1]
            .add_member(&peers[1].client, &v, &inv, true)
            .unwrap_err(),
        Error::NotPermitted("this identity may not invite")
    );
}

#[test]
fn owner_policy_change_round_trips() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let mut p = groups[0].policy().unwrap();
    p.invite = InvitePermission::Members;
    p.admins = vec![peers[1].identity.id()];
    let out = groups[0].set_policy(&peers[0].client, &p).unwrap();
    assert_eq!(
        groups[0].seal(&peers[0].client, &inner(&peers[0], "x")),
        Err(Error::CommitPending)
    );
    let s = groups[0]
        .confirm_pending_commit(&peers[0].client, &out.msg_id)
        .unwrap();
    assert!(s.policy_changed);
    let s = expect_commit(groups[1].process(&peers[1].client, &out.commit).unwrap());
    assert!(s.policy_changed);
    assert_eq!(groups[1].policy().unwrap(), p);
    assert_converged(&peers, &groups);

    // Admin may change the floor only.
    let mut floor = p.clone();
    floor.floor = Floor::Moderated;
    floor.floor_moderator = Some(peers[1].identity.id());
    let out = groups[1].set_policy(&peers[1].client, &floor).unwrap();
    groups[1]
        .confirm_pending_commit(&peers[1].client, &out.msg_id)
        .unwrap();
    expect_commit(groups[0].process(&peers[0].client, &out.commit).unwrap());
    assert_converged(&peers, &groups);

    // Now a member may invite: B adds C.
    let c = peer(50, &clock);
    let (gc, out) = {
        let (a, b) = groups.split_at_mut(1);
        let r = join(&peers[1], &mut b[0], &c);
        expect_commit(a[0].process(&peers[0].client, &r.1.commit).unwrap());
        r
    };
    groups.push(gc);
    assert_converged(&[&peers[0], &peers[1], &c], &groups);
    drop(out);
}

#[test]
fn update_commits_converge_and_change_sas() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let before = run_codes(&peers[0].client, &groups[0], &peers[1].client, &groups[1]).0;
    let out = groups[1].update(&peers[1].client).unwrap();
    groups[1]
        .confirm_pending_commit(&peers[1].client, &out.msg_id)
        .unwrap();
    for i in [0, 2] {
        expect_commit(groups[i].process(&peers[i].client, &out.commit).unwrap());
    }
    assert_converged(&peers, &groups);
    let after = run_codes(&peers[0].client, &groups[0], &peers[1].client, &groups[1]).0;
    assert_ne!(after, before);
}

#[test]
fn epoch_conflict_discard_process_rebuild() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let a = groups[0].update(&peers[0].client).unwrap();
    let _b = groups[1].update(&peers[1].client).unwrap();
    assert_eq!(
        groups[1].update(&peers[1].client).unwrap_err(),
        Error::CommitPending
    );
    // The relay accepts A's commit; B gets epoch_conflict.
    groups[0]
        .confirm_pending_commit(&peers[0].client, &a.msg_id)
        .unwrap();
    groups[1].discard_pending_commit(&peers[1].client).unwrap();
    assert_eq!(
        groups[1].discard_pending_commit(&peers[1].client),
        Err(Error::NoPendingCommit)
    );
    expect_commit(groups[1].process(&peers[1].client, &a.commit).unwrap());
    expect_commit(groups[2].process(&peers[2].client, &a.commit).unwrap());
    let b = groups[1].update(&peers[1].client).unwrap();
    assert_eq!(b.epoch, a.epoch + 1);
    groups[1]
        .confirm_pending_commit(&peers[1].client, &b.msg_id)
        .unwrap();
    for i in [0, 2] {
        expect_commit(groups[i].process(&peers[i].client, &b.commit).unwrap());
    }
    assert_converged(&peers, &groups);
}

#[test]
fn winner_commit_drops_pending_commit() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let a = groups[0].update(&peers[0].client).unwrap();
    groups[0]
        .confirm_pending_commit(&peers[0].client, &a.msg_id)
        .unwrap();
    let _b = groups[1].update(&peers[1].client).unwrap();
    let s = expect_commit(groups[1].process(&peers[1].client, &a.commit).unwrap());
    assert!(s.discarded_own_pending);
    assert!(!groups[1].has_pending_commit());
    assert_converged(&peers, &groups);
}

#[test]
fn own_commit_echo_confirms() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let out = groups[0].update(&peers[0].client).unwrap();
    let Event::OwnCommitConfirmed(s) = groups[0].process(&peers[0].client, &out.commit).unwrap()
    else {
        panic!("expected confirmation");
    };
    assert_eq!(s.epoch, 2);
    assert!(!groups[0].has_pending_commit());
    expect_commit(groups[1].process(&peers[1].client, &out.commit).unwrap());
    assert_converged(&peers, &groups);
    // A second echo after confirmation is an old-epoch echo, nothing more.
    assert_eq!(
        groups[0].process(&peers[0].client, &out.commit),
        Ok(Event::OwnEcho)
    );
    assert_eq!(groups[0].epoch(), 2);
    // A late `accepted` for it finds nothing pending.
    assert_eq!(
        groups[0].confirm_pending_commit(&peers[0].client, &out.msg_id),
        Err(Error::NoPendingCommit)
    );
}

#[test]
fn accepted_confirms_only_its_own_msg_id_and_later_echo_is_harmless() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let first = groups[0].update(&peers[0].client).unwrap();
    groups[0].discard_pending_commit(&peers[0].client).unwrap();
    let out = groups[0].update(&peers[0].client).unwrap();
    assert_ne!(first.msg_id, out.msg_id);
    assert_eq!(out.msg_id.len(), 22, "base64url of 16 bytes");
    // `accepted` for the discarded commit's msg_id confirms nothing.
    assert_eq!(
        groups[0].confirm_pending_commit(&peers[0].client, &first.msg_id),
        Err(Error::PendingCommitMismatch)
    );
    assert!(groups[0].has_pending_commit());
    assert_eq!(groups[0].epoch(), 1);
    let s = groups[0]
        .confirm_pending_commit(&peers[0].client, &out.msg_id)
        .unwrap();
    assert_eq!(s.epoch, 2);
    // The fan-out copy arrives after `accepted`.
    assert_eq!(
        groups[0].process(&peers[0].client, &out.commit),
        Ok(Event::OwnEcho)
    );
    expect_commit(groups[1].process(&peers[1].client, &out.commit).unwrap());
    assert_converged(&peers, &groups);
}

/// Review F1, honest relay: A's commit X was accepted but A timed out,
/// discarded it and built Y at the same epoch. The fan-out then delivers X.
/// Before the fix A merged Y on seeing "its own commit" while B merged X:
/// same epoch, different state (a fork).
#[test]
fn stale_own_commit_is_not_taken_for_the_pending_one() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let x = groups[0].update(&peers[0].client).unwrap();
    groups[0].discard_pending_commit(&peers[0].client).unwrap();
    let _y = groups[0].update(&peers[0].client).unwrap();
    let epoch = groups[0].epoch();

    assert_eq!(
        groups[0].process(&peers[0].client, &x.commit),
        Err(Error::OwnCommitLost)
    );
    // Y was not merged: it is discarded, and A knows it has to re-sync.
    assert_eq!(groups[0].epoch(), epoch);
    assert!(!groups[0].has_pending_commit());
    // B follows X; A did not silently fork to Y's state.
    expect_commit(groups[1].process(&peers[1].client, &x.commit).unwrap());
    assert_ne!(groups[0].epoch(), groups[1].epoch());

    // Same when nothing was pending any more.
    let (peers, mut groups) = group_of_seeded(2, 10, &clock);
    let x = groups[0].update(&peers[0].client).unwrap();
    groups[0].discard_pending_commit(&peers[0].client).unwrap();
    assert_eq!(
        groups[0].process(&peers[0].client, &x.commit),
        Err(Error::OwnCommitLost)
    );
}

#[test]
fn forked_group_view_gives_different_sas() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    // A and B commit concurrently. A malicious relay confirms both senders
    // and gives A's commit to C: A and C share a view, B is forked off.
    let a = groups[0].update(&peers[0].client).unwrap();
    let b = groups[1].update(&peers[1].client).unwrap();
    groups[0]
        .confirm_pending_commit(&peers[0].client, &a.msg_id)
        .unwrap();
    groups[1]
        .confirm_pending_commit(&peers[1].client, &b.msg_id)
        .unwrap();
    expect_commit(groups[2].process(&peers[2].client, &a.commit).unwrap());
    assert!(groups.iter().all(|g| g.epoch() == groups[0].epoch()));
    let (p, g) = (&peers, &groups);
    assert!(same_view(&p[0].client, &g[0], &p[2].client, &g[2]));
    let (a, b) = run_codes(&p[0].client, &g[0], &p[1].client, &g[1]);
    assert_ne!(a, b);
    assert_ne!(a.decimal(), b.decimal());
}

#[test]
fn two_parallel_groups_have_different_sas() {
    // SPEC §14.4: the attacker runs one group with A and another with B.
    let clock = clock();
    let (p1, g1) = group_of(2, &clock);
    let (p2, g2) = group_of_seeded(2, 100, &clock);
    let one = run_codes(&p1[0].client, &g1[0], &p1[1].client, &g1[1]);
    let two = run_codes(&p2[0].client, &g2[0], &p2[1].client, &g2[1]);
    assert_eq!(one.0, one.1);
    assert_eq!(two.0, two.1);
    assert_ne!(one.0, two.0);
}

#[test]
fn leave_via_remove_proposal() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let proposal = groups[2].propose_leave(&peers[2].client).unwrap();
    for i in [0, 1] {
        let Event::LeaveProposed(m) = groups[i].process(&peers[i].client, &proposal).unwrap()
        else {
            panic!("expected a leave proposal");
        };
        assert_eq!(m.identity, peers[2].identity.id());
    }
    // B (a plain member) commits C's leave: allowed for self-removals.
    let out = groups[1]
        .commit_pending_proposals(&peers[1].client)
        .unwrap();
    assert_eq!(
        out.routing.remove,
        vec![peers[2].client.instance().mailbox_id()]
    );
    groups[1]
        .confirm_pending_commit(&peers[1].client, &out.msg_id)
        .unwrap();
    expect_commit(groups[0].process(&peers[0].client, &out.commit).unwrap());
    let Event::Removed(_) = groups[2].process(&peers[2].client, &out.commit).unwrap() else {
        panic!("expected removal");
    };
    groups.truncate(2);
    assert_converged(&peers[..2], &groups);
    assert_eq!(
        groups[0]
            .commit_pending_proposals(&peers[0].client)
            .unwrap_err(),
        Error::NothingToCommit
    );
    // A sole member doesn't propose; it deletes its state.
    let mut solo = peers[0].client.create_group("solo", "").unwrap();
    assert_eq!(
        solo.propose_leave(&peers[0].client).unwrap_err(),
        Error::NotPermitted("sole member: delete the local state instead")
    );
    solo.delete(&peers[0].client).unwrap();
}

const OWNER_MUST_TRANSFER: Error =
    Error::NotPermitted("the owner must transfer ownership before leaving");

#[test]
fn owner_may_not_leave_without_transferring_ownership() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    assert_eq!(
        groups[0].propose_leave(&peers[0].client).unwrap_err(),
        OWNER_MUST_TRANSFER
    );
    assert!(!groups[0].has_pending_commit());
    // Plain members still may.
    groups[1].propose_leave(&peers[1].client).unwrap();
}

#[test]
fn owner_may_leave_after_transferring_ownership() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let mut p = groups[0].policy().unwrap();
    p.owner = peers[1].identity.id();
    let out = groups[0].set_policy(&peers[0].client, &p).unwrap();
    groups[0]
        .confirm_pending_commit(&peers[0].client, &out.msg_id)
        .unwrap();
    for i in [1, 2] {
        expect_commit(groups[i].process(&peers[i].client, &out.commit).unwrap());
    }
    let proposal = groups[0].propose_leave(&peers[0].client).unwrap();
    for i in [1, 2] {
        let Event::LeaveProposed(m) = groups[i].process(&peers[i].client, &proposal).unwrap()
        else {
            panic!("expected a leave proposal");
        };
        assert_eq!(m.identity, peers[0].identity.id());
    }
    let out = groups[2]
        .commit_pending_proposals(&peers[2].client)
        .unwrap();
    groups[2]
        .confirm_pending_commit(&peers[2].client, &out.msg_id)
        .unwrap();
    expect_commit(groups[1].process(&peers[1].client, &out.commit).unwrap());
    let Event::Removed(_) = groups[0].process(&peers[0].client, &out.commit).unwrap() else {
        panic!("expected removal");
    };
    groups.remove(0);
    assert_converged(&[&peers[1], &peers[2]], &groups);
    assert_eq!(groups[0].policy().unwrap().owner, peers[1].identity.id());
}

#[test]
fn one_of_several_owner_instances_may_leave() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let a2 = replica(&peers[0].identity, 78, &clock);
    let (mut ga2, out) = join(&peers[0], &mut groups[0], &a2);
    expect_commit(groups[1].process(&peers[1].client, &out.commit).unwrap());
    let proposal = ga2.propose_leave(&a2.client).unwrap();
    groups[0].process(&peers[0].client, &proposal).unwrap();
    groups[1].process(&peers[1].client, &proposal).unwrap();
    // With A2's leave pending, A is now the owner's last instance.
    assert_eq!(
        groups[0].propose_leave(&peers[0].client).unwrap_err(),
        OWNER_MUST_TRANSFER
    );
    let out = groups[1]
        .commit_pending_proposals(&peers[1].client)
        .unwrap();
    groups[1]
        .confirm_pending_commit(&peers[1].client, &out.msg_id)
        .unwrap();
    expect_commit(groups[0].process(&peers[0].client, &out.commit).unwrap());
    let Event::Removed(_) = ga2.process(&a2.client, &out.commit).unwrap() else {
        panic!("expected removal");
    };
    assert_converged(&peers, &groups);
}

#[test]
fn multi_replica_identity_joins_and_is_removed_together() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    // B's second instance joins via an invite from A.
    let b2 = replica(&peers[1].identity, 77, &clock);
    let (gb2, out) = join(&peers[0], &mut groups[0], &b2);
    for i in [1, 2] {
        expect_commit(groups[i].process(&peers[i].client, &out.commit).unwrap());
    }
    groups.push(gb2);
    assert_converged(&[&peers[0], &peers[1], &peers[2], &b2], &groups);
    assert_eq!(groups[2].members().unwrap().len(), 4);
    // Removing B's identity removes both instances, for every member.
    let out = groups[0]
        .remove(&peers[0].client, &peers[1].identity.id())
        .unwrap();
    // OpenMLS orders the proposals; compare as sets.
    let mut removed = out.routing.remove.clone();
    removed.sort();
    let mut expected = vec![
        peers[1].client.instance().mailbox_id(),
        b2.client.instance().mailbox_id(),
    ];
    expected.sort();
    assert_eq!(removed, expected);
    groups[0]
        .confirm_pending_commit(&peers[0].client, &out.msg_id)
        .unwrap();
    let seen_by_c = expect_commit(groups[2].process(&peers[2].client, &out.commit).unwrap());
    assert_eq!(seen_by_c.removed.len(), 2);
    assert!(
        seen_by_c
            .removed
            .iter()
            .all(|m| m.identity == peers[1].identity.id())
    );
    assert_eq!(seen_by_c.routing(), out.routing);
    for (g, p) in [(1, &peers[1]), (3, &b2)] {
        let Event::Removed(_) = groups[g].process(&p.client, &out.commit).unwrap() else {
            panic!("replica {g} should see its removal");
        };
    }
    let remaining = [peers[0].identity.id(), peers[2].identity.id()];
    for g in [0, 2] {
        let ids: Vec<String> = groups[g]
            .members()
            .unwrap()
            .into_iter()
            .map(|m| m.identity)
            .collect();
        assert_eq!(ids, remaining);
    }
    assert!(same_view(
        &peers[0].client,
        &groups[0],
        &peers[2].client,
        &groups[2]
    ));
}

#[test]
fn padding_hides_length_within_a_bucket() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let base = inner(&peers[0], "").len();
    // 940 + 2 (length prefix) + 66 (signature) + 16 (tag) = 1024.
    let sizes: Vec<usize> = [0, 50, 940 - base]
        .iter()
        .map(|extra| {
            let msg = inner(&peers[0], &"x".repeat(*extra));
            let ct = groups[0].seal(&peers[0].client, &msg).unwrap();
            groups[1].open(&peers[1].client, &ct).unwrap();
            ct.len()
        })
        .collect();
    assert!(sizes.iter().all(|s| *s == sizes[0]), "{sizes:?}");
    let bigger = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], &"x".repeat(941 - base)))
        .unwrap();
    assert_eq!(bigger.len(), sizes[0] + 4096 - 1024, "next bucket");
    let huge = vec![b' '; agentconnect_core::padding::max_plaintext_len() + 1];
    assert_eq!(
        groups[0].seal(&peers[0].client, &huge),
        Err(Error::TooLarge)
    );
}

/// The relay's frame limit (SPEC §8.3).
const RELAY_FRAME_MAX: usize = 2 << 20;

/// SPEC §8.3 and §10.2: a maximal 256 KiB application message, and the
/// largest plaintext `seal` accepts at all (the 1 MiB bucket), both fit one
/// relay frame once sealed, base64url-encoded and put in an envelope.
#[test]
fn largest_application_message_fits_the_relay_frame() {
    use agentconnect_core::encoding::b64;
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let base = inner(&peers[0], "").len();
    for len in [256 << 10, agentconnect_core::padding::max_plaintext_len()] {
        let msg = inner(&peers[0], &"x".repeat(len - base));
        assert_eq!(msg.len(), len);
        let ct = groups[0].seal(&peers[0].client, &msg).unwrap();
        // The relay test of the same limit assumes at most 256 bytes of MLS
        // framing around the 1 MiB bucket.
        assert!(
            ct.len() <= (1 << 20) + 256,
            "sealed message exceeds the 1 MiB bucket plus framing"
        );
        let frame = serde_json::json!({
            "t": "send",
            "env": {
                "v": 0,
                "kind": "application",
                "group_id": b64(groups[0].group_id()),
                "epoch": u64::MAX,
                "msg_id": b64(&[0xff; 16]),
                "sender": peers[0].client.instance().mailbox_id(),
                "ct": b64(&ct),
            },
        })
        .to_string();
        assert!(frame.len() <= RELAY_FRAME_MAX, "{}", frame.len());
        assert_eq!(
            groups[1].open(&peers[1].client, &ct).unwrap().plaintext,
            msg
        );
    }
}

#[test]
fn sqlite_store_persists_across_reopen() {
    let clock = clock();
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("core-sqlite-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let a = peer(1, &clock);
    let db_key =
        agentconnect_core::DbKey::generate(&agentconnect_core::Rng::for_test("db-key")).unwrap();
    let b_identity =
        agentconnect_core::Identity::generate(&agentconnect_core::Rng::for_test("seed-2")).unwrap();
    let b_instance = b_identity
        .create_instance(&agentconnect_core::Rng::for_test("seed-3"), clock.as_ref())
        .unwrap();
    let saved_instance = b_instance.to_secret_bytes().unwrap();
    let open = |inst| {
        agentconnect_core::Client::new(
            SqliteStore::open(&path, &db_key).unwrap(),
            agentconnect_core::Rng::os().unwrap(),
            inst,
            clock.clone(),
        )
        .unwrap()
    };
    let b = open(b_instance);
    let mut ga = a.client.create_group(NAME, PURPOSE).unwrap();
    let inv = invite(&a);
    let link = InviteLink::parse(&inv.url()).unwrap();
    let req = b.create_join_request(link.secret(), "b").unwrap();
    let v = a
        .client
        .verify_join_request(&req, &inv, &req.mailbox_id)
        .unwrap();
    let out = ga.add_member(&a.client, &v, &inv, true).unwrap();
    ga.confirm_pending_commit(&a.client, &out.msg_id).unwrap();
    let gid = b
        .join_from_wrapped_welcome(
            link.secret(),
            &meta_for(&inv),
            out.welcome.as_ref().unwrap(),
        )
        .unwrap()
        .group_id()
        .to_vec();
    drop(b);

    let b = open(agentconnect_core::Instance::from_secret_bytes(&saved_instance).unwrap());
    let mut gb = b.load_group(&gid).unwrap().unwrap();
    assert!(same_view(&b, &gb, &a.client, &ga));
    let ct = ga.seal(&a.client, &inner(&a, "persisted")).unwrap();
    gb.open(&b, &ct).unwrap();
    assert!(b.load_group(&[0; 16]).unwrap().is_none());
    assert!(format!("{gb:?} {b:?}").contains("Group"));
    drop(b);
    let _ = std::fs::remove_file(&path);
    assert!(SqliteStore::open_in_memory().is_ok());
}

#[test]
fn real_ciphertexts_follow_padding_vectors() {
    // testdata/padding-vectors.json: within one length-prefix class, the
    // serialised message minus its bucket is a per-group constant.
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/padding-vectors.json"
    ))
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let base = inner(&peers[0], "").len();
    let mut overheads = std::collections::BTreeSet::new();
    for case in v["cases"].as_array().unwrap() {
        let (Some(len), Some(bucket)) = (case["plaintext_len"].as_u64(), case["bucket"].as_u64())
        else {
            continue;
        };
        let (len, bucket) = (
            usize::try_from(len).unwrap(),
            usize::try_from(bucket).unwrap(),
        );
        if len < base || bucket > 4096 {
            continue;
        }
        let msg = inner(&peers[0], &"x".repeat(len - base));
        assert_eq!(msg.len(), len);
        let ct = groups[0].seal(&peers[0].client, &msg).unwrap();
        groups[1].open(&peers[1].client, &ct).unwrap();
        overheads.insert(ct.len() - bucket);
    }
    assert_eq!(overheads.len(), 1, "{overheads:?}");
}

#[test]
fn event_kind_names_the_variant_without_content() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "secret body"))
        .unwrap();
    let event = groups[1].process(&peers[1].client, &ct).unwrap();
    assert_eq!(event.kind(), "application");

    let out = groups[0]
        .remove(&peers[0].client, &peers[2].identity.id())
        .unwrap();
    let seen = groups[1].process(&peers[1].client, &out.commit).unwrap();
    assert_eq!(seen.kind(), "commit");
    let removed = groups[2].process(&peers[2].client, &out.commit).unwrap();
    assert_eq!(removed.kind(), "removed");
    assert_eq!(Event::OwnEcho.kind(), "own_echo");
}

/// SPEC §7.1: the receiver compares the envelope with the unprotected
/// `PrivateMessage` header before processing anything.
#[test]
fn peek_header_reads_group_epoch_and_content_type() {
    let clock = clock();
    let (peers, mut groups) = group_of(3, &clock);
    let gid = groups[0].group_id().to_vec();
    let epoch = groups[0].epoch();

    let ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "peeked"))
        .unwrap();
    let head = peek_header(&ct).unwrap();
    assert_eq!(
        head,
        MessageHeader {
            group_id: gid.clone(),
            epoch,
            content_type: MessageKind::Application,
        }
    );
    assert_eq!(head.content_type.as_str(), "application");

    let proposal = groups[2].propose_leave(&peers[2].client).unwrap();
    let head = peek_header(&proposal).unwrap();
    assert_eq!(
        (head.epoch, head.content_type.as_str()),
        (epoch, "proposal")
    );

    let out = groups[1].update(&peers[1].client).unwrap();
    let head = peek_header(&out.commit).unwrap();
    assert_eq!(head.group_id, gid);
    assert_eq!(
        (head.epoch, head.content_type),
        (epoch, MessageKind::Commit)
    );
    assert_eq!(MessageKind::Commit.as_str(), "commit");
}

/// A peek is not processing: a message whose envelope epoch disagrees with
/// its header is dropped without consuming its key, and the same bytes
/// still process under a correct envelope.
#[test]
fn peek_header_consumes_no_key() {
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "kept"))
        .unwrap();
    let claimed = groups[1].epoch() + 1; // what a lying envelope says
    for _ in 0..3 {
        assert_ne!(peek_header(&ct).unwrap().epoch, claimed);
    }
    let msg = groups[1].open(&peers[1].client, &ct).unwrap();
    assert_eq!(msg.epoch, groups[1].epoch());
    // Processing does consume it.
    assert!(matches!(
        groups[1].open(&peers[1].client, &ct),
        Err(Error::Mls(_))
    ));
    assert_eq!(peek_header(&ct).unwrap().epoch, groups[1].epoch());
}

#[test]
fn peek_header_validates_like_process() {
    assert_eq!(peek_header(b"junk"), Err(Error::Malformed("MLS message")));
    assert_eq!(peek_header(b""), Err(Error::Malformed("MLS message")));
    let clock = clock();
    let (peers, mut groups) = group_of(2, &clock);
    let mut ct = groups[0]
        .seal(&peers[0].client, &inner(&peers[0], "x"))
        .unwrap();
    // Trailing bytes: exact deserialisation, as for `process`.
    ct.push(0);
    assert_eq!(peek_header(&ct), Err(Error::Malformed("MLS message")));
    assert_eq!(
        groups[1].process(&peers[1].client, &ct),
        Err(Error::Malformed("MLS message"))
    );
}
