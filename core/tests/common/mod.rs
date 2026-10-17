//! Shared helpers for the group integration tests: in-memory peers and a
//! complete invite → join flow, with a trivially honest "relay".

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::clock::FakeClock;
use agentconnect_core::group::{CommitOut, Event};
use agentconnect_core::{
    Client, Group, Identity, Invite, InviteLink, InviteMeta, MemoryStore, Rng,
};

pub const RELAY: &str = "relay.example";
pub const NAME: &str = "Trip planning";
pub const PURPOSE: &str = "Plan the offsite";

/// One instance with in-memory storage.
pub struct Peer {
    pub identity: Identity,
    pub client: Client<MemoryStore>,
}

/// Seeded and deterministic: the seed picks the identity and instance keys.
pub fn peer(seed: u64, clock: &Arc<FakeClock>) -> Peer {
    let rng = Rng::for_test(&format!("seed-{seed}"));
    let identity = Identity::generate(&rng).unwrap();
    replica(&identity, seed + 1_000_000, clock)
}

/// Another instance of `identity`.
pub fn replica(identity: &Identity, seed: u64, clock: &Arc<FakeClock>) -> Peer {
    let rng = Rng::for_test(&format!("seed-{seed}"));
    let instance = identity.create_instance(&rng, clock.as_ref()).unwrap();
    let client = Client::new(
        MemoryStore::new(),
        Rng::for_test(&format!("seed-{}", seed ^ 0xA5A5)),
        instance,
        clock.clone(),
    )
    .unwrap();
    let identity = Identity::from_secret_bytes(&identity.secret_bytes());
    Peer { identity, client }
}

pub fn clock() -> Arc<FakeClock> {
    Arc::new(FakeClock::default())
}

pub fn inner(peer: &Peer, text: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "v": 0,
        "seq": 1,
        "sender": peer.client.instance().identity(),
        "instance_id": peer.client.instance().cert().instance_id_hex(),
        "to": ["*"],
        "hop": 0,
        "origin": "agent",
        "kind": "a2a.message",
        "body": {"text": text},
    }))
    .unwrap()
}

pub fn invite(peer: &Peer) -> Invite {
    Invite::create(
        peer.client.rng(),
        peer.client.clock(),
        RELAY,
        Duration::from_secs(3600),
    )
    .unwrap()
}

pub fn meta_for(invite: &Invite) -> InviteMeta {
    InviteMeta::expected(invite.secret().id(), NAME, PURPOSE)
}

/// The whole SPEC §6 flow, with the relay confirming the commit. Returns
/// the joiner's group and the commit for the other existing members.
pub fn join(inviter: &Peer, group: &mut Group, joiner: &Peer) -> (Group, CommitOut) {
    let inv = invite(inviter);
    let link = InviteLink::parse(&inv.url()).unwrap();
    let req = joiner
        .client
        .create_join_request(link.secret(), "joiner")
        .unwrap();
    let req = agentconnect_core::JoinRequest::from_json(&req.to_json().unwrap()).unwrap();
    let verified = inviter.client.verify_join_request(&req, &inv).unwrap();
    let out = group
        .add_member(&inviter.client, &verified, &inv, true)
        .unwrap();
    group
        .confirm_pending_commit(&inviter.client, &out.msg_id)
        .unwrap();
    let joined = joiner
        .client
        .join_from_wrapped_welcome(
            link.secret(),
            &meta_for(&inv),
            out.welcome.as_ref().unwrap(),
        )
        .unwrap();
    (joined, out)
}

/// A group of `n` peers: peer 0 created it and invited the rest one by one.
pub fn group_of(n: usize, clock: &Arc<FakeClock>) -> (Vec<Peer>, Vec<Group>) {
    group_of_seeded(n, 0, clock)
}

/// [`group_of`] with peer seeds starting at `base + 1`.
pub fn group_of_seeded(n: usize, base: u64, clock: &Arc<FakeClock>) -> (Vec<Peer>, Vec<Group>) {
    let peers: Vec<Peer> = (0..n as u64).map(|i| peer(base + i + 1, clock)).collect();
    let mut groups = vec![peers[0].client.create_group(NAME, PURPOSE).unwrap()];
    for j in 1..n {
        let (head, _) = groups.split_at_mut(1);
        let (g, out) = join(&peers[0], &mut head[0], &peers[j]);
        for (k, existing) in groups.iter_mut().enumerate().skip(1) {
            expect_commit(existing.process(&peers[k].client, &out.commit).unwrap());
        }
        groups.push(g);
    }
    (peers, groups)
}

pub fn expect_commit(event: Event) -> agentconnect_core::CommitSummary {
    match event {
        Event::Commit(s) => s,
        other => panic!("expected a commit, got {other:?}"),
    }
}

pub fn assert_converged(groups: &[Group]) {
    let first = (groups[0].epoch(), groups[0].sas());
    for g in groups {
        assert_eq!((g.epoch(), g.sas()), first);
    }
}
