//! Shared helpers for the group integration tests: in-memory peers and a
//! complete invite → join flow, with a trivially honest "relay".

#![allow(dead_code)]

use std::borrow::Borrow;
use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::clock::FakeClock;
use agentconnect_core::group::{CommitOut, Event};
use agentconnect_core::{
    Client, Group, Identity, Invite, InviteLink, InviteMeta, MemoryStore, Rng, Sas, SasNonce, Store,
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
        other => panic!("expected a commit, got {}", other.kind()),
    }
}

/// Both sides' codes of a SAS run between `ca` in `ga` and `cb` in `gb`
/// (SPEC §11.4). The nonces come from a fixed test RNG, so two calls with
/// unchanged groups give the same codes.
pub fn run_codes<S1: Store, S2: Store>(
    ca: &Client<S1>,
    ga: &Group,
    cb: &Client<S2>,
    gb: &Group,
) -> (Sas, Sas) {
    let rng = Rng::for_test("sas-run");
    let (na, nb) = (
        SasNonce::generate(&rng).unwrap(),
        SasNonce::generate(&rng).unwrap(),
    );
    let (a, b) = (ca.instance(), cb.instance());
    let code_a = ga
        .sas_code(
            ca,
            ga.epoch(),
            &na,
            b.identity(),
            b.instance_id(),
            nb.expose(),
        )
        .unwrap();
    let code_b = gb
        .sas_code(
            cb,
            gb.epoch(),
            &nb,
            a.identity(),
            a.instance_id(),
            na.expose(),
        )
        .unwrap();
    (code_a, code_b)
}

/// Whether a SAS run between the two instances shows both humans the same
/// code: the same view of the group, except with probability 2^-48.
pub fn same_view<S1: Store, S2: Store>(
    ca: &Client<S1>,
    ga: &Group,
    cb: &Client<S2>,
    gb: &Group,
) -> bool {
    let (x, y) = run_codes(ca, ga, cb, gb);
    x == y
}

/// Every member at the same epoch and with the same view: a SAS run
/// between each member and one of another identity gives equal codes.
pub fn assert_converged<P: std::borrow::Borrow<Peer>>(peers: &[P], groups: &[Group]) {
    assert_eq!(peers.len(), groups.len(), "one peer per group");
    let peers: Vec<&Peer> = peers.iter().map(Borrow::borrow).collect();
    let epoch = groups[0].epoch();
    for (i, g) in groups.iter().enumerate() {
        assert_eq!(g.epoch(), epoch, "member {i}");
        let id = peers[i].client.instance().identity();
        let Some(k) = (0..groups.len()).find(|&k| peers[k].client.instance().identity() != id)
        else {
            continue;
        };
        assert!(
            same_view(&peers[i].client, g, &peers[k].client, &groups[k]),
            "members {i} and {k}"
        );
        if k != 0 && peers[0].client.instance().identity() != id {
            assert!(same_view(&peers[i].client, g, &peers[0].client, &groups[0]));
        }
    }
}
