//! Fuzz target: KeyPackages in JoinRequests, and Welcomes.
#![no_main]

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::clock::FakeClock;
use agentconnect_core::join::join_request_mac;
use agentconnect_core::{
    Client, Group, Identity, Invite, InviteLink, InviteMeta, JoinRequest, MemoryStore, Rng,
};
use libfuzzer_sys::fuzz_target;

// Whoever holds an invite link can MAC any KeyPackage, so the inviter's
// KeyPackage checks (SPEC §6.2 step 3) see attacker bytes; the checks run
// before OpenMLS parses them. A Welcome is AEAD-wrapped under the invite,
// so its TLS framing and the §3.1 KEM length checks see bytes only an
// inviter (or a link holder) chooses; this target wraps the mutated
// Welcome itself. Nothing may panic, and a mutated KeyPackage never
// verifies. The first byte picks the target and the base to mutate.
struct State {
    alice: Client<MemoryStore>,
    bob: Client<MemoryStore>,
    invite: Invite,
    link: InviteLink,
    meta: InviteMeta,
    request: JoinRequest,
    welcome: Vec<u8>,
    // A failed join may spend the KeyPackage; rebuild now and then so
    // later Welcomes still reach the checks behind it.
    tries: u32,
}

fn peer(label: &str, clock: &Arc<FakeClock>) -> Client<MemoryStore> {
    let rng = Rng::for_test(label);
    let identity = Identity::generate(&rng).unwrap();
    let instance = identity.create_instance(&rng, clock.as_ref()).unwrap();
    Client::new(
        MemoryStore::new(),
        Rng::for_test(&format!("{label}/client")),
        instance,
        clock.clone(),
    )
    .unwrap()
}

fn build() -> State {
    let clock = Arc::new(FakeClock::default());
    let alice = peer("fuzz/alice", &clock);
    let bob = peer("fuzz/bob", &clock);
    let mut group: Group = alice.create_group("Fuzz", "Fuzz the joiner").unwrap();
    let invite = Invite::create(
        alice.rng(),
        alice.clock(),
        "relay.example",
        Duration::from_secs(3600),
    )
    .unwrap();
    let link = InviteLink::parse(&invite.url()).unwrap();
    let request = bob.create_join_request(link.secret(), "joiner").unwrap();
    let verified = alice.verify_join_request(&request, &invite).unwrap();
    let out = group.add_member(&alice, &verified, &invite, true).unwrap();
    let welcome = link
        .secret()
        .unwrap_welcome(out.welcome.as_ref().unwrap())
        .unwrap();
    let meta = InviteMeta::expected(invite.secret().id(), "Fuzz", "Fuzz the joiner");
    State {
        alice,
        bob,
        invite,
        link,
        meta,
        request,
        welcome,
        tries: 0,
    }
}

fn mutate(base: &[u8], edits: &[u8]) -> Vec<u8> {
    let mut bytes = base.to_vec();
    for edit in edits.chunks_exact(3) {
        let at = usize::from(u16::from_be_bytes([edit[0], edit[1]]));
        match bytes.len() {
            0 => break,
            n if at % 7 == 6 => bytes.truncate(at % n),
            n => bytes[at % n] ^= edit[2] | 1,
        }
    }
    bytes
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, edits)) = data.split_first() else {
        return;
    };
    // An unmodified Welcome joins; that only forces a rebuild.
    if pick % 3 == 2 && edits.len() < 3 {
        return;
    }
    STATE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let s = slot.get_or_insert_with(build);
        match pick % 3 {
            0 | 1 => {
                let key_package = if pick % 3 == 0 {
                    mutate(&s.request.key_package, edits)
                } else {
                    edits.to_vec()
                };
                let mut request = s.request.clone();
                request.key_package = key_package;
                request.mac = join_request_mac(&s.invite.secret().join_key(), &request.mac_input());
                let verified = s.alice.verify_join_request(&request, &s.invite);
                if request.key_package != s.request.key_package {
                    assert!(verified.is_err(), "a mutated KeyPackage verified");
                }
            }
            _ => {
                let welcome = mutate(&s.welcome, edits);
                let wrapped = s
                    .link
                    .secret()
                    .wrap_welcome(s.alice.rng(), &welcome)
                    .unwrap();
                let joined = s
                    .bob
                    .join_from_wrapped_welcome(s.link.secret(), &s.meta, &wrapped);
                s.tries += 1;
                // The unmodified Welcome joined, or the KeyPackage may be
                // spent: start over with a fresh one.
                if joined.is_ok() || s.tries >= 256 {
                    *slot = None;
                }
            }
        }
    });
});
