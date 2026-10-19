//! Fuzz target: MLS messages a member receives from the relay.
#![no_main]

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::clock::FakeClock;
use agentconnect_core::group::peek_header;
use agentconnect_core::{
    Client, Group, Identity, Invite, InviteLink, InviteMeta, MemoryStore, Rng,
};
use libfuzzer_sys::fuzz_target;

// The relay chooses every byte a member processes, and so does any member
// for the ciphertext under its own keys. `peek_header` runs on every
// envelope before MLS, and `process`/`open` on what passes. Nothing may
// panic. The first byte picks a valid message to mutate (an application
// message, a commit with an update path, a leave proposal) or the raw
// input; the rest flips bytes in it, so the fuzzer gets past the TLS
// framing to the checks behind it.
struct State {
    alice: Client<MemoryStore>,
    group: Group,
    base: [Vec<u8>; 3],
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

fn join(
    inviter: &Client<MemoryStore>,
    group: &mut Group,
    joiner: &Client<MemoryStore>,
) -> (Group, Vec<u8>) {
    let inv = Invite::create(
        inviter.rng(),
        inviter.clock(),
        "relay.example",
        Duration::from_secs(3600),
    )
    .unwrap();
    let link = InviteLink::parse(&inv.url()).unwrap();
    let req = joiner.create_join_request(link.secret(), "joiner").unwrap();
    let verified = inviter.verify_join_request(&req, &inv).unwrap();
    let out = group.add_member(inviter, &verified, &inv, true).unwrap();
    group.confirm_pending_commit(inviter, &out.msg_id).unwrap();
    let meta = InviteMeta::expected(inv.secret().id(), "Fuzz", "Fuzz the receiver");
    let joined = joiner
        .join_from_wrapped_welcome(link.secret(), &meta, out.welcome.as_ref().unwrap())
        .unwrap();
    (joined, out.commit)
}

fn inner(client: &Client<MemoryStore>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "v": 0, "seq": 1,
        "sender": client.instance().identity(),
        "instance_id": client.instance().cert().instance_id_hex(),
        "to": ["*"], "hop": 0, "origin": "agent", "kind": "a2a.message",
        "body": {"text": "hello"},
    }))
    .unwrap()
}

fn build() -> State {
    let clock = Arc::new(FakeClock::default());
    let alice = peer("fuzz/alice", &clock);
    let bob = peer("fuzz/bob", &clock);
    let carol = peer("fuzz/carol", &clock);
    let mut group = alice.create_group("Fuzz", "Fuzz the receiver").unwrap();
    let (mut bob_group, _) = join(&alice, &mut group, &bob);
    let (mut carol_group, commit) = join(&alice, &mut group, &carol);
    bob_group.process(&bob, &commit).unwrap();
    let application = bob_group.seal(&bob, &inner(&bob)).unwrap();
    let proposal = carol_group.propose_leave(&carol).unwrap();
    let update = bob_group.update(&bob).unwrap().commit;
    State {
        alice,
        group,
        base: [application, update, proposal],
    }
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

fuzz_target!(|data: &[u8]| {
    let _ = peek_header(data);
    let Some((&pick, edits)) = data.split_first() else {
        return;
    };
    // An unmodified base is a valid message; processing it only forces a
    // rebuild.
    if pick % 4 != 3 && edits.len() < 3 {
        return;
    }
    STATE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let state = slot.get_or_insert_with(build);
        let bytes = match pick % 4 {
            3 => edits.to_vec(),
            i => {
                let mut bytes = state.base[usize::from(i)].clone();
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
        };
        let _ = peek_header(&bytes);
        let opened = state.group.open(&state.alice, &bytes).is_ok();
        let processed = state.group.process(&state.alice, &bytes).is_ok();
        // Only an unmodified message processes; rebuild so the bases stay
        // current for the next input.
        if opened || processed {
            *slot = None;
        }
    });
});
