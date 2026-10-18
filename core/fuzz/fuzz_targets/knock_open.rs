//! Fuzz target: opening sealed knocks and parsing knock plaintexts.
#![no_main]

use agentconnect_core::knock::{Door, Knock};
use libfuzzer_sys::fuzz_target;

// Anyone who can read a listing can seal bytes to its door, so the owner's
// checks 1-3 see attacker input. The first 48 bytes pick the door (id and
// key material, so the fuzzer can't learn one fixed key), the rest is the
// sealed knock. Nothing may panic, and an opened knock re-encodes to a
// canonical knock for the same door.
fuzz_target!(|data: &[u8]| {
    if let Ok(knock) = Knock::from_json(data) {
        assert_eq!(knock.to_json().as_slice(), data);
    }
    if data.len() < 48 {
        return;
    }
    let (head, sealed) = data.split_at(48);
    let mut id = [0u8; 16];
    id.copy_from_slice(&head[..16]);
    let mut ikm = [0u8; 32];
    ikm.copy_from_slice(&head[16..]);
    let Ok(door) = Door::derive(id, &ikm, u64::MAX / 2) else {
        return;
    };
    if let Ok(opened) = door.open_knock(&id, sealed, 1_800_000_000) {
        let k = opened.knock();
        assert_eq!(k.door_id, id);
        let again = Knock::from_json(&k.to_json()).unwrap();
        assert_eq!(again.to_json(), k.to_json());
    }
});
