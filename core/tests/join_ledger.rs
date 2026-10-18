//! The inviter's replay ledger for JoinRequests (SPEC §6.2, "Replays"): a
//! request that passed the checks is remembered by its request id and its
//! `KeyPackageRef` until its invite expires, plus the ledger's grace, so a
//! relay can't put a rejected, lapsed or dropped request in front of the
//! human again. After that the invite's own expiry refuses any copy.

mod common;

use std::time::Duration;

use agentconnect_core::clock::Clock as _;
use agentconnect_core::ledger::{LEDGER_GRACE_SECS, MemoryLedger, ReplayLedger};
use agentconnect_core::{Error, ErrorKind, Invite};
use common::*;

fn now(clock: &agentconnect_core::clock::FakeClock) -> u64 {
    clock.unix_millis() / 1000
}

/// A day-long invite, so a replay can come well after the hour.
fn day_invite(peer: &Peer) -> Invite {
    Invite::create(
        peer.client.rng(),
        peer.client.clock(),
        RELAY,
        Duration::from_secs(86_400),
    )
    .unwrap()
}

#[test]
fn a_join_request_seen_before_is_a_replay() {
    let clock = clock();
    let a = peer(1, &clock);
    let b = peer(2, &clock);
    let inv = day_invite(&a);
    let req = b.client.create_join_request(inv.secret(), "b").unwrap();
    let verified = a.client.verify_join_request(&req, &inv).unwrap();
    // Remembered until the invite expires, plus the grace: a replay
    // restarts the approval timeout, so nothing earlier bounds it.
    assert_eq!(
        verified.forget_after(),
        inv.expires_at() + LEDGER_GRACE_SECS
    );
    assert_eq!(LEDGER_GRACE_SECS, 300);
    let mut ledger = MemoryLedger::default();
    verified.remember_in(&mut ledger, b"request-1").unwrap();
    assert!(
        ledger
            .seen(b"request-1", verified.key_package_ref())
            .unwrap()
    );

    // The same bytes again, under the same or a fresh request id (the
    // relay picks the msg_id), an hour and a half later.
    clock.advance(Duration::from_secs(5400));
    let again = a.client.verify_join_request(&req, &inv).unwrap();
    for id in [&b"request-1"[..], b"request-2"] {
        let e = again.remember_in(&mut ledger, id).unwrap_err();
        assert_eq!(e, Error::Replayed);
        assert_eq!(e.kind(), ErrorKind::Replay);
    }
    // Another request (a fresh KeyPackage) under a request id seen before
    // is refused too: the id is taken.
    let other = b.client.create_join_request(inv.secret(), "b").unwrap();
    let other = a.client.verify_join_request(&other, &inv).unwrap();
    assert_eq!(
        other.remember_in(&mut ledger, b"request-1"),
        Err(Error::Replayed)
    );
    other.remember_in(&mut ledger, b"request-3").unwrap();
    assert_eq!(ledger.len(), 2);

    // Kept through forget_after, gone after it; by then the invite itself
    // refuses the request.
    ledger.purge(verified.forget_after());
    assert_eq!(ledger.len(), 2);
    ledger.purge(verified.forget_after() + 1);
    assert!(ledger.is_empty());
    clock.advance(Duration::from_secs(
        verified.forget_after() + 1 - now(&clock),
    ));
    assert_eq!(
        a.client.verify_join_request(&req, &inv).unwrap_err(),
        Error::InviteExpired
    );
}

#[test]
fn a_full_join_ledger_refuses_without_evicting() {
    let clock = clock();
    let a = peer(1, &clock);
    let b = peer(2, &clock);
    let inv = invite(&a);
    let verified: Vec<_> = (0..3)
        .map(|_| {
            let req = b.client.create_join_request(inv.secret(), "b").unwrap();
            a.client.verify_join_request(&req, &inv).unwrap()
        })
        .collect();
    let mut ledger = MemoryLedger::with_capacity(2);
    verified[0].remember_in(&mut ledger, b"r0").unwrap();
    verified[1].remember_in(&mut ledger, b"r1").unwrap();
    let e = verified[2].remember_in(&mut ledger, b"r2").unwrap_err();
    assert_eq!(e, Error::LedgerFull);
    assert_eq!(e.kind(), ErrorKind::Busy);
    // Both live entries are still there, and survive an export and import.
    let saved = ledger.entries();
    let mut restarted = MemoryLedger::with_capacity(2);
    for e in saved {
        restarted
            .insert(e.id, e.key_package_ref, e.forget_after)
            .unwrap();
    }
    for (v, id) in verified[..2].iter().zip([&b"r0"[..], b"r1"]) {
        assert_eq!(v.remember_in(&mut restarted, id), Err(Error::Replayed));
    }
}
