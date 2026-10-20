//! SR-01 regression (SPEC 11.6, 11.7): the grinding attack on the earlier
//! v0 short code, against the SAS run.
//!
//! Mallory is in the middle of two forked views: view 1 with Alice and view
//! 2 with Bob. As the review's probe did, it tries Updates offline in view 1
//! (building each one and dropping it unsent) until the earlier code (the
//! epoch authenticator alone) agrees with view 2's on its first bits. That still works: the
//! last committer chooses the authenticator. Then the humans compare codes
//! from SAS runs, where Mallory fixes its nonce in each view before that
//! view's honest nonce arrives, and the codes match no more often than
//! chance allows.

use std::sync::Arc;
use std::time::Duration;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::*;
use crate::clock::FakeClock;
use crate::identity::Identity;
use crate::provider::MemoryStore;
use crate::sas::{self, Participant, Sas, SasNonce};

type C = Client<MemoryStore>;

/// Bits of the earlier code Mallory grinds to agree, offline: enough to show
/// that it chooses them, at 2^3 Updates on average.
const GRIND_BITS: u32 = 3;
/// Bits of the run codes compared: the code cut to 12 bits for the test.
const CUT_BITS: u32 = 12;
/// SAS runs per view.
const TRIALS: u32 = 1 << 13;
/// Runs through the full run model (every code through `Group::sas_code`).
const RUNS: u32 = 1 << 7;
/// Bits of Bob's code Mallory grinds the re-derived code to agree on.
const REDERIVE_BITS: u32 = 3;

fn client(id: &Identity, label: &str, clock: &Arc<FakeClock>) -> (C, Zeroizing<Vec<u8>>) {
    let inst = id
        .create_instance(&Rng::for_test(&format!("grind-{label}")), clock.as_ref())
        .unwrap();
    let secret = inst.to_secret_bytes().unwrap();
    let c = Client::new(
        MemoryStore::new(),
        Rng::for_test(&format!("grind-{label}-client")),
        inst,
        clock.clone(),
    )
    .unwrap();
    (c, secret)
}

fn identity(label: &str) -> Identity {
    Identity::generate(&Rng::for_test(&format!("grind-{label}-ik"))).unwrap()
}

/// `joiner` joins `owner`'s group `g`.
fn join(owner: &C, g: &mut Group, joiner: &C) -> Group {
    let inv = Invite::create(
        owner.rng(),
        owner.clock(),
        "r.example",
        Duration::from_secs(60),
    )
    .unwrap();
    let req = joiner.create_join_request(inv.secret(), "j").unwrap();
    let v = owner.verify_join_request(&req, &inv).unwrap();
    let out = g.add_member(owner, &v, &inv, true).unwrap();
    g.confirm_pending_commit(owner, &out.msg_id).unwrap();
    let meta = InviteMeta::expected(inv.secret().id(), "g", "p");
    joiner
        .join_from_wrapped_welcome(inv.secret(), &meta, out.welcome.as_ref().unwrap())
        .unwrap()
}

/// The earlier v0 code: HKDF(`epoch_authenticator`, `group_id`,
/// "agentconnect/v0/sas" ‖ u64be(epoch), L = 6).
fn earlier_code_of(authenticator: &[u8], group_id: &[u8], epoch: u64) -> [u8; 6] {
    let info = [b"agentconnect/v0/sas".as_slice(), &epoch.to_be_bytes()].concat();
    let mut out = [0u8; 6];
    Hkdf::<Sha256>::new(Some(group_id), authenticator)
        .expand(&info, &mut out)
        .unwrap();
    out
}

fn earlier_code(g: &Group) -> [u8; 6] {
    earlier_code_of(&g.state_fingerprint(), g.group_id(), g.epoch())
}

/// Mallory's offline grinding: it builds Updates in `g` and drops each one
/// unsent until `wins` accepts the epoch authenticator it would give (with
/// the epoch it would start), merges that one and returns it. Fails after
/// 2^(`bits` + 6) tries, which a match on `bits` bits never needs.
fn grind(m: &C, g: &mut Group, bits: u32, wins: impl Fn(&[u8], u64) -> bool) -> Vec<u8> {
    for _ in 0..1u32 << (bits + 6) {
        let out = g.update(m).unwrap();
        let staged = g.mls.pending_commit().unwrap();
        let authenticator = staged.epoch_authenticator().unwrap().as_slice().to_vec();
        if wins(&authenticator, g.epoch() + 1) {
            g.confirm_pending_commit(m, &out.msg_id).unwrap();
            assert_eq!(g.state_fingerprint(), authenticator);
            return out.commit;
        }
        g.discard_pending_commit(m).unwrap();
    }
    panic!("grinding should find a match");
}

fn leading(bytes: [u8; 6], bits: u32) -> u64 {
    let mut buf = [0u8; 8];
    buf[2..].copy_from_slice(&bytes);
    u64::from_be_bytes(buf) >> (48 - bits)
}

fn participant<'a>(c: &'a C, nonce: &'a [u8; 32]) -> Participant<'a> {
    Participant {
        identity: c.instance().identity(),
        instance_id: c.instance().instance_id(),
        nonce,
    }
}

fn code(g: &Group, a: (&C, &[u8; 32]), b: (&C, &[u8; 32])) -> Sas {
    let (pa, pb) = (participant(a.0, a.1), participant(b.0, b.1));
    Sas::derive(&g.state_fingerprint(), g.group_id(), g.epoch(), &pa, &pb).unwrap()
}

#[test]
fn grinding_the_epoch_authenticator_no_longer_chooses_the_code() {
    let clock = Arc::new(FakeClock::default());
    let mallory = identity("mallory");
    let (alice, _) = client(&identity("alice"), "alice", &clock);
    let (bob, _) = client(&identity("bob"), "bob", &clock);
    let (m1, _) = client(&mallory, "m1", &clock);
    let (m2, _) = client(&mallory, "m2", &clock);

    // View 1: Alice's group, Mallory joined with the leaked link. View 2:
    // Mallory's group posing as Alice, Bob invited.
    let mut g1 = alice.create_group("g", "p").unwrap();
    let mut m1_g1 = join(&alice, &mut g1, &m1);
    let mut g2 = m2.create_group("g", "p").unwrap();
    let b_g2 = join(&m2, &mut g2, &bob);

    // The probe's strategy: Updates tried offline until the earlier code
    // agrees with view 2's on GRIND_BITS bits.
    let target = leading(earlier_code(&b_g2), GRIND_BITS);
    let gid = m1_g1.group_id().to_vec();
    let commit = grind(&m1, &mut m1_g1, GRIND_BITS, |auth, epoch| {
        leading(earlier_code_of(auth, &gid, epoch), GRIND_BITS) == target
    });
    assert!(matches!(
        g1.process(&alice, &commit).unwrap(),
        Event::Commit(_)
    ));
    // Against the earlier code the attack works: both views show it.
    assert_eq!(leading(earlier_code(&g1), GRIND_BITS), target);
    assert_eq!(earlier_code(&g1), earlier_code(&m1_g1));

    // SAS runs. Mallory's nonce in each view is fixed before the honest one
    // arrives. In view 2 it even chooses its nonce after it learned Alice's
    // code (the delay race): nothing it can do predicts Bob's.
    let rng = Rng::for_test("grind-runs");
    let (mut cut, mut full) = (0u32, 0u32);
    for _ in 0..TRIALS {
        let n_m1: [u8; 32] = rng.array().unwrap();
        let n_a = SasNonce::generate(&rng).unwrap();
        let alice_code = code(&g1, (&alice, n_a.expose()), (&m1, &n_m1));
        let n_m2: [u8; 32] = Sha256::digest(alice_code.bytes()).into();
        let n_b = SasNonce::generate(&rng).unwrap();
        let bob_code = code(&b_g2, (&bob, n_b.expose()), (&m2, &n_m2));
        cut +=
            u32::from(leading(alice_code.bytes(), CUT_BITS) == leading(bob_code.bytes(), CUT_BITS));
        full += u32::from(alice_code.decimal() == bob_code.decimal());
    }
    // 2^-12 per run: about 2 in 2^13 runs. More than 14 has a probability
    // below 10^-8.
    assert!(cut <= 14, "{cut} of {TRIALS} cut codes matched");
    assert_eq!(full, 0, "the real codes never match");

    // The same code the group derives through its API (SPEC 11.4).
    let n_a = SasNonce::generate(&rng).unwrap();
    let n_m = SasNonce::generate(&rng).unwrap();
    let via_group = g1
        .sas_code(
            &alice,
            g1.epoch(),
            &n_a,
            m1.instance().identity(),
            m1.instance().instance_id(),
            n_m.expose(),
        )
        .unwrap();
    assert_eq!(
        via_group,
        code(&g1, (&alice, n_a.expose()), (&m1, n_m.expose()))
    );
    // An earlier epoch's authenticator never gives a code.
    assert_eq!(
        g1.sas_code(
            &alice,
            g1.epoch() - 1,
            &n_a,
            m1.instance().identity(),
            m1.instance().instance_id(),
            n_m.expose(),
        ),
        Err(Error::WrongEpoch)
    );
}

/// One honest side of a SAS run, with the rules of SPEC 11.3 that the
/// daemon enforces: it reveals only once paired, checks the peer's reveal
/// against the commitment it paired with, and derives the code only under
/// its run's epoch (`Group::sas_code`, which refuses any other).
struct Side<'a> {
    client: &'a C,
    peer: &'a C,
    epoch: u64,
    nonce: SasNonce,
    commitment: [u8; 32],
    paired: Option<[u8; 32]>,
    revealed: bool,
    peer_nonce: Option<[u8; 32]>,
    aborted: bool,
}

impl<'a> Side<'a> {
    fn start(client: &'a C, peer: &'a C, g: &Group, rng: &Rng) -> Self {
        let nonce = SasNonce::generate(rng).unwrap();
        let commitment = g.sas_commitment(client, peer.instance().identity(), &nonce);
        Self {
            client,
            peer,
            epoch: g.epoch(),
            nonce,
            commitment,
            paired: None,
            revealed: false,
            peer_nonce: None,
            aborted: false,
        }
    }

    /// Step 2: the first commitment from the peer.
    fn pair(&mut self, commitment: [u8; 32]) {
        if self.paired.is_none() {
            self.paired = Some(commitment);
        }
    }

    /// Step 3: the nonce, only once paired.
    fn reveal(&mut self) -> Option<[u8; 32]> {
        self.paired?;
        self.revealed = true;
        Some(*self.nonce.expose())
    }

    /// Step 4: the peer's reveal must open the commitment paired with.
    fn take_reveal(&mut self, g: &Group, nonce: [u8; 32]) {
        let expected = sas::commitment(
            g.group_id(),
            self.epoch,
            self.peer.instance().identity(),
            self.peer.instance().instance_id(),
            self.client.instance().identity(),
            &nonce,
        );
        if self.paired == Some(expected) && self.revealed {
            self.peer_nonce = Some(nonce);
        } else {
            self.aborted = true;
        }
    }

    /// Step 5: the code, under the run's epoch only.
    fn code(&self, g: &Group) -> Option<Sas> {
        if self.aborted {
            return None;
        }
        g.sas_code(
            self.client,
            self.epoch,
            &self.nonce,
            self.peer.instance().identity(),
            self.peer.instance().instance_id(),
            &self.peer_nonce?,
        )
        .ok()
    }
}

/// Mallory's commitment in a view where `m` talks to `honest`.
fn m_commit(g: &Group, m: &C, honest: &C, nonce: &[u8; 32]) -> [u8; 32] {
    sas::commitment(
        g.group_id(),
        g.epoch(),
        m.instance().identity(),
        m.instance().instance_id(),
        honest.instance().identity(),
        nonce,
    )
}

#[test]
fn the_run_ordering_leaves_mallory_one_guess_per_run() {
    let clock = Arc::new(FakeClock::default());
    let mallory = identity("order-mallory");
    let (alice, _) = client(&identity("order-alice"), "order-alice", &clock);
    let (bob, _) = client(&identity("order-bob"), "order-bob", &clock);
    let (m1, _) = client(&mallory, "order-m1", &clock);
    let (m2, _) = client(&mallory, "order-m2", &clock);
    let mut g1 = alice.create_group("g", "p").unwrap();
    let mut m1_g1 = join(&alice, &mut g1, &m1);
    let mut g2 = m2.create_group("g", "p").unwrap();
    let b_g2 = join(&m2, &mut g2, &bob);
    let rng = Rng::for_test("order-runs");

    // Bob's run first; Mallory's nonce in view 2 is fixed before Bob's
    // arrives, and Bob reveals nothing before he pairs.
    let mut bob_side = Side::start(&bob, &m2, &b_g2, &rng);
    assert_eq!(bob_side.reveal(), None, "no reveal before pairing");
    let n_m2: [u8; 32] = rng.array().unwrap();
    bob_side.pair(m_commit(&b_g2, &m2, &bob, &n_m2));
    bob_side.reveal().unwrap();
    bob_side.take_reveal(&b_g2, n_m2);
    let bob_code = bob_side.code(&b_g2).unwrap();
    let target = leading(bob_code.bytes(), CUT_BITS);

    // The winning variant if the ordering were broken: Mallory commits
    // ahead in view 1, learns Alice's nonce from her reveal, then grinds
    // Updates on copied state until the code re-derived from the revealed
    // nonces under the new epoch agrees with Bob's.
    let mut alice_side = Side::start(&alice, &m1, &g1, &rng);
    let n_m1: [u8; 32] = rng.array().unwrap();
    alice_side.pair(m_commit(&g1, &m1, &alice, &n_m1));
    let n_a = alice_side.reveal().unwrap();
    let want = REDERIVE_BITS;
    let (pa, pm) = (participant(&alice, &n_a), participant(&m1, &n_m1));
    let gid = m1_g1.group_id().to_vec();
    let rederive = |auth: &[u8], epoch| Sas::derive(auth, &gid, epoch, &pa, &pm).unwrap();
    let commit = grind(&m1, &mut m1_g1, want, |auth, epoch| {
        leading(rederive(auth, epoch).bytes(), want) == target >> (CUT_BITS - want)
    });
    let rederived = rederive(&m1_g1.state_fingerprint(), m1_g1.epoch());
    assert!(matches!(
        g1.process(&alice, &commit).unwrap(),
        Event::Commit(_)
    ));
    alice_side.take_reveal(&g1, n_m1);
    // A daemon that re-derived would show Mallory's chosen code...
    assert_eq!(
        leading(rederived.bytes(), want),
        target >> (CUT_BITS - want)
    );
    // ...the run's rules give none: its epoch has ended.
    assert_eq!(alice_side.code(&g1), None);
    // A reveal that doesn't open the commitment gives none either.
    let mut cheated = Side::start(&alice, &m1, &g1, &rng);
    cheated.pair(m_commit(&g1, &m1, &alice, &n_m1));
    cheated.reveal().unwrap();
    cheated.take_reveal(&g1, rng.array().unwrap());
    assert_eq!(cheated.code(&g1), None);

    // Every run in turn, with Mallory's best strategies against the real
    // ordering: commit before the honest nonce, then in view 2 choose the
    // nonce after Alice's code is known (the delay race). Codes cut to 12
    // bits match at chance.
    let (mut cut, mut full) = (0u32, 0u32);
    for _ in 0..RUNS {
        let mut a = Side::start(&alice, &m1, &g1, &rng);
        // All Mallory has seen of Alice's nonce is its commitment.
        let n1: [u8; 32] = Sha256::digest(a.commitment).into();
        a.pair(m_commit(&g1, &m1, &alice, &n1));
        a.reveal().unwrap();
        a.take_reveal(&g1, n1);
        let alice_code = a.code(&g1).unwrap();
        let mut b = Side::start(&bob, &m2, &b_g2, &rng);
        let n2: [u8; 32] = Sha256::digest(alice_code.bytes()).into();
        b.pair(m_commit(&b_g2, &m2, &bob, &n2));
        b.reveal().unwrap();
        b.take_reveal(&b_g2, n2);
        let bob_code = b.code(&b_g2).unwrap();
        cut +=
            u32::from(leading(alice_code.bytes(), CUT_BITS) == leading(bob_code.bytes(), CUT_BITS));
        full += u32::from(alice_code.decimal() == bob_code.decimal());
    }
    // About 0.03 expected in 2^7 runs; more than 3 has a probability below
    // 10^-7. (The derivation alone is checked over 2^13 runs above.)
    assert!(cut <= 3, "{cut} of {RUNS} cut codes matched");
    assert_eq!(full, 0, "the real codes never match");
    drop(m1_g1);
}
