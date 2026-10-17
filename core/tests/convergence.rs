//! Property test: over random sequences of adds, removes, updates and
//! messages, every honest member converges on the same epoch and SAS.
//!
//! Seeded from `AC_TEST_SEED` when set (TESTING.md), so a failing run can
//! be reproduced; `PROPTEST_CASES` raises the case count (nightly).

mod common;

use agentconnect_core::Group;
use agentconnect_core::group::Event;
use common::*;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

#[derive(Clone, Debug)]
enum Op {
    Add,
    Remove(usize),
    Update(usize),
    Message(usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::Add),
        1 => any::<usize>().prop_map(Op::Remove),
        2 => any::<usize>().prop_map(Op::Update),
        2 => any::<usize>().prop_map(Op::Message),
    ]
}

fn config() -> Config {
    let mut c = Config {
        cases: 6,
        failure_persistence: None,
        ..Config::default()
    };
    if let Ok(cases) = std::env::var("PROPTEST_CASES") {
        c.cases = cases.parse().unwrap_or(c.cases);
    }
    if let Some(seed) = std::env::var("AC_TEST_SEED")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        c.rng_seed = RngSeed::Fixed(seed);
    }
    c
}

const MAX_MEMBERS: usize = 5;

struct World {
    peers: Vec<Peer>,
    groups: Vec<Group>,
    next_seed: u64,
}

impl World {
    /// Commit `out` was built by member `from`: confirm it there and
    /// process it everywhere else.
    fn fan_out(&mut self, from: usize, commit: &[u8]) {
        self.groups[from]
            .confirm_pending_commit(&self.peers[from].client)
            .unwrap();
        let mut removed = Vec::new();
        for i in 0..self.groups.len() {
            if i == from {
                continue;
            }
            match self.groups[i]
                .process(&self.peers[i].client, commit)
                .unwrap()
            {
                Event::Commit(_) => {}
                Event::Removed(_) => removed.push(i),
                other => panic!("unexpected {other:?}"),
            }
        }
        for i in removed.into_iter().rev() {
            self.groups.remove(i);
            self.peers.remove(i);
        }
    }

    fn apply(&mut self, op: &Op, base: u64) {
        let n = self.groups.len();
        match *op {
            Op::Add if n < MAX_MEMBERS => {
                self.next_seed += 1;
                let joiner = peer(base + self.next_seed, &clock());
                let (head, _) = self.groups.split_at_mut(1);
                let (g, out) = join(&self.peers[0], &mut head[0], &joiner);
                for i in 1..n {
                    let e = self.groups[i].process(&self.peers[i].client, &out.commit);
                    assert!(matches!(e, Ok(Event::Commit(_))), "{e:?}");
                }
                self.peers.push(joiner);
                self.groups.push(g);
            }
            Op::Remove(k) if n > 1 => {
                let victim = 1 + k % (n - 1);
                let id = self.peers[victim].identity.id();
                let out = self.groups[0].remove(&self.peers[0].client, &id).unwrap();
                self.fan_out(0, &out.commit);
            }
            Op::Update(k) => {
                let who = k % n;
                let out = self.groups[who].update(&self.peers[who].client).unwrap();
                self.fan_out(who, &out.commit);
            }
            Op::Message(k) => {
                let who = k % n;
                let ct = self.groups[who]
                    .seal(&self.peers[who].client, &inner(&self.peers[who], "ping"))
                    .unwrap();
                for i in (0..n).filter(|i| *i != who) {
                    let m = self.groups[i].open(&self.peers[i].client, &ct).unwrap();
                    assert_eq!(m.sender.identity, self.peers[who].identity.id());
                }
            }
            _ => {}
        }
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn honest_members_converge(base in 0u64..1_000_000, ops in prop::collection::vec(op(), 1..8)) {
        let clock = clock();
        let owner = peer(base * 100, &clock);
        let group = owner.client.create_group(NAME, PURPOSE).unwrap();
        let mut world = World { peers: vec![owner], groups: vec![group], next_seed: 0 };
        for op in &ops {
            world.apply(op, base * 100);
            assert_converged(&world.groups);
            let members = world.groups[0].members().unwrap();
            prop_assert_eq!(members.len(), world.groups.len());
        }
    }
}
