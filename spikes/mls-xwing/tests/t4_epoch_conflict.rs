//! Spike item 4: epoch conflict resolution (SPEC §8.3, §14.3).

use agentconnect_spike_mls_xwing::*;
use openmls::prelude::*;

/// Toy Delivery Service: accepts a commit only for the current epoch.
struct Relay {
    epoch: u64,
}

impl Relay {
    fn submit(&mut self, epoch: GroupEpoch) -> Result<(), u64> {
        if epoch.as_u64() == self.epoch {
            self.epoch += 1;
            Ok(())
        } else {
            Err(self.epoch) // epoch_conflict{current_epoch}
        }
    }
}

#[test]
fn loser_discards_processes_winner_and_rebuilds() {
    let mut m = group_of(3, &create_config());
    let mut relay = Relay {
        epoch: m[0].group.epoch().as_u64(),
    };

    // A and B both build a commit from the same epoch (not merged yet: a
    // commit is merged only when the relay confirms it).
    let mut build = |i: usize| {
        let x = &mut m[i];
        let epoch = x.group.epoch();
        let bundle = x
            .group
            .self_update(&x.provider, &x.id.signer, LeafNodeParameters::default())
            .unwrap();
        assert!(x.group.pending_commit().is_some());
        (epoch, wire(bundle.commit()))
    };
    let (epoch_a, commit_a) = build(0);
    let (epoch_b, _commit_b) = build(1);

    // The relay accepts A's commit and rejects B's.
    relay.submit(epoch_a).unwrap();
    let current = relay.submit(epoch_b).unwrap_err();
    assert_eq!(current, epoch_a.as_u64() + 1);

    // A gets its own commit back as confirmation and merges; C processes it.
    let a = &mut m[0];
    a.group.merge_pending_commit(&a.provider).unwrap();
    let c = &mut m[2];
    apply_commit(&mut c.group, &c.provider, &commit_a).unwrap();

    // B: discard the pending commit, process the winner, rebuild, resend.
    let b = &mut m[1];
    b.group.clear_pending_commit(b.provider.storage()).unwrap();
    apply_commit(&mut b.group, &b.provider, &commit_a).unwrap();
    let epoch_b2 = b.group.epoch();
    let rebuilt = b
        .group
        .self_update(&b.provider, &b.id.signer, LeafNodeParameters::default())
        .unwrap();
    relay.submit(epoch_b2).unwrap();
    b.group.merge_pending_commit(&b.provider).unwrap();
    let rebuilt = wire(rebuilt.commit());
    for i in [0, 2] {
        let x = &mut m[i];
        apply_commit(&mut x.group, &x.provider, &rebuilt).unwrap();
    }

    let sas: Vec<_> = m.iter().map(|x| sas_bytes(&x.group)).collect();
    assert!(sas.iter().all(|s| *s == sas[0]));
    assert_eq!(m[0].group.epoch().as_u64(), relay.epoch);
}

#[test]
fn processing_winner_while_pending_also_works() {
    // Without the explicit discard, OpenMLS still lets the loser process the
    // winning commit; merging it drops the stale pending commit.
    let mut m = group_of(2, &create_config());
    let a = &mut m[0];
    let commit_a = wire(
        a.group
            .self_update(&a.provider, &a.id.signer, LeafNodeParameters::default())
            .unwrap()
            .commit(),
    );
    a.group.merge_pending_commit(&a.provider).unwrap();
    let b = &mut m[1];
    let _ = b
        .group
        .self_update(&b.provider, &b.id.signer, LeafNodeParameters::default())
        .unwrap();
    apply_commit(&mut b.group, &b.provider, &commit_a).unwrap();
    assert!(b.group.pending_commit().is_none());
    assert_eq!(sas_bytes(&m[0].group), sas_bytes(&m[1].group));
}
