//! Spike item 7: sizes and rough latency.
//!
//! Run with:
//! `cargo test --release -p agentconnect-spike-mls-xwing --test t7_measure -- --ignored --nocapture`

use std::time::{Duration, Instant};

use agentconnect_spike_mls_xwing::*;
use openmls::prelude::*;
use openmls_libcrux_crypto::Provider;

const ROUNDS: u32 = 20;
const PAYLOAD: [u8; 256] = [0x41; 256];

fn ms(d: Duration) -> String {
    format!("{:.2}", d.as_secs_f64() * 1e3)
}

#[test]
#[ignore = "benchmark; run explicitly in release mode"]
fn sizes_and_latency() {
    println!(
        "| N | KeyPackage B | Welcome B (add Nth) | Add commit B | Update commit B | App msg B (256 B payload) | create commit ms | process commit ms | join ms |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    for n in [2usize, 5, 20] {
        let mut m = group_of(n - 1, &create_config());

        // Add the Nth member: KeyPackage, Welcome, Add commit, join time.
        let pj = Provider::new().unwrap();
        let joiner = Identity::new("ac:v0:joiner", &pj);
        let kp = joiner.key_package(&pj, ac_capabilities(), instance_cert_ext(b"{}"));
        let kp_len = kp.tls_serialized_len();
        let a = &mut m[0];
        let (add, w, _) = a
            .group
            .add_members(&a.provider, &a.id.signer, &[kp])
            .unwrap();
        a.group.merge_pending_commit(&a.provider).unwrap();
        let (add, w) = (wire(&add), wire(&w));
        for x in &mut m[1..] {
            apply_commit(&mut x.group, &x.provider, &add).unwrap();
        }
        let t = Instant::now();
        let gj = join(&pj, &w).unwrap();
        let join_time = t.elapsed();
        m.push(Peer {
            provider: pj,
            id: joiner,
            group: gj,
        });

        // Application message size.
        let a = &mut m[0];
        let app = wire(
            &a.group
                .create_message(&a.provider, &a.id.signer, &PAYLOAD)
                .unwrap(),
        );
        for x in &mut m[1..] {
            read_app(&mut x.group, &x.provider, &app).unwrap();
        }

        // Update commits: member 0 creates, member n-1 processes.
        let (mut create, mut process, mut update_len) = (Duration::ZERO, Duration::ZERO, 0);
        for _ in 0..ROUNDS {
            let a = &mut m[0];
            let t = Instant::now();
            let bundle = a
                .group
                .self_update(&a.provider, &a.id.signer, LeafNodeParameters::default())
                .unwrap();
            create += t.elapsed();
            a.group.merge_pending_commit(&a.provider).unwrap();
            let commit = wire(bundle.commit());
            update_len = commit.len();
            let last = m.len() - 1;
            for (i, x) in m.iter_mut().enumerate().skip(1) {
                let t = Instant::now();
                apply_commit(&mut x.group, &x.provider, &commit).unwrap();
                if i == last {
                    process += t.elapsed();
                }
            }
        }
        println!(
            "| {n} | {kp_len} | {} | {} | {update_len} | {} | {} | {} | {} |",
            w.len(),
            add.len(),
            app.len(),
            ms(create / ROUNDS),
            ms(process / ROUNDS),
            ms(join_time),
        );
    }
}
