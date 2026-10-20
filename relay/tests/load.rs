//! Load tests for the storage limits (security review SR-03 and SR-05).
//! Ignored in `just test`; `just test-nightly` runs them
//! (`nightly-relay-load`). They time real work, so they assert loose bounds.

mod common;

use std::time::{Duration, Instant};

use agentconnect_relay::Limits;
use agentconnect_relay::proto::{MAX_WELCOME_CT, b64_encode, mailbox_id_from_key};
use agentconnect_relay::store::Store;
use common::{Client, Harness, commit, fresh_id, make_group};
use serde_json::json;

fn made_up(n: u8) -> String {
    mailbox_id_from_key(&[n, 0xA5])
}

async fn create_latency(c: &mut Client, n: usize) -> Duration {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        assert_eq!(c.group_create(&fresh_id()).await["t"], "accepted");
        out.push(t.elapsed());
    }
    out.sort();
    out[n / 2]
}

/// Median latency of `n` small sends from `a` to `gid`.
async fn send_latency(a: &mut Client, gid: &str, n: usize) -> Duration {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let m = a.envelope("application", gid, 1);
        let t = Instant::now();
        assert_eq!(a.send(&m).await["t"], "accepted");
        out.push(t.elapsed());
    }
    out.sort();
    out[n / 2]
}

/// The review's probe 8: 20 mailboxes at their quota, then one connection
/// looping small sends to them. Each send used to sum all 20 queues on the
/// single connection, and every other client waited behind it; now it
/// reads 20 counters, so a send to full queues costs no more than one to
/// empty queues, and others wait for at most about one such send.
#[tokio::test]
#[ignore = "load test: just test-nightly"]
async fn load_full_mailboxes_do_not_stall_the_relay() {
    let h = Harness::with_limits(Limits {
        sends_per_sec: 1_000_000,
        ..Limits::default()
    })
    .await;
    let mut victim = h.client(1).await;
    let mut a = h.client(2).await;
    let gid = make_group(&mut a, &[]).await;
    let targets: Vec<String> = (0..20).map(made_up).collect();
    let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
    assert_eq!(
        a.send(&commit(&a, &gid, 0, &refs, &[])).await["t"],
        "accepted"
    );
    a.deliver().await;
    let empty = send_latency(&mut a, &gid, 30).await;

    // Fill the targets' non-member queues (they never sent in the group).
    let big = b64_encode(&vec![9_u8; 1_000_000]);
    for _ in 0..20 {
        let mut m = a.envelope("application", &gid, 1);
        m["ct"] = json!(big);
        assert_eq!(a.send(&m).await["t"], "accepted");
    }
    assert!(
        h.relay
            .metrics()
            .render()
            .contains("agentconnect_relay_queue_overflows_total 20"),
        "the targets' queues are full"
    );
    let full = send_latency(&mut a, &gid, 30).await;
    assert!(
        full < empty * 3 + Duration::from_millis(2),
        "{full:?} vs {empty:?}"
    );

    let idle = create_latency(&mut victim, 10).await;
    let flood_addr = h.addr;
    let flood_key = a.disconnect().await;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let flood = tokio::spawn(async move {
        let mut a = Client::connect(flood_addr, flood_key).await;
        let mut sent = 0_u64;
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            let m = a.envelope("application", &gid, 1);
            assert_eq!(a.send(&m).await["t"], "accepted");
            sent += 1;
        }
        sent
    });
    let loaded = create_latency(&mut victim, 50).await;
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let sent = flood.await.unwrap();
    eprintln!(
        "send to 20 queues: {empty:?} empty, {full:?} full; \
         group.create {idle:?} alone, {loaded:?} during {sent} flood sends"
    );
    assert!(
        loaded < full * 3 + Duration::from_millis(2),
        "{loaded:?} vs {full:?}"
    );
}

/// The review's probes 5 and 6 at scale: one sender spreads large messages
/// over ten groups of 49 mailboxes its commits added, so no recipient queue
/// fills first, until its budget stops it. Storage grows by about the
/// budget, not 49 times it.
#[tokio::test]
#[ignore = "load test: just test-nightly"]
async fn load_one_sender_cannot_store_more_than_its_budget() {
    let limits = Limits {
        sends_per_sec: 1_000_000,
        ..Limits::default()
    };
    let budget = limits.sender_max_bytes;
    let h = Harness::with_limits(limits).await;
    let mut a = h.client(1).await;
    let mut groups = Vec::new();
    for g in 0..10_u8 {
        let gid = make_group(&mut a, &[]).await;
        let targets: Vec<String> = (0..49)
            .map(|n| mailbox_id_from_key(&[g, n, 0x5A]))
            .collect();
        let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
        assert_eq!(
            a.send(&commit(&a, &gid, 0, &refs, &[])).await["t"],
            "accepted"
        );
        a.deliver().await;
        let mut w = common::envelope("welcome_wrapped", Some(&gid), None, &a.mailbox);
        w["to"] = json!(targets);
        w["ct"] = json!(b64_encode(&vec![1_u8; MAX_WELCOME_CT]));
        assert_eq!(a.send(&w).await["t"], "accepted");
        groups.push(gid);
    }
    let before = h.relay.store().storage_bytes().await.unwrap();
    let big = b64_encode(&vec![2_u8; 1_000_000]);
    let mut accepted = 0_u64;
    for gid in groups.iter().cycle() {
        let mut m = a.envelope("application", gid, 1);
        m["ct"] = json!(big);
        let r = a.send(&m).await;
        if r["t"] != "accepted" {
            assert_eq!(r["code"], "over_budget", "{r}");
            assert!(r["detail"].as_str().unwrap().contains("undelivered"), "{r}");
            break;
        }
        accepted += 1;
        assert!(accepted < 1000, "never refused");
    }
    let grown = h.relay.store().storage_bytes().await.unwrap() - before;
    eprintln!(
        "{accepted} messages accepted; storage grew {grown} bytes for a {budget}-byte budget"
    );
    assert!(grown < budget + budget / 10, "grew {grown}");
}

#[allow(clippy::too_many_arguments)]
async fn put(
    s: &agentconnect_relay::SqliteStore,
    kind: agentconnect_relay::proto::Kind,
    gid: &str,
    sender: &str,
    epoch: u64,
    add: &[String],
    m: &agentconnect_relay::store::NewMessage,
    limits: &Limits,
    now: u64,
) {
    let send = agentconnect_relay::store::GroupSend {
        kind,
        group_id: gid,
        sender,
        epoch,
        add,
        remove: &[],
        to: &[],
        msg: m,
        ct_bytes: m.json.len(),
    };
    let o = s.deliver_group(&send, limits, now).await.unwrap();
    assert!(
        matches!(o, agentconnect_relay::store::GroupOutcome::Delivered { .. }),
        "{o:?}"
    );
}

/// Review F6: one purge transaction of 2,000 large rows held the only
/// writer for 15.8 s. The purge now deletes at most 16 MiB a transaction
/// and yields between them, so a write waits for about one batch.
/// `LOAD_PURGE_N` and `LOAD_PURGE_SIZE` scale it (the review's probe was
/// 2,000 x 1.4 MB); the database goes under `target/` so it is on disk.
#[tokio::test]
#[ignore = "load test: just test-nightly"]
async fn load_a_purge_of_large_payloads_does_not_hold_the_writer() {
    use agentconnect_relay::SqliteStore;
    use agentconnect_relay::proto::Kind;
    use agentconnect_relay::store::NewMessage;

    let env = |k: &str, d: usize| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let (n, size) = (env("LOAD_PURGE_N", 400), env("LOAD_PURGE_SIZE", 1_400_000));
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/load-tmp");
    std::fs::create_dir_all(&base).unwrap();
    let dir = tempfile::tempdir_in(&base).unwrap();
    let path = dir.path().join("relay.db");
    let s = SqliteStore::open(path.to_str().unwrap()).await.unwrap();
    let limits = Limits {
        sender_max_bytes: u64::MAX,
        queue_max_bytes: u64::MAX,
        ..Limits::default()
    };
    let now = 1_735_689_600_000;
    let (a, b) = (made_up(1), made_up(2));
    let gid = fresh_id();
    s.create_group(&gid, &a, now).await.unwrap();
    let message = |sender: &str, id: &str, bytes: usize| NewMessage {
        msg_id: id.into(),
        sender: sender.into(),
        json: format!(r#"{{"ct":"{}"}}"#, "x".repeat(bytes)),
    };
    let add = [b.clone()];
    put(
        &s,
        Kind::Commit,
        &gid,
        &a,
        0,
        &add,
        &message(&a, "c", 10),
        &limits,
        now,
    )
    .await;
    // B confirms, so its copies go to its group part.
    put(
        &s,
        Kind::Application,
        &gid,
        &b,
        1,
        &[],
        &message(&b, "hi", 10),
        &limits,
        now,
    )
    .await;
    for i in 0..n {
        let id = format!("m{i}");
        put(
            &s,
            Kind::Application,
            &gid,
            &a,
            1,
            &[],
            &message(&a, &id, size),
            &limits,
            now,
        )
        .await;
    }
    s.purge_expired(now + 1).await.unwrap(); // checkpoint first
    let ttl = u64::try_from(limits.message_ttl.as_millis()).unwrap();
    let later = now + ttl + 1;
    let purging = s.clone();
    let t = Instant::now();
    let purge = tokio::spawn(async move { purging.purge_expired(later).await.unwrap() });
    let mut worst = Duration::ZERO;
    let mut writes = 0;
    while !purge.is_finished() {
        let w = Instant::now();
        s.create_group(&fresh_id(), &made_up(3), later)
            .await
            .unwrap();
        worst = worst.max(w.elapsed());
        writes += 1;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let stats = purge.await.unwrap();
    eprintln!(
        "purged {} rows ({n} of {size} B) in {:?}; {writes} writes during it, the slowest \
         waited {worst:?}",
        stats.messages,
        t.elapsed()
    );
    assert!(stats.messages >= u64::try_from(n).unwrap());
    assert!(worst < Duration::from_secs(2), "a write waited {worst:?}");
}
