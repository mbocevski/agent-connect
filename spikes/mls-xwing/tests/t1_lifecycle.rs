//! Spike item 1: X-Wing group lifecycle with one SQLite-backed member.

use std::sync::Mutex;

use agentconnect_spike_mls_xwing::*;
use openmls::prelude::*;
use openmls_libcrux_crypto::Provider as MemProvider;

fn temp_db(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("ac-spike-{tag}-{}.sqlite", std::process::id()))
}

#[test]
fn create_add_message_remove() {
    // A and C keep state in memory; B persists to SQLite behind a Mutex,
    // building a borrowed provider per operation.
    let pa = MemProvider::new().unwrap();
    let pc = MemProvider::new().unwrap();
    let pd = MemProvider::new().unwrap();
    let db = temp_db("t1");
    let _ = std::fs::remove_file(&db);
    let b_conn = Mutex::new(open_sqlite(&db));

    let a = Identity::new("ac:v0:alice", &pa);
    let c = Identity::new("ac:v0:carol", &pc);
    let d = Identity::new("ac:v0:dave", &pd);
    let (b, kp_b) = {
        let guard = b_conn.lock().unwrap();
        let pb = SqliteProvider::new(&*guard);
        let b = Identity::new("ac:v0:bob", &pb);
        let kp = b.key_package(&pb, ac_capabilities(), instance_cert_ext(b"{}"));
        (b, kp)
    };
    let kp_c = c.key_package(&pc, ac_capabilities(), instance_cert_ext(b"{}"));
    let kp_d = d.key_package(&pd, ac_capabilities(), instance_cert_ext(b"{}"));

    let mut ga = MlsGroup::new(&pa, &a.signer, &create_config(), a.credential.clone()).unwrap();
    assert_eq!(ga.ciphersuite(), CS);

    // Add B, C and D in one commit; one Welcome serves all three.
    let (commit, welcome_msg, _) = ga.add_members(&pa, &a.signer, &[kp_b, kp_c, kp_d]).unwrap();
    let _ = wire(&commit); // fanned out to existing members (none yet)
    ga.merge_pending_commit(&pa).unwrap();
    let welcome_bytes = wire(&welcome_msg);

    let group_id = ga.group_id().clone();
    {
        let guard = b_conn.lock().unwrap();
        let pb = SqliteProvider::new(&*guard);
        let gb = join(&pb, &welcome_bytes).unwrap();
        assert_eq!(gb.epoch(), ga.epoch());
    }
    let mut gc = join(&pc, &welcome_bytes).unwrap();
    let mut gd = join(&pd, &welcome_bytes).unwrap();

    // A -> group.
    let m1 = wire(&ga.create_message(&pa, &a.signer, b"hello from A").unwrap());
    {
        let guard = b_conn.lock().unwrap();
        let pb = SqliteProvider::new(&*guard);
        let mut gb = MlsGroup::load(pb.storage(), &group_id).unwrap().unwrap();
        assert_eq!(read_app(&mut gb, &pb, &m1).unwrap(), b"hello from A");
    }
    assert_eq!(read_app(&mut gc, &pc, &m1).unwrap(), b"hello from A");

    // B -> group, after closing and reopening its database (persistence).
    drop(b_conn);
    let b_conn = Mutex::new(open_sqlite(&db));
    let m2 = {
        let guard = b_conn.lock().unwrap();
        let pb = SqliteProvider::new(&*guard);
        let mut gb = MlsGroup::load(pb.storage(), &group_id).unwrap().unwrap();
        wire(&gb.create_message(&pb, &b.signer, b"hello from B").unwrap())
    };
    assert_eq!(read_app(&mut ga, &pa, &m2).unwrap(), b"hello from B");
    assert_eq!(read_app(&mut gc, &pc, &m2).unwrap(), b"hello from B");

    // A removes C and D. D never processes the removal (stale state).
    let leaves = [gc.own_leaf_index(), gd.own_leaf_index()];
    let (remove, _, _) = ga.remove_members(&pa, &a.signer, &leaves).unwrap();
    ga.merge_pending_commit(&pa).unwrap();
    let remove = wire(&remove);
    {
        let guard = b_conn.lock().unwrap();
        let pb = SqliteProvider::new(&*guard);
        let mut gb = MlsGroup::load(pb.storage(), &group_id).unwrap().unwrap();
        apply_commit(&mut gb, &pb, &remove).unwrap();
        assert_eq!(gb.members().count(), 2);
    }
    // C processes its own removal and becomes inactive.
    apply_commit(&mut gc, &pc, &remove).unwrap();
    assert!(!gc.is_active());

    // Next-epoch message: B reads it, C cannot.
    let m3 = wire(&ga.create_message(&pa, &a.signer, b"after removal").unwrap());
    {
        let guard = b_conn.lock().unwrap();
        let pb = SqliteProvider::new(&*guard);
        let mut gb = MlsGroup::load(pb.storage(), &group_id).unwrap().unwrap();
        assert_eq!(read_app(&mut gb, &pb, &m3).unwrap(), b"after removal");
    }
    // C, having processed its removal, is evicted: the library refuses.
    let err = read_app(&mut gc, &pc, &m3).unwrap_err();
    assert!(matches!(
        err,
        ProcessMessageError::GroupStateError(MlsGroupStateError::UseAfterEviction)
    ));
    // D, which never saw the removal, has no secrets for the new epoch.
    let err = read_app(&mut gd, &pd, &m3).unwrap_err();
    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch)
    ));

    drop(b_conn);
    let _ = std::fs::remove_file(&db);
}
