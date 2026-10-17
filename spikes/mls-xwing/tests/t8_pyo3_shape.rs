//! Spike item 8: can these types sit behind a PyO3 `#[pyclass]`?
//!
//! PyO3 ≥ 0.23 requires `#[pyclass]` types to be `Send + Sync` (or
//! `unsendable`). These are compile-time checks of the candidate fields.

use std::sync::Mutex;

use agentconnect_spike_mls_xwing::*;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_sqlite_storage::Connection;

fn send_sync<T: Send + Sync>() {}
fn send<T: Send>() {}

#[test]
fn candidate_pyclass_fields_are_send_and_sync() {
    send_sync::<MlsGroup>();
    send_sync::<SignatureKeyPair>();
    send_sync::<openmls_libcrux_crypto::Provider>();
    send_sync::<KeyPackage>();
    send_sync::<MlsMessageOut>();
    // `rusqlite::Connection` is `Send` but not `Sync`: wrap it in a Mutex and
    // build a borrowed `SqliteProvider<&Connection>` per call (see t1).
    send::<Connection>();
    send_sync::<Mutex<Connection>>();
    send_sync::<Mutex<SqliteProvider<Connection>>>();
}

/// The shape a binding would take: all state behind one lock, no lifetimes
/// crossing the FFI boundary, bytes in and bytes out.
struct GroupHandle {
    conn: Mutex<Connection>,
    group_id: GroupId,
    signer: SignatureKeyPair,
}

impl GroupHandle {
    fn send(&self, plaintext: &[u8]) -> Vec<u8> {
        let conn = self.conn.lock().unwrap();
        let provider = SqliteProvider::new(&*conn);
        let mut group = MlsGroup::load(provider.storage(), &self.group_id)
            .unwrap()
            .unwrap();
        wire(
            &group
                .create_message(&provider, &self.signer, plaintext)
                .unwrap(),
        )
    }
}

#[test]
fn handle_shape_works() {
    send_sync::<GroupHandle>();
    let db = std::env::temp_dir().join(format!("ac-spike-t8-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&db);
    let conn = open_sqlite(&db);
    let (group_id, signer) = {
        let provider = SqliteProvider::new(&conn);
        let me = Identity::new("ac:v0:alice", &provider);
        let g = MlsGroup::new(&provider, &me.signer, &create_config(), me.credential).unwrap();
        (g.group_id().clone(), me.signer)
    };
    let handle = GroupHandle {
        conn: Mutex::new(conn),
        group_id,
        signer,
    };
    assert!(!handle.send(b"hi").is_empty());
    drop(handle);
    let _ = std::fs::remove_file(&db);
}
