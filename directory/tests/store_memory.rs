//! Store conformance on the in-memory store (fast tier).

mod common;

use agentconnect_directory::MemoryStore;

#[tokio::test]
async fn memory_store_conforms() {
    common::store_suite::run(|| async { MemoryStore::new() }).await;
}
