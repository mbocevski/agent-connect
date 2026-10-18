//! Fuzz target: the owner well-known file and the owner state machine.
#![no_main]

use agentconnect_core::listing::{FetchResult, OwnerChecks, OwnerFile, OwnerState, owner_state};
use libfuzzer_sys::fuzz_target;

// The file comes from whatever web server the owner domain points at. No
// parse may panic, a file that doesn't parse is a failed fetch, and a
// negative result followed by failed fetches never turns `verified` or
// `stale`.
fuzz_target!(|data: &[u8]| {
    let parsed = OwnerFile::parse(data);
    let Ok(file) = parsed else {
        assert_eq!(
            OwnerFile::fetch_result(data, "ac:v0:x", "agents.example", "release-planner"),
            FetchResult::Failed
        );
        return;
    };
    // Probe with an identity the file itself names.
    let named = file.identities().first().map(|e| e.identity.clone());
    let Some(identity) = named.or_else(|| file.revoked().first().map(|r| r.identity.clone()))
    else {
        return;
    };
    let result = OwnerFile::fetch_result(data, &identity, "agents.example", "release-planner");
    let mut checks = OwnerChecks::default();
    checks.record(1_000, result);
    checks.record(2_000, FetchResult::Failed);
    let state = owner_state(Some("example.com"), &checks, 2_000);
    if let FetchResult::Fetched(v) = result
        && v.as_str() != "vouches"
    {
        assert!(matches!(state, OwnerState::Failed | OwnerState::Revoked));
    }
});
