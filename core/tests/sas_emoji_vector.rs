//! Contract test: the shared SAS emoji table (`testdata/sas-emoji.json`).
//!
//! The Python suite loads the same file (`daemon/tests/test_sas_emoji_vector.py`).

use std::collections::HashSet;
use std::path::PathBuf;

fn load() -> Vec<serde_json::Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/sas-emoji.json");
    let raw = std::fs::read_to_string(&path).expect("read testdata/sas-emoji.json");
    serde_json::from_str(&raw).expect("parse sas-emoji.json")
}

#[test]
fn table_has_64_entries() {
    assert_eq!(load().len(), 64);
}

#[test]
fn numbers_are_unique_and_cover_0_to_63() {
    let numbers: HashSet<u64> = load()
        .iter()
        .map(|e| e["number"].as_u64().expect("number is an integer"))
        .collect();
    assert_eq!(numbers, (0..64).collect::<HashSet<u64>>());
}

#[test]
fn emoji_and_description_are_non_empty_and_unique() {
    let entries = load();
    for field in ["emoji", "description"] {
        let values: Vec<&str> = entries
            .iter()
            .map(|e| e[field].as_str().expect("string field"))
            .collect();
        assert!(values.iter().all(|v| !v.trim().is_empty()), "{field} empty");
        assert_eq!(values.iter().collect::<HashSet<_>>().len(), 64, "{field}");
    }
}
