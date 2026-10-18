//! Fuzz target: reading a publish body's card text and rendering it.
#![no_main]

use agentconnect_directory::card::{Card, MAX_CARD_BYTES, MAX_DESCRIPTION, MAX_NAME};
use agentconnect_directory::render::{escape, fenced};
use libfuzzer_sys::fuzz_target;

// Card text is attacker-controlled. Reading it must never panic, and what
// comes out must be single-line, capped, and inert once escaped or fenced.
fuzz_target!(|data: &[u8]| {
    let Ok(card) = Card::parse(data) else {
        return;
    };
    assert!(data.len() <= MAX_CARD_BYTES);
    assert!(card.name.chars().count() <= MAX_NAME);
    assert!(card.description.chars().count() <= MAX_DESCRIPTION);
    let words = card.skill_words();
    let _ = card.skill_keys();
    for text in std::iter::once(&card.name)
        .chain(std::iter::once(&card.description))
        .chain(card.organization.iter())
        .chain(words.iter())
    {
        assert!(!text.chars().any(char::is_control));
        assert!(!escape(text).contains('<'));
        let block = fenced(text);
        let lines: Vec<&str> = block.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines.len(), 3);
        let fence = lines[0].strip_suffix("text").unwrap();
        assert_eq!(lines[2], fence);
        assert!(!lines[1].contains(fence));
    }
    let _ = serde_json::to_string(&words).unwrap();
});
