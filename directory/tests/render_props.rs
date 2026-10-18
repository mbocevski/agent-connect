//! Properties of the escaping that keeps card text inert.

use agentconnect_directory::card::Card;
use agentconnect_directory::render::{escape, fenced};
use proptest::prelude::*;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        rng_seed: std::env::var("AC_TEST_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .map_or(
                proptest::test_runner::RngSeed::Random,
                proptest::test_runner::RngSeed::Fixed,
            ),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// A fenced block is exactly three lines and its fence can't occur inside.
    #[test]
    fn fenced_text_cannot_close_its_block(text in any::<String>()) {
        let block = fenced(&text);
        let lines: Vec<&str> = block.trim_end_matches('\n').split('\n').collect();
        prop_assert_eq!(lines.len(), 3);
        let fence = lines[0].strip_suffix("text").unwrap();
        prop_assert!(fence.len() >= 3 && fence.chars().all(|c| c == '`'));
        prop_assert_eq!(lines[2], fence);
        prop_assert!(!lines[1].contains(fence));
    }

    /// Escaped text has no markup characters left.
    #[test]
    fn escaped_text_has_no_markup(text in any::<String>()) {
        let e = escape(&text);
        prop_assert!(!e.contains('<') && !e.contains('>') && !e.contains('"') && !e.contains('\''));
    }

    /// Card display text never carries control characters or exceeds its caps.
    #[test]
    fn card_text_is_single_line_and_capped(name in any::<String>(), description in any::<String>()) {
        let bytes = serde_json::to_vec(&serde_json::json!({"name": name, "description": description})).unwrap();
        let c = Card::parse(&bytes).unwrap();
        prop_assert!(!c.name.chars().any(char::is_control));
        prop_assert!(!c.description.chars().any(char::is_control));
        prop_assert!(c.name.chars().count() <= 80);
        prop_assert!(c.description.chars().count() <= 500);
    }
}
