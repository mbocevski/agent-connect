//! Property tests for the listing canonical form (SPEC §13.1.3): JCS is
//! idempotent, any valid card signs to bytes that parse back to the same
//! card and to themselves, and no single-byte change of a signed listing is
//! accepted.
//!
//! Seeded from `AC_TEST_SEED` when set (TESTING.md); `PROPTEST_CASES`
//! raises the case count (nightly).

use agentconnect_core::encoding::{MAX_SAFE_INTEGER, from_jcs, jcs};
use agentconnect_core::listing::{
    DirectoryKey, E2eParams, ListingCard, ListingProvider, ListingSkill, SignedListing, TokenGrant,
    is_text, is_text_char,
};
use agentconnect_core::{Identity, Rng};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};
use serde_json::Value;

fn config(cases: u32) -> Config {
    let mut c = Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    };
    if let Ok(n) = std::env::var("PROPTEST_CASES") {
        c.cases = n.parse().unwrap_or(c.cases);
    }
    if let Some(seed) = std::env::var("AC_TEST_SEED")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        c.rng_seed = RngSeed::Fixed(seed);
    }
    c
}

/// JSON values within the protocol's number rules (no floats, I-JSON
/// integers), with arbitrary Unicode strings and keys.
fn json_value() -> impl Strategy<Value = Value> {
    let max = i64::try_from(MAX_SAFE_INTEGER).unwrap_or(i64::MAX);
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-max..=max).prop_map(Value::from),
        any::<String>().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(any::<String>(), inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// One-line text of 1 to `max` characters: anything `is_text_char` allows
/// (SPEC 13.1.2).
fn text(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(
        any::<char>().prop_filter("one-line text", |c| {
            is_text_char(*c) && is_text(&c.to_string())
        }),
        1..=max,
    )
    .prop_map(|cs: Vec<char>| cs.into_iter().collect::<String>())
    .prop_filter("NFC", |s| is_text(s))
}

fn media_type() -> impl Strategy<Value = String> {
    "[a-z]{1,10}/[a-z0-9.+-]{1,20}"
}

fn skill() -> impl Strategy<Value = ListingSkill> {
    (
        text(80),
        text(80),
        text(120),
        prop::collection::vec(text(32), 1..=8),
        prop::collection::vec(text(60), 0..=4),
        prop::collection::vec(media_type(), 0..=3),
    )
        .prop_map(
            |(id, name, description, tags, examples, modes)| ListingSkill {
                id,
                name,
                description,
                tags,
                examples,
                input_modes: modes.clone(),
                output_modes: modes,
            },
        )
}

#[derive(Debug, Clone)]
struct CardText {
    name: String,
    description: String,
    version: String,
    organization: Option<String>,
    streaming: bool,
    modes: Vec<String>,
    skills: Vec<ListingSkill>,
    seq: u64,
}

fn card_text() -> impl Strategy<Value = CardText> {
    (
        text(80),
        text(500),
        text(32),
        prop::option::of(text(80)),
        any::<bool>(),
        prop::collection::vec(media_type(), 1..=8),
        prop::collection::vec(skill(), 1..=3),
        1..=MAX_SAFE_INTEGER,
    )
        .prop_map(
            |(name, description, version, organization, streaming, modes, skills, seq)| CardText {
                name,
                description,
                version,
                organization,
                streaming,
                modes,
                skills,
                seq,
            },
        )
}

struct Keys {
    ik: Identity,
    dk: DirectoryKey,
    rng: Rng,
}

fn keys() -> Keys {
    let rng = Rng::for_test("listing-props");
    Keys {
        ik: Identity::generate(&rng).unwrap(),
        dk: DirectoryKey::generate(&rng).unwrap(),
        rng,
    }
}

fn build(k: &Keys, t: CardText) -> ListingCard {
    let issued_at = 1_792_497_600;
    let grant = TokenGrant {
        directory: "agents.example".into(),
        name: "release-planner".into(),
        identity: k.ik.id(),
        owner_domain: Some("example.com".into()),
        issued_at,
        expires_at: issued_at + 3600,
    };
    ListingCard {
        name: t.name,
        description: t.description,
        version: t.version,
        provider: t.organization.map(|organization| ListingProvider {
            organization,
            url: "https://example.com/team".into(),
        }),
        streaming: t.streaming,
        push_notifications: false,
        default_input_modes: t.modes.clone(),
        default_output_modes: t.modes,
        skills: t.skills,
        extension_description: None,
        params: E2eParams {
            identity: k.ik.id(),
            name: "release-planner".into(),
            directory: "agents.example".into(),
            relay: "relay.example".into(),
            seq: t.seq,
            issued_at,
            door: None,
            owner_domain: Some("example.com".into()),
            token: k.dk.issue_token(&k.rng, &grant).unwrap(),
        },
    }
}

proptest! {
    #![proptest_config(config(64))]

    #[test]
    fn jcs_is_idempotent(v in json_value()) {
        let once = jcs(&v).unwrap();
        let back: Value = from_jcs(&once, "value").unwrap();
        prop_assert_eq!(&back, &v);
        prop_assert_eq!(jcs(&back).unwrap(), once);
    }
}

proptest! {
    #![proptest_config(config(24))]

    #[test]
    fn valid_cards_round_trip(t in card_text()) {
        let k = keys();
        let card = build(&k, t);
        let listing = card.sign(&k.ik).unwrap();
        prop_assert_eq!(listing.card(), &card);
        let back = SignedListing::from_bytes(listing.bytes()).unwrap();
        prop_assert_eq!(&back, &listing);
        let v: Value = serde_json::from_slice(listing.bytes()).unwrap();
        prop_assert_eq!(jcs(&v).unwrap(), listing.bytes().to_vec());
        // The unsigned form parses back from any formatting.
        let unsigned: Value = serde_json::from_slice(&card.to_unsigned_json().unwrap()).unwrap();
        let pretty = serde_json::to_vec_pretty(&unsigned).unwrap();
        prop_assert_eq!(ListingCard::from_unsigned_json(&pretty).unwrap(), card);
    }

    #[test]
    fn no_single_byte_change_is_accepted(t in card_text(), at in any::<prop::sample::Index>(), flip in 1u8..=255) {
        let k = keys();
        let listing = build(&k, t).sign(&k.ik).unwrap();
        let mut bytes = listing.bytes().to_vec();
        let i = at.index(bytes.len());
        bytes[i] ^= flip;
        prop_assert!(SignedListing::from_bytes(&bytes).is_err());
    }
}
