//! Discovery: signed listings, listing tokens, withdrawals and owner
//! verification (SPEC §13.1, §13.2).
//!
//! This is the one implementation of these checks: the directory service and
//! the daemon (through the Python bindings) both verify through it.
//!
//! - [`SignedListing`]: a published listing, parsed and verified
//!   ([`SignedListing::from_bytes`]); [`ListingCard`] is its content, signed
//!   with [`ListingCard::sign`].
//! - [`ListingToken`], [`TokenRevocation`], [`DirectoryKey`] (the operator's
//!   signing key) and [`TrustedDirectory`] (the pinned public keys).
//! - [`Withdrawal`].
//! - [`OwnerFile`] (`/.well-known/agentconnect.json`), [`Vouch`] and
//!   [`owner_state`].
//!
//! Doors and knocks are in [`crate::knock`].

mod card;
mod owner;
mod token;
mod withdrawal;

pub use card::{
    E2eParams, ListedDoor, ListingCard, ListingProvider, ListingSkill, MAX_LISTING_BYTES,
    SignedListing, protected_header,
};
pub use owner::{
    FetchResult, LatestFetch, MAX_OWNER_FILE_BYTES, OWNER_FILE_PATH, OwnerChecks, OwnerFile,
    OwnerIdentity, OwnerRevocation, OwnerState, RevocationReason, STALE_AFTER_SECS,
    VERIFIED_FOR_SECS, Vouch, owner_file_url, owner_state,
};
pub use token::{
    DirectoryKey, ListingToken, MAX_TOKEN_LIFETIME_SECS, TOKEN_SKEW_SECS, TokenGrant,
    TokenRevocation, TrustedDirectory, directory_key_id,
};
pub use withdrawal::{WITHDRAWAL_SKEW_SECS, Withdrawal};

use ed25519_dalek::{Signature, VerifyingKey};

use crate::identity::canonical_relay_host;

/// The `e2e` extension URI (SPEC §13.1).
pub const E2E_EXTENSION_URI: &str = "https://yggdrasill.network/ext/agentconnect/e2e/v0";
/// `supportedInterfaces[0].protocolBinding` of a listing (SPEC §13.1.2).
pub const PROTOCOL_BINDING: &str = "AGENTCONNECT";
/// The longest a door may live, from the listing's `issued_at` (SPEC §6.6.1).
pub const MAX_DOOR_LIFETIME_SECS: u64 = 7 * 24 * 3600;
/// How far in the future a published `issued_at` may be (SPEC §13.2.2).
pub const PUBLISH_SKEW_SECS: u64 = 300;

/// Whether `s` is a listing name: 3 to 32 characters of `[a-z0-9-]`,
/// starting and ending with a letter or digit (SPEC §13.1.1).
#[must_use]
pub fn is_listing_name(s: &str) -> bool {
    let b = s.as_bytes();
    let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (3..=32).contains(&b.len())
        && b.iter().all(|c| alnum(c) || *c == b'-')
        && b.first().is_some_and(alnum)
        && b.last().is_some_and(alnum)
}

/// Whether `s` is an owner domain: a lower-case ASCII DNS name in A-label
/// form with at least two labels, no port, no IP literal and no trailing
/// dot (SPEC §13.1.1).
#[must_use]
pub fn is_owner_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    labels.len() >= 2
        && labels.iter().all(label_ok)
        // An all-digit last label would make this an IPv4 literal.
        && labels
            .last()
            .is_some_and(|l| !l.bytes().all(|c| c.is_ascii_digit()))
}

/// Whether `s` is a host already in the canonical form of SPEC §8.1.1.
#[must_use]
pub fn is_canonical_host(s: &str) -> bool {
    canonical_relay_host(s).is_ok_and(|c| c == s)
}

/// The Unicode version whose general categories [`is_text_char`] uses
/// (SPEC §13.1.2).
pub const TEXT_UNICODE_VERSION: (u64, u64, u64) = unicode_properties::UNICODE_VERSION;

/// Whether `c` may appear in single-line text (SPEC §13.1.2): not a
/// control (Cc), format (Cf), line or paragraph separator (Zl, Zp),
/// private-use (Co) or unassigned (Cn) character in Unicode 17.0.0, and no
/// space separator (Zs) but U+0020. (Surrogates, Cs, can't be a `char`.)
#[must_use]
pub fn is_text_char(c: char) -> bool {
    use unicode_properties::{GeneralCategory as G, UnicodeGeneralCategory as _};
    match c.general_category() {
        G::Control
        | G::Format
        | G::LineSeparator
        | G::ParagraphSeparator
        | G::PrivateUse
        | G::Surrogate
        | G::Unassigned => false,
        G::SpaceSeparator => c == ' ',
        _ => true,
    }
}

/// Single-line text (SPEC §13.1.2): 1 to `max` Unicode scalar values, each
/// allowed by [`is_text_char`].
#[must_use]
pub fn is_one_line_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max && s.chars().all(is_text_char)
}

fn text_ok(s: &str, max: usize) -> bool {
    is_one_line_text(s, max)
}

/// Strict Ed25519 verification (as for SPEC §3.3).
fn verify_ed25519(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public)
        .is_ok_and(|k| k.verify_strict(msg, &Signature::from_bytes(sig)).is_ok())
}

/// Test fixtures shared by the listing, knock and vector tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::identity::Identity;
    use crate::mls::HPKE_PUBLIC_KEY_LEN;
    use crate::rng::Rng;

    pub(crate) const DIRECTORY: &str = "agents.example";
    pub(crate) const RELAY: &str = "relay.example";
    pub(crate) const T0: u64 = 1_792_497_600;

    /// A directory key, its trust anchor, an identity and a valid card for
    /// that identity, all derived from `rng`.
    pub(crate) struct Fixture {
        pub dk: DirectoryKey,
        pub trusted: TrustedDirectory,
        pub ik: Identity,
        pub card: ListingCard,
    }

    pub(crate) fn grant(identity: &str) -> TokenGrant {
        TokenGrant {
            directory: DIRECTORY.into(),
            name: "release-planner".into(),
            identity: identity.into(),
            owner_domain: Some("example.com".into()),
            issued_at: T0,
            expires_at: T0 + 30 * 24 * 3600,
        }
    }

    pub(crate) fn card_for(
        ik: &Identity,
        token: ListingToken,
        door: Option<ListedDoor>,
    ) -> ListingCard {
        ListingCard {
            name: "Release planner".into(),
            description: "Plans release trains and drafts schedules from a list of changes.".into(),
            version: "1.4.0".into(),
            provider: Some(ListingProvider {
                organization: "Example Ltd".into(),
                url: "https://example.com".into(),
            }),
            streaming: false,
            push_notifications: false,
            default_input_modes: vec!["text/plain".into()],
            default_output_modes: vec!["text/plain".into()],
            skills: vec![ListingSkill {
                id: "release-planning".into(),
                name: "Release planning".into(),
                description: "Turns a change list into a dated release plan.".into(),
                tags: vec!["release planning".into(), "scheduling".into()],
                examples: vec![],
                input_modes: vec![],
                output_modes: vec![],
            }],
            extension_description: Some(
                "Reachable end-to-end encrypted through AgentConnect. Knock to connect; a human approves every connection."
                    .into(),
            ),
            params: E2eParams {
                identity: ik.id(),
                name: "release-planner".into(),
                directory: DIRECTORY.into(),
                relay: RELAY.into(),
                seq: 7,
                issued_at: T0,
                door,
                owner_domain: Some("example.com".into()),
                token,
            },
        }
    }

    /// A door of random (not HPKE-valid) key bytes: enough for the card.
    pub(crate) fn random_door(rng: &Rng) -> ListedDoor {
        let mut key = vec![0u8; HPKE_PUBLIC_KEY_LEN];
        rng.fill(&mut key).unwrap();
        ListedDoor {
            id: rng.array().unwrap(),
            key,
            expires_at: T0 + 7 * 24 * 3600,
        }
    }

    pub(crate) fn fixture(label: &str) -> Fixture {
        let rng = Rng::for_test(label);
        fixture_from(&rng)
    }

    pub(crate) fn fixture_from(rng: &Rng) -> Fixture {
        let dk = DirectoryKey::generate(rng).unwrap();
        let trusted = TrustedDirectory::new(DIRECTORY, &[dk.public_key()]).unwrap();
        let ik = Identity::generate(rng).unwrap();
        let token = dk.issue_token(rng, &grant(&ik.id())).unwrap();
        let card = card_for(&ik, token, Some(random_door(rng)));
        Fixture {
            dk,
            trusted,
            ik,
            card,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_names_are_ascii_slugs() {
        for ok in ["abc", "release-planner", "a1b", &"a".repeat(32), "0-0"] {
            assert!(is_listing_name(ok), "{ok}");
        }
        for bad in [
            "ab",
            &"a".repeat(33),
            "-ab",
            "ab-",
            "Abc",
            "a_b",
            "a.b",
            "ab\u{e9}",
            "r\u{435}lease",
            "",
        ] {
            assert!(!is_listing_name(bad), "{bad}");
        }
    }

    #[test]
    fn owner_domains_are_lowercase_a_labels() {
        for ok in [
            "example.com",
            "a.b.c",
            "xn--bcher-kva.example",
            "1x.io",
            "a-b.co",
        ] {
            assert!(is_owner_domain(ok), "{ok}");
        }
        for bad in [
            "example",
            "Example.com",
            "example.com.",
            "example.com:443",
            "127.0.0.1",
            "[::1]",
            "-a.com",
            "a-.com",
            "a..com",
            "b\u{fc}cher.example",
            &format!("{}.com", "a".repeat(64)),
            &format!("{}.com", "a.".repeat(126)),
            "",
        ] {
            assert!(!is_owner_domain(bad), "{bad}");
        }
    }

    /// Review M2: Cc is not the only way to break a line or disguise text.
    #[test]
    fn text_rejects_line_format_private_and_unassigned_characters() {
        for bad in [
            '\u{9}',      // tab (Cc)
            '\u{85}',     // NEL (Cc)
            '\u{2028}',   // LINE SEPARATOR (Zl)
            '\u{2029}',   // PARAGRAPH SEPARATOR (Zp)
            '\u{202E}',   // RIGHT-TO-LEFT OVERRIDE (Cf)
            '\u{2066}',   // LEFT-TO-RIGHT ISOLATE (Cf)
            '\u{200B}',   // ZERO WIDTH SPACE (Cf)
            '\u{200D}',   // ZERO WIDTH JOINER (Cf)
            '\u{FEFF}',   // BOM (Cf)
            '\u{AD}',     // SOFT HYPHEN (Cf)
            '\u{E0041}',  // TAG LATIN CAPITAL LETTER A (Cf)
            '\u{E000}',   // private use (Co)
            '\u{10FFFD}', // supplementary private use (Co)
            '\u{A0}',     // NO-BREAK SPACE (Zs other than U+0020)
            '\u{3000}',   // IDEOGRAPHIC SPACE (Zs)
            '\u{0378}',   // unassigned (Cn)
            '\u{FFFF}',   // noncharacter (Cn)
        ] {
            assert!(!is_text_char(bad), "U+{:04X}", u32::from(bad));
            assert!(
                !is_one_line_text(&format!("a{bad}b"), 80),
                "U+{:04X}",
                u32::from(bad)
            );
        }
        for ok in [
            ' ',
            'a',
            '\u{e9}',
            '\u{1F600}',
            '\u{4E2D}',
            '\u{0627}',
            '-',
            '\u{2014}',
        ] {
            assert!(is_text_char(ok), "U+{:04X}", u32::from(ok));
        }
    }

    #[test]
    fn canonical_hosts_and_text() {
        assert!(is_canonical_host("agents.example"));
        assert!(is_canonical_host("relay.test:8443"));
        assert!(!is_canonical_host("Agents.example"));
        assert!(!is_canonical_host("a/b"));
        assert!(text_ok("one line", 8));
        assert!(!text_ok("one line", 7));
        assert!(!text_ok("", 7));
        assert!(!text_ok("two\nlines", 80));
        assert!(!text_ok("bell\u{7}", 80));
        assert!(text_ok("\u{e9}\u{e9}", 2));
    }
}
