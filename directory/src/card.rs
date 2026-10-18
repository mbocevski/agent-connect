//! The display text of a listing's card.
//!
//! This runs only on bytes the [`Verifier`](crate::verify::Verifier) has
//! already accepted, and it decides nothing about trust: it pulls out the
//! text the pages, the Markdown copy, the search index and MCP show. Every
//! string here was written by whoever holds the listing's key and is
//! untrusted (SPEC §10.5). It is cleaned again (control characters replaced,
//! length capped) so a verifier bug can't turn into a rendering bug.

use serde::Deserialize;

/// Longest card name kept for display, in characters (Decision 1).
pub const MAX_NAME: usize = 80;
/// Longest description kept, in characters.
pub const MAX_DESCRIPTION: usize = 500;
/// Longest tag kept, in characters.
pub const MAX_TAG: usize = 32;
/// Most skills kept.
pub const MAX_SKILLS: usize = 16;
/// Most tags kept per skill.
pub const MAX_TAGS: usize = 8;
/// Largest card accepted, in bytes (the whole canonical card).
pub const MAX_CARD_BYTES: usize = 32 * 1024;

/// One skill of a card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    /// `skills[].id`.
    pub id: String,
    /// `skills[].name`.
    pub name: String,
    /// `skills[].tags`.
    pub tags: Vec<String>,
}

/// The text of a card, cleaned for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// `name`, the card's display name (not the listing slug).
    pub name: String,
    /// `description`.
    pub description: String,
    /// `provider.organization`. Show it only next to a verified domain.
    pub organization: Option<String>,
    /// `skills`.
    pub skills: Vec<Skill>,
}

/// The card could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardError;

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("card text is not readable")
    }
}

#[derive(Deserialize)]
struct RawCard {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    provider: Option<RawProvider>,
    #[serde(default)]
    skills: Vec<RawSkill>,
}

#[derive(Deserialize)]
struct RawProvider {
    #[serde(default)]
    organization: Option<String>,
}

#[derive(Deserialize)]
struct RawSkill {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// Replace control characters with U+FFFD and cap the length.
#[must_use]
pub fn clean(s: &str, max_chars: usize) -> String {
    s.chars()
        .take(max_chars)
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

impl Card {
    /// Read the display text of verified card bytes.
    ///
    /// # Errors
    ///
    /// [`CardError`] if the bytes are larger than [`MAX_CARD_BYTES`] or are
    /// not a JSON object with a string `name`.
    pub fn parse(bytes: &[u8]) -> Result<Self, CardError> {
        if bytes.len() > MAX_CARD_BYTES {
            return Err(CardError);
        }
        let raw: RawCard = serde_json::from_slice(bytes).map_err(|_| CardError)?;
        Ok(Self {
            name: clean(&raw.name, MAX_NAME),
            description: clean(&raw.description, MAX_DESCRIPTION),
            organization: raw
                .provider
                .and_then(|p| p.organization)
                .map(|o| clean(&o, MAX_NAME)),
            skills: raw
                .skills
                .into_iter()
                .take(MAX_SKILLS)
                .map(|s| Skill {
                    id: clean(&s.id, MAX_NAME),
                    name: clean(&s.name, MAX_NAME),
                    tags: s
                        .tags
                        .iter()
                        .take(MAX_TAGS)
                        .map(|t| clean(t, MAX_TAG))
                        .collect(),
                })
                .collect(),
        })
    }

    /// The words of the "skills: a · b" line: every tag once, in card order,
    /// or the skill names when no skill has tags.
    #[must_use]
    pub fn skill_words(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for t in self.skills.iter().flat_map(|s| &s.tags) {
            if !out.contains(t) {
                out.push(t.clone());
            }
        }
        if out.is_empty() {
            for s in &self.skills {
                if !s.name.is_empty() && !out.contains(&s.name) {
                    out.push(s.name.clone());
                }
            }
        }
        out
    }

    /// The `skill=` filter keys: every id, name and tag, lower-cased.
    #[must_use]
    pub fn skill_keys(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for s in &self.skills {
            for k in std::iter::once(&s.id)
                .chain(std::iter::once(&s.name))
                .chain(&s.tags)
            {
                let k = k.to_lowercase();
                if !k.is_empty() && !out.contains(&k) {
                    out.push(k);
                }
            }
        }
        out
    }

    /// The text of the skills for the full-text index: names and tags.
    #[must_use]
    pub fn skills_text(&self) -> String {
        let mut parts = Vec::new();
        for s in &self.skills {
            parts.push(s.name.clone());
            parts.extend(s.tags.iter().cloned());
        }
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bytes(v: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    #[test]
    fn reads_the_display_fields() {
        let c = Card::parse(&bytes(&json!({
            "name": "Release planner",
            "description": "Plans releases.",
            "provider": {"organization": "Example Ltd", "url": "https://example.com"},
            "skills": [
                {"id": "rp", "name": "Release planning", "tags": ["release planning", "scheduling"]},
                {"id": "x", "name": "Extra", "tags": ["scheduling"]}
            ],
            "unknown": 1
        })))
        .unwrap();
        assert_eq!(c.name, "Release planner");
        assert_eq!(c.organization.as_deref(), Some("Example Ltd"));
        assert_eq!(c.skill_words(), ["release planning", "scheduling"]);
        assert_eq!(
            c.skill_keys(),
            ["rp", "release planning", "scheduling", "x", "extra"]
        );
        assert_eq!(
            c.skills_text(),
            "Release planning release planning scheduling Extra scheduling"
        );
    }

    #[test]
    fn falls_back_to_skill_names_without_tags() {
        let c = Card::parse(&bytes(&json!({
            "name": "n", "skills": [{"id": "a", "name": "Alpha"}, {"id": "b", "name": "Alpha"}]
        })))
        .unwrap();
        assert_eq!(c.skill_words(), ["Alpha"]);
        assert!(c.organization.is_none());
    }

    #[test]
    fn cleans_control_characters_and_caps_lengths() {
        let long = "x".repeat(900);
        let c = Card::parse(&bytes(&json!({
            "name": "a\nb\u{7}c", "description": long
        })))
        .unwrap();
        assert_eq!(c.name, "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(c.description.chars().count(), MAX_DESCRIPTION);
    }

    #[test]
    fn rejects_what_is_not_a_card() {
        assert_eq!(Card::parse(b"[]"), Err(CardError));
        assert_eq!(Card::parse(b"{\"name\": 3}"), Err(CardError));
        assert_eq!(Card::parse(b"not json"), Err(CardError));
        let big = vec![b' '; MAX_CARD_BYTES + 1];
        assert_eq!(Card::parse(&big), Err(CardError));
        assert_eq!(CardError.to_string(), "card text is not readable");
    }
}
