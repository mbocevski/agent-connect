//! The listing: a signed A2A v1.0 `AgentCard` with the `e2e` extension
//! (SPEC §13.1).
//!
//! Parsing goes bytes → canonical-form check → profile check (no empty
//! values, no defaults) → closed-schema decode → field rules → re-encode,
//! and the re-encoded bytes must equal the input. One byte string is
//! accepted per listing.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::token::{ListingToken, TokenJson, TrustedDirectory};
use super::{
    E2E_EXTENSION_URI, MAX_DOOR_LIFETIME_SECS, PROTOCOL_BINDING, PUBLISH_SKEW_SECS,
    is_canonical_host, is_listing_name, is_owner_domain, text_ok, verify_ed25519,
};
use crate::encoding::parse_json_unique_keys;
use crate::encoding::{MAX_SAFE_INTEGER, b64, b64_decode, b64_decode_array, jcs};
use crate::error::{Error, Result};
use crate::identity::{Identity, fingerprint, parse_identity};
use crate::mls::HPKE_PUBLIC_KEY_LEN;

/// The largest canonical listing (SPEC §13.1.2).
pub const MAX_LISTING_BYTES: usize = 32 * 1024;

const MAX_NAME: usize = 80;
const MAX_DESCRIPTION: usize = 500;
const MAX_VERSION: usize = 32;
const MAX_ORGANIZATION: usize = 80;
const MAX_PROVIDER_URL: usize = 256;
const MAX_SKILLS: usize = 16;
const MAX_SKILL_ID: usize = 80;
const MAX_TAGS: usize = 8;
const MAX_TAG: usize = 32;
const MAX_EXAMPLES: usize = 4;
const MAX_EXAMPLE: usize = 200;
const MAX_MODES: usize = 8;
const MAX_MEDIA_TYPE: usize = 127;

const fn bad(what: &'static str) -> Error {
    Error::InvalidListing(what)
}

/// `provider` of a listing. Shown only next to a verified owner domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingProvider {
    /// At most 80 characters.
    pub organization: String,
    /// `https://<owner_domain>` or a path under it.
    pub url: String,
}

/// One skill of a listing. Empty lists are encoded as absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingSkill {
    /// At most 80 characters.
    pub id: String,
    /// At most 80 characters.
    pub name: String,
    /// At most 500 characters.
    pub description: String,
    /// 1 to 8 tags of at most 32 characters.
    pub tags: Vec<String>,
    /// At most 4 examples of at most 200 characters.
    pub examples: Vec<String>,
    /// At most 8 media types.
    pub input_modes: Vec<String>,
    /// At most 8 media types.
    pub output_modes: Vec<String>,
}

/// The door a listing advertises (SPEC §13.1.1).
#[derive(Clone, PartialEq, Eq)]
pub struct ListedDoor {
    /// `door_id`.
    pub id: [u8; 16],
    /// The door's HPKE public key (1216 bytes).
    pub key: Vec<u8>,
    /// Unix seconds; after `issued_at`, at most 7 days after it.
    pub expires_at: u64,
}

/// The `e2e` extension params (SPEC §13.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eParams {
    /// `ac:v0:…`, the key that signs the listing.
    pub identity: String,
    /// The listing name (slug).
    pub name: String,
    /// The directory host.
    pub directory: String,
    /// The relay host knocks go through.
    pub relay: String,
    /// Positive, increasing with every listing of this name.
    pub seq: u64,
    /// Unix seconds.
    pub issued_at: u64,
    /// The door, or `None` when it is closed.
    pub door: Option<ListedDoor>,
    /// The claimed owner domain.
    pub owner_domain: Option<String>,
    /// The operator-issued token.
    pub token: ListingToken,
}

/// The content of a listing: everything but the signature.
///
/// The interface (`supportedInterfaces`) and the extension URI are derived
/// from the params, so they can't disagree with them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingCard {
    /// At most 80 characters.
    pub name: String,
    /// At most 500 characters.
    pub description: String,
    /// At most 32 characters.
    pub version: String,
    /// Optional provider; needs `owner_domain`.
    pub provider: Option<ListingProvider>,
    /// `capabilities.streaming` (`false` is encoded as absent).
    pub streaming: bool,
    /// `capabilities.pushNotifications` (`false` is encoded as absent).
    pub push_notifications: bool,
    /// 1 to 8 media types.
    pub default_input_modes: Vec<String>,
    /// 1 to 8 media types.
    pub default_output_modes: Vec<String>,
    /// 1 to 16 skills.
    pub skills: Vec<ListingSkill>,
    /// The extension's optional `description`.
    pub extension_description: Option<String>,
    /// The `e2e` params.
    pub params: E2eParams,
}

// ---- JSON layer: the closed schema, field for field ----

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CardJson {
    name: String,
    description: String,
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider: Option<ProviderJson>,
    capabilities: CapabilitiesJson,
    default_input_modes: Vec<String>,
    default_output_modes: Vec<String>,
    skills: Vec<SkillJson>,
    supported_interfaces: Vec<InterfaceJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signatures: Option<Vec<SignatureJson>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderJson {
    organization: String,
    url: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CapabilitiesJson {
    extensions: Vec<ExtensionJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    streaming: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    push_notifications: Option<bool>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtensionJson {
    uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    required: bool,
    params: ParamsJson,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParamsJson {
    v: u64,
    identity: String,
    name: String,
    directory: String,
    relay: String,
    seq: u64,
    issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    door: Option<DoorJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_domain: Option<String>,
    token: TokenJson,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DoorJson {
    id: String,
    key: String,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SkillJson {
    id: String,
    name: String,
    description: String,
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    examples: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input_modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output_modes: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InterfaceJson {
    url: String,
    protocol_binding: String,
    protocol_version: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureJson {
    protected: String,
    signature: String,
}

fn non_empty(v: &[String]) -> Option<Vec<String>> {
    (!v.is_empty()).then(|| v.to_vec())
}

/// SPEC §13.1.3 rule 1 and the Cc rule, over the raw JSON: no empty
/// string, array or object, no `null`, no control characters, and outside
/// `params` no proto3 default (`false`, `0`).
fn check_profile(v: &Value, in_params: bool) -> Result<()> {
    match v {
        Value::Null => Err(bad("null value")),
        Value::Bool(false) if !in_params => Err(bad("default value (false)")),
        Value::Number(n) if !in_params && n.as_u64() == Some(0) => Err(bad("default value (0)")),
        Value::String(s) if s.is_empty() => Err(bad("empty string")),
        Value::String(s) if s.chars().any(char::is_control) => Err(bad("control character")),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
        Value::Array(items) if items.is_empty() => Err(bad("empty array")),
        Value::Array(items) => items.iter().try_for_each(|i| check_profile(i, in_params)),
        Value::Object(map) if map.is_empty() => Err(bad("empty object")),
        Value::Object(map) => map
            .iter()
            .try_for_each(|(k, v)| check_profile(v, in_params || k == "params")),
    }
}

fn text(s: &str, max: usize, what: &'static str) -> Result<()> {
    if text_ok(s, max) {
        Ok(())
    } else {
        Err(bad(what))
    }
}

fn modes(list: &[String], required: bool, what: &'static str) -> Result<()> {
    let media_ok = |m: &String| {
        !m.is_empty() && m.len() <= MAX_MEDIA_TYPE && m.bytes().all(|c| (b' '..=b'~').contains(&c))
    };
    if (required && list.is_empty()) || list.len() > MAX_MODES || !list.iter().all(media_ok) {
        return Err(bad(what));
    }
    Ok(())
}

/// The protected header for `identity`: base64url of the JCS of exactly
/// `{"alg":"EdDSA","kid":<identity>,"typ":"JOSE"}` (SPEC §13.1.4).
///
/// # Errors
///
/// Only if serialisation fails.
pub fn protected_header(identity: &str) -> Result<String> {
    Ok(b64(&jcs(
        &json!({"alg": "EdDSA", "kid": identity, "typ": "JOSE"}),
    )?))
}

/// Explains why a protected header isn't the one expected for `identity`.
fn protected_error(protected: &str, identity: &str) -> Error {
    let header = b64_decode(protected, "protected")
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let Some(Value::Object(h)) = header else {
        return bad("protected header encoding");
    };
    if ["jku", "jwk", "x5u", "x5c", "crit"]
        .iter()
        .any(|k| h.contains_key(*k))
    {
        return bad("protected header names a key location");
    }
    if h.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return bad("alg must be EdDSA");
    }
    if h.get("kid").and_then(Value::as_str) != Some(identity) {
        return bad("kid is not params.identity");
    }
    bad("protected header")
}

impl std::fmt::Debug for ListedDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListedDoor")
            .field("id", &b64(&self.id))
            .field("key_len", &self.key.len())
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl std::fmt::Debug for SignedListing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedListing")
            .field("name", &self.card.params.name)
            .field("identity", &self.card.params.identity)
            .field("seq", &self.card.params.seq)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl ListedDoor {
    fn json(&self) -> DoorJson {
        DoorJson {
            id: b64(&self.id),
            key: b64(&self.key),
            expires_at: self.expires_at,
        }
    }
}

impl E2eParams {
    fn json(&self) -> ParamsJson {
        ParamsJson {
            v: 0,
            identity: self.identity.clone(),
            name: self.name.clone(),
            directory: self.directory.clone(),
            relay: self.relay.clone(),
            seq: self.seq,
            issued_at: self.issued_at,
            door: self.door.as_ref().map(ListedDoor::json),
            owner_domain: self.owner_domain.clone(),
            token: self.token.json(true),
        }
    }

    fn from_json(raw: ParamsJson) -> Result<Self> {
        if raw.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        let door = match raw.door {
            None => None,
            Some(d) => Some(ListedDoor {
                id: b64_decode_array(&d.id, "door id").map_err(|_| bad("door id"))?,
                key: b64_decode(&d.key, "door key").map_err(|_| bad("door key"))?,
                expires_at: d.expires_at,
            }),
        };
        Ok(Self {
            identity: raw.identity,
            name: raw.name,
            directory: raw.directory,
            relay: raw.relay,
            seq: raw.seq,
            issued_at: raw.issued_at,
            door,
            owner_domain: raw.owner_domain,
            token: ListingToken::from_raw(raw.token)?,
        })
    }

    fn validate(&self) -> Result<()> {
        parse_identity(&self.identity).map_err(|_| bad("identity"))?;
        if !is_listing_name(&self.name) {
            return Err(bad("name (slug)"));
        }
        if !is_canonical_host(&self.directory) {
            return Err(bad("directory host"));
        }
        if !is_canonical_host(&self.relay) {
            return Err(bad("relay host"));
        }
        if self.seq == 0 || self.seq > MAX_SAFE_INTEGER || self.issued_at > MAX_SAFE_INTEGER {
            return Err(bad("seq or issued_at"));
        }
        if let Some(door) = &self.door {
            if door.key.len() != HPKE_PUBLIC_KEY_LEN {
                return Err(bad("door key length"));
            }
            if door.expires_at <= self.issued_at
                || door.expires_at - self.issued_at > MAX_DOOR_LIFETIME_SECS
            {
                return Err(bad("door expires_at"));
            }
        }
        if self
            .owner_domain
            .as_deref()
            .is_some_and(|d| !is_owner_domain(d))
        {
            return Err(bad("owner_domain"));
        }
        let g = &self.token.grant;
        if g.name != self.name {
            return Err(bad("token name differs"));
        }
        if g.directory != self.directory {
            return Err(bad("token directory differs"));
        }
        Ok(())
    }
}

impl ListingSkill {
    fn json(&self) -> SkillJson {
        SkillJson {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            tags: self.tags.clone(),
            examples: non_empty(&self.examples),
            input_modes: non_empty(&self.input_modes),
            output_modes: non_empty(&self.output_modes),
        }
    }

    fn validate(&self) -> Result<()> {
        text(&self.id, MAX_SKILL_ID, "skill id")?;
        text(&self.name, MAX_NAME, "skill name")?;
        text(&self.description, MAX_DESCRIPTION, "skill description")?;
        if self.tags.is_empty()
            || self.tags.len() > MAX_TAGS
            || !self.tags.iter().all(|t| text_ok(t, MAX_TAG))
        {
            return Err(bad("skill tags"));
        }
        if self.examples.len() > MAX_EXAMPLES
            || !self.examples.iter().all(|e| text_ok(e, MAX_EXAMPLE))
        {
            return Err(bad("skill examples"));
        }
        modes(&self.input_modes, false, "skill inputModes")?;
        modes(&self.output_modes, false, "skill outputModes")
    }
}

impl ListingCard {
    /// The interface URL: `https://<directory>/a/<name>.json`.
    #[must_use]
    pub fn url(&self) -> String {
        format!(
            "https://{}/a/{}.json",
            self.params.directory, self.params.name
        )
    }

    fn json(&self, signature: Option<&SignatureJson>) -> CardJson {
        CardJson {
            name: self.name.clone(),
            description: self.description.clone(),
            version: self.version.clone(),
            provider: self.provider.as_ref().map(|p| ProviderJson {
                organization: p.organization.clone(),
                url: p.url.clone(),
            }),
            capabilities: CapabilitiesJson {
                extensions: vec![ExtensionJson {
                    uri: E2E_EXTENSION_URI.to_owned(),
                    description: self.extension_description.clone(),
                    required: true,
                    params: self.params.json(),
                }],
                streaming: self.streaming.then_some(true),
                push_notifications: self.push_notifications.then_some(true),
            },
            default_input_modes: self.default_input_modes.clone(),
            default_output_modes: self.default_output_modes.clone(),
            skills: self.skills.iter().map(ListingSkill::json).collect(),
            supported_interfaces: vec![InterfaceJson {
                url: self.url(),
                protocol_binding: PROTOCOL_BINDING.to_owned(),
                protocol_version: "0".to_owned(),
            }],
            signatures: signature.map(|s| vec![s.clone()]),
        }
    }

    /// Decodes the closed-schema JSON into a card (and its signatures) and
    /// checks every rule of SPEC §13.1.
    fn from_json(raw: CardJson) -> Result<(Self, Option<Vec<SignatureJson>>)> {
        let CapabilitiesJson {
            mut extensions,
            streaming,
            push_notifications,
        } = raw.capabilities;
        if extensions.len() != 1 {
            return Err(bad("exactly one extension"));
        }
        let ext = extensions.remove(0);
        if ext.uri != E2E_EXTENSION_URI {
            return Err(bad("extension uri"));
        }
        if !ext.required {
            return Err(bad("extension must be required"));
        }
        let params = E2eParams::from_json(ext.params)?;
        let card = Self {
            name: raw.name,
            description: raw.description,
            version: raw.version,
            provider: raw.provider.map(|p| ListingProvider {
                organization: p.organization,
                url: p.url,
            }),
            streaming: streaming == Some(true),
            push_notifications: push_notifications == Some(true),
            default_input_modes: raw.default_input_modes,
            default_output_modes: raw.default_output_modes,
            skills: raw
                .skills
                .into_iter()
                .map(|s| ListingSkill {
                    id: s.id,
                    name: s.name,
                    description: s.description,
                    tags: s.tags,
                    examples: s.examples.unwrap_or_default(),
                    input_modes: s.input_modes.unwrap_or_default(),
                    output_modes: s.output_modes.unwrap_or_default(),
                })
                .collect(),
            extension_description: ext.description,
            params,
        };
        card.validate()?;
        let [interface] = raw.supported_interfaces.as_slice() else {
            return Err(bad("exactly one interface"));
        };
        if interface.protocol_binding != PROTOCOL_BINDING
            || interface.protocol_version != "0"
            || interface.url != card.url()
        {
            return Err(bad("interface"));
        }
        Ok((card, raw.signatures))
    }

    /// Checks every rule of SPEC §13.1.1 and §13.1.2 on the card's fields
    /// (the encoding rules follow from the types).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidListing`] naming the first rule broken.
    pub fn validate(&self) -> Result<()> {
        text(&self.name, MAX_NAME, "name")?;
        text(&self.description, MAX_DESCRIPTION, "description")?;
        text(&self.version, MAX_VERSION, "version")?;
        if let Some(d) = &self.extension_description {
            text(d, MAX_DESCRIPTION, "extension description")?;
        }
        modes(&self.default_input_modes, true, "defaultInputModes")?;
        modes(&self.default_output_modes, true, "defaultOutputModes")?;
        if self.skills.is_empty() || self.skills.len() > MAX_SKILLS {
            return Err(bad("1 to 16 skills"));
        }
        self.skills.iter().try_for_each(ListingSkill::validate)?;
        self.params.validate()?;
        if let Some(p) = &self.provider {
            text(&p.organization, MAX_ORGANIZATION, "provider organization")?;
            let domain = self
                .params
                .owner_domain
                .as_deref()
                .ok_or(bad("provider needs owner_domain"))?;
            let base = format!("https://{domain}");
            let under = p.url == base
                || p.url
                    .strip_prefix(&base)
                    .is_some_and(|rest| rest.starts_with('/'));
            let clean = p.url.len() <= MAX_PROVIDER_URL
                && p.url.bytes().all(|c| (b'!'..=b'~').contains(&c))
                && !p.url.contains(['?', '#', '\\']);
            if !under || !clean {
                return Err(bad("provider url is not under owner_domain"));
            }
        }
        Ok(())
    }

    /// Parses a card to sign: JSON in any formatting (but with no duplicate
    /// keys), without `signatures`, that follows every other rule of SPEC
    /// §13.1. The daemon builds the card its human approves this way.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidListing`] (or a token or version error from the
    /// params).
    pub fn from_unsigned_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2 * MAX_LISTING_BYTES {
            return Err(bad("too large"));
        }
        let value = parse_json_unique_keys(bytes, "listing").map_err(|_| bad("json"))?;
        check_profile(&value, false)?;
        let raw: CardJson = serde_json::from_value(value).map_err(|_| bad("schema"))?;
        if raw.signatures.is_some() {
            return Err(bad("an unsigned card has no signatures"));
        }
        let (card, _) = Self::from_json(raw)?;
        Ok(card)
    }

    /// The signed payload: JCS of the card without `signatures` (SPEC
    /// §13.1.3 rule 4). Also what a human is shown before signing.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidListing`] if the card breaks a rule.
    pub fn to_unsigned_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        jcs(&self.json(None))
    }

    /// Signs the card with `ik`, which must be `params.identity`, and
    /// returns the verified listing.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidListing`] if `ik` isn't the listed identity, the card
    /// breaks a rule or is too large.
    pub fn sign(&self, ik: &Identity) -> Result<SignedListing> {
        let payload = self.to_unsigned_json()?;
        if ik.id() != self.params.identity {
            return Err(bad("signing key is not params.identity"));
        }
        let protected = protected_header(&self.params.identity)?;
        let input = format!("{protected}.{}", b64(&payload));
        let signature = SignatureJson {
            protected,
            signature: b64(&ik.sign(input.as_bytes())),
        };
        SignedListing::from_bytes(&jcs(&self.json(Some(&signature)))?)
    }
}

/// A published listing that passed every check of SPEC §13.1, including
/// its JWS. The token's signature, expiry and revocation are checked
/// separately against pinned directory keys
/// ([`SignedListing::check_token`]).
#[derive(Clone, PartialEq, Eq)]
pub struct SignedListing {
    card: ListingCard,
    bytes: Vec<u8>,
    signature: [u8; 64],
}

impl SignedListing {
    /// Parses and verifies published listing bytes (SPEC §13.1): size,
    /// byte-for-byte canonical JCS, the profile, the closed schema, every
    /// field rule, exactly one signature with exactly the expected
    /// protected header, and the Ed25519 signature under the key `kid`
    /// names.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidListing`] naming the failed check, or a format error
    /// of the embedded token ([`Error::InvalidToken`]) or a `v` other than
    /// 0 ([`Error::UnsupportedVersion`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_LISTING_BYTES {
            return Err(bad("too large"));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|_| bad("json"))?;
        if jcs(&value).map_err(|_| bad("number (floats and big integers are not allowed)"))?
            != bytes
        {
            return Err(bad("not canonical JCS"));
        }
        check_profile(&value, false)?;
        let raw: CardJson = serde_json::from_value(value).map_err(|_| bad("schema"))?;
        let (card, signatures) = ListingCard::from_json(raw)?;
        let signatures = signatures.ok_or(bad("no signature"))?;
        let [sig] = signatures.as_slice() else {
            return Err(bad("exactly one signature"));
        };
        if sig.protected != protected_header(&card.params.identity)? {
            return Err(protected_error(&sig.protected, &card.params.identity));
        }
        let signature: [u8; 64] =
            b64_decode_array(&sig.signature, "signature").map_err(|_| bad("signature encoding"))?;
        let listing = Self {
            card,
            bytes: bytes.to_vec(),
            signature,
        };
        // The decoded card re-encodes to exactly the input.
        if jcs(&listing.card.json(Some(sig)))? != bytes {
            return Err(bad("not canonical"));
        }
        let ik = parse_identity(&listing.card.params.identity).map_err(|_| bad("identity"))?;
        if !verify_ed25519(&ik, &listing.signing_input()?, &listing.signature) {
            return Err(bad("signature"));
        }
        Ok(listing)
    }

    /// `protected ‖ "." ‖ base64url(payload)`, the bytes Ed25519 signs.
    fn signing_input(&self) -> Result<Vec<u8>> {
        let protected = protected_header(&self.card.params.identity)?;
        let payload = jcs(&self.card.json(None))?;
        Ok(format!("{protected}.{}", b64(&payload)).into_bytes())
    }

    /// The card.
    #[must_use]
    pub fn card(&self) -> &ListingCard {
        &self.card
    }

    /// The `e2e` params.
    #[must_use]
    pub fn params(&self) -> &E2eParams {
        &self.card.params
    }

    /// The token embedded in the params.
    #[must_use]
    pub fn token(&self) -> &ListingToken {
        &self.card.params.token
    }

    /// The published bytes (canonical JCS, signature included).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of the published bytes: the `ETag` and cache key.
    #[must_use]
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    /// The JWS signature.
    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The §2 fingerprint of the listed identity.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        // `from_bytes` checked that the identity parses.
        parse_identity(&self.card.params.identity)
            .map(|k| fingerprint(&k))
            .unwrap_or_default()
    }

    /// The listing's canonical URL, `https://<directory>/a/<name>.json`.
    #[must_use]
    pub fn url(&self) -> String {
        self.card.url()
    }

    /// Whether the listing advertises a door that hasn't expired at `now`.
    #[must_use]
    pub fn door_open(&self, now: u64) -> bool {
        self.card
            .params
            .door
            .as_ref()
            .is_some_and(|d| now < d.expires_at)
    }

    /// SPEC §13.2.1: the token verifies under a key pinned for the
    /// listing's directory, binds this listing (directory, name, identity,
    /// owner domain), hasn't expired at `now`, and `is_revoked` doesn't
    /// know its `token_id`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] naming the failed check.
    pub fn check_token(
        &self,
        trusted: &TrustedDirectory,
        now: u64,
        is_revoked: impl Fn(&[u8; 16]) -> bool,
    ) -> Result<()> {
        let p = &self.card.params;
        let token = &p.token;
        token.check_binding(
            &p.directory,
            &p.name,
            &p.identity,
            p.owner_domain.as_deref(),
        )?;
        token.verify(trusted, now)?;
        if is_revoked(&token.token_id) {
            return Err(Error::InvalidToken("revoked"));
        }
        Ok(())
    }

    /// The time checks of a publish (SPEC §13.2.2): `issued_at` is at most
    /// 300 s in the future, and a door, if present, hasn't expired. The
    /// `seq`, tombstone and relay checks need the directory's state.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidListing`] naming the failed check.
    pub fn check_publish(&self, now: u64) -> Result<()> {
        let p = &self.card.params;
        if p.issued_at > now.saturating_add(PUBLISH_SKEW_SECS) {
            return Err(bad("issued_at is in the future"));
        }
        if p.door.as_ref().is_some_and(|d| d.expires_at <= now) {
            return Err(bad("door has expired"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::Withdrawal;
    use crate::listing::testing::{Fixture, T0, card_for, fixture, grant};
    use crate::rng::Rng;

    fn signed(f: &Fixture) -> SignedListing {
        f.card.sign(&f.ik).unwrap()
    }

    fn value(l: &SignedListing) -> Value {
        serde_json::from_slice(l.bytes()).unwrap()
    }

    /// Re-signs a (mutated) card value with `ik` under `protected`, so that
    /// only the mutation can make it fail.
    fn resign_with(mut v: Value, ik: &Identity, protected: &str) -> Vec<u8> {
        v.as_object_mut().unwrap().remove("signatures");
        let input = format!("{protected}.{}", b64(&jcs(&v).unwrap()));
        let sig = b64(&ik.sign(input.as_bytes()));
        v["signatures"] = json!([{"protected": protected, "signature": sig}]);
        jcs(&v).unwrap()
    }

    fn resign(v: Value, ik: &Identity) -> Vec<u8> {
        let protected = protected_header(&ik.id()).unwrap();
        resign_with(v, ik, &protected)
    }

    type Case = (&'static str, Box<dyn Fn(&mut Value)>, Error);

    fn err(bytes: &[u8]) -> Error {
        SignedListing::from_bytes(bytes).unwrap_err()
    }

    #[test]
    fn signed_listing_round_trips() {
        let f = fixture("card-round-trip");
        let l = signed(&f);
        assert_eq!(l.card(), &f.card);
        assert_eq!(SignedListing::from_bytes(l.bytes()).unwrap(), l);
        assert_eq!(l.params().identity, f.ik.id());
        assert_eq!(l.fingerprint(), f.ik.fingerprint());
        assert_eq!(l.url(), "https://agents.example/a/release-planner.json");
        assert_eq!(l.sha256(), <[u8; 32]>::from(Sha256::digest(l.bytes())));
        assert_eq!(l.token(), &f.card.params.token);
        // The payload is the card without signatures, and the signature
        // covers `protected.payload`.
        let mut v = value(&l);
        v.as_object_mut().unwrap().remove("signatures");
        assert_eq!(f.card.to_unsigned_json().unwrap(), jcs(&v).unwrap());
        let input = format!(
            "{}.{}",
            protected_header(&f.ik.id()).unwrap(),
            b64(&jcs(&v).unwrap())
        );
        assert!(input.starts_with("eyJ"));
        let pk = parse_identity(&f.ik.id()).unwrap();
        assert!(verify_ed25519(&pk, input.as_bytes(), l.signature()));
        l.check_token(&f.trusted, T0, |_| false).unwrap();
        l.check_publish(T0).unwrap();
        assert!(l.door_open(T0));
    }

    #[test]
    fn protected_header_is_exactly_alg_kid_typ() {
        let ik = Identity::generate(&Rng::for_test("hdr")).unwrap();
        let h = b64_decode(&protected_header(&ik.id()).unwrap(), "h").unwrap();
        assert_eq!(
            String::from_utf8(h).unwrap(),
            format!(
                "{{\"alg\":\"EdDSA\",\"kid\":\"{}\",\"typ\":\"JOSE\"}}",
                ik.id()
            )
        );
    }

    #[test]
    fn optional_fields_round_trip() {
        let mut f = fixture("card-optional");
        f.card.streaming = true;
        f.card.push_notifications = true;
        f.card.extension_description = None;
        f.card.params.door = None;
        f.card.skills[0].examples = vec!["Plan the 2.0 train".into()];
        f.card.skills[0].input_modes = vec!["text/plain".into()];
        f.card.skills[0].output_modes = vec!["application/json".into()];
        f.card.provider.as_mut().unwrap().url = "https://example.com/agents".into();
        let l = signed(&f);
        assert_eq!(l.card(), &f.card);
        assert!(!l.door_open(T0));
        let s = String::from_utf8(l.bytes().to_vec()).unwrap();
        assert!(s.contains("\"streaming\":true"));
        assert!(!s.contains("\"door\""));
        // Without a provider, no owner domain is needed.
        f.card.provider = None;
        f.card.params.owner_domain = None;
        let mut g = grant(&f.ik.id());
        g.owner_domain = None;
        f.card.params.token = f.dk.issue_token(&Rng::for_test("no-domain"), &g).unwrap();
        let l = signed(&f);
        l.check_token(&f.trusted, T0, |_| false).unwrap();
    }

    #[test]
    fn non_canonical_bytes_are_rejected() {
        let f = fixture("card-canonical");
        let l = signed(&f);
        let v = value(&l);
        let pretty = serde_json::to_vec_pretty(&v).unwrap();
        assert_eq!(err(&pretty), bad("not canonical JCS"));
        let mut spaced = l.bytes().to_vec();
        spaced.push(b' ');
        assert_eq!(err(&spaced), bad("not canonical JCS"));
        // A duplicate key: serde keeps one, so the bytes no longer match.
        let s = String::from_utf8(l.bytes().to_vec()).unwrap();
        let dup = s.replacen(
            "{\"capabilities\"",
            "{\"version\":\"9\",\"capabilities\"",
            1,
        );
        assert_eq!(err(dup.as_bytes()), bad("not canonical JCS"));
        // Escaped where JCS writes the character itself.
        let esc = s.replacen("Release planner", "Release\\u0020planner", 1);
        assert_eq!(err(esc.as_bytes()), bad("not canonical JCS"));
        assert_eq!(err(b"not json"), bad("json"));
    }

    #[test]
    fn numbers_must_be_safe_integers() {
        let f = fixture("card-numbers");
        let s = String::from_utf8(signed(&f).bytes().to_vec()).unwrap();
        for bad_num in ["7.5", "9007199254740992", "-1"] {
            let b = s.replacen("\"seq\":7", &format!("\"seq\":{bad_num}"), 1);
            let e = err(b.as_bytes());
            assert!(matches!(e, Error::InvalidListing(_)), "{bad_num}: {e:?}");
        }
        let b = s.replacen("\"seq\":7", "\"seq\":7.0", 1);
        assert_eq!(
            err(b.as_bytes()),
            bad("number (floats and big integers are not allowed)")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn profile_rejects_empty_values_and_defaults() {
        let f = fixture("card-profile");
        let v = value(&signed(&f));
        let cases: Vec<Case> = vec![
            (
                "empty string",
                Box::new(|v| v["version"] = json!("")),
                bad("empty string"),
            ),
            (
                "empty array",
                Box::new(|v| v["skills"][0]["examples"] = json!([])),
                bad("empty array"),
            ),
            (
                "empty object",
                Box::new(|v| v["provider"] = json!({})),
                bad("empty object"),
            ),
            (
                "null",
                Box::new(|v| v["provider"] = Value::Null),
                bad("null value"),
            ),
            (
                "false",
                Box::new(|v| v["capabilities"]["streaming"] = json!(false)),
                bad("default value (false)"),
            ),
            (
                "zero",
                Box::new(|v| v["capabilities"]["streaming"] = json!(0)),
                bad("default value (0)"),
            ),
            (
                "empty in params",
                Box::new(|v| {
                    v["capabilities"]["extensions"][0]["params"]["owner_domain"] = json!("");
                }),
                bad("empty string"),
            ),
            (
                "control char",
                Box::new(|v| v["description"] = json!("two\nlines")),
                bad("control character"),
            ),
            (
                "required false",
                Box::new(|v| v["capabilities"]["extensions"][0]["required"] = json!(false)),
                bad("default value (false)"),
            ),
        ];
        for (what, mutate, expected) in cases {
            let mut m = v.clone();
            mutate(&mut m);
            assert_eq!(
                SignedListing::from_bytes(&resign(m, &f.ik)).err(),
                Some(expected),
                "{what}"
            );
        }
        // `v: 0` inside params is not a default to drop.
        assert_eq!(
            value(&signed(&f))["capabilities"]["extensions"][0]["params"]["v"],
            json!(0)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn closed_schema_rejects_extra_fields() {
        let f = fixture("card-schema");
        let v = value(&signed(&f));
        let ext = |v: &mut Value| v["capabilities"]["extensions"][0].clone();
        let cases: Vec<Case> = vec![
            (
                "iconUrl",
                Box::new(|v| v["iconUrl"] = json!("https://example.com/i.png")),
                bad("schema"),
            ),
            (
                "documentationUrl",
                Box::new(|v| v["documentationUrl"] = json!("https://x.example")),
                bad("schema"),
            ),
            (
                "securitySchemes",
                Box::new(|v| v["securitySchemes"] = json!({"k": {"x": 1}})),
                bad("schema"),
            ),
            (
                "securityRequirements",
                Box::new(|v| v["securityRequirements"] = json!([{"x": 1}])),
                bad("schema"),
            ),
            (
                "skill securityRequirements",
                Box::new(|v| v["skills"][0]["securityRequirements"] = json!([{"x": 1}])),
                bad("schema"),
            ),
            (
                "extendedAgentCard",
                Box::new(|v| v["capabilities"]["extendedAgentCard"] = json!(true)),
                bad("schema"),
            ),
            (
                "tenant",
                Box::new(|v| v["supportedInterfaces"][0]["tenant"] = json!("t")),
                bad("schema"),
            ),
            (
                "unknown param",
                Box::new(|v| v["capabilities"]["extensions"][0]["params"]["x"] = json!(1)),
                bad("schema"),
            ),
            (
                "unknown door field",
                Box::new(|v| v["capabilities"]["extensions"][0]["params"]["door"]["x"] = json!(1)),
                bad("schema"),
            ),
            (
                "unknown token field",
                Box::new(|v| v["capabilities"]["extensions"][0]["params"]["token"]["x"] = json!(1)),
                bad("schema"),
            ),
            (
                "second extension",
                Box::new(move |v| {
                    let mut e = ext(v);
                    e["uri"] = json!("https://other.example/ext");
                    v["capabilities"]["extensions"]
                        .as_array_mut()
                        .unwrap()
                        .push(e);
                }),
                bad("exactly one extension"),
            ),
            (
                "other extension uri",
                Box::new(|v| {
                    v["capabilities"]["extensions"][0]["uri"] =
                        json!("https://yggdrasill.network/ext/agentconnect/e2e/v1");
                }),
                bad("extension uri"),
            ),
            (
                "second interface",
                Box::new(|v| {
                    let i = v["supportedInterfaces"][0].clone();
                    v["supportedInterfaces"].as_array_mut().unwrap().push(i);
                }),
                bad("exactly one interface"),
            ),
            (
                "plaintext endpoint",
                Box::new(|v| {
                    v["supportedInterfaces"][0]["url"] = json!("https://agent.example/a2a");
                }),
                bad("interface"),
            ),
            (
                "other binding",
                Box::new(|v| v["supportedInterfaces"][0]["protocolBinding"] = json!("JSONRPC")),
                bad("interface"),
            ),
            (
                "missing field",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("version");
                }),
                bad("schema"),
            ),
            (
                "params v",
                Box::new(|v| v["capabilities"]["extensions"][0]["params"]["v"] = json!(1)),
                Error::UnsupportedVersion,
            ),
        ];
        for (what, mutate, expected) in cases {
            let mut m = v.clone();
            mutate(&mut m);
            assert_eq!(
                SignedListing::from_bytes(&resign(m, &f.ik)).err(),
                Some(expected),
                "{what}"
            );
        }
    }

    #[test]
    fn signature_rules() {
        let f = fixture("card-signature");
        let l = signed(&f);
        let v = value(&l);
        let id = f.ik.id();
        let hdr = |h: Value| b64(&jcs(&h).unwrap());
        // Exactly one signature.
        let mut two = v.clone();
        let s0 = two["signatures"][0].clone();
        two["signatures"].as_array_mut().unwrap().push(s0);
        assert_eq!(err(&jcs(&two).unwrap()), bad("exactly one signature"));
        let mut none = v.clone();
        none.as_object_mut().unwrap().remove("signatures");
        assert_eq!(err(&jcs(&none).unwrap()), bad("no signature"));
        // Key locations, other algorithms and other kids, each correctly
        // signed by the listed key.
        for (h, expected) in [
            (
                json!({"alg": "EdDSA", "jku": "https://evil.example/jwks", "kid": id, "typ": "JOSE"}),
                bad("protected header names a key location"),
            ),
            (
                json!({"alg": "EdDSA", "crit": ["b64"], "kid": id, "typ": "JOSE"}),
                bad("protected header names a key location"),
            ),
            (
                json!({"alg": "Ed25519", "kid": id, "typ": "JOSE"}),
                bad("alg must be EdDSA"),
            ),
            (
                json!({"alg": "EdDSA", "kid": "ac:v0:other", "typ": "JOSE"}),
                bad("kid is not params.identity"),
            ),
            (
                json!({"alg": "EdDSA", "kid": id, "typ": "JWT"}),
                bad("protected header"),
            ),
            (json!({"alg": "EdDSA", "kid": id}), bad("protected header")),
        ] {
            assert_eq!(err(&resign_with(v.clone(), &f.ik, &hdr(h))), expected);
        }
        assert_eq!(
            err(&resign_with(v.clone(), &f.ik, "not-base64!")),
            bad("protected header encoding")
        );
        // Signed by another key under the listed kid.
        let other = Identity::generate(&Rng::for_test("card-signature-other")).unwrap();
        let wrong = resign_with(v.clone(), &other, &protected_header(&id).unwrap());
        assert_eq!(err(&wrong), bad("signature"));
        assert_eq!(
            f.card.sign(&other),
            Err(bad("signing key is not params.identity"))
        );
        // Tampered text after signing.
        let s = String::from_utf8(l.bytes().to_vec()).unwrap();
        let tampered = s.replacen("Plans release", "Plans RELEASE", 1);
        assert_eq!(err(tampered.as_bytes()), bad("signature"));
        // An unprotected header is outside the closed schema.
        let mut with_header = v.clone();
        with_header["signatures"][0]["header"] = json!({"k": "v"});
        assert_eq!(err(&jcs(&with_header).unwrap()), bad("schema"));
        let mut bad_sig = v;
        bad_sig["signatures"][0]["signature"] = json!("AA");
        assert_eq!(err(&jcs(&bad_sig).unwrap()), bad("signature encoding"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn field_rules() {
        let f = fixture("card-fields");
        let rng = Rng::for_test("card-fields-extra");
        let check = |mutate: &dyn Fn(&mut ListingCard), expected: Error| {
            let mut c = f.card.clone();
            mutate(&mut c);
            assert_eq!(c.sign(&f.ik).unwrap_err().to_string(), expected.to_string());
            assert_eq!(c.validate(), Err(expected));
        };
        check(&|c| c.name = "n".repeat(81), bad("name"));
        check(&|c| c.description = "d".repeat(501), bad("description"));
        check(&|c| c.version = "v".repeat(33), bad("version"));
        check(
            &|c| c.extension_description = Some("x\u{7f}".into()),
            bad("extension description"),
        );
        check(&|c| c.default_input_modes.clear(), bad("defaultInputModes"));
        check(
            &|c| c.default_output_modes = vec!["text/plain".into(); 9],
            bad("defaultOutputModes"),
        );
        check(
            &|c| c.default_input_modes = vec!["t".repeat(128)],
            bad("defaultInputModes"),
        );
        check(
            &|c| c.default_input_modes = vec!["text/pl\u{e4}in".into()],
            bad("defaultInputModes"),
        );
        check(&|c| c.skills.clear(), bad("1 to 16 skills"));
        check(
            &|c| c.skills = vec![c.skills[0].clone(); 17],
            bad("1 to 16 skills"),
        );
        check(&|c| c.skills[0].id = "i".repeat(81), bad("skill id"));
        check(&|c| c.skills[0].name = String::new(), bad("skill name"));
        check(
            &|c| c.skills[0].description = "d".repeat(501),
            bad("skill description"),
        );
        check(&|c| c.skills[0].tags.clear(), bad("skill tags"));
        check(
            &|c| c.skills[0].tags = vec!["t".into(); 9],
            bad("skill tags"),
        );
        check(
            &|c| c.skills[0].tags = vec!["t".repeat(33)],
            bad("skill tags"),
        );
        check(
            &|c| c.skills[0].examples = vec!["e".into(); 5],
            bad("skill examples"),
        );
        check(
            &|c| c.skills[0].examples = vec!["e".repeat(201)],
            bad("skill examples"),
        );
        check(
            &|c| c.skills[0].input_modes = vec!["m".into(); 9],
            bad("skill inputModes"),
        );
        check(
            &|c| c.skills[0].output_modes = vec![String::new()],
            bad("skill outputModes"),
        );
        check(
            &|c| c.params.identity = "ac:v0:nope".into(),
            bad("identity"),
        );
        check(&|c| c.params.name = "Release".into(), bad("name (slug)"));
        check(
            &|c| c.params.directory = "Agents.example".into(),
            bad("directory host"),
        );
        check(
            &|c| c.params.relay = "relay.example/x".into(),
            bad("relay host"),
        );
        check(&|c| c.params.seq = 0, bad("seq or issued_at"));
        check(
            &|c| c.params.issued_at = MAX_SAFE_INTEGER + 1,
            bad("seq or issued_at"),
        );
        check(
            &|c| c.params.door.as_mut().unwrap().key.truncate(1215),
            bad("door key length"),
        );
        check(
            &|c| c.params.door.as_mut().unwrap().expires_at = T0 + MAX_DOOR_LIFETIME_SECS + 1,
            bad("door expires_at"),
        );
        check(
            &|c| c.params.door.as_mut().unwrap().expires_at = T0,
            bad("door expires_at"),
        );
        check(
            &|c| c.params.owner_domain = Some("example.com.".into()),
            bad("owner_domain"),
        );
        check(
            &|c| c.params.owner_domain = None,
            bad("provider needs owner_domain"),
        );
        check(
            &|c| c.provider.as_mut().unwrap().url = "https://example.com.evil.example".into(),
            bad("provider url is not under owner_domain"),
        );
        check(
            &|c| c.provider.as_mut().unwrap().url = "http://example.com".into(),
            bad("provider url is not under owner_domain"),
        );
        check(
            &|c| c.provider.as_mut().unwrap().url = "https://example.com/?q=1".into(),
            bad("provider url is not under owner_domain"),
        );
        check(
            &|c| c.provider.as_mut().unwrap().organization = "o".repeat(81),
            bad("provider organization"),
        );
        // The token must be for this name and directory.
        let mut g = grant(&f.ik.id());
        g.name = "other-name".into();
        let other_name = f.dk.issue_token(&rng, &g).unwrap();
        check(
            &|c| c.params.token = other_name.clone(),
            bad("token name differs"),
        );
        let mut g = grant(&f.ik.id());
        g.directory = "other.example".into();
        let other_dir = f.dk.issue_token(&rng, &g).unwrap();
        check(
            &|c| c.params.token = other_dir.clone(),
            bad("token directory differs"),
        );
        // Too large once encoded.
        let mut big = f.card.clone();
        big.skills = vec![
            ListingSkill {
                examples: vec!["\u{1F600}".repeat(200); 4],
                description: "\u{1F600}".repeat(500),
                ..f.card.skills[0].clone()
            };
            16
        ];
        assert_eq!(big.sign(&f.ik), Err(bad("too large")));
        assert_eq!(err(&vec![b' '; MAX_LISTING_BYTES + 1]), bad("too large"));
    }

    #[test]
    fn token_checks_on_a_listing() {
        let f = fixture("card-token");
        let l = signed(&f);
        let token_id = l.token().token_id;
        assert_eq!(
            l.check_token(&f.trusted, T0, |id| *id == token_id),
            Err(Error::InvalidToken("revoked"))
        );
        let end = l.token().grant.expires_at;
        assert_eq!(
            l.check_token(&f.trusted, end, |_| false),
            Err(Error::InvalidToken("expired"))
        );
        let other = DirectoryKeyFixture::new("card-token-other");
        assert_eq!(
            l.check_token(&other.trusted, T0, |_| false),
            Err(Error::InvalidToken("unknown key_id"))
        );
        // A valid token for another identity, embedded in this listing.
        let stranger = Identity::generate(&Rng::for_test("stranger")).unwrap();
        let theirs =
            f.dk.issue_token(&Rng::for_test("theirs"), &grant(&stranger.id()))
                .unwrap();
        let l2 = card_for(&f.ik, theirs, None).sign(&f.ik).unwrap();
        assert_eq!(
            l2.check_token(&f.trusted, T0, |_| false),
            Err(Error::InvalidToken("bound to another identity"))
        );
        // A token pinning another owner domain.
        let mut g = grant(&f.ik.id());
        g.owner_domain = Some("other.example".into());
        let pinned = f.dk.issue_token(&Rng::for_test("pinned"), &g).unwrap();
        let l3 = card_for(&f.ik, pinned, None).sign(&f.ik).unwrap();
        assert_eq!(
            l3.check_token(&f.trusted, T0, |_| false),
            Err(Error::InvalidToken("bound to another owner domain"))
        );
    }

    struct DirectoryKeyFixture {
        trusted: TrustedDirectory,
    }

    impl DirectoryKeyFixture {
        fn new(label: &str) -> Self {
            let dk = crate::listing::DirectoryKey::generate(&Rng::for_test(label)).unwrap();
            Self {
                trusted: TrustedDirectory::new(
                    crate::listing::testing::DIRECTORY,
                    &[dk.public_key()],
                )
                .unwrap(),
            }
        }
    }

    #[test]
    fn publish_time_checks() {
        let f = fixture("card-publish");
        let l = signed(&f);
        l.check_publish(T0 - 300).unwrap();
        assert_eq!(
            l.check_publish(T0 - 301),
            Err(bad("issued_at is in the future"))
        );
        let expiry = l.params().door.as_ref().unwrap().expires_at;
        assert!(l.door_open(expiry - 1));
        assert!(!l.door_open(expiry));
        assert_eq!(l.check_publish(expiry), Err(bad("door has expired")));
    }

    #[test]
    fn unsigned_json_is_parsed_strictly() {
        let f = fixture("card-unsigned");
        let payload = f.card.to_unsigned_json().unwrap();
        assert_eq!(ListingCard::from_unsigned_json(&payload).unwrap(), f.card);
        let v: Value = serde_json::from_slice(&payload).unwrap();
        let pretty = serde_json::to_vec_pretty(&v).unwrap();
        assert_eq!(ListingCard::from_unsigned_json(&pretty).unwrap(), f.card);
        let s = String::from_utf8(payload).unwrap();
        let dup = s.replacen(
            "{\"capabilities\"",
            "{\"version\":\"9\",\"capabilities\"",
            1,
        );
        assert_eq!(
            ListingCard::from_unsigned_json(dup.as_bytes()),
            Err(bad("json"))
        );
        let signed_bytes = signed(&f).bytes().to_vec();
        assert_eq!(
            ListingCard::from_unsigned_json(&signed_bytes),
            Err(bad("an unsigned card has no signatures"))
        );
        let mut v2 = v.clone();
        v2["iconUrl"] = json!("https://example.com/i.png");
        assert_eq!(
            ListingCard::from_unsigned_json(&jcs(&v2).unwrap()),
            Err(bad("schema"))
        );
        let mut v3 = v;
        v3["description"] = json!("");
        assert_eq!(
            ListingCard::from_unsigned_json(&jcs(&v3).unwrap()),
            Err(bad("empty string"))
        );
        assert_eq!(
            ListingCard::from_unsigned_json(&vec![b' '; 2 * MAX_LISTING_BYTES + 1]),
            Err(bad("too large"))
        );
    }

    #[test]
    fn withdrawals_apply_to_their_own_listing_only() {
        let f = fixture("card-withdrawal");
        let l = signed(&f);
        let w =
            |seq| Withdrawal::sign(&f.ik, "agents.example", "release-planner", seq, T0).unwrap();
        assert!(w(7).applies_to(&l));
        assert!(w(9).applies_to(&l));
        // An older seq doesn't withdraw a newer listing.
        assert!(!w(6).applies_to(&l));
        let other = Identity::generate(&Rng::for_test("card-withdrawal-other")).unwrap();
        let theirs = Withdrawal::sign(&other, "agents.example", "release-planner", 9, T0).unwrap();
        assert!(!theirs.applies_to(&l));
        let elsewhere = Withdrawal::sign(&f.ik, "other.example", "release-planner", 9, T0).unwrap();
        assert!(!elsewhere.applies_to(&l));
        let renamed = Withdrawal::sign(&f.ik, "agents.example", "other-name", 9, T0).unwrap();
        assert!(!renamed.applies_to(&l));
    }
}
