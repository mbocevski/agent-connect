//! Operator-issued listing tokens and their revocations (SPEC §13.2.1).

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{is_canonical_host, is_listing_name, is_owner_domain, text_ok, verify_ed25519};
use crate::encoding::{MAX_SAFE_INTEGER, b64, b64_decode_array, from_jcs, jcs};
use crate::error::{Error, Result};
use crate::identity::parse_identity;
use crate::rng::Rng;

const TOKEN_LABEL: &[u8] = b"agentconnect/v0/listing-token";
const REVOKE_LABEL: &[u8] = b"agentconnect/v0/listing-token-revoke";

/// The longest a token may be valid: 90 days (SPEC §13.2.1).
pub const MAX_TOKEN_LIFETIME_SECS: u64 = 90 * 24 * 3600;
/// Longest `TokenRevocation.reason`, in characters.
const MAX_REASON_CHARS: usize = 200;
/// At most two directory keys are valid at once, so `DK` can rotate.
const MAX_DIRECTORY_KEYS: usize = 2;

const fn bad(what: &'static str) -> Error {
    Error::InvalidToken(what)
}

/// `key_id` of a directory key: the first 16 bytes of SHA-256(DK.pub).
#[must_use]
pub fn directory_key_id(public_key: &[u8; 32]) -> [u8; 16] {
    let digest = Sha256::digest(public_key);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// The directory keys a daemon or directory pinned for one directory host
/// (SPEC §13.2.1). Keys are never fetched from a URL a listing names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedDirectory {
    host: String,
    keys: Vec<[u8; 32]>,
}

impl TrustedDirectory {
    /// The pinned keys `keys` (one or two, for rotation) of `host`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] for a host that isn't in canonical form, no
    /// keys, more than two, a duplicate, or a key that isn't an Ed25519
    /// point.
    pub fn new(host: &str, keys: &[[u8; 32]]) -> Result<Self> {
        if !is_canonical_host(host) {
            return Err(bad("directory host"));
        }
        if keys.is_empty() || keys.len() > MAX_DIRECTORY_KEYS {
            return Err(bad("one or two directory keys"));
        }
        if keys.len() == 2 && keys[0] == keys[1] {
            return Err(bad("duplicate directory key"));
        }
        if keys.iter().any(|k| VerifyingKey::from_bytes(k).is_err()) {
            return Err(bad("directory key"));
        }
        Ok(Self {
            host: host.to_owned(),
            keys: keys.to_vec(),
        })
    }

    /// The directory host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The pinned public keys.
    #[must_use]
    pub fn keys(&self) -> &[[u8; 32]] {
        &self.keys
    }

    fn key_for(&self, key_id: &[u8; 16]) -> Option<&[u8; 32]> {
        self.keys.iter().find(|k| directory_key_id(k) == *key_id)
    }
}

/// What a [`DirectoryKey`] signs into a [`ListingToken`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenGrant {
    /// The directory host, in canonical form.
    pub directory: String,
    /// The listing name (slug).
    pub name: String,
    /// The identity the name is granted to.
    pub identity: String,
    /// Optional: the only owner domain the listing may claim.
    pub owner_domain: Option<String>,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds, after `issued_at` and at most 90 days after it.
    pub expires_at: u64,
}

/// An operator-signed authorisation to list one identity under one name
/// (SPEC §13.2.1). It is not a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingToken {
    /// Random token id.
    pub token_id: [u8; 16],
    /// The grant.
    pub grant: TokenGrant,
    /// `SHA-256(DK.pub)[0..16]`.
    pub key_id: [u8; 16],
    /// Ed25519 by `DK`.
    pub sig: [u8; 64],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenJson {
    v: u64,
    token_id: String,
    directory: String,
    name: String,
    identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_domain: Option<String>,
    issued_at: u64,
    expires_at: u64,
    key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
}

fn check_grant(g: &TokenGrant) -> Result<()> {
    if !is_canonical_host(&g.directory) {
        return Err(bad("directory"));
    }
    if !is_listing_name(&g.name) {
        return Err(bad("name"));
    }
    parse_identity(&g.identity).map_err(|_| bad("identity"))?;
    if g.owner_domain
        .as_deref()
        .is_some_and(|d| !is_owner_domain(d))
    {
        return Err(bad("owner_domain"));
    }
    if g.issued_at > MAX_SAFE_INTEGER || g.expires_at > MAX_SAFE_INTEGER {
        return Err(bad("time out of range"));
    }
    if g.expires_at <= g.issued_at || g.expires_at - g.issued_at > MAX_TOKEN_LIFETIME_SECS {
        return Err(bad("lifetime"));
    }
    Ok(())
}

impl ListingToken {
    pub(super) fn json(&self, with_sig: bool) -> TokenJson {
        TokenJson {
            v: 0,
            token_id: b64(&self.token_id),
            directory: self.grant.directory.clone(),
            name: self.grant.name.clone(),
            identity: self.grant.identity.clone(),
            owner_domain: self.grant.owner_domain.clone(),
            issued_at: self.grant.issued_at,
            expires_at: self.grant.expires_at,
            key_id: b64(&self.key_id),
            sig: with_sig.then(|| b64(&self.sig)),
        }
    }

    /// Decodes the JSON form and checks every field's format, including
    /// the lifetime rule. Doesn't verify the signature.
    pub(super) fn from_raw(raw: TokenJson) -> Result<Self> {
        if raw.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        let sig = raw.sig.ok_or(bad("missing sig"))?;
        let token = Self {
            token_id: b64_decode_array(&raw.token_id, "token_id").map_err(|_| bad("token_id"))?,
            grant: TokenGrant {
                directory: raw.directory,
                name: raw.name,
                identity: raw.identity,
                owner_domain: raw.owner_domain,
                issued_at: raw.issued_at,
                expires_at: raw.expires_at,
            },
            key_id: b64_decode_array(&raw.key_id, "key_id").map_err(|_| bad("key_id"))?,
            sig: b64_decode_array(&sig, "sig").map_err(|_| bad("sig"))?,
        };
        check_grant(&token.grant)?;
        Ok(token)
    }

    /// Parses a token on its own (for example the file an operator hands
    /// an owner). It must be canonical JCS with exactly the token's fields.
    /// Doesn't verify the signature; see [`ListingToken::verify`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] or [`Error::UnsupportedVersion`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Self::from_raw(from_jcs(bytes, "listing token").map_err(|_| bad("encoding"))?)
    }

    /// The canonical JCS encoding.
    ///
    /// # Errors
    ///
    /// Only if serialisation fails, which it can't for a valid token.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        jcs(&self.json(true))
    }

    /// `"agentconnect/v0/listing-token" ‖ JCS(token without "sig")`.
    ///
    /// # Errors
    ///
    /// Only if serialisation fails.
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        Ok([TOKEN_LABEL, &jcs(&self.json(false))?].concat())
    }

    /// The token's own checks (SPEC §13.2.1): its directory is `trusted`'s
    /// host, its `key_id` names a pinned key and `sig` verifies under it,
    /// its lifetime is at most 90 days, and it hasn't expired at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] naming the failed check.
    pub fn verify(&self, trusted: &TrustedDirectory, now: u64) -> Result<()> {
        check_grant(&self.grant)?;
        if self.grant.directory != trusted.host {
            return Err(bad("directory"));
        }
        let key = trusted.key_for(&self.key_id).ok_or(bad("unknown key_id"))?;
        if !verify_ed25519(key, &self.signing_input()?, &self.sig) {
            return Err(bad("signature"));
        }
        if now >= self.grant.expires_at {
            return Err(bad("expired"));
        }
        Ok(())
    }

    /// Whether the token binds a listing with these params: the same
    /// directory, name and identity, and the same owner domain if the
    /// token pins one.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] naming the field that differs.
    pub fn check_binding(
        &self,
        directory: &str,
        name: &str,
        identity: &str,
        owner_domain: Option<&str>,
    ) -> Result<()> {
        if self.grant.directory != directory {
            return Err(bad("bound to another directory"));
        }
        if self.grant.name != name {
            return Err(bad("bound to another name"));
        }
        if self.grant.identity != identity {
            return Err(bad("bound to another identity"));
        }
        if let Some(pinned) = &self.grant.owner_domain
            && owner_domain != Some(pinned.as_str())
        {
            return Err(bad("bound to another owner domain"));
        }
        Ok(())
    }
}

/// An operator-signed revocation of a token (SPEC §13.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRevocation {
    /// The revoked token.
    pub token_id: [u8; 16],
    /// Unix seconds.
    pub revoked_at: u64,
    /// Operator text, 1 to 200 characters, no control characters.
    pub reason: String,
    /// `SHA-256(DK.pub)[0..16]`.
    pub key_id: [u8; 16],
    /// Ed25519 by `DK`.
    pub sig: [u8; 64],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationJson {
    v: u64,
    token_id: String,
    revoked_at: u64,
    reason: String,
    key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
}

impl TokenRevocation {
    fn json(&self, with_sig: bool) -> RevocationJson {
        RevocationJson {
            v: 0,
            token_id: b64(&self.token_id),
            revoked_at: self.revoked_at,
            reason: self.reason.clone(),
            key_id: b64(&self.key_id),
            sig: with_sig.then(|| b64(&self.sig)),
        }
    }

    /// Parses a revocation: canonical JCS with exactly its fields. Doesn't
    /// verify the signature; see [`TokenRevocation::verify`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] or [`Error::UnsupportedVersion`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let raw: RevocationJson =
            from_jcs(bytes, "token revocation").map_err(|_| bad("revocation encoding"))?;
        if raw.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        if !text_ok(&raw.reason, MAX_REASON_CHARS) {
            return Err(bad("revocation reason"));
        }
        let sig = raw.sig.ok_or(bad("missing sig"))?;
        Ok(Self {
            token_id: b64_decode_array(&raw.token_id, "token_id").map_err(|_| bad("token_id"))?,
            revoked_at: raw.revoked_at,
            reason: raw.reason,
            key_id: b64_decode_array(&raw.key_id, "key_id").map_err(|_| bad("key_id"))?,
            sig: b64_decode_array(&sig, "sig").map_err(|_| bad("sig"))?,
        })
    }

    /// The canonical JCS encoding.
    ///
    /// # Errors
    ///
    /// Only if serialisation fails.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        jcs(&self.json(true))
    }

    /// `"agentconnect/v0/listing-token-revoke" ‖ JCS(revocation without "sig")`.
    ///
    /// # Errors
    ///
    /// Only if serialisation fails.
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        Ok([REVOKE_LABEL, &jcs(&self.json(false))?].concat())
    }

    /// Verifies the signature under a key pinned for the directory.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] for an unknown `key_id` or a bad signature.
    pub fn verify(&self, trusted: &TrustedDirectory) -> Result<()> {
        let key = trusted.key_for(&self.key_id).ok_or(bad("unknown key_id"))?;
        if verify_ed25519(key, &self.signing_input()?, &self.sig) {
            Ok(())
        } else {
            Err(bad("revocation signature"))
        }
    }
}

/// The directory operator's token key `DK` (SPEC §13.2.1), for the
/// operator's offline tool. A directory server never holds it.
///
/// The secret key is zeroized on drop and never shown by `Debug`.
pub struct DirectoryKey {
    key: SigningKey,
}

impl DirectoryKey {
    /// A fresh key.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`].
    pub fn generate(rng: &Rng) -> Result<Self> {
        let seed = Zeroizing::new(rng.array::<32>()?);
        Ok(Self::from_secret_bytes(&seed))
    }

    /// Restores a key from its 32-byte secret.
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(secret),
        }
    }

    /// The 32-byte secret, for the operator's tool to store.
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes())
    }

    /// `DK.pub`, which daemons and the directory pin.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// `SHA-256(DK.pub)[0..16]`.
    #[must_use]
    pub fn key_id(&self) -> [u8; 16] {
        directory_key_id(&self.public_key())
    }

    /// Issues a token for `grant` with a fresh random `token_id`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] for a grant that breaks the format rules
    /// (host, slug, identity, domain, a lifetime over 90 days), or
    /// [`Error::Rng`].
    pub fn issue_token(&self, rng: &Rng, grant: &TokenGrant) -> Result<ListingToken> {
        check_grant(grant)?;
        let mut token = ListingToken {
            token_id: rng.array()?,
            grant: grant.clone(),
            key_id: self.key_id(),
            sig: [0; 64],
        };
        token.sig = self.key.sign(&token.signing_input()?).to_bytes();
        Ok(token)
    }

    /// Signs a token as given, skipping the grant checks: for negative
    /// vectors only.
    #[cfg(test)]
    pub(crate) fn sign_unchecked(&self, token: &mut ListingToken) {
        token.key_id = self.key_id();
        token.sig = self.key.sign(&token.signing_input().unwrap()).to_bytes();
    }

    /// Revokes the token `token_id`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidToken`] for a `reason` that is empty, longer than
    /// 200 characters or has control characters, or a time beyond 2^53 − 1.
    pub fn revoke_token(
        &self,
        token_id: &[u8; 16],
        revoked_at: u64,
        reason: &str,
    ) -> Result<TokenRevocation> {
        if !text_ok(reason, MAX_REASON_CHARS) {
            return Err(bad("revocation reason"));
        }
        if revoked_at > MAX_SAFE_INTEGER {
            return Err(bad("time out of range"));
        }
        let mut rev = TokenRevocation {
            token_id: *token_id,
            revoked_at,
            reason: reason.to_owned(),
            key_id: self.key_id(),
            sig: [0; 64],
        };
        rev.sig = self.key.sign(&rev.signing_input()?).to_bytes();
        Ok(rev)
    }
}

impl fmt::Debug for DirectoryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryKey")
            .field("key_id", &b64(&self.key_id()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::identity::Identity;

    pub(crate) const DIRECTORY: &str = "agents.example";
    pub(crate) const T0: u64 = 1_792_497_600;

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

    fn setup() -> (DirectoryKey, TrustedDirectory, Identity, ListingToken) {
        let rng = Rng::for_test("listing-token");
        let dk = DirectoryKey::generate(&rng).unwrap();
        let trusted = TrustedDirectory::new(DIRECTORY, &[dk.public_key()]).unwrap();
        let ik = Identity::generate(&rng).unwrap();
        let token = dk.issue_token(&rng, &grant(&ik.id())).unwrap();
        (dk, trusted, ik, token)
    }

    #[test]
    fn token_round_trips_and_verifies() {
        let (dk, trusted, ik, token) = setup();
        token.verify(&trusted, T0).unwrap();
        let json = token.to_json().unwrap();
        assert_eq!(ListingToken::from_json(&json).unwrap(), token);
        assert_eq!(token.key_id, dk.key_id());
        token
            .check_binding(DIRECTORY, "release-planner", &ik.id(), Some("example.com"))
            .unwrap();
        assert!(token.signing_input().unwrap().starts_with(TOKEN_LABEL));
        // DK rotation: either of two pinned keys verifies.
        let other = DirectoryKey::generate(&Rng::for_test("listing-token-other")).unwrap();
        let both =
            TrustedDirectory::new(DIRECTORY, &[other.public_key(), dk.public_key()]).unwrap();
        token.verify(&both, T0).unwrap();
        assert_eq!(both.keys().len(), 2);
        assert_eq!(both.host(), DIRECTORY);
    }

    #[test]
    fn token_with_wrong_key_or_tampered_field_fails() {
        let (_, _, ik, token) = setup();
        let other = DirectoryKey::generate(&Rng::for_test("listing-token-other")).unwrap();
        let wrong = TrustedDirectory::new(DIRECTORY, &[other.public_key()]).unwrap();
        assert_eq!(token.verify(&wrong, T0), Err(bad("unknown key_id")));
        // A forged token under another key but claiming the pinned key_id.
        let (dk, trusted, _, _) = setup();
        let mut forged = other
            .issue_token(&Rng::for_test("forge"), &grant(&ik.id()))
            .unwrap();
        forged.key_id = dk.key_id();
        assert_eq!(forged.verify(&trusted, T0), Err(bad("signature")));
        let mut t = token.clone();
        t.grant.name = "release-plannex".into();
        assert_eq!(t.verify(&trusted, T0), Err(bad("signature")));
        let mut t = token;
        t.grant.directory = "other.example".into();
        assert_eq!(t.verify(&trusted, T0), Err(bad("directory")));
    }

    #[test]
    fn token_expiry_and_lifetime() {
        let (dk, trusted, ik, token) = setup();
        let end = token.grant.expires_at;
        token.verify(&trusted, end - 1).unwrap();
        assert_eq!(token.verify(&trusted, end), Err(bad("expired")));
        let rng = Rng::for_test("lifetime");
        let mut g = grant(&ik.id());
        g.expires_at = g.issued_at + MAX_TOKEN_LIFETIME_SECS;
        dk.issue_token(&rng, &g)
            .unwrap()
            .verify(&trusted, T0)
            .unwrap();
        g.expires_at += 1;
        assert_eq!(dk.issue_token(&rng, &g), Err(bad("lifetime")));
        g.expires_at = g.issued_at;
        assert_eq!(dk.issue_token(&rng, &g), Err(bad("lifetime")));
        // An overlong token signed by hand is still refused on parse.
        let mut long = token.json(true);
        long.expires_at = T0 + MAX_TOKEN_LIFETIME_SECS + 1;
        assert_eq!(
            ListingToken::from_json(&jcs(&long).unwrap()),
            Err(bad("lifetime"))
        );
    }

    #[test]
    fn token_binding_checks_every_field() {
        let (dk, _, ik, token) = setup();
        let other = Identity::generate(&Rng::for_test("other-identity")).unwrap();
        let id = ik.id();
        let oid = other.id();
        let cases = [
            (
                (
                    "other.example",
                    "release-planner",
                    id.as_str(),
                    Some("example.com"),
                ),
                "bound to another directory",
            ),
            (
                (DIRECTORY, "other-name", id.as_str(), Some("example.com")),
                "bound to another name",
            ),
            (
                (
                    DIRECTORY,
                    "release-planner",
                    oid.as_str(),
                    Some("example.com"),
                ),
                "bound to another identity",
            ),
            (
                (
                    DIRECTORY,
                    "release-planner",
                    id.as_str(),
                    Some("evil.example"),
                ),
                "bound to another owner domain",
            ),
            (
                (DIRECTORY, "release-planner", id.as_str(), None),
                "bound to another owner domain",
            ),
        ];
        for ((d, n, i, o), err) in cases {
            assert_eq!(token.check_binding(d, n, i, o), Err(bad(err)));
        }
        // A token without a pinned domain allows any (or no) domain.
        let mut g = grant(&ik.id());
        g.owner_domain = None;
        let open = dk.issue_token(&Rng::for_test("open"), &g).unwrap();
        open.check_binding(DIRECTORY, "release-planner", &id, None)
            .unwrap();
        open.check_binding(DIRECTORY, "release-planner", &id, Some("x.example"))
            .unwrap();
    }

    #[test]
    fn token_parsing_is_strict() {
        let (_, _, _, token) = setup();
        let good = String::from_utf8(token.to_json().unwrap()).unwrap();
        for (bad_json, err) in [
            (
                good.replace("\"v\":0", "\"v\":1"),
                Error::UnsupportedVersion,
            ),
            (good.replace("\"v\":0", "\"v\":0,\"x\":1"), bad("encoding")),
            (
                good.replace(",\"token_id\"", " ,\"token_id\""),
                bad("encoding"),
            ),
            (good.replace("release-planner", "Release"), bad("name")),
        ] {
            assert_eq!(
                ListingToken::from_json(bad_json.as_bytes()),
                Err(err),
                "{bad_json}"
            );
        }
        let mut raw = token.json(false);
        assert_eq!(
            ListingToken::from_json(&jcs(&raw).unwrap()),
            Err(bad("missing sig"))
        );
        raw.sig = Some("AA".into());
        assert_eq!(
            ListingToken::from_json(&jcs(&raw).unwrap()),
            Err(bad("sig"))
        );
        let mut raw = token.json(true);
        raw.token_id = "AA".into();
        assert_eq!(
            ListingToken::from_json(&jcs(&raw).unwrap()),
            Err(bad("token_id"))
        );
        let mut raw = token.json(true);
        raw.key_id = "AA".into();
        assert_eq!(
            ListingToken::from_json(&jcs(&raw).unwrap()),
            Err(bad("key_id"))
        );
        let mut raw = token.json(true);
        raw.identity = "ac:v0:x".into();
        assert_eq!(
            ListingToken::from_json(&jcs(&raw).unwrap()),
            Err(bad("identity"))
        );
        let mut raw = token.json(true);
        raw.owner_domain = Some("Example.com".into());
        assert_eq!(
            ListingToken::from_json(&jcs(&raw).unwrap()),
            Err(bad("owner_domain"))
        );
        let mut raw = token.json(true);
        raw.directory = "Agents.example".into();
        assert_eq!(
            ListingToken::from_json(&jcs(&raw).unwrap()),
            Err(bad("directory"))
        );
    }

    #[test]
    fn revocations_verify_under_the_pinned_key_only() {
        let (dk, trusted, _, token) = setup();
        let rev = dk.revoke_token(&token.token_id, T0 + 5, "spam").unwrap();
        rev.verify(&trusted).unwrap();
        let json = rev.to_json().unwrap();
        let back = TokenRevocation::from_json(&json).unwrap();
        assert_eq!(back, rev);
        let other = DirectoryKey::generate(&Rng::for_test("rev-other")).unwrap();
        let mut forged = other.revoke_token(&token.token_id, T0, "x").unwrap();
        assert_eq!(forged.verify(&trusted), Err(bad("unknown key_id")));
        forged.key_id = dk.key_id();
        assert_eq!(forged.verify(&trusted), Err(bad("revocation signature")));
        let mut t = rev.clone();
        t.revoked_at += 1;
        assert_eq!(t.verify(&trusted), Err(bad("revocation signature")));
        for reason in ["", "a\nb", &"r".repeat(201)] {
            assert_eq!(
                dk.revoke_token(&token.token_id, T0, reason),
                Err(bad("revocation reason"))
            );
        }
        assert_eq!(
            dk.revoke_token(&token.token_id, MAX_SAFE_INTEGER + 1, "x"),
            Err(bad("time out of range"))
        );
        let s = String::from_utf8(json).unwrap();
        for (b, err) in [
            (s.replace("\"v\":0", "\"v\":2"), Error::UnsupportedVersion),
            (s.replace("spam", "sp\\u0000am"), bad("revocation reason")),
            (
                s.replace("\"v\":0", "\"v\":0,\"y\":1"),
                bad("revocation encoding"),
            ),
        ] {
            assert_eq!(TokenRevocation::from_json(b.as_bytes()), Err(err));
        }
        let mut raw = rev.json(false);
        assert_eq!(
            TokenRevocation::from_json(&jcs(&raw).unwrap()),
            Err(bad("missing sig"))
        );
        raw.sig = Some(b64(&rev.sig));
        raw.token_id = "A".into();
        assert_eq!(
            TokenRevocation::from_json(&jcs(&raw).unwrap()),
            Err(bad("token_id"))
        );
        raw.token_id = b64(&rev.token_id);
        raw.key_id = "A".into();
        assert_eq!(
            TokenRevocation::from_json(&jcs(&raw).unwrap()),
            Err(bad("key_id"))
        );
        raw.key_id = b64(&rev.key_id);
        raw.sig = Some("A".into());
        assert_eq!(
            TokenRevocation::from_json(&jcs(&raw).unwrap()),
            Err(bad("sig"))
        );
    }

    #[test]
    fn trusted_directory_rules_and_key_hygiene() {
        let (dk, _, _, _) = setup();
        let k = dk.public_key();
        assert!(TrustedDirectory::new("Agents.example", &[k]).is_err());
        assert!(TrustedDirectory::new(DIRECTORY, &[]).is_err());
        assert!(TrustedDirectory::new(DIRECTORY, &[k, k]).is_err());
        let three: Vec<[u8; 32]> = (0..3)
            .map(|i| {
                DirectoryKey::generate(&Rng::for_test(&format!("dk-{i}")))
                    .unwrap()
                    .public_key()
            })
            .collect();
        assert!(TrustedDirectory::new(DIRECTORY, &three).is_err());
        let restored = DirectoryKey::from_secret_bytes(&dk.secret_bytes());
        assert_eq!(restored.public_key(), k);
        let dbg = format!("{dk:?}");
        assert!(dbg.contains(&b64(&dk.key_id())));
        assert!(!dbg.contains(&b64(dk.secret_bytes().as_slice())));
        let mut g = grant(&Identity::generate(&Rng::for_test("g")).unwrap().id());
        g.issued_at = MAX_SAFE_INTEGER + 1;
        assert_eq!(
            dk.issue_token(&Rng::for_test("g"), &g),
            Err(bad("time out of range"))
        );
    }
}
