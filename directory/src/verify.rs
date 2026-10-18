//! The seam to `agentconnect_core` for every signature, token and
//! canonical-form check (ADR-006, Decisions 1, 2 and 6).
//!
//! Heimdall never checks a signature, parses a JWS or canonicalises JSON on
//! its own. Everything that decides whether a signed object is genuine goes
//! through a [`Verifier`]. What Heimdall does itself is policy: comparing the
//! verified fields with its own host, its relays, its clock and its store.
//!
//! The production implementation wraps `agentconnect_core::listing`. Until
//! that module is available, the binary runs with [`Unavailable`], which
//! refuses every signed object, so nothing can be published.

use serde::Serialize;

/// The door of a listing (`params.door`, Decision 3). The public key is not
/// needed by the directory and is not carried here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Door {
    /// The relay-side door handle, 22 base64url characters.
    pub id: String,
    /// Unix seconds after which the door is closed.
    pub expires_at: u64,
}

/// The `e2e` extension params of a listing whose JWS, canonical form, closed
/// schema and text limits have been verified (Decision 1).
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedListing {
    /// The listing name (slug).
    pub name: String,
    /// The listed identity, `ac:v0:<b64url IK.pub>`; the JWS `kid`.
    pub identity: String,
    /// The directory host the listing is for, in canonical form.
    pub directory: String,
    /// The relay host a knock goes through, in canonical form.
    pub relay: String,
    /// The listing sequence number.
    pub seq: u64,
    /// Unix seconds at signing.
    pub issued_at: u64,
    /// The door, absent when the listing takes no new connections.
    pub door: Option<Door>,
    /// The claimed owner domain.
    pub owner_domain: Option<String>,
    /// The embedded `ListingToken`, still to be checked with
    /// [`Verifier::verify_token`].
    pub token: serde_json::Value,
}

/// A `ListingToken` whose signature verified against a configured operator
/// key (Decision 6). Its scope and lifetime are not yet compared with
/// anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingToken {
    /// The token id (16 random bytes, base64url).
    pub token_id: String,
    /// The directory host the token is for.
    pub directory: String,
    /// The listing name it authorises.
    pub name: String,
    /// The identity it authorises.
    pub identity: String,
    /// The only owner domain the listing may claim, if pinned.
    pub owner_domain: Option<String>,
    /// Unix seconds at issue.
    pub issued_at: u64,
    /// Unix seconds after which the token is void.
    pub expires_at: u64,
    /// The operator key that signed it.
    pub key_id: String,
}

/// An IK-signed `Withdrawal` whose signature verified (Decision 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    /// The directory host.
    pub directory: String,
    /// The listing name.
    pub name: String,
    /// The signing identity.
    pub identity: String,
    /// The highest `seq` withdrawn.
    pub seq: u64,
    /// Unix seconds at signing.
    pub ts: u64,
}

/// An operator-signed `TokenRevocation` whose signature verified against a
/// configured operator key (Decision 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRevocation {
    /// The revoked token.
    pub token_id: String,
    /// Unix seconds of the revocation.
    pub revoked_at: u64,
    /// The operator's reason.
    pub reason: String,
    /// The operator key that signed it.
    pub key_id: String,
}

/// What an owner's `/.well-known/agentconnect.json` says about one identity
/// in one listing (Decision 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerVerdict {
    /// The file lists the identity, and this listing if it scopes listings.
    Vouched,
    /// The file is valid but does not vouch for the identity here.
    NotVouched,
    /// The identity is in the file's `revoked` list.
    Revoked {
        /// Unix seconds of the revocation.
        revoked_at: u64,
        /// `superseded` or `compromised`.
        reason: String,
    },
    /// The file is not valid (not I-JSON, too large, duplicate keys, ...).
    Invalid,
}

/// An operator token key, published for information at
/// `/.well-known/agentconnect-directory.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenKey {
    /// `b64url(SHA-256(DK.pub)[0..16])`.
    pub key_id: String,
    /// `DK.pub`, base64url.
    pub public_key: String,
}

/// Why a signed object was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// Not canonical, not the closed schema, over a limit or otherwise
    /// malformed. The detail is safe to return to the client.
    Malformed(&'static str),
    /// The signature does not verify.
    BadSignature,
    /// The signing key is not one this directory is configured with.
    UnknownKey,
    /// No verifier is available in this build.
    Unavailable,
}

/// Every cryptographic and canonical-form check Heimdall needs.
///
/// Implementations must be pure: no I/O, no clock. Time-dependent and
/// store-dependent rules (expiry, `seq`, revoked token ids) are the
/// directory's job.
pub trait Verifier: Send + Sync + 'static {
    /// Verify a listing (Decision 1): byte-for-byte canonical JCS, the closed
    /// schema and text limits, exactly one interface and one JWS, the
    /// protected header, and the Ed25519 signature under the key in `kid`.
    ///
    /// # Errors
    ///
    /// A [`Rejection`] naming the first failed check.
    fn verify_listing(&self, bytes: &[u8]) -> Result<VerifiedListing, Rejection>;

    /// Verify an embedded `ListingToken`'s signature against the configured
    /// operator keys.
    ///
    /// # Errors
    ///
    /// [`Rejection::UnknownKey`] for a `key_id` that isn't configured, else
    /// as for [`Verifier::verify_listing`].
    fn verify_token(&self, token: &serde_json::Value) -> Result<ListingToken, Rejection>;

    /// Verify a `Withdrawal`: canonical JCS and the IK signature under the
    /// `agentconnect/v0/listing-withdraw` label.
    ///
    /// # Errors
    ///
    /// A [`Rejection`].
    fn verify_withdrawal(&self, bytes: &[u8]) -> Result<Withdrawal, Rejection>;

    /// Verify a `TokenRevocation` against the configured operator keys.
    ///
    /// # Errors
    ///
    /// A [`Rejection`].
    fn verify_revocation(&self, bytes: &[u8]) -> Result<TokenRevocation, Rejection>;

    /// Decide what an owner's well-known file says about `identity` in the
    /// listing `listing` (`<directory>/a/<name>`), including the fingerprint
    /// consistency rule.
    fn owner_verdict(&self, file: &[u8], identity: &str, listing: &str) -> OwnerVerdict;

    /// The configured operator token keys.
    fn token_keys(&self) -> Vec<TokenKey>;
}

/// The verifier of a build without `agentconnect_core::listing`. It refuses
/// every signed object, so the directory serves pages but accepts nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unavailable;

impl Verifier for Unavailable {
    fn verify_listing(&self, _: &[u8]) -> Result<VerifiedListing, Rejection> {
        Err(Rejection::Unavailable)
    }

    fn verify_token(&self, _: &serde_json::Value) -> Result<ListingToken, Rejection> {
        Err(Rejection::Unavailable)
    }

    fn verify_withdrawal(&self, _: &[u8]) -> Result<Withdrawal, Rejection> {
        Err(Rejection::Unavailable)
    }

    fn verify_revocation(&self, _: &[u8]) -> Result<TokenRevocation, Rejection> {
        Err(Rejection::Unavailable)
    }

    fn owner_verdict(&self, _: &[u8], _: &str, _: &str) -> OwnerVerdict {
        OwnerVerdict::Invalid
    }

    fn token_keys(&self) -> Vec<TokenKey> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_refuses_everything() {
        let v = Unavailable;
        assert_eq!(v.verify_listing(b"{}"), Err(Rejection::Unavailable));
        assert_eq!(
            v.verify_token(&serde_json::json!({})),
            Err(Rejection::Unavailable)
        );
        assert_eq!(v.verify_withdrawal(b"{}"), Err(Rejection::Unavailable));
        assert_eq!(v.verify_revocation(b"{}"), Err(Rejection::Unavailable));
        assert_eq!(v.owner_verdict(b"{}", "x", "y"), OwnerVerdict::Invalid);
        assert_eq!(v.token_keys(), Vec::new());
    }
}
