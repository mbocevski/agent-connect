//! The seam to `agentconnect_core::listing` for every signature, token and
//! canonical-form check (ADR-006, Decisions 1, 2 and 6).
//!
//! The directory never checks a signature, parses a JWS or canonicalises JSON on
//! its own. Everything that decides whether a signed object is genuine goes
//! through a [`Verifier`], implemented by [`CoreVerifier`]. Refusals carry
//! the core's stable [`ErrorKind`], which picks the HTTP code, and the
//! core's reason, which becomes the detail. What the directory does itself is
//! state the core can't see: its host and relays, the stored listing and
//! tombstones (compared with the core's `replaces` and `tombstoned_by`) and
//! the revoked token ids.

use agentconnect_core::encoding::{b64, b64_decode_array};
use agentconnect_core::listing::{
    OwnerFile, RevocationReason, SignedListing, TokenRevocation, TrustedDirectory, Vouch,
    Withdrawal, directory_key_id,
};
use agentconnect_core::{Error, ErrorKind};
use serde::Serialize;

/// What an owner's `/.well-known/agentconnect.json` says about one identity
/// in one listing (Decision 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerVerdict {
    /// The file lists the identity, and this listing if it scopes listings.
    Vouched,
    /// The file doesn't vouch for the identity here.
    NotVouched,
    /// The identity is in the file's `revoked` list.
    Revoked {
        /// Unix seconds of the revocation, if the file gives one.
        revoked_at: Option<u64>,
        /// `superseded` or `compromised`, if the file gives one.
        reason: Option<&'static str>,
    },
    /// The file isn't a valid owner file: the fetch counts as failed.
    Unreadable,
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

/// Why a signed object was refused: the core's stable kind and its reason.
/// Both are safe to return to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection {
    /// What failed, as the core classifies it.
    pub kind: ErrorKind,
    /// The core's reason, naming the failed check.
    pub reason: &'static str,
}

impl From<&Error> for Rejection {
    fn from(e: &Error) -> Self {
        let reason = match e {
            Error::InvalidListing(r)
            | Error::InvalidToken(r)
            | Error::InvalidWithdrawal(r)
            | Error::InvalidOwnerFile(r)
            | Error::Malformed(r) => r,
            _ => e.kind().as_str(),
        };
        Self {
            kind: e.kind(),
            reason,
        }
    }
}

/// Every cryptographic and canonical-form check the directory needs.
pub trait Verifier: Send + Sync + 'static {
    /// Verify published listing bytes: canonical JCS, the closed schema and
    /// field rules, the one JWS and its signature, and the token's binding.
    ///
    /// # Errors
    ///
    /// A [`Rejection`].
    fn listing(&self, bytes: &[u8]) -> Result<SignedListing, Rejection>;

    /// The publish-time checks: `issued_at` at most 300 s ahead, an
    /// unexpired door.
    ///
    /// # Errors
    ///
    /// A [`Rejection`].
    fn check_publish(&self, listing: &SignedListing, now: u64) -> Result<(), Rejection>;

    /// The embedded token verifies under a pinned key, binds this listing
    /// and is valid at `now`. Revocation is the store's to check, atomically
    /// with the publish.
    ///
    /// # Errors
    ///
    /// A [`Rejection`].
    fn check_token(&self, listing: &SignedListing, now: u64) -> Result<(), Rejection>;

    /// Verify a `Withdrawal` and that it is for this directory and fresh.
    ///
    /// # Errors
    ///
    /// A [`Rejection`].
    fn withdrawal(&self, bytes: &[u8], now: u64) -> Result<Withdrawal, Rejection>;

    /// Whether `withdrawal` removes `listing`.
    fn applies(&self, withdrawal: &Withdrawal, listing: &SignedListing) -> bool;

    /// Verify an operator `TokenRevocation` under the pinned keys.
    ///
    /// # Errors
    ///
    /// A [`Rejection`].
    fn revocation(&self, bytes: &[u8]) -> Result<TokenRevocation, Rejection>;

    /// What an owner file says about `identity` listed as `name` here.
    fn owner_verdict(&self, file: &[u8], identity: &str, name: &str) -> OwnerVerdict;

    /// The pinned operator token keys.
    fn token_keys(&self) -> Vec<TokenKey>;
}

/// The [`Verifier`] on `agentconnect_core::listing`, with the operator keys
/// pinned for this directory.
#[derive(Debug, Clone)]
pub struct CoreVerifier {
    trusted: TrustedDirectory,
}

impl CoreVerifier {
    /// Pin `keys` (base64url `DK.pub`, one or two) for `host`.
    ///
    /// # Errors
    ///
    /// A message if a key isn't base64url of 32 bytes, or the core refuses
    /// the set (no keys, more than two, a duplicate, not an Ed25519 point,
    /// a host that isn't canonical).
    pub fn new(host: &str, keys: &[String]) -> Result<Self, String> {
        let keys = keys
            .iter()
            .map(|k| b64_decode_array::<32>(k, "token key"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "a token key is not base64url of 32 bytes".to_owned())?;
        TrustedDirectory::new(host, &keys)
            .map(|trusted| Self { trusted })
            .map_err(|e| e.to_string())
    }
}

impl Verifier for CoreVerifier {
    fn listing(&self, bytes: &[u8]) -> Result<SignedListing, Rejection> {
        SignedListing::from_bytes(bytes).map_err(|e| Rejection::from(&e))
    }

    fn check_publish(&self, listing: &SignedListing, now: u64) -> Result<(), Rejection> {
        listing.check_publish(now).map_err(|e| Rejection::from(&e))
    }

    fn check_token(&self, listing: &SignedListing, now: u64) -> Result<(), Rejection> {
        listing
            .check_token(&self.trusted, now, |_| false)
            .map_err(|e| Rejection::from(&e))
    }

    fn withdrawal(&self, bytes: &[u8], now: u64) -> Result<Withdrawal, Rejection> {
        let w = Withdrawal::from_json(bytes).map_err(|e| Rejection::from(&e))?;
        w.check_fresh(self.trusted.host(), now)
            .map_err(|e| Rejection::from(&e))?;
        Ok(w)
    }

    fn applies(&self, withdrawal: &Withdrawal, listing: &SignedListing) -> bool {
        withdrawal.applies_to(listing)
    }

    fn revocation(&self, bytes: &[u8]) -> Result<TokenRevocation, Rejection> {
        let r = TokenRevocation::from_json(bytes).map_err(|e| Rejection::from(&e))?;
        r.verify(&self.trusted).map_err(|e| Rejection::from(&e))?;
        Ok(r)
    }

    fn owner_verdict(&self, file: &[u8], identity: &str, name: &str) -> OwnerVerdict {
        let Ok(file) = OwnerFile::parse(file) else {
            return OwnerVerdict::Unreadable;
        };
        match file.vouch(identity, self.trusted.host(), name) {
            Vouch::Vouches => OwnerVerdict::Vouched,
            Vouch::DoesNotVouch => OwnerVerdict::NotVouched,
            Vouch::Revoked { revoked_at, reason } => OwnerVerdict::Revoked {
                revoked_at,
                reason: reason.map(|r| match r {
                    RevocationReason::Superseded => "superseded",
                    RevocationReason::Compromised => "compromised",
                }),
            },
        }
    }

    fn token_keys(&self) -> Vec<TokenKey> {
        self.trusted
            .keys()
            .iter()
            .map(|k| TokenKey {
                key_id: b64(&directory_key_id(k)),
                public_key: b64(k),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_checked() {
        assert!(CoreVerifier::new("agents.test", &[]).is_err());
        assert!(CoreVerifier::new("agents.test", &["not base64!".into()]).is_err());
        let k = b64(&[0_u8; 31]);
        assert!(CoreVerifier::new("agents.test", &[k]).is_err());
    }

    #[test]
    fn rejections_carry_the_cores_kind_and_reason() {
        let r = Rejection::from(&Error::InvalidListing("signature"));
        assert_eq!((r.kind, r.reason), (ErrorKind::Signature, "signature"));
        let r = Rejection::from(&Error::UnsupportedVersion);
        assert_eq!(
            (r.kind, r.reason),
            (ErrorKind::UnsupportedVersion, "unsupported_version")
        );
    }
}
