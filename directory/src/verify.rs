//! The seam to `agentconnect_core::listing` for every signature, token and
//! canonical-form check (ADR-006, Decisions 1, 2 and 6).
//!
//! Heimdall never checks a signature, parses a JWS or canonicalises JSON on
//! its own. Everything that decides whether a signed object is genuine goes
//! through a [`Verifier`], implemented by [`CoreVerifier`]. What Heimdall
//! does itself is policy that needs its own state: its host and relays, the
//! `seq` and tombstone rules and the revoked token ids.

use agentconnect_core::Error;
use agentconnect_core::encoding::{b64, b64_decode_array};
use agentconnect_core::listing::{
    ListingToken, OwnerFile, RevocationReason, SignedListing, TokenRevocation, TrustedDirectory,
    Vouch, Withdrawal, directory_key_id,
};
use serde::Serialize;

/// What an owner's `/.well-known/agentconnect.json` says about one identity
/// in one listing (Decision 2). A file that doesn't parse vouches for
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerVerdict {
    /// The file lists the identity, and this listing if it scopes listings.
    Vouched,
    /// The file doesn't vouch for the identity here, or isn't valid.
    NotVouched,
    /// The identity is in the file's `revoked` list.
    Revoked {
        /// Unix seconds of the revocation, if the file gives one.
        revoked_at: Option<u64>,
        /// `superseded` or `compromised`, if the file gives one.
        reason: Option<&'static str>,
    },
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

/// Why a signed object was refused. The strings are the core's reasons and
/// are safe to return to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Not canonical, not the closed schema, over a limit or otherwise
    /// malformed.
    Malformed(&'static str),
    /// The listing, withdrawal or revocation signature doesn't verify.
    BadSignature,
    /// The door has expired.
    DoorExpired,
    /// The token isn't signed by a pinned operator key.
    UnknownKey,
    /// The token doesn't verify, doesn't bind this listing or has expired.
    BadToken(&'static str),
    /// The object is for another directory.
    WrongDirectory,
    /// A withdrawal's `ts` is more than 300 s from the directory clock.
    StaleTs,
}

/// Every cryptographic and canonical-form check Heimdall needs.
pub trait Verifier: Send + Sync + 'static {
    /// Verify published listing bytes: canonical JCS, the closed schema and
    /// field rules, the one JWS and its Ed25519 signature.
    ///
    /// # Errors
    ///
    /// [`Rejection::Malformed`] or [`Rejection::BadSignature`].
    fn listing(&self, bytes: &[u8]) -> Result<SignedListing, Rejection>;

    /// The publish-time checks: `issued_at` at most 300 s ahead, an
    /// unexpired door.
    ///
    /// # Errors
    ///
    /// [`Rejection::Malformed`] or [`Rejection::DoorExpired`].
    fn check_publish(&self, listing: &SignedListing, now: u64) -> Result<(), Rejection>;

    /// The embedded token verifies under a pinned key, binds this listing
    /// and hasn't expired. Revocation is the store's to check, atomically
    /// with the publish.
    ///
    /// # Errors
    ///
    /// [`Rejection::UnknownKey`] or [`Rejection::BadToken`].
    fn check_token(&self, listing: &SignedListing, now: u64) -> Result<(), Rejection>;

    /// Verify a `Withdrawal` and that it is for this directory and fresh.
    ///
    /// # Errors
    ///
    /// [`Rejection::Malformed`], [`Rejection::BadSignature`],
    /// [`Rejection::WrongDirectory`] or [`Rejection::StaleTs`].
    fn withdrawal(&self, bytes: &[u8], now: u64) -> Result<Withdrawal, Rejection>;

    /// Whether `withdrawal` removes `listing`.
    fn applies(&self, withdrawal: &Withdrawal, listing: &SignedListing) -> bool;

    /// Verify an operator `TokenRevocation` under the pinned keys.
    ///
    /// # Errors
    ///
    /// [`Rejection::Malformed`], [`Rejection::UnknownKey`] or
    /// [`Rejection::BadSignature`].
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

/// Map a core error to a rejection. The core names the failed check in a
/// fixed string; the signature checks are the ones a client must tell apart
/// from format errors.
fn rejection(e: &Error) -> Rejection {
    match e {
        Error::InvalidListing("signature")
        | Error::InvalidWithdrawal("signature")
        | Error::InvalidToken("revocation signature") => Rejection::BadSignature,
        Error::InvalidListing("door has expired") => Rejection::DoorExpired,
        Error::InvalidToken("unknown key_id") => Rejection::UnknownKey,
        Error::InvalidWithdrawal("for another directory") => Rejection::WrongDirectory,
        Error::InvalidWithdrawal("ts not within 300 s") => Rejection::StaleTs,
        Error::InvalidListing(why)
        | Error::InvalidWithdrawal(why)
        | Error::InvalidToken(why)
        | Error::Malformed(why) => Rejection::Malformed(why),
        Error::UnsupportedVersion => Rejection::Malformed("unsupported version"),
        _ => Rejection::Malformed("malformed"),
    }
}

impl CoreVerifier {
    /// Check a token on its own against a listing's binding fields: it binds
    /// `directory`, `name`, `identity` (and the domain, if it pins one), and
    /// it verifies under a pinned key and hasn't expired at `now`. This is
    /// [`Verifier::check_token`] without a signed card around the token.
    ///
    /// # Errors
    ///
    /// [`Rejection::UnknownKey`] or [`Rejection::BadToken`].
    pub fn check_listing_token(
        &self,
        token: &ListingToken,
        binding: (&str, &str, &str, Option<&str>),
        now: u64,
    ) -> Result<(), Rejection> {
        let (directory, name, identity, owner_domain) = binding;
        token
            .check_binding(directory, name, identity, owner_domain)
            .and_then(|()| token.verify(&self.trusted, now))
            .map_err(|e| token_rejection(&e))
    }
}

fn token_rejection(e: &Error) -> Rejection {
    match rejection(e) {
        Rejection::Malformed(why) => Rejection::BadToken(why),
        r => r,
    }
}

impl Verifier for CoreVerifier {
    fn listing(&self, bytes: &[u8]) -> Result<SignedListing, Rejection> {
        SignedListing::from_bytes(bytes).map_err(|e| rejection(&e))
    }

    fn check_publish(&self, listing: &SignedListing, now: u64) -> Result<(), Rejection> {
        listing.check_publish(now).map_err(|e| rejection(&e))
    }

    fn check_token(&self, listing: &SignedListing, now: u64) -> Result<(), Rejection> {
        listing
            .check_token(&self.trusted, now, |_| false)
            .map_err(|e| token_rejection(&e))
    }

    fn withdrawal(&self, bytes: &[u8], now: u64) -> Result<Withdrawal, Rejection> {
        let w = Withdrawal::from_json(bytes).map_err(|e| rejection(&e))?;
        w.check_fresh(self.trusted.host(), now)
            .map_err(|e| rejection(&e))?;
        Ok(w)
    }

    fn applies(&self, withdrawal: &Withdrawal, listing: &SignedListing) -> bool {
        withdrawal.applies_to(listing)
    }

    fn revocation(&self, bytes: &[u8]) -> Result<TokenRevocation, Rejection> {
        let r = TokenRevocation::from_json(bytes).map_err(|e| rejection(&e))?;
        r.verify(&self.trusted).map_err(|e| rejection(&e))?;
        Ok(r)
    }

    fn owner_verdict(&self, file: &[u8], identity: &str, name: &str) -> OwnerVerdict {
        let Ok(file) = OwnerFile::parse(file) else {
            return OwnerVerdict::NotVouched;
        };
        match file.vouch(identity, self.trusted.host(), name) {
            Vouch::Vouches => OwnerVerdict::Vouched,
            Vouch::DoesNotVouch => OwnerVerdict::NotVouched,
            Vouch::Revoked => {
                let entry = file.revoked().iter().find(|r| r.identity == identity);
                OwnerVerdict::Revoked {
                    revoked_at: entry.and_then(|r| r.revoked_at),
                    reason: entry.and_then(|r| r.reason).map(|r| match r {
                        RevocationReason::Superseded => "superseded",
                        RevocationReason::Compromised => "compromised",
                    }),
                }
            }
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
    fn core_errors_map_to_rejections() {
        assert_eq!(
            rejection(&Error::InvalidListing("signature")),
            Rejection::BadSignature
        );
        assert_eq!(
            rejection(&Error::InvalidListing("schema")),
            Rejection::Malformed("schema")
        );
        assert_eq!(
            rejection(&Error::UnsupportedVersion),
            Rejection::Malformed("unsupported version")
        );
        assert_eq!(
            rejection(&Error::WelcomeAuth),
            Rejection::Malformed("malformed")
        );
        assert_eq!(
            rejection(&Error::InvalidWithdrawal("ts not within 300 s")),
            Rejection::StaleTs
        );
    }
}
