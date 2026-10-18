//! Owner-signed withdrawals of a listing (SPEC §13.2.3).

use serde::{Deserialize, Serialize};

use super::card::SignedListing;
use super::{is_canonical_host, is_listing_name, verify_ed25519};
use crate::encoding::{MAX_SAFE_INTEGER, b64, b64_decode_array, from_jcs, jcs};
use crate::error::{Error, Result};
use crate::identity::{Identity, parse_identity};

const WITHDRAW_LABEL: &[u8] = b"agentconnect/v0/listing-withdraw";

/// How far a withdrawal's `ts` may be from the directory's clock (SPEC
/// §13.2.3).
pub const WITHDRAWAL_SKEW_SECS: u64 = 300;

const fn bad(what: &'static str) -> Error {
    Error::InvalidWithdrawal(what)
}

/// A withdrawal of every listing of `name` up to `seq`, signed by the
/// listed identity's `IK` (SPEC §13.2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    /// The directory host, in canonical form.
    pub directory: String,
    /// The listing name.
    pub name: String,
    /// The listed identity, whose key signed this.
    pub identity: String,
    /// The highest `seq` withdrawn.
    pub seq: u64,
    /// Unix seconds.
    pub ts: u64,
    /// Ed25519 by `IK`.
    pub sig: [u8; 64],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WithdrawalJson {
    v: u64,
    directory: String,
    name: String,
    identity: String,
    seq: u64,
    ts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
}

impl Withdrawal {
    fn json(&self, with_sig: bool) -> WithdrawalJson {
        WithdrawalJson {
            v: 0,
            directory: self.directory.clone(),
            name: self.name.clone(),
            identity: self.identity.clone(),
            seq: self.seq,
            ts: self.ts,
            sig: with_sig.then(|| b64(&self.sig)),
        }
    }

    fn check_fields(&self) -> Result<()> {
        if !is_canonical_host(&self.directory) {
            return Err(bad("directory"));
        }
        if !is_listing_name(&self.name) {
            return Err(bad("name"));
        }
        if self.seq == 0 || self.seq > MAX_SAFE_INTEGER || self.ts > MAX_SAFE_INTEGER {
            return Err(bad("integer out of range"));
        }
        Ok(())
    }

    /// Signs a withdrawal of `name` up to `seq` with `ik`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidWithdrawal`] for a malformed directory or name, or a
    /// `seq` of 0.
    pub fn sign(ik: &Identity, directory: &str, name: &str, seq: u64, ts: u64) -> Result<Self> {
        let mut w = Self {
            directory: directory.to_owned(),
            name: name.to_owned(),
            identity: ik.id(),
            seq,
            ts,
            sig: [0; 64],
        };
        w.check_fields()?;
        w.sig = ik.sign(&w.signing_input()?);
        Ok(w)
    }

    /// `"agentconnect/v0/listing-withdraw" ‖ JCS(withdrawal without "sig")`.
    ///
    /// # Errors
    ///
    /// Only if serialisation fails.
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        Ok([WITHDRAW_LABEL, &jcs(&self.json(false))?].concat())
    }

    /// The canonical JCS encoding.
    ///
    /// # Errors
    ///
    /// Only if serialisation fails.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        jcs(&self.json(true))
    }

    /// Parses a withdrawal and verifies its signature under the key in
    /// `identity`. The input must be canonical JCS with exactly the
    /// withdrawal's fields. Freshness is separate
    /// ([`Withdrawal::check_fresh`]), because a mirror verifies old feed
    /// entries.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidWithdrawal`] or [`Error::UnsupportedVersion`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let raw: WithdrawalJson = from_jcs(bytes, "withdrawal").map_err(|_| bad("encoding"))?;
        if raw.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        let sig = raw.sig.ok_or(bad("missing sig"))?;
        let w = Self {
            directory: raw.directory,
            name: raw.name,
            identity: raw.identity,
            seq: raw.seq,
            ts: raw.ts,
            sig: b64_decode_array(&sig, "sig").map_err(|_| bad("sig"))?,
        };
        w.check_fields()?;
        let ik = parse_identity(&w.identity).map_err(|_| bad("identity"))?;
        if !verify_ed25519(&ik, &w.signing_input()?, &w.sig) {
            return Err(bad("signature"));
        }
        Ok(w)
    }

    /// The directory's checks on `POST /v0/withdrawals`: the withdrawal is
    /// for `directory`, and `ts` is within 300 s of `now`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidWithdrawal`] naming the failed check.
    pub fn check_fresh(&self, directory: &str, now: u64) -> Result<()> {
        if self.directory != directory {
            return Err(bad("for another directory"));
        }
        if self.ts.abs_diff(now) > WITHDRAWAL_SKEW_SECS {
            return Err(bad("ts not within 300 s"));
        }
        Ok(())
    }

    /// Whether this withdrawal removes `listing`: the same directory, name
    /// and identity, and a listing `seq` no higher than the withdrawal's.
    #[must_use]
    pub fn applies_to(&self, listing: &SignedListing) -> bool {
        let p = listing.params();
        p.directory == self.directory
            && p.name == self.name
            && p.identity == self.identity
            && p.seq <= self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    const DIR: &str = "agents.example";
    const T0: u64 = 1_792_497_600;

    #[test]
    fn withdrawal_round_trips_and_checks_freshness() {
        let ik = Identity::generate(&Rng::for_test("withdrawal")).unwrap();
        let w = Withdrawal::sign(&ik, DIR, "release-planner", 7, T0).unwrap();
        let json = w.to_json().unwrap();
        let back = Withdrawal::from_json(&json).unwrap();
        assert_eq!(back, w);
        assert!(w.signing_input().unwrap().starts_with(WITHDRAW_LABEL));
        back.check_fresh(DIR, T0 + 300).unwrap();
        back.check_fresh(DIR, T0 - 300).unwrap();
        // A replay after the window is refused.
        assert_eq!(
            back.check_fresh(DIR, T0 + 301),
            Err(bad("ts not within 300 s"))
        );
        assert_eq!(
            back.check_fresh(DIR, T0 - 301),
            Err(bad("ts not within 300 s"))
        );
        assert_eq!(
            back.check_fresh("other.example", T0),
            Err(bad("for another directory"))
        );
    }

    #[test]
    fn withdrawal_signature_and_fields_are_checked() {
        let ik = Identity::generate(&Rng::for_test("withdrawal")).unwrap();
        let other = Identity::generate(&Rng::for_test("withdrawal-other")).unwrap();
        let w = Withdrawal::sign(&ik, DIR, "release-planner", 7, T0).unwrap();
        let s = String::from_utf8(w.to_json().unwrap()).unwrap();
        // Signed by another key, or with a changed seq.
        let wrong_key = s.replace(&ik.id(), &other.id());
        assert_eq!(
            Withdrawal::from_json(wrong_key.as_bytes()),
            Err(bad("signature"))
        );
        let tampered = s.replace("\"seq\":7", "\"seq\":8");
        assert_eq!(
            Withdrawal::from_json(tampered.as_bytes()),
            Err(bad("signature"))
        );
        for (b, err) in [
            (s.replace("\"v\":0", "\"v\":1"), Error::UnsupportedVersion),
            (s.replace("\"v\":0", "\"v\":0,\"z\":1"), bad("encoding")),
            (s.replace('{', "{ "), bad("encoding")),
            (
                s.replace("\"seq\":7", "\"seq\":0"),
                bad("integer out of range"),
            ),
            (s.replace("release-planner", "x"), bad("name")),
            (s.replace(DIR, "Agents.example"), bad("directory")),
            (s.replace(&ik.id(), "ac:v0:AA"), bad("identity")),
        ] {
            assert_eq!(Withdrawal::from_json(b.as_bytes()), Err(err), "{b}");
        }
        let mut raw = w.json(false);
        assert_eq!(
            Withdrawal::from_json(&jcs(&raw).unwrap()),
            Err(bad("missing sig"))
        );
        raw.sig = Some("AA".into());
        assert_eq!(Withdrawal::from_json(&jcs(&raw).unwrap()), Err(bad("sig")));
        assert_eq!(
            Withdrawal::sign(&ik, DIR, "release-planner", 0, T0),
            Err(bad("integer out of range"))
        );
        assert_eq!(
            Withdrawal::sign(&ik, "a b", "release-planner", 1, T0),
            Err(bad("directory"))
        );
    }
}
