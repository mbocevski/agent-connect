//! Short authentication string (SPEC §3.5, §11).
//!
//! The code comes from a SAS run: two instances each commit to a fresh
//! nonce ([`commitment`]), then reveal it, and both derive the code from
//! the epoch's `epoch_authenticator` and both nonces ([`Sas::derive`]).
//! The state machine of a run lives in the daemon; this module holds the
//! cryptography.

use std::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::rng::Rng;

const COMMIT_LABEL: &[u8] = b"agentconnect/v0/sas-commit";
const CODE_LABEL: &[u8] = b"agentconnect/v0/sas-code";

/// Length of a SAS nonce and of a commitment.
pub const NONCE_LEN: usize = 32;

/// The largest epoch a run can name: `epoch` is an I-JSON integer (§11.2).
pub const MAX_EPOCH: u64 = (1 << 53) - 1;

/// `lp(x) = u32be(len(x)) ‖ x` (SPEC §6.1).
fn lp(out: &mut Vec<u8>, x: &[u8]) {
    // Every input here is far below 4 GiB; a longer one is a caller bug.
    let len = u32::try_from(x.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(x);
}

/// This instance's nonce for one run (SPEC §11.2): 32 bytes from the RNG,
/// wiped when dropped and never shown by `Debug`.
pub struct SasNonce(Zeroizing<[u8; NONCE_LEN]>);

impl SasNonce {
    /// A fresh nonce.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the source fails.
    pub fn generate(rng: &Rng) -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; NONCE_LEN]);
        rng.fill(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// A nonce from known bytes. **Tests only**: with the `test-hooks`
    /// feature, which release builds leave off.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use]
    pub fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The bytes, for the reveal (step 3) and the code. Once revealed, the
    /// nonce is spent: the daemon never uses it again.
    #[must_use]
    pub fn expose(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl fmt::Debug for SasNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SasNonce(..)")
    }
}

/// The input of a SAS commitment (SPEC §11.2), 208 bytes for v0 values:
/// `"agentconnect/v0/sas-commit" ‖ lp(group_id) ‖ u64be(epoch) ‖ lp(sender)
/// ‖ lp(sender_instance) ‖ lp(peer) ‖ lp(nonce)`.
#[must_use]
pub fn commitment_input(
    group_id: &[u8],
    epoch: u64,
    sender: &str,
    sender_instance: u64,
    peer: &str,
    nonce: &[u8; NONCE_LEN],
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(208));
    out.extend_from_slice(COMMIT_LABEL);
    lp(&mut out, group_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    lp(&mut out, sender.as_bytes());
    lp(&mut out, &sender_instance.to_be_bytes());
    lp(&mut out, peer.as_bytes());
    lp(&mut out, nonce);
    out
}

/// The SAS commitment: SHA-256 of [`commitment_input`] (SPEC §11.2).
#[must_use]
pub fn commitment(
    group_id: &[u8],
    epoch: u64,
    sender: &str,
    sender_instance: u64,
    peer: &str,
    nonce: &[u8; NONCE_LEN],
) -> [u8; NONCE_LEN] {
    Sha256::digest(commitment_input(
        group_id,
        epoch,
        sender,
        sender_instance,
        peer,
        nonce,
    ))
    .into()
}

/// One participant of a run: its identity, its instance and its revealed
/// nonce (SPEC §11.4).
#[derive(Clone, Copy)]
pub struct Participant<'a> {
    /// The `ac:v0:…` identity identifier.
    pub identity: &'a str,
    /// The 64-bit instance id.
    pub instance_id: u64,
    /// The participant's nonce.
    pub nonce: &'a [u8; NONCE_LEN],
}

impl fmt::Debug for Participant<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Participant")
            .field("identity", &self.identity)
            .field("instance_id", &self.instance_id)
            .finish_non_exhaustive()
    }
}

impl Participant<'_> {
    fn write(&self, out: &mut Vec<u8>) {
        lp(out, self.identity.as_bytes());
        lp(out, &self.instance_id.to_be_bytes());
        lp(out, self.nonce);
    }
}

/// The HKDF `info` of the code (SPEC §11.4), 234 bytes for v0 values:
/// `"agentconnect/v0/sas-code" ‖ u64be(epoch) ‖ P_lo ‖ P_hi`, with the two
/// participants ordered by identity.
///
/// # Errors
///
/// [`Error::Malformed`] if both participants have the same identity (a run
/// with one's own identity is refused, §11.1).
pub fn code_info(epoch: u64, a: &Participant<'_>, b: &Participant<'_>) -> Result<Vec<u8>> {
    let (lo, hi) = match a.identity.as_bytes().cmp(b.identity.as_bytes()) {
        std::cmp::Ordering::Less => (a, b),
        std::cmp::Ordering::Greater => (b, a),
        std::cmp::Ordering::Equal => return Err(Error::Malformed("SAS run with oneself")),
    };
    let mut out = Vec::with_capacity(234);
    out.extend_from_slice(CODE_LABEL);
    out.extend_from_slice(&epoch.to_be_bytes());
    lo.write(&mut out);
    hi.write(&mut out);
    Ok(out)
}

/// The code of one completed run: 48 bits, rendered as emoji or decimal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sas {
    bytes: [u8; 6],
}

impl Sas {
    /// `sas_bytes` = HKDF(ikm = `epoch_authenticator`, salt = `group_id`,
    /// info = [`code_info`], L = 6) (SPEC §11.4).
    ///
    /// Callers in a group use [`crate::Group::sas_code`], which takes the
    /// authenticator of the group's current epoch and nothing else.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if both participants have the same identity.
    pub fn derive(
        epoch_authenticator: &[u8],
        group_id: &[u8],
        epoch: u64,
        a: &Participant<'_>,
        b: &Participant<'_>,
    ) -> Result<Self> {
        let info = code_info(epoch, a, b)?;
        let mut bytes = [0u8; 6];
        Hkdf::<Sha256>::new(Some(group_id), epoch_authenticator)
            .expand(&info, &mut bytes)
            .map_err(|_| Error::Internal("HKDF-SHA256 output of 6 bytes"))?;
        Ok(Self { bytes })
    }

    /// The raw `sas_bytes`.
    #[must_use]
    pub fn bytes(&self) -> [u8; 6] {
        self.bytes
    }

    fn bits(self) -> u64 {
        let mut buf = [0u8; 8];
        buf[2..].copy_from_slice(&self.bytes);
        u64::from_be_bytes(buf)
    }

    /// The first 42 bits as 7 indices (0–63) into the emoji table
    /// (`testdata/sas-emoji.json`).
    #[must_use]
    pub fn emoji_indices(&self) -> [u8; 7] {
        let bits = self.bits();
        std::array::from_fn(|i| {
            let shift = 48 - 6 * (u32::try_from(i).unwrap_or(0) + 1);
            // Masked to 6 bits, so the cast is lossless.
            u8::try_from((bits >> shift) & 0x3f).unwrap_or(0)
        })
    }

    /// The first 39 bits as three 13-bit numbers plus 1000, `NNNN-NNNN-NNNN`.
    #[must_use]
    pub fn decimal(&self) -> String {
        let bits = self.bits();
        let n = |i: u32| ((bits >> (48 - 13 * (i + 1))) & 0x1fff) + 1000;
        format!("{}-{}-{}", n(0), n(1), n(2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(rng: &Rng) -> (String, String) {
        let a = crate::encoding::b64(&rng.array::<32>().unwrap());
        let b = crate::encoding::b64(&rng.array::<32>().unwrap());
        (format!("ac:v0:{a}"), format!("ac:v0:{b}"))
    }

    #[test]
    fn a_participant_prints_without_its_nonce() {
        let rng = Rng::for_test("participant-debug");
        let (id, _) = ids(&rng);
        let nonce: [u8; NONCE_LEN] = rng.array().unwrap();
        let p = Participant {
            identity: &id,
            instance_id: 7,
            nonce: &nonce,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.starts_with("Participant {"));
        assert!(dbg.contains(&id) && dbg.contains("instance_id: 7"));
        assert!(!dbg.contains("nonce"));
        assert!(!dbg.contains(&format!("{:?}", &nonce[..4])));
    }

    #[test]
    fn renderings_take_the_leading_bits() {
        let sas = Sas {
            bytes: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        };
        assert_eq!(sas.emoji_indices(), [63; 7]);
        assert_eq!(sas.decimal(), "9191-9191-9191");
        let sas = Sas { bytes: [0; 6] };
        assert_eq!(sas.emoji_indices(), [0; 7]);
        assert_eq!(sas.decimal(), "1000-1000-1000");
        // 0b000001_000010_... : first indices 1, 2.
        let sas = Sas {
            bytes: [0x04, 0x20, 0, 0, 0, 0],
        };
        assert_eq!(sas.emoji_indices()[..2], [1, 2]);
    }

    #[test]
    fn input_lengths_match_the_spec() {
        let rng = Rng::for_test("sas/lengths");
        let (a, b) = ids(&rng);
        let (g, n): ([u8; 16], [u8; 32]) = (rng.array().unwrap(), rng.array().unwrap());
        assert_eq!(commitment_input(&g, 7, &a, 9, &b, &n).len(), 208);
        let pa = Participant {
            identity: &a,
            instance_id: 1,
            nonce: &n,
        };
        let pb = Participant {
            identity: &b,
            instance_id: 2,
            nonce: &n,
        };
        assert_eq!(code_info(7, &pa, &pb).unwrap().len(), 234);
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn every_input_changes_the_commitment() {
        let rng = Rng::for_test("sas/commitment");
        let (a, b) = ids(&rng);
        let (g, h): ([u8; 16], [u8; 16]) = (rng.array().unwrap(), rng.array().unwrap());
        let (n, m): ([u8; 32], [u8; 32]) = (rng.array().unwrap(), rng.array().unwrap());
        let base = commitment(&g, 3, &a, 5, &b, &n);
        assert_eq!(base, commitment(&g, 3, &a, 5, &b, &n));
        for other in [
            commitment(&h, 3, &a, 5, &b, &n),
            commitment(&g, 4, &a, 5, &b, &n),
            commitment(&g, 3, &b, 5, &b, &n),
            commitment(&g, 3, &a, 6, &b, &n),
            commitment(&g, 3, &a, 5, &a, &n),
            commitment(&g, 3, &a, 5, &b, &m),
            // Reflection: the peer's own commitment back to it.
            commitment(&g, 3, &b, 5, &a, &n),
        ] {
            assert_ne!(base, other);
        }
    }

    fn code(
        ea: &[u8; 32],
        g: &[u8; 16],
        epoch: u64,
        x: (&str, u64, &[u8; 32]),
        y: (&str, u64, &[u8; 32]),
    ) -> Result<Sas> {
        let p = |(identity, instance_id, nonce)| Participant {
            identity,
            instance_id,
            nonce,
        };
        Sas::derive(ea, g, epoch, &p(x), &p(y))
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn the_code_is_symmetric_and_binds_every_input() {
        let rng = Rng::for_test("sas/code");
        let (a, b) = ids(&rng);
        let (ea, eb): ([u8; 32], [u8; 32]) = (rng.array().unwrap(), rng.array().unwrap());
        let (g, h): ([u8; 16], [u8; 16]) = (rng.array().unwrap(), rng.array().unwrap());
        let (n, m, o): ([u8; 32], [u8; 32], [u8; 32]) = (
            rng.array().unwrap(),
            rng.array().unwrap(),
            rng.array().unwrap(),
        );
        let (a, b) = (a.as_str(), b.as_str());
        let base = code(&ea, &g, 1, (a, 1, &n), (b, 2, &m)).unwrap();
        assert_eq!(base, code(&ea, &g, 1, (b, 2, &m), (a, 1, &n)).unwrap());
        for other in [
            code(&eb, &g, 1, (a, 1, &n), (b, 2, &m)),
            code(&ea, &h, 1, (a, 1, &n), (b, 2, &m)),
            code(&ea, &g, 2, (a, 1, &n), (b, 2, &m)),
            code(&ea, &g, 1, (a, 3, &n), (b, 2, &m)),
            code(&ea, &g, 1, (a, 1, &o), (b, 2, &m)),
            code(&ea, &g, 1, (a, 1, &n), (b, 2, &o)),
            // The nonces swapped between the participants.
            code(&ea, &g, 1, (a, 1, &m), (b, 2, &n)),
        ] {
            assert_ne!(base, other.unwrap());
        }
        assert!(matches!(
            code(&ea, &g, 1, (a, 1, &n), (a, 2, &m)),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn a_nonce_never_shows_in_debug() {
        let nonce = SasNonce::from_bytes(Rng::for_test("sas/debug").array().unwrap());
        assert_eq!(format!("{nonce:?}"), "SasNonce(..)");
        let p = Participant {
            identity: "ac:v0:x",
            instance_id: 1,
            nonce: nonce.expose(),
        };
        assert!(!format!("{p:?}").contains("nonce"));
    }

    #[test]
    fn generated_nonces_differ() {
        let rng = Rng::for_test("sas/nonces");
        let a = SasNonce::generate(&rng).unwrap();
        let b = SasNonce::generate(&rng).unwrap();
        assert_ne!(a.expose(), b.expose());
    }
}
