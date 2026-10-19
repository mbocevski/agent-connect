//! Randomness source.
//!
//! Production code uses [`Rng::os`]: the libcrux DRBG, seeded from the
//! operating system. Tests and vector generation use [`Rng::seeded`], a
//! `ChaCha20` stream from a fixed seed, so key generation is reproducible.
//!
//! The seeded RNG drives everything that goes through OpenMLS's random
//! provider (group ids, KeyPackage and leaf HPKE keys, signing keys, nonces).
//! HPKE encapsulation inside libcrux draws from its own DRBG, so commit and
//! Welcome ciphertexts are not reproducible even with a seeded `Rng`.

use std::fmt;
use std::sync::{Mutex, OnceLock};

use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::random::OpenMlsRand;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{Rng as _, SeedableRng};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// The per-run test seed: `AC_TEST_SEED` if set (an integer), otherwise
/// random, fixed for the life of the process (TESTING.md). **Tests only.**
#[must_use]
pub fn test_seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        std::env::var("AC_TEST_SEED")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or_else(|| {
                Rng::os()
                    .and_then(|r| r.array::<8>())
                    .map_or(0, u64::from_be_bytes)
            })
    })
}

/// A source of cryptographic randomness.
pub struct Rng(Source);

enum Source {
    Os(Box<CryptoProvider>),
    Seeded(Box<Mutex<ChaCha20Rng>>),
}

impl Rng {
    /// Operating-system randomness (via the libcrux DRBG). Use this in
    /// production.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the OS can't seed the DRBG.
    pub fn os() -> Result<Self> {
        Ok(Self(Source::Os(Box::new(
            CryptoProvider::new().map_err(|_| Error::Rng)?,
        ))))
    }

    /// A deterministic `ChaCha20` stream. **Tests and test vectors only.**
    #[must_use]
    pub fn seeded(seed: [u8; 32]) -> Self {
        Self(Source::Seeded(Box::new(Mutex::new(
            ChaCha20Rng::from_seed(seed),
        ))))
    }

    /// [`Rng::seeded`] from a `u64` (e.g. `AC_TEST_SEED`). **Tests only.**
    #[must_use]
    pub fn from_u64(seed: u64) -> Self {
        let mut full = [0u8; 32];
        full[..8].copy_from_slice(&seed.to_be_bytes());
        Self::seeded(full)
    }

    /// A seeded RNG for test key material: `SHA-256(test_seed() ‖ label)`.
    /// The same label gives the same keys within one run, and a run can be
    /// reproduced with `AC_TEST_SEED`. **Tests only.**
    #[must_use]
    pub fn for_test(label: &str) -> Self {
        let digest = Sha256::new()
            .chain_update(test_seed().to_be_bytes())
            .chain_update(label.as_bytes())
            .finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        Self::seeded(seed)
    }

    /// Fills `buf` with random bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the source fails.
    pub fn fill(&self, buf: &mut [u8]) -> Result<()> {
        match &self.0 {
            Source::Os(p) => {
                let bytes = p.random_vec(buf.len()).map_err(|_| Error::Rng)?;
                buf.copy_from_slice(&bytes);
            }
            Source::Seeded(m) => m.lock().map_err(|_| Error::Rng)?.fill_bytes(buf),
        }
        Ok(())
    }

    /// `N` random bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the source fails.
    pub fn array<const N: usize>(&self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        self.fill(&mut out)?;
        Ok(out)
    }
}

impl fmt::Debug for Rng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Source::Os(_) => "Rng(os)",
            Source::Seeded(_) => "Rng(seeded)",
        })
    }
}

/// The randomness source failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("randomness source failed")]
pub struct RngError;

impl OpenMlsRand for Rng {
    type Error = RngError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        self.array().map_err(|_| RngError)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        self.fill(&mut out).map_err(|_| RngError)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_rng_is_reproducible() {
        let a = Rng::for_test("a");
        let b = Rng::for_test("a");
        assert_eq!(a.array::<32>().unwrap(), b.array::<32>().unwrap());
        assert_ne!(
            a.array::<32>().unwrap(),
            Rng::for_test("b").array::<32>().unwrap()
        );
        let n = test_seed();
        assert_eq!(
            Rng::from_u64(n).array::<16>().unwrap(),
            Rng::from_u64(n).array::<16>().unwrap()
        );
        assert_eq!(format!("{a:?}"), "Rng(seeded)");
    }

    #[test]
    fn os_rng_produces_distinct_output() {
        let r = Rng::os().unwrap();
        assert_ne!(r.array::<32>().unwrap(), r.array::<32>().unwrap());
        assert_eq!(r.random_vec(5).unwrap().len(), 5);
        assert_eq!(r.random_array::<3>().unwrap().len(), 3);
        assert_eq!(format!("{r:?}"), "Rng(os)");
    }

    #[test]
    fn openmls_draws_are_random() {
        // OpenMLS takes group ids, key seeds and nonces from `random_array`:
        // a broken source that repeats itself or returns a constant would
        // make them all the same.
        for r in [Rng::os().unwrap(), Rng::for_test("openmls-draws")] {
            let a: [u8; 32] = r.random_array().unwrap();
            let b: [u8; 32] = r.random_array().unwrap();
            assert_ne!(a, b, "{r:?}: two draws");
            assert!(a.iter().any(|&x| x != a[0]), "{r:?}: constant output");
            assert_ne!(r.random_vec(32).unwrap(), b.to_vec(), "{r:?}");
        }
    }
}
