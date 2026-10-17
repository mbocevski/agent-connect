//! Short authentication string (SPEC §3.5, §11).

use hkdf::Hkdf;
use sha2::Sha256;

const SAS_INFO: &[u8] = b"agentconnect/v0/sas";

/// The SAS of one epoch: 48 bits, rendered as emoji or decimal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sas {
    bytes: [u8; 6],
}

impl Sas {
    /// `sas_bytes` = HKDF(ikm = `epoch_authenticator`, salt = `group_id`,
    /// info = "agentconnect/v0/sas" ‖ u64be(epoch), L = 6).
    #[must_use]
    pub fn derive(epoch_authenticator: &[u8], group_id: &[u8], epoch: u64) -> Self {
        let info = [SAS_INFO, &epoch.to_be_bytes()].concat();
        let mut bytes = [0u8; 6];
        if Hkdf::<Sha256>::new(Some(group_id), epoch_authenticator)
            .expand(&info, &mut bytes)
            .is_err()
        {
            unreachable!("HKDF-SHA256 output of 6 bytes is always valid");
        }
        Self { bytes }
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
    fn epoch_and_group_change_the_code() {
        let rng = crate::rng::Rng::for_test("sas");
        let (ea, eb): ([u8; 32], [u8; 32]) = (rng.array().unwrap(), rng.array().unwrap());
        let (g, h): ([u8; 16], [u8; 16]) = (rng.array().unwrap(), rng.array().unwrap());
        let a = Sas::derive(&ea, &g, 1);
        assert_eq!(a, Sas::derive(&ea, &g, 1));
        assert_ne!(a, Sas::derive(&ea, &g, 2));
        assert_ne!(a, Sas::derive(&ea, &h, 1));
        assert_ne!(a, Sas::derive(&eb, &g, 1));
        assert_eq!(a.bytes().len(), 6);
    }
}
