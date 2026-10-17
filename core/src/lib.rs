//! AgentConnect protocol core.
//!
//! Implements the cryptographic and wire-format parts of `SPEC.md`: MLS groups
//! with the v0 ciphersuite, invite binding, SAS derivation and envelopes.
#![warn(clippy::pedantic, missing_docs)]

pub mod clock;

/// Protocol version implemented by this crate (SPEC §13).
pub const PROTOCOL_VERSION: u32 = 0;

/// The only MLS ciphersuite permitted in protocol v0 (SPEC §3.1).
pub const CIPHERSUITE_V0: &str = "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519";

/// Returns `true` if `v` is a protocol version this crate can speak.
#[must_use]
pub fn supports_protocol(v: u32) -> bool {
    v == PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_only_v0() {
        assert!(supports_protocol(0));
        assert!(!supports_protocol(1));
    }
}
