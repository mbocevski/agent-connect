//! AgentConnect protocol core.
//!
//! Implements the cryptographic and wire-format parts of `SPEC.md`: MLS groups
//! with the v0 ciphersuite, invite binding, SAS derivation and envelopes.
//!
//! OpenMLS types never appear in the public API: everything crossing it is
//! our own types or bytes.
//!
//! - [`identity`]: identities, instances and instance certificates (§2, §3.3)
//! - [`export`]: the wrapped identity export that provisions a replica (§9.4)
//! - [`invite`]: invite URLs, `join_key`/`welcome_key`, the wrapped Welcome (§4, §6.4)
//! - [`join`]: the JoinRequest (§6.1)
//! - [`group`]: [`Client`] and [`Group`]: creation, joins, commits, policy
//!   enforcement, application messages (§5–§9)
//! - [`policy`]: `ac_group_meta`, `ac_group_policy` (§3.4, §9.1)
//! - [`sas`]: the short authentication string (§11)
//! - [`padding`]: application padding buckets (§7.1)
//! - [`provider`]: storage backends ([`MemoryStore`], the SQLCipher-encrypted
//!   [`SqliteStore`] and its [`DbKey`])
//! - [`db`]: [`EncryptedDb`], the SQLCipher database for a daemon's own records
//! - [`journal`]: the processing journal that makes processing crash-safe (ADR-004)
//! - [`knock`]: doors, sealed knocks and the knock Welcome wrap (§6.6)
//! - [`ledger`]: the owner's replay ledger for join requests and knocks
//!   (§6.2, §6.6.3)
//! - [`listing`]: signed listings, listing tokens, withdrawals and owner
//!   verification (§13)
//! - [`net`]: which addresses an outbound fetch may connect to (§13.2.4)
//! - [`operator`]: the terms and abuse links the relay and the directory show
//! - [`healthcheck`]: the relay's and the directory's `healthcheck` subcommand
#![warn(clippy::pedantic, missing_docs)]

pub mod clock;
pub mod db;
pub mod encoding;
mod error;
pub mod export;
#[doc(hidden)]
pub mod failpoint;
pub mod group;
pub mod healthcheck;
pub mod identity;
pub mod invite;
pub mod join;
pub mod journal;
pub mod knock;
pub mod ledger;
pub mod listing;
mod mls;
pub mod net;
pub mod operator;
pub mod padding;
pub mod policy;
pub mod provider;
mod records;
pub mod rng;
pub mod sas;
#[cfg(test)]
mod vectors;

pub use db::EncryptedDb;
pub use error::{Error, ErrorKind, Result};
pub use group::{
    ApplicationMessage, Client, CommitOut, CommitSummary, Event, Group, MemberInfo, MessageHeader,
    MessageKind, Routing, VerifiedJoinRequest,
};
pub use identity::{Identity, Instance, InstanceCert};
pub use invite::{Invite, InviteLink, InviteMeta, InviteSecret};
pub use join::JoinRequest;
pub use journal::{JournalEntry, Journaled};
pub use mls::{EXT_GROUP_META, EXT_GROUP_POLICY, EXT_INSTANCE_CERT, HPKE_PUBLIC_KEY_LEN};
pub use policy::{GroupMeta, GroupPolicy};
pub use provider::{DbKey, MemoryStore, SqliteStore, Store};
pub use rng::Rng;
pub use sas::{Participant, Sas, SasNonce};

/// Protocol version implemented by this crate (SPEC §13).
pub const PROTOCOL_VERSION: u32 = 0;

/// The only MLS ciphersuite permitted in protocol v0 (SPEC §3.1).
pub const CIPHERSUITE_V0: &str = "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519";

/// Its (provisional) codepoint, `0x004F` (SPEC §3.1).
pub const CIPHERSUITE_V0_CODEPOINT: u16 = 0x004F;

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

    #[test]
    fn ciphersuite_constants_agree() {
        assert_eq!(u16::from(mls::CS), CIPHERSUITE_V0_CODEPOINT);
        assert_eq!(format!("{:?}", mls::CS), CIPHERSUITE_V0);
    }
}
