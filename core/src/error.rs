//! The crate's error type.

use std::fmt::Display;

/// Everything that can go wrong in `agentconnect-core`.
///
/// Messages never contain key material or plaintext. Errors from OpenMLS and
/// the storage backend are flattened to strings so that no OpenMLS type
/// appears in the public API.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A protocol version other than v0 (SPEC §13).
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    /// A ciphersuite other than the v0 suite (SPEC §3.1).
    #[error("unsupported ciphersuite")]
    WrongCiphersuite,
    /// Input that doesn't parse, or isn't in canonical form.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// An invite URL that doesn't follow SPEC §4.1.
    #[error("invalid invite URL: {0}")]
    InvalidInviteUrl(&'static str),
    /// The invite has expired (SPEC §4.3).
    #[error("invite expired")]
    InviteExpired,
    /// The object belongs to a different invite.
    #[error("invite mismatch")]
    InviteMismatch,
    /// The JoinRequest MAC doesn't verify (SPEC §6.2).
    #[error("join request MAC verification failed")]
    BadMac,
    /// The wrapped Welcome doesn't decrypt under `welcome_key` (SPEC §6.4).
    #[error("wrapped Welcome failed authentication")]
    WelcomeAuth,
    /// An HPKE public key whose length isn't 1216 bytes (SPEC §3.1).
    #[error("HPKE public key has the wrong length")]
    HpkeKeyLength,
    /// A KEM ciphertext (HPKE `kem_output`) whose length isn't 1120 bytes
    /// (SPEC §3.1).
    #[error("KEM ciphertext has the wrong length")]
    KemOutputLength,
    /// A KeyPackage that fails validation (SPEC §6.2 step 3).
    #[error("invalid key package: {0}")]
    InvalidKeyPackage(&'static str),
    /// The KeyPackage was already used in an Add (a replayed JoinRequest,
    /// SPEC §6.2).
    #[error("key package already used")]
    KeyPackageReused,
    /// A missing or invalid `ac_instance_cert` (SPEC §3.3).
    #[error("invalid instance certificate: {0}")]
    InvalidCert(&'static str),
    /// Credential, certificate and leaf key don't belong together (SPEC §3.1, §3.3).
    #[error("credential mismatch: {0}")]
    CredentialMismatch(&'static str),
    /// `ac_group_meta` differs from the `InviteMeta` shown to the human (SPEC §6.3).
    #[error("group metadata does not match the invite")]
    MetaMismatch,
    /// Group context extensions that violate SPEC §3.1 or §9.2.
    #[error("invalid group context: {0}")]
    InvalidGroupContext(&'static str),
    /// A received commit or proposal that the group policy forbids
    /// (`unauthorized_commit`, SPEC §9.2). It was not merged.
    #[error("unauthorized commit: {0}")]
    Unauthorized(&'static str),
    /// A local operation that the group policy doesn't allow this instance.
    #[error("not permitted: {0}")]
    NotPermitted(&'static str),
    /// A commit is already pending relay confirmation (SPEC §8.3).
    #[error("a commit is already pending")]
    CommitPending,
    /// There is no pending commit to confirm or discard.
    #[error("no pending commit")]
    NoPendingCommit,
    /// The confirmation (`accepted` `msg_id`) is not for the pending commit
    /// (SPEC §8.3). Nothing was merged.
    #[error("confirmation does not match the pending commit")]
    PendingCommitMismatch,
    /// The relay accepted an own commit that this instance had already
    /// discarded, so the group moved on without it (SPEC §8.3). The pending
    /// commit (if any) was discarded; the instance must re-sync (rejoin).
    #[error("an own commit discarded earlier was accepted; re-sync required")]
    OwnCommitLost,
    /// The plaintext doesn't fit the largest padding bucket (SPEC §7.1).
    #[error("message too large")]
    TooLarge,
    /// The message is for another group.
    #[error("message is for a different group")]
    WrongGroup,
    /// The message is not for the group's current epoch.
    #[error("message is for a different epoch")]
    WrongEpoch,
    /// The message has a type that isn't valid in this context.
    #[error("unexpected message: {0}")]
    UnexpectedMessage(&'static str),
    /// This instance is no longer a member of the group.
    #[error("not a member of the group")]
    NotMember,
    /// No member with that identity.
    #[error("unknown member")]
    UnknownMember,
    /// An error reported by OpenMLS.
    #[error("MLS error: {0}")]
    Mls(String),
    /// An error reported by the storage backend.
    #[error("storage error: {0}")]
    Storage(String),
    /// The database key doesn't decrypt the store: a wrong key, or a file
    /// that isn't an encrypted AgentConnect store.
    #[error("wrong database key, or not an encrypted store")]
    StorageKey,
    /// The random number generator failed.
    #[error("randomness source failed")]
    Rng,
    /// A bug or an unexpected library failure.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// Shorthand for `Result<T, agentconnect_core::Error>`.
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn mls<E: Display>(e: E) -> Error {
    Error::Mls(e.to_string())
}

pub(crate) fn storage<E: Display>(e: E) -> Error {
    Error::Storage(e.to_string())
}
