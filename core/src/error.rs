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
    /// The message was already processed under this journal key and its
    /// entry consumed (a redelivery; ADR-004). Nothing changed.
    #[error("message already processed")]
    Duplicate,
    /// The journal key was already used for different bytes. Nothing
    /// changed.
    #[error("journal key reused for a different message")]
    JournalConflict,
    /// A listing that breaks SPEC §13.1 (format, canonical form, schema,
    /// limits or its JWS).
    #[error("invalid listing: {0}")]
    InvalidListing(&'static str),
    /// A `ListingToken` or `TokenRevocation` that is malformed, doesn't
    /// verify under a pinned directory key, doesn't bind the listing, has
    /// expired or was revoked (SPEC §13.2.1).
    #[error("invalid listing token: {0}")]
    InvalidToken(&'static str),
    /// A `Withdrawal` that is malformed, doesn't verify or is not fresh
    /// (SPEC §13.2.3).
    #[error("invalid withdrawal: {0}")]
    InvalidWithdrawal(&'static str),
    /// An owner well-known file that breaks SPEC §13.2.4.
    #[error("invalid owner file: {0}")]
    InvalidOwnerFile(&'static str),
    /// A knock that fails one of the owner's checks (SPEC §6.6.3), or a
    /// door key or sealed knock of the wrong shape.
    #[error("invalid knock: {0}")]
    InvalidKnock(&'static str),
    /// A Welcome that unwrapped under a knock's `welcome_key` but is not
    /// the group the knock asked for (SPEC §6.6.5): the wrong owner, name
    /// or members. Only the knock's two ends know the key, so raise
    /// `relay_misbehaviour`. The KeyPackage is spent.
    #[error("knock Welcome mismatch: {0}")]
    KnockWelcome(&'static str),
    /// A knock or JoinRequest whose id or `KeyPackageRef` the owner's
    /// replay ledger remembers (SPEC §6.2, §6.6.3 step 6): drop it
    /// silently.
    #[error("replayed")]
    Replayed,
    /// The replay ledger is full and evicts nothing live: the request is
    /// refused until entries expire.
    #[error("replay ledger full")]
    LedgerFull,
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

/// A stable classification of an [`Error`], for callers that act on the
/// kind of failure (answer codes, retries, badges). Messages are human
/// text and may change; kinds don't. Python sees [`ErrorKind::as_str`] as
/// `AgentConnectError.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Bytes that don't parse, aren't canonical or break a format rule.
    Malformed,
    /// A `v` (protocol version) other than 0.
    UnsupportedVersion,
    /// A signature that doesn't verify (listing JWS, token, revocation,
    /// withdrawal, knock).
    Signature,
    /// A `key_id` that names no pinned directory key.
    UnknownKey,
    /// A token past its `expires_at`.
    Expired,
    /// A token whose `issued_at` is still in the future.
    NotYetValid,
    /// A revoked token.
    Revoked,
    /// A token bound to another directory, name, identity or owner domain.
    TokenMismatch,
    /// A door that has expired.
    DoorExpired,
    /// A knock for another door.
    WrongDoor,
    /// An object for another directory.
    WrongDirectory,
    /// A timestamp outside its window (stale or in the future).
    StaleTimestamp,
    /// A listing a newer one for its name (a later token, a higher `seq` or
    /// a tombstone) supersedes.
    Superseded,
    /// A bounded store that is full; the input is refused, not queued.
    Busy,
    /// A knock, JoinRequest or KeyPackage already seen (a replay).
    Replay,
    /// A KeyPackage already used in an Add.
    KeyPackageReused,
    /// Credential, certificate, leaf key or mailbox that don't belong
    /// together.
    CredentialMismatch,
    /// A key or KEM ciphertext of the wrong length.
    KeyLength,
    /// An AEAD or HPKE open that failed: wrong key, wrong secret or tampering.
    Authentication,
    /// A knock Welcome that isn't the group the knock asked for (SPEC
    /// §6.6.5).
    WelcomeMismatch,
    /// A commit or proposal the group policy forbids (SPEC §9.2): one
    /// received from a member, or one this instance would build.
    Unauthorized,
    /// A local operation the group's state doesn't allow this instance,
    /// such as committing while its own leave is pending.
    NotPermitted,
    /// A commit of this instance's is already waiting for the relay's
    /// answer (SPEC §8.3).
    CommitPending,
    /// Anything else (storage, MLS, randomness, internal).
    Other,
}

impl ErrorKind {
    /// The kind's stable snake-case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnsupportedVersion => "unsupported_version",
            Self::Signature => "signature",
            Self::UnknownKey => "unknown_key",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Revoked => "revoked",
            Self::TokenMismatch => "token_mismatch",
            Self::DoorExpired => "door_expired",
            Self::WrongDoor => "wrong_door",
            Self::WrongDirectory => "wrong_directory",
            Self::StaleTimestamp => "stale_timestamp",
            Self::Superseded => "superseded",
            Self::Busy => "busy",
            Self::Replay => "replay",
            Self::KeyPackageReused => "key_package_reused",
            Self::CredentialMismatch => "credential_mismatch",
            Self::KeyLength => "key_length",
            Self::Authentication => "authentication",
            Self::WelcomeMismatch => "welcome_mismatch",
            Self::Unauthorized => "unauthorized",
            Self::NotPermitted => "not_permitted",
            Self::CommitPending => "commit_pending",
            Self::Other => "other",
        }
    }
}

/// The kind of a discovery failure reason. This is the one place reasons
/// are classified; nothing else may branch on them.
fn reason_kind(reason: &str) -> ErrorKind {
    use ErrorKind as K;
    match reason {
        "signature" | "revocation signature" => K::Signature,
        "unknown key_id" => K::UnknownKey,
        "expired" | "lapsed" => K::Expired,
        "not yet valid" => K::NotYetValid,
        "revoked" => K::Revoked,
        r if r.starts_with("bound to another") => K::TokenMismatch,
        "door has expired" | "door expired" => K::DoorExpired,
        "not this door" | "door_id mismatch" => K::WrongDoor,
        "for another directory" => K::WrongDirectory,
        "ts not within 300 s"
        | "ts out of range"
        | "issued_at is in the future"
        | "issued_at goes back" => K::StaleTimestamp,
        "token older than the name's newest"
        | "does not replace the stored listing"
        | "tombstoned"
        | "seq does not increase" => K::Superseded,
        "seal does not open" => K::Authentication,
        _ => K::Malformed,
    }
}

impl Error {
    /// The stable kind of this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        use ErrorKind as K;
        match self {
            Self::UnsupportedVersion => K::UnsupportedVersion,
            Self::InvalidListing(r)
            | Self::InvalidToken(r)
            | Self::InvalidWithdrawal(r)
            | Self::InvalidOwnerFile(r)
            | Self::InvalidKnock(r) => reason_kind(r),
            Self::Malformed(_)
            | Self::InvalidInviteUrl(_)
            | Self::InvalidKeyPackage(_)
            | Self::InvalidCert(_)
            | Self::InvalidGroupContext(_)
            | Self::WrongCiphersuite => K::Malformed,
            Self::KeyPackageReused => K::KeyPackageReused,
            Self::CredentialMismatch(_) => K::CredentialMismatch,
            Self::HpkeKeyLength | Self::KemOutputLength => K::KeyLength,
            Self::WelcomeAuth | Self::BadMac => K::Authentication,
            Self::InviteExpired => K::Expired,
            Self::KnockWelcome(_) => K::WelcomeMismatch,
            Self::Replayed => K::Replay,
            Self::LedgerFull => K::Busy,
            Self::Unauthorized(_) => K::Unauthorized,
            Self::NotPermitted(_) => K::NotPermitted,
            Self::CommitPending => K::CommitPending,
            _ => K::Other,
        }
    }
}

pub(crate) fn mls<E: Display>(e: E) -> Error {
    Error::Mls(e.to_string())
}

pub(crate) fn storage<E: Display>(e: E) -> Error {
    Error::Storage(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ErrorKind as K;

    #[test]
    fn discovery_reasons_have_kinds() {
        for (e, k) in [
            (Error::InvalidListing("signature"), K::Signature),
            (Error::InvalidToken("revocation signature"), K::Signature),
            (Error::InvalidWithdrawal("signature"), K::Signature),
            (Error::InvalidKnock("signature"), K::Signature),
            (Error::InvalidToken("unknown key_id"), K::UnknownKey),
            (Error::InvalidToken("expired"), K::Expired),
            (Error::InvalidToken("not yet valid"), K::NotYetValid),
            (Error::InvalidToken("revoked"), K::Revoked),
            (
                Error::InvalidToken("bound to another name"),
                K::TokenMismatch,
            ),
            (Error::InvalidListing("door has expired"), K::DoorExpired),
            (Error::InvalidKnock("door expired"), K::DoorExpired),
            (Error::InvalidKnock("door_id mismatch"), K::WrongDoor),
            (
                Error::InvalidWithdrawal("for another directory"),
                K::WrongDirectory,
            ),
            (
                Error::InvalidWithdrawal("ts not within 300 s"),
                K::StaleTimestamp,
            ),
            (Error::InvalidKnock("ts out of range"), K::StaleTimestamp),
            (
                Error::InvalidListing("issued_at goes back"),
                K::StaleTimestamp,
            ),
            (
                Error::InvalidListing("issued_at is in the future"),
                K::StaleTimestamp,
            ),
            (Error::Replayed, K::Replay),
            (Error::InvalidListing("tombstoned"), K::Superseded),
            (
                Error::InvalidListing("seq does not increase"),
                K::Superseded,
            ),
            (Error::LedgerFull, K::Busy),
            (Error::InvalidKnock("lapsed"), K::Expired),
            (Error::KnockWelcome("name"), K::WelcomeMismatch),
            (Error::InvalidKnock("seal does not open"), K::Authentication),
            (Error::InvalidListing("not canonical JCS"), K::Malformed),
            (Error::InvalidOwnerFile("not I-JSON"), K::Malformed),
            (Error::UnsupportedVersion, K::UnsupportedVersion),
            (Error::KeyPackageReused, K::KeyPackageReused),
            (Error::CredentialMismatch("x"), K::CredentialMismatch),
            (Error::HpkeKeyLength, K::KeyLength),
            (Error::WelcomeAuth, K::Authentication),
            (Error::InviteExpired, K::Expired),
            (Error::Malformed("x"), K::Malformed),
            (Error::Unauthorized("x"), K::Unauthorized),
            (Error::NotPermitted("x"), K::NotPermitted),
            (Error::CommitPending, K::CommitPending),
            (Error::NotMember, K::Other),
            (Error::Storage("x".into()), K::Other),
        ] {
            assert_eq!(e.kind(), k, "{e}");
        }
        let names: std::collections::BTreeSet<&str> = [
            K::Malformed,
            K::UnsupportedVersion,
            K::Signature,
            K::UnknownKey,
            K::Expired,
            K::NotYetValid,
            K::Revoked,
            K::TokenMismatch,
            K::DoorExpired,
            K::WrongDoor,
            K::WrongDirectory,
            K::StaleTimestamp,
            K::Superseded,
            K::Busy,
            K::Replay,
            K::KeyPackageReused,
            K::CredentialMismatch,
            K::KeyLength,
            K::Authentication,
            K::WelcomeMismatch,
            K::Unauthorized,
            K::NotPermitted,
            K::CommitPending,
            K::Other,
        ]
        .into_iter()
        .map(ErrorKind::as_str)
        .collect();
        assert_eq!(names.len(), 24, "kind names are distinct");
    }
}
