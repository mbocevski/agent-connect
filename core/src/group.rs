//! MLS groups: creation, joining, membership changes, policy enforcement and
//! application messages (SPEC §5–§9, §11).

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use openmls::group::{MlsGroup, ProcessedWelcome, QueuedProposal, StagedCommit};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    BasicCredential, ContentType, CredentialWithKey, GroupId, KeyPackage, LeafNodeIndex,
    MlsGroupStateError, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ProcessMessageError, ProcessedMessageContent, Proposal,
    ProtocolMessage, Sender, ValidationError, WireFormat,
};
use openmls_traits::OpenMlsProvider as _;
use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::encoding::{b64, hex};
use crate::error::{Error, Result, mls, storage};
use crate::failpoint::Failpoints;
use crate::identity::Instance;
use crate::invite::{Invite, InviteMeta, InviteSecret};
use crate::join::{JoinRequest, check_display_name, join_request_mac};
use crate::journal::{self, JournalEntry, Journaled, Stored, Tx, WELCOME_SCOPE, keeps_state};
use crate::knock::{KNOCK_FUTURE_SECS, Knock, KnockExpectation, KnockSecret, VerifiedKnock};
use crate::ledger::{LEDGER_GRACE_SECS, ReplayLedger, remember_once};
use crate::mls::{
    CS, GroupContextInfo, InstanceSigner, LeafInfo, MAX_PAST_EPOCHS, capabilities,
    check_group_context, check_group_info_extensions, check_tree_keys, check_welcome_kem_outputs,
    group_context_extensions, guard, instance_cert_bytes, join_config, join_config_with_padding,
    leaf_extensions, leaf_mailbox, validate_key_package, validate_leaf,
};
use crate::padding::bucket_for;
use crate::policy::{
    CommitFacts, Floor, GroupMeta, GroupPolicy, OWNER_MUST_TRANSFER, Removal, authorize,
};
use crate::provider::{Provider, Store};
use crate::records::{self, OwnCommits, PendingRecord, PreviousMembers, wire_hash};
use crate::rng::Rng;
use crate::sas::{self, Participant, Sas, SasNonce};

/// Why an instance whose own leave is pending may not commit: the commit
/// would carry its own removal.
pub(crate) const OWN_LEAVE_PENDING: &str = "this instance's own leave is pending";
/// A JoinRequest from a mailbox other than the one it names (SPEC §6.2 step 3).
pub(crate) const SENDER_MISMATCH: &str = "sender is not the request's mailbox_id";

/// One instance's MLS state: storage, randomness, its signing key and a
/// clock. Groups are loaded from and written through to its store.
pub struct Client<S: Store> {
    provider: Provider<S>,
    instance: Instance,
    clock: Arc<dyn Clock>,
    failpoints: Failpoints,
}

impl<S: Store> fmt::Debug for Client<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

/// A member instance, as seen in the group's ratchet tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberInfo {
    /// MLS leaf index.
    pub leaf_index: u32,
    /// `ac:v0:…` identity.
    pub identity: String,
    /// Instance id from the instance certificate.
    pub instance_id: u64,
    /// Relay mailbox id derived from the leaf signature key.
    pub mailbox_id: String,
}

impl MemberInfo {
    fn from_leaf(leaf_index: u32, info: &LeafInfo) -> Self {
        Self {
            leaf_index,
            identity: info.identity.clone(),
            instance_id: info.instance_id,
            mailbox_id: leaf_mailbox(info),
        }
    }

    /// The instance id as 16 lowercase hex characters, as in inner messages.
    #[must_use]
    pub fn instance_id_hex(&self) -> String {
        hex(&self.instance_id.to_be_bytes())
    }
}

/// Relay fan-out hints for a commit (SPEC §7.1 `routing`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Routing {
    /// Mailboxes added by the commit.
    pub add: Vec<String>,
    /// Mailboxes removed by the commit.
    pub remove: Vec<String>,
}

/// A commit created by this instance. It stays **pending** until the relay
/// confirms it (SPEC §8.3): call [`Group::confirm_pending_commit`] with the
/// `msg_id` of the relay's `accepted` frame, or let [`Group::process`]
/// confirm it when the fan-out delivers these exact bytes back. Call
/// [`Group::discard_pending_commit`] only when the relay rejected the send
/// (`epoch_conflict` or another error frame for this `msg_id`); after a
/// timeout, resend the same bytes under the same `msg_id` instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitOut {
    /// The serialised MLS commit (`kind: commit`).
    pub commit: Vec<u8>,
    /// The envelope `msg_id` to send the commit under (base64url of 16
    /// random bytes). Only an `accepted` for this id confirms the commit.
    pub msg_id: String,
    /// The epoch the commit was built in (`env.epoch`).
    pub epoch: u64,
    /// Routing hints for the envelope.
    pub routing: Routing,
    /// The `WrappedWelcome` for an added member. Send it only after the
    /// commit is confirmed: a Welcome for a rejected commit is useless.
    pub welcome: Option<Vec<u8>>,
}

/// What a merged commit changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSummary {
    /// The new epoch.
    pub epoch: u64,
    /// Who committed.
    pub committer: MemberInfo,
    /// Added instances.
    pub added: Vec<MemberInfo>,
    /// Removed instances.
    pub removed: Vec<MemberInfo>,
    /// The removed instances that left: the commit carried their own leave
    /// proposals (SPEC §9.2). The rest of `removed` were removed by the
    /// committer. Empty in summaries journalled before it existed.
    #[serde(default)]
    pub left: Vec<MemberInfo>,
    /// Whether `ac_group_policy` changed.
    pub policy_changed: bool,
    /// The policy before the commit, when `policy_changed`.
    #[serde(default)]
    pub previous_policy: Option<GroupPolicy>,
    /// The policy the commit ended with, when `policy_changed`. With
    /// `previous_policy` it gives role changes from the summary alone, the
    /// same on a journal replay as the first time (ADR-004). A summary
    /// journalled before these fields existed reads back with
    /// `policy_changed` true and both `None`: the change happened, but
    /// what it was isn't known.
    #[serde(default)]
    pub policy: Option<GroupPolicy>,
    /// Whether this commit (another member's, at the epoch of this
    /// instance's own pending commit) won the epoch: the pending commit was
    /// discarded and should be rebuilt if still needed (SPEC §8.3).
    pub discarded_own_pending: bool,
}

impl CommitSummary {
    /// The routing hints this commit should have carried, to compare with
    /// the envelope's `routing` (SPEC §7.1, `relay_misbehaviour`).
    #[must_use]
    pub fn routing(&self) -> Routing {
        Routing {
            add: self.added.iter().map(|m| m.mailbox_id.clone()).collect(),
            remove: self.removed.iter().map(|m| m.mailbox_id.clone()).collect(),
        }
    }
}

/// A decrypted application message.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationMessage {
    /// The sending instance, authenticated by MLS.
    pub sender: MemberInfo,
    /// The epoch it was sent in.
    pub epoch: u64,
    /// The inner message (SPEC §7.2), UTF-8 JSON.
    #[serde(with = "crate::encoding::b64_serde")]
    pub plaintext: Vec<u8>,
}

impl fmt::Debug for ApplicationMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print message bodies (AGENTS.md).
        f.debug_struct("ApplicationMessage")
            .field("sender", &self.sender)
            .field("epoch", &self.epoch)
            .field("len", &self.plaintext.len())
            .finish()
    }
}

/// The outcome of processing one message from the relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Event {
    /// An application message.
    Application(ApplicationMessage),
    /// Another member's commit, checked against the policy and merged.
    Commit(CommitSummary),
    /// This instance's pending commit came back from the relay byte for
    /// byte and is merged.
    OwnCommitConfirmed(CommitSummary),
    /// A commit removed this instance. The group is now inactive; delete it.
    Removed(CommitSummary),
    /// A member proposed its own removal (a leave). The proposal is stored;
    /// some other member should commit it with
    /// [`Group::commit_pending_proposals`].
    LeaveProposed(MemberInfo),
    /// One of this instance's own messages from an earlier epoch (e.g. a
    /// commit already confirmed by `accepted`), with nothing to do.
    OwnEcho,
}

impl Event {
    /// The variant name, for logs and error messages. Unlike `Debug`, it
    /// carries no message content at all.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Event::Application(_) => "application",
            Event::Commit(_) => "commit",
            Event::OwnCommitConfirmed(_) => "own_commit_confirmed",
            Event::Removed(_) => "removed",
            Event::LeaveProposed(_) => "leave_proposed",
            Event::OwnEcho => "own_echo",
        }
    }
}

/// A JoinRequest that passed every check of SPEC §6.2 steps 1–3.
#[derive(Debug)]
pub struct VerifiedJoinRequest {
    invite_id: [u8; 16],
    display_name: String,
    mailbox_id: String,
    key_package: KeyPackage,
    key_package_ref: Vec<u8>,
    forget_after: u64,
    info: LeafInfo,
}

impl VerifiedJoinRequest {
    /// The `KeyPackageRef` (RFC 9420 §5.2) of the joiner's KeyPackage: the
    /// same request replayed under another `msg_id` has the same ref.
    #[must_use]
    pub fn key_package_ref(&self) -> &[u8] {
        &self.key_package_ref
    }

    /// The joiner's identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.info.identity
    }

    /// The joiner's instance id.
    #[must_use]
    pub fn instance_id(&self) -> u64 {
        self.info.instance_id
    }

    /// The (unauthenticated) display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The joiner's mailbox, where the wrapped Welcome goes.
    #[must_use]
    pub fn mailbox_id(&self) -> &str {
        &self.mailbox_id
    }

    /// Until when the inviter must remember this request: its invite's
    /// `expires_at` plus [`LEDGER_GRACE_SECS`]. The approval timeout
    /// (SPEC §6.2 step 4) runs from receipt, so a replay would restart it;
    /// the invite's expiry is the one deadline no copy can pass.
    #[must_use]
    pub fn forget_after(&self) -> u64 {
        self.forget_after
    }

    /// SPEC §6.2, "Replays": if `ledger` has seen `request_id` (the id
    /// of the approval this request would wait in) or this request's
    /// `KeyPackageRef`, the request is a replay; otherwise both are
    /// recorded until [`VerifiedJoinRequest::forget_after`]. Call it for
    /// every request that passed steps 1–3, before anything else happens to
    /// it (held for the human, approved, rejected, dropped, lapsed), so a
    /// request the human rejected can't be put in front of them again.
    ///
    /// # Errors
    ///
    /// [`Error::Replayed`] (kind `replay`): drop it silently.
    /// [`Error::LedgerFull`] (kind `busy`): drop it too. A ledger error.
    pub fn remember_in(&self, ledger: &mut impl ReplayLedger, request_id: &[u8]) -> Result<()> {
        remember_once(ledger, request_id, &self.key_package_ref, self.forget_after)
    }
}

impl<S: Store> Client<S> {
    /// A client for `instance` over `store`.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the crypto provider can't be seeded.
    pub fn new(store: S, rng: Rng, instance: Instance, clock: Arc<dyn Clock>) -> Result<Self> {
        Ok(Self {
            provider: Provider::new(store, rng)?,
            instance,
            clock,
            failpoints: Failpoints::default(),
        })
    }

    /// This client's failpoints. **Tests only** (see [`crate::failpoint`]).
    #[doc(hidden)]
    #[must_use]
    pub fn failpoints(&self) -> &Failpoints {
        &self.failpoints
    }

    fn fail(&self, point: &'static str) -> Result<()> {
        self.failpoints.hit(point)
    }

    fn store(&self) -> &S {
        self.provider.records()
    }

    /// Every journal entry not consumed yet, oldest first (ADR-004): the
    /// results a caller may not have recorded before a crash. Each must be
    /// finished and then consumed with [`Client::journal_consume`].
    ///
    /// # Errors
    ///
    /// [`Error::Storage`].
    pub fn journal_pending(&self) -> Result<Vec<JournalEntry>> {
        self.store()
            .journal_pending()?
            .into_iter()
            .map(journal::entry)
            .collect()
    }

    /// Consumes a journal entry once the caller has durably recorded its
    /// result: the result (plaintext) and context are deleted, the key and
    /// hash stay so a redelivery fails with [`Error::Duplicate`]. `group_id`
    /// is `None` for a Welcome entry. Returns whether the entry exists.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`].
    pub fn journal_consume(&self, group_id: Option<&[u8]>, key: &str) -> Result<bool> {
        let scope = group_id.unwrap_or(WELCOME_SCOPE);
        let tx = Tx::begin(self.store())?;
        let Some(mut row) = self.store().journal_get(scope, key)? else {
            return Ok(false);
        };
        if row.result.is_some() {
            row.result = None;
            row.context = None;
            self.store().journal_put(&row)?;
        }
        self.fail("consume.before_commit")?;
        tx.commit()?;
        Ok(true)
    }

    /// Deletes consumed entries older than `before` (Unix seconds), e.g.
    /// the relay's message TTL ago, after which no redelivery can come.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`].
    pub fn journal_purge(&self, before: u64) -> Result<u64> {
        self.store().journal_purge(before)
    }

    /// This client's instance.
    #[must_use]
    pub fn instance(&self) -> &Instance {
        &self.instance
    }

    /// This client's randomness source.
    #[must_use]
    pub fn rng(&self) -> &Rng {
        self.provider.rng()
    }

    /// This client's clock.
    #[must_use]
    pub fn clock(&self) -> &dyn Clock {
        &*self.clock
    }

    fn signer(&self) -> InstanceSigner<'_> {
        InstanceSigner(&self.instance)
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.instance.identity().as_bytes().to_vec()).into(),
            signature_key: self.instance.public_key().to_vec().into(),
        }
    }

    fn now(&self) -> u64 {
        self.clock.unix_millis() / 1000
    }

    /// Creates a group with this instance as owner (SPEC §5).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidGroupContext`] for an over-long name or purpose, or
    /// an MLS/storage error.
    pub fn create_group(&self, name: &str, purpose: &str) -> Result<Group> {
        self.create_group_with_policy(
            name,
            purpose,
            &GroupPolicy::default_for(self.instance.identity()),
        )
    }

    /// [`Client::create_group`] with `policy` in force from epoch 0, so no
    /// policy commit (and no new epoch) follows the creation. The policy
    /// must be valid and name this identity as `owner`; it may list roles
    /// for identities that aren't members yet.
    ///
    /// # Errors
    ///
    /// As [`Client::create_group`]; a policy validation error, or
    /// [`Error::NotPermitted`] for another owner.
    pub fn create_group_with_policy(
        &self,
        name: &str,
        purpose: &str,
        policy: &GroupPolicy,
    ) -> Result<Group> {
        policy.validate()?;
        if policy.owner != self.instance.identity() {
            return Err(Error::NotPermitted("the creator must be the owner"));
        }
        let meta = GroupMeta {
            v: 0,
            name: name.to_owned(),
            purpose: purpose.to_owned(),
            created_at: self.now(),
            created_by: self.instance.identity().to_owned(),
        };
        meta.validate()?;
        let extensions = group_context_extensions(&meta.to_json()?, &policy.to_json()?)?;
        let group_id: [u8; 16] = self.rng().array()?;
        let tx = Tx::begin(self.store())?;
        let mls = MlsGroup::builder()
            .with_group_id(GroupId::from_slice(&group_id))
            .ciphersuite(CS)
            .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_PAST_EPOCHS)
            .with_capabilities(capabilities())
            .with_leaf_node_extensions(leaf_extensions(self.instance.cert())?)
            .map_err(mls)?
            .with_group_context_extensions(extensions)
            .build(&self.provider, &self.signer(), self.credential())
            .map_err(mls)?;
        tx.commit()?;
        Ok(Group { mls })
    }

    /// Loads a group from storage.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`].
    pub fn load_group(&self, group_id: &[u8]) -> Result<Option<Group>> {
        Ok(
            MlsGroup::load(self.provider.storage(), &GroupId::from_slice(group_id))
                .map_err(storage)?
                .map(|mls| Group { mls }),
        )
    }

    /// A fresh KeyPackage (TLS bytes) for this instance; its private keys
    /// go to this client's store.
    pub(crate) fn new_key_package(&self) -> Result<Vec<u8>> {
        let tx = Tx::begin(self.store())?;
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .leaf_node_extensions(leaf_extensions(self.instance.cert())?)
            .build(CS, &self.provider, &self.signer(), self.credential())
            .map_err(mls)?;
        tx.commit()?;
        bundle.key_package().tls_serialize_detached().map_err(mls)
    }

    /// SPEC §6.2 step 3 on a peer's KeyPackage, before the MLS group sees
    /// it: everything [`validate_key_package`] checks, the mailbox id is
    /// the one derived from its leaf signature key, and it is unused.
    /// Returns the KeyPackage, its `KeyPackageRef` and the leaf.
    pub(crate) fn check_peer_key_package(
        &self,
        bytes: &[u8],
        mailbox_id: &str,
    ) -> Result<(KeyPackage, Vec<u8>, LeafInfo)> {
        let (key_package, info) = validate_key_package(self.provider.crypto(), bytes)?;
        if leaf_mailbox(&info) != mailbox_id {
            return Err(Error::CredentialMismatch(
                "mailbox_id != key package signature key",
            ));
        }
        let kp_ref = key_package_ref(self, &key_package)?;
        if records::key_package_used(self.provider.records(), &kp_ref)? {
            return Err(Error::KeyPackageReused);
        }
        Ok((key_package, kp_ref, info))
    }

    /// Deletes the private keys of a KeyPackage this instance made, given
    /// its TLS bytes: for a knock that lapsed (SPEC §6.6.6) or any other
    /// KeyPackage that will never be used. Deleting one that isn't stored
    /// is not an error.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`], or an MLS error computing its reference.
    pub fn delete_key_package(&self, key_package: &[u8]) -> Result<()> {
        use openmls_traits::storage::StorageProvider as _;
        let kp_ref = openmls::ciphersuite::hash_ref::make_key_package_ref(
            key_package,
            CS,
            self.provider.crypto(),
        )
        .map_err(mls)?;
        let tx = Tx::begin(self.store())?;
        self.provider
            .storage()
            .delete_key_package(&kp_ref)
            .map_err(storage)?;
        tx.commit()
    }

    /// The memory store, for tests that count what it holds.
    #[cfg(test)]
    pub(crate) fn store_for_testing(&self) -> &S {
        self.store()
    }

    /// Records `kp_ref` as used, as merging an Add of it would. **Tests
    /// only** (a binding's reused-KeyPackage case); it can only refuse more.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`].
    #[doc(hidden)]
    pub fn mark_key_package_used_for_testing(&self, kp_ref: &[u8]) -> Result<()> {
        records::mark_key_packages_used(self.provider.records(), &[kp_ref.to_vec()])
    }

    /// Creates a JoinRequest for an invite (SPEC §6.1). The KeyPackage's
    /// private keys go to this client's store.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a display name that is too long or has control
    /// characters, or an MLS error.
    pub fn create_join_request(
        &self,
        invite: &InviteSecret,
        display_name: &str,
    ) -> Result<JoinRequest> {
        check_display_name(display_name)?;
        let key_package = self.new_key_package()?;
        let mailbox_id = self.instance.mailbox_id();
        let mut request = JoinRequest {
            invite_id: *invite.id(),
            display_name: display_name.to_owned(),
            key_package,
            mailbox_id,
            mac: [0; 32],
        };
        request.mac = join_request_mac(&invite.join_key(), &request.mac_input());
        Ok(request)
    }

    /// Inviter side, SPEC §6.2 steps 1–3: the invite is ours and not
    /// expired, the MAC verifies, the request came from the mailbox it
    /// names, and the KeyPackage passes every check (ciphersuite, HPKE key
    /// lengths, signature, instance certificate, capabilities, mailbox id)
    /// before it reaches the MLS group.
    ///
    /// `sender` is the envelope's relay-authenticated sender. Anyone with
    /// the link can MAC any KeyPackage, so without it a link holder could
    /// present someone else's unused KeyPackage and have that identity
    /// added as a leaf nobody controls.
    ///
    /// Use limits are the daemon's: a failed MAC must not consume a use.
    ///
    /// # Errors
    ///
    /// [`Error::InviteMismatch`], [`Error::InviteExpired`], [`Error::BadMac`],
    /// [`Error::CredentialMismatch`] (another sender, or a mailbox id that
    /// isn't the KeyPackage's), or a KeyPackage validation error.
    pub fn verify_join_request(
        &self,
        request: &JoinRequest,
        invite: &Invite,
        sender: &str,
    ) -> Result<VerifiedJoinRequest> {
        if request.invite_id != *invite.secret().id() {
            return Err(Error::InviteMismatch);
        }
        if invite.is_expired(self.clock()) {
            return Err(Error::InviteExpired);
        }
        if !request.mac_ok(&invite.secret().join_key()) {
            return Err(Error::BadMac);
        }
        if request.mailbox_id != sender {
            return Err(Error::CredentialMismatch(SENDER_MISMATCH));
        }
        let (key_package, kp_ref, info) =
            self.check_peer_key_package(&request.key_package, &request.mailbox_id)?;
        Ok(VerifiedJoinRequest {
            invite_id: request.invite_id,
            display_name: request.display_name.clone(),
            mailbox_id: request.mailbox_id.clone(),
            key_package,
            key_package_ref: kp_ref,
            forget_after: invite.expires_at().saturating_add(LEDGER_GRACE_SECS),
            info,
        })
    }

    /// Joiner side, SPEC §6.3: unwrap with `welcome_key`, check the
    /// ciphersuite and the KEM ciphertext lengths before OpenMLS touches the
    /// Welcome, allow no `GroupInfo` extension but `ratchet_tree`, check
    /// every HPKE key before MLS processes the tree, check that the policy
    /// is well-formed and in range, check
    /// that `ac_group_meta` matches the `InviteMeta` shown to the human, and
    /// verify every leaf's instance certificate. On any failure after MLS
    /// has started, the KeyPackage is spent and no group is kept.
    ///
    /// The caller deletes the invite secret after success (dropping the
    /// [`InviteSecret`] zeroizes it).
    ///
    /// # Errors
    ///
    /// [`Error::WelcomeAuth`], [`Error::WrongCiphersuite`],
    /// [`Error::KemOutputLength`], [`Error::HpkeKeyLength`],
    /// [`Error::InvalidGroupContext`], [`Error::MetaMismatch`], certificate
    /// errors, or an MLS error.
    pub fn join_from_wrapped_welcome(
        &self,
        invite: &InviteSecret,
        expected: &InviteMeta,
        wrapped: &[u8],
    ) -> Result<Group> {
        self.join_tx(&Joining::Invite { invite, expected }, wrapped, None)
            .map(|j| j.value)
    }

    /// [`Client::join_from_wrapped_welcome`], journalled under `key` (e.g.
    /// the invite id) with the caller's `context` (ADR-004). Joining again
    /// with the same key and Welcome before the entry is consumed returns
    /// the joined group with `replayed` set instead of failing on the spent
    /// KeyPackage.
    ///
    /// # Errors
    ///
    /// As [`Client::join_from_wrapped_welcome`]; [`Error::Duplicate`] if
    /// the entry was consumed, [`Error::JournalConflict`] for another
    /// Welcome under the same key.
    pub fn join_journaled(
        &self,
        invite: &InviteSecret,
        expected: &InviteMeta,
        wrapped: &[u8],
        key: &str,
        context: &[u8],
    ) -> Result<Journaled<Group>> {
        self.join_tx(
            &Joining::Invite { invite, expected },
            wrapped,
            Some((key, context)),
        )
    }

    /// Knocker side, SPEC §6.6.5: joins the group an approved knock created
    /// from its wrapped Welcome. Every check of §6.3 runs except the
    /// comparison with an `InviteMeta`, which these replace:
    ///
    /// - the Welcome unwraps under the knock's `welcome_key`;
    /// - `ac_group_meta.name` is `expected.name`;
    /// - `ac_group_meta.created_by` and `ac_group_policy.owner` are both
    ///   `expected.identity`, which is not this instance's own identity;
    /// - the group has exactly two leaves: this instance's own, and one of
    ///   `expected.identity` whose instance certificate verifies.
    ///
    /// The knocker stops waiting at [`Knock::gives_up_at`] (SPEC §6.6.6),
    /// on this client's clock: after it, a Welcome is refused before the
    /// unwrap. A failure after the unwrap spends the KeyPackage and keeps no
    /// group (SPEC §6.3), so the knock is over; [`Error::KnockWelcome`] (kind
    /// `welcome_mismatch`) should raise `relay_misbehaviour`. The caller
    /// deletes its stored knock after success (dropping the [`Knock`]
    /// zeroizes the `welcome_secret`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKnock`] `"lapsed"` (kind `expired`) after
    /// `gives_up_at`, [`Error::WelcomeAuth`] if it doesn't unwrap under this
    /// knock (try the next pending one), [`Error::NotPermitted`] if
    /// `expected` names this
    /// identity, [`Error::KnockWelcome`], or any error of
    /// [`Client::join_from_wrapped_welcome`] but [`Error::MetaMismatch`].
    pub fn join_from_knock_welcome(
        &self,
        knock: &Knock,
        expected: &KnockExpectation,
        wrapped: &[u8],
    ) -> Result<Group> {
        self.join_tx(
            &Joining::Knock {
                secret: knock.secret(),
                expected,
                gives_up_at: knock.gives_up_at(),
            },
            wrapped,
            None,
        )
        .map(|j| j.value)
    }

    /// [`Client::join_from_knock_welcome`], journalled under `key` with the
    /// caller's `context` (ADR-004), as [`Client::join_journaled`] is.
    ///
    /// # Errors
    ///
    /// As [`Client::join_from_knock_welcome`]; [`Error::Duplicate`] if the
    /// entry was consumed, [`Error::JournalConflict`] for another Welcome
    /// under the same key.
    pub fn join_knock_journaled(
        &self,
        knock: &Knock,
        expected: &KnockExpectation,
        wrapped: &[u8],
        key: &str,
        context: &[u8],
    ) -> Result<Journaled<Group>> {
        self.join_tx(
            &Joining::Knock {
                secret: knock.secret(),
                expected,
                gives_up_at: knock.gives_up_at(),
            },
            wrapped,
            Some((key, context)),
        )
    }

    fn join_tx(
        &self,
        joining: &Joining<'_>,
        wrapped: &[u8],
        journal_as: Option<(&str, &[u8])>,
    ) -> Result<Journaled<Group>> {
        let hash = joining.journal_hash(wrapped);
        if let Some((key, _)) = journal_as
            && let Some((row, _)) = journal::lookup(self.store(), WELCOME_SCOPE, key, Some(&hash))?
        {
            let group = self
                .load_group(&row.group_id)?
                .ok_or(Error::Internal("journalled group missing"))?;
            if let Joining::Knock { expected, .. } = joining {
                group.check_knock_replay(expected)?;
            }
            return Ok(Journaled {
                value: group,
                replayed: true,
            });
        }
        let tx = Tx::begin(self.store())?;
        match self.join_inner(joining, wrapped) {
            Ok(group) => {
                if let Some((key, context)) = journal_as {
                    journal::record(
                        self.store(),
                        WELCOME_SCOPE,
                        group.group_id(),
                        key,
                        &hash,
                        context,
                        &Stored::Joined,
                        self.now(),
                    )?;
                }
                self.fail("join.before_commit")?;
                tx.commit()?;
                Ok(Journaled {
                    value: group,
                    replayed: false,
                })
            }
            Err(e) => {
                // SPEC §6.3: a failed Welcome consumes the KeyPackage, so
                // keep what OpenMLS did (unless the store itself failed).
                if keeps_state(&e) {
                    tx.commit()?;
                }
                Err(e)
            }
        }
    }

    fn join_inner(&self, joining: &Joining<'_>, wrapped: &[u8]) -> Result<Group> {
        let welcome_bytes = match joining {
            Joining::Invite { invite, expected } => {
                if expected.invite_id != invite.id_b64() {
                    return Err(Error::InviteMismatch);
                }
                invite.unwrap_welcome(wrapped)?
            }
            Joining::Knock {
                secret,
                expected,
                gives_up_at,
            } => {
                if self.now() > *gives_up_at {
                    return Err(Error::InvalidKnock("lapsed"));
                }
                if expected.identity == self.instance.identity() {
                    return Err(Error::NotPermitted(
                        "a knock on this identity's own listing",
                    ));
                }
                secret.unwrap_welcome(wrapped)?
            }
        };
        let msg = MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice())
            .map_err(|_| Error::Malformed("welcome"))?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(Error::UnexpectedMessage("not a Welcome"));
        };
        if welcome.ciphersuite() != CS {
            return Err(Error::WrongCiphersuite);
        }
        // The only KEM ciphertexts outside the encryption: check them before
        // OpenMLS decapsulates ours (SPEC §3.1).
        check_welcome_kem_outputs(
            welcome
                .secrets()
                .iter()
                .filter_map(|s| s.tls_serialize_detached().ok()),
        )?;
        guard(|| {
            let processed =
                ProcessedWelcome::new_from_welcome(&self.provider, &join_config(), welcome)
                    .map_err(mls)?;
            if !processed.psks().is_empty() {
                return Err(Error::InvalidGroupContext("PSKs are not used in v0"));
            }
            let group_info_exts = processed.unverified_group_info().extensions();
            check_group_info_extensions(group_info_exts)?;
            let tree = group_info_exts
                .ratchet_tree()
                .ok_or(Error::InvalidGroupContext("missing ratchet tree"))?
                .ratchet_tree()
                .clone();
            check_tree_keys(
                tree.leaves()
                    .filter_map(|l| l.tls_serialize_detached().ok()),
                tree.parents()
                    .filter_map(|p| p.tls_serialize_detached().ok()),
            )?;
            let staged = processed
                .into_staged_welcome(&self.provider, None)
                .map_err(mls)?;
            if staged.group_context().ciphersuite() != CS {
                return Err(Error::WrongCiphersuite);
            }
            let ctx = check_group_context(staged.group_context().extensions())?;
            joining.check_context(&ctx, staged.group_context().epoch().as_u64())?;
            let mut group = Group {
                mls: staged.into_group(&self.provider).map_err(mls)?,
            };
            self.fail("join.after_stage")?;
            let checked = group.check_all_leaves(&ctx.policy).and_then(|()| {
                if let Joining::Knock { expected, .. } = joining {
                    group.check_knock_members(self.instance.identity(), &expected.identity)
                } else {
                    Ok(())
                }
            });
            if let Err(e) = checked {
                delete_mls_group(self, &mut group.mls)?;
                return Err(e);
            }
            Ok(group)
        })
    }
}

/// What a Welcome is joined under and checked against.
enum Joining<'a> {
    /// An invite (SPEC §6.3): the `InviteMeta` shown to the human.
    Invite {
        invite: &'a InviteSecret,
        expected: &'a InviteMeta,
    },
    /// An approved knock (SPEC §6.6.5): the listing knocked on, and when
    /// the knocker stops waiting.
    Knock {
        secret: KnockSecret,
        expected: &'a KnockExpectation,
        gives_up_at: u64,
    },
}

impl Joining<'_> {
    /// The journal hash of a Welcome joined this way. A knock join binds the
    /// knock and the listing it expects, under its own label, so an entry
    /// replays only for the same knock and listing, and never for an invite
    /// join (whose hash is the Welcome's alone).
    fn journal_hash(&self, wrapped: &[u8]) -> String {
        match self {
            Self::Invite { .. } => wire_hash(wrapped),
            Self::Knock {
                secret, expected, ..
            } => {
                let mut input = b"agentconnect/v0/journal/knock-welcome".to_vec();
                for part in [
                    secret.knock_id().as_slice(),
                    expected.identity.as_bytes(),
                    expected.name.as_bytes(),
                    wrapped,
                ] {
                    input.extend_from_slice(
                        &u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes(),
                    );
                    input.extend_from_slice(part);
                }
                wire_hash(&input)
            }
        }
    }

    /// The group-context checks: the `InviteMeta` comparison, or the knock
    /// checks that replace it. `epoch` is the Welcome's.
    fn check_context(&self, ctx: &GroupContextInfo, epoch: u64) -> Result<()> {
        match self {
            Self::Invite { expected, .. } => {
                if ctx.meta.name != expected.group_name || ctx.meta.purpose != expected.purpose {
                    return Err(Error::MetaMismatch);
                }
            }
            Self::Knock { expected, .. } => {
                if ctx.meta.name != expected.name {
                    return Err(Error::KnockWelcome("name"));
                }
                if ctx.meta.created_by != expected.identity {
                    return Err(Error::KnockWelcome("created_by"));
                }
                if ctx.policy.owner != expected.identity {
                    return Err(Error::KnockWelcome("owner"));
                }
                // The group add_knocker builds: the owner's fresh group,
                // whose one commit added this instance.
                if epoch != 1 {
                    return Err(Error::KnockWelcome("not a fresh group"));
                }
                if ctx.policy.floor != Floor::Free {
                    return Err(Error::KnockWelcome("the floor is not free"));
                }
                if ctx.policy.floor_pinned {
                    return Err(Error::KnockWelcome("the floor is pinned"));
                }
                if !roles_only_for(&ctx.policy, &expected.identity) {
                    return Err(Error::KnockWelcome("roles for another identity"));
                }
            }
        }
        Ok(())
    }
}

/// The leaves of a group, as `(identity, instance_id)`, name each instance
/// once (SPEC §9.4): a second leaf repeating an instance of its identity,
/// which anyone holding that identity's `IK` can certify, would take over
/// what that instance id means (routing hints, `--instance` removal, the
/// instances shown as new).
const REPEATED_INSTANCE: &str = "an instance id repeated within its identity";

/// A leaf's instance certificate may not change in an update (SPEC §9.2).
const FIXED_CERT: &str = "an update changed the leaf's instance certificate";

/// Checks that the leaves after a commit name each instance once: the
/// members but the `removed` leaves, the committer's leaf as its update
/// path left it (`updated`), and the `added` ones.
fn check_unique_instances(
    members: &[MemberInfo],
    removed: &BTreeSet<u32>,
    updated: Option<&(u32, LeafInfo)>,
    added: &[LeafInfo],
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let leaves = members
        .iter()
        .filter(|m| !removed.contains(&m.leaf_index))
        .map(|m| match updated {
            Some((leaf, info)) if *leaf == m.leaf_index => {
                (info.identity.as_str(), info.instance_id)
            }
            _ => (m.identity.as_str(), m.instance_id),
        })
        .chain(added.iter().map(|a| (a.identity.as_str(), a.instance_id)));
    for leaf in leaves {
        if !seen.insert(leaf) {
            return Err(Error::Unauthorized(REPEATED_INSTANCE));
        }
    }
    Ok(())
}

/// Whether a SAS run naming `epoch` may derive its code in a group at
/// epoch `current` (SPEC 11.4): only the current epoch, and only one that
/// an I-JSON integer can name (no group gets past 2^53 - 1 one commit at a
/// time, but a Welcome can start a group at any epoch).
fn sas_epoch_ok(epoch: u64, current: u64) -> bool {
    epoch == current && epoch <= sas::MAX_EPOCH
}

/// Whether every admin and the floor moderator of `policy` is `owner`.
fn roles_only_for(policy: &GroupPolicy, owner: &str) -> bool {
    policy.admins.iter().all(|a| a == owner)
        && policy.floor_moderator.as_deref().is_none_or(|m| m == owner)
}

/// How a commit's Welcome is wrapped (SPEC §6.4).
enum WelcomeWrap<'a> {
    /// Under the invite's `welcome_key` (SPEC §6.2 step 6).
    Invite(&'a Invite),
    /// Under the knock's `welcome_key` (SPEC §6.6.4 step 4).
    Knock(KnockSecret),
}

impl WelcomeWrap<'_> {
    fn wrap(&self, rng: &Rng, welcome: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Invite(invite) => invite.secret().wrap_welcome(rng, welcome),
            Self::Knock(secret) => secret.wrap_welcome(rng, welcome),
        }
    }
}

/// An MLS group (one conversation).
pub struct Group {
    mls: MlsGroup,
}

impl fmt::Debug for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Group")
            .field("group_id", &hex(self.group_id()))
            .field("epoch", &self.epoch())
            .finish_non_exhaustive()
    }
}

/// Per-commit facts gathered before merging.
struct Inspection {
    committer: MemberInfo,
    added: Vec<LeafInfo>,
    /// `KeyPackageRef`s of the added KeyPackages.
    added_refs: Vec<Vec<u8>>,
    removed: Vec<MemberInfo>,
    /// The removals proposed by the removed leaf itself.
    left: Vec<MemberInfo>,
    /// The policy before and after, if the commit changes it.
    policy_change: Option<(GroupPolicy, GroupPolicy)>,
}

#[derive(Deserialize)]
struct InnerHead {
    v: u32,
    sender: String,
    instance_id: String,
}

/// SPEC §7.2: `sender` and `instance_id` must match the MLS sender.
fn check_inner(bytes: &[u8], sender: &MemberInfo) -> Result<()> {
    let head: InnerHead =
        serde_json::from_slice(bytes).map_err(|_| Error::Malformed("inner message"))?;
    if head.v != 0 {
        return Err(Error::UnsupportedVersion);
    }
    if head.sender != sender.identity {
        return Err(Error::CredentialMismatch("inner sender != MLS sender"));
    }
    if head.instance_id != sender.instance_id_hex() {
        return Err(Error::CredentialMismatch("inner instance_id != MLS sender"));
    }
    Ok(())
}

fn process_error<E: fmt::Display>(e: ProcessMessageError<E>) -> Error {
    match e {
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch) => Error::WrongEpoch,
        ProcessMessageError::GroupStateError(MlsGroupStateError::UseAfterEviction) => {
            Error::NotMember
        }
        e => mls(e),
    }
}

fn key_package_ref<S: Store>(client: &Client<S>, kp: &KeyPackage) -> Result<Vec<u8>> {
    Ok(kp
        .hash_ref(client.provider.crypto())
        .map_err(mls)?
        .as_slice()
        .to_vec())
}

fn wire(msg: &MlsMessageOut) -> Result<Vec<u8>> {
    msg.tls_serialize_detached().map_err(mls)
}

fn parse_protocol(bytes: &[u8]) -> Result<ProtocolMessage> {
    let msg =
        MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| Error::Malformed("MLS message"))?;
    if msg.wire_format() != WireFormat::PrivateMessage {
        return Err(Error::UnexpectedMessage("only PrivateMessage is accepted"));
    }
    msg.try_into_protocol_message()
        .map_err(|_| Error::UnexpectedMessage("not a protocol message"))
}

/// The content type in a `PrivateMessage` header, named like the envelope
/// `kind` that must match it (SPEC §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    /// An application message.
    Application,
    /// A proposal.
    Proposal,
    /// A commit.
    Commit,
}

impl MessageKind {
    /// `"application"`, `"proposal"` or `"commit"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Proposal => "proposal",
            Self::Commit => "commit",
        }
    }
}

/// The unprotected header of a `PrivateMessage` (RFC 9420 §6.3).
///
/// Nothing in it is authenticated by itself: it is what the sender (or
/// whoever altered the bytes) put there. Processing then authenticates it,
/// because the AEAD binds the header as associated data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    /// The `group_id` field.
    pub group_id: Vec<u8>,
    /// The `epoch` field.
    pub epoch: u64,
    /// The `content_type` field.
    pub content_type: MessageKind,
}

/// Parses only the unprotected header of an MLS message, so a receiver can
/// compare the relay's envelope with it before processing (SPEC §7.1).
///
/// The input is validated exactly as [`Group::process`] does before it
/// touches any state: one TLS-encoded `MLSMessage` with nothing after it,
/// whose wire format is `PrivateMessage`. No key material is used and no
/// storage is read or written, so peeking consumes nothing: the same bytes
/// still process afterwards.
///
/// # Errors
///
/// [`Error::Malformed`] for bytes that are not one MLS message, and
/// [`Error::UnexpectedMessage`] for any other wire format.
pub fn peek_header(bytes: &[u8]) -> Result<MessageHeader> {
    let msg = parse_protocol(bytes)?;
    let content_type = match msg.content_type() {
        ContentType::Application => MessageKind::Application,
        ContentType::Proposal => MessageKind::Proposal,
        ContentType::Commit => MessageKind::Commit,
    };
    Ok(MessageHeader {
        group_id: msg.group_id().as_slice().to_vec(),
        epoch: msg.epoch().as_u64(),
        content_type,
    })
}

/// The identities of `members` (the group before a commit), and those that
/// keep an instance the commit doesn't remove (`removed` leaves).
fn identities_kept(
    members: &[MemberInfo],
    removed: &BTreeSet<u32>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let before = members.iter().map(|m| m.identity.clone()).collect();
    let kept = members
        .iter()
        .filter(|m| !removed.contains(&m.leaf_index))
        .map(|m| m.identity.clone())
        .collect();
    (before, kept)
}

/// Whether `q` is the leave (own Remove proposal) of `leaf`.
fn is_leave_of(q: &QueuedProposal, leaf: u32) -> bool {
    matches!(
        (q.proposal(), q.sender()),
        (Proposal::Remove(r), Sender::Member(s)) if r.removed() == *s && s.u32() == leaf
    )
}

/// Builds, stages and checks a commit; `$build` maps the commit builder.
/// The commit carries every stored proposal (the pending leaves) but the
/// owner leave [`Group::kept_owner_leaf`] leaves out.
macro_rules! commit {
    ($self:ident, $client:ident, $wrap:expr, |$b:ident| $build:expr) => {{
        $self.ready()?;
        let kept = $self.leaves_for_commit()?;
        $self.handshake_padding($client)?;
        let signer = $client.signer();
        let $b = $self.mls.commit_builder();
        let bundle = $build
            .load_psks($client.provider.storage())
            .map_err(mls)?
            .build(
                $client.provider.rand(),
                $client.provider.crypto(),
                &signer,
                |q| !kept.is_some_and(|leaf| is_leave_of(q, leaf)),
            )
            .map_err(mls)?
            .stage_commit(&$client.provider)
            .map_err(mls)?;
        $self.finish_commit($client, &bundle, $wrap)
    }};
}

impl Group {
    /// Commits `Add` for a verified joiner and wraps the Welcome
    /// (SPEC §6.2 steps 4–6). With `switch_floor`, a group growing past two
    /// identities also moves from `free` to `mention` in the same commit
    /// (SPEC §9.1), unless its policy has `floor_pinned`. Another instance
    /// of an identity already in the group never switches it.
    ///
    /// The request is only borrowed: after a failure (e.g. another commit
    /// pending, or an `epoch_conflict` that discarded this one) the inviter
    /// can retry with the same verified request.
    ///
    /// # Errors
    ///
    /// [`Error::InviteMismatch`], [`Error::InviteExpired`],
    /// [`Error::KeyPackageReused`], [`Error::NotPermitted`],
    /// [`Error::CommitPending`], or an MLS error.
    pub fn add_member<S: Store>(
        &mut self,
        client: &Client<S>,
        request: &VerifiedJoinRequest,
        invite: &Invite,
        switch_floor: bool,
    ) -> Result<CommitOut> {
        self.atomically(client, |g| {
            g.add_member_inner(client, request, invite, switch_floor)
        })
    }

    /// SPEC §6.6.4 steps 3–4: commits `Add` of an approved knock's
    /// KeyPackage and wraps the Welcome under the knock's `welcome_key`,
    /// with `aad = "agentconnect/v0/knock-welcome" ‖ knock_id`. The group
    /// must be a fresh one of this instance's own: one leaf, created and
    /// owned by this identity, floor `free` and not pinned, epoch 0 (the caller creates it
    /// with [`Client::create_group`] under the listing's name).
    ///
    /// Only a human approves a knock (SPEC §6.6.4); this is the step after.
    /// The deadline is checked on this client's clock: the approval lapses
    /// at [`Knock::lapses_at`], and no Add is committed after it, nor for a
    /// knock whose `ts` is further ahead of the clock than check 3 allows.
    /// Atomic, and the knock is only borrowed, as for [`Group::add_member`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKnock`] `"lapsed"` (kind `expired`) or `"ts out of
    /// range"` (kind `stale_timestamp`),
    /// [`Error::KeyPackageReused`], [`Error::NotPermitted`] for a knock
    /// from this instance's own identity or a group that isn't fresh,
    /// [`Error::CommitPending`], or an MLS error.
    pub fn add_knocker<S: Store>(
        &mut self,
        client: &Client<S>,
        knock: &VerifiedKnock,
    ) -> Result<CommitOut> {
        self.atomically(client, |g| g.add_knocker_inner(client, knock))
    }

    /// Commits the removal of every instance of `identity` (SPEC §9.2:
    /// removing an identity removes all its instances). Removing one's own
    /// identity removes this identity's *other* instances.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownMember`], [`Error::NotPermitted`],
    /// [`Error::CommitPending`], or an MLS error.
    pub fn remove<S: Store>(&mut self, client: &Client<S>, identity: &str) -> Result<CommitOut> {
        self.atomically(client, |g| g.remove_inner(client, identity))
    }

    /// Commits the removal of the instances at `leaves` (leaf indices,
    /// duplicates ignored), for example a dead replica (SPEC §9.2). Removing
    /// only one's own other instances needs no permission. Any other
    /// identity's instance needs `remove`, and the owner's need the owner.
    /// This instance's own leaf can't be removed: it proposes a leave.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownMember`] for no leaves or a leaf with no member,
    /// [`Error::NotPermitted`], [`Error::CommitPending`], or an MLS error.
    pub fn remove_instances<S: Store>(
        &mut self,
        client: &Client<S>,
        leaves: &[u32],
    ) -> Result<CommitOut> {
        self.atomically(client, |g| g.remove_instances_inner(client, leaves))
    }

    /// Commits an Update of this instance's leaf (fresh HPKE keys; SPEC §3.1
    /// update cadence).
    ///
    /// # Errors
    ///
    /// [`Error::CommitPending`] or an MLS error.
    pub fn update<S: Store>(&mut self, client: &Client<S>) -> Result<CommitOut> {
        self.atomically(client, |g| g.update_inner(client))
    }

    /// Commits a policy change. The GroupContextExtensions proposal carries
    /// the full set: the unchanged `ac_group_meta` and
    /// `RequiredCapabilities` plus the new policy (SPEC §9.2).
    ///
    /// # Errors
    ///
    /// Policy validation errors, [`Error::Unauthorized`] if this instance's
    /// role doesn't allow the change, [`Error::CommitPending`], or an MLS
    /// error.
    pub fn set_policy<S: Store>(
        &mut self,
        client: &Client<S>,
        policy: &GroupPolicy,
    ) -> Result<CommitOut> {
        self.atomically(client, |g| g.set_policy_inner(client, policy))
    }

    /// What [`Group::set_policy`] with `policy` would answer now, without
    /// building a commit: the policy's limits, then the checks of any
    /// commit of this instance (a member, no commit pending, its own leave
    /// not pending), then SPEC §9.2 for the commit `set_policy` would build,
    /// as every receiver checks it. That commit carries this
    /// GroupContextExtensions proposal and the pending leaves
    /// ([`Group::pending_leaves`]). The group is not changed.
    ///
    /// # Errors
    ///
    /// A policy validation error, [`Error::NotMember`],
    /// [`Error::CommitPending`], [`Error::NotPermitted`] while this
    /// instance's own leave is pending, or the [`Error::Unauthorized`] that
    /// `set_policy` would return.
    pub fn check_policy_change<S: Store>(
        &self,
        client: &Client<S>,
        policy: &GroupPolicy,
    ) -> Result<()> {
        policy.validate()?;
        self.ready()?;
        self.leaves_for_commit()?;
        let current = self.policy()?;
        let members = self.members()?;
        let leaving = self.pending_leave_leaves()?;
        let identities_before: BTreeSet<String> =
            members.iter().map(|m| m.identity.clone()).collect();
        let staying: Vec<&MemberInfo> = members
            .iter()
            .filter(|m| !leaving.contains(&m.leaf_index))
            .collect();
        authorize(
            &current,
            &CommitFacts {
                committer: client.instance.identity().to_owned(),
                adds: Vec::new(),
                removes: members
                    .iter()
                    .filter(|m| leaving.contains(&m.leaf_index))
                    .map(|m| Removal {
                        identity: m.identity.clone(),
                        self_proposed: true,
                    })
                    .collect(),
                new_policy: Some(policy.clone()),
                identities_before,
                members_after: staying.len(),
                identities_after: staying.iter().map(|m| m.identity.clone()).collect(),
                identities_kept: staying.iter().map(|m| m.identity.clone()).collect(),
            },
        )
    }

    /// Commits pending proposals (other members' leaves).
    ///
    /// # Errors
    ///
    /// [`Error::NothingToCommit`] if none are pending, [`Error::CommitPending`],
    /// or an MLS error.
    pub fn commit_pending_proposals<S: Store>(&mut self, client: &Client<S>) -> Result<CommitOut> {
        self.atomically(client, |g| g.commit_pending_proposals_inner(client))
    }

    /// Proposes this instance's own removal, as a `PrivateMessage` Remove
    /// proposal (`kind: proposal`, SPEC §9.2). Another member commits it.
    ///
    /// # Errors
    ///
    /// [`Error::NotPermitted`] for a sole member (it should just delete its
    /// state) or for the owner's last instance (it must transfer ownership
    /// first, SPEC §9.2), [`Error::CommitPending`], or an MLS error.
    pub fn propose_leave<S: Store>(&mut self, client: &Client<S>) -> Result<Vec<u8>> {
        self.atomically(client, |g| g.propose_leave_inner(client))
    }

    /// Merges the pending commit after the relay confirmed it: `msg_id` is
    /// the id in the relay's `accepted` frame and must be the pending
    /// commit's [`CommitOut::msg_id`] (SPEC §8.3).
    ///
    /// A late `accepted` for a commit that the fan-out already confirmed
    /// returns [`Error::NoPendingCommit`]; the daemon ignores it.
    ///
    /// # Errors
    ///
    /// [`Error::NoPendingCommit`], [`Error::PendingCommitMismatch`] (nothing
    /// is merged), or an MLS error.
    pub fn confirm_pending_commit<S: Store>(
        &mut self,
        client: &Client<S>,
        msg_id: &str,
    ) -> Result<CommitSummary> {
        self.atomically(client, |g| g.confirm_pending_commit_inner(client, msg_id))
    }

    /// Drops the pending commit after the relay rejected it
    /// (`epoch_conflict`, or another error for its `msg_id`; SPEC §8.3).
    /// Process the winning commit next, then rebuild if still needed.
    ///
    /// Don't discard on a timeout: resend the same commit under the same
    /// `msg_id` (the relay deduplicates it). If a discarded commit is later
    /// delivered back, [`Group::process`] reports [`Error::OwnCommitLost`].
    ///
    /// # Errors
    ///
    /// [`Error::NoPendingCommit`] or a storage error.
    pub fn discard_pending_commit<S: Store>(&mut self, client: &Client<S>) -> Result<()> {
        self.atomically(client, |g| g.discard_pending_commit_inner(client))
    }

    /// Encrypts an inner message (SPEC §7.2) as an application message,
    /// padded to its bucket (SPEC §7.1). The inner `v`, `sender` and
    /// `instance_id` must be this instance's.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`]/[`Error::CredentialMismatch`] for a bad inner
    /// header, [`Error::TooLarge`], [`Error::CommitPending`], or an MLS error.
    pub fn seal<S: Store>(&mut self, client: &Client<S>, inner: &[u8]) -> Result<Vec<u8>> {
        self.atomically(client, |g| g.seal_inner(client, inner))
    }

    /// Processes one MLS message from the relay. Commits are checked against
    /// the policy in force (SPEC §9.2) and the key/certificate rules
    /// (§3.1, §3.3) **before** they are merged; a rejected commit is not
    /// merged and returns [`Error::Unauthorized`] (raise
    /// `unauthorized_commit`) or a validation error.
    ///
    /// Processing is atomic: on success the whole state change is stored,
    /// on failure none of it is (the group is reloaded from the store), so
    /// a failed message can be retried and fails the same way. Success is
    /// one-shot, though: it consumes the message's key. A caller that must
    /// survive a crash before it has recorded the event uses
    /// [`Group::process_journaled`].
    ///
    /// # Errors
    ///
    /// See above; also [`Error::WrongGroup`], [`Error::WrongEpoch`],
    /// [`Error::NotMember`], [`Error::Malformed`], [`Error::OwnCommitLost`]
    /// (the pending commit was discarded, and that is stored), and MLS
    /// errors (e.g. for tampered or replayed messages).
    pub fn process<S: Store>(&mut self, client: &Client<S>, bytes: &[u8]) -> Result<Event> {
        self.atomically_keeping(client, Self::lost, |g| {
            let event = g.process_inner(client, bytes)?;
            client.fail("process.before_commit")?;
            Ok(event)
        })
    }

    /// [`Group::process`], with the event journalled under `key` (the
    /// caller's id for the message, e.g. `sender/msg_id`) in the same
    /// transaction as the state change (ADR-004). Processing the same bytes
    /// under the same key again, before the entry is consumed with
    /// [`Client::journal_consume`], returns the journalled event with
    /// `replayed` set and changes nothing.
    ///
    /// # Errors
    ///
    /// As [`Group::process`]; [`Error::Duplicate`] once the entry was
    /// consumed, [`Error::JournalConflict`] for other bytes under the same
    /// key.
    pub fn process_journaled<S: Store>(
        &mut self,
        client: &Client<S>,
        key: &str,
        context: &[u8],
        bytes: &[u8],
    ) -> Result<Journaled<Event>> {
        let hash = wire_hash(bytes);
        if let Some((_, stored)) =
            journal::lookup(client.store(), self.group_id(), key, Some(&hash))?
        {
            let Stored::Event { event } = stored else {
                return Err(Error::JournalConflict);
            };
            return Ok(Journaled {
                value: event,
                replayed: true,
            });
        }
        self.atomically_keeping(client, Self::lost, |g| {
            let event = g.process_inner(client, bytes)?;
            journal::record(
                client.store(),
                g.group_id(),
                g.group_id(),
                key,
                &hash,
                context,
                &Stored::Event {
                    event: event.clone(),
                },
                client.now(),
            )?;
            client.fail("process.before_commit")?;
            Ok(Journaled {
                value: event,
                replayed: false,
            })
        })
    }

    /// [`Group::confirm_pending_commit`], journalled under `key` with the
    /// caller's `context` (ADR-004), as an `OwnCommitConfirmed` event. Use
    /// the key the commit's fan-out copy is processed under
    /// (`own mailbox/msg_id`): whichever of the two confirms the commit
    /// first journals it, and the other gets the same result back.
    ///
    /// # Errors
    ///
    /// As [`Group::confirm_pending_commit`]; [`Error::Duplicate`] once the
    /// entry was consumed.
    pub fn confirm_pending_commit_journaled<S: Store>(
        &mut self,
        client: &Client<S>,
        msg_id: &str,
        key: &str,
        context: &[u8],
    ) -> Result<Journaled<CommitSummary>> {
        if let Some((_, stored)) = journal::lookup(client.store(), self.group_id(), key, None)? {
            return match stored {
                Stored::Event {
                    event: Event::OwnCommitConfirmed(summary),
                } => Ok(Journaled {
                    value: summary,
                    replayed: true,
                }),
                _ => Err(Error::JournalConflict),
            };
        }
        self.atomically(client, |g| {
            let hash = OwnCommits::load(client.store(), g.group_id(), g.epoch())?
                .pending
                .map(|p| p.hash)
                .unwrap_or_default();
            let summary = g.confirm_pending_commit_inner(client, msg_id)?;
            journal::record(
                client.store(),
                g.group_id(),
                g.group_id(),
                key,
                &hash,
                context,
                &Stored::Event {
                    event: Event::OwnCommitConfirmed(summary.clone()),
                },
                client.now(),
            )?;
            client.fail("confirm.before_commit")?;
            Ok(Journaled {
                value: summary,
                replayed: false,
            })
        })
    }

    fn lost(e: &Error) -> bool {
        matches!(e, Error::OwnCommitLost)
    }

    /// Runs `f` in one store transaction: committed if it succeeds, rolled
    /// back (and the in-memory group reloaded from the store) if it fails.
    fn atomically<S: Store, T>(
        &mut self,
        client: &Client<S>,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.atomically_keeping(client, |_| false, f)
    }

    /// [`Group::atomically`], but errors for which `keep` holds commit the
    /// work done so far (a state change made on purpose before failing).
    fn atomically_keeping<S: Store, T>(
        &mut self,
        client: &Client<S>,
        keep: fn(&Error) -> bool,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let tx = Tx::begin(client.store())?;
        let out = f(self);
        let commit = match &out {
            Ok(_) => true,
            Err(e) => keep(e),
        };
        if commit {
            match tx.commit() {
                Ok(()) => return out,
                Err(e) => {
                    self.reload(client)?;
                    return Err(e);
                }
            }
        }
        drop(tx);
        // OpenMLS may have moved the in-memory group ahead of the store.
        self.reload(client)?;
        out
    }

    fn reload<S: Store>(&mut self, client: &Client<S>) -> Result<()> {
        if let Some(mls) =
            MlsGroup::load(client.provider.storage(), self.mls.group_id()).map_err(storage)?
        {
            self.mls = mls;
        }
        Ok(())
    }

    /// The 16-byte group id.
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        self.mls.group_id().as_slice()
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.mls.epoch().as_u64()
    }

    /// Whether this instance is still a member.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.mls.is_active()
    }

    /// Whether a commit is waiting for relay confirmation.
    #[must_use]
    pub fn has_pending_commit(&self) -> bool {
        self.mls.pending_commit().is_some()
    }

    /// Whether a proposal (a leave, SPEC §9.2) is stored for the next
    /// commit. While one is, OpenMLS seals no application message.
    #[must_use]
    pub fn has_pending_proposals(&self) -> bool {
        self.mls.pending_proposals().next().is_some()
    }

    /// This instance's leaf index.
    #[must_use]
    pub fn own_leaf_index(&self) -> u32 {
        self.mls.own_leaf_index().u32()
    }

    /// The current `ac_group_policy`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidGroupContext`] if the stored context is broken.
    pub fn policy(&self) -> Result<GroupPolicy> {
        Ok(check_group_context(self.mls.extensions())?.policy)
    }

    /// The `ac_group_meta`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidGroupContext`] if the stored context is broken.
    pub fn meta(&self) -> Result<GroupMeta> {
        Ok(check_group_context(self.mls.extensions())?.meta)
    }

    /// Every member instance.
    ///
    /// # Errors
    ///
    /// A validation error if a stored leaf is broken.
    pub fn members(&self) -> Result<Vec<MemberInfo>> {
        self.mls
            .members()
            .map(|m| self.member_info(m.index))
            .collect()
    }

    /// The epoch authenticator, as a fingerprint of the group state for
    /// unit tests. Never a code: a code comes from a SAS run (SPEC §11.4).
    #[cfg(test)]
    pub(crate) fn state_fingerprint(&self) -> Vec<u8> {
        self.mls.epoch_authenticator().as_slice().to_vec()
    }

    /// [`Group::state_fingerprint`] for the bindings' tests. Only with the
    /// `test-hooks` feature, which release builds leave off.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use]
    pub fn state_fingerprint_for_testing(&self) -> Vec<u8> {
        self.mls.epoch_authenticator().as_slice().to_vec()
    }

    /// This instance's SAS commitment for a run with `peer` in the current
    /// epoch (SPEC §11.2).
    #[must_use]
    pub fn sas_commitment<S: Store>(
        &self,
        client: &Client<S>,
        peer: &str,
        nonce: &SasNonce,
    ) -> [u8; sas::NONCE_LEN] {
        sas::commitment(
            self.group_id(),
            self.epoch(),
            client.instance().identity(),
            client.instance().instance_id(),
            peer,
            nonce.expose(),
        )
    }

    /// The code of a completed SAS run (SPEC §11.4): this instance with
    /// `own` and the peer instance with its revealed `peer_nonce`.
    ///
    /// The code is derived only under the authenticator of the group's
    /// current epoch, and only for the epoch the run named.
    ///
    /// # Errors
    ///
    /// - [`Error::WrongEpoch`] if `epoch` isn't the current epoch.
    /// - [`Error::Malformed`] if the peer is this instance's own identity.
    /// - [`Error::UnknownMember`] if the peer instance isn't a member.
    pub fn sas_code<S: Store>(
        &self,
        client: &Client<S>,
        epoch: u64,
        own: &SasNonce,
        peer_identity: &str,
        peer_instance: u64,
        peer_nonce: &[u8; sas::NONCE_LEN],
    ) -> Result<Sas> {
        if !sas_epoch_ok(epoch, self.epoch()) {
            return Err(Error::WrongEpoch);
        }
        if peer_identity == client.instance().identity() {
            return Err(Error::Malformed("SAS run with oneself"));
        }
        if !self
            .members()?
            .iter()
            .any(|m| m.identity == peer_identity && m.instance_id == peer_instance)
        {
            return Err(Error::UnknownMember);
        }
        let me = Participant {
            identity: client.instance().identity(),
            instance_id: client.instance().instance_id(),
            nonce: own.expose(),
        };
        let peer = Participant {
            identity: peer_identity,
            instance_id: peer_instance,
            nonce: peer_nonce,
        };
        Sas::derive(
            self.mls.epoch_authenticator().as_slice(),
            self.group_id(),
            epoch,
            &me,
            &peer,
        )
    }

    fn member_info(&self, index: LeafNodeIndex) -> Result<MemberInfo> {
        let leaf = self
            .mls
            .public_group()
            .leaf(index)
            .ok_or(Error::UnknownMember)?;
        Ok(MemberInfo::from_leaf(index.u32(), &validate_leaf(leaf)?))
    }

    /// Whether the leave of `leaving`, together with the leaves already
    /// pending in this epoch, would remove the owner's last instance
    /// (SPEC §9.2). Pending proposals don't outlive their epoch, so these
    /// are all the removals the next commit can carry.
    fn owner_left_without(&self, leaving: LeafNodeIndex) -> Result<bool> {
        let owner = self.policy()?.owner;
        if self.member_info(leaving)?.identity != owner {
            return Ok(false);
        }
        let mut gone = self.stored_leave_leaves();
        gone.insert(leaving.u32());
        Ok(!self
            .members()?
            .iter()
            .any(|m| m.identity == owner && !gone.contains(&m.leaf_index)))
    }

    /// Whether `leaving` is the owner's only instance in the group (pending
    /// leaves not counted): the receiver's check on a leave proposal
    /// (SPEC §9.2). It depends on the membership alone, never on which
    /// other leaves arrived first, so every member decides the same way.
    fn owner_sole_instance(&self, leaving: LeafNodeIndex) -> Result<bool> {
        let owner = self.policy()?.owner;
        let leaving = self.member_info(leaving)?;
        Ok(leaving.identity == owner
            && self
                .members()?
                .iter()
                .all(|m| m.identity != owner || m.leaf_index == leaving.leaf_index))
    }

    /// The leaves whose own Remove proposal (a leave) is stored in this
    /// epoch.
    fn stored_leave_leaves(&self) -> BTreeSet<u32> {
        self.mls
            .pending_proposals()
            .filter_map(|q| match (q.proposal(), q.sender()) {
                (Proposal::Remove(r), Sender::Member(s)) if r.removed() == *s => Some(s.u32()),
                _ => None,
            })
            .collect()
    }

    /// The owner instance whose stored leave the next commit leaves out:
    /// when every instance of the owner has a leave stored (instances that
    /// proposed at once, each before seeing the other's), the one with the
    /// lowest leaf index stays, so the owner keeps an instance (SPEC §9.2).
    /// Every member that stored the same proposals picks the same one,
    /// whatever order they arrived in.
    fn kept_owner_leaf(&self, stored: &BTreeSet<u32>) -> Result<Option<u32>> {
        let owner = self.policy()?.owner;
        let owner_leaves: Vec<u32> = self
            .members()?
            .iter()
            .filter(|m| m.identity == owner)
            .map(|m| m.leaf_index)
            .collect();
        Ok(
            if !owner_leaves.is_empty() && owner_leaves.iter().all(|l| stored.contains(l)) {
                owner_leaves.into_iter().min()
            } else {
                None
            },
        )
    }

    /// The leaves whose stored leave the next commit carries: every stored
    /// leave but the one [`Group::kept_owner_leaf`] leaves out.
    fn pending_leave_leaves(&self) -> Result<BTreeSet<u32>> {
        let mut leaving = self.stored_leave_leaves();
        if let Some(kept) = self.kept_owner_leaf(&leaving)? {
            leaving.remove(&kept);
        }
        Ok(leaving)
    }

    /// Before any commit of this instance: which stored leave to leave out
    /// of it, and a refusal if the commit would carry this instance's own
    /// leave (no member commits its own removal).
    fn leaves_for_commit(&self) -> Result<Option<u32>> {
        let stored = self.stored_leave_leaves();
        let kept = self.kept_owner_leaf(&stored)?;
        let own = self.own_leaf_index();
        if stored.contains(&own) && kept != Some(own) {
            return Err(Error::NotPermitted(OWN_LEAVE_PENDING));
        }
        Ok(kept)
    }

    /// The members whose leave is pending in this epoch (SPEC §9.2), in
    /// leaf order: the leaves the next commit of any member carries, this
    /// instance's own included. That is every stored leave proposal, except
    /// that when every instance of the owner has proposed a leave (at once,
    /// each before seeing the others'), the instance with the lowest leaf
    /// index stays and its leave is left out. Members that stored the same
    /// proposals get the same list, in whatever order they arrived.
    /// Proposals don't outlive their epoch: a commit that doesn't carry a
    /// leave drops it, and that member proposes again if it still means to
    /// leave.
    ///
    /// # Errors
    ///
    /// A validation error if a stored leaf is broken.
    pub fn pending_leaves(&self) -> Result<Vec<MemberInfo>> {
        self.pending_leave_leaves()?
            .into_iter()
            .map(|leaf| self.member_info(LeafNodeIndex::new(leaf)))
            .collect()
    }

    fn check_all_leaves(&self, policy: &GroupPolicy) -> Result<()> {
        let members = self.members()?;
        if members.len() > usize::try_from(policy.max_members).unwrap_or(usize::MAX) {
            return Err(Error::InvalidGroupContext("group exceeds max_members"));
        }
        check_unique_instances(&members, &BTreeSet::new(), None, &[])
            .map_err(|_| Error::InvalidGroupContext(REPEATED_INSTANCE))
    }

    /// A replayed knock join (a journal entry not consumed yet): the
    /// group's name and creator are the listing's, and the listed identity
    /// is a member. Later commits may have changed the rest.
    fn check_knock_replay(&self, expected: &KnockExpectation) -> Result<()> {
        let meta = self.meta()?;
        if meta.name != expected.name {
            return Err(Error::KnockWelcome("name"));
        }
        if meta.created_by != expected.identity {
            return Err(Error::KnockWelcome("created_by"));
        }
        if !self
            .members()?
            .iter()
            .any(|m| m.identity == expected.identity)
        {
            return Err(Error::KnockWelcome(
                "the other member is not the listed identity",
            ));
        }
        Ok(())
    }

    /// SPEC §6.6.5: exactly two leaves, this instance's own and one of
    /// `listed` (each validated by [`Group::members`], certificate
    /// included).
    fn check_knock_members(&self, me: &str, listed: &str) -> Result<()> {
        let members = self.members()?;
        let own = self.own_leaf_index();
        if members.len() != 2 {
            return Err(Error::KnockWelcome("not exactly two members"));
        }
        let ok = members.iter().all(|m| {
            if m.leaf_index == own {
                m.identity == me
            } else {
                m.identity == listed
            }
        });
        if !ok {
            return Err(Error::KnockWelcome(
                "the other member is not the listed identity",
            ));
        }
        Ok(())
    }

    fn ready(&self) -> Result<()> {
        if !self.mls.is_active() {
            return Err(Error::NotMember);
        }
        if self.has_pending_commit() {
            return Err(Error::CommitPending);
        }
        Ok(())
    }

    fn set_padding<S: Store>(&mut self, client: &Client<S>, padding: usize) -> Result<()> {
        if self.mls.configuration().padding_size() != padding {
            self.mls
                .set_configuration(
                    client.provider.storage(),
                    &join_config_with_padding(padding),
                )
                .map_err(storage)?;
        }
        Ok(())
    }

    /// Handshake messages are not bucketed; reset any application padding.
    fn handshake_padding<S: Store>(&mut self, client: &Client<S>) -> Result<()> {
        self.set_padding(client, 0)
    }

    /// Checks a staged commit against SPEC §3.1/§3.3 and the policy in force
    /// (§9.2) before it is merged.
    /// The committer's leaf as the commit's update path leaves it, checked:
    /// the same identity and the same instance certificate, which is fixed
    /// for a leaf's life (SPEC §9.2), so an update can't take another
    /// instance's id.
    fn updated_leaf(
        &self,
        staged: &StagedCommit,
        committer: &MemberInfo,
    ) -> Result<Option<(u32, LeafInfo)>> {
        let Some(leaf) = staged.update_path_leaf_node() else {
            return Ok(None);
        };
        let info = validate_leaf(leaf)?;
        if info.identity != committer.identity {
            return Err(Error::CredentialMismatch("committer changed its identity"));
        }
        let current = self
            .mls
            .public_group()
            .leaf(LeafNodeIndex::new(committer.leaf_index))
            .ok_or(Error::UnknownMember)?;
        if instance_cert_bytes(leaf) != instance_cert_bytes(current) {
            return Err(Error::Unauthorized(FIXED_CERT));
        }
        Ok(Some((committer.leaf_index, info)))
    }

    fn inspect_commit<S: Store>(
        &self,
        client: &Client<S>,
        staged: &StagedCommit,
        committer: LeafNodeIndex,
    ) -> Result<Inspection> {
        let current = check_group_context(self.mls.extensions())?;
        let committer = self.member_info(committer)?;
        let mut added = Vec::new();
        let mut added_refs = Vec::new();
        let mut removals = Vec::new();
        let mut removed = Vec::new();
        let mut left = Vec::new();
        let mut new_ctx = None;
        for queued in staged.queued_proposals() {
            match queued.proposal() {
                Proposal::Add(add) => {
                    let kp = add.key_package();
                    if kp.hpke_init_key().as_slice().len() != crate::mls::HPKE_PUBLIC_KEY_LEN {
                        return Err(Error::HpkeKeyLength);
                    }
                    added.push(validate_leaf(kp.leaf_node())?);
                    let kp_ref = key_package_ref(client, kp)?;
                    if records::key_package_used(client.provider.records(), &kp_ref)? {
                        return Err(Error::Unauthorized("key package already used"));
                    }
                    added_refs.push(kp_ref);
                }
                Proposal::Remove(remove) => {
                    let index = remove.removed();
                    let member = self.member_info(index)?;
                    let self_proposed = matches!(queued.sender(), Sender::Member(s) if *s == index);
                    removals.push(Removal {
                        identity: member.identity.clone(),
                        self_proposed,
                    });
                    if self_proposed {
                        left.push(member.clone());
                    }
                    removed.push(member);
                }
                Proposal::GroupContextExtensions(gce) => {
                    if new_ctx.is_some() {
                        return Err(Error::Unauthorized("duplicate GroupContextExtensions"));
                    }
                    let ctx = check_group_context(gce.extensions())?;
                    if ctx.meta_bytes != current.meta_bytes {
                        return Err(Error::Unauthorized("ac_group_meta is immutable"));
                    }
                    // One accepted encoding per policy in a commit. Older
                    // encodings (no `floor_pinned`) are only read where they
                    // already are: a stored context or a Welcome.
                    if ctx.policy.to_json()? != ctx.policy_bytes {
                        return Err(Error::InvalidGroupContext("policy not in canonical form"));
                    }
                    new_ctx = Some(ctx);
                }
                _ => return Err(Error::Unauthorized("proposal type not allowed in v0")),
            }
        }
        let updated = self.updated_leaf(staged, &committer)?;
        if let Some(tree) = staged
            .export_ratchet_tree(client.provider.crypto(), self.mls.export_ratchet_tree())
            .map_err(mls)?
        {
            check_tree_keys(
                tree.leaves()
                    .filter_map(|l| l.tls_serialize_detached().ok()),
                tree.parents()
                    .filter_map(|p| p.tls_serialize_detached().ok()),
            )?;
        }

        let removed_leaves: BTreeSet<u32> = removed.iter().map(|m| m.leaf_index).collect();
        let members = self.members()?;
        check_unique_instances(&members, &removed_leaves, updated.as_ref(), &added)?;
        let (identities_before, identities_kept) = identities_kept(&members, &removed_leaves);
        let mut identities_after = identities_kept.clone();
        identities_after.extend(added.iter().map(|a| a.identity.clone()));
        let new_policy = new_ctx.map(|c| c.policy);
        let policy_change = new_policy
            .as_ref()
            .filter(|p| **p != current.policy)
            .map(|p| (current.policy.clone(), p.clone()));
        let facts = CommitFacts {
            committer: committer.identity.clone(),
            adds: added.iter().map(|a| a.identity.clone()).collect(),
            removes: removals,
            new_policy,
            identities_before,
            members_after: members.len() + added.len() - removed_leaves.len(),
            identities_after,
            identities_kept,
        };
        authorize(&current.policy, &facts)?;
        Ok(Inspection {
            committer,
            added,
            added_refs,
            removed,
            left,
            policy_change,
        })
    }

    fn summary(
        &self,
        inspection: Inspection,
        discarded_own_pending: bool,
    ) -> Result<CommitSummary> {
        let members = self.members().unwrap_or_default();
        let added = inspection
            .added
            .iter()
            .map(|a| {
                members
                    .iter()
                    .find(|m| leaf_mailbox(a) == m.mailbox_id)
                    .cloned()
                    .ok_or(Error::Internal("added member missing after merge"))
            })
            .collect::<Result<_>>()?;
        let (previous_policy, policy) = inspection.policy_change.unzip();
        Ok(CommitSummary {
            epoch: self.epoch(),
            committer: inspection.committer,
            added,
            removed: inspection.removed,
            left: inspection.left,
            policy_changed: policy.is_some(),
            previous_policy,
            policy,
            discarded_own_pending,
        })
    }

    fn finish_commit<S: Store>(
        &mut self,
        client: &Client<S>,
        bundle: &openmls::prelude::CommitMessageBundle,
        wrap: Option<WelcomeWrap<'_>>,
    ) -> Result<CommitOut> {
        let epoch = self.epoch();
        let staged = self
            .mls
            .pending_commit()
            .ok_or(Error::Internal("staged commit missing"))?;
        let inspection = match self
            .inspect_commit(client, staged, self.mls.own_leaf_index())
            .and_then(|i| self.check_not_reserved(client, &i).map(|()| i))
        {
            Ok(i) => i,
            Err(e) => {
                self.mls
                    .clear_pending_commit(client.provider.storage())
                    .map_err(storage)?;
                return Err(e);
            }
        };
        let built = (|| {
            let welcome = match (wrap, bundle.to_welcome_msg()) {
                (Some(wrap), Some(w)) => Some(wrap.wrap(client.rng(), &wire(&w)?)?),
                _ => None,
            };
            let commit = wire(bundle.commit())?;
            let msg_id = b64(&client.rng().array::<16>()?);
            let mut own = OwnCommits::load(client.provider.records(), self.group_id(), epoch)?;
            let hash = wire_hash(&commit);
            own.pending = Some(PendingRecord {
                msg_id: msg_id.clone(),
                hash: hash.clone(),
            });
            own.save(client.provider.records(), self.group_id())?;
            records::reserve_key_packages(
                client.provider.records(),
                &inspection.added_refs,
                &records::Reservation {
                    group_id: self.group_id().to_vec(),
                    hash,
                },
            )?;
            Ok((welcome, commit, msg_id))
        })();
        let (welcome, commit, msg_id) = match built {
            Ok(b) => b,
            Err(e) => {
                self.mls
                    .clear_pending_commit(client.provider.storage())
                    .map_err(storage)?;
                return Err(e);
            }
        };
        Ok(CommitOut {
            commit,
            msg_id,
            epoch,
            routing: Routing {
                add: inspection.added.iter().map(leaf_mailbox).collect(),
                remove: inspection
                    .removed
                    .iter()
                    .map(|m| m.mailbox_id.clone())
                    .collect(),
            },
            welcome,
        })
    }

    /// SPEC §6.2 "KeyPackage reuse": a KeyPackage that another group's
    /// pending own commit Adds can't be Added here until that commit merges
    /// (it is then used) or is dropped. A reservation counts only while its
    /// commit is still that group's pending one.
    fn check_not_reserved<S: Store>(&self, client: &Client<S>, i: &Inspection) -> Result<()> {
        for kp_ref in &i.added_refs {
            let Some(r) = records::key_package_reservation(client.provider.records(), kp_ref)?
            else {
                continue;
            };
            if r.group_id == self.group_id() {
                continue;
            }
            let Some(other) =
                MlsGroup::load(client.provider.storage(), &GroupId::from_slice(&r.group_id))
                    .map_err(storage)?
            else {
                continue;
            };
            if other.pending_commit().is_none() {
                continue;
            }
            let own = OwnCommits::load(
                client.provider.records(),
                &r.group_id,
                other.epoch().as_u64(),
            )?;
            if own.pending.is_some_and(|p| p.hash == r.hash) {
                return Err(Error::KeyPackageReused);
            }
        }
        Ok(())
    }

    fn add_member_inner<S: Store>(
        &mut self,
        client: &Client<S>,
        request: &VerifiedJoinRequest,
        invite: &Invite,
        switch_floor: bool,
    ) -> Result<CommitOut> {
        if request.invite_id != *invite.secret().id() {
            return Err(Error::InviteMismatch);
        }
        if invite.is_expired(client.clock()) {
            return Err(Error::InviteExpired);
        }
        if records::key_package_used(
            client.provider.records(),
            &key_package_ref(client, &request.key_package)?,
        )? {
            return Err(Error::KeyPackageReused);
        }
        let ctx = check_group_context(self.mls.extensions())?;
        let me = client.instance.identity();
        if request.info.identity != me && !ctx.policy.may_invite(me) {
            return Err(Error::NotPermitted("this identity may not invite"));
        }
        // SPEC §9.1 counts identities, before the commit and after it; the
        // commit also carries the leaves pending in this epoch.
        let members = self.members()?;
        let leaving = self.pending_leave_leaves()?;
        let before: BTreeSet<&str> = members.iter().map(|m| m.identity.as_str()).collect();
        let mut after: BTreeSet<&str> = members
            .iter()
            .filter(|m| !leaving.contains(&m.leaf_index))
            .map(|m| m.identity.as_str())
            .collect();
        after.insert(request.info.identity.as_str());
        let gce = if switch_floor
            && ctx.policy.floor == Floor::Free
            && !ctx.policy.floor_pinned
            && before.len() <= 2
            && after.len() > 2
        {
            let policy = GroupPolicy {
                floor: Floor::Mention,
                ..ctx.policy
            };
            Some(group_context_extensions(
                &ctx.meta_bytes,
                &policy.to_json()?,
            )?)
        } else {
            None
        };
        let key_package = request.key_package.clone();
        guard(|| {
            commit!(self, client, Some(WelcomeWrap::Invite(invite)), |b| {
                let b = b.propose_adds([key_package]);
                match gce {
                    Some(exts) => b.propose_group_context_extensions(exts).map_err(mls)?,
                    None => b,
                }
            })
        })
    }

    fn add_knocker_inner<S: Store>(
        &mut self,
        client: &Client<S>,
        knock: &VerifiedKnock,
    ) -> Result<CommitOut> {
        let now = client.now();
        if now > knock.knock().lapses_at() {
            return Err(Error::InvalidKnock("lapsed"));
        }
        if knock.knock().ts > now.saturating_add(KNOCK_FUTURE_SECS) {
            return Err(Error::InvalidKnock("ts out of range"));
        }
        let me = client.instance.identity();
        if knock.identity() == me {
            return Err(Error::NotPermitted("a knock from this identity"));
        }
        if records::key_package_used(client.provider.records(), knock.key_package_ref())? {
            return Err(Error::KeyPackageReused);
        }
        let ctx = check_group_context(self.mls.extensions())?;
        if ctx.policy.owner != me || ctx.meta.created_by != me {
            return Err(Error::NotPermitted(
                "not a group this identity created and owns",
            ));
        }
        if ctx.policy.floor != Floor::Free {
            return Err(Error::NotPermitted("the floor is not free"));
        }
        if ctx.policy.floor_pinned {
            return Err(Error::NotPermitted("the floor is pinned"));
        }
        if !roles_only_for(&ctx.policy, me) {
            return Err(Error::NotPermitted("roles for another identity"));
        }
        if self.mls.members().count() != 1 || self.epoch() != 0 {
            return Err(Error::NotPermitted("not a fresh group"));
        }
        let key_package = knock.key_package().clone();
        guard(|| {
            commit!(
                self,
                client,
                Some(WelcomeWrap::Knock(knock.secret())),
                |b| b.propose_adds([key_package])
            )
        })
    }

    /// [`Group::add_knocker`] without its checks, adding the KeyPackages of
    /// `extra` knocks too: the Welcomes a broken (or malicious) owner could
    /// send, which a knocker must refuse (SPEC §6.6.5). **Tests only**: it
    /// changes nothing a knocker accepts, since a knocker checks every
    /// Welcome whoever built it. Only with the `test-hooks` feature, which
    /// release builds leave off.
    ///
    /// # Errors
    ///
    /// [`Error::CommitPending`], or an MLS error.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn add_knocker_unchecked<S: Store>(
        &mut self,
        client: &Client<S>,
        knock: &VerifiedKnock,
        extra: &[&VerifiedKnock],
    ) -> Result<CommitOut> {
        let adds: Vec<KeyPackage> = std::iter::once(knock)
            .chain(extra.iter().copied())
            .map(|k| k.key_package().clone())
            .collect();
        commit!(
            self,
            client,
            Some(WelcomeWrap::Knock(knock.secret())),
            |b| b.propose_adds(adds)
        )
    }

    fn remove_inner<S: Store>(&mut self, client: &Client<S>, identity: &str) -> Result<CommitOut> {
        let own = self.mls.own_leaf_index();
        let leaves: Vec<LeafNodeIndex> = self
            .members()?
            .into_iter()
            .filter(|m| m.identity == identity && m.leaf_index != own.u32())
            .map(|m| LeafNodeIndex::new(m.leaf_index))
            .collect();
        if leaves.is_empty() {
            return Err(Error::UnknownMember);
        }
        // A leaf whose leave is pending goes by that proposal, which the
        // commit carries anyway, so every member reports it as a leave.
        let leaving = self.pending_leave_leaves()?;
        let leaves: Vec<LeafNodeIndex> = leaves
            .into_iter()
            .filter(|l| !leaving.contains(&l.u32()))
            .collect();
        let policy = self.policy()?;
        let me = client.instance.identity();
        if identity != me && !leaves.is_empty() && !policy.may_remove(me) {
            return Err(Error::NotPermitted("this identity may not remove members"));
        }
        commit!(self, client, None, |b| b.propose_removals(leaves))
    }

    fn remove_instances_inner<S: Store>(
        &mut self,
        client: &Client<S>,
        leaves: &[u32],
    ) -> Result<CommitOut> {
        let wanted: BTreeSet<u32> = leaves.iter().copied().collect();
        if wanted.is_empty() {
            return Err(Error::UnknownMember);
        }
        if wanted.contains(&self.own_leaf_index()) {
            return Err(Error::NotPermitted(
                "this instance's own leaf: propose a leave instead",
            ));
        }
        let members = self.members()?;
        let targets = wanted
            .iter()
            .map(|l| {
                members
                    .iter()
                    .find(|m| m.leaf_index == *l)
                    .ok_or(Error::UnknownMember)
            })
            .collect::<Result<Vec<_>>>()?;
        // A leaf whose leave is pending goes by that proposal (see
        // `remove_inner`); only the others need the permission.
        let leaving = self.pending_leave_leaves()?;
        let targets: Vec<&MemberInfo> = targets
            .into_iter()
            .filter(|m| !leaving.contains(&m.leaf_index))
            .collect();
        let policy = self.policy()?;
        let me = client.instance.identity();
        if targets.iter().any(|m| m.identity != me) {
            if !policy.may_remove(me) {
                return Err(Error::NotPermitted("this identity may not remove members"));
            }
            if me != policy.owner && targets.iter().any(|m| m.identity == policy.owner) {
                return Err(Error::NotPermitted("only the owner may remove the owner"));
            }
        }
        let by_value: Vec<LeafNodeIndex> = targets
            .iter()
            .map(|m| LeafNodeIndex::new(m.leaf_index))
            .collect();
        commit!(self, client, None, |b| b.propose_removals(by_value))
    }

    /// Builds, sends and merges a commit with these proposals, skipping
    /// every check of this crate: what a broken or malicious member could
    /// commit, which every other member must reject (SPEC §9.2). `adds` are
    /// KeyPackages (TLS bytes), checked only by OpenMLS; `remove_leaves` are
    /// leaf indices; with `meta` or `policy` (raw bytes, not checked), the
    /// commit carries a GroupContextExtensions proposal with them, and the
    /// current values for the one not given. There is no Welcome.
    ///
    /// The commit is merged at once, as if the relay had accepted it, so
    /// this instance moves to the next epoch alone when the others reject
    /// it; its fan-out copy is then an echo, and a later `accepted` finds
    /// no pending commit. **Tests only**: only with the `test-hooks`
    /// feature, which release builds leave off.
    ///
    /// # Errors
    ///
    /// [`Error::CommitPending`], [`Error::InvalidKeyPackage`], or an MLS
    /// error.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn commit_unchecked<S: Store>(
        &mut self,
        client: &Client<S>,
        adds: &[Vec<u8>],
        remove_leaves: &[u32],
        meta: Option<&[u8]>,
        policy: Option<&[u8]>,
    ) -> Result<CommitOut> {
        self.atomically(client, |g| {
            g.commit_unchecked_inner(client, adds, remove_leaves, meta, policy)
        })
    }

    #[cfg(any(test, feature = "test-hooks"))]
    fn commit_unchecked_inner<S: Store>(
        &mut self,
        client: &Client<S>,
        adds: &[Vec<u8>],
        remove_leaves: &[u32],
        meta: Option<&[u8]>,
        policy: Option<&[u8]>,
    ) -> Result<CommitOut> {
        use openmls::prelude::{KeyPackageIn, ProtocolVersion};
        self.ready()?;
        self.handshake_padding(client)?;
        let key_packages = adds
            .iter()
            .map(|bytes| {
                KeyPackageIn::tls_deserialize_exact(bytes.as_slice())
                    .map_err(|_| Error::InvalidKeyPackage("encoding"))?
                    .validate(client.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|_| Error::InvalidKeyPackage("signature or lifetime"))
            })
            .collect::<Result<Vec<_>>>()?;
        let gce = if meta.is_some() || policy.is_some() {
            let ctx = check_group_context(self.mls.extensions())?;
            let current = ctx.policy.to_json()?;
            Some(group_context_extensions(
                meta.unwrap_or(&ctx.meta_bytes),
                policy.unwrap_or(&current),
            )?)
        } else {
            None
        };
        let routing = Routing {
            add: key_packages
                .iter()
                .map(|kp| crate::identity::mailbox_id(kp.leaf_node().signature_key().as_slice()))
                .collect(),
            remove: remove_leaves
                .iter()
                .filter_map(|l| self.member_info(LeafNodeIndex::new(*l)).ok())
                .map(|m| m.mailbox_id)
                .collect(),
        };
        let epoch = self.epoch();
        let previous = self.snapshot()?;
        let signer = client.signer();
        let b = self
            .mls
            .commit_builder()
            .propose_adds(key_packages)
            .propose_removals(remove_leaves.iter().map(|l| LeafNodeIndex::new(*l)));
        let b = match gce {
            Some(exts) => b.propose_group_context_extensions(exts).map_err(mls)?,
            None => b,
        };
        let bundle = guard(|| {
            b.load_psks(client.provider.storage())
                .map_err(mls)?
                .build(
                    client.provider.rand(),
                    client.provider.crypto(),
                    &signer,
                    |_| true,
                )
                .map_err(mls)?
                .stage_commit(&client.provider)
                .map_err(mls)
        })?;
        let commit = wire(bundle.commit())?;
        self.mls
            .merge_pending_commit(&client.provider)
            .map_err(mls)?;
        previous.save(client.provider.records(), self.group_id())?;
        OwnCommits {
            epoch: self.epoch(),
            confirmed: Some(wire_hash(&commit)),
            ..OwnCommits::default()
        }
        .save(client.provider.records(), self.group_id())?;
        Ok(CommitOut {
            commit,
            msg_id: b64(&client.rng().array::<16>()?),
            epoch,
            routing,
            welcome: None,
        })
    }

    fn update_inner<S: Store>(&mut self, client: &Client<S>) -> Result<CommitOut> {
        commit!(self, client, None, |b| b.force_self_update(true))
    }

    fn set_policy_inner<S: Store>(
        &mut self,
        client: &Client<S>,
        policy: &GroupPolicy,
    ) -> Result<CommitOut> {
        policy.validate()?;
        let ctx = check_group_context(self.mls.extensions())?;
        let exts = group_context_extensions(&ctx.meta_bytes, &policy.to_json()?)?;
        commit!(self, client, None, |b| b
            .propose_group_context_extensions(exts)
            .map_err(mls)?)
    }

    fn commit_pending_proposals_inner<S: Store>(
        &mut self,
        client: &Client<S>,
    ) -> Result<CommitOut> {
        if self.pending_leave_leaves()?.is_empty() {
            return Err(Error::NothingToCommit);
        }
        commit!(self, client, None, |b| b)
    }

    fn propose_leave_inner<S: Store>(&mut self, client: &Client<S>) -> Result<Vec<u8>> {
        self.ready()?;
        if self.mls.members().count() < 2 {
            return Err(Error::NotPermitted(
                "sole member: delete the local state instead",
            ));
        }
        if self.owner_left_without(self.mls.own_leaf_index())? {
            return Err(Error::NotPermitted(OWNER_MUST_TRANSFER));
        }
        self.handshake_padding(client)?;
        let msg = self
            .mls
            .leave_group(&client.provider, &client.signer())
            .map_err(mls)?;
        wire(&msg)
    }

    fn confirm_pending_commit_inner<S: Store>(
        &mut self,
        client: &Client<S>,
        msg_id: &str,
    ) -> Result<CommitSummary> {
        if !self.has_pending_commit() {
            return Err(Error::NoPendingCommit);
        }
        let own = OwnCommits::load(client.provider.records(), self.group_id(), self.epoch())?;
        match own.pending {
            Some(p) if p.msg_id == msg_id => {
                let summary = self.merge_own(client)?;
                client.fail("confirm.after_merge")?;
                Ok(summary)
            }
            _ => Err(Error::PendingCommitMismatch),
        }
    }

    /// The current epoch's members, taken just before a merge.
    fn snapshot(&self) -> Result<PreviousMembers> {
        Ok(PreviousMembers {
            epoch: self.epoch(),
            members: self.members()?,
        })
    }

    /// Records kept after every merged commit: the members of the epoch
    /// that just ended (for its grace window) and the KeyPackages it used.
    fn after_merge<S: Store>(
        &self,
        client: &Client<S>,
        previous: &PreviousMembers,
        inspection: &Inspection,
    ) -> Result<()> {
        previous.save(client.provider.records(), self.group_id())?;
        records::mark_key_packages_used(client.provider.records(), &inspection.added_refs)
    }

    /// The sender of an application message, resolved in the epoch the
    /// message was sent in (SPEC §8.3 grace window): a member removed by the
    /// commit that ended that epoch is still its sender.
    fn sender_in_epoch<S: Store>(
        &self,
        client: &Client<S>,
        index: LeafNodeIndex,
        epoch: u64,
    ) -> Result<MemberInfo> {
        if epoch == self.epoch() {
            return self.member_info(index);
        }
        PreviousMembers::load(client.provider.records(), self.group_id())?
            .filter(|p| p.epoch == epoch)
            .and_then(|p| p.members.into_iter().find(|m| m.leaf_index == index.u32()))
            .ok_or(Error::UnknownMember)
    }

    fn merge_own<S: Store>(&mut self, client: &Client<S>) -> Result<CommitSummary> {
        let staged = self.mls.pending_commit().ok_or(Error::NoPendingCommit)?;
        let inspection = self.inspect_commit(client, staged, self.mls.own_leaf_index())?;
        let sent = OwnCommits::load(client.provider.records(), self.group_id(), self.epoch())?
            .pending
            .map(|p| p.hash);
        let previous = self.snapshot()?;
        self.mls
            .merge_pending_commit(&client.provider)
            .map_err(mls)?;
        self.after_merge(client, &previous, &inspection)?;
        OwnCommits {
            epoch: self.epoch(),
            confirmed: sent,
            ..OwnCommits::default()
        }
        .save(client.provider.records(), self.group_id())?;
        self.summary(inspection, false)
    }

    fn discard_pending_commit_inner<S: Store>(&mut self, client: &Client<S>) -> Result<()> {
        if !self.has_pending_commit() {
            return Err(Error::NoPendingCommit);
        }
        let mut own = OwnCommits::load(client.provider.records(), self.group_id(), self.epoch())?;
        own.discard_pending();
        own.save(client.provider.records(), self.group_id())?;
        self.mls
            .clear_pending_commit(client.provider.storage())
            .map_err(storage)
    }

    /// An MLS commit whose sender data names this instance's own leaf.
    /// OpenMLS can't decrypt or authenticate it (the sender data is
    /// encrypted under a key every member knows), so only an exact byte
    /// match with what this instance sent confirms anything (SPEC §8.3).
    fn own_commit<S: Store>(&mut self, client: &Client<S>, bytes: &[u8]) -> Result<Event> {
        let mut own = OwnCommits::load(client.provider.records(), self.group_id(), self.epoch())?;
        let hash = wire_hash(bytes);
        if self.has_pending_commit() && own.pending.as_ref().is_some_and(|p| p.hash == hash) {
            return Ok(Event::OwnCommitConfirmed(self.merge_own(client)?));
        }
        if own.discarded.contains(&hash) {
            // The relay accepted a commit we no longer hold: the group has
            // moved to an epoch this instance can't enter.
            if self.has_pending_commit() {
                own.discard_pending();
                own.save(client.provider.records(), self.group_id())?;
                self.mls
                    .clear_pending_commit(client.provider.storage())
                    .map_err(storage)?;
            }
            return Err(Error::OwnCommitLost);
        }
        // Not something this instance sent: forged (any member can write
        // sender data naming our leaf) or corrupted. Ignore it and keep the
        // pending commit, which only authenticated evidence may settle.
        Err(Error::Unauthorized(
            "commit claims this instance as sender but was not sent by it",
        ))
    }

    fn seal_inner<S: Store>(&mut self, client: &Client<S>, inner: &[u8]) -> Result<Vec<u8>> {
        self.ready()?;
        let bucket = bucket_for(inner.len()).ok_or(Error::TooLarge)?;
        let me = self.member_info(self.mls.own_leaf_index())?;
        check_inner(inner, &me)?;
        self.set_padding(client, bucket)?;
        let msg = self
            .mls
            .create_message(&client.provider, &client.signer(), inner)
            .map_err(mls)?;
        wire(&msg)
    }

    /// Decrypts an application message.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedMessage`] if `ct` is not an application message,
    /// or any [`Group::process`] error.
    pub fn open<S: Store>(&mut self, client: &Client<S>, ct: &[u8]) -> Result<ApplicationMessage> {
        let msg = parse_protocol(ct)?;
        if msg.content_type() != ContentType::Application {
            return Err(Error::UnexpectedMessage("not an application message"));
        }
        match self.process(client, ct)? {
            Event::Application(m) => Ok(m),
            _ => Err(Error::UnexpectedMessage("not an application message")),
        }
    }

    /// The body of [`Group::process`], inside its transaction.
    fn process_inner<S: Store>(&mut self, client: &Client<S>, bytes: &[u8]) -> Result<Event> {
        client.fail("process.before_mls")?;
        if !self.mls.is_active() {
            return Err(Error::NotMember);
        }
        let msg = parse_protocol(bytes)?;
        if msg.group_id().as_slice() != self.group_id() {
            return Err(Error::WrongGroup);
        }
        let content_type = msg.content_type();
        let epoch = msg.epoch().as_u64();
        if content_type == ContentType::Commit && epoch.checked_add(1) == Some(self.epoch()) {
            // The fan-out copy of our own commit, already merged on `accepted`.
            let own = OwnCommits::load(client.provider.records(), self.group_id(), self.epoch())?;
            if own.confirmed == Some(wire_hash(bytes)) {
                return Ok(Event::OwnEcho);
            }
        }
        // A commit's UpdatePath KEM ciphertexts are only readable once
        // OpenMLS has decrypted the commit, and it decapsulates ours in the
        // same call; the provider rejects any `kem_output` that isn't
        // KEM_CIPHERTEXT_LEN bytes (SPEC §3.1).
        let processed = guard(|| {
            self.mls
                .process_message(&client.provider, msg)
                .map_err(process_error)
        })?;
        client.fail("process.after_mls")?;
        let sender = processed.sender().clone();
        let msg_epoch = processed.epoch().as_u64();
        let credential = processed.credential().clone();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => {
                let Sender::Member(index) = sender else {
                    return Err(Error::UnexpectedMessage(
                        "application message from non-member",
                    ));
                };
                let sender = self.sender_in_epoch(client, index, msg_epoch)?;
                // OpenMLS verified the message against the leaf of its own
                // epoch; the attribution must name the same credential.
                let identity = BasicCredential::try_from(credential)
                    .map_err(|_| Error::CredentialMismatch("not a basic credential"))?;
                if identity.identity() != sender.identity.as_bytes() {
                    return Err(Error::CredentialMismatch("sender != epoch member"));
                }
                let plaintext = m.into_bytes();
                check_inner(&plaintext, &sender)?;
                Ok(Event::Application(ApplicationMessage {
                    sender,
                    epoch: msg_epoch,
                    plaintext,
                }))
            }
            ProcessedMessageContent::ProposalMessage(queued) => {
                let leave = match (queued.proposal(), queued.sender()) {
                    (Proposal::Remove(r), Sender::Member(s)) if r.removed() == *s => Some(*s),
                    _ => None,
                };
                let Some(index) = leave else {
                    return Err(Error::Unauthorized("only leave proposals are accepted"));
                };
                let member = self.member_info(index)?;
                if self.owner_sole_instance(index)? {
                    return Err(Error::Unauthorized(OWNER_MUST_TRANSFER));
                }
                self.mls
                    .store_pending_proposal(client.provider.storage(), *queued)
                    .map_err(storage)?;
                Ok(Event::LeaveProposed(member))
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let Sender::Member(committer) = sender else {
                    return Err(Error::Unauthorized("commit from a non-member"));
                };
                let had_pending = self.has_pending_commit();
                let inspection = self.inspect_commit(client, &staged, committer)?;
                let self_removed = staged.self_removed();
                let previous = self.snapshot()?;
                self.mls
                    .merge_staged_commit(&client.provider, *staged)
                    .map_err(mls)?;
                client.fail("process.after_merge")?;
                self.after_merge(client, &previous, &inspection)?;
                let summary = self.summary(inspection, had_pending)?;
                Ok(if self_removed {
                    Event::Removed(summary)
                } else {
                    Event::Commit(summary)
                })
            }
            ProcessedMessageContent::OwnPendingCommit
            | ProcessedMessageContent::OwnPrivateMessage => {
                if content_type == ContentType::Commit && epoch == self.epoch() {
                    self.own_commit(client, bytes)
                } else {
                    Ok(Event::OwnEcho)
                }
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(Error::Unauthorized("external proposals are not accepted"))
            }
        }
    }

    /// Deletes the group's state from the store (after leaving or being
    /// removed).
    ///
    /// # Errors
    ///
    /// [`Error::Storage`].
    pub fn delete<S: Store>(mut self, client: &Client<S>) -> Result<()> {
        let tx = Tx::begin(client.store())?;
        records::delete_group(client.store(), self.group_id())?;
        client.store().journal_delete_group(self.group_id())?;
        delete_mls_group(client, &mut self.mls)?;
        tx.commit()
    }

    /// [`Group::delete`] as it was before SR-61: OpenMLS's delete alone,
    /// which leaves a removed member's previous-epoch key pairs. **Tests
    /// only**, to build a store the old way.
    #[cfg(test)]
    pub(crate) fn delete_before_sr61_for_testing<S: Store>(
        mut self,
        client: &Client<S>,
    ) -> Result<()> {
        let tx = Tx::begin(client.store())?;
        records::delete_group(client.store(), self.group_id())?;
        client.store().journal_delete_group(self.group_id())?;
        self.mls
            .delete(client.provider.storage())
            .map_err(storage)?;
        tx.commit()
    }
}

/// Deletes an MLS group's state from the store: OpenMLS's delete, then
/// every row it leaves keyed by the group. OpenMLS deletes the HPKE key
/// pairs of the current epoch only, and a member that merged its own
/// removal still holds the previous epoch's (SR-61).
fn delete_mls_group<S: Store>(client: &Client<S>, mls: &mut MlsGroup) -> Result<()> {
    let group_id = mls.group_id().as_slice().to_vec();
    mls.delete(client.provider.storage()).map_err(storage)?;
    client.store().delete_group_mls_rows(&group_id)
}

#[cfg(test)]
mod group_mode_tests;
#[cfg(test)]
mod knock_tests;
#[cfg(test)]
mod sas_grind_tests;
#[cfg(test)]
mod tests;
