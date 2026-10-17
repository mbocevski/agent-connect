//! Spike: OpenMLS with the X-Wing ciphersuite.
//!
//! Small helpers shared by the integration tests in `tests/`. Findings are in
//! `docs/spikes/mls-xwing.md`. This crate is throwaway code; the real
//! implementation belongs in `core/`.

use std::borrow::Borrow;

use hkdf::Hkdf;
use openmls::prelude::{tls_codec::*, *};
use openmls::storage::OpenMlsProvider;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};

use sha2::Sha256;

/// The only v0 ciphersuite (SPEC §3.1). OpenMLS codepoint `0x004D`.
pub const CS: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

/// `ac_group_policy` GroupContext extension (SPEC §3.2).
pub const EXT_GROUP_POLICY: u16 = 0xF0A1;
/// `ac_group_meta` GroupContext extension (SPEC §3.2).
pub const EXT_GROUP_META: u16 = 0xF0A2;
/// `ac_instance_cert` LeafNode extension (SPEC §3.2).
pub const EXT_INSTANCE_CERT: u16 = 0xF0A3;

/// JSON codec for the SQLite storage provider.
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// libcrux crypto + SQLite storage.
///
/// `openmls_libcrux_crypto::Provider` hard-wires in-memory storage, so
/// persistent storage needs a provider of our own. It is generic over how the
/// connection is held: owned, or borrowed from a `Mutex<Connection>` for a
/// single operation (the shape a PyO3 class needs, since `Connection` is not
/// `Sync`).
pub struct SqliteProvider<C: Borrow<Connection>> {
    crypto: CryptoProvider,
    storage: SqliteStorageProvider<JsonCodec, C>,
}

impl<C: Borrow<Connection>> SqliteProvider<C> {
    /// Wraps a connection whose migrations have already run.
    ///
    /// # Panics
    /// If the OS RNG cannot seed the libcrux DRBG.
    pub fn new(connection: C) -> Self {
        Self {
            crypto: CryptoProvider::new().expect("seed libcrux DRBG"),
            storage: SqliteStorageProvider::new(connection),
        }
    }
}

/// Opens (or creates) a SQLite database and runs the OpenMLS migrations.
///
/// # Panics
/// On any SQLite error.
#[must_use]
pub fn open_sqlite(path: &std::path::Path) -> Connection {
    let mut connection = Connection::open(path).expect("open sqlite");
    SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut connection)
        .run_migrations()
        .expect("migrations");
    connection
}

impl<C: Borrow<Connection>> openmls_traits::OpenMlsProvider for SqliteProvider<C> {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = SqliteStorageProvider<JsonCodec, C>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// One instance (leaf): signing key + credential.
pub struct Identity {
    /// Leaf signature key (`SK`).
    pub signer: SignatureKeyPair,
    /// Basic credential + public signature key.
    pub credential: CredentialWithKey,
}

impl Identity {
    /// A fresh instance with a `BasicCredential` of `name` (SPEC uses `ac:v0:…`).
    ///
    /// # Panics
    /// On key generation or storage failure.
    pub fn new(name: &str, provider: &impl OpenMlsProvider) -> Self {
        let signer = SignatureKeyPair::new(CS.signature_algorithm()).expect("sig key");
        signer.store(provider.storage()).expect("store sig key");
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Self { signer, credential }
    }

    /// A KeyPackage for this instance with the given capabilities and leaf
    /// extensions.
    ///
    /// # Panics
    /// On KeyPackage construction failure.
    pub fn key_package(
        &self,
        provider: &impl OpenMlsProvider,
        capabilities: Capabilities,
        leaf_extensions: Extensions<LeafNode>,
    ) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .leaf_node_extensions(leaf_extensions)
            .build(CS, provider, &self.signer, self.credential.clone())
            .expect("key package")
            .key_package()
            .clone()
    }
}

/// Capabilities advertising the AgentConnect extensions (SPEC §3.1).
#[must_use]
pub fn ac_capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![CS])
        .proposals(vec![ProposalType::SelfRemove])
        .extensions(vec![
            ExtensionType::Unknown(EXT_GROUP_POLICY),
            ExtensionType::Unknown(EXT_GROUP_META),
            ExtensionType::Unknown(EXT_INSTANCE_CERT),
        ])
        .build()
}

/// A placeholder `ac_instance_cert` leaf extension.
///
/// # Panics
/// Never in practice (single extension).
#[must_use]
pub fn instance_cert_ext(cert_json: &[u8]) -> Extensions<LeafNode> {
    Extensions::single(Extension::Unknown(
        EXT_INSTANCE_CERT,
        UnknownExtension(cert_json.to_vec()),
    ))
    .expect("leaf extension")
}

/// GroupContext extensions: policy, meta and `RequiredCapabilities`.
///
/// # Panics
/// On invalid extension sets.
#[must_use]
pub fn ac_group_context_extensions(policy_json: &[u8]) -> Extensions<GroupContext> {
    Extensions::from_vec(vec![
        Extension::Unknown(EXT_GROUP_POLICY, UnknownExtension(policy_json.to_vec())),
        Extension::Unknown(EXT_GROUP_META, UnknownExtension(b"{\"v\":0}".to_vec())),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[
                ExtensionType::Unknown(EXT_GROUP_POLICY),
                ExtensionType::Unknown(EXT_GROUP_META),
                ExtensionType::Unknown(EXT_INSTANCE_CERT),
                ExtensionType::RatchetTree,
            ],
            &[],
            &[],
        )),
    ])
    .expect("group context extensions")
}

/// The create config used throughout: X-Wing, `PrivateMessage` only, ratchet
/// tree in the Welcome.
#[must_use]
pub fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CS)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(ac_capabilities())
        .build()
}

/// The join config matching [`create_config`].
#[must_use]
pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

/// Serialise an outgoing message, as it would cross the relay.
///
/// # Panics
/// On serialisation failure.
#[must_use]
pub fn wire(msg: &MlsMessageOut) -> Vec<u8> {
    msg.tls_serialize_detached().expect("serialise")
}

/// Parse bytes from the relay into a protocol message (commit / app message).
///
/// # Panics
/// If the bytes are not a protocol message.
#[must_use]
pub fn protocol_message(bytes: &[u8]) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .expect("parse")
        .try_into_protocol_message()
        .expect("protocol message")
}

/// Parse bytes from the relay into a Welcome.
///
/// # Panics
/// If the bytes are not a Welcome.
#[must_use]
pub fn welcome(bytes: &[u8]) -> Welcome {
    match MlsMessageIn::tls_deserialize_exact(bytes)
        .expect("parse")
        .extract()
    {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => panic!("not a welcome"),
    }
}

/// Join from Welcome bytes.
///
/// # Errors
/// Whatever OpenMLS returns while staging the Welcome.
pub fn join<P: OpenMlsProvider>(
    provider: &P,
    welcome_bytes: &[u8],
) -> Result<MlsGroup, WelcomeError<P::StorageError>> {
    join_with(provider, &join_config(), welcome_bytes)
}

/// Join from Welcome bytes with an explicit join config.
///
/// # Errors
/// Whatever OpenMLS returns while staging the Welcome.
pub fn join_with<P: OpenMlsProvider>(
    provider: &P,
    config: &MlsGroupJoinConfig,
    welcome_bytes: &[u8],
) -> Result<MlsGroup, WelcomeError<P::StorageError>> {
    StagedWelcome::new_from_welcome(provider, config, welcome(welcome_bytes), None)?
        .into_group(provider)
}

/// Process a commit from the relay and merge it.
///
/// # Errors
/// If processing fails (the commit is rejected, not merged).
///
/// # Panics
/// If the message is not a commit, or merging fails.
pub fn apply_commit<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    bytes: &[u8],
) -> Result<(), ProcessMessageError<P::StorageError>> {
    let processed = group.process_message(provider, protocol_message(bytes))?;
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(provider, *staged)
                .expect("merge staged commit");
            Ok(())
        }
        _ => panic!("expected a commit"),
    }
}

/// Decrypt an application message.
///
/// # Errors
/// If decryption or validation fails.
///
/// # Panics
/// If the message is not an application message.
pub fn read_app<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    bytes: &[u8],
) -> Result<Vec<u8>, ProcessMessageError<P::StorageError>> {
    let processed = group.process_message(provider, protocol_message(bytes))?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => Ok(m.into_bytes()),
        _ => panic!("expected an application message"),
    }
}

/// HKDF-SHA256 expand to `L` bytes (SPEC §3.5).
///
/// # Panics
/// If `L` is too long for HKDF-SHA256.
#[must_use]
pub fn hkdf<const L: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; L] {
    let mut out = [0u8; L];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("hkdf length");
    out
}

/// `invite_psk` (SPEC §3.5).
#[must_use]
pub fn invite_psk(invite_secret: &[u8], invite_id: &[u8]) -> [u8; 32] {
    hkdf(invite_secret, invite_id, b"agentconnect/v0/psk")
}

/// `welcome_key` (SPEC §3.5, fallback §6.4).
#[must_use]
pub fn welcome_key(invite_secret: &[u8], invite_id: &[u8]) -> [u8; 32] {
    hkdf(invite_secret, invite_id, b"agentconnect/v0/welcome")
}

/// External PSK id `"ac:v0:invite:" ‖ invite_id` (SPEC §6.1).
#[must_use]
pub fn invite_psk_id(invite_id: &[u8]) -> Vec<u8> {
    [b"ac:v0:invite:".as_slice(), invite_id].concat()
}

/// `sas_bytes` for the group's current epoch (SPEC §3.5, §11).
#[must_use]
pub fn sas_bytes(group: &MlsGroup) -> [u8; 6] {
    let epoch = group.epoch().as_u64();
    let info = [b"agentconnect/v0/sas".as_slice(), &epoch.to_be_bytes()].concat();
    hkdf(
        group.epoch_authenticator().as_slice(),
        group.group_id().as_slice(),
        &info,
    )
}

/// Decimal SAS rendering: first 39 bits as three 13-bit numbers + 1000 (SPEC §11).
#[must_use]
pub fn sas_decimal(sas: [u8; 6]) -> String {
    let mut buf = [0u8; 8];
    buf[2..].copy_from_slice(&sas);
    let bits = u64::from_be_bytes(buf); // 48 significant bits
    let n = |i: u32| ((bits >> (48 - 13 * (i + 1))) & 0x1FFF) + 1000;
    format!("{}-{}-{}", n(0), n(1), n(2))
}

/// An in-memory member: provider, identity and group state.
pub struct Peer {
    /// libcrux provider with in-memory storage.
    pub provider: openmls_libcrux_crypto::Provider,
    /// Signing key and credential.
    pub id: Identity,
    /// MLS group state.
    pub group: MlsGroup,
}

/// A group of `n` in-memory members created with `config`; member 0 created it
/// and added the rest in one commit.
///
/// # Panics
/// On any MLS failure.
#[must_use]
pub fn group_of(n: usize, config: &MlsGroupCreateConfig) -> Vec<Peer> {
    let creator = openmls_libcrux_crypto::Provider::new().expect("provider");
    let creator_id = Identity::new("ac:v0:member-0", &creator);
    let mut group = MlsGroup::new(
        &creator,
        &creator_id.signer,
        config,
        creator_id.credential.clone(),
    )
    .expect("group");
    let mut joiners: Vec<_> = (1..n)
        .map(|i| {
            let p = openmls_libcrux_crypto::Provider::new().expect("provider");
            let id = Identity::new(&format!("ac:v0:member-{i}"), &p);
            (p, id)
        })
        .collect();
    let mut members = Vec::with_capacity(n);
    if n > 1 {
        let kps: Vec<_> = joiners
            .iter()
            .map(|(p, id)| id.key_package(p, ac_capabilities(), instance_cert_ext(b"{}")))
            .collect();
        let (_, w, _) = group
            .add_members(&creator, &creator_id.signer, &kps)
            .expect("add");
        group.merge_pending_commit(&creator).expect("merge");
        let w = wire(&w);
        for (provider, id) in joiners.drain(..) {
            let g = join_with(&provider, config.join_config(), &w).expect("join");
            members.push(Peer {
                provider,
                id,
                group: g,
            });
        }
    }
    members.insert(
        0,
        Peer {
            provider: creator,
            id: creator_id,
            group,
        },
    );
    members
}
