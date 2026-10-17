//! OpenMLS glue: the v0 profile (ciphersuite, extensions, capabilities,
//! configs) and the validation `core` performs before and after handing
//! objects to OpenMLS.

use std::panic::{AssertUnwindSafe, catch_unwind};

use openmls::prelude::tls_codec::{Deserialize as _, VLBytes};
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialType, Extension, ExtensionType,
    Extensions, GroupContext, KeyPackage, KeyPackageIn, LeafNode, MlsGroupJoinConfig,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ProtocolVersion, RequiredCapabilitiesExtension,
    SenderRatchetConfiguration, UnknownExtension,
};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;

use crate::error::{Error, Result};
use crate::identity::{InstanceCert, mailbox_id, parse_identity};
use crate::policy::{GroupMeta, GroupPolicy};

/// The only v0 ciphersuite (SPEC §3.1), OpenMLS provisional codepoint 0x004F.
pub(crate) const CS: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;
/// The codepoint of [`CS`] on the wire.
pub(crate) const CS_CODEPOINT: u16 = 0x004F;

/// HPKE public key length of the v0 suite: ML-KEM-768 (1184) + X25519 (32).
pub const HPKE_PUBLIC_KEY_LEN: usize = 1216;
/// Ed25519 public key length.
pub(crate) const SIGNATURE_KEY_LEN: usize = 32;

/// `ac_group_policy` (SPEC §3.2).
pub const EXT_GROUP_POLICY: u16 = 0xF0A1;
/// `ac_group_meta` (SPEC §3.2).
pub const EXT_GROUP_META: u16 = 0xF0A2;
/// `ac_instance_cert` (SPEC §3.2).
pub const EXT_INSTANCE_CERT: u16 = 0xF0A3;

/// How many past epochs keep their application secrets, matching the
/// relay's one-epoch grace window for application messages (SPEC §8.3).
pub(crate) const MAX_PAST_EPOCHS: usize = 1;

pub(crate) fn ac_extension_types() -> Vec<ExtensionType> {
    vec![
        ExtensionType::Unknown(EXT_GROUP_POLICY),
        ExtensionType::Unknown(EXT_GROUP_META),
        ExtensionType::Unknown(EXT_INSTANCE_CERT),
    ]
}

/// Leaf capabilities: the v0 suite only, the AgentConnect extensions, and
/// basic credentials.
pub(crate) fn capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![CS])
        .extensions(ac_extension_types())
        .credentials(vec![CredentialType::Basic])
        .build()
}

pub(crate) fn required_capabilities() -> RequiredCapabilitiesExtension {
    let mut types = ac_extension_types();
    types.push(ExtensionType::RatchetTree);
    RequiredCapabilitiesExtension::new(&types, &[], &[])
}

/// The full GroupContext extension set (SPEC §5, §9.2).
pub(crate) fn group_context_extensions(
    meta: &[u8],
    policy: &[u8],
) -> Result<Extensions<GroupContext>> {
    Extensions::from_vec(vec![
        Extension::Unknown(EXT_GROUP_META, UnknownExtension(meta.to_vec())),
        Extension::Unknown(EXT_GROUP_POLICY, UnknownExtension(policy.to_vec())),
        Extension::RequiredCapabilities(required_capabilities()),
    ])
    .map_err(|_| Error::Internal("group context extensions"))
}

pub(crate) fn leaf_extensions(cert: &InstanceCert) -> Result<Extensions<LeafNode>> {
    Extensions::single(Extension::Unknown(
        EXT_INSTANCE_CERT,
        UnknownExtension(cert.to_json()?),
    ))
    .map_err(|_| Error::Internal("leaf extensions"))
}

pub(crate) fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .sender_ratchet_configuration(SenderRatchetConfiguration::default())
        .build()
}

pub(crate) fn join_config_with_padding(padding: usize) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .padding_size(padding)
        .build()
}

/// Validated contents of the AgentConnect GroupContext extensions.
#[derive(Clone, Debug)]
pub(crate) struct GroupContextInfo {
    pub meta: GroupMeta,
    pub meta_bytes: Vec<u8>,
    pub policy: GroupPolicy,
}

/// Checks a full GroupContext extension set: exactly `ac_group_meta`,
/// `ac_group_policy` and `RequiredCapabilities` (with our exact value), no
/// others, all well-formed (SPEC §3.1, §9.2).
pub(crate) fn check_group_context(exts: &Extensions<GroupContext>) -> Result<GroupContextInfo> {
    let mut meta = None;
    let mut policy = None;
    let mut req = None;
    for ext in exts.iter() {
        match ext {
            Extension::Unknown(EXT_GROUP_META, UnknownExtension(b)) => meta = Some(b),
            Extension::Unknown(EXT_GROUP_POLICY, UnknownExtension(b)) => policy = Some(b),
            Extension::RequiredCapabilities(r) => req = Some(r),
            _ => return Err(Error::InvalidGroupContext("unexpected extension")),
        }
    }
    let (Some(meta), Some(policy), Some(req)) = (meta, policy, req) else {
        return Err(Error::InvalidGroupContext("missing required extension"));
    };
    if *req != required_capabilities() {
        return Err(Error::InvalidGroupContext("RequiredCapabilities"));
    }
    Ok(GroupContextInfo {
        meta: GroupMeta::from_json(meta)?,
        meta_bytes: meta.clone(),
        policy: GroupPolicy::from_json(policy)?,
    })
}

/// Length of the first variable-length vector in a TLS encoding.
fn first_vl_len(bytes: &[u8]) -> Result<usize> {
    let mut rest = bytes;
    Ok(VLBytes::tls_deserialize(&mut rest)
        .map_err(|_| Error::Malformed("tls vector"))?
        .as_slice()
        .len())
}

/// Length of the HPKE key inside an OpenMLS `EncryptionKey` (its bytes are
/// not exposed, but its TLS encoding is just the vector).
pub(crate) fn encryption_key_len(
    key: &impl openmls::prelude::tls_codec::Serialize,
) -> Result<usize> {
    first_vl_len(
        &key.tls_serialize_detached()
            .map_err(|_| Error::Malformed("key"))?,
    )
}

/// Every HPKE key a commit could later encrypt to, in a ratchet tree:
/// leaf and parent encryption keys (SPEC §3.1, extended to parent nodes).
pub(crate) fn check_tree_keys(
    leaves: impl Iterator<Item = Vec<u8>>,
    parents: impl Iterator<Item = Vec<u8>>,
) -> Result<()> {
    for leaf in leaves {
        // LeafNode = encryption_key<V> ‖ signature_key<V> ‖ ...
        let mut rest = leaf.as_slice();
        let enc = VLBytes::tls_deserialize(&mut rest).map_err(|_| Error::Malformed("leaf"))?;
        let sig = VLBytes::tls_deserialize(&mut rest).map_err(|_| Error::Malformed("leaf"))?;
        if enc.as_slice().len() != HPKE_PUBLIC_KEY_LEN {
            return Err(Error::HpkeKeyLength);
        }
        if sig.as_slice().len() != SIGNATURE_KEY_LEN {
            return Err(Error::CredentialMismatch("leaf signature key length"));
        }
    }
    for parent in parents {
        // ParentNode = encryption_key<V> ‖ parent_hash<V> ‖ unmerged_leaves<V>
        if first_vl_len(&parent)? != HPKE_PUBLIC_KEY_LEN {
            return Err(Error::HpkeKeyLength);
        }
    }
    Ok(())
}

/// Raw pre-check of a serialised KeyPackage, before OpenMLS parses it:
/// protocol version, ciphersuite and the HPKE/signature key lengths
/// (SPEC §3.1, §6.2 step 3; mitigates RUSTSEC-2026-0331).
pub(crate) fn precheck_key_package(bytes: &[u8]) -> Result<()> {
    // KeyPackage = version(2) ‖ cipher_suite(2) ‖ init_key<V> ‖ LeafNode ‖ ...
    if bytes.len() < 4 {
        return Err(Error::InvalidKeyPackage("truncated"));
    }
    if bytes[..2] != [0, 1] {
        return Err(Error::InvalidKeyPackage("protocol version"));
    }
    if u16::from_be_bytes([bytes[2], bytes[3]]) != CS_CODEPOINT {
        return Err(Error::WrongCiphersuite);
    }
    let mut rest = &bytes[4..];
    let init =
        VLBytes::tls_deserialize(&mut rest).map_err(|_| Error::InvalidKeyPackage("init_key"))?;
    if init.as_slice().len() != HPKE_PUBLIC_KEY_LEN {
        return Err(Error::HpkeKeyLength);
    }
    check_tree_keys(std::iter::once(rest.to_vec()), std::iter::empty())
}

/// What a validated leaf tells us about its instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafInfo {
    pub identity: String,
    pub instance_id: u64,
    pub sig_key: Vec<u8>,
}

/// Validates a leaf against SPEC §3.1/§3.3: key lengths, basic credential
/// with an `ac:v0:` identity, capabilities, exactly one leaf extension
/// (`ac_instance_cert`), and the certificate binding.
pub(crate) fn validate_leaf(leaf: &LeafNode) -> Result<LeafInfo> {
    if encryption_key_len(leaf.encryption_key())? != HPKE_PUBLIC_KEY_LEN {
        return Err(Error::HpkeKeyLength);
    }
    let sig_key = leaf.signature_key().as_slice();
    if sig_key.len() != SIGNATURE_KEY_LEN {
        return Err(Error::CredentialMismatch("leaf signature key length"));
    }
    let credential = BasicCredential::try_from(leaf.credential().clone())
        .map_err(|_| Error::CredentialMismatch("not a basic credential"))?;
    let identity = std::str::from_utf8(credential.identity())
        .map_err(|_| Error::CredentialMismatch("credential identity"))?
        .to_owned();
    parse_identity(&identity).map_err(|_| Error::CredentialMismatch("credential identity"))?;

    let caps = leaf.capabilities();
    if !caps.ciphersuites().contains(&CS.into()) {
        return Err(Error::InvalidKeyPackage("capabilities: ciphersuite"));
    }
    if !ac_extension_types()
        .iter()
        .all(|t| caps.extensions().contains(t))
    {
        return Err(Error::InvalidKeyPackage("capabilities: extensions"));
    }

    let mut cert = None;
    for ext in leaf.extensions().iter() {
        match ext {
            Extension::Unknown(EXT_INSTANCE_CERT, UnknownExtension(b)) => cert = Some(b),
            _ => return Err(Error::InvalidKeyPackage("unexpected leaf extension")),
        }
    }
    let cert = InstanceCert::from_json(cert.ok_or(Error::InvalidCert("missing"))?)?;
    cert.verify_binding(identity.as_bytes(), sig_key)?;
    Ok(LeafInfo {
        identity,
        instance_id: cert.instance_id,
        sig_key: sig_key.to_vec(),
    })
}

/// SPEC §6.2 step 3: everything about a peer's KeyPackage, checked
/// before it is used for anything.
pub(crate) fn validate_key_package(
    crypto: &impl OpenMlsCrypto,
    bytes: &[u8],
) -> Result<(KeyPackage, LeafInfo)> {
    precheck_key_package(bytes)?;
    let kp = guard(|| {
        KeyPackageIn::tls_deserialize_exact(bytes)
            .map_err(|_| Error::InvalidKeyPackage("encoding"))?
            .validate(crypto, ProtocolVersion::Mls10)
            .map_err(|_| Error::InvalidKeyPackage("signature or lifetime"))
    })?;
    if kp.ciphersuite() != CS {
        return Err(Error::WrongCiphersuite);
    }
    if kp.hpke_init_key().as_slice().len() != HPKE_PUBLIC_KEY_LEN {
        return Err(Error::HpkeKeyLength);
    }
    if kp.extensions().iter().next().is_some() || kp.last_resort() {
        return Err(Error::InvalidKeyPackage("unexpected key package extension"));
    }
    let info = validate_leaf(kp.leaf_node())?;
    Ok((kp, info))
}

/// Mailbox id of a leaf.
pub(crate) fn leaf_mailbox(info: &LeafInfo) -> String {
    mailbox_id(&info.sig_key)
}

/// Runs OpenMLS code, turning a panic into an error. Defence in depth: the
/// key-length checks should prevent the known panics (SPEC §3.1), but a
/// panic must not take the daemon down. Storage may be partially written
/// when this triggers, so the affected group should be treated as broken.
pub(crate) fn guard<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err(Error::Internal("MLS library panicked")))
}

/// Adapts an [`crate::identity::Instance`] to OpenMLS's signer trait.
pub(crate) struct InstanceSigner<'a>(pub &'a crate::identity::Instance);

impl Signer for InstanceSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::prelude::tls_codec::Serialize as _;

    #[test]
    fn precheck_rejects_garbage_and_wrong_suite() {
        assert_eq!(
            precheck_key_package(&[0, 1]),
            Err(Error::InvalidKeyPackage("truncated"))
        );
        assert_eq!(
            precheck_key_package(&[0, 2, 0, 0x4f]),
            Err(Error::InvalidKeyPackage("protocol version"))
        );
        assert_eq!(
            precheck_key_package(&[0, 1, 0, 0x4d]),
            Err(Error::WrongCiphersuite)
        );
        assert_eq!(
            precheck_key_package(&[0, 1, 0, 0x4f]),
            Err(Error::InvalidKeyPackage("init_key"))
        );
        let mut short = vec![0, 1, 0, 0x4f];
        let short_key = crate::rng::Rng::for_test("short-key")
            .array::<32>()
            .unwrap();
        short.extend(
            VLBytes::new(short_key.to_vec())
                .tls_serialize_detached()
                .unwrap(),
        );
        assert_eq!(precheck_key_package(&short), Err(Error::HpkeKeyLength));
    }

    #[test]
    fn tree_key_checks() {
        let vl = |n: usize| VLBytes::new(vec![1; n]).tls_serialize_detached().unwrap();
        let leaf = |e: usize, s: usize| [vl(e), vl(s)].concat();
        check_tree_keys([leaf(1216, 32)].into_iter(), [vl(1216)].into_iter()).unwrap();
        assert_eq!(
            check_tree_keys([leaf(32, 32)].into_iter(), std::iter::empty()),
            Err(Error::HpkeKeyLength)
        );
        assert_eq!(
            check_tree_keys([leaf(1216, 33)].into_iter(), std::iter::empty()),
            Err(Error::CredentialMismatch("leaf signature key length"))
        );
        assert_eq!(
            check_tree_keys(std::iter::empty(), [vl(1215)].into_iter()),
            Err(Error::HpkeKeyLength)
        );
        assert_eq!(
            check_tree_keys([vec![0xff]].into_iter(), std::iter::empty()),
            Err(Error::Malformed("leaf"))
        );
        assert_eq!(
            check_tree_keys(std::iter::empty(), [vec![0xff]].into_iter()),
            Err(Error::Malformed("tls vector"))
        );
    }

    #[test]
    fn guard_turns_panics_into_errors() {
        let r: Result<()> = guard(|| panic!("boom"));
        assert_eq!(r, Err(Error::Internal("MLS library panicked")));
        assert_eq!(guard(|| Ok(1)), Ok(1));
    }
}
