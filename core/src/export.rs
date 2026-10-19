//! The identity export: `IK`'s secret wrapped for a replica's host (SPEC §9.4,
//! "Provisioning a replica").
//!
//! ```text
//! IdentityExport = JCS({"v": 0, "identity": "ac:v0:…",
//!                       "wrapped": b64url(nonce(12) ‖ ChaCha20-Poly1305(key, nonce,
//!                                  aad = "agentconnect/v0/identity-export", IK.secret))})
//! ```
//!
//! `key` is 32 fresh random bytes, given to the human once as the export
//! code (`b64url(key)`, 43 characters) to carry apart from the file. There
//! is no password KDF: the code has the full 256 bits. `identity` is the
//! one readable field, so a human can tell which identity a file holds;
//! after opening, the secret must give that identity, so a file whose
//! `identity` was changed doesn't open.
//!
//! Only the CLI uses it, on a stopped runtime's data directory (ADR-005).

use std::fmt;

use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::AeadType;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::encoding::{b64, b64_decode, b64_decode_secret, from_jcs, jcs};
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::rng::Rng;

/// The AEAD's associated data (SPEC §3.5, "Other labels").
pub const IDENTITY_EXPORT_AAD: &[u8] = b"agentconnect/v0/identity-export";

/// The largest export file accepted. A real one is about 130 bytes.
pub const MAX_EXPORT_LEN: usize = 4096;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SECRET_LEN: usize = 32;
const WRAPPED_LEN: usize = NONCE_LEN + SECRET_LEN + TAG_LEN;
const WHAT: &str = "identity export";
const CODE: &str = "export code";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportJson {
    v: u32,
    identity: String,
    wrapped: String,
}

/// A wrapped identity: the file to write and the code to show once.
pub struct IdentityExport {
    /// The file's bytes: the JCS object and a newline. Not secret on its
    /// own, but whoever also has the code holds the identity.
    pub file: Vec<u8>,
    /// The export code, `b64url(key)`. Show it once; never store it.
    pub code: Zeroizing<String>,
}

impl fmt::Debug for IdentityExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityExport").finish_non_exhaustive()
    }
}

/// Wraps `identity` under a fresh random key (the export code).
///
/// # Errors
///
/// [`Error::Rng`] or an AEAD failure.
pub fn wrap_identity_export(identity: &Identity, rng: &Rng) -> Result<IdentityExport> {
    let key = Zeroizing::new(rng.array::<32>()?);
    let nonce = rng.array::<NONCE_LEN>()?;
    wrap_with(identity, &key, &nonce)
}

pub(crate) fn wrap_with(
    identity: &Identity,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<IdentityExport> {
    let crypto = CryptoProvider::new().map_err(|_| Error::Rng)?;
    let secret = identity.secret_bytes();
    let ct = crypto
        .aead_encrypt(
            AeadType::ChaCha20Poly1305,
            key,
            secret.as_slice(),
            nonce,
            IDENTITY_EXPORT_AAD,
        )
        .map_err(|_| Error::Internal("identity export AEAD encryption failed"))?;
    let raw = ExportJson {
        v: 0,
        identity: identity.id(),
        wrapped: b64(&[nonce.as_slice(), &ct].concat()),
    };
    let mut file = jcs(&raw)?;
    file.push(b'\n');
    Ok(IdentityExport {
        file,
        code: Zeroizing::new(b64(key)),
    })
}

/// The identity an export file holds: its `identity` field, read without
/// the code, so the human can check the file before importing it.
///
/// # Errors
///
/// As [`unwrap_identity_export`], short of the code.
pub fn identity_export_identity(file: &[u8]) -> Result<String> {
    Ok(parse(file)?.identity)
}

/// Opens an export file with its code.
///
/// # Errors
///
/// - [`Error::UnsupportedVersion`] if `v` isn't 0;
/// - [`Error::Malformed`] if the file isn't a canonical export (wrong
///   fields, a truncated `wrapped`, larger than [`MAX_EXPORT_LEN`]) or the
///   code isn't 32 bytes of canonical base64url;
/// - [`Error::ExportAuth`] if it doesn't open under the code, or the
///   secret inside isn't the identity the file names (a wrong code or a
///   changed file).
pub fn unwrap_identity_export(file: &[u8], code: &str) -> Result<Identity> {
    let raw = parse(file)?;
    let wrapped = b64_decode(&raw.wrapped, WHAT)?;
    if wrapped.len() != WRAPPED_LEN {
        return Err(Error::Malformed(WHAT));
    }
    let key = b64_decode_secret::<32>(code.trim(), CODE)?;
    let (nonce, ct) = wrapped.split_at(NONCE_LEN);
    let crypto = CryptoProvider::new().map_err(|_| Error::Rng)?;
    let secret = Zeroizing::new(
        crypto
            .aead_decrypt(
                AeadType::ChaCha20Poly1305,
                key.as_slice(),
                ct,
                nonce,
                IDENTITY_EXPORT_AAD,
            )
            .map_err(|_| Error::ExportAuth)?,
    );
    // WRAPPED_LEN leaves exactly SECRET_LEN bytes of plaintext.
    let mut seed = Zeroizing::new([0u8; SECRET_LEN]);
    seed.copy_from_slice(&secret);
    let identity = Identity::from_secret_bytes(&seed);
    if identity.id() != raw.identity {
        return Err(Error::ExportAuth);
    }
    Ok(identity)
}

fn parse(file: &[u8]) -> Result<ExportJson> {
    if file.len() > MAX_EXPORT_LEN {
        return Err(Error::Malformed(WHAT));
    }
    let text = file.trim_ascii_end();
    // The version first, so a later format reads as one, not as garbage.
    // Only a non-negative integer names a version; `-0`, `0.0` and the
    // like are malformed (and never canonical).
    let value: Value = serde_json::from_slice(text).map_err(|_| Error::Malformed(WHAT))?;
    match value.get("v").and_then(Value::as_number) {
        Some(n) if n.is_u64() => {
            if n.as_u64() != Some(0) {
                return Err(Error::UnsupportedVersion);
            }
        }
        _ => return Err(Error::Malformed(WHAT)),
    }
    from_jcs(text, WHAT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(label: &str) -> Identity {
        Identity::generate(&Rng::for_test(label)).unwrap()
    }

    fn export(label: &str) -> (Identity, IdentityExport) {
        let ik = identity(label);
        let out = wrap_identity_export(&ik, &Rng::for_test(&format!("{label}/wrap"))).unwrap();
        (ik, out)
    }

    fn with_field(file: &[u8], key: &str, value: Value) -> Vec<u8> {
        let mut v: Value = serde_json::from_slice(file).unwrap();
        v[key] = value;
        jcs(&v).unwrap()
    }

    #[test]
    fn an_export_opens_under_its_code_to_the_same_identity() {
        let (ik, out) = export("roundtrip");
        assert_eq!(out.code.len(), 43);
        assert!(out.file.ends_with(b"\n"));
        let back = unwrap_identity_export(&out.file, &out.code).unwrap();
        assert_eq!(back.id(), ik.id());
        assert_eq!(*back.secret_bytes(), *ik.secret_bytes());
        assert_eq!(identity_export_identity(&out.file).unwrap(), ik.id());
        // Whitespace around the code and a missing final newline are fine.
        let padded = format!("  {}\n", out.code.as_str());
        let bare = &out.file[..out.file.len() - 1];
        assert_eq!(unwrap_identity_export(bare, &padded).unwrap().id(), ik.id());
    }

    #[test]
    fn the_file_never_holds_the_secret_or_the_code() {
        let (ik, out) = export("no-secret");
        let text = String::from_utf8(out.file.clone()).unwrap();
        assert!(!text.contains(&b64(ik.secret_bytes().as_slice())));
        assert!(!text.contains(out.code.as_str()));
        assert_eq!(format!("{out:?}"), "IdentityExport { .. }");
        // Two exports of one identity share nothing but the identity.
        let again = wrap_identity_export(&ik, &Rng::for_test("no-secret/again")).unwrap();
        assert_ne!(again.file, out.file);
        assert_ne!(again.code, out.code);
    }

    #[test]
    fn a_wrong_code_does_not_open_it() {
        let (_, out) = export("wrong-code");
        let (_, other) = export("wrong-code/other");
        assert_eq!(
            unwrap_identity_export(&out.file, &other.code).unwrap_err(),
            Error::ExportAuth
        );
    }

    #[test]
    fn a_changed_ciphertext_nonce_or_identity_does_not_open() {
        let (_, out) = export("tamper");
        let v: Value = serde_json::from_slice(&out.file).unwrap();
        let wrapped = b64_decode(v["wrapped"].as_str().unwrap(), "w").unwrap();
        for i in [0, NONCE_LEN, WRAPPED_LEN - 1] {
            let mut bad = wrapped.clone();
            bad[i] ^= 1;
            let file = with_field(&out.file, "wrapped", Value::String(b64(&bad)));
            assert_eq!(
                unwrap_identity_export(&file, &out.code).unwrap_err(),
                Error::ExportAuth,
                "byte {i}"
            );
        }
        let file = with_field(&out.file, "identity", Value::String(identity("x").id()));
        assert_eq!(
            unwrap_identity_export(&file, &out.code).unwrap_err(),
            Error::ExportAuth
        );
    }

    #[test]
    fn a_truncated_export_is_malformed() {
        let (_, out) = export("truncated");
        for cut in [1, 10, out.file.len() / 2, out.file.len() - 3] {
            assert_eq!(
                unwrap_identity_export(&out.file[..cut], &out.code).unwrap_err(),
                Error::Malformed(WHAT),
                "cut at {cut}"
            );
        }
        let v: Value = serde_json::from_slice(&out.file).unwrap();
        let wrapped = b64_decode(v["wrapped"].as_str().unwrap(), "w").unwrap();
        for len in [0, NONCE_LEN + TAG_LEN, WRAPPED_LEN - 1] {
            let file = with_field(&out.file, "wrapped", Value::String(b64(&wrapped[..len])));
            assert_eq!(
                unwrap_identity_export(&file, &out.code).unwrap_err(),
                Error::Malformed(WHAT)
            );
        }
        assert_eq!(
            unwrap_identity_export(&[b' '; MAX_EXPORT_LEN + 1], &out.code).unwrap_err(),
            Error::Malformed(WHAT)
        );
    }

    #[test]
    fn another_format_version_is_refused_as_unsupported() {
        let (_, out) = export("version");
        for v in [1u64, 2, u64::from(u32::MAX) + 1] {
            let file = with_field(&out.file, "v", Value::from(v));
            assert_eq!(
                unwrap_identity_export(&file, &out.code).unwrap_err(),
                Error::UnsupportedVersion
            );
        }
        // A version that isn't a non-negative integer, or none at all, is
        // malformed: only an integer names a format version.
        for v in [Value::String("0".into()), Value::Null] {
            let file = with_field(&out.file, "v", v);
            assert_eq!(
                unwrap_identity_export(&file, &out.code).unwrap_err(),
                Error::Malformed(WHAT)
            );
        }
        let text = String::from_utf8(out.file.clone()).unwrap();
        for v in ["-0", "0.0", "1.0", "-1", "1e0"] {
            let file = text.replace("\"v\":0", &format!("\"v\":{v}"));
            assert_eq!(
                unwrap_identity_export(file.as_bytes(), &out.code).unwrap_err(),
                Error::Malformed(WHAT),
                "{v}"
            );
        }
        let mut v: Value = serde_json::from_slice(&out.file).unwrap();
        v.as_object_mut().unwrap().remove("v");
        assert_eq!(
            unwrap_identity_export(&jcs(&v).unwrap(), &out.code).unwrap_err(),
            Error::Malformed(WHAT)
        );
    }

    #[test]
    fn extra_fields_and_other_encodings_are_malformed() {
        let (_, out) = export("shape");
        let file = with_field(&out.file, "note", Value::String("x".into()));
        assert_eq!(
            unwrap_identity_export(&file, &out.code).unwrap_err(),
            Error::Malformed(WHAT)
        );
        let v: Value = serde_json::from_slice(&out.file).unwrap();
        let pretty = serde_json::to_vec_pretty(&v).unwrap();
        assert_eq!(
            unwrap_identity_export(&pretty, &out.code).unwrap_err(),
            Error::Malformed(WHAT)
        );
        for file in [&b"[]"[..], b"0", b"{}", b"not json"] {
            assert_eq!(
                unwrap_identity_export(file, &out.code).unwrap_err(),
                Error::Malformed(WHAT)
            );
        }
    }

    #[test]
    fn a_code_of_the_wrong_shape_is_malformed() {
        let (_, out) = export("code");
        let short = &out.code[..42];
        let padded = format!("{}=", out.code.as_str());
        let standard = out.code.replace(['-', '_'], "+");
        for code in ["", short, &padded, "!".repeat(43).as_str()] {
            assert_eq!(
                unwrap_identity_export(&out.file, code).unwrap_err(),
                Error::Malformed(CODE),
                "{code:?}"
            );
        }
        // Standard base64 differs only where the code has '-' or '_'.
        if standard != *out.code {
            assert!(unwrap_identity_export(&out.file, &standard).is_err());
        }
    }
}
