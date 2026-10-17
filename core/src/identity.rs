//! Identities, instances and instance certificates (SPEC §2, §3.3).

use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::encoding::{
    b64, b64_decode_array, b64_decode_secret, from_jcs, hex, hex_decode, jcs, jcs_string,
};
use crate::error::{Error, Result};
use crate::rng::Rng;

/// Prefix of every identity identifier (SPEC §2).
pub const IDENTITY_PREFIX: &str = "ac:v0:";

const CERT_LABEL: &[u8] = b"agentconnect/v0/instance-cert";

/// Parses an identity identifier `ac:v0:<b64url IK.pub>` into the public key.
///
/// # Errors
///
/// [`Error::Malformed`] if the prefix, encoding or Ed25519 point is invalid.
pub fn parse_identity(id: &str) -> Result<[u8; 32]> {
    let rest = id
        .strip_prefix(IDENTITY_PREFIX)
        .ok_or(Error::Malformed("identity"))?;
    let key: [u8; 32] = b64_decode_array(rest, "identity")?;
    VerifyingKey::from_bytes(&key).map_err(|_| Error::Malformed("identity"))?;
    Ok(key)
}

/// The identifier `ac:v0:<b64url IK.pub>` for an identity public key.
#[must_use]
pub fn identity_id(ik_pub: &[u8; 32]) -> String {
    format!("{IDENTITY_PREFIX}{}", b64(ik_pub))
}

/// Fingerprint of an identity public key: the first 16 bytes of
/// SHA-256(IK.pub) as 8 space-separated groups of 4 lowercase hex characters
/// (SPEC §2).
#[must_use]
pub fn fingerprint(ik_pub: &[u8; 32]) -> String {
    let digest = Sha256::digest(ik_pub);
    let h = hex(&digest[..16]);
    let groups: Vec<&str> = (0..8).map(|i| &h[i * 4..i * 4 + 4]).collect();
    groups.join(" ")
}

/// Mailbox id for an instance signing key: base64url(SHA-256(SK.pub))[0..22]
/// (SPEC §2).
#[must_use]
pub fn mailbox_id(sig_key: &[u8]) -> String {
    let mut s = b64(&Sha256::digest(sig_key));
    s.truncate(22);
    s
}

/// A long-lived identity key `IK` (SPEC §2).
///
/// The secret key is zeroized on drop and never shown by `Debug`.
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    /// A fresh identity.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the randomness source fails.
    pub fn generate(rng: &Rng) -> Result<Self> {
        let seed = Zeroizing::new(rng.array::<32>()?);
        Ok(Self::from_secret_bytes(&seed))
    }

    /// Restores an identity from its 32-byte secret (as returned by
    /// [`Identity::secret_bytes`]).
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(secret),
        }
    }

    /// The 32-byte secret, for the daemon to store (encrypted) at rest.
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes())
    }

    /// `IK.pub`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The identifier `ac:v0:…`.
    #[must_use]
    pub fn id(&self) -> String {
        identity_id(&self.public_key())
    }

    /// The fingerprint shown to humans (SPEC §2).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key())
    }

    /// Creates a new instance of this identity: a fresh signing key `SK`, a
    /// random 64-bit `instance_id` and an [`InstanceCert`] signed by `IK`.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the randomness source fails.
    pub fn create_instance(&self, rng: &Rng, clock: &dyn Clock) -> Result<Instance> {
        let seed = Zeroizing::new(rng.array::<32>()?);
        let instance_id = u64::from_be_bytes(rng.array::<8>()?);
        let key = SigningKey::from_bytes(&seed);
        let mut cert = InstanceCert {
            identity: self.id(),
            instance_id,
            sig_key: key.verifying_key().to_bytes(),
            created_at: clock.unix_millis() / 1000,
            sig: [0; 64],
        };
        cert.sig = self.key.sign(&cert.signing_input()?).to_bytes();
        Ok(Instance { key, cert })
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").field("id", &self.id()).finish()
    }
}

/// An instance certificate binding `SK.pub` to `IK` (SPEC §3.3).
#[derive(Clone, PartialEq, Eq)]
pub struct InstanceCert {
    /// `ac:v0:<b64url IK.pub>`.
    pub identity: String,
    /// The random 64-bit instance id.
    pub instance_id: u64,
    /// `SK.pub`.
    pub sig_key: [u8; 32],
    /// Creation time, Unix seconds.
    pub created_at: u64,
    /// Ed25519 signature by `IK`.
    pub sig: [u8; 64],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertJson {
    v: u32,
    identity: String,
    instance_id: String,
    sig_key: String,
    created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
}

impl InstanceCert {
    fn json(&self, with_sig: bool) -> CertJson {
        CertJson {
            v: 0,
            identity: self.identity.clone(),
            instance_id: hex(&self.instance_id.to_be_bytes()),
            sig_key: b64(&self.sig_key),
            created_at: self.created_at,
            sig: with_sig.then(|| b64(&self.sig)),
        }
    }

    /// The signed message: `"agentconnect/v0/instance-cert" ‖ JCS(cert without "sig")`.
    ///
    /// # Errors
    ///
    /// Only if JSON serialisation fails, which can't happen for this type.
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        Ok([CERT_LABEL, &jcs(&self.json(false))?].concat())
    }

    /// The JCS encoding carried in the `ac_instance_cert` leaf extension.
    ///
    /// # Errors
    ///
    /// Only if JSON serialisation fails, which can't happen for this type.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        jcs(&self.json(true))
    }

    /// Parses a certificate. The encoding must be canonical JCS, `v` must be
    /// 0 and no unknown fields are accepted. This does **not** verify the
    /// signature; use [`InstanceCert::verify`].
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`] or [`Error::InvalidCert`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let raw: CertJson =
            from_jcs(bytes, "instance cert").map_err(|_| Error::InvalidCert("encoding"))?;
        if raw.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        if raw.instance_id.len() != 16 {
            return Err(Error::InvalidCert("instance_id"));
        }
        let id_bytes: [u8; 8] = hex_decode(&raw.instance_id, "instance_id")
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::InvalidCert("instance_id"))?;
        let sig = raw.sig.ok_or(Error::InvalidCert("missing sig"))?;
        Ok(Self {
            identity: raw.identity,
            instance_id: u64::from_be_bytes(id_bytes),
            sig_key: b64_decode_array(&raw.sig_key, "sig_key")
                .map_err(|_| Error::InvalidCert("sig_key"))?,
            created_at: raw.created_at,
            sig: b64_decode_array(&sig, "sig").map_err(|_| Error::InvalidCert("sig"))?,
        })
    }

    /// Verifies the signature under the IK encoded in `identity`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCert`] if `identity` isn't a valid identifier or the
    /// signature doesn't verify.
    pub fn verify(&self) -> Result<()> {
        let ik = parse_identity(&self.identity).map_err(|_| Error::InvalidCert("identity"))?;
        let ik = VerifyingKey::from_bytes(&ik).map_err(|_| Error::InvalidCert("identity"))?;
        ik.verify_strict(&self.signing_input()?, &Signature::from_bytes(&self.sig))
            .map_err(|_| Error::InvalidCert("signature"))
    }

    /// All receiver checks of SPEC §3.3: the signature verifies,
    /// `identity` equals the credential identity and `sig_key` equals the
    /// leaf signature key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCert`] or [`Error::CredentialMismatch`].
    pub fn verify_binding(&self, credential_identity: &[u8], leaf_sig_key: &[u8]) -> Result<()> {
        self.verify()?;
        if self.identity.as_bytes() != credential_identity {
            return Err(Error::CredentialMismatch("cert identity != credential"));
        }
        if self.sig_key.as_slice() != leaf_sig_key {
            return Err(Error::CredentialMismatch("cert sig_key != leaf key"));
        }
        Ok(())
    }

    /// The instance id as 16 lowercase hex characters.
    #[must_use]
    pub fn instance_id_hex(&self) -> String {
        hex(&self.instance_id.to_be_bytes())
    }
}

impl fmt::Debug for InstanceCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstanceCert")
            .field("identity", &self.identity)
            .field("instance_id", &self.instance_id_hex())
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// One running copy of an identity: signing key `SK` plus its certificate
/// (SPEC §2). Each instance is one MLS leaf.
pub struct Instance {
    key: SigningKey,
    cert: InstanceCert,
}

/// The parsed form of [`Instance::to_secret_bytes`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceIn<'a> {
    v: u32,
    sk: &'a str,
    cert: String,
}

impl Instance {
    /// The identity this instance belongs to.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.cert.identity
    }

    /// The 64-bit instance id.
    #[must_use]
    pub fn instance_id(&self) -> u64 {
        self.cert.instance_id
    }

    /// The instance certificate.
    #[must_use]
    pub fn cert(&self) -> &InstanceCert {
        &self.cert
    }

    /// `SK.pub`, the MLS leaf signature key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.cert.sig_key
    }

    /// This instance's relay mailbox id (SPEC §2).
    #[must_use]
    pub fn mailbox_id(&self) -> String {
        mailbox_id(&self.cert.sig_key)
    }

    /// Signs `msg` with `SK`.
    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }

    /// Serialises the instance (secret key and certificate) so the daemon can
    /// store it. **Contains secret key material**: encrypt it at rest.
    ///
    /// # Errors
    ///
    /// Only if JSON serialisation fails, which can't happen for this type.
    pub fn to_secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        // JCS of {"cert": <cert JSON as a string>, "sk": <b64url SK>, "v": 0},
        // written by hand into one zeroizing buffer of the exact size so the
        // secret key never lands in a temporary `String` or `Value`.
        let cert = String::from_utf8(self.cert.to_json()?)
            .map_err(|_| Error::Internal("cert json is not utf-8"))?;
        let cert = jcs_string(&cert);
        let mut sk = Zeroizing::new([0u8; 43]);
        let sk = Base64UrlUnpadded::encode(self.key.as_bytes(), sk.as_mut_slice())
            .map_err(|_| Error::Internal("instance key encoding"))?;
        let parts: [&[u8]; 5] = [
            b"{\"cert\":",
            cert.as_bytes(),
            b",\"sk\":\"",
            sk.as_bytes(),
            b"\",\"v\":0}",
        ];
        let mut out = Zeroizing::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum()));
        for p in parts {
            out.extend_from_slice(p);
        }
        Ok(out)
    }

    /// Restores an instance from [`Instance::to_secret_bytes`]. The input
    /// must be exactly that canonical encoding; the certificate is
    /// re-verified and must match the key.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::InvalidCert`] or
    /// [`Error::CredentialMismatch`].
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        // `sk` is borrowed from `bytes` (canonical base64url has no escapes),
        // so parsing makes no copy of the secret key.
        let raw: InstanceIn<'_> =
            serde_json::from_slice(bytes).map_err(|_| Error::Malformed("instance"))?;
        if raw.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        let sk = b64_decode_secret::<32>(raw.sk, "instance key")?;
        let key = SigningKey::from_bytes(&sk);
        let cert = InstanceCert::from_json(raw.cert.as_bytes())?;
        cert.verify()?;
        if cert.sig_key != key.verifying_key().to_bytes() {
            return Err(Error::CredentialMismatch("instance key != cert sig_key"));
        }
        let instance = Self { key, cert };
        // Canonical form: exactly what `to_secret_bytes` writes.
        if instance.to_secret_bytes()?.as_slice() != bytes {
            return Err(Error::Malformed("instance"));
        }
        Ok(instance)
    }
}

impl fmt::Debug for Instance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Instance")
            .field("identity", &self.cert.identity)
            .field("instance_id", &self.cert.instance_id_hex())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use serde::Serialize;

    fn instance() -> (Identity, Instance) {
        let rng = Rng::for_test("seed-1");
        let id = Identity::generate(&rng).unwrap();
        let inst = id.create_instance(&rng, &FakeClock::default()).unwrap();
        (id, inst)
    }

    #[test]
    fn identity_id_round_trips() {
        let (id, _) = instance();
        let s = id.id();
        assert!(s.starts_with("ac:v0:"));
        assert_eq!(s.len(), 6 + 43);
        assert_eq!(parse_identity(&s).unwrap(), id.public_key());
        for bad in ["ac:v1:AAAA", "ac:v0:", "ac:v0:!!", "x"] {
            assert_eq!(parse_identity(bad), Err(Error::Malformed("identity")));
        }
        let restored = Identity::from_secret_bytes(&id.secret_bytes());
        assert_eq!(restored.id(), s);
    }

    #[test]
    fn debug_output_has_no_secrets() {
        let (id, inst) = instance();
        let secret = b64(id.secret_bytes().as_slice());
        let dbg = format!("{id:?} {inst:?} {:?}", inst.cert());
        assert!(!dbg.contains(&secret));
        assert!(dbg.contains(&id.id()));
        assert!(!dbg.contains("sig:"));
    }

    #[test]
    fn fingerprint_and_mailbox_shape() {
        let (id, inst) = instance();
        let fp = id.fingerprint();
        assert_eq!(fp.len(), 8 * 4 + 7);
        assert_eq!(fp.split(' ').count(), 8);
        assert_eq!(inst.mailbox_id().len(), 22);
    }

    #[test]
    fn cert_verifies_and_round_trips() {
        let (id, inst) = instance();
        let cert = inst.cert();
        assert_eq!(cert.identity, id.id());
        assert_eq!(cert.created_at, 1_735_689_600);
        cert.verify().unwrap();
        let parsed = InstanceCert::from_json(&cert.to_json().unwrap()).unwrap();
        assert_eq!(&parsed, cert);
        cert.verify_binding(id.id().as_bytes(), &inst.public_key())
            .unwrap();
    }

    #[test]
    fn cert_binding_checks_identity_and_key() {
        let (_, inst) = instance();
        let cert = inst.cert();
        let other = Identity::generate(&Rng::for_test("seed-9")).unwrap();
        assert_eq!(
            cert.verify_binding(other.id().as_bytes(), &inst.public_key()),
            Err(Error::CredentialMismatch("cert identity != credential"))
        );
        assert_eq!(
            cert.verify_binding(cert.identity.as_bytes(), &other.public_key()),
            Err(Error::CredentialMismatch("cert sig_key != leaf key"))
        );
    }

    #[test]
    fn tampered_cert_is_rejected() {
        let (_, inst) = instance();
        let mut cert = inst.cert().clone();
        cert.created_at += 1;
        assert_eq!(cert.verify(), Err(Error::InvalidCert("signature")));
        let mut cert = inst.cert().clone();
        cert.identity = Identity::generate(&Rng::for_test("seed-3")).unwrap().id();
        assert_eq!(cert.verify(), Err(Error::InvalidCert("signature")));
        cert.identity = "nope".into();
        assert_eq!(cert.verify(), Err(Error::InvalidCert("identity")));
    }

    #[test]
    fn cert_parsing_is_strict() {
        let (_, inst) = instance();
        let good = String::from_utf8(inst.cert().to_json().unwrap()).unwrap();
        let cases = [
            (
                good.replace("\"v\":0", "\"v\":1"),
                Error::UnsupportedVersion,
            ),
            (
                good.replace(",\"sig\"", " ,\"sig\""),
                Error::InvalidCert("encoding"),
            ),
            (
                good.replace("\"v\":0", "\"v\":0,\"x\":1"),
                Error::InvalidCert("encoding"),
            ),
        ];
        for (bad, err) in cases {
            assert_eq!(InstanceCert::from_json(bad.as_bytes()), Err(err), "{bad}");
        }
        let id_hex = inst.cert().instance_id_hex();
        let bad = good.replace(&id_hex, &id_hex[..14]);
        assert_eq!(
            InstanceCert::from_json(bad.as_bytes()),
            Err(Error::InvalidCert("instance_id"))
        );
        let bad = good.replace(&id_hex, "zzzzzzzzzzzzzzzz");
        assert_eq!(
            InstanceCert::from_json(bad.as_bytes()),
            Err(Error::InvalidCert("instance_id"))
        );
        let mut no_sig = inst.cert().json(false);
        no_sig.sig = None;
        assert_eq!(
            InstanceCert::from_json(&jcs(&no_sig).unwrap()),
            Err(Error::InvalidCert("missing sig"))
        );
        let mut bad_key = inst.cert().json(true);
        bad_key.sig_key = "AA".into();
        assert_eq!(
            InstanceCert::from_json(&jcs(&bad_key).unwrap()),
            Err(Error::InvalidCert("sig_key"))
        );
        let mut bad_sig = inst.cert().json(true);
        bad_sig.sig = Some("AA".into());
        assert_eq!(
            InstanceCert::from_json(&jcs(&bad_sig).unwrap()),
            Err(Error::InvalidCert("sig"))
        );
    }

    /// SPEC §3.2: integers are capped at the I-JSON range.
    #[test]
    fn cert_created_at_beyond_i_json_range_is_rejected() {
        let (_, inst) = instance();
        let good = String::from_utf8(inst.cert().to_json().unwrap()).unwrap();
        let created = inst.cert().created_at.to_string();
        let max = crate::encoding::MAX_SAFE_INTEGER;
        let at = |n: u64| good.replace(&created, &n.to_string());
        // At the cap it parses (the signature no longer matches, but the
        // encoding is accepted).
        assert_eq!(
            InstanceCert::from_json(at(max).as_bytes())
                .unwrap()
                .created_at,
            max
        );
        assert_eq!(
            InstanceCert::from_json(at(max + 1).as_bytes()),
            Err(Error::InvalidCert("encoding"))
        );
        let mut far = inst.cert().clone();
        far.created_at = max + 1;
        assert!(far.to_json().is_err());
        assert!(far.signing_input().is_err());
    }

    #[test]
    fn instance_secret_bytes_round_trip() {
        let (_, inst) = instance();
        let bytes = inst.to_secret_bytes().unwrap();
        let back = Instance::from_secret_bytes(&bytes).unwrap();
        assert_eq!(back.cert(), inst.cert());
        assert_eq!(back.sign(b"m"), inst.sign(b"m"));
        assert_eq!(back.identity(), inst.identity());
        assert_eq!(back.instance_id(), inst.instance_id());
    }

    #[derive(Serialize)]
    struct InstanceJson {
        v: u32,
        sk: String,
        cert: String,
    }

    /// The hand-written encoding (no secret in a temporary `Value`) is
    /// byte-for-byte the generic JCS one, and parsing accepts nothing else.
    #[test]
    fn instance_secret_bytes_are_canonical_jcs() {
        let (_, inst) = instance();
        let json = InstanceJson {
            v: 0,
            sk: b64(inst.key.as_bytes()),
            cert: String::from_utf8(inst.cert().to_json().unwrap()).unwrap(),
        };
        let canonical = jcs(&json).unwrap();
        assert_eq!(inst.to_secret_bytes().unwrap().as_slice(), canonical);
        let s = String::from_utf8(canonical).unwrap();
        let first = &json.sk[..1];
        let escaped = format!("\\u{:04x}", u32::from(first.as_bytes()[0]));
        for bad in [
            s.replacen("{\"cert\":", "{ \"cert\":", 1),
            s.replacen(",\"v\":0}", ",\"v\":0,\"x\":1}", 1),
            s.replacen(
                &format!("\"sk\":\"{first}"),
                &format!("\"sk\":\"{escaped}"),
                1,
            ),
            format!("{{\"v\":0,{}", &s[1..s.len() - 7]) + "}",
        ] {
            assert_eq!(
                Instance::from_secret_bytes(bad.as_bytes()).unwrap_err(),
                Error::Malformed("instance"),
                "{bad}"
            );
        }
    }

    #[test]
    fn instance_with_foreign_cert_is_rejected() {
        let (_, a) = instance();
        let other = Identity::generate(&Rng::for_test("seed-5")).unwrap();
        let b = other
            .create_instance(&Rng::for_test("seed-6"), &FakeClock::default())
            .unwrap();
        let json = InstanceJson {
            v: 0,
            sk: b64(a.key.as_bytes()),
            cert: String::from_utf8(b.cert().to_json().unwrap()).unwrap(),
        };
        assert_eq!(
            Instance::from_secret_bytes(&jcs(&json).unwrap()).unwrap_err(),
            Error::CredentialMismatch("instance key != cert sig_key")
        );
        let json = InstanceJson { v: 1, ..json };
        assert_eq!(
            Instance::from_secret_bytes(&jcs(&json).unwrap()).unwrap_err(),
            Error::UnsupportedVersion
        );
    }
}
