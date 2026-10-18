//! Invites: URL format, key derivation and the AEAD-wrapped Welcome
//! (SPEC §3.5, §4, §6.4).

use std::fmt;
use std::time::Duration;

use hkdf::Hkdf;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::AeadType;
use serde::Deserialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::encoding::{b64, b64_decode_array, b64_decode_secret};
use crate::error::{Error, Result};
use crate::rng::Rng;

/// Length of `invite_id` in bytes (SPEC §4.1).
pub const INVITE_ID_LEN: usize = 16;
/// Length of `invite_secret` in bytes (SPEC §4.1).
pub const INVITE_SECRET_LEN: usize = 32;
/// Default invite lifetime (SPEC §4.3).
pub const DEFAULT_TTL: Duration = Duration::from_hours(24);
/// Maximum invite lifetime (SPEC §4.3).
pub const MAX_TTL: Duration = Duration::from_hours(7 * 24);

const JOIN_INFO: &[u8] = b"agentconnect/v0/join";
const WELCOME_INFO: &[u8] = b"agentconnect/v0/welcome";
const WELCOME_AAD_LABEL: &[u8] = b"agentconnect/v0/welcome";
pub(crate) const NONCE_LEN: usize = 12;

pub(crate) fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below HKDF-SHA256's 8160-byte limit, so this can't fail.
    if Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.as_mut_slice())
        .is_err()
    {
        unreachable!("HKDF-SHA256 output of 32 bytes is always valid");
    }
    out
}

/// `join_key` = HKDF(ikm = `invite_secret`, salt = `invite_id`,
/// info = "agentconnect/v0/join", L = 32) (SPEC §3.5).
#[must_use]
pub fn derive_join_key(invite_id: &[u8; 16], invite_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(invite_secret, invite_id, JOIN_INFO)
}

/// `welcome_key` = HKDF(ikm = `invite_secret`, salt = `invite_id`,
/// info = "agentconnect/v0/welcome", L = 32) (SPEC §3.5).
#[must_use]
pub fn derive_welcome_key(invite_id: &[u8; 16], invite_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(invite_secret, invite_id, WELCOME_INFO)
}

/// The capability part of an invite: `invite_id` and `invite_secret`.
///
/// The secret is zeroized on drop and never shown by `Debug`.
#[derive(Clone)]
pub struct InviteSecret {
    id: [u8; 16],
    secret: Zeroizing<[u8; 32]>,
}

impl InviteSecret {
    /// From raw parts. The secret is copied into a zeroizing buffer; the
    /// caller keeps (and should zeroize) its own copy.
    #[must_use]
    pub fn from_parts(id: [u8; 16], secret: &[u8; 32]) -> Self {
        let mut copy = Zeroizing::new([0u8; 32]);
        copy.copy_from_slice(secret);
        Self { id, secret: copy }
    }

    /// A fresh random invite id and secret.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the randomness source fails.
    pub fn generate(rng: &Rng) -> Result<Self> {
        Ok(Self {
            id: rng.array()?,
            secret: Zeroizing::new(rng.array()?),
        })
    }

    /// The public `invite_id`.
    #[must_use]
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// The `invite_id` as base64url (22 characters).
    #[must_use]
    pub fn id_b64(&self) -> String {
        b64(&self.id)
    }

    /// The secret. Handle with care: it must only ever appear in the URL
    /// fragment.
    #[must_use]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// `join_key` (SPEC §3.5).
    #[must_use]
    pub fn join_key(&self) -> Zeroizing<[u8; 32]> {
        derive_join_key(&self.id, &self.secret)
    }

    /// `welcome_key` (SPEC §3.5).
    #[must_use]
    pub fn welcome_key(&self) -> Zeroizing<[u8; 32]> {
        derive_welcome_key(&self.id, &self.secret)
    }

    fn welcome_aad(&self) -> Vec<u8> {
        [WELCOME_AAD_LABEL, &self.id].concat()
    }

    /// `WrappedWelcome = nonce(12) ‖ ChaCha20-Poly1305(welcome_key, nonce,
    /// aad = "agentconnect/v0/welcome" ‖ invite_id, welcome)` (SPEC §6.4),
    /// with a fresh random nonce.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] or an AEAD failure.
    pub fn wrap_welcome(&self, rng: &Rng, welcome: &[u8]) -> Result<Vec<u8>> {
        self.wrap_welcome_with_nonce(&rng.array()?, welcome)
    }

    pub(crate) fn wrap_welcome_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        welcome: &[u8],
    ) -> Result<Vec<u8>> {
        seal_wrapped_welcome(&self.welcome_key(), &self.welcome_aad(), nonce, welcome)
    }

    /// Opens a `WrappedWelcome` (SPEC §6.3, first check).
    ///
    /// # Errors
    ///
    /// [`Error::WelcomeAuth`] if the input is too short or doesn't
    /// authenticate under this invite's `welcome_key`.
    pub fn unwrap_welcome(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        open_wrapped_welcome(&self.welcome_key(), &self.welcome_aad(), wrapped)
    }
}

/// The SPEC §6.4 `WrappedWelcome` under any `welcome_key` and AAD:
/// `nonce(12) ‖ ChaCha20-Poly1305(key, nonce, aad, welcome)`. Invites and
/// knocks (§6.6) differ only in the key and the AAD.
pub(crate) fn seal_wrapped_welcome(
    key: &[u8; 32],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
    welcome: &[u8],
) -> Result<Vec<u8>> {
    let crypto = CryptoProvider::new().map_err(|_| Error::Rng)?;
    let ct = crypto
        .aead_encrypt(AeadType::ChaCha20Poly1305, key, welcome, nonce, aad)
        .map_err(|_| Error::Internal("welcome AEAD encryption failed"))?;
    Ok([nonce.as_slice(), &ct].concat())
}

/// Opens a [`seal_wrapped_welcome`] output.
///
/// # Errors
///
/// [`Error::WelcomeAuth`] if `wrapped` is shorter than nonce plus tag or
/// doesn't authenticate.
pub(crate) fn open_wrapped_welcome(key: &[u8; 32], aad: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < NONCE_LEN + 16 {
        return Err(Error::WelcomeAuth);
    }
    let (nonce, ct) = wrapped.split_at(NONCE_LEN);
    let crypto = CryptoProvider::new().map_err(|_| Error::Rng)?;
    crypto
        .aead_decrypt(AeadType::ChaCha20Poly1305, key, ct, nonce, aad)
        .map_err(|_| Error::WelcomeAuth)
}

impl fmt::Debug for InviteSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteSecret")
            .field("id", &self.id_b64())
            .finish_non_exhaustive()
    }
}

/// An invite as held by the instance that created it (SPEC §4.3).
///
/// Use counting (`max_uses`, `uses_left`) is tracked by the daemon and the
/// relay; `core` only checks expiry.
#[derive(Clone, Debug)]
pub struct Invite {
    relay_host: String,
    secret: InviteSecret,
    expires_at: u64,
}

impl Invite {
    /// Creates an invite for `relay_host` that expires after `ttl` (at most
    /// [`MAX_TTL`]).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInviteUrl`] for a bad host, [`Error::NotPermitted`]
    /// if `ttl` is zero or longer than [`MAX_TTL`], [`Error::Rng`].
    pub fn create(rng: &Rng, clock: &dyn Clock, relay_host: &str, ttl: Duration) -> Result<Self> {
        check_host(relay_host)?;
        if ttl.is_zero() || ttl > MAX_TTL {
            return Err(Error::NotPermitted("invite ttl must be within 7 days"));
        }
        Ok(Self {
            relay_host: relay_host.to_owned(),
            secret: InviteSecret::generate(rng)?,
            expires_at: clock.unix_millis() / 1000 + ttl.as_secs(),
        })
    }

    /// Restores an invite the daemon stored.
    #[must_use]
    pub fn from_parts(relay_host: String, secret: InviteSecret, expires_at: u64) -> Self {
        Self {
            relay_host,
            secret,
            expires_at,
        }
    }

    /// The relay host.
    #[must_use]
    pub fn relay_host(&self) -> &str {
        &self.relay_host
    }

    /// Id and secret.
    #[must_use]
    pub fn secret(&self) -> &InviteSecret {
        &self.secret
    }

    /// Expiry, Unix seconds.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Whether the invite has expired at the clock's current time.
    #[must_use]
    pub fn is_expired(&self, clock: &dyn Clock) -> bool {
        clock.unix_millis() / 1000 >= self.expires_at
    }

    /// The invite URL (SPEC §4.1).
    #[must_use]
    pub fn url(&self) -> String {
        format_url(&self.relay_host, &self.secret)
    }
}

/// An invite as parsed from a URL by the joiner (SPEC §4.1).
#[derive(Clone, Debug)]
pub struct InviteLink {
    relay_host: String,
    secret: InviteSecret,
}

impl InviteLink {
    /// Parses `https://<relay-host>/i/<invite_id>#v=0&s=<invite_secret>`.
    ///
    /// Rules (SPEC §4.1, plus conservative choices):
    /// - scheme `https`; `http` only for loopback hosts (local development);
    /// - no userinfo, query string or extra path segments;
    /// - `v` is required and must be `0`, otherwise [`Error::UnsupportedVersion`];
    /// - `s` is required; unknown fragment parameters are ignored;
    ///   duplicated parameters are rejected.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInviteUrl`] or [`Error::UnsupportedVersion`].
    pub fn parse(url: &str) -> Result<Self> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or(Error::InvalidInviteUrl("missing scheme"))?;
        let (before_fragment, fragment) = rest
            .split_once('#')
            .ok_or(Error::InvalidInviteUrl("missing fragment"))?;
        if before_fragment.contains('?') {
            return Err(Error::InvalidInviteUrl("query string not allowed"));
        }
        let (host, path) = before_fragment
            .split_once('/')
            .ok_or(Error::InvalidInviteUrl("missing path"))?;
        check_host(host)?;
        match scheme {
            "https" => {}
            "http" if is_loopback(host) => {}
            _ => return Err(Error::InvalidInviteUrl("scheme must be https")),
        }
        let id_b64 = path
            .strip_prefix("i/")
            .ok_or(Error::InvalidInviteUrl("path must be /i/<invite_id>"))?;
        let id: [u8; 16] = b64_decode_array(id_b64, "invite_id")
            .map_err(|_| Error::InvalidInviteUrl("invite_id"))?;

        let mut version = None;
        let mut secret = None;
        for param in fragment.split('&') {
            let (k, v) = param.split_once('=').unwrap_or((param, ""));
            let slot = match k {
                "v" => &mut version,
                "s" => &mut secret,
                _ => continue,
            };
            if slot.replace(v).is_some() {
                return Err(Error::InvalidInviteUrl("duplicate fragment parameter"));
            }
        }
        match version {
            Some("0") => {}
            Some(_) => return Err(Error::UnsupportedVersion),
            None => return Err(Error::InvalidInviteUrl("missing v")),
        }
        let secret_b64 = secret.ok_or(Error::InvalidInviteUrl("missing s"))?;
        let secret = b64_decode_secret::<32>(secret_b64, "invite_secret")
            .map_err(|_| Error::InvalidInviteUrl("invite_secret"))?;
        Ok(Self {
            relay_host: host.to_owned(),
            secret: InviteSecret { id, secret },
        })
    }

    /// The relay host.
    #[must_use]
    pub fn relay_host(&self) -> &str {
        &self.relay_host
    }

    /// Id and secret.
    #[must_use]
    pub fn secret(&self) -> &InviteSecret {
        &self.secret
    }

    /// Formats the URL again.
    #[must_use]
    pub fn url(&self) -> String {
        format_url(&self.relay_host, &self.secret)
    }
}

fn format_url(host: &str, secret: &InviteSecret) -> String {
    let scheme = if is_loopback(host) { "http" } else { "https" };
    format!(
        "{scheme}://{host}/i/{}#v=0&s={}",
        secret.id_b64(),
        b64(secret.secret())
    )
}

fn host_name(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    host.rsplit_once(':').map_or(host, |(name, _)| name)
}

fn is_loopback(host: &str) -> bool {
    matches!(host_name(host), "localhost" | "127.0.0.1" | "::1")
}

fn check_host(host: &str) -> Result<()> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c));
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidInviteUrl("relay host"))
    }
}

/// Public invite metadata served by the relay (SPEC §4.2). Informational
/// and unauthenticated; only `group_name` and `purpose` are compared against
/// the Welcome. Unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct InviteMeta {
    /// The invite id (base64url).
    pub invite_id: String,
    /// Group display name.
    pub group_name: String,
    /// Inviter display name.
    #[serde(default)]
    pub inviter_name: String,
    /// The group's scope statement.
    pub purpose: String,
    /// Expiry, Unix seconds.
    #[serde(default)]
    pub expires_at: u64,
    /// Maximum uses.
    #[serde(default)]
    pub max_uses: u32,
    /// Remaining uses.
    #[serde(default)]
    pub uses_left: u32,
    /// Member count, if the relay knows it.
    #[serde(default)]
    pub member_count: Option<u32>,
    /// `open`, `exhausted`, `expired` or `revoked`.
    #[serde(default)]
    pub status: String,
    /// Protocol version; must be 0.
    pub protocol: u32,
}

impl InviteMeta {
    /// Parses relay JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], or [`Error::UnsupportedVersion`] if `protocol`
    /// isn't 0.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let meta: Self =
            serde_json::from_slice(bytes).map_err(|_| Error::Malformed("invite meta"))?;
        if meta.protocol != 0 {
            return Err(Error::UnsupportedVersion);
        }
        Ok(meta)
    }

    /// The minimal metadata needed to check a Welcome against what the
    /// human was shown.
    #[must_use]
    pub fn expected(invite_id: &[u8; 16], group_name: &str, purpose: &str) -> Self {
        Self {
            invite_id: b64(invite_id),
            group_name: group_name.to_owned(),
            inviter_name: String::new(),
            purpose: purpose.to_owned(),
            expires_at: 0,
            max_uses: 0,
            uses_left: 0,
            member_count: None,
            status: String::new(),
            protocol: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;

    /// Random id and secret, stable within a run (`AC_TEST_SEED`).
    fn parts() -> ([u8; 16], [u8; 32], [u8; 32]) {
        let rng = Rng::for_test("invite-parts");
        (
            rng.array().unwrap(),
            rng.array().unwrap(),
            rng.array().unwrap(),
        )
    }

    fn link() -> InviteSecret {
        let (id, secret, _) = parts();
        InviteSecret::from_parts(id, &secret)
    }

    #[test]
    fn welcome_wrap_round_trips_and_rejects_wrong_secret_or_tamper() {
        let rng = Rng::for_test("seed-1");
        let s = link();
        let wrapped = s.wrap_welcome(&rng, b"welcome bytes").unwrap();
        assert_eq!(wrapped.len(), 12 + 13 + 16);
        assert_eq!(s.unwrap_welcome(&wrapped).unwrap(), b"welcome bytes");

        let (id, secret, other) = parts();
        let wrong = InviteSecret::from_parts(id, &other);
        assert_eq!(wrong.unwrap_welcome(&wrapped), Err(Error::WelcomeAuth));
        let mut other_id_bytes = id;
        other_id_bytes[0] ^= 1;
        let other_id = InviteSecret::from_parts(other_id_bytes, &secret);
        assert_eq!(other_id.unwrap_welcome(&wrapped), Err(Error::WelcomeAuth));
        for i in [0, 12, wrapped.len() - 1] {
            let mut t = wrapped.clone();
            t[i] ^= 1;
            assert_eq!(s.unwrap_welcome(&t), Err(Error::WelcomeAuth));
        }
        assert_eq!(s.unwrap_welcome(&wrapped[..27]), Err(Error::WelcomeAuth));
        // Fresh nonce each time.
        assert_ne!(wrapped, s.wrap_welcome(&rng, b"welcome bytes").unwrap());
    }

    #[test]
    fn keys_are_label_separated() {
        let s = link();
        assert_ne!(*s.join_key(), *s.welcome_key());
        let (id, secret, _) = parts();
        assert_eq!(*s.join_key(), *derive_join_key(&id, &secret));
    }

    #[test]
    fn url_round_trips_and_keeps_secret_in_fragment() {
        let rng = Rng::for_test("seed-4");
        let clock = FakeClock::default();
        let inv = Invite::create(&rng, &clock, "relay.example", DEFAULT_TTL).unwrap();
        let url = inv.url();
        let (before, frag) = url.split_once('#').unwrap();
        assert!(!before.contains(&b64(inv.secret().secret())));
        assert!(frag.contains(&b64(inv.secret().secret())));
        let parsed = InviteLink::parse(&url).unwrap();
        assert_eq!(parsed.secret().id(), inv.secret().id());
        assert_eq!(parsed.secret().secret(), inv.secret().secret());
        assert_eq!(parsed.relay_host(), "relay.example");
        assert_eq!(parsed.url(), url);
        assert_eq!(inv.relay_host(), "relay.example");
    }

    #[test]
    fn invite_expiry_uses_the_clock() {
        let rng = Rng::for_test("seed-4");
        let clock = FakeClock::default();
        let inv = Invite::create(&rng, &clock, "relay.example", Duration::from_secs(60)).unwrap();
        assert!(!inv.is_expired(&clock));
        clock.advance(Duration::from_secs(60));
        assert!(inv.is_expired(&clock));
        assert!(Invite::create(&rng, &clock, "r", MAX_TTL + Duration::from_secs(1)).is_err());
        assert!(Invite::create(&rng, &clock, "r", Duration::ZERO).is_err());
        assert!(Invite::create(&rng, &clock, "bad host", DEFAULT_TTL).is_err());
        let restored = Invite::from_parts("r".into(), inv.secret().clone(), inv.expires_at());
        assert_eq!(restored.expires_at(), inv.expires_at());
    }

    #[test]
    fn loopback_hosts_may_use_http() {
        let s = link();
        for host in ["localhost:8080", "127.0.0.1", "[::1]:9000"] {
            let url = format_url(host, &s);
            assert!(url.starts_with("http://"), "{url}");
            assert_eq!(InviteLink::parse(&url).unwrap().relay_host(), host);
        }
        let url = format_url("relay.example", &s).replace("https://", "http://");
        assert_eq!(
            InviteLink::parse(&url).unwrap_err(),
            Error::InvalidInviteUrl("scheme must be https")
        );
    }

    #[test]
    fn debug_hides_the_secret() {
        let s = link();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains(&b64(s.secret())));
        assert!(dbg.contains(&s.id_b64()));
    }

    #[test]
    fn invite_meta_parses_and_checks_protocol() {
        let json = br#"{"invite_id":"AQ","group_name":"g","purpose":"p","protocol":0,"extra":1}"#;
        let m = InviteMeta::from_json(json).unwrap();
        assert_eq!((m.group_name.as_str(), m.purpose.as_str()), ("g", "p"));
        let json = br#"{"invite_id":"AQ","group_name":"g","purpose":"p","protocol":1}"#;
        assert_eq!(InviteMeta::from_json(json), Err(Error::UnsupportedVersion));
        assert_eq!(
            InviteMeta::from_json(b"{}"),
            Err(Error::Malformed("invite meta"))
        );
        assert_eq!(InviteMeta::expected(&[0; 16], "g", "p").group_name, "g");
    }
}
