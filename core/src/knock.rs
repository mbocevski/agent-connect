//! Doors and knocks (SPEC §6.6).
//!
//! - [`Door`]: the owner's door: its id, expiry and HPKE key pair in the v0
//!   suite's own HPKE algorithms. [`Door::open_knock`] runs the owner's
//!   checks 1–3 (door, seal and fields, timestamp).
//! - [`Knock`]: the signed knock, in its JCS form. It holds the
//!   `welcome_secret`, so it is zeroized and never shown by `Debug`.
//! - [`Client::create_knock`] (knocker) and [`Client::verify_knock`] (owner,
//!   checks 4–5: the KeyPackage and the signature).
//! - [`KnockSecret`]: the knock `welcome_key` and the §6.4 Welcome wrap.
//!
//! Deduplication, the local limits and the human approval (checks 6–8)
//! need the daemon's state and are the daemon's.

use std::fmt;
use std::fmt::Write as _;

use base64ct::{Base64UrlUnpadded, Encoding};
use openmls::prelude::KeyPackage;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::HpkeCiphertext;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::encoding::{
    MAX_SAFE_INTEGER, b64, b64_decode, b64_decode_array, b64_decode_secret, jcs_string,
};
use crate::error::{Error, Result};
use crate::group::Client;
use crate::identity::{fingerprint, parse_identity};
use crate::invite::{NONCE_LEN, hkdf32, open_wrapped_welcome, seal_wrapped_welcome};
use crate::listing::{is_one_line_text, is_text};
use crate::mls::{CS, HPKE_PUBLIC_KEY_LEN, KEM_CIPHERTEXT_LEN, LeafInfo};
use crate::provider::Store;
use crate::rng::Rng;

const KNOCK_LABEL: &[u8] = b"agentconnect/v0/knock";
const KNOCK_WELCOME_LABEL: &[u8] = b"agentconnect/v0/knock-welcome";

/// Length of a door's HPKE public key (SPEC §6.6.1): the v0 suite's 1216.
pub const DOOR_KEY_LEN: usize = HPKE_PUBLIC_KEY_LEN;
/// Length of a door's HPKE private key in the v0 suite (the 32-byte
/// `MLKEM768-X25519` seed).
pub const DOOR_PRIVATE_KEY_LEN: usize = 32;
/// Length of `enc` at the start of a `SealedKnock`: the suite's KEM
/// ciphertext, 1120 bytes.
pub const KNOCK_ENC_LEN: usize = KEM_CIPHERTEXT_LEN;
/// The largest `SealedKnock` (SPEC §7.1).
pub const MAX_SEALED_KNOCK: usize = 16 * 1024;
/// A door accepts knocks until this long after its `expires_at`.
pub const DOOR_GRACE_SECS: u64 = 3600;
/// How old a knock's `ts` may be; also when its approval lapses.
pub const KNOCK_LIFETIME_SECS: u64 = 3600;
/// How far in the future a knock's `ts` may be.
pub const KNOCK_FUTURE_SECS: u64 = 300;
/// Longest `note`, in characters.
pub const MAX_NOTE_CHARS: usize = 500;
const AEAD_TAG_LEN: usize = 16;

const fn bad(what: &'static str) -> Error {
    Error::InvalidKnock(what)
}

/// `info` of a sealed knock: `"agentconnect/v0/knock" ‖ door_id`.
fn knock_info(door_id: &[u8; 16]) -> Vec<u8> {
    [KNOCK_LABEL, door_id].concat()
}

/// The owner's door (SPEC §6.6.1): id, expiry and HPKE key pair. The
/// private key is zeroized on drop and never shown by `Debug`.
pub struct Door {
    id: [u8; 16],
    expires_at: u64,
    public: Vec<u8>,
    private: Zeroizing<Vec<u8>>,
}

impl Door {
    /// A fresh door: a random `door_id` and a fresh key pair.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`], or an HPKE failure.
    pub fn generate(rng: &Rng, expires_at: u64) -> Result<Self> {
        let id = rng.array()?;
        let ikm = Zeroizing::new(rng.array::<32>()?);
        Self::derive(id, &ikm, expires_at)
    }

    /// The door `id` whose key pair is HPKE `DeriveKeyPair(ikm)` in the v0
    /// suite. `ikm` must be 32 secret random bytes; [`Door::generate`] draws
    /// them. Deterministic, so test vectors can rebuild a door.
    ///
    /// # Errors
    ///
    /// An HPKE failure.
    pub fn derive(id: [u8; 16], ikm: &[u8; 32], expires_at: u64) -> Result<Self> {
        let crypto = CryptoProvider::new().map_err(|_| Error::Rng)?;
        let pair = crypto
            .derive_hpke_keypair(CS.hpke_config(), ikm)
            .map_err(|_| Error::Internal("door key derivation"))?;
        if pair.public.len() != DOOR_KEY_LEN || pair.private.len() != DOOR_PRIVATE_KEY_LEN {
            return Err(Error::HpkeKeyLength);
        }
        Ok(Self {
            id,
            expires_at,
            public: pair.public,
            private: Zeroizing::new(pair.private.to_vec()),
        })
    }

    /// `door_id`.
    #[must_use]
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Expiry, Unix seconds.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// The 1216-byte public key that goes in the listing.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// The door as a listing advertises it.
    #[must_use]
    pub fn listed(&self) -> crate::listing::ListedDoor {
        crate::listing::ListedDoor {
            id: self.id,
            key: self.public.clone(),
            expires_at: self.expires_at,
        }
    }

    /// Whether the private key may be deleted at `now`: 1 hour after
    /// expiry, once every knock it could have taken has lapsed.
    #[must_use]
    pub fn key_deletable(&self, now: u64) -> bool {
        now > self.expires_at.saturating_add(DOOR_GRACE_SECS)
    }

    /// Serialises the door for the daemon's encrypted store:
    /// `door_id(16) ‖ u64be(expires_at) ‖ public(1216) ‖ private`.
    /// **Contains the private key.**
    #[must_use]
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            24 + self.public.len() + self.private.len(),
        ));
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&self.private);
        out
    }

    /// Restores a door from [`Door::to_secret_bytes`]. The bytes must be
    /// exactly the layout, and the private key must open what is sealed to
    /// the public key, so a corrupted store fails here instead of dropping
    /// every knock later.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKnock`]: `"door bytes"` for the wrong length,
    /// `"door key pair mismatch"` for keys that don't belong together.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 24 + DOOR_KEY_LEN + DOOR_PRIVATE_KEY_LEN {
            return Err(bad("door bytes"));
        }
        let (id, rest) = bytes.split_at(16);
        let (exp, rest) = rest.split_at(8);
        let (public, private) = rest.split_at(DOOR_KEY_LEN);
        let door = Self {
            id: id.try_into().map_err(|_| bad("door bytes"))?,
            expires_at: u64::from_be_bytes(exp.try_into().map_err(|_| bad("door bytes"))?),
            public: public.to_vec(),
            private: Zeroizing::new(private.to_vec()),
        };
        door.check_key_pair()?;
        Ok(door)
    }

    /// Seals a probe to the public key and opens it with the private key.
    fn check_key_pair(&self) -> Result<()> {
        const PROBE: &[u8] = b"agentconnect/v0/door-key-check";
        let sealed =
            seal(&self.id, &self.public, PROBE).map_err(|_| bad("door key pair mismatch"))?;
        let (enc, ct) = sealed.split_at(KNOCK_ENC_LEN);
        let crypto = CryptoProvider::new().map_err(|_| Error::Rng)?;
        let input = HpkeCiphertext {
            kem_output: enc.to_vec().into(),
            ciphertext: ct.to_vec().into(),
        };
        match crypto.hpke_open(
            CS.hpke_config(),
            &input,
            &self.private,
            &knock_info(&self.id),
            b"",
        ) {
            Ok(p) if p == PROBE => Ok(()),
            _ => Err(bad("door key pair mismatch")),
        }
    }

    /// The owner's checks 1–3 (SPEC §6.6.3) on a knock that arrived in an
    /// envelope for `envelope_door_id`:
    ///
    /// 1. this is that door, and it expired at most 1 hour ago;
    /// 2. the seal opens, the plaintext is a canonical `Knock` with exactly
    ///    its fields, and its `door_id` is this door's;
    /// 3. `ts` is within [now − 3600 s, now + 300 s].
    ///
    /// The KeyPackage and the signature (checks 4–5) are
    /// [`Client::verify_knock`]'s. Every failure must drop the knock
    /// silently.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKnock`] naming the failed check.
    pub fn open_knock(
        &self,
        envelope_door_id: &[u8; 16],
        sealed: &[u8],
        now: u64,
    ) -> Result<OpenedKnock> {
        if *envelope_door_id != self.id {
            return Err(bad("not this door"));
        }
        if now > self.expires_at.saturating_add(DOOR_GRACE_SECS) {
            return Err(bad("door expired"));
        }
        if sealed.len() > MAX_SEALED_KNOCK {
            return Err(bad("sealed knock too large"));
        }
        if sealed.len() <= KNOCK_ENC_LEN + AEAD_TAG_LEN {
            return Err(bad("sealed knock too short"));
        }
        let (enc, ct) = sealed.split_at(KNOCK_ENC_LEN);
        let crypto = CryptoProvider::new().map_err(|_| Error::Rng)?;
        let input = HpkeCiphertext {
            kem_output: enc.to_vec().into(),
            ciphertext: ct.to_vec().into(),
        };
        let plaintext = Zeroizing::new(
            crypto
                .hpke_open(
                    CS.hpke_config(),
                    &input,
                    &self.private,
                    &knock_info(&self.id),
                    b"",
                )
                .map_err(|_| bad("seal does not open"))?,
        );
        let knock = Knock::from_json(&plaintext)?;
        if knock.door_id != self.id {
            return Err(bad("door_id mismatch"));
        }
        if now > knock.ts.saturating_add(KNOCK_LIFETIME_SECS)
            || knock.ts > now.saturating_add(KNOCK_FUTURE_SECS)
        {
            return Err(bad("ts out of range"));
        }
        Ok(OpenedKnock { knock })
    }
}

impl fmt::Debug for Door {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Door")
            .field("id", &b64(&self.id))
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// `SealedKnock = enc(1120) ‖ HPKE.Seal(door_key, info = "agentconnect/v0/knock"
/// ‖ door_id, aad = "", JCS(knock))` (SPEC §6.6.2). The door key length is
/// checked before HPKE sees it.
fn seal(door_id: &[u8; 16], door_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if door_key.len() != DOOR_KEY_LEN {
        return Err(Error::HpkeKeyLength);
    }
    let crypto = CryptoProvider::new().map_err(|_| Error::Rng)?;
    let ct = crypto
        .hpke_seal(
            CS.hpke_config(),
            door_key,
            &knock_info(door_id),
            b"",
            plaintext,
        )
        .map_err(|_| bad("seal failed"))?;
    if ct.kem_output.as_slice().len() != KNOCK_ENC_LEN {
        return Err(Error::KemOutputLength);
    }
    Ok([ct.kem_output.as_slice(), ct.ciphertext.as_slice()].concat())
}

/// A signed knock (SPEC §6.6.2). It carries the `welcome_secret`: the
/// knocker keeps it (encrypted) until it joins or the knock lapses.
#[derive(Clone)]
pub struct Knock {
    /// The door knocked on.
    pub door_id: [u8; 16],
    /// Random id of this knock.
    pub knock_id: [u8; 16],
    /// The knocker's clock, Unix seconds.
    pub ts: u64,
    /// At most 80 characters, no control characters. Untrusted text.
    pub display_name: String,
    /// 1 to 500 characters, no control characters. Untrusted text.
    pub note: Option<String>,
    /// The knocker's fresh KeyPackage (TLS bytes).
    pub key_package: Vec<u8>,
    /// The knocker's mailbox, where the Welcome goes.
    pub mailbox_id: String,
    welcome_secret: Zeroizing<[u8; 32]>,
    /// Ed25519 by the KeyPackage's leaf key `SK`.
    pub sig: [u8; 64],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KnockIn<'a> {
    v: u64,
    door_id: &'a str,
    knock_id: &'a str,
    ts: u64,
    display_name: String,
    #[serde(default)]
    note: Option<String>,
    key_package: &'a str,
    mailbox_id: &'a str,
    welcome_secret: &'a str,
    sig: &'a str,
}

/// Longest `display_name`, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 80;

/// At most 80 characters of single-line text (SPEC §6.6.2, §13.1.2); may
/// be empty.
fn check_display_name(name: &str) -> Result<()> {
    if name.chars().count() <= MAX_DISPLAY_NAME_CHARS && is_text(name) {
        Ok(())
    } else {
        Err(bad("display_name"))
    }
}

/// 1 to 500 characters of single-line text, when present.
fn check_note(note: Option<&str>) -> Result<()> {
    match note {
        Some(n) if !is_one_line_text(n, MAX_NOTE_CHARS) => Err(bad("note")),
        _ => Ok(()),
    }
}

fn check_mailbox(m: &str) -> Result<()> {
    if m.len() == 22
        && m.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        Ok(())
    } else {
        Err(bad("mailbox_id"))
    }
}

impl Knock {
    /// JCS of the knock, written by hand into one zeroizing buffer so the
    /// `welcome_secret` never lands in a temporary `String` or `Value`. The
    /// keys are ASCII, so their sort order is the RFC 8785 order.
    fn write(&self, with_sig: bool) -> Zeroizing<Vec<u8>> {
        let mut head = format!(
            "{{\"display_name\":{},\"door_id\":\"{}\",\"key_package\":\"{}\",\"knock_id\":\"{}\",\"mailbox_id\":{}",
            jcs_string(&self.display_name),
            b64(&self.door_id),
            b64(&self.key_package),
            b64(&self.knock_id),
            jcs_string(&self.mailbox_id),
        );
        if let Some(note) = &self.note {
            head.push_str(",\"note\":");
            head.push_str(&jcs_string(note));
        }
        if with_sig {
            head.push_str(",\"sig\":\"");
            head.push_str(&b64(&self.sig));
            head.push('"');
        }
        let _ = write!(head, ",\"ts\":{},\"v\":0,\"welcome_secret\":\"", self.ts);
        let mut secret = Zeroizing::new([0u8; 43]);
        let mut out = Zeroizing::new(Vec::with_capacity(head.len() + 45));
        out.extend_from_slice(head.as_bytes());
        if let Ok(s) =
            Base64UrlUnpadded::encode(self.welcome_secret.as_slice(), secret.as_mut_slice())
        {
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(b"\"}");
        out
    }

    /// The canonical JCS form, the sealed plaintext. **Contains the
    /// `welcome_secret`**: also what the knocker stores (encrypted).
    #[must_use]
    pub fn to_json(&self) -> Zeroizing<Vec<u8>> {
        self.write(true)
    }

    /// `"agentconnect/v0/knock" ‖ JCS(knock without "sig")`.
    #[must_use]
    pub fn signing_input(&self) -> Zeroizing<Vec<u8>> {
        let body = self.write(false);
        let mut out = Zeroizing::new(Vec::with_capacity(KNOCK_LABEL.len() + body.len()));
        out.extend_from_slice(KNOCK_LABEL);
        out.extend_from_slice(&body);
        out
    }

    /// Parses a knock: canonical JCS with exactly the knock's fields, each
    /// in its form (SPEC §6.6.2, §6.6.3 check 2). Doesn't verify the
    /// signature.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKnock`] or [`Error::UnsupportedVersion`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let raw: KnockIn<'_> = serde_json::from_slice(bytes).map_err(|_| bad("fields"))?;
        if raw.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        check_display_name(&raw.display_name)?;
        check_note(raw.note.as_deref())?;
        check_mailbox(raw.mailbox_id)?;
        if raw.ts > MAX_SAFE_INTEGER {
            return Err(bad("ts"));
        }
        let knock = Self {
            door_id: b64_decode_array(raw.door_id, "door_id").map_err(|_| bad("door_id"))?,
            knock_id: b64_decode_array(raw.knock_id, "knock_id").map_err(|_| bad("knock_id"))?,
            ts: raw.ts,
            display_name: raw.display_name,
            note: raw.note,
            key_package: b64_decode(raw.key_package, "key_package")
                .ok()
                .filter(|k| !k.is_empty())
                .ok_or(bad("key_package"))?,
            mailbox_id: raw.mailbox_id.to_owned(),
            welcome_secret: b64_decode_secret(raw.welcome_secret, "welcome_secret")
                .map_err(|_| bad("welcome_secret"))?,
            sig: b64_decode_array(raw.sig, "sig").map_err(|_| bad("sig"))?,
        };
        if knock.write(true).as_slice() != bytes {
            return Err(bad("not canonical"));
        }
        Ok(knock)
    }

    /// Strict Ed25519 verification of `sig` under `sig_key`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKnock`] if it doesn't verify.
    pub fn verify_signature(&self, sig_key: &[u8; 32]) -> Result<()> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(sig_key).map_err(|_| bad("signature"))?;
        key.verify_strict(
            &self.signing_input(),
            &ed25519_dalek::Signature::from_bytes(&self.sig),
        )
        .map_err(|_| bad("signature"))
    }

    /// The knock's `welcome_key` and Welcome wrap.
    #[must_use]
    pub fn secret(&self) -> KnockSecret {
        KnockSecret::from_parts(self.knock_id, &self.welcome_secret)
    }

    /// When the approval lapses: `ts + 3600`.
    #[must_use]
    pub fn lapses_at(&self) -> u64 {
        self.ts.saturating_add(KNOCK_LIFETIME_SECS)
    }

    /// When the knocker stops waiting and reports "no answer":
    /// `ts + 3600 + 300` (SPEC §6.6.6).
    #[must_use]
    pub fn gives_up_at(&self) -> u64 {
        self.lapses_at().saturating_add(KNOCK_FUTURE_SECS)
    }
}

impl fmt::Debug for Knock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Knock")
            .field("door_id", &b64(&self.door_id))
            .field("knock_id", &b64(&self.knock_id))
            .field("ts", &self.ts)
            .finish_non_exhaustive()
    }
}

/// A knock that passed the owner's checks 1–3 ([`Door::open_knock`]).
#[derive(Clone, Debug)]
pub struct OpenedKnock {
    knock: Knock,
}

impl OpenedKnock {
    /// The knock. Its KeyPackage and signature are not verified yet.
    #[must_use]
    pub fn knock(&self) -> &Knock {
        &self.knock
    }
}

/// A knock that passed the owner's checks 1–5 (SPEC §6.6.3). What remains
/// is the daemon's: deduplication, the local limits, and the human.
pub struct VerifiedKnock {
    knock: Knock,
    #[allow(dead_code)] // For the approval's Add (phase 3).
    key_package: KeyPackage,
    key_package_ref: Vec<u8>,
    info: LeafInfo,
}

impl VerifiedKnock {
    /// The knock.
    #[must_use]
    pub fn knock(&self) -> &Knock {
        &self.knock
    }

    /// The knocker's identity (from its KeyPackage's instance certificate).
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.info.identity
    }

    /// The knocker's instance id.
    #[must_use]
    pub fn instance_id(&self) -> u64 {
        self.info.instance_id
    }

    /// The §2 fingerprint of the knocker's identity, for the approval.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        parse_identity(&self.info.identity)
            .map(|k| fingerprint(&k))
            .unwrap_or_default()
    }

    /// The `KeyPackageRef`: at most one pending approval per ref.
    #[must_use]
    pub fn key_package_ref(&self) -> &[u8] {
        &self.key_package_ref
    }

    /// The knock's `welcome_key` and wrap.
    #[must_use]
    pub fn secret(&self) -> KnockSecret {
        self.knock.secret()
    }
}

impl VerifiedKnock {
    /// Until when the owner must remember this knock: `ts + 3600 + 300`,
    /// after which check 3 drops any copy anyway.
    #[must_use]
    pub fn forget_after(&self) -> u64 {
        self.knock.gives_up_at()
    }

    /// SPEC §6.6.3 step 6, replay part: if `ledger` has seen this knock's
    /// `knock_id` or `KeyPackageRef`, the knock is a replay; otherwise both
    /// are recorded until [`VerifiedKnock::forget_after`]. Call it for every
    /// knock that passed checks 1–5, before anything else happens to it
    /// (queued, approved, rejected, dropped by a limit or by policy), so a
    /// knock a human rejected can't be put in front of them again.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKnock`] `"replayed"` (kind `replay`): drop it
    /// silently. A ledger error.
    pub fn remember_in(&self, ledger: &mut impl KnockLedger) -> Result<()> {
        let id = self.knock.knock_id;
        if ledger.seen(&id, &self.key_package_ref)? {
            return Err(bad("replayed"));
        }
        ledger.remember(&id, &self.key_package_ref, self.forget_after())
    }
}

/// What an owner remembers about the knocks it has seen (SPEC §6.6.3 step
/// 6): every `knock_id` and `KeyPackageRef` until its knock's
/// `forget_after`. The daemon backs it with its encrypted store;
/// [`MemoryKnockLedger`] is an in-memory one.
pub trait KnockLedger {
    /// Whether `knock_id` or `key_package_ref` is remembered.
    ///
    /// # Errors
    ///
    /// The backing store's error.
    fn seen(&self, knock_id: &[u8; 16], key_package_ref: &[u8]) -> Result<bool>;

    /// Remembers both until `forget_after` (Unix seconds).
    ///
    /// # Errors
    ///
    /// The backing store's error.
    fn remember(
        &mut self,
        knock_id: &[u8; 16],
        key_package_ref: &[u8],
        forget_after: u64,
    ) -> Result<()>;
}

/// How many knocks a [`MemoryKnockLedger`] holds by default: well above
/// 32 pending per door times the 4 doors a mailbox may hold, times the
/// knocks a door can take in its 65-minute window at the relay's limits.
pub const DEFAULT_LEDGER_CAPACITY: usize = 65_536;

/// One remembered knock, for persisting a ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    /// The knock's id.
    pub knock_id: [u8; 16],
    /// Its KeyPackage's `KeyPackageRef`.
    pub key_package_ref: Vec<u8>,
    /// Unix seconds after which it may be forgotten.
    pub forget_after: u64,
}

/// An in-memory [`KnockLedger`] with a hard capacity. The daemon MUST
/// persist it (SPEC §6.6.3 step 6): save [`MemoryKnockLedger::entries`] in
/// its encrypted store and [`MemoryKnockLedger::insert`] them back after a
/// restart, or a knock seen before the restart could be replayed after it.
///
/// It never evicts an entry that is still live: when it is full, a new
/// knock is refused (kind `busy`) until [`MemoryKnockLedger::purge`] frees
/// expired entries. Refusing is safe; forgetting early would reopen the
/// replay window.
#[derive(Debug)]
pub struct MemoryKnockLedger {
    knocks: std::collections::HashMap<[u8; 16], (Vec<u8>, u64)>,
    refs: std::collections::HashMap<Vec<u8>, u64>,
    capacity: usize,
}

impl Default for MemoryKnockLedger {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_LEDGER_CAPACITY)
    }
}

impl MemoryKnockLedger {
    /// An empty ledger that holds at most `capacity` knocks.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            knocks: std::collections::HashMap::new(),
            refs: std::collections::HashMap::new(),
            capacity,
        }
    }

    /// The most knocks it holds.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Forgets every knock whose `forget_after` is before `now`.
    pub fn purge(&mut self, now: u64) {
        self.knocks.retain(|_, (_, until)| *until >= now);
        self.refs.retain(|_, until| *until >= now);
    }

    /// How many knocks it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.knocks.len()
    }

    /// Whether it holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.knocks.is_empty()
    }

    /// Every remembered knock, for persisting.
    #[must_use]
    pub fn entries(&self) -> Vec<LedgerEntry> {
        let mut out: Vec<LedgerEntry> = self
            .knocks
            .iter()
            .map(|(id, (kp_ref, until))| LedgerEntry {
                knock_id: *id,
                key_package_ref: kp_ref.clone(),
                forget_after: *until,
            })
            .collect();
        out.sort_by_key(|e| (e.forget_after, e.knock_id));
        out
    }

    /// Restores one persisted knock (or remembers a new one).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKnock`] `"ledger full"` (kind `busy`) when it is at
    /// capacity and this knock isn't in it yet.
    pub fn insert(
        &mut self,
        knock_id: [u8; 16],
        key_package_ref: Vec<u8>,
        forget_after: u64,
    ) -> Result<()> {
        if !self.knocks.contains_key(&knock_id) && self.knocks.len() >= self.capacity {
            return Err(bad("ledger full"));
        }
        let until = self
            .refs
            .entry(key_package_ref.clone())
            .or_insert(forget_after);
        *until = (*until).max(forget_after);
        let entry = self
            .knocks
            .entry(knock_id)
            .or_insert((key_package_ref, forget_after));
        entry.1 = entry.1.max(forget_after);
        Ok(())
    }
}

impl KnockLedger for MemoryKnockLedger {
    fn seen(&self, knock_id: &[u8; 16], key_package_ref: &[u8]) -> Result<bool> {
        Ok(self.knocks.contains_key(knock_id) || self.refs.contains_key(key_package_ref))
    }

    fn remember(
        &mut self,
        knock_id: &[u8; 16],
        key_package_ref: &[u8],
        forget_after: u64,
    ) -> Result<()> {
        self.insert(*knock_id, key_package_ref.to_vec(), forget_after)
    }
}

impl fmt::Debug for VerifiedKnock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedKnock")
            .field("knock", &self.knock)
            .field("identity", &self.info.identity)
            .finish_non_exhaustive()
    }
}

impl<S: Store> Client<S> {
    /// Knocker side (SPEC §6.6.2): a fresh KeyPackage, a random `knock_id`
    /// and `welcome_secret`, `ts` from this client's clock, the signature by
    /// this instance's `SK`, sealed to `door_key`. Returns the sealed knock
    /// (the envelope's `ct`) and the knock to keep until it lapses.
    ///
    /// The caller has verified the listing, checked its relay and that the
    /// door is open, and shown its human what it knocks on.
    ///
    /// # Errors
    ///
    /// [`Error::HpkeKeyLength`] for a door key that isn't 1216 bytes,
    /// [`Error::Malformed`] for a bad display name, [`Error::InvalidKnock`]
    /// for a bad note, or an MLS or RNG error.
    pub fn create_knock(
        &self,
        door_id: &[u8; 16],
        door_key: &[u8],
        display_name: &str,
        note: Option<&str>,
    ) -> Result<(Vec<u8>, Knock)> {
        if door_key.len() != DOOR_KEY_LEN {
            return Err(Error::HpkeKeyLength);
        }
        check_display_name(display_name)?;
        check_note(note)?;
        // Validate the door key fully before a KeyPackage is stored: HPKE
        // refuses keys of the right length that aren't valid, and a failed
        // knock must leave nothing behind.
        seal(door_id, door_key, b"").map_err(|_| bad("door key does not seal"))?;
        let mut knock = Knock {
            door_id: *door_id,
            knock_id: self.rng().array()?,
            ts: self.clock().unix_millis() / 1000,
            display_name: display_name.to_owned(),
            note: note.map(str::to_owned),
            key_package: self.new_key_package()?,
            mailbox_id: self.instance().mailbox_id(),
            welcome_secret: Zeroizing::new(self.rng().array()?),
            sig: [0; 64],
        };
        knock.sig = self.instance().sign(&knock.signing_input());
        match seal(door_id, door_key, &knock.to_json()) {
            Ok(sealed) => Ok((sealed, knock)),
            Err(e) => {
                // Not expected after the probe; still leave nothing behind.
                self.delete_key_package(&knock.key_package)?;
                Err(e)
            }
        }
    }

    /// Knocker side, SPEC §6.6.6: at `gives_up_at`, or after joining,
    /// deletes the private keys of the knock's KeyPackage. The caller drops
    /// the [`Knock`] (which zeroizes its `welcome_secret`) and its stored
    /// copy.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`], or an MLS error.
    pub fn forget_knock(&self, knock: &Knock) -> Result<()> {
        self.delete_key_package(&knock.key_package)
    }

    /// Owner side, SPEC §6.6.3 checks 4–5: the KeyPackage passes §6.2 step
    /// 3 (suite, key lengths, signature, instance certificate,
    /// capabilities, no extensions, not last resort, unused, `mailbox_id`
    /// derived from its leaf key), and `sig` verifies under its leaf key.
    ///
    /// # Errors
    ///
    /// A KeyPackage validation error ([`Error::KeyPackageReused`] for a
    /// used one), or [`Error::InvalidKnock`] for a bad signature.
    pub fn verify_knock(&self, opened: OpenedKnock) -> Result<VerifiedKnock> {
        let knock = opened.knock;
        let (key_package, key_package_ref, info) =
            self.check_peer_key_package(&knock.key_package, &knock.mailbox_id)?;
        let sig_key: [u8; 32] = info
            .sig_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::CredentialMismatch("leaf signature key length"))?;
        knock.verify_signature(&sig_key)?;
        Ok(VerifiedKnock {
            knock,
            key_package,
            key_package_ref,
            info,
        })
    }
}

/// A knock's `knock_id` and `welcome_secret` (SPEC §6.6.4): the knock
/// `welcome_key` and the §6.4 Welcome wrap under it. Zeroized on drop.
#[derive(Clone)]
pub struct KnockSecret {
    knock_id: [u8; 16],
    secret: Zeroizing<[u8; 32]>,
}

impl KnockSecret {
    /// From raw parts; the secret is copied into a zeroizing buffer.
    #[must_use]
    pub fn from_parts(knock_id: [u8; 16], secret: &[u8; 32]) -> Self {
        let mut copy = Zeroizing::new([0u8; 32]);
        copy.copy_from_slice(secret);
        Self {
            knock_id,
            secret: copy,
        }
    }

    /// The `knock_id`.
    #[must_use]
    pub fn knock_id(&self) -> &[u8; 16] {
        &self.knock_id
    }

    /// `welcome_key` = HKDF(ikm = `welcome_secret`, salt = `knock_id`,
    /// info = "agentconnect/v0/knock-welcome", L = 32) (SPEC §3.5).
    #[must_use]
    pub fn welcome_key(&self) -> Zeroizing<[u8; 32]> {
        hkdf32(self.secret.as_slice(), &self.knock_id, KNOCK_WELCOME_LABEL)
    }

    fn aad(&self) -> Vec<u8> {
        [KNOCK_WELCOME_LABEL, &self.knock_id].concat()
    }

    /// The §6.4 `WrappedWelcome` under the knock `welcome_key`, with
    /// `aad = "agentconnect/v0/knock-welcome" ‖ knock_id` and a fresh nonce.
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
        seal_wrapped_welcome(&self.welcome_key(), &self.aad(), nonce, welcome)
    }

    /// Opens a knock-wrapped Welcome.
    ///
    /// # Errors
    ///
    /// [`Error::WelcomeAuth`] if it doesn't authenticate under this knock.
    pub fn unwrap_welcome(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        open_wrapped_welcome(&self.welcome_key(), &self.aad(), wrapped)
    }
}

#[cfg(test)]
impl KnockSecret {
    /// The raw secret, for test vectors only.
    pub(crate) fn secret_for_vectors(&self) -> &[u8; 32] {
        &self.secret
    }
}

/// Seals an arbitrary knock to a door, for negative vectors only.
#[cfg(test)]
pub(crate) fn seal_for_vectors(door_id: &[u8; 16], door_key: &[u8], knock: &Knock) -> Vec<u8> {
    seal(door_id, door_key, &knock.to_json()).unwrap()
}

impl fmt::Debug for KnockSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnockSecret")
            .field("knock_id", &b64(&self.knock_id))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::clock::{Clock as _, FakeClock};
    use crate::identity::Identity;
    use crate::invite::InviteSecret;
    use crate::mls::key_package_signature_key;
    use crate::provider::MemoryStore;

    type C = Client<MemoryStore>;

    pub(crate) fn client(label: &str, clock: &Arc<FakeClock>) -> C {
        let rng = Rng::for_test(label);
        let id = Identity::generate(&rng).unwrap();
        let inst = id.create_instance(&rng, &**clock).unwrap();
        Client::new(MemoryStore::new(), rng, inst, clock.clone()).unwrap()
    }

    fn now(clock: &FakeClock) -> u64 {
        clock.unix_millis() / 1000
    }

    struct Setup {
        clock: Arc<FakeClock>,
        owner: C,
        knocker: C,
        door: Door,
    }

    fn setup(label: &str) -> Setup {
        let clock = Arc::new(FakeClock::default());
        let owner = client(&format!("{label}-owner"), &clock);
        let knocker = client(&format!("{label}-knocker"), &clock);
        let door = Door::generate(
            &Rng::for_test(&format!("{label}-door")),
            now(&clock) + 7 * 24 * 3600,
        )
        .unwrap();
        Setup {
            clock,
            owner,
            knocker,
            door,
        }
    }

    fn knock(s: &Setup) -> (Vec<u8>, Knock) {
        s.knocker
            .create_knock(
                s.door.id(),
                s.door.public_key(),
                "bob's agent",
                Some("about the 2.0 train"),
            )
            .unwrap()
    }

    #[test]
    fn a_knock_opens_and_verifies() {
        let s = setup("knock-ok");
        let (sealed, sent) = knock(&s);
        assert!(sealed.len() > KNOCK_ENC_LEN && sealed.len() < MAX_SEALED_KNOCK);
        let opened = s
            .door
            .open_knock(s.door.id(), &sealed, now(&s.clock))
            .unwrap();
        assert_eq!(opened.knock().to_json(), sent.to_json());
        let v = s.owner.verify_knock(opened).unwrap();
        assert_eq!(v.identity(), s.knocker.instance().identity());
        assert_eq!(v.instance_id(), s.knocker.instance().instance_id());
        assert_eq!(v.knock().mailbox_id, s.knocker.instance().mailbox_id());
        assert_eq!(v.knock().display_name, "bob's agent");
        assert_eq!(v.knock().note.as_deref(), Some("about the 2.0 train"));
        let ik = parse_identity(v.identity()).unwrap();
        assert_eq!(v.fingerprint(), fingerprint(&ik));
        assert_eq!(v.key_package_ref().len(), 32);
        assert_eq!(v.secret().knock_id(), &sent.knock_id);
        // The raw leaf key is the one the signature verifies under.
        let leaf = key_package_signature_key(&sent.key_package).unwrap();
        assert_eq!(leaf, s.knocker.instance().public_key());
        sent.verify_signature(&leaf).unwrap();
        assert!(format!("{v:?}").contains(v.identity()));
    }

    #[test]
    fn the_knock_json_is_canonical_and_strict() {
        let s = setup("knock-json");
        let (_, k) = knock(&s);
        let json = k.to_json();
        let back = Knock::from_json(&json).unwrap();
        assert_eq!(back.to_json(), json);
        // It is exactly the generic JCS encoding.
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(crate::encoding::jcs(&v).unwrap(), json.to_vec());
        assert!(k.signing_input().starts_with(KNOCK_LABEL));
        assert!(!String::from_utf8_lossy(&k.signing_input()).contains("\"sig\""));
        let s_json = String::from_utf8(json.to_vec()).unwrap();
        let cases = [
            (
                s_json.replace("\"v\":0", "\"v\":1"),
                Error::UnsupportedVersion,
            ),
            (s_json.replace("\"v\":0", "\"v\":0,\"x\":1"), bad("fields")),
            (s_json.replacen('{', "{ ", 1), bad("not canonical")),
            (
                s_json.replace("bob's agent", &"b".repeat(81)),
                bad("display_name"),
            ),
            (s_json.replace("about the 2.0 train", ""), bad("note")),
            (s_json.replace("about the 2.0 train", "a\\nb"), bad("note")),
            (s_json.replace(&k.mailbox_id, "short"), bad("mailbox_id")),
            (
                s_json.replace(&format!("\"ts\":{}", k.ts), "\"ts\":9007199254740992"),
                bad("ts"),
            ),
            (s_json.replace(&b64(&k.door_id), "AA"), bad("door_id")),
            (s_json.replace(&b64(&k.knock_id), "AA"), bad("knock_id")),
            (s_json.replace(&b64(&k.sig), "AA"), bad("sig")),
            (s_json.replace(&b64(&k.key_package), ""), bad("key_package")),
        ];
        for (b, err) in cases {
            assert_eq!(Knock::from_json(b.as_bytes()).err(), Some(err), "{b:.80}");
        }
        // A null note is not an absent note.
        let no_note = Knock {
            note: None,
            ..k.clone()
        };
        let nn = String::from_utf8(no_note.to_json().to_vec()).unwrap();
        Knock::from_json(nn.as_bytes()).unwrap();
        let null = nn.replace(",\"sig\"", ",\"note\":null,\"sig\"");
        assert_eq!(
            Knock::from_json(null.as_bytes()).err(),
            Some(bad("not canonical"))
        );
        // Debug shows no secret.
        let secret = b64(k.secret().secret.as_slice());
        assert!(!format!("{k:?} {:?}", k.secret()).contains(&secret));
    }

    #[test]
    fn owner_checks_1_to_3() {
        let s = setup("knock-checks");
        let (sealed, k) = knock(&s);
        let t = now(&s.clock);
        let other_door =
            Door::generate(&Rng::for_test("knock-checks-other"), s.door.expires_at()).unwrap();
        // 1: another door's envelope, or a door long expired.
        assert_eq!(
            s.door.open_knock(other_door.id(), &sealed, t).err(),
            Some(bad("not this door"))
        );
        let exp = s.door.expires_at();
        assert_eq!(
            s.door.open_knock(s.door.id(), &sealed, exp + 3601).err(),
            Some(bad("door expired"))
        );
        // 2: the wrong key, tampering, truncation.
        let other_seal = Door::from_secret_bytes(&{
            let mut b = other_door.to_secret_bytes().to_vec();
            b[..16].copy_from_slice(s.door.id());
            b
        })
        .unwrap();
        assert_eq!(
            other_seal.open_knock(s.door.id(), &sealed, t).err(),
            Some(bad("seal does not open"))
        );
        for i in [0, KNOCK_ENC_LEN, sealed.len() - 1] {
            let mut x = sealed.clone();
            x[i] ^= 1;
            assert_eq!(
                s.door.open_knock(s.door.id(), &x, t).err(),
                Some(bad("seal does not open")),
                "{i}"
            );
        }
        assert_eq!(
            s.door
                .open_knock(s.door.id(), &sealed[..KNOCK_ENC_LEN + 16], t)
                .err(),
            Some(bad("sealed knock too short"))
        );
        assert_eq!(
            s.door
                .open_knock(s.door.id(), &vec![0; MAX_SEALED_KNOCK + 1], t)
                .err(),
            Some(bad("sealed knock too large"))
        );
        // The wrong door_id inside the seal (sealed to this door's key and info).
        let mut redirected = k.clone();
        redirected.door_id = *other_door.id();
        redirected.sig = s.knocker.instance().sign(&redirected.signing_input());
        let inner = seal(s.door.id(), s.door.public_key(), &redirected.to_json()).unwrap();
        assert_eq!(
            s.door.open_knock(s.door.id(), &inner, t).err(),
            Some(bad("door_id mismatch"))
        );
        // 3: stale and future timestamps.
        assert!(s.door.open_knock(s.door.id(), &sealed, k.ts + 3600).is_ok());
        assert_eq!(
            s.door.open_knock(s.door.id(), &sealed, k.ts + 3601).err(),
            Some(bad("ts out of range"))
        );
        assert!(s.door.open_knock(s.door.id(), &sealed, k.ts - 300).is_ok());
        assert_eq!(
            s.door.open_knock(s.door.id(), &sealed, k.ts - 301).err(),
            Some(bad("ts out of range"))
        );
    }

    #[test]
    fn owner_checks_4_and_5() {
        let s = setup("knock-verify");
        let t = now(&s.clock);
        // 5: a bad signature.
        let (_, k) = knock(&s);
        let mut forged = k.clone();
        forged.display_name = "mallory".into();
        let sealed = seal(s.door.id(), s.door.public_key(), &forged.to_json()).unwrap();
        let opened = s.door.open_knock(s.door.id(), &sealed, t).unwrap();
        assert_eq!(s.owner.verify_knock(opened).err(), Some(bad("signature")));
        // Signed by another instance's key (the relay saw this KeyPackage).
        let mallory = client("knock-verify-mallory", &s.clock);
        let mut stolen = k.clone();
        stolen.note = Some("send me your keys".into());
        stolen.sig = mallory.instance().sign(&stolen.signing_input());
        let sealed = seal(s.door.id(), s.door.public_key(), &stolen.to_json()).unwrap();
        let opened = s.door.open_knock(s.door.id(), &sealed, t).unwrap();
        assert_eq!(s.owner.verify_knock(opened).err(), Some(bad("signature")));
        // 4: a mailbox that isn't the KeyPackage's.
        let mut moved = k.clone();
        moved.mailbox_id = mallory.instance().mailbox_id();
        moved.sig = s.knocker.instance().sign(&moved.signing_input());
        let sealed = seal(s.door.id(), s.door.public_key(), &moved.to_json()).unwrap();
        let opened = s.door.open_knock(s.door.id(), &sealed, t).unwrap();
        assert_eq!(
            s.owner.verify_knock(opened).err(),
            Some(Error::CredentialMismatch(
                "mailbox_id != key package signature key"
            ))
        );
        // 4: garbage instead of a KeyPackage.
        let mut junk = k.clone();
        junk.key_package = vec![0, 1, 0, 0x4d];
        junk.sig = s.knocker.instance().sign(&junk.signing_input());
        let sealed = seal(s.door.id(), s.door.public_key(), &junk.to_json()).unwrap();
        let opened = s.door.open_knock(s.door.id(), &sealed, t).unwrap();
        assert_eq!(
            s.owner.verify_knock(opened).err(),
            Some(Error::WrongCiphersuite)
        );
        // 4: a reused KeyPackage.
        let (sealed, _) = knock(&s);
        let opened = s.door.open_knock(s.door.id(), &sealed, t).unwrap();
        let v = s.owner.verify_knock(opened).unwrap();
        s.owner
            .mark_key_package_used_for_testing(v.key_package_ref())
            .unwrap();
        let opened = s.door.open_knock(s.door.id(), &sealed, t).unwrap();
        assert_eq!(
            s.owner.verify_knock(opened).err(),
            Some(Error::KeyPackageReused)
        );
    }

    /// Review M4 (`knock_probe.py`): the relay could redeliver a knock the
    /// human had rejected, and every check passed again.
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn a_knock_seen_before_is_a_replay() {
        let s = setup("knock-replay");
        let t = now(&s.clock);
        let (sealed, k) = knock(&s);
        let mut ledger = MemoryKnockLedger::default();
        let v = s
            .owner
            .verify_knock(s.door.open_knock(s.door.id(), &sealed, t).unwrap())
            .unwrap();
        v.remember_in(&mut ledger).unwrap();
        assert_eq!(v.forget_after(), k.ts + 3600 + 300);
        // The same sealed bytes, later inside the window.
        let again = s
            .owner
            .verify_knock(s.door.open_knock(s.door.id(), &sealed, t + 3000).unwrap())
            .unwrap();
        let e = again.remember_in(&mut ledger).unwrap_err();
        assert_eq!(e, bad("replayed"));
        assert_eq!(e.kind(), crate::ErrorKind::Replay);
        // The same KeyPackage under a fresh knock_id and signature.
        let mut renamed = k.clone();
        renamed.knock_id = Rng::for_test("knock-replay-id").array().unwrap();
        renamed.sig = s.knocker.instance().sign(&renamed.signing_input());
        let sealed2 = seal(s.door.id(), s.door.public_key(), &renamed.to_json()).unwrap();
        let v2 = s
            .owner
            .verify_knock(s.door.open_knock(s.door.id(), &sealed2, t).unwrap())
            .unwrap();
        assert_eq!(v2.remember_in(&mut ledger), Err(bad("replayed")));
        // A different knock is fresh.
        let (sealed3, _) = knock(&s);
        let v3 = s
            .owner
            .verify_knock(s.door.open_knock(s.door.id(), &sealed3, t).unwrap())
            .unwrap();
        v3.remember_in(&mut ledger).unwrap();
        // After the knock can no longer pass check 3, it is forgotten.
        assert_eq!(ledger.len(), 2);
        ledger.purge(v.forget_after());
        assert_eq!(ledger.len(), 2);
        ledger.purge(v.forget_after() + 1);
        assert_eq!(ledger.len(), 0);
        assert!(ledger.is_empty());
    }

    /// Review N4: the ledger survives a restart through export and import,
    /// and when full it refuses new knocks instead of evicting live ones.
    #[test]
    fn the_ledger_persists_and_never_evicts_a_live_entry() {
        let s = setup("knock-ledger");
        let t = now(&s.clock);
        let verified: Vec<VerifiedKnock> = (0..3)
            .map(|_| {
                let (sealed, _) = knock(&s);
                s.owner
                    .verify_knock(s.door.open_knock(s.door.id(), &sealed, t).unwrap())
                    .unwrap()
            })
            .collect();
        let mut ledger = MemoryKnockLedger::with_capacity(2);
        verified[0].remember_in(&mut ledger).unwrap();
        verified[1].remember_in(&mut ledger).unwrap();
        // Full: the third knock is refused, and nothing was evicted.
        let e = verified[2].remember_in(&mut ledger).unwrap_err();
        assert_eq!(e, bad("ledger full"));
        assert_eq!(e.kind(), crate::ErrorKind::Busy);
        assert_eq!(verified[0].remember_in(&mut ledger), Err(bad("replayed")));
        // Export, restart, import: replays are still caught.
        let saved = ledger.entries();
        assert_eq!(saved.len(), 2);
        let mut restarted = MemoryKnockLedger::with_capacity(2);
        for e in &saved {
            restarted
                .insert(e.knock_id, e.key_package_ref.clone(), e.forget_after)
                .unwrap();
        }
        assert_eq!(restarted.entries().len(), 2);
        for v in &verified[..2] {
            assert_eq!(v.remember_in(&mut restarted), Err(bad("replayed")));
        }
        // Once the entries expire, purging makes room.
        restarted.purge(verified[0].forget_after() + 1);
        verified[2].remember_in(&mut restarted).unwrap();
        // Import refuses past the cap too.
        let mut tiny = MemoryKnockLedger::with_capacity(1);
        tiny.insert(
            saved[0].knock_id,
            saved[0].key_package_ref.clone(),
            saved[0].forget_after,
        )
        .unwrap();
        assert_eq!(
            tiny.insert(
                saved[1].knock_id,
                saved[1].key_package_ref.clone(),
                saved[1].forget_after
            ),
            Err(bad("ledger full"))
        );
        assert_eq!(
            MemoryKnockLedger::default().capacity(),
            DEFAULT_LEDGER_CAPACITY
        );
    }

    /// Review L1: a door key that HPKE can't seal to used to leave a
    /// KeyPackage's private keys in the store.
    #[test]
    fn a_door_key_that_does_not_seal_leaves_nothing_behind() {
        let s = setup("knock-bad-key");
        let mut junk = vec![0u8; DOOR_KEY_LEN];
        Rng::for_test("knock-bad-key-bytes")
            .fill(&mut junk)
            .unwrap();
        let before = s.knocker.store_for_testing().mls_value_count();
        let e = s
            .knocker
            .create_knock(s.door.id(), &junk, "bob", None)
            .unwrap_err();
        assert_eq!(e, bad("door key does not seal"));
        assert_eq!(s.knocker.store_for_testing().mls_value_count(), before);
        // A knock that lapses gives its KeyPackage's keys back.
        let (_, k) = knock(&s);
        let with = s.knocker.store_for_testing().mls_value_count();
        assert!(with > before);
        s.knocker.forget_knock(&k).unwrap();
        assert_eq!(s.knocker.store_for_testing().mls_value_count(), before);
        // Forgetting twice is harmless.
        s.knocker.forget_knock(&k).unwrap();
    }

    /// Review L6: a stored door must be exactly the layout, and its private
    /// key must belong to its public key.
    #[test]
    fn stored_doors_are_checked_on_load() {
        let s = setup("door-load");
        let bytes = s.door.to_secret_bytes();
        assert_eq!(bytes.len(), 24 + DOOR_KEY_LEN + DOOR_PRIVATE_KEY_LEN);
        Door::from_secret_bytes(&bytes).unwrap();
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(
            Door::from_secret_bytes(&long).err(),
            Some(bad("door bytes"))
        );
        assert_eq!(
            Door::from_secret_bytes(&bytes[..bytes.len() - 1]).err(),
            Some(bad("door bytes"))
        );
        // Another door's private key under this door's public key.
        let other = Door::generate(&Rng::for_test("door-load-other"), s.door.expires_at()).unwrap();
        let mut mixed = bytes.to_vec();
        let split = 24 + DOOR_KEY_LEN;
        mixed[split..].copy_from_slice(&other.to_secret_bytes()[split..]);
        assert_eq!(
            Door::from_secret_bytes(&mixed).err(),
            Some(bad("door key pair mismatch"))
        );
    }

    /// Review M2: a display name or note that reorders or splits the
    /// approval prompt is refused on both ends.
    #[test]
    fn knock_text_rejects_line_format_and_private_characters() {
        let s = setup("knock-unicode");
        let key = s.door.public_key();
        let (_, k) = knock(&s);
        for c in [
            '\u{2028}', '\u{2029}', '\u{202E}', '\u{200B}', '\u{FEFF}', '\u{E000}', '\u{A0}',
        ] {
            let text = format!("bob{c}s agent");
            assert_eq!(
                s.knocker.create_knock(s.door.id(), key, &text, None).err(),
                Some(bad("display_name")),
                "U+{:04X}",
                u32::from(c)
            );
            assert_eq!(
                s.knocker
                    .create_knock(s.door.id(), key, "b", Some(&text))
                    .err(),
                Some(bad("note"))
            );
            let mut forged = k.clone();
            forged.display_name.clone_from(&text);
            assert_eq!(
                Knock::from_json(&forged.to_json()).err(),
                Some(bad("display_name"))
            );
            let mut forged = k.clone();
            forged.note = Some(text);
            assert_eq!(Knock::from_json(&forged.to_json()).err(), Some(bad("note")));
        }
    }

    #[test]
    fn knocks_need_a_well_formed_door_key_and_text() {
        let s = setup("knock-create");
        let key = s.door.public_key();
        for len in [0, 32, 1215, 1217] {
            let mut k = key.to_vec();
            k.resize(len, 0);
            assert_eq!(
                s.knocker.create_knock(s.door.id(), &k, "b", None).err(),
                Some(Error::HpkeKeyLength)
            );
            assert_eq!(
                seal(s.door.id(), &k, b"x").err(),
                Some(Error::HpkeKeyLength)
            );
        }
        assert!(
            s.knocker
                .create_knock(s.door.id(), key, &"n".repeat(81), None)
                .is_err()
        );
        assert!(
            s.knocker
                .create_knock(s.door.id(), key, "a\u{1b}[2J", None)
                .is_err()
        );
        assert_eq!(
            s.knocker
                .create_knock(s.door.id(), key, "b", Some(""))
                .err(),
            Some(bad("note"))
        );
        assert_eq!(
            s.knocker
                .create_knock(s.door.id(), key, "b", Some(&"n".repeat(501)))
                .err(),
            Some(bad("note"))
        );
        let (_, k) = s.knocker.create_knock(s.door.id(), key, "", None).unwrap();
        assert_eq!(k.lapses_at(), k.ts + 3600);
        assert_eq!(k.gives_up_at(), k.ts + 3900);
    }

    #[test]
    fn doors_round_trip_and_hide_their_key() {
        let s = setup("door-bytes");
        let bytes = s.door.to_secret_bytes();
        let back = Door::from_secret_bytes(&bytes).unwrap();
        assert_eq!(back.id(), s.door.id());
        assert_eq!(back.expires_at(), s.door.expires_at());
        assert_eq!(back.public_key(), s.door.public_key());
        assert_eq!(back.public_key().len(), DOOR_KEY_LEN);
        assert!(Door::from_secret_bytes(&bytes[..24 + DOOR_KEY_LEN]).is_err());
        let listed = s.door.listed();
        assert_eq!(listed.key, s.door.public_key());
        assert!(!s.door.key_deletable(s.door.expires_at() + 3600));
        assert!(s.door.key_deletable(s.door.expires_at() + 3601));
        assert!(!format!("{:?}", s.door).contains(&b64(&s.door.private)));
        // Derivation is deterministic in the input key material.
        let ikm: [u8; 32] = Rng::for_test("door-ikm").array().unwrap();
        let id: [u8; 16] = Rng::for_test("door-ikm-id").array().unwrap();
        let a = Door::derive(id, &ikm, 5).unwrap();
        let b = Door::derive(id, &ikm, 5).unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn knock_welcome_wrap() {
        let rng = Rng::for_test("knock-welcome");
        let (id, secret, other): ([u8; 16], [u8; 32], [u8; 32]) = (
            rng.array().unwrap(),
            rng.array().unwrap(),
            rng.array().unwrap(),
        );
        let ks = KnockSecret::from_parts(id, &secret);
        let wrapped = ks.wrap_welcome(&rng, b"welcome").unwrap();
        assert_eq!(ks.unwrap_welcome(&wrapped).unwrap(), b"welcome");
        // The wrong secret, the wrong knock id, tampering.
        assert_eq!(
            KnockSecret::from_parts(id, &other).unwrap_welcome(&wrapped),
            Err(Error::WelcomeAuth)
        );
        let mut id2 = id;
        id2[0] ^= 1;
        assert_eq!(
            KnockSecret::from_parts(id2, &secret).unwrap_welcome(&wrapped),
            Err(Error::WelcomeAuth)
        );
        let mut t = wrapped.clone();
        t[20] ^= 1;
        assert_eq!(ks.unwrap_welcome(&t), Err(Error::WelcomeAuth));
        // An invite wrap with the same bytes as key material doesn't open:
        // the label separates the two.
        let invite = InviteSecret::from_parts(id, &secret);
        assert_ne!(*invite.welcome_key(), *ks.welcome_key());
        assert_eq!(invite.unwrap_welcome(&wrapped), Err(Error::WelcomeAuth));
        assert_eq!(
            ks.unwrap_welcome(&invite.wrap_welcome(&rng, b"w").unwrap()),
            Err(Error::WelcomeAuth)
        );
        assert!(!format!("{ks:?}").contains(&b64(&secret)));
    }
}
