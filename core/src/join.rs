//! JoinRequest wire format and MAC (SPEC §6.1).

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::encoding::{b64, b64_decode, b64_decode_array};
use crate::error::{Error, Result};

const MAC_LABEL: &[u8] = b"agentconnect/v0/join-request";
/// Maximum `display_name` length in characters (SPEC §6.1).
pub const MAX_DISPLAY_NAME_CHARS: usize = 80;

/// `mac` = HMAC-SHA256(`join_key`, "agentconnect/v0/join-request" ‖ `invite_id`
/// ‖ `key_package_bytes` ‖ `mailbox_id`).
///
/// `invite_id` is the raw 16 bytes and `mailbox_id` its ASCII string; SPEC
/// doesn't state the byte encodings, these are the choices v0 implements.
#[must_use]
pub fn join_request_mac(
    join_key: &[u8; 32],
    invite_id: &[u8; 16],
    key_package: &[u8],
    mailbox_id: &str,
) -> [u8; 32] {
    mac(join_key, invite_id, key_package, mailbox_id)
        .finalize()
        .into_bytes()
        .into()
}

fn mac(
    join_key: &[u8; 32],
    invite_id: &[u8; 16],
    key_package: &[u8],
    mailbox_id: &str,
) -> Hmac<Sha256> {
    // HMAC accepts keys of any length.
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(join_key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    m.update(MAC_LABEL);
    m.update(invite_id);
    m.update(key_package);
    m.update(mailbox_id.as_bytes());
    m
}

/// A JoinRequest (SPEC §6.1). Parsing doesn't authenticate anything; the
/// inviter verifies it with `Client::verify_join_request`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    /// The invite being redeemed.
    pub invite_id: [u8; 16],
    /// The joiner's display name. **Not covered by the MAC.**
    pub display_name: String,
    /// The serialised MLS KeyPackage.
    pub key_package: Vec<u8>,
    /// The joiner's mailbox id.
    pub mailbox_id: String,
    /// HMAC-SHA256 under `join_key`.
    pub mac: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct JoinRequestJson {
    v: u32,
    invite_id: String,
    display_name: String,
    key_package: String,
    mailbox_id: String,
    mac: String,
}

impl JoinRequest {
    /// Verifies the MAC in constant time.
    pub(crate) fn mac_ok(&self, join_key: &[u8; 32]) -> bool {
        mac(
            join_key,
            &self.invite_id,
            &self.key_package,
            &self.mailbox_id,
        )
        .verify_slice(&self.mac)
        .is_ok()
    }

    /// JSON encoding (JCS).
    ///
    /// # Errors
    ///
    /// Only if serialisation fails.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        crate::encoding::jcs(&JoinRequestJson {
            v: 0,
            invite_id: b64(&self.invite_id),
            display_name: self.display_name.clone(),
            key_package: b64(&self.key_package),
            mailbox_id: self.mailbox_id.clone(),
            mac: b64(&self.mac),
        })
    }

    /// Parses JSON. Unknown fields are ignored; `v` must be 0.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] or [`Error::UnsupportedVersion`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let raw: JoinRequestJson =
            serde_json::from_slice(bytes).map_err(|_| Error::Malformed("join request"))?;
        if raw.v != 0 {
            return Err(Error::UnsupportedVersion);
        }
        if raw.display_name.chars().count() > MAX_DISPLAY_NAME_CHARS {
            return Err(Error::Malformed("display_name"));
        }
        if raw.mailbox_id.len() != 22
            || !raw
                .mailbox_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(Error::Malformed("mailbox_id"));
        }
        Ok(Self {
            invite_id: b64_decode_array(&raw.invite_id, "invite_id")?,
            display_name: raw.display_name,
            key_package: b64_decode(&raw.key_package, "key_package")?,
            mailbox_id: raw.mailbox_id,
            mac: b64_decode_array(&raw.mac, "mac")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::rng::Rng;

    /// Random keys, stable within a run (`AC_TEST_SEED`).
    fn keys() -> ([u8; 32], [u8; 32]) {
        let rng = Rng::for_test("join-keys");
        (rng.array().unwrap(), rng.array().unwrap())
    }

    fn req() -> JoinRequest {
        let (key, _) = keys();
        let rng = Rng::for_test("join-request");
        let invite_id: [u8; 16] = rng.array().unwrap();
        let key_package = rng.array::<10>().unwrap().to_vec();
        let mailbox = "A".repeat(22);
        JoinRequest {
            invite_id,
            display_name: "bob".into(),
            mac: join_request_mac(&key, &invite_id, &key_package, &mailbox),
            key_package,
            mailbox_id: mailbox,
        }
    }

    #[test]
    fn mac_verifies_and_covers_every_input() {
        let (key, other) = keys();
        let r = req();
        assert!(r.mac_ok(&key));
        assert!(!r.mac_ok(&other));
        let mut t = r.clone();
        t.key_package[0] ^= 1;
        assert!(!t.mac_ok(&key));
        let mut t = r.clone();
        t.mailbox_id = "B".repeat(22);
        assert!(!t.mac_ok(&key));
        let mut t = r.clone();
        t.invite_id[0] ^= 1;
        assert!(!t.mac_ok(&key));
        // display_name is not covered (SPEC §6.1).
        let mut t = r;
        t.display_name = "mallory".into();
        assert!(t.mac_ok(&key));
    }

    #[test]
    fn json_round_trips_and_validates() {
        let r = req();
        let json = r.to_json().unwrap();
        assert_eq!(JoinRequest::from_json(&json).unwrap(), r);
        let s = String::from_utf8(json).unwrap();
        let cases = [
            (s.replace("\"v\":0", "\"v\":1"), Error::UnsupportedVersion),
            (
                s.replace("bob", &"b".repeat(81)),
                Error::Malformed("display_name"),
            ),
            (
                s.replace(&"A".repeat(22), "AAAA"),
                Error::Malformed("mailbox_id"),
            ),
            ("{}".to_owned(), Error::Malformed("join request")),
        ];
        for (bad, err) in cases {
            assert_eq!(JoinRequest::from_json(bad.as_bytes()), Err(err));
        }
    }
}
