//! JoinRequest wire format and MAC (SPEC §6.1).

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::encoding::{b64, b64_decode, b64_decode_array};
use crate::error::{Error, Result};

const MAC_LABEL: &[u8] = b"agentconnect/v0/join-request";
/// Maximum `display_name` length in characters (SPEC §6.1).
pub const MAX_DISPLAY_NAME_CHARS: usize = 80;

/// The fields a JoinRequest MAC covers (SPEC §6.1).
#[derive(Clone, Copy, Debug)]
pub struct MacInput<'a> {
    /// The raw 16-byte `invite_id`.
    pub invite_id: &'a [u8; 16],
    /// The TLS-serialised KeyPackage.
    pub key_package: &'a [u8],
    /// The joiner's mailbox id (ASCII).
    pub mailbox_id: &'a str,
    /// The display name (UTF-8).
    pub display_name: &'a str,
}

/// `mac` = HMAC-SHA256(`join_key`, "agentconnect/v0/join-request" ‖
/// lp(`invite_id`) ‖ lp(`key_package_bytes`) ‖ lp(`mailbox_id`) ‖
/// lp(`display_name`)), where lp(x) = u32be(len(x)) ‖ x (SPEC §6.1).
#[must_use]
pub fn join_request_mac(join_key: &[u8; 32], input: &MacInput<'_>) -> [u8; 32] {
    mac(join_key, input).finalize().into_bytes().into()
}

fn mac(join_key: &[u8; 32], input: &MacInput<'_>) -> Hmac<Sha256> {
    // HMAC accepts keys of any length.
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(join_key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    m.update(MAC_LABEL);
    for field in [
        input.invite_id.as_slice(),
        input.key_package,
        input.mailbox_id.as_bytes(),
        input.display_name.as_bytes(),
    ] {
        // Every field is far below 4 GiB (KeyPackages are bounded by the
        // relay frame); saturate rather than wrap if that ever changes.
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        m.update(&len.to_be_bytes());
        m.update(field);
    }
    m
}

/// SPEC §6.1: at most 80 characters of one-line text (§13.1.2), since the
/// inviter's human approves the join by this name.
pub(crate) fn check_display_name(name: &str) -> Result<()> {
    if name.chars().count() > MAX_DISPLAY_NAME_CHARS || !crate::listing::is_text(name) {
        return Err(Error::Malformed("display_name"));
    }
    Ok(())
}

/// A JoinRequest (SPEC §6.1). Parsing doesn't authenticate anything; the
/// inviter verifies it with `Client::verify_join_request`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    /// The invite being redeemed.
    pub invite_id: [u8; 16],
    /// The joiner's display name (covered by the MAC; still chosen by the
    /// joiner, so untrusted text).
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
    /// The MAC-covered fields.
    #[must_use]
    pub fn mac_input(&self) -> MacInput<'_> {
        MacInput {
            invite_id: &self.invite_id,
            key_package: &self.key_package,
            mailbox_id: &self.mailbox_id,
            display_name: &self.display_name,
        }
    }

    /// Verifies the MAC in constant time.
    pub(crate) fn mac_ok(&self, join_key: &[u8; 32]) -> bool {
        mac(join_key, &self.mac_input())
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
        check_display_name(&raw.display_name)?;
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
        let mut r = JoinRequest {
            invite_id,
            display_name: "bob".into(),
            mac: [0; 32],
            key_package,
            mailbox_id: mailbox,
        };
        r.mac = join_request_mac(&key, &r.mac_input());
        r
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
        // The relay can no longer rename the joiner the human approves.
        let mut t = r.clone();
        t.display_name = "mallory".into();
        assert!(!t.mac_ok(&key));
        // Length prefixes keep field boundaries: moving a character from
        // mailbox_id to display_name leaves the plain concatenation the same
        // but changes the MAC.
        let mut t = r;
        t.mailbox_id.pop();
        t.display_name = format!("A{}", t.display_name);
        assert!(!t.mac_ok(&key));
    }

    #[test]
    fn display_names_have_at_most_80_characters() {
        assert_eq!(check_display_name(&"\u{e9}".repeat(80)), Ok(()));
        assert_eq!(
            check_display_name(&"b".repeat(81)),
            Err(Error::Malformed("display_name"))
        );
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
                s.replace("bob", "bo\\u001b[2Jb"),
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

    /// Review N5: the name the inviter's human approves follows the
    /// one-line text rule (SPEC §6.1), not only "no Cc".
    #[test]
    fn display_names_are_one_line_text() {
        for bad in [
            "bo\u{2028}b",
            "\u{202E}bob",
            "b\u{200B}ob",
            "\u{3164}",
            "bo\u{0301}b\u{0301}",
        ] {
            assert_eq!(
                check_display_name(bad),
                Err(Error::Malformed("display_name")),
                "{bad:?}"
            );
        }
        check_display_name("").unwrap();
        check_display_name("Zo\u{eb}'s agent \u{1D11E}").unwrap();
        // SPEC 13.1.2: one presentation selector right after an Emoji.
        check_display_name("bob \u{2764}\u{FE0F}").unwrap();
        for bad in [
            "bob\u{FE0F}",
            "\u{2764}\u{FE0F}\u{FE0F}",
            "\u{1F468}\u{200D}\u{1F469}",
        ] {
            assert_eq!(
                check_display_name(bad),
                Err(Error::Malformed("display_name")),
                "{bad:?}"
            );
        }
    }
}
