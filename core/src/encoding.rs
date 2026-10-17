//! Byte encodings: unpadded base64url, hex, and JCS (RFC 8785) JSON.
//!
//! Every JSON object this protocol signs or carries inside MLS extensions is
//! encoded with JCS. Values here are restricted to what the protocol uses:
//! `null`, booleans, integers, strings, arrays and objects. Floats are
//! rejected, which sidesteps JCS's number serialisation rules.

use std::fmt::Write as _;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Unpadded base64url encoding (RFC 4648 §5), as used throughout SPEC.
#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decodes unpadded base64url. Padding and non-canonical trailing bits are
/// rejected.
///
/// # Errors
///
/// [`Error::Malformed`] naming `what` if `s` isn't canonical base64url.
pub fn b64_decode(s: &str, what: &'static str) -> Result<Vec<u8>> {
    let bytes = Base64UrlUnpadded::decode_vec(s).map_err(|_| Error::Malformed(what))?;
    // base64ct is strict, but re-encoding makes canonicality explicit.
    if b64(&bytes) == s {
        Ok(bytes)
    } else {
        Err(Error::Malformed(what))
    }
}

/// Decodes unpadded base64url into exactly `N` bytes.
///
/// # Errors
///
/// [`Error::Malformed`] if `s` isn't canonical base64url of `N` bytes.
pub fn b64_decode_array<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N]> {
    Ok(*b64_decode_secret(s, what)?)
}

/// Decodes unpadded base64url into exactly `N` bytes held in a
/// [`Zeroizing`] buffer, with no intermediate copies: use it for secrets.
///
/// # Errors
///
/// [`Error::Malformed`] if `s` isn't canonical base64url of `N` bytes.
pub fn b64_decode_secret<const N: usize>(
    s: &str,
    what: &'static str,
) -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0u8; N]);
    let len = Base64UrlUnpadded::decode(s, out.as_mut_slice())
        .map_err(|_| Error::Malformed(what))?
        .len();
    if len != N {
        return Err(Error::Malformed(what));
    }
    // Re-encoding makes canonicality explicit (no stray trailing bits).
    let mut encoded = Zeroizing::new(vec![0u8; Base64UrlUnpadded::encoded_len(out.as_slice())]);
    let canonical = Base64UrlUnpadded::encode(out.as_slice(), &mut encoded).is_ok_and(|e| e == s);
    if canonical {
        Ok(out)
    } else {
        Err(Error::Malformed(what))
    }
}

/// `s` as a JCS (RFC 8785) string literal, quotes included.
pub(crate) fn jcs_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    write_string(s, &mut out);
    out
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Decodes lowercase hex (uppercase is rejected so there is one encoding).
///
/// # Errors
///
/// [`Error::Malformed`] naming `what` on odd length or a non-hex character.
pub fn hex_decode(s: &str, what: &'static str) -> Result<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let raw = s.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(Error::Malformed(what));
    }
    raw.as_chunks::<2>()
        .0
        .iter()
        .map(|[hi, lo]| match (nibble(*hi), nibble(*lo)) {
            (Some(hi), Some(lo)) => Ok(hi << 4 | lo),
            _ => Err(Error::Malformed(what)),
        })
        .collect()
}

/// Serialises `value` as JCS (RFC 8785).
///
/// # Errors
///
/// [`Error::Malformed`] if the value contains a float or can't be serialised.
pub fn jcs<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|_| Error::Malformed("json value"))?;
    let mut out = String::new();
    write_value(&value, &mut out)?;
    Ok(out.into_bytes())
}

/// Parses JSON that must already be in JCS form, so that every value has
/// exactly one accepted encoding.
///
/// # Errors
///
/// [`Error::Malformed`] naming `what` if `bytes` isn't valid JSON for `T` or
/// isn't canonical (e.g. extra whitespace, unsorted or duplicate keys).
pub fn from_jcs<T: DeserializeOwned>(bytes: &[u8], what: &'static str) -> Result<T> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::Malformed(what))?;
    let mut canonical = String::new();
    write_value(&value, &mut canonical).map_err(|_| Error::Malformed(what))?;
    if canonical.as_bytes() != bytes {
        return Err(Error::Malformed(what));
    }
    serde_json::from_value(value).map_err(|_| Error::Malformed(what))
}

fn write_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(Error::Malformed("json number (floats are not allowed)"));
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: sort by the UTF-16 code units of the keys.
            let mut entries: Vec<(Vec<u16>, &String, &Value)> = map
                .iter()
                .map(|(k, v)| (k.encode_utf16().collect(), k, v))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (_, k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jcs_sorts_keys_and_escapes_like_rfc_8785() {
        let v = json!({"b": [1, true, null], "a": "x\u{1}\"\\\n", "\u{e9}": -3, "Z": {}});
        let out = String::from_utf8(jcs(&v).unwrap()).unwrap();
        assert_eq!(
            out,
            "{\"Z\":{},\"a\":\"x\\u0001\\\"\\\\\\n\",\"b\":[1,true,null],\"\u{e9}\":-3}"
        );
    }

    #[test]
    fn jcs_sorts_by_utf16_code_units() {
        // U+1F600 sorts after U+FB01 in UTF-8 byte order, but its UTF-16
        // surrogate pair (0xD83D ...) sorts before 0xFB01.
        let v = json!({"\u{1F600}": 1, "\u{FB01}": 2});
        let out = String::from_utf8(jcs(&v).unwrap()).unwrap();
        assert_eq!(out, "{\"\u{1F600}\":1,\"\u{FB01}\":2}");
    }

    #[test]
    fn jcs_rejects_floats() {
        assert_eq!(
            jcs(&json!({"x": 1.5})),
            Err(Error::Malformed("json number (floats are not allowed)"))
        );
        assert!(jcs(&json!(u64::MAX)).is_ok());
    }

    #[test]
    fn from_jcs_rejects_non_canonical_input() {
        let ok: Value = from_jcs(br#"{"a":1,"b":2}"#, "x").unwrap();
        assert_eq!(ok, json!({"a": 1, "b": 2}));
        for bad in [
            &br#"{"b":2,"a":1}"#[..],
            br#"{"a": 1}"#,
            br#"{"a":1,"a":1}"#,
            br#"{"a":1.0}"#,
            b"not json",
        ] {
            assert_eq!(from_jcs::<Value>(bad, "x"), Err(Error::Malformed("x")));
        }
        // Valid canonical JSON that doesn't fit the target type.
        assert_eq!(from_jcs::<u8>(b"300", "x"), Err(Error::Malformed("x")));
    }

    #[test]
    fn base64url_round_trips_and_is_strict() {
        assert_eq!(b64(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64_decode("-_8", "x").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(b64_decode("-_8=", "x"), Err(Error::Malformed("x")));
        assert_eq!(b64_decode("-_9", "x"), Err(Error::Malformed("x")));
        assert_eq!(b64_decode("+/8", "x"), Err(Error::Malformed("x")));
        assert_eq!(b64_decode_array::<2>("-_8", "x").unwrap(), [0xfb, 0xff]);
        assert_eq!(
            b64_decode_array::<3>("-_8", "x"),
            Err(Error::Malformed("x"))
        );
        assert_eq!(
            b64_decode_array::<1>("-_8", "x"),
            Err(Error::Malformed("x"))
        );
        assert_eq!(*b64_decode_secret::<2>("-_8", "x").unwrap(), [0xfb, 0xff]);
        for bad in ["-_9", "-_8=", "-_"] {
            assert_eq!(
                b64_decode_secret::<2>(bad, "x").map(|s| *s),
                Err(Error::Malformed("x"))
            );
        }
        assert_eq!(jcs_string("a\"\n"), "\"a\\\"\\n\"");
    }

    #[test]
    fn hex_round_trips_and_is_lowercase_only() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex_decode("00abff", "x").unwrap(), vec![0x00, 0xab, 0xff]);
        for bad in ["0", "AB", "zz"] {
            assert_eq!(hex_decode(bad, "x"), Err(Error::Malformed("x")));
        }
    }
}
