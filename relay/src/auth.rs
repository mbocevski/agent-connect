//! Mailbox authentication: Ed25519 signatures by the instance key `SK`.
//!
//! WebSocket auth is SPEC §8.2. REST auth reuses the same key with a distinct
//! domain-separation label and a signed request header (see `README.md`).

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::proto::{b64_decode, mailbox_id_from_key};

/// Domain-separation label for the WebSocket challenge (SPEC §8.2).
pub const WS_LABEL: &[u8] = b"agentconnect/v0/relay-auth";
/// Domain-separation label for signed REST requests.
pub const REST_LABEL: &[u8] = b"agentconnect/v0/relay-rest";
/// The `Authorization` scheme for signed REST requests.
pub const REST_SCHEME: &str = "AgentConnect-Ed25519";
/// Accepted clock skew for signed REST requests, in seconds.
pub const REST_MAX_SKEW_SECS: u64 = 300;

/// `N` random bytes from the operating system.
///
/// # Panics
///
/// Panics if the OS random source fails, which is unrecoverable.
#[must_use]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0_u8; N];
    getrandom::fill(&mut buf).expect("OS randomness unavailable");
    buf
}

/// The bytes a client signs to answer the WebSocket challenge.
#[must_use]
pub fn ws_auth_message(nonce: &[u8], relay_host: &str) -> Vec<u8> {
    [WS_LABEL, nonce, relay_host.as_bytes()].concat()
}

/// The bytes a client signs for a REST request.
///
/// `label || method \n path \n ts \n SHA-256(body) || relay_host`
#[must_use]
pub fn rest_auth_message(
    method: &str,
    path: &str,
    ts: u64,
    body: &[u8],
    relay_host: &str,
) -> Vec<u8> {
    let mut m = REST_LABEL.to_vec();
    m.extend_from_slice(format!("{method}\n{path}\n{ts}\n").as_bytes());
    m.extend_from_slice(&Sha256::digest(body));
    m.extend_from_slice(relay_host.as_bytes());
    m
}

fn verify(sig_key_b64: &str, sig_b64: &str, message: &[u8]) -> Option<String> {
    let key_bytes: [u8; 32] = b64_decode(sig_key_b64)?.try_into().ok()?;
    let sig_bytes: [u8; 64] = b64_decode(sig_b64)?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&key_bytes).ok()?;
    key.verify_strict(message, &Signature::from_bytes(&sig_bytes))
        .ok()?;
    Some(mailbox_id_from_key(&key_bytes))
}

/// Verify a WebSocket `auth` frame; returns the authenticated mailbox id.
#[must_use]
pub fn verify_ws_auth(
    nonce: &[u8],
    relay_host: &str,
    sig_key_b64: &str,
    sig_b64: &str,
) -> Option<String> {
    verify(sig_key_b64, sig_b64, &ws_auth_message(nonce, relay_host))
}

/// Verify an `Authorization: AgentConnect-Ed25519 <sig_key>.<ts>.<sig>` header
/// (all base64url except the decimal unix-seconds `ts`).
///
/// # Errors
///
/// Returns a short reason; callers map every failure to `auth_failed`.
pub fn verify_rest_auth(
    header: &str,
    method: &str,
    path: &str,
    body: &[u8],
    relay_host: &str,
    now_secs: u64,
) -> Result<RestCredentials, &'static str> {
    let token = header
        .strip_prefix(REST_SCHEME)
        .and_then(|r| r.strip_prefix(' '))
        .ok_or("unsupported authorization scheme")?;
    let mut parts = token.trim().split('.');
    let (Some(key), Some(ts), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed credentials");
    };
    let ts: u64 = ts.parse().map_err(|_| "malformed timestamp")?;
    if ts.abs_diff(now_secs) > REST_MAX_SKEW_SECS {
        return Err("timestamp outside the accepted window");
    }
    let mailbox = verify(
        key,
        sig,
        &rest_auth_message(method, path, ts, body, relay_host),
    )
    .ok_or("bad signature")?;
    Ok(RestCredentials {
        mailbox,
        sig: sig.to_owned(),
        ts,
    })
}

/// A verified signed REST request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestCredentials {
    /// The authenticated mailbox.
    pub mailbox: String,
    /// The request signature (the replay-cache key, with the mailbox).
    pub sig: String,
    /// The signed timestamp, unix seconds.
    pub ts: u64,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::proto::b64_encode;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn pub_b64(k: &SigningKey) -> String {
        b64_encode(k.verifying_key().as_bytes())
    }

    #[test]
    fn ws_auth_roundtrip_and_failures() {
        let k = key(1);
        let nonce = [9_u8; 32];
        let sig = b64_encode(&k.sign(&ws_auth_message(&nonce, "relay.test")).to_bytes());
        let id = verify_ws_auth(&nonce, "relay.test", &pub_b64(&k), &sig).unwrap();
        assert_eq!(id, mailbox_id_from_key(k.verifying_key().as_bytes()));
        assert!(verify_ws_auth(&[8; 32], "relay.test", &pub_b64(&k), &sig).is_none());
        assert!(verify_ws_auth(&nonce, "other.test", &pub_b64(&k), &sig).is_none());
        assert!(verify_ws_auth(&nonce, "relay.test", &pub_b64(&key(2)), &sig).is_none());
        assert!(verify_ws_auth(&nonce, "relay.test", "short", &sig).is_none());
        assert!(verify_ws_auth(&nonce, "relay.test", &pub_b64(&k), "short").is_none());
    }

    fn rest_header(k: &SigningKey, method: &str, path: &str, ts: u64, body: &[u8]) -> String {
        let sig = k.sign(&rest_auth_message(method, path, ts, body, "relay.test"));
        format!(
            "{REST_SCHEME} {}.{ts}.{}",
            pub_b64(k),
            b64_encode(&sig.to_bytes())
        )
    }

    #[test]
    fn rest_auth_binds_method_path_body_time_and_host() {
        let k = key(3);
        let h = rest_header(&k, "POST", "/v0/invites", 1000, b"{}");
        let ok = |h: &str, m, p, b: &[u8], host, now| verify_rest_auth(h, m, p, b, host, now);
        assert!(ok(&h, "POST", "/v0/invites", b"{}", "relay.test", 1000).is_ok());
        assert!(ok(&h, "POST", "/v0/invites", b"{}", "relay.test", 1300).is_ok());
        assert!(ok(&h, "POST", "/v0/invites", b"{}", "relay.test", 700).is_ok());
        assert!(ok(&h, "POST", "/v0/invites", b"{}", "relay.test", 1301).is_err());
        assert!(ok(&h, "DELETE", "/v0/invites", b"{}", "relay.test", 1000).is_err());
        assert!(ok(&h, "POST", "/v0/invites/x", b"{}", "relay.test", 1000).is_err());
        assert!(ok(&h, "POST", "/v0/invites", b"{ }", "relay.test", 1000).is_err());
        assert!(ok(&h, "POST", "/v0/invites", b"{}", "evil.test", 1000).is_err());
    }

    #[test]
    fn rest_auth_rejects_malformed_headers() {
        let bad = |h: &str| verify_rest_auth(h, "GET", "/", b"", "relay.test", 0).is_err();
        assert!(bad("Bearer abc"));
        assert!(bad(REST_SCHEME));
        assert!(bad(&format!("{REST_SCHEME} a.b")));
        assert!(bad(&format!("{REST_SCHEME} a.b.c.d")));
        assert!(bad(&format!("{REST_SCHEME} a.notanumber.c")));
    }

    #[test]
    fn randomness_differs() {
        assert_ne!(random_bytes::<32>(), random_bytes::<32>());
    }
}
