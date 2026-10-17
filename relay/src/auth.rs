//! Mailbox authentication: Ed25519 signatures by the instance key `SK`.
//!
//! WebSocket auth is SPEC §8.2. REST auth reuses the same key with a distinct
//! domain-separation label and a signed request header (see `README.md`).

use ed25519_dalek::{Signature, VerifyingKey};

use crate::proto::{b64_decode, mailbox_id_from_key};

/// Domain-separation label for the WebSocket challenge (SPEC §8.2).
pub const WS_LABEL: &[u8] = agentconnect_core::identity::RELAY_AUTH_LABEL;
/// Domain-separation label for signed REST requests.
pub const REST_LABEL: &[u8] = agentconnect_core::identity::RELAY_REST_LABEL;
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

/// The bytes a client signs to answer the WebSocket challenge. Built by
/// `agentconnect_core`, which also signs them, so the layouts can't drift.
/// `None` unless `nonce` is 32 bytes (SPEC §8.2).
#[must_use]
pub fn ws_auth_message(nonce: &[u8], relay_host: &str) -> Option<Vec<u8>> {
    agentconnect_core::identity::relay_auth_message(nonce, relay_host).ok()
}

/// The bytes a client signs for a REST request (built by `agentconnect_core`).
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
    agentconnect_core::identity::relay_rest_message(method, path, ts, body, relay_host)
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
    verify(sig_key_b64, sig_b64, &ws_auth_message(nonce, relay_host)?)
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
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::proto::b64_encode;

    /// Per-run random seed: keys are stable within a run (same `n`, same
    /// key) but never hard-coded.
    static KEY_SEED: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(random_bytes);

    fn key(n: u8) -> SigningKey {
        let secret: [u8; 32] = Sha256::digest([KEY_SEED.as_slice(), &[n]].concat()).into();
        SigningKey::from_bytes(&secret)
    }

    fn pub_b64(k: &SigningKey) -> String {
        b64_encode(k.verifying_key().as_bytes())
    }

    #[test]
    fn ws_auth_roundtrip_and_failures() {
        let k = key(1);
        let nonce = random_bytes::<32>();
        let sig = b64_encode(
            &k.sign(&ws_auth_message(&nonce, "relay.test").unwrap())
                .to_bytes(),
        );
        let id = verify_ws_auth(&nonce, "relay.test", &pub_b64(&k), &sig).unwrap();
        assert_eq!(id, mailbox_id_from_key(k.verifying_key().as_bytes()));
        let other_nonce = random_bytes::<32>();
        assert!(verify_ws_auth(&other_nonce, "relay.test", &pub_b64(&k), &sig).is_none());
        assert!(verify_ws_auth(&nonce, "other.test", &pub_b64(&k), &sig).is_none());
        assert!(verify_ws_auth(&nonce, "relay.test", &pub_b64(&key(2)), &sig).is_none());
        assert!(verify_ws_auth(&nonce, "relay.test", "short", &sig).is_none());
        assert!(verify_ws_auth(&nonce, "relay.test", &pub_b64(&k), "short").is_none());
    }

    #[test]
    fn ws_auth_refuses_nonces_that_are_not_32_bytes() {
        // A signature over `label || X || "x." || "relay.test"` must not be
        // accepted as the answer to nonce `X` at `x.relay.test`, nor the
        // other way round: only 32-byte nonces are ever verified.
        let k = key(3);
        let nonce = random_bytes::<32>();
        let mut long = nonce.to_vec();
        long.extend_from_slice(b"x.");
        let forged = [WS_LABEL, &long, b"relay.test"].concat();
        let sig = b64_encode(&k.sign(&forged).to_bytes());
        assert!(verify_ws_auth(&long, "relay.test", &pub_b64(&k), &sig).is_none());
        assert!(ws_auth_message(&long, "relay.test").is_none());
        assert!(ws_auth_message(&nonce[..31], "relay.test").is_none());
        assert!(verify_ws_auth(&nonce[..31], "relay.test", &pub_b64(&k), &sig).is_none());
        // The same bytes do verify as nonce `X` for the suffixed host: that
        // is why the signer and the verifier both insist on 32 bytes.
        assert!(verify_ws_auth(&nonce, "x.relay.test", &pub_b64(&k), &sig).is_some());
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
