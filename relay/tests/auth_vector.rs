//! Contract vector `testdata/relay-auth.json`: signatures made by
//! `agentconnect_core` (and the Python bindings) verify with the relay's
//! `verify_ws_auth` and `verify_rest_auth`, and nothing else does.

use agentconnect_relay::auth::{verify_rest_auth, verify_ws_auth};
use agentconnect_relay::proto::b64_decode;
use serde_json::Value;

fn vector() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/relay-auth.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

#[test]
fn challenge_signatures_verify_for_their_host_only() {
    let v = vector();
    let mailbox = s(&v, "mailbox_id");
    for c in v["challenges"].as_array().unwrap() {
        let nonce = b64_decode(s(c, "nonce")).unwrap();
        let host = s(c, "relay_host");
        let got = verify_ws_auth(&nonce, host, s(&v, "sig_key"), s(c, "sig"));
        assert_eq!(got.as_deref(), Some(mailbox));
        assert_eq!(
            verify_ws_auth(&nonce, "relay.other", s(&v, "sig_key"), s(c, "sig")),
            None
        );
    }
}

#[test]
fn rest_signatures_verify_for_their_request_only() {
    let v = vector();
    for r in v["requests"].as_array().unwrap() {
        let (method, path, host) = (s(r, "method"), s(r, "path"), s(r, "relay_host"));
        let body = s(r, "body").as_bytes();
        let ts = r["ts"].as_u64().unwrap();
        let auth = s(r, "authorization");
        let creds = verify_rest_auth(auth, method, path, body, host, ts).unwrap();
        assert_eq!(creds.mailbox, s(&v, "mailbox_id"));
        assert_eq!(creds.sig, s(r, "sig"));
        assert!(verify_rest_auth(auth, method, "/v0/other", body, host, ts).is_err());
        assert!(verify_rest_auth(auth, method, path, b"tampered", host, ts).is_err());
        assert!(verify_rest_auth(auth, method, path, body, "relay.other", ts).is_err());
    }
}
