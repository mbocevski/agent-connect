//! Shared test vectors in `testdata/` (TESTING.md, "Contract tests").
//!
//! Each test recomputes its vector file from fixed inputs and compares it
//! with the committed file. To regenerate after an intentional change:
//!
//! ```text
//! just vectors        # AC_REGENERATE_VECTORS=1 cargo test -p agentconnect-core --lib vectors
//! ```
//!
//! Every input comes from a [`Rng`] seeded with the file's `seed` field, so
//! a check reads its inputs from the committed file and recomputes the
//! outputs; no key material is written in this source. Regeneration picks a
//! fresh seed, `SHA-256(AC_TEST_SEED ‖ file name)` (random unless
//! `AC_TEST_SEED` is set), so `AC_TEST_SEED=<n> just vectors` is
//! reproducible. The Python suite (`core-py/tests/test_vectors.py`)
//! checks the same files through the bindings.

use std::path::PathBuf;

use serde_json::{Value, json};

use crate::Error;
use crate::clock::FakeClock;
use crate::encoding::{b64, hex, hex_decode};
use crate::identity::{
    Identity, canonical_relay_host, fingerprint, mailbox_id, relay_auth_message, relay_rest_message,
};

/// Relay hosts for the canonical-form vector (none is a secret).
const HOST_CASES: [&str; 12] = [
    "relay.test",
    "Relay.TEST",
    "RELAY.example.org:8443",
    "127.0.0.1:8080",
    "[::1]:8080",
    "[FE80::1]",
    "user@relay.test",
    "relay.test:0",
    "relay.test:08080",
    "relay.test:99999",
    "relay.test/path",
    "",
];
use crate::invite::{InviteLink, InviteSecret, derive_join_key, derive_welcome_key};
use crate::join::{MacInput, join_request_mac};
use crate::padding::{BUCKETS, bucket_for, max_plaintext_len};
use crate::rng::Rng;
use crate::sas::Sas;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata")
        .join(name)
}

/// Compares `computed` with `testdata/<name>`, or rewrites the file when
/// `AC_REGENERATE_VECTORS=1`.
fn regenerating() -> bool {
    std::env::var("AC_REGENERATE_VECTORS").as_deref() == Ok("1")
}

/// The seeded RNG for vector file `name`: its stored seed when checking, a
/// fresh per-run seed when regenerating.
fn vector_rng(name: &str) -> ([u8; 32], Rng) {
    let seed: [u8; 32] = if regenerating() {
        Rng::for_test(name).array().unwrap()
    } else {
        let raw = std::fs::read_to_string(path(name))
            .unwrap_or_else(|e| panic!("{name}: {e}; run `just vectors` to create it"));
        let stored: Value = serde_json::from_str(&raw).unwrap();
        hex_decode(stored["seed"].as_str().unwrap(), "seed")
            .unwrap()
            .try_into()
            .unwrap()
    };
    (seed, Rng::seeded(seed))
}

fn check_or_write(name: &str, computed: &Value) {
    let p = path(name);
    if regenerating() {
        let text = serde_json::to_string_pretty(computed).unwrap() + "\n";
        std::fs::write(&p, text).unwrap();
        return;
    }
    let raw = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("{name}: {e}; run `just vectors` to create it"));
    let stored: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        &stored, computed,
        "{name} is stale; run `just vectors` if the change is intended"
    );
}

fn header(description: &str, seed: &[u8; 32]) -> Value {
    json!({
        "description": description,
        "generator": "core/src/vectors.rs (just vectors)",
        "seed": hex(seed),
    })
}

#[test]
fn invite_kdf_vectors() {
    let (seed, rng) = vector_rng("invite-kdf.json");
    let mut cases = Vec::new();
    for (i, display_name) in (0..3u8).zip(["bob", "", "Zo\u{eb}'s agent \u{1D11E}"]) {
        let id: [u8; 16] = rng.array().unwrap();
        let secret: [u8; 32] = rng.array().unwrap();
        let invite = InviteSecret::from_parts(id, &secret);
        let key_package: Vec<u8> = (0..40).map(|b| b ^ i).collect();
        let mailbox = mailbox_id(&rng.array::<32>().unwrap());
        let input = MacInput {
            invite_id: &id,
            key_package: &key_package,
            mailbox_id: &mailbox,
            display_name,
        };
        let mac = join_request_mac(&invite.join_key(), &input);
        // The exact HMAC input, built independently of `join.rs`.
        let lp = |b: &[u8]| [&u32::try_from(b.len()).unwrap().to_be_bytes()[..], b].concat();
        let mac_input = [
            b"agentconnect/v0/join-request".to_vec(),
            lp(&id),
            lp(&key_package),
            lp(mailbox.as_bytes()),
            lp(display_name.as_bytes()),
        ]
        .concat();
        let mut h =
            <Hmac<Sha256> as KeyInit>::new_from_slice(invite.join_key().as_slice()).unwrap();
        h.update(&mac_input);
        assert_eq!(h.finalize().into_bytes().as_slice(), mac);
        let nonce: [u8; 12] = rng.array().unwrap();
        let welcome = format!("welcome bytes {i}").into_bytes();
        let wrapped = invite.wrap_welcome_with_nonce(&nonce, &welcome).unwrap();
        assert_eq!(invite.unwrap_welcome(&wrapped).unwrap(), welcome);
        cases.push(json!({
            "invite_id": hex(&id),
            "invite_secret": hex(&secret),
            "join_key": hex(derive_join_key(&id, &secret).as_slice()),
            "welcome_key": hex(derive_welcome_key(&id, &secret).as_slice()),
            "join_request": {
                "key_package": hex(&key_package),
                "mailbox_id": mailbox,
                "display_name": display_name,
                "mac_input": hex(&mac_input),
                "mac": hex(&mac),
            },
            "wrapped_welcome": {
                "nonce": hex(&nonce),
                "welcome": hex(&welcome),
                "wrapped": hex(&wrapped),
            },
        }));
    }
    let mut v = header(
        "SPEC 3.5 join_key/welcome_key (HKDF-SHA256), SPEC 6.1 JoinRequest MAC over label || lp(invite_id raw bytes) || lp(key_package) || lp(mailbox_id ASCII) || lp(display_name UTF-8), lp(x) = u32be(len(x)) || x and SPEC 6.4 WrappedWelcome (nonce || ChaCha20-Poly1305). Hex unless noted.",
        &seed,
    );
    v["cases"] = cases.into();
    check_or_write("invite-kdf.json", &v);
}

fn emoji_table() -> Vec<Value> {
    let raw = std::fs::read_to_string(path("sas-emoji.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn sas_vectors() {
    let table = emoji_table();
    let (seed, rng) = vector_rng("sas-vectors.json");
    let mut cases = Vec::new();
    for epoch in [0u64, 1, 2, 255, 1 << 40] {
        let ea: [u8; 32] = rng.array().unwrap();
        let group_id: [u8; 16] = rng.array().unwrap();
        let sas = Sas::derive(&ea, &group_id, epoch);
        let indices = sas.emoji_indices();
        let emoji: Vec<Value> = indices
            .iter()
            .map(|i| table[usize::from(*i)]["emoji"].clone())
            .collect();
        cases.push(json!({
            "epoch_authenticator": hex(&ea),
            "group_id": hex(&group_id),
            "epoch": epoch,
            "sas_bytes": hex(&sas.bytes()),
            "emoji_indices": indices,
            "emoji": emoji,
            "decimal": sas.decimal(),
        }));
    }
    let mut v = header(
        "SPEC 3.5/11 SAS: sas_bytes = HKDF(ikm = epoch_authenticator, salt = group_id, info = 'agentconnect/v0/sas' || u64be(epoch), L = 6); 7 x 6-bit emoji indices into sas-emoji.json; three 13-bit numbers + 1000.",
        &seed,
    );
    v["cases"] = cases.into();
    check_or_write("sas-vectors.json", &v);
}

#[test]
fn padding_vectors() {
    // No random inputs; the seed only keeps the file format uniform.
    let (seed, _) = vector_rng("padding-vectors.json");
    let mut lens: Vec<usize> = vec![0, 1, 63, 64];
    for b in BUCKETS {
        // The largest plaintext in the bucket and the first one past it,
        // accounting for the 1-, 2- or 4-byte length prefix.
        let fits = (b.saturating_sub(100)..=b)
            .filter(|n| bucket_for(*n) == Some(b))
            .max();
        if let Some(n) = fits {
            lens.extend([n, n + 1]);
        }
    }
    lens.push(max_plaintext_len());
    lens.sort_unstable();
    lens.dedup();
    let cases: Vec<Value> = lens
        .iter()
        .map(|n| json!({"plaintext_len": n, "bucket": bucket_for(*n)}))
        .collect();
    let mut v = header(
        "SPEC 7.1 padding buckets. The PrivateMessage AEAD ciphertext of an application message is exactly `bucket` bytes: plaintext + varint length + 66-byte signature field + 16-byte tag, padded. null = too large.",
        &seed,
    );
    v["buckets"] = BUCKETS.to_vec().into();
    v["max_plaintext_len"] = max_plaintext_len().into();
    v["cases"] = cases.into();
    check_or_write("padding-vectors.json", &v);
}

#[test]
fn instance_cert_vectors() {
    let clock = FakeClock::default();
    let mut cases = Vec::new();
    let (seed, rng) = vector_rng("instance-cert.json");
    for _ in 0..2 {
        let ik_secret: [u8; 32] = rng.array().unwrap();
        let identity = Identity::from_secret_bytes(&ik_secret);
        let instance = identity.create_instance(&rng, &clock).unwrap();
        let cert = instance.cert();
        cert.verify().unwrap();
        cases.push(json!({
            "ik_secret": hex(&ik_secret),
            "ik_pub": hex(&identity.public_key()),
            "identity": identity.id(),
            "fingerprint": fingerprint(&identity.public_key()),
            "sig_key": hex(&cert.sig_key),
            "mailbox_id": instance.mailbox_id(),
            "instance_id": cert.instance_id_hex(),
            "created_at": cert.created_at,
            "signing_input": String::from_utf8(cert.signing_input().unwrap()).unwrap(),
            "cert_json": String::from_utf8(cert.to_json().unwrap()).unwrap(),
            "sig": b64(&cert.sig),
        }));
    }
    let mut v = header(
        "SPEC 2/3.3 identity id, fingerprint, mailbox id and InstanceCert: sig = Ed25519(IK, 'agentconnect/v0/instance-cert' || JCS(cert without sig)); cert_json is the JCS encoding carried in ac_instance_cert.",
        &seed,
    );
    v["cases"] = cases.into();
    check_or_write("instance-cert.json", &v);
}

#[test]
fn relay_auth_vectors() {
    let (seed, rng) = vector_rng("relay-auth.json");
    let identity = Identity::from_secret_bytes(&rng.array().unwrap());
    let instance = identity
        .create_instance(&rng, &FakeClock::default())
        .unwrap();
    let challenges: Vec<Value> = ["relay.test", "127.0.0.1:8080"]
        .into_iter()
        .map(|host| {
            let nonce: [u8; 32] = rng.array().unwrap();
            json!({
                "nonce": b64(&nonce),
                "relay_host": host,
                "message": hex(&relay_auth_message(&nonce, host).unwrap()),
                "sig": b64(&instance.sign_relay_challenge(&nonce, host).unwrap()),
            })
        })
        .collect();
    let requests: Vec<Value> = [
        ("POST", "/v0/invites", "{\"invite_id\":\"x\"}"),
        ("DELETE", "/v0/invites/AAAAAAAAAAAAAAAAAAAAAA", ""),
    ]
    .into_iter()
    .zip([1_735_689_600_u64, 1_735_689_900])
    .map(|((method, path, body), ts)| {
        let sig =
            b64(&instance.sign_relay_request(method, path, ts, body.as_bytes(), "relay.test").unwrap());
        json!({
            "method": method,
            "path": path,
            "ts": ts,
            "body": body,
            "relay_host": "relay.test",
            "message": hex(&relay_rest_message(method, path, ts, body.as_bytes(), "relay.test").unwrap()),
            "sig": sig,
            "authorization": format!(
                "AgentConnect-Ed25519 {}.{ts}.{sig}",
                b64(&instance.public_key())
            ),
        })
    })
    .collect();
    let secret = instance.to_secret_bytes().unwrap();
    let mut v = header(
        "SPEC 8.1.1/8.2 relay authentication by the instance key SK: challenge sig = Ed25519(SK, 'agentconnect/v0/relay-auth' || nonce || relay_host); REST sig = Ed25519(SK, 'agentconnect/v0/relay-rest' || METHOD '\\n' || PATH '\\n' || ts '\\n' || SHA-256(body) || relay_host). instance is Instance.to_secret_bytes of a seeded test instance.",
        &seed,
    );
    v["instance"] = String::from_utf8(secret.to_vec()).unwrap().into();
    v["sig_key"] = b64(&instance.public_key()).into();
    v["mailbox_id"] = instance.mailbox_id().into();
    v["challenges"] = challenges.into();
    v["requests"] = requests.into();
    // SPEC 8.1.1: the canonical relay host, applied by signer and verifier.
    v["hosts"] = HOST_CASES
        .iter()
        .map(|h| json!({"input": h, "canonical": canonical_relay_host(h).ok()}))
        .collect::<Vec<_>>()
        .into();
    check_or_write("relay-auth.json", &v);
}

fn url_error(e: &Error) -> &'static str {
    match e {
        Error::UnsupportedVersion => "unsupported_version",
        Error::InvalidInviteUrl(_) => "invalid_url",
        _ => "other",
    }
}

#[test]
fn invite_url_vectors() {
    let (seed, rng) = vector_rng("invite-urls.json");
    let mut valid = Vec::new();
    for host in ["relay.example", "relay.example:8443", "localhost:8080"] {
        let s = InviteSecret::from_parts(rng.array().unwrap(), &rng.array().unwrap());
        let link = InviteLink::parse(&format!(
            "{}://{host}/i/{}#v=0&s={}",
            if host.starts_with("localhost") {
                "http"
            } else {
                "https"
            },
            s.id_b64(),
            b64(s.secret())
        ))
        .unwrap();
        valid.push(json!({
            "url": link.url(),
            "relay_host": host,
            "invite_id": s.id_b64(),
            "invite_secret": b64(s.secret()),
        }));
    }
    let id = b64(&rng.array::<16>().unwrap());
    let sec = b64(&rng.array::<32>().unwrap());
    // Unknown parameters are ignored, in any order.
    let extra = format!("https://relay.example/i/{id}#x=1&s={sec}&v=0");
    let parsed = InviteLink::parse(&extra).unwrap();
    valid.push(json!({
        "url": extra,
        "relay_host": parsed.relay_host(),
        "invite_id": id,
        "invite_secret": sec,
    }));
    let bad = [
        format!("https://relay.example/i/{id}#v=1&s={sec}"),
        format!("https://relay.example/i/{id}#s={sec}"),
        format!("https://relay.example/i/{id}#v=0"),
        format!("https://relay.example/i/{id}"),
        format!("https://relay.example/i/{id}?s={sec}#v=0&s={sec}"),
        format!("http://relay.example/i/{id}#v=0&s={sec}"),
        format!("ftp://relay.example/i/{id}#v=0&s={sec}"),
        format!("https://relay.example/x/{id}#v=0&s={sec}"),
        format!("https://relay.example/i/{id}x#v=0&s={sec}"),
        format!("https://relay.example/i/{id}#v=0&s={sec}A"),
        format!("https://relay.example/i/{id}#v=0&s={sec}&s={sec}"),
        format!("https://user@relay.example/i/{id}#v=0&s={sec}"),
        format!("https:///i/{id}#v=0&s={sec}"),
        "relay.example".to_owned(),
        format!("https://relay.example#v=0&s={sec}"),
    ];
    let invalid: Vec<Value> = bad
        .iter()
        .map(|u| {
            let e = InviteLink::parse(u).expect_err(u);
            json!({"url": u, "error": url_error(&e)})
        })
        .collect();
    let mut v = header(
        "SPEC 4.1 invite URLs. error: unsupported_version (abort on v != 0) or invalid_url. http is accepted for loopback hosts only.",
        &seed,
    );
    v["valid"] = valid.into();
    v["invalid"] = invalid.into();
    check_or_write("invite-urls.json", &v);
}
