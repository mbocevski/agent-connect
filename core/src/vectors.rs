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
use crate::identity::{Identity, fingerprint, mailbox_id};
use crate::invite::{InviteLink, InviteSecret, derive_join_key, derive_welcome_key};
use crate::join::join_request_mac;
use crate::padding::{BUCKETS, bucket_for, max_plaintext_len};
use crate::rng::Rng;
use crate::sas::Sas;

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
    for i in 0..3u8 {
        let id: [u8; 16] = rng.array().unwrap();
        let secret: [u8; 32] = rng.array().unwrap();
        let invite = InviteSecret::from_parts(id, secret);
        let key_package: Vec<u8> = (0..40).map(|b| b ^ i).collect();
        let mailbox = mailbox_id(&rng.array::<32>().unwrap());
        let mac = join_request_mac(&invite.join_key(), &id, &key_package, &mailbox);
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
        "SPEC 3.5 join_key/welcome_key (HKDF-SHA256), SPEC 6.1 JoinRequest MAC (invite_id raw bytes, mailbox_id ASCII) and SPEC 6.4 WrappedWelcome (nonce || ChaCha20-Poly1305). Hex unless noted.",
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
        let s = InviteSecret::from_parts(rng.array().unwrap(), rng.array().unwrap());
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
