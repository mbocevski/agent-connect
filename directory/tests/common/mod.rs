//! Shared harness: an in-process directory on the in-memory store, a fake
//! clock, a fake owner-file fetcher and a test double for the verifier.
//! Nothing here sleeps or touches the network.
//!
//! The verifier double never does cryptography. A test "signs" an object by
//! registering the hash of its exact bytes, and "issues" a token by
//! registering its id; anything else is refused as the real verifier would
//! (tampered bytes: bad signature; unknown token: unknown key). Canonical
//! form is checked with the core's own JCS check. The double lives in tests
//! only and is never linked into the binary.

#![allow(dead_code, clippy::missing_panics_doc, clippy::must_use_candidate)]

pub mod store_suite;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentconnect_core::clock::FakeClock;
use agentconnect_core::encoding::{b64, from_jcs, hex, jcs};
use agentconnect_core::{Identity, Rng};
use agentconnect_directory::owner::{BoxFuture, FetchError, OwnerFetcher};
use agentconnect_directory::verify::{
    Door, ListingToken, OwnerVerdict, Rejection, TokenKey, TokenRevocation, VerifiedListing,
    Verifier, Withdrawal,
};
use agentconnect_directory::{Directory, HttpConfig, MemoryStore, Settings, Store, app};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

pub const HOST: &str = "agents.test";
pub const RELAY: &str = "relay.test";
pub const DAY: u64 = 86_400;

fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// A fresh label for per-run randomness.
pub fn label(prefix: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!("{prefix}:{}", N.fetch_add(1, Ordering::Relaxed))
}

/// Random bytes from the per-run seed, as base64url.
pub fn random_b64(n: usize) -> String {
    let mut buf = vec![0_u8; n];
    Rng::for_test(&label("bytes")).fill(&mut buf).unwrap();
    b64(&buf)
}

/// A fresh identity id (`ac:v0:...`) from the per-run seed.
pub fn identity() -> String {
    Identity::generate(&Rng::for_test(&label("identity")))
        .unwrap()
        .id()
}

/// The verifier double.
#[derive(Default)]
pub struct FakeVerifier {
    signed: Mutex<HashSet<String>>,
    tokens: Mutex<HashSet<String>>,
    pub calls: AtomicU64,
}

impl FakeVerifier {
    /// Treat `bytes` as validly signed by the key it names.
    pub fn sign(&self, bytes: &[u8]) {
        self.signed.lock().unwrap().insert(sha(bytes));
    }

    /// Treat `token_id` as issued by a configured operator key.
    pub fn issue(&self, token_id: &str) {
        self.tokens.lock().unwrap().insert(token_id.to_owned());
    }

    fn canonical(bytes: &[u8]) -> Result<Value, Rejection> {
        from_jcs::<Value>(bytes, "object").map_err(|_| Rejection::Malformed("not canonical"))
    }

    fn check_signed(&self, bytes: &[u8]) -> Result<(), Rejection> {
        if self.signed.lock().unwrap().contains(&sha(bytes)) {
            Ok(())
        } else {
            Err(Rejection::BadSignature)
        }
    }
}

fn s(v: &Value, k: &str) -> Result<String, Rejection> {
    v[k].as_str()
        .map(str::to_owned)
        .ok_or(Rejection::Malformed("missing field"))
}

fn n(v: &Value, k: &str) -> Result<u64, Rejection> {
    v[k].as_u64().ok_or(Rejection::Malformed("missing field"))
}

impl Verifier for FakeVerifier {
    fn verify_listing(&self, bytes: &[u8]) -> Result<VerifiedListing, Rejection> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let card = Self::canonical(bytes)?;
        self.check_signed(bytes)?;
        let p = &card["capabilities"]["extensions"][0]["params"];
        Ok(VerifiedListing {
            name: s(p, "name")?,
            identity: s(p, "identity")?,
            directory: s(p, "directory")?,
            relay: s(p, "relay")?,
            seq: n(p, "seq")?,
            issued_at: n(p, "issued_at")?,
            door: match p.get("door") {
                Some(d) => Some(Door {
                    id: s(d, "id")?,
                    expires_at: n(d, "expires_at")?,
                }),
                None => None,
            },
            owner_domain: p["owner_domain"].as_str().map(str::to_owned),
            token: p["token"].clone(),
        })
    }

    fn verify_token(&self, t: &Value) -> Result<ListingToken, Rejection> {
        let token_id = s(t, "token_id")?;
        if !self.tokens.lock().unwrap().contains(&token_id) {
            return Err(Rejection::UnknownKey);
        }
        Ok(ListingToken {
            token_id,
            directory: s(t, "directory")?,
            name: s(t, "name")?,
            identity: s(t, "identity")?,
            owner_domain: t["owner_domain"].as_str().map(str::to_owned),
            issued_at: n(t, "issued_at")?,
            expires_at: n(t, "expires_at")?,
            key_id: s(t, "key_id")?,
        })
    }

    fn verify_withdrawal(&self, bytes: &[u8]) -> Result<Withdrawal, Rejection> {
        let w = Self::canonical(bytes)?;
        self.check_signed(bytes)?;
        Ok(Withdrawal {
            directory: s(&w, "directory")?,
            name: s(&w, "name")?,
            identity: s(&w, "identity")?,
            seq: n(&w, "seq")?,
            ts: n(&w, "ts")?,
        })
    }

    fn verify_revocation(&self, bytes: &[u8]) -> Result<TokenRevocation, Rejection> {
        let r = Self::canonical(bytes)?;
        self.check_signed(bytes)?;
        Ok(TokenRevocation {
            token_id: s(&r, "token_id")?,
            revoked_at: n(&r, "revoked_at")?,
            reason: s(&r, "reason")?,
            key_id: s(&r, "key_id")?,
        })
    }

    fn owner_verdict(&self, file: &[u8], identity: &str, listing: &str) -> OwnerVerdict {
        let Ok(f) = serde_json::from_slice::<Value>(file) else {
            return OwnerVerdict::Invalid;
        };
        if let Some(r) = f["revoked"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["identity"] == identity)
        {
            return OwnerVerdict::Revoked {
                revoked_at: r["revoked_at"].as_u64().unwrap_or(0),
                reason: r["reason"].as_str().unwrap_or("compromised").to_owned(),
            };
        }
        let listed = f["identities"].as_array().into_iter().flatten().any(|e| {
            e["identity"] == identity
                && e.get("listings")
                    .and_then(Value::as_array)
                    .is_none_or(|ls| ls.iter().any(|l| l == listing))
        });
        if listed {
            OwnerVerdict::Vouched
        } else {
            OwnerVerdict::NotVouched
        }
    }

    fn token_keys(&self) -> Vec<TokenKey> {
        vec![TokenKey {
            key_id: "test-key".to_owned(),
            public_key: "test-public-key".to_owned(),
        }]
    }
}

/// The owner-file fetcher double.
#[derive(Default)]
pub struct FakeFetcher {
    files: Mutex<HashMap<String, Result<Vec<u8>, FetchError>>>,
    pub calls: AtomicU64,
}

impl FakeFetcher {
    pub fn serve(&self, domain: &str, file: &Value) {
        self.files
            .lock()
            .unwrap()
            .insert(domain.to_owned(), Ok(serde_json::to_vec(file).unwrap()));
    }

    pub fn fail(&self, domain: &str, e: FetchError) {
        self.files.lock().unwrap().insert(domain.to_owned(), Err(e));
    }

    /// Serve a file that vouches for `identity`.
    pub fn vouch(&self, domain: &str, identity: &str) {
        self.serve(
            domain,
            &json!({"v": 0, "identities": [{"identity": identity}]}),
        );
    }
}

impl OwnerFetcher for FakeFetcher {
    fn fetch<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let r = self
            .files
            .lock()
            .unwrap()
            .get(domain)
            .cloned()
            .unwrap_or(Err(FetchError::Transport));
        Box::pin(async move { r })
    }
}

/// One skill: id, name, tags.
pub type SkillSpec = (&'static str, &'static str, &'static [&'static str]);

/// A listing to build.
#[derive(Clone)]
pub struct Spec {
    pub name: String,
    pub identity: String,
    pub seq: u64,
    pub issued_at: u64,
    pub door_expires_at: Option<u64>,
    pub owner_domain: Option<String>,
    pub card_name: String,
    pub description: String,
    pub organization: Option<String>,
    pub skills: Vec<SkillSpec>,
    pub token_id: String,
    pub token_expires_at: u64,
    pub token_directory: String,
    pub token_name: Option<String>,
    pub directory: String,
    pub relay: String,
}

/// A built listing: its exact bytes and how it was made.
pub struct Built {
    pub bytes: Vec<u8>,
    pub spec: Spec,
}

impl Spec {
    pub fn card(&self) -> Value {
        let mut params = json!({
            "directory": self.directory,
            "identity": self.identity,
            "issued_at": self.issued_at,
            "name": self.name,
            "relay": self.relay,
            "seq": self.seq,
            "token": self.token(),
            "v": 0,
        });
        if let Some(t) = self.door_expires_at {
            params["door"] =
                json!({"expires_at": t, "id": random_b64(16), "key": random_b64(1216)});
        }
        if let Some(d) = &self.owner_domain {
            params["owner_domain"] = json!(d);
        }
        let skills: Vec<Value> = self
            .skills
            .iter()
            .map(|(id, name, tags)| json!({"id": id, "name": name, "tags": tags}))
            .collect();
        let mut card = json!({
            "capabilities": {"extensions": [{
                "description": "Reachable end-to-end encrypted through AgentConnect.",
                "params": params,
                "required": true,
                "uri": "https://yggdrasill.network/ext/agentconnect/e2e/v0",
            }]},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "description": self.description,
            "name": self.card_name,
            "signatures": [{"protected": random_b64(48), "signature": random_b64(64)}],
            "supportedInterfaces": [{
                "protocolBinding": "AGENTCONNECT",
                "protocolVersion": "0",
                "url": format!("https://{}/a/{}.json", self.directory, self.name),
            }],
            "version": "1.0.0",
        });
        if !skills.is_empty() {
            card["skills"] = json!(skills);
        }
        if let (Some(org), Some(d)) = (&self.organization, &self.owner_domain) {
            card["provider"] = json!({"organization": org, "url": format!("https://{d}")});
        }
        card
    }

    pub fn token(&self) -> Value {
        let mut t = json!({
            "directory": self.token_directory,
            "expires_at": self.token_expires_at,
            "identity": self.identity,
            "issued_at": self.issued_at.saturating_sub(DAY),
            "key_id": "test-key",
            "name": self.token_name.clone().unwrap_or_else(|| self.name.clone()),
            "sig": random_b64(64),
            "token_id": self.token_id,
            "v": 0,
        });
        if let Some(d) = &self.owner_domain {
            t["owner_domain"] = json!(d);
        }
        t
    }
}

pub struct Harness {
    pub dir: Arc<Directory<MemoryStore>>,
    pub clock: Arc<FakeClock>,
    pub verifier: Arc<FakeVerifier>,
    pub fetcher: Arc<FakeFetcher>,
    pub http: HttpConfig,
}

/// A response: status, headers, body bytes.
pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    }
}

pub const CLIENT: &str = "198.51.100.7";

impl Harness {
    pub fn new() -> Self {
        Self::with(|d| d)
    }

    pub fn with(f: impl FnOnce(Directory<MemoryStore>) -> Directory<MemoryStore>) -> Self {
        let clock = Arc::new(FakeClock::default());
        let verifier = Arc::new(FakeVerifier::default());
        let fetcher = Arc::new(FakeFetcher::default());
        let dir = Directory::new(
            MemoryStore::new(),
            verifier.clone(),
            fetcher.clone(),
            clock.clone(),
            Settings {
                host: HOST.to_owned(),
                relays: vec![RELAY.to_owned()],
            },
        );
        Self {
            dir: Arc::new(f(dir)),
            clock,
            verifier,
            fetcher,
            http: HttpConfig::default(),
        }
    }

    pub fn now(&self) -> u64 {
        self.dir.now()
    }

    pub fn advance(&self, secs: u64) {
        self.clock.advance(Duration::from_secs(secs));
    }

    /// A listing spec with sensible defaults and a fresh, issued token.
    pub fn spec(&self, name: &str, identity: &str) -> Spec {
        let now = self.now();
        let token_id = random_b64(16);
        self.verifier.issue(&token_id);
        Spec {
            name: name.to_owned(),
            identity: identity.to_owned(),
            seq: 1,
            issued_at: now,
            door_expires_at: Some(now + 5 * DAY + 3600),
            owner_domain: None,
            card_name: format!("Card {name}"),
            description: format!("Agent {name} does things."),
            organization: None,
            skills: vec![],
            token_id,
            token_expires_at: now + 90 * DAY,
            token_directory: HOST.to_owned(),
            token_name: None,
            directory: HOST.to_owned(),
            relay: RELAY.to_owned(),
        }
    }

    /// Canonical, signed bytes for `spec`.
    pub fn build(&self, spec: &Spec) -> Built {
        let bytes = jcs(&spec.card()).unwrap();
        self.verifier.sign(&bytes);
        Built {
            bytes,
            spec: spec.clone(),
        }
    }

    /// Build and publish; panics unless accepted.
    pub async fn publish(&self, spec: &Spec) -> Built {
        let b = self.build(spec);
        let r = self.post("/v0/listings", b.bytes.clone()).await;
        assert!(r.status.is_success(), "{} {}", r.status, r.text());
        b
    }

    /// A signed withdrawal.
    pub fn withdrawal(&self, name: &str, identity: &str, seq: u64) -> Vec<u8> {
        let w = json!({
            "directory": HOST, "identity": identity, "name": name, "seq": seq,
            "sig": random_b64(64), "ts": self.now(), "v": 0,
        });
        let bytes = jcs(&w).unwrap();
        self.verifier.sign(&bytes);
        bytes
    }

    /// A signed token revocation.
    pub fn revocation(&self, token_id: &str) -> Vec<u8> {
        let r = json!({
            "key_id": "test-key", "reason": "spam", "revoked_at": self.now(),
            "sig": random_b64(64), "token_id": token_id, "v": 0,
        });
        let bytes = jcs(&r).unwrap();
        self.verifier.sign(&bytes);
        bytes
    }

    pub async fn send(&self, req: Request<Body>) -> Resp {
        self.send_from(req, CLIENT.parse().unwrap()).await
    }

    pub async fn send_from(&self, mut req: Request<Body>, ip: IpAddr) -> Resp {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
        let resp = app(self.dir.clone(), self.http.clone())
            .oneshot(req)
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        Resp {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes().to_vec(),
        }
    }

    pub async fn get(&self, path: &str) -> Resp {
        self.get_with(path, &[]).await
    }

    pub async fn get_with(&self, path: &str, headers: &[(&str, &str)]) -> Resp {
        let mut b = Request::get(path).header("host", HOST);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        self.send(b.body(Body::empty()).unwrap()).await
    }

    pub async fn post(&self, path: &str, body: Vec<u8>) -> Resp {
        self.send(
            Request::post(path)
                .header("host", HOST)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    pub fn store(&self) -> &MemoryStore {
        self.dir.store()
    }

    pub async fn record(&self, name: &str) -> Option<agentconnect_directory::store::ListingRecord> {
        self.store().get(name).await.unwrap()
    }
}
