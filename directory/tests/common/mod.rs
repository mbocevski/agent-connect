//! Shared harness: an in-process directory on the in-memory store, a fake
//! clock and a fake owner-file fetcher, verifying with the real
//! [`CoreVerifier`]. Nothing here sleeps or touches the network.
//!
//! Keys are never literals: identities and the operator key come from the
//! per-run seed (`Rng::for_test`), and the vector tests read theirs from
//! `testdata/`.

#![allow(dead_code, clippy::missing_panics_doc, clippy::must_use_candidate)]

pub mod store_suite;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentconnect_core::clock::FakeClock;
use agentconnect_core::encoding::b64;
use agentconnect_core::listing::{
    DirectoryKey, E2eParams, ListedDoor, ListingCard, ListingProvider, ListingSkill, ListingToken,
    TokenGrant, Withdrawal,
};
use agentconnect_core::{HPKE_PUBLIC_KEY_LEN, Identity, Rng};
use agentconnect_directory::owner::{BoxFuture, FetchError, OwnerFetcher};
use agentconnect_directory::verify::CoreVerifier;
use agentconnect_directory::{Directory, HttpConfig, MemoryStore, Settings, Store, app};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

pub const HOST: &str = "agents.test";
pub const RELAY: &str = "relay.test";
pub const DAY: u64 = 86_400;
pub const CLIENT: &str = "198.51.100.7";

/// A fresh label for per-run randomness.
pub fn label(prefix: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!("{prefix}:{}", N.fetch_add(1, Ordering::Relaxed))
}

/// A fresh seeded RNG.
pub fn rng() -> Rng {
    Rng::for_test(&label("rng"))
}

/// Random bytes from the per-run seed, as base64url.
pub fn random_b64(n: usize) -> String {
    let mut buf = vec![0_u8; n];
    rng().fill(&mut buf).unwrap();
    b64(&buf)
}

/// An identity key the test can sign with.
pub type Agent = Arc<Identity>;

/// A fresh identity from the per-run seed.
pub fn identity() -> Agent {
    Arc::new(Identity::generate(&rng()).unwrap())
}

/// The identity whose secret is `hex` (a published vector value).
pub fn agent_from_hex(hex: &str) -> Agent {
    let secret: [u8; 32] = agentconnect_core::encoding::hex_decode(hex, "secret")
        .unwrap()
        .try_into()
        .unwrap();
    Arc::new(Identity::from_secret_bytes(&secret))
}

/// The operator key whose secret is `hex` (a published vector value).
pub fn directory_key_from_hex(hex: &str) -> DirectoryKey {
    let secret: [u8; 32] = agentconnect_core::encoding::hex_decode(hex, "secret")
        .unwrap()
        .try_into()
        .unwrap();
    DirectoryKey::from_secret_bytes(&secret)
}

/// A fresh identity id (`ac:v0:...`).
pub fn identity_id() -> String {
    identity().id()
}

/// The owner-file fetcher double.
#[derive(Default)]
pub struct FakeFetcher {
    files: Mutex<HashMap<String, Result<Vec<u8>, FetchError>>>,
    gate: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    pub calls: AtomicU64,
}

impl FakeFetcher {
    pub fn serve(&self, domain: &str, file: &Value) {
        self.serve_bytes(domain, serde_json::to_vec(file).unwrap());
    }

    pub fn serve_bytes(&self, domain: &str, file: Vec<u8>) {
        self.files
            .lock()
            .unwrap()
            .insert(domain.to_owned(), Ok(file));
    }

    pub fn fail(&self, domain: &str, e: FetchError) {
        self.files.lock().unwrap().insert(domain.to_owned(), Err(e));
    }

    /// Hold the next fetch until the returned sender fires (or drops).
    pub fn hold(&self) -> tokio::sync::oneshot::Sender<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        *self.gate.lock().unwrap() = Some(rx);
        tx
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
        let gate = self.gate.lock().unwrap().take();
        Box::pin(async move {
            if let Some(g) = gate {
                let _ = g.await;
            }
            r
        })
    }
}

/// One skill: id, name, tags.
pub type SkillSpec = (&'static str, &'static str, &'static [&'static str]);

/// Which operator key issues the token.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Issuer {
    /// The key the directory pins.
    Pinned,
    /// A key it doesn't know.
    Stranger,
}

/// A listing to build.
#[derive(Clone)]
pub struct Spec {
    pub name: String,
    pub agent: Agent,
    pub seq: u64,
    pub issued_at: u64,
    pub door_expires_at: Option<u64>,
    pub owner_domain: Option<String>,
    pub card_name: String,
    pub description: String,
    pub organization: Option<String>,
    pub skills: Vec<SkillSpec>,
    /// Reuse this token instead of issuing one.
    pub token: Option<ListingToken>,
    pub token_issued_at: u64,
    pub token_expires_at: u64,
    pub token_directory: String,
    pub token_identity: Option<String>,
    pub token_domain: Option<String>,
    pub issuer: Issuer,
    pub directory: String,
    pub relay: String,
}

/// A built listing: its exact bytes and its token.
pub struct Built {
    pub bytes: Vec<u8>,
    pub token: ListingToken,
}

pub struct Harness {
    pub dir: Arc<Directory<MemoryStore>>,
    pub clock: Arc<FakeClock>,
    pub fetcher: Arc<FakeFetcher>,
    pub dk: DirectoryKey,
    pub stranger_dk: DirectoryKey,
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

    pub fn code(&self) -> Value {
        self.json()["code"].clone()
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    }
}

impl Harness {
    pub fn new() -> Self {
        Self::with(|d| d)
    }

    pub fn with(f: impl FnOnce(Directory<MemoryStore>) -> Directory<MemoryStore>) -> Self {
        let dk = DirectoryKey::generate(&rng()).unwrap();
        let keys = vec![b64(&dk.public_key())];
        let mut h = Self::pinned(HOST, RELAY, &keys, None, f);
        h.dk = dk;
        h
    }

    /// A directory for `host` and `relay` pinning `keys` (base64url), with
    /// the clock at `now` if given.
    pub fn pinned(
        host: &str,
        relay: &str,
        keys: &[String],
        now: Option<u64>,
        f: impl FnOnce(Directory<MemoryStore>) -> Directory<MemoryStore>,
    ) -> Self {
        let clock = Arc::new(FakeClock::default());
        if let Some(t) = now {
            clock.set(std::time::UNIX_EPOCH + Duration::from_secs(t));
        }
        let fetcher = Arc::new(FakeFetcher::default());
        let verifier = CoreVerifier::new(host, keys).unwrap();
        let dir = Directory::new(
            MemoryStore::new(),
            Arc::new(verifier),
            fetcher.clone(),
            clock.clone(),
            Settings {
                host: host.to_owned(),
                relays: vec![relay.to_owned()],
            },
        );
        Self {
            dir: Arc::new(f(dir)),
            clock,
            fetcher,
            dk: DirectoryKey::generate(&rng()).unwrap(),
            stranger_dk: DirectoryKey::generate(&rng()).unwrap(),
            http: HttpConfig::default(),
        }
    }

    pub fn now(&self) -> u64 {
        self.dir.now()
    }

    pub fn advance(&self, secs: u64) {
        self.clock.advance(Duration::from_secs(secs));
    }

    /// A listing spec with sensible defaults.
    pub fn spec(&self, name: &str, agent: &Agent) -> Spec {
        let now = self.now();
        Spec {
            name: name.to_owned(),
            agent: agent.clone(),
            seq: 1,
            issued_at: now,
            door_expires_at: Some(now + 5 * DAY + 3600),
            owner_domain: None,
            card_name: format!("Card {name}"),
            description: format!("Agent {name} does things."),
            organization: None,
            skills: vec![("general", "General", &["general"])],
            token: None,
            token_issued_at: now - DAY,
            token_expires_at: now + 80 * DAY,
            token_directory: HOST.to_owned(),
            token_identity: None,
            token_domain: None,
            issuer: Issuer::Pinned,
            directory: HOST.to_owned(),
            relay: RELAY.to_owned(),
        }
    }

    fn token(&self, s: &Spec) -> ListingToken {
        if let Some(t) = &s.token {
            return t.clone();
        }
        let key = match s.issuer {
            Issuer::Pinned => &self.dk,
            Issuer::Stranger => &self.stranger_dk,
        };
        key.issue_token(
            &rng(),
            &TokenGrant {
                directory: s.token_directory.clone(),
                name: s.name.clone(),
                identity: s.token_identity.clone().unwrap_or_else(|| s.agent.id()),
                owner_domain: s.token_domain.clone(),
                issued_at: s.token_issued_at,
                expires_at: s.token_expires_at,
            },
        )
        .unwrap()
    }

    /// Canonical, signed bytes for `spec`, or the core's refusal to sign.
    pub fn try_build(&self, s: &Spec) -> agentconnect_core::Result<Built> {
        let token = self.token(s);
        let r = rng();
        let door = s.door_expires_at.map(|expires_at| {
            let mut key = vec![0_u8; HPKE_PUBLIC_KEY_LEN];
            r.fill(&mut key).unwrap();
            ListedDoor {
                id: r.array().unwrap(),
                key,
                expires_at,
            }
        });
        let card = ListingCard {
            name: s.card_name.clone(),
            description: s.description.clone(),
            version: "1.0.0".into(),
            provider: s.organization.as_ref().map(|o| ListingProvider {
                organization: o.clone(),
                url: format!("https://{}", s.owner_domain.as_deref().unwrap_or_default()),
            }),
            streaming: false,
            push_notifications: false,
            default_input_modes: vec!["text/plain".into()],
            default_output_modes: vec!["text/plain".into()],
            skills: s
                .skills
                .iter()
                .map(|(id, name, tags)| ListingSkill {
                    id: (*id).into(),
                    name: (*name).into(),
                    description: format!("Does {name}."),
                    tags: tags.iter().map(|t| (*t).to_owned()).collect(),
                    examples: vec![],
                    input_modes: vec![],
                    output_modes: vec![],
                })
                .collect(),
            extension_description: Some(
                "Reachable end-to-end encrypted through AgentConnect.".into(),
            ),
            params: E2eParams {
                identity: s.agent.id(),
                name: s.name.clone(),
                directory: s.directory.clone(),
                relay: s.relay.clone(),
                seq: s.seq,
                issued_at: s.issued_at,
                door,
                owner_domain: s.owner_domain.clone(),
                token: token.clone(),
            },
        };
        let signed = card.sign(&s.agent)?;
        Ok(Built {
            bytes: signed.bytes().to_vec(),
            token,
        })
    }

    pub fn build(&self, s: &Spec) -> Built {
        self.try_build(s).unwrap()
    }

    /// Build and publish; panics unless accepted.
    pub async fn publish(&self, s: &Spec) -> Built {
        let b = self.build(s);
        let r = self.post("/v0/listings", b.bytes.clone()).await;
        assert!(r.status.is_success(), "{} {}", r.status, r.text());
        b
    }

    /// A signed withdrawal, timestamped now.
    pub fn withdrawal(&self, name: &str, agent: &Agent, seq: u64) -> Vec<u8> {
        Withdrawal::sign(agent, &self.dir.settings().host, name, seq, self.now())
            .unwrap()
            .to_json()
            .unwrap()
    }

    /// A revocation of `token` by the pinned operator key.
    pub fn revocation(&self, token: &ListingToken) -> Vec<u8> {
        self.dk
            .revoke_token(&token.token_id, self.now(), "spam")
            .unwrap()
            .to_json()
            .unwrap()
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
        let host = self.dir.settings().host.clone();
        let mut b = Request::get(path).header("host", host);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        self.send(b.body(Body::empty()).unwrap()).await
    }

    pub async fn post(&self, path: &str, body: Vec<u8>) -> Resp {
        let host = self.dir.settings().host.clone();
        self.send(
            Request::post(path)
                .header("host", host)
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
