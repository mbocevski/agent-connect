//! Owner verification (ADR-006 Decision 2): fetching
//! `https://<domain>/.well-known/agentconnect.json` and the states shown.
//!
//! The fetch is the directory's only outbound request, so it is fenced in:
//! HTTPS on port 443 only, a Web PKI certificate, no redirects, no proxies,
//! `Content-Type: application/json`, a 64 KiB cap and a 5 s budget for the
//! whole exchange. The resolver drops every address that isn't public
//! unicast before a connection is attempted, so a domain that resolves to
//! loopback, private, link-local, ULA or other special ranges can't be used
//! to reach internal services (SSRF).

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::Empty;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::rt::TokioExecutor;

use agentconnect_core::listing as core;
use agentconnect_core::net::is_public_ip;

use crate::store::{OwnerCheck, OwnerStatus};

/// Largest accepted owner file (the core's limit).
pub const MAX_OWNER_FILE: usize = core::MAX_OWNER_FILE_BYTES;
/// Budget for one fetch, connection to last byte.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// How often every listing is re-checked.
pub const RECHECK_EVERY_SECS: u64 = 6 * 3600;

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why an owner file could not be fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The domain isn't a lower-case DNS name (no IP literals, no port).
    InvalidDomain,
    /// Every resolved address is non-public.
    Blocked,
    /// Name resolution, connection or TLS failed.
    Transport,
    /// The 5 s budget ran out.
    Timeout,
    /// The server answered with a redirect.
    Redirect,
    /// The server answered with a status other than 200.
    Status(u16),
    /// The response isn't `application/json`.
    ContentType,
    /// The body is larger than [`MAX_OWNER_FILE`].
    TooLarge,
}

impl FetchError {
    /// A short, identifier-free name for logs and metrics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FetchError::InvalidDomain => "invalid_domain",
            FetchError::Blocked => "blocked",
            FetchError::Transport => "transport",
            FetchError::Timeout => "timeout",
            FetchError::Redirect => "redirect",
            FetchError::Status(_) => "status",
            FetchError::ContentType => "content_type",
            FetchError::TooLarge => "too_large",
        }
    }
}

/// Fetches an owner's well-known file.
pub trait OwnerFetcher: Send + Sync + 'static {
    /// Fetch `https://<domain>/.well-known/agentconnect.json`.
    fn fetch<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<Vec<u8>, FetchError>>;
}

/// Whether `d` is an acceptable owner domain: the core's rule (lower-case
/// A-labels, at least two, no trailing dot, no port, not an IP literal).
#[must_use]
pub fn valid_domain(d: &str) -> bool {
    core::is_owner_domain(d)
}

/// The name to resolve for `host`: the absolute name (a trailing dot), so
/// resolver search domains (`resolv.conf` `search`, `ndots`) never apply.
#[must_use]
pub fn fqdn(host: &str) -> String {
    if host.ends_with('.') {
        host.to_owned()
    } else {
        format!("{host}.")
    }
}

/// Resolves host names to addresses.
pub trait Lookup: Send + Sync + 'static {
    /// The addresses of `host`.
    fn lookup(&self, host: &str) -> BoxFuture<'static, io::Result<Vec<IpAddr>>>;
}

/// The system resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup(&self, host: &str) -> BoxFuture<'static, io::Result<Vec<IpAddr>>> {
        let host = host.to_owned();
        Box::pin(async move {
            Ok(tokio::net::lookup_host((fqdn(&host).as_str(), 443))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    }
}

/// The error the resolver returns when it has dropped every address.
#[derive(Debug)]
pub struct BlockedAddress;

impl std::fmt::Display for BlockedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no public address")
    }
}

impl StdError for BlockedAddress {}

/// A resolver that keeps public addresses only.
#[derive(Clone)]
pub struct GuardedResolver {
    lookup: Arc<dyn Lookup>,
}

impl GuardedResolver {
    /// Wrap `lookup`.
    pub fn new(lookup: Arc<dyn Lookup>) -> Self {
        Self { lookup }
    }

    /// Resolve `host` and keep only public addresses, on port 443.
    ///
    /// # Errors
    ///
    /// The lookup's error, or [`BlockedAddress`] if nothing public is left.
    pub async fn resolve(&self, host: &str) -> io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = self
            .lookup
            .lookup(host)
            .await?
            .into_iter()
            .filter(|ip| is_public_ip(*ip))
            .map(|ip| SocketAddr::new(ip, 443))
            .collect();
        if addrs.is_empty() {
            return Err(io::Error::other(BlockedAddress));
        }
        Ok(addrs)
    }
}

impl tower::Service<Name> for GuardedResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = BoxFuture<'static, io::Result<Self::Response>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.resolve(name.as_str()).await.map(Vec::into_iter) })
    }
}

/// Check a response's status and headers before reading the body.
///
/// # Errors
///
/// [`FetchError::Redirect`], [`FetchError::Status`],
/// [`FetchError::ContentType`] or [`FetchError::TooLarge`].
pub fn check_head(status: StatusCode, headers: &HeaderMap) -> Result<(), FetchError> {
    if status.is_redirection() {
        return Err(FetchError::Redirect);
    }
    if status != StatusCode::OK {
        return Err(FetchError::Status(status.as_u16()));
    }
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"));
    if !json {
        return Err(FetchError::ContentType);
    }
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_OWNER_FILE as u64) {
        return Err(FetchError::TooLarge);
    }
    Ok(())
}

/// Read a body, refusing more than `cap` bytes whatever it declared.
///
/// # Errors
///
/// [`FetchError::TooLarge`] past the cap, [`FetchError::Transport`] if the
/// body fails.
pub async fn read_capped<B>(mut body: B, cap: usize) -> Result<Vec<u8>, FetchError>
where
    B: http_body_util::BodyExt + Unpin,
    B::Data: AsRef<[u8]>,
{
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| FetchError::Transport)?;
        if let Some(data) = frame.data_ref() {
            let data = data.as_ref();
            if out.len() + data.len() > cap {
                return Err(FetchError::TooLarge);
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

fn blocked(e: &(dyn StdError + 'static)) -> bool {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if err.is::<BlockedAddress>() {
            return true;
        }
        if let Some(io) = err.downcast_ref::<io::Error>()
            && io
                .get_ref()
                .is_some_and(<dyn StdError + Send + Sync>::is::<BlockedAddress>)
        {
            return true;
        }
        cur = err.source();
    }
    false
}

type HttpsClient = Client<HttpsConnector<HttpConnector<GuardedResolver>>, Empty<Bytes>>;

/// The production fetcher.
#[derive(Clone)]
pub struct HttpsFetcher {
    client: HttpsClient,
    timeout: Duration,
}

impl HttpsFetcher {
    /// A fetcher on the system resolver and the system's root certificates.
    ///
    /// # Errors
    ///
    /// Fails if no root certificates can be loaded.
    pub fn new() -> io::Result<Self> {
        Self::with_lookup(Arc::new(SystemLookup))
    }

    /// A fetcher on the given resolver.
    ///
    /// # Errors
    ///
    /// Fails if no root certificates can be loaded.
    pub fn with_lookup(lookup: Arc<dyn Lookup>) -> io::Result<Self> {
        let mut http = HttpConnector::new_with_resolver(GuardedResolver::new(lookup));
        http.enforce_http(false);
        http.set_connect_timeout(Some(FETCH_TIMEOUT));
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls::crypto::ring::default_provider())?
            .https_only()
            .enable_http1()
            .wrap_connector(http);
        let client = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self {
            client,
            timeout: FETCH_TIMEOUT,
        })
    }

    async fn get(&self, domain: &str) -> Result<Vec<u8>, FetchError> {
        let req = Request::get(format!("https://{domain}/.well-known/agentconnect.json"))
            .header(header::ACCEPT, "application/json")
            .header(header::USER_AGENT, "agentconnect-directory")
            .body(Empty::<Bytes>::new())
            .map_err(|_| FetchError::InvalidDomain)?;
        let resp = self.client.request(req).await.map_err(|e| {
            if blocked(&e) {
                FetchError::Blocked
            } else {
                FetchError::Transport
            }
        })?;
        check_head(resp.status(), resp.headers())?;
        read_capped(resp.into_body(), MAX_OWNER_FILE).await
    }
}

impl OwnerFetcher for HttpsFetcher {
    fn fetch<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<Vec<u8>, FetchError>> {
        Box::pin(async move {
            if !valid_domain(domain) {
                return Err(FetchError::InvalidDomain);
            }
            tokio::time::timeout(self.timeout, self.get(domain))
                .await
                .map_err(|_| FetchError::Timeout)?
        })
    }
}

/// The owner state a page shows (Decision 2). `revoked` never reaches a
/// live page: the listing is withdrawn instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerState {
    /// Published with a domain; the first check hasn't finished.
    Checking,
    /// A check within 24 h vouched.
    Verified,
    /// No owner domain.
    Unclaimed,
    /// The last success was 24 h to 7 days ago.
    Stale,
    /// The domain doesn't vouch, or hasn't for 7 days.
    Failed,
}

impl OwnerState {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OwnerState::Checking => "checking",
            OwnerState::Verified => "verified",
            OwnerState::Unclaimed => "unclaimed",
            OwnerState::Stale => "stale",
            OwnerState::Failed => "failed",
        }
    }
}

fn to_core(c: OwnerCheck) -> core::FetchResult {
    match c {
        OwnerCheck::Vouched => core::FetchResult::Fetched(core::Vouch::Vouches),
        OwnerCheck::NotVouched => core::FetchResult::Fetched(core::Vouch::DoesNotVouch),
        OwnerCheck::Revoked => core::FetchResult::Fetched(core::Vouch::Revoked {
            revoked_at: None,
            reason: None,
        }),
        OwnerCheck::Failed => core::FetchResult::Failed,
    }
}

fn from_core(r: core::FetchResult) -> OwnerCheck {
    match r {
        core::FetchResult::Fetched(v) => from_vouch(v),
        core::FetchResult::Failed => OwnerCheck::Failed,
    }
}

fn from_vouch(v: core::Vouch) -> OwnerCheck {
    match v {
        core::Vouch::Vouches => OwnerCheck::Vouched,
        core::Vouch::DoesNotVouch => OwnerCheck::NotVouched,
        core::Vouch::Revoked { .. } => OwnerCheck::Revoked,
    }
}

/// The stored history as the core's `OwnerChecks`. The directory never skips a
/// fetch.
fn checks(s: &OwnerStatus) -> core::OwnerChecks {
    core::OwnerChecks {
        last_vouched_at: s.verified_at,
        last_negative: s.negative.map(|(t, c)| {
            let core::FetchResult::Fetched(v) = to_core(c) else {
                unreachable!("a negative result is a fetched file")
            };
            (t, v)
        }),
        latest: s.latest.map(|(at, c)| core::LatestFetch {
            at,
            result: to_core(c),
        }),
        skipped: false,
    }
}

/// Fold one fetch at `at` into the stored history, with the core's
/// `OwnerChecks::record`.
#[must_use]
pub fn record_fetch(s: OwnerStatus, at: u64, check: OwnerCheck) -> OwnerStatus {
    let mut c = checks(&s);
    c.record(at, to_core(check));
    OwnerStatus {
        latest: c.latest.map(|l| (l.at, from_core(l.result))),
        verified_at: c.last_vouched_at,
        negative: c.last_negative.map(|(t, v)| (t, from_vouch(v))),
    }
}

/// The state to show for a listing at `now`: the core's `owner_state` on
/// the stored history. A revoked key is withdrawn at once, so `revoked`
/// never reaches a live page; the directory never skips a fetch, so `unchecked`
/// can't occur. Both show as the nearest live state.
#[must_use]
pub fn owner_state(domain: Option<&str>, s: &OwnerStatus, now: u64) -> OwnerState {
    match core::owner_state(domain, &checks(s), now) {
        core::OwnerState::Checking | core::OwnerState::Unchecked => OwnerState::Checking,
        core::OwnerState::Verified => OwnerState::Verified,
        core::OwnerState::Unclaimed => OwnerState::Unclaimed,
        core::OwnerState::Stale => OwnerState::Stale,
        core::OwnerState::Failed | core::OwnerState::Revoked => OwnerState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The resolver keeps exactly the addresses the core's rule allows, over
    /// the shared vector file (`testdata/public-addresses.json`).
    #[tokio::test]
    async fn the_resolver_follows_the_shared_address_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/public-addresses.json"
        );
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let list = |key: &str| -> Vec<IpAddr> {
            raw[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| ip(c["ip"].as_str().unwrap()))
                .collect()
        };
        let (refused, allowed) = (list("blocked"), list("allowed"));
        for b in &refused {
            let r = GuardedResolver::new(Arc::new(Fixed(vec![*b])));
            assert!(blocked(&r.resolve("x.example").await.unwrap_err()), "{b}");
        }
        let all = [refused, allowed.clone()].concat();
        let r = GuardedResolver::new(Arc::new(Fixed(all)));
        let kept: Vec<IpAddr> = r
            .resolve("x.example")
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.ip())
            .collect();
        assert_eq!(kept, allowed);
    }

    #[test]
    fn domains_are_lower_case_dns_names_only() {
        for ok in ["example.com", "a.b.example.org", "x-1.io", "1password.com"] {
            assert!(valid_domain(ok), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "Example.com",
            "example.com.",
            "example.com:443",
            "-a.com",
            "a-.com",
            "a..com",
            "10.0.0.1",
            "[::1]",
            "user@example.com",
            "exa mple.com",
            "bücher.de",
            &format!("{}.com", "a".repeat(64)),
            &format!("{}.com", "a.".repeat(130)),
        ] {
            assert!(!valid_domain(bad), "{bad:?}");
        }
    }

    fn headers(ct: Option<&str>, len: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(ct) = ct {
            h.insert(header::CONTENT_TYPE, ct.parse().unwrap());
        }
        if let Some(len) = len {
            h.insert(header::CONTENT_LENGTH, len.parse().unwrap());
        }
        h
    }

    #[test]
    fn responses_must_be_200_json_and_small() {
        let json = headers(Some("application/json; charset=utf-8"), None);
        assert_eq!(check_head(StatusCode::OK, &json), Ok(()));
        for s in [301, 302, 307, 308] {
            assert_eq!(
                check_head(StatusCode::from_u16(s).unwrap(), &json),
                Err(FetchError::Redirect)
            );
        }
        assert_eq!(
            check_head(StatusCode::NOT_FOUND, &json),
            Err(FetchError::Status(404))
        );
        assert_eq!(
            check_head(StatusCode::OK, &headers(Some("text/html"), None)),
            Err(FetchError::ContentType)
        );
        assert_eq!(
            check_head(StatusCode::OK, &headers(None, None)),
            Err(FetchError::ContentType)
        );
        assert_eq!(
            check_head(
                StatusCode::OK,
                &headers(Some("application/json"), Some("65537"))
            ),
            Err(FetchError::TooLarge)
        );
        assert_eq!(
            check_head(
                StatusCode::OK,
                &headers(Some("Application/JSON"), Some("65536"))
            ),
            Ok(())
        );
    }

    #[tokio::test]
    async fn bodies_are_capped_whatever_they_declare() {
        use http_body_util::Full;
        let ok = read_capped(
            Full::new(Bytes::from(vec![b'x'; MAX_OWNER_FILE])),
            MAX_OWNER_FILE,
        )
        .await
        .unwrap();
        assert_eq!(ok.len(), MAX_OWNER_FILE);
        let big = Full::new(Bytes::from(vec![b'x'; MAX_OWNER_FILE + 1]));
        assert_eq!(
            read_capped(big, MAX_OWNER_FILE).await,
            Err(FetchError::TooLarge)
        );
        // Many small chunks that add up past the cap.
        let chunks = (0..70).map(|_| Ok::<_, io::Error>(Bytes::from(vec![b'y'; 1024])));
        let body = axum::body::Body::from_stream(futures_util::stream::iter(chunks));
        assert_eq!(
            read_capped(body, MAX_OWNER_FILE).await,
            Err(FetchError::TooLarge)
        );
    }

    struct Fixed(Vec<IpAddr>);

    impl Lookup for Fixed {
        fn lookup(&self, _: &str) -> BoxFuture<'static, io::Result<Vec<IpAddr>>> {
            let v = self.0.clone();
            Box::pin(async move { Ok(v) })
        }
    }

    #[tokio::test]
    async fn the_resolver_drops_private_addresses() {
        let r = GuardedResolver::new(Arc::new(Fixed(vec![ip("10.0.0.1"), ip("1.1.1.1")])));
        assert_eq!(
            r.resolve("x.example").await.unwrap(),
            vec![SocketAddr::new(ip("1.1.1.1"), 443)]
        );
        let r = GuardedResolver::new(Arc::new(Fixed(vec![ip("127.0.0.1"), ip("::1")])));
        let e = r.resolve("x.example").await.unwrap_err();
        assert!(blocked(&e));
    }

    #[tokio::test]
    async fn the_real_fetcher_never_connects_to_a_private_address() {
        // The resolver maps the name to loopback; the fetch must fail before
        // any connection is made.
        for target in ["127.0.0.1", "169.254.169.254", "10.0.0.7", "::1"] {
            let f = HttpsFetcher::with_lookup(Arc::new(Fixed(vec![ip(target)]))).unwrap();
            assert_eq!(
                f.fetch("owner.example").await,
                Err(FetchError::Blocked),
                "{target}"
            );
        }
        let f = HttpsFetcher::with_lookup(Arc::new(Fixed(vec![]))).unwrap();
        assert_eq!(f.fetch("owner.example").await, Err(FetchError::Blocked));
        assert_eq!(f.fetch("127.0.0.1").await, Err(FetchError::InvalidDomain));
        assert_eq!(f.fetch("localhost").await, Err(FetchError::InvalidDomain));
    }

    #[test]
    fn states_come_from_the_recorded_history() {
        let now = 10 * 86_400;
        let d = Some("example.com");
        let h = |fetches: &[(u64, OwnerCheck)]| {
            fetches
                .iter()
                .fold(OwnerStatus::PENDING, |s, (at, c)| record_fetch(s, *at, *c))
        };
        assert_eq!(
            owner_state(None, &h(&[(now, OwnerCheck::Vouched)]), now),
            OwnerState::Unclaimed
        );
        assert_eq!(
            owner_state(d, &OwnerStatus::PENDING, now),
            OwnerState::Checking
        );
        let vouched_then_failed =
            h(&[(now - 3600, OwnerCheck::Vouched), (now, OwnerCheck::Failed)]);
        assert_eq!(
            owner_state(d, &vouched_then_failed, now),
            OwnerState::Verified
        );
        assert_eq!(vouched_then_failed.latest, Some((now, OwnerCheck::Failed)));
        let stale = h(&[
            (now - 2 * 86_400, OwnerCheck::Vouched),
            (now, OwnerCheck::Failed),
        ]);
        assert_eq!(owner_state(d, &stale, now), OwnerState::Stale);
        // A negative result sticks through later failed fetches.
        let sticky = h(&[
            (now - 7200, OwnerCheck::Vouched),
            (now - 3600, OwnerCheck::NotVouched),
            (now, OwnerCheck::Failed),
        ]);
        assert_eq!(sticky.negative, Some((now - 3600, OwnerCheck::NotVouched)));
        assert_eq!(owner_state(d, &sticky, now), OwnerState::Failed);
        let revoked = h(&[(now, OwnerCheck::Revoked)]);
        assert_eq!(owner_state(d, &revoked, now), OwnerState::Failed);
        for st in [
            OwnerState::Checking,
            OwnerState::Verified,
            OwnerState::Unclaimed,
            OwnerState::Stale,
            OwnerState::Failed,
        ] {
            assert_ne!(st.as_str(), "");
        }
        for e in [
            FetchError::InvalidDomain,
            FetchError::Blocked,
            FetchError::Transport,
            FetchError::Timeout,
            FetchError::Redirect,
            FetchError::Status(500),
            FetchError::ContentType,
            FetchError::TooLarge,
        ] {
            assert_ne!(e.as_str(), "");
        }
    }
}
