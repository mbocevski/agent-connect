//! HTTP routes, content negotiation, cache headers, rate limiting and
//! request logging.
//!
//! Negotiation is on `Accept` only: a `text/markdown` range (with `q > 0`)
//! gets the Markdown copy, everything else (`*/*`, `text/html`, a missing
//! header) gets HTML. Every negotiated response says `Vary: Accept`, and no
//! response depends on `User-Agent` or any other header, so one URL with one
//! `Accept` returns the same bytes to everyone.
//!
//! Requests are logged and counted by route template and status only: no
//! query string, name, identity or address (ADR-006 Decision 4).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Bytes;
use axum::extract::{
    ConnectInfo, DefaultBodyLimit, Extension, MatchedPath, Path, Query, Request, State,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::api::{UNTRUSTED_NOTICE, listing_json};
use crate::directory::{DirError, Directory, Lookup, valid_name};
use crate::metrics::template;
use crate::ratelimit::Class;
use crate::render::{self, HomeQuery, Site};
use crate::store::Store;

/// Content-Security-Policy of every response: no script at all.
pub const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; \
form-action 'self'; frame-ancestors 'none'";
/// [`CSP`] with `font-src 'self'`, when the operator serves fonts.
pub const CSP_FONTS: &str = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; \
form-action 'self'; frame-ancestors 'none'; font-src 'self'";
/// Largest font file served.
const MAX_FONT_BYTES: u64 = 4 * 1024 * 1024;
/// Cache policy of readable pages and cards (Decision 6).
pub const CACHE_PUBLIC: &str = "public, max-age=60, must-revalidate";
/// Cache policy of 404 and 410 answers.
pub const CACHE_MISSING: &str = "public, max-age=60";
/// Cache policy of writes and operational endpoints.
pub const CACHE_NONE: &str = "no-store";

/// Where the operator's fonts are served (route template).
const FONT_ROUTE: &str = "/static/fonts/{file}";

const HTML: &str = "text/html; charset=utf-8";
const MARKDOWN: &str = "text/markdown; charset=utf-8";
const JSON_TYPE: &str = "application/json";
/// Largest publish body accepted on the wire (the card cap is checked again).
const MAX_PUBLISH_BODY: usize = 40 * 1024;
/// Largest withdrawal or revocation body.
const MAX_SMALL_BODY: usize = 4 * 1024;

/// HTTP settings.
#[derive(Debug, Clone, Default)]
pub struct HttpConfig {
    /// A trusted proxy's client-address header (its last value is used),
    /// believed only on connections from `trusted_proxies`.
    pub client_ip_header: Option<HeaderName>,
    /// Proxies whose client-address header is believed.
    pub trusted_proxies: Vec<crate::config::Cidr>,
    /// Serve `/metrics` on this router (false when it has its own
    /// listener).
    pub hide_metrics: bool,
    /// The stylesheet served at [`render::CSS_PATH`] instead of the default.
    pub stylesheet: Option<Arc<str>>,
    /// A directory of fonts served at `/static/fonts/{file}`. Setting it also
    /// adds `font-src 'self'` to the CSP.
    pub font_dir: Option<std::path::PathBuf>,
    /// The operator's name for the site (`AC_DIRECTORY_NAME`).
    pub name: Option<String>,
    /// The operator's home link in the header (`AC_DIRECTORY_HOME`).
    pub home: Option<crate::config::HomeLink>,
    /// The operator's notice above every page (`AC_DIRECTORY_NOTICE`).
    pub notice: Option<String>,
    /// The operator's terms and abuse links in every page's footer
    /// (`AC_DIRECTORY_TERMS`, `AC_DIRECTORY_ABUSE`).
    pub links: agentconnect_core::operator::OperatorLinks,
}

struct App<S: Store> {
    dir: Arc<Directory<S>>,
    config: HttpConfig,
    /// Whether the operator has been told about a forwarded client address
    /// from a peer that isn't a trusted proxy.
    warned_untrusted_proxy: AtomicBool,
}

type Shared<S> = Arc<App<S>>;

/// Whether `Accept` asks for Markdown: a `text/markdown` range whose `q` is
/// not zero.
#[must_use]
pub fn wants_markdown(headers: &HeaderMap) -> bool {
    let (mut markdown, mut other) = (0.0_f32, 0.0_f32);
    for range in headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
    {
        let mut parts = range.split(';');
        let media = parts.next().unwrap_or_default().trim();
        if media.is_empty() {
            continue;
        }
        let q = quality(parts);
        if media.eq_ignore_ascii_case("text/markdown") {
            markdown = markdown.max(q);
        } else {
            other = other.max(q);
        }
    }
    markdown > 0.0 && markdown >= other
}

/// The `q` of a media range's parameters: 1 when absent, and 0 when it
/// isn't a number from 0 to 1 (RFC 9110 §12.4.2).
fn quality<'a>(params: impl Iterator<Item = &'a str>) -> f32 {
    for p in params {
        let p = p.trim();
        if let Some(v) = p
            .get(..2)
            .filter(|k| k.eq_ignore_ascii_case("q="))
            .map(|_| &p[2..])
        {
            return v
                .trim()
                .parse::<f32>()
                .ok()
                .filter(|q| q.is_finite() && (0.0..=1.0).contains(q))
                .unwrap_or(0.0);
        }
    }
    1.0
}

fn header_value(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
}

fn respond(
    status: StatusCode,
    content_type: &'static str,
    cache: &'static str,
    body: impl Into<axum::body::Body>,
) -> Response {
    let mut r = Response::new(body.into());
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    r
}

/// A negotiated page: HTML or its Markdown copy at `alternate`.
fn page(
    status: StatusCode,
    markdown: bool,
    cache: &'static str,
    alternate: &str,
    html: impl FnOnce() -> String,
    md: impl FnOnce() -> String,
) -> Response {
    let mut r = if markdown {
        respond(status, MARKDOWN, cache, md())
    } else {
        let mut r = respond(status, HTML, cache, html());
        r.headers_mut().insert(
            header::LINK,
            header_value(&format!(
                "<{alternate}>; rel=\"alternate\"; type=\"text/markdown\""
            )),
        );
        r
    };
    r.headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept"));
    r
}

fn error_json(e: DirError) -> Response {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut body = json!({"code": e.code, "detail": e.detail});
    if let Some(kind) = e.kind {
        body["kind"] = json!(kind);
    }
    let mut r = (status, Json(body)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE_NONE));
    r
}

fn site<S: Store>(app: &App<S>) -> Site<'_> {
    let s = app.dir.settings();
    Site {
        host: &s.host,
        relay: s.relays.first().map_or("", String::as_str),
        name: app.config.name.as_deref(),
        home: app.config.home.as_ref(),
        notice: app.config.notice.as_deref(),
        links: &app.config.links,
    }
}

/// Query of `/`, `/index.md` and `/search`.
#[derive(Debug, Default, Deserialize)]
pub struct SearchParams {
    /// Free text.
    #[serde(default)]
    pub q: Option<String>,
    /// Skill filter.
    #[serde(default)]
    pub skill: Option<String>,
}

impl SearchParams {
    fn home(&self) -> HomeQuery<'_> {
        fn some(s: Option<&String>) -> Option<&str> {
            s.map(|s| s.trim()).filter(|s| !s.is_empty())
        }
        HomeQuery {
            q: some(self.q.as_ref()),
            skill: some(self.skill.as_ref()),
        }
    }
}

async fn home_page<S: Store>(
    app: &App<S>,
    params: &SearchParams,
    markdown: bool,
    negotiated: bool,
) -> Response {
    let query = params.home();
    let results = if query.is_search() {
        app.dir.search(query.q, query.skill).await
    } else {
        app.dir.listed(crate::directory::SEARCH_LIMIT).await
    };
    let results = match results {
        Ok(r) => r,
        Err(e) => return error_json(e),
    };
    let site = site(app);
    let alternate = query.alternate();
    let mut r = page(
        StatusCode::OK,
        markdown,
        CACHE_PUBLIC,
        &alternate,
        || render::home_html(&site, &query, &results),
        || render::home_md(&site, &query, &results),
    );
    if !negotiated {
        r.headers_mut().remove(header::VARY);
    }
    r
}

async fn home<S: Store>(
    State(app): State<Shared<S>>,
    Query(p): Query<SearchParams>,
    headers: HeaderMap,
) -> Response {
    home_page(&app, &p, wants_markdown(&headers), true).await
}

async fn index_md<S: Store>(
    State(app): State<Shared<S>>,
    Query(p): Query<SearchParams>,
) -> Response {
    home_page(&app, &p, true, false).await
}

async fn search<S: Store>(State(app): State<Shared<S>>, Query(p): Query<SearchParams>) -> Response {
    let q = p.home();
    match app.dir.search(q.q, q.skill).await {
        Ok(found) => {
            let results: Vec<_> = found.iter().map(|l| listing_json(&app.dir, l)).collect();
            let body = json!({"untrusted": true, "notice": UNTRUSTED_NOTICE, "results": results});
            respond(StatusCode::OK, JSON_TYPE, CACHE_PUBLIC, body.to_string())
        }
        Err(e) => error_json(e),
    }
}

enum Format {
    Negotiated,
    Json,
    Markdown,
}

async fn listing<S: Store>(
    State(app): State<Shared<S>>,
    Path(file): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (name, format) = if let Some(n) = file.strip_suffix(".json") {
        (n, Format::Json)
    } else if let Some(n) = file.strip_suffix(".md") {
        (n, Format::Markdown)
    } else {
        (file.as_str(), Format::Negotiated)
    };
    let found = match app.dir.lookup(name).await {
        Ok(l) => l,
        Err(e) => return error_json(e),
    };
    let site = site(&app);
    // Only a valid slug is ever echoed into a header.
    let alternate = if valid_name(name) {
        format!("/a/{name}.md")
    } else {
        "/index.md".to_owned()
    };
    let markdown = match format {
        Format::Json => return card_json(&found, &headers),
        Format::Markdown => true,
        Format::Negotiated => wants_markdown(&headers),
    };
    let mut r = match &found {
        Lookup::Found(l) => page(
            StatusCode::OK,
            markdown,
            CACHE_PUBLIC,
            &alternate,
            || render::listing_html(&site, l),
            || render::listing_md(&site, l),
        ),
        Lookup::Gone { reason, at } => page(
            StatusCode::GONE,
            markdown,
            CACHE_MISSING,
            &alternate,
            || render::gone_html(&site, name, *reason, *at),
            || render::gone_md(&site, *reason, *at),
        ),
        Lookup::Missing => page(
            StatusCode::NOT_FOUND,
            markdown,
            CACHE_MISSING,
            &alternate,
            || render::not_found_html(&site, &alternate),
            || render::not_found_md(&site),
        ),
    };
    if matches!(format, Format::Markdown) {
        r.headers_mut().remove(header::VARY);
    }
    r
}

fn card_json(found: &Lookup, headers: &HeaderMap) -> Response {
    match found {
        Lookup::Found(l) => {
            let etag = format!("\"{}\"", l.record.sha256);
            let matches = headers
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    // Weak comparison (RFC 9110 §13.1.2): `W/` is ignored.
                    v.split(',').any(|t| {
                        let t = t.trim();
                        t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag
                    })
                });
            let mut r = if matches {
                respond(
                    StatusCode::NOT_MODIFIED,
                    JSON_TYPE,
                    CACHE_PUBLIC,
                    Bytes::new(),
                )
            } else {
                respond(
                    StatusCode::OK,
                    JSON_TYPE,
                    CACHE_PUBLIC,
                    l.record.bytes.clone(),
                )
            };
            r.headers_mut().insert(header::ETAG, header_value(&etag));
            r
        }
        Lookup::Gone { .. } => respond(
            StatusCode::GONE,
            JSON_TYPE,
            CACHE_MISSING,
            json!({"code": "withdrawn", "detail": "this listing was withdrawn"}).to_string(),
        ),
        Lookup::Missing => respond(
            StatusCode::NOT_FOUND,
            JSON_TYPE,
            CACHE_MISSING,
            json!({"code": "not_found", "detail": DirError::NOT_FOUND.detail}).to_string(),
        ),
    }
}

async fn llms<S: Store>(State(app): State<Shared<S>>) -> Response {
    match app.dir.listed(crate::directory::LLMS_LIMIT).await {
        Ok(found) => {
            let names: Vec<String> = found.into_iter().map(|l| l.record.name).collect();
            respond(
                StatusCode::OK,
                "text/plain; charset=utf-8",
                CACHE_PUBLIC,
                render::llms_txt(&site(&app), &names),
            )
        }
        Err(e) => error_json(e),
    }
}

async fn stylesheet<S: Store>(State(app): State<Shared<S>>) -> Response {
    let css = app
        .config
        .stylesheet
        .as_deref()
        .unwrap_or(render::CSS)
        .to_owned();
    respond(
        StatusCode::OK,
        "text/css; charset=utf-8",
        "public, max-age=3600",
        css,
    )
}

/// The font directory as the router will use it: canonical, and a directory.
///
/// # Errors
/// The path does not exist or is not a directory.
pub fn resolve_font_dir(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let dir = std::fs::canonicalize(path)?;
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AC_DIRECTORY_FONT_DIR is not a directory",
        ))
    }
}

/// The font media type of a file name, chosen by extension only.
fn font_type(file: &str) -> Option<&'static str> {
    let (_, ext) = file.rsplit_once('.')?;
    match ext.to_ascii_lowercase().as_str() {
        "woff2" => Some("font/woff2"),
        "woff" => Some("font/woff"),
        "ttf" => Some("font/ttf"),
        "otf" => Some("font/otf"),
        _ => None,
    }
}

/// A font from the operator's directory: one regular file directly in it,
/// never a symlink, a subdirectory or a name with a separator.
async fn font<S: Store>(State(app): State<Shared<S>>, Path(file): Path<String>) -> Response {
    let not_found = || {
        respond(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            CACHE_MISSING,
            "not found\n",
        )
    };
    let (Some(dir), Some(ty)) = (app.config.font_dir.as_ref(), font_type(&file)) else {
        return not_found();
    };
    if file.starts_with('.') || file.contains(['/', '\\', '\0']) {
        return not_found();
    }
    let path = dir.join(&file);
    let Ok(meta) = tokio::fs::symlink_metadata(&path).await else {
        return not_found();
    };
    if !meta.is_file() || meta.len() > MAX_FONT_BYTES {
        return not_found();
    }
    match tokio::fs::read(&path).await {
        Ok(bytes) => respond(StatusCode::OK, ty, "public, max-age=3600", bytes),
        Err(_) => not_found(),
    }
}

async fn well_known<S: Store>(State(app): State<Shared<S>>) -> Response {
    let s = app.dir.settings();
    let mut body = json!({
        "v": 0,
        "directory": s.host,
        "relays": s.relays,
        "token_keys": app.dir.token_keys(),
    });
    // SPEC §13.2.7: `terms` is an https URL and `abuse` one too or a mailto
    // address; a field without a value (or, for a loopback `http://` link
    // allowed on the pages, without that form) is left out, never null.
    let links = &app.config.links;
    let https = |u: &&String| u.starts_with("https://");
    if let Some(terms) = links.terms.as_ref().filter(https) {
        body["terms"] = json!(terms);
    }
    if let Some(abuse) = links
        .abuse
        .as_ref()
        .filter(|u| https(u) || u.starts_with("mailto:"))
    {
        body["abuse"] = json!(abuse);
    }
    respond(StatusCode::OK, JSON_TYPE, CACHE_PUBLIC, body.to_string())
}

fn written(status: StatusCode, body: &serde_json::Value) -> Response {
    respond(status, JSON_TYPE, CACHE_NONE, body.to_string())
}

async fn publish<S: Store>(
    State(app): State<Shared<S>>,
    Extension(ClientKey(key)): Extension<ClientKey>,
    body: Bytes,
) -> Response {
    match app.dir.publish_from(&body, key).await {
        Ok(p) => written(
            if p.changed {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            &json!({
                "name": p.name,
                "seq": p.seq,
                "url": app.dir.card_url(&p.name),
                "owner_state": p.owner.as_str(),
            }),
        ),
        Err(e) => error_json(e),
    }
}

async fn withdraw<S: Store>(
    State(app): State<Shared<S>>,
    Extension(ClientKey(key)): Extension<ClientKey>,
    body: Bytes,
) -> Response {
    match app.dir.withdraw_from(&body, key).await {
        Ok(w) => written(
            StatusCode::OK,
            &json!({"withdrawn": w.name, "seq": w.seq, "changed": w.changed}),
        ),
        Err(e) => error_json(e),
    }
}

async fn revoke<S: Store>(State(app): State<Shared<S>>, body: Bytes) -> Response {
    match app.dir.revoke(&body).await {
        Ok(changed) => written(
            StatusCode::OK,
            &json!({"revoked": true, "changed": changed}),
        ),
        Err(e) => error_json(e),
    }
}

/// Query of the withdrawal feed.
#[derive(Debug, Deserialize)]
pub struct FeedParams {
    /// Return entries after this cursor.
    #[serde(default)]
    pub after: i64,
    /// At most this many entries (1 to 100).
    #[serde(default)]
    pub limit: Option<u32>,
}

async fn feed<S: Store>(State(app): State<Shared<S>>, Query(p): Query<FeedParams>) -> Response {
    match app
        .dir
        .feed(p.after, p.limit.unwrap_or(crate::directory::FEED_PAGE))
        .await
    {
        Ok((entries, next)) => {
            let entries: Vec<_> = entries
                .iter()
                .map(|e| {
                    json!({
                        "cursor": e.cursor,
                        "kind": e.kind.as_str(),
                        "created_at": e.created_at,
                        "entry": serde_json::from_str::<serde_json::Value>(&e.entry).unwrap_or_default(),
                    })
                })
                .collect();
            respond(
                StatusCode::OK,
                JSON_TYPE,
                "public, max-age=10",
                json!({"entries": entries, "next": next}).to_string(),
            )
        }
        Err(e) => error_json(e),
    }
}

async fn healthz() -> Response {
    respond(
        StatusCode::OK,
        JSON_TYPE,
        CACHE_NONE,
        json!({"status": "ok", "protocol": agentconnect_core::PROTOCOL_VERSION}).to_string(),
    )
}

async fn metrics<S: Store>(State(app): State<Shared<S>>) -> Response {
    respond(
        StatusCode::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        CACHE_NONE,
        app.dir.metrics().render(),
    )
}

async fn fallback<S: Store>(State(app): State<Shared<S>>, headers: HeaderMap) -> Response {
    let site = site(&app);
    page(
        StatusCode::NOT_FOUND,
        wants_markdown(&headers),
        CACHE_MISSING,
        "/index.md",
        || render::not_found_html(&site, "/index.md"),
        || render::not_found_md(&site),
    )
}

/// The client address used for rate limiting: the trusted proxy header's
/// last value if configured, else the TCP peer. Also whether the request
/// names a client (the header, `X-Forwarded-For` or `Forwarded`) while its
/// peer is outside the trusted proxies, which suggests a proxy that isn't
/// listed.
fn client_ip(req: &Request, config: &HttpConfig) -> (Option<IpAddr>, bool) {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let trusted = |ip: IpAddr| config.trusted_proxies.iter().any(|c| c.contains(ip));
    let Some(name) = &config.client_ip_header else {
        return (peer, false);
    };
    if !peer.is_some_and(trusted) {
        let headers = req.headers();
        let names_a_client = headers.contains_key(name)
            || headers.contains_key("x-forwarded-for")
            || headers.contains_key("forwarded");
        return (peer, peer.is_some() && names_a_client);
    }
    // Walk the chain from the right (each proxy appends the address it saw),
    // skipping trusted proxies; the first untrusted hop is the client. An
    // entry that doesn't parse ends the walk at the last trusted hop.
    let hops: Vec<&str> = req
        .headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .collect();
    let mut key = peer;
    for hop in hops.iter().rev() {
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            break;
        };
        key = Some(ip);
        if !trusted(ip) {
            break;
        }
    }
    (key, false)
}

/// The rate-limit key a request was counted under, for the handlers' own
/// per-name limits.
#[derive(Debug, Clone, Copy)]
struct ClientKey(Option<IpAddr>);

fn class_of(route: &str, req: &Request) -> Class {
    // Decoded as the handlers decode it, so `%71=` counts as `q=`.
    let searching = || {
        Query::<SearchParams>::try_from_uri(req.uri()).is_ok_and(|Query(p)| p.home().is_search())
    };
    match route {
        "/search" => Class::Search,
        "/" | "/index.md" if searching() => Class::Search,
        "/mcp" => Class::Mcp,
        _ if req.method() == axum::http::Method::POST => Class::Write,
        _ => Class::Read,
    }
}

/// Rate limit, then add the security headers, then log and count by route
/// template only.
async fn guard<S: Store>(State(app): State<Shared<S>>, mut req: Request, next: Next) -> Response {
    let route = template(
        req.extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
    );
    let method = req.method().clone();
    let (key, from_untrusted_proxy) = client_ip(&req, &app.config);
    if from_untrusted_proxy && !app.warned_untrusted_proxy.swap(true, Ordering::Relaxed) {
        // Never with an address: the peer and the client are not logged.
        tracing::warn!(
            "a request carries a client-address header (X-Forwarded-For or Forwarded) from a \
             peer outside AC_DIRECTORY_TRUSTED_PROXIES: the header is ignored, so every client \
             behind that proxy shares its rate limits and its connection cap; list the proxy's \
             address as the directory sees it (behind Docker, the bridge gateway, not 127.0.0.1)"
        );
    }
    req.extensions_mut().insert(ClientKey(key));
    let limited = app.dir.rate_check(key, class_of(route, &req));
    let mut resp = match limited {
        Ok(()) => next.run(req).await,
        Err(wait) => {
            let mut r = error_json(DirError::RATE_LIMITED);
            r.headers_mut()
                .insert(header::RETRY_AFTER, header_value(&wait.to_string()));
            r
        }
    };
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(if app.config.font_dir.is_some() {
            CSP_FONTS
        } else {
            CSP
        }),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    let status = resp.status().as_u16();
    app.dir.metrics().request(route, status);
    tracing::info!(method = %method, route, status, "request");
    resp
}

/// A router serving only `/metrics`, for a separate (private) listener.
pub fn metrics_app<S: Store>(dir: Arc<Directory<S>>) -> Router {
    let state = Arc::new(App {
        dir,
        config: HttpConfig::default(),
        warned_untrusted_proxy: AtomicBool::new(false),
    });
    Router::new()
        .route("/metrics", get(metrics::<S>))
        // For health checks: the public listener's connection caps can
        // refuse a probe under load, and an orchestrator would then restart
        // a working directory.
        .route("/healthz", get(healthz))
        .with_state(state)
}

/// Build the directory's router.
pub fn app<S: Store>(dir: Arc<Directory<S>>, config: HttpConfig) -> Router {
    let mcp = crate::mcp::service(Arc::clone(&dir), &dir.settings().host);
    let hide_metrics = config.hide_metrics;
    let has_fonts = config.font_dir.is_some();
    let state = Arc::new(App {
        dir,
        config,
        warned_untrusted_proxy: AtomicBool::new(false),
    });
    let router = Router::new()
        .route("/", get(home::<S>))
        .route("/index.md", get(index_md::<S>))
        .route("/search", get(search::<S>))
        .route("/a/{name}", get(listing::<S>))
        .route("/llms.txt", get(llms::<S>))
        .route(render::CSS_PATH, get(stylesheet::<S>))
        .route(
            "/.well-known/agentconnect-directory.json",
            get(well_known::<S>),
        )
        .route(
            "/v0/listings",
            post(publish::<S>).layer(DefaultBodyLimit::max(MAX_PUBLISH_BODY)),
        )
        .route(
            "/v0/withdrawals",
            post(withdraw::<S>)
                .get(feed::<S>)
                .layer(DefaultBodyLimit::max(MAX_SMALL_BODY)),
        )
        .route(
            "/v0/revocations",
            post(revoke::<S>).layer(DefaultBodyLimit::max(MAX_SMALL_BODY)),
        )
        .route_service("/mcp", mcp)
        .route("/healthz", get(healthz));
    let router = if has_fonts {
        router.route(FONT_ROUTE, get(font::<S>))
    } else {
        router
    };
    let router = if hide_metrics {
        router
    } else {
        router.route("/metrics", get(metrics::<S>))
    };
    router
        .fallback(fallback::<S>)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            guard::<S>,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_accept_ranges_are_ignored() {
        assert!(wants_markdown(&accept("text/markdown,, ,")));
        assert!(!wants_markdown(&accept(",,")));
    }

    fn accept(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, v.parse().unwrap());
        h
    }

    #[test]
    fn markdown_only_when_asked_for() {
        assert!(wants_markdown(&accept("text/markdown")));
        assert!(wants_markdown(&accept("text/markdown, text/html;q=0.9")));
        assert!(wants_markdown(&accept(
            "text/html;q=0.9, Text/Markdown;charset=utf-8"
        )));
        assert!(wants_markdown(&accept("text/markdown;q=0.5")));
        assert!(!wants_markdown(&accept(
            "text/html;q=1, text/markdown;q=0.01"
        )));
        assert!(!wants_markdown(&accept("text/markdown;q=NaN")));
        assert!(!wants_markdown(&accept("text/markdown;q=2")));
        assert!(wants_markdown(&accept(
            "text/markdown;q=0.9, text/html;q=0.5"
        )));
        assert!(!wants_markdown(&accept("text/markdown;q=0")));
        assert!(!wants_markdown(&accept("text/markdown; Q=0.0")));
        assert!(!wants_markdown(&accept("*/*")));
        assert!(!wants_markdown(&accept("text/*")));
        assert!(!wants_markdown(&accept(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )));
        assert!(!wants_markdown(&HeaderMap::new()));
    }
}
