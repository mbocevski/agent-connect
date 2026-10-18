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

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Path, Query, Request, State};
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
/// Cache policy of readable pages and cards (Decision 6).
pub const CACHE_PUBLIC: &str = "public, max-age=60, must-revalidate";
/// Cache policy of 404 and 410 answers.
pub const CACHE_MISSING: &str = "public, max-age=60";
/// Cache policy of writes and operational endpoints.
pub const CACHE_NONE: &str = "no-store";

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
    /// A trusted proxy's client-address header (last value used).
    pub client_ip_header: Option<HeaderName>,
}

struct App<S: Store> {
    dir: Arc<Directory<S>>,
    config: HttpConfig,
}

type Shared<S> = Arc<App<S>>;

/// Whether `Accept` asks for Markdown: a `text/markdown` range whose `q` is
/// not zero.
#[must_use]
pub fn wants_markdown(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|range| {
            let mut parts = range.split(';');
            let media = parts.next().unwrap_or_default().trim();
            if !media.eq_ignore_ascii_case("text/markdown") {
                return false;
            }
            !parts.any(|p| {
                let p = p.trim();
                p.get(..2).is_some_and(|k| k.eq_ignore_ascii_case("q="))
                    && p[2..].trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
            })
        })
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
    let mut r = (status, Json(json!({"code": e.code, "detail": e.detail}))).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE_NONE));
    r
}

fn site<S: Store>(dir: &Directory<S>) -> Site<'_> {
    let s = dir.settings();
    Site {
        host: &s.host,
        relay: s.relays.first().map_or("", String::as_str),
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
    dir: &Directory<S>,
    params: &SearchParams,
    markdown: bool,
    negotiated: bool,
) -> Response {
    let query = params.home();
    let results = match dir.search(query.q, query.skill).await {
        Ok(r) => r,
        Err(e) => return error_json(e),
    };
    let site = site(dir);
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
    home_page(&app.dir, &p, wants_markdown(&headers), true).await
}

async fn index_md<S: Store>(
    State(app): State<Shared<S>>,
    Query(p): Query<SearchParams>,
) -> Response {
    home_page(&app.dir, &p, true, false).await
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
    let dir = &app.dir;
    let site = site(dir);
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
            || render::gone_md(*reason, *at),
        ),
        Lookup::Missing => page(
            StatusCode::NOT_FOUND,
            markdown,
            CACHE_MISSING,
            &alternate,
            || render::not_found_html(&site, &alternate),
            render::not_found_md,
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
                .is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*"));
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
    match app.dir.search(None, None).await {
        Ok(found) => {
            let names: Vec<String> = found.into_iter().map(|l| l.record.name).collect();
            respond(
                StatusCode::OK,
                "text/plain; charset=utf-8",
                CACHE_PUBLIC,
                render::llms_txt(&site(&app.dir), &names),
            )
        }
        Err(e) => error_json(e),
    }
}

async fn stylesheet() -> Response {
    respond(
        StatusCode::OK,
        "text/css; charset=utf-8",
        "public, max-age=3600",
        render::CSS,
    )
}

async fn well_known<S: Store>(State(app): State<Shared<S>>) -> Response {
    let s = app.dir.settings();
    let body = json!({
        "v": 0,
        "directory": s.host,
        "relays": s.relays,
        "token_keys": app.dir.token_keys(),
    });
    respond(StatusCode::OK, JSON_TYPE, CACHE_PUBLIC, body.to_string())
}

fn written(status: StatusCode, body: &serde_json::Value) -> Response {
    respond(status, JSON_TYPE, CACHE_NONE, body.to_string())
}

async fn publish<S: Store>(State(app): State<Shared<S>>, body: Bytes) -> Response {
    match app.dir.publish(&body).await {
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

async fn withdraw<S: Store>(State(app): State<Shared<S>>, body: Bytes) -> Response {
    match app.dir.withdraw(&body).await {
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
    let site = site(&app.dir);
    page(
        StatusCode::NOT_FOUND,
        wants_markdown(&headers),
        CACHE_MISSING,
        "/index.md",
        || render::not_found_html(&site, "/index.md"),
        render::not_found_md,
    )
}

/// The client address used for rate limiting: the trusted proxy header's
/// last value if configured, else the TCP peer.
fn client_ip(req: &Request, config: &HttpConfig) -> Option<IpAddr> {
    if let Some(name) = &config.client_ip_header {
        return req
            .headers()
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .next_back()
            .and_then(|v| v.trim().parse().ok());
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
}

fn class_of(route: &str, req: &Request) -> Class {
    let searching = || {
        req.uri().query().is_some_and(|q| {
            q.split('&')
                .any(|kv| kv.starts_with("q=") || kv.starts_with("skill="))
        })
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
async fn guard<S: Store>(State(app): State<Shared<S>>, req: Request, next: Next) -> Response {
    let route = template(
        req.extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
    );
    let method = req.method().clone();
    let limited = app
        .dir
        .rate_check(client_ip(&req, &app.config), class_of(route, &req));
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
        HeaderValue::from_static(CSP),
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

/// Build the directory's router.
pub fn app<S: Store>(dir: Arc<Directory<S>>, config: HttpConfig) -> Router {
    let mcp = crate::mcp::service(Arc::clone(&dir), &dir.settings().host);
    let state = Arc::new(App { dir, config });
    Router::new()
        .route("/", get(home::<S>))
        .route("/index.md", get(index_md::<S>))
        .route("/search", get(search::<S>))
        .route("/a/{name}", get(listing::<S>))
        .route("/llms.txt", get(llms::<S>))
        .route(render::CSS_PATH, get(stylesheet))
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
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics::<S>))
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
