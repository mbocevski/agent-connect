//! REST endpoints (SPEC §8.1).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::verify_rest_auth;
use crate::proto::ErrorCode;
use crate::relay::{NewInviteRequest, Relay, RelayError};
use crate::store::{InviteRecord, Store};

/// Largest accepted REST body.
const MAX_BODY: usize = 16 * 1024;

/// Public invite metadata (SPEC §4.2).
#[derive(Debug, Serialize)]
pub struct InviteMeta {
    invite_id: String,
    group_name: String,
    inviter_name: String,
    purpose: String,
    expires_at: u64,
    max_uses: u32,
    uses_left: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    member_count: Option<u32>,
    status: &'static str,
    protocol: u32,
}

impl InviteMeta {
    fn new(r: &InviteRecord, now_secs: u64) -> Self {
        Self {
            invite_id: r.invite_id.clone(),
            group_name: r.group_name.clone(),
            inviter_name: r.inviter_name.clone(),
            purpose: r.purpose.clone(),
            expires_at: r.expires_at,
            max_uses: r.max_uses,
            uses_left: r.uses_left,
            member_count: r.member_count,
            status: r.status(now_secs).as_str(),
            protocol: agentconnect_core::PROTOCOL_VERSION,
        }
    }
}

/// A REST error: JSON `{code, detail}` with a matching HTTP status.
#[derive(Debug)]
pub struct RestError(pub RelayError);

impl From<RelayError> for RestError {
    fn from(e: RelayError) -> Self {
        Self(e)
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    detail: &'a str,
}

impl IntoResponse for RestError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            Json(ErrorBody {
                code: self.0.code.as_str(),
                detail: &self.0.detail,
            }),
        )
            .into_response()
    }
}

fn authenticate<S: Store>(
    relay: &Relay<S>,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<String, RestError> {
    let denied = |d: &str| RestError(RelayError::new(ErrorCode::AuthFailed, d));
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| denied("missing Authorization header"))?;
    let creds = verify_rest_auth(
        value,
        method.as_str(),
        uri.path(),
        body,
        relay.host(),
        relay.now_secs(),
    )
    .map_err(denied)?;
    // Signed requests are single use (SPEC 8.1).
    relay.check_replay(&creds)?;
    Ok(creds.mailbox)
}

async fn create_invite<S: Store>(
    State(relay): State<Arc<Relay<S>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<InviteMeta>), RestError> {
    let mailbox = authenticate(&relay, &headers, &method, &uri, &body)?;
    let req: NewInviteRequest = serde_json::from_slice(&body)
        .map_err(|_| RestError(RelayError::new(ErrorCode::BadRequest, "malformed invite")))?;
    let record = relay.create_invite(&mailbox, req).await?;
    Ok((
        StatusCode::CREATED,
        Json(InviteMeta::new(&record, relay.now_secs())),
    ))
}

async fn get_invite<S: Store>(
    State(relay): State<Arc<Relay<S>>>,
    Path(invite_id): Path<String>,
) -> Result<Json<InviteMeta>, RestError> {
    let record = relay.invite(&invite_id).await?;
    Ok(Json(InviteMeta::new(&record, relay.now_secs())))
}

async fn delete_invite<S: Store>(
    State(relay): State<Arc<Relay<S>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(invite_id): Path<String>,
) -> Result<StatusCode, RestError> {
    let mailbox = authenticate(&relay, &headers, &method, &uri, &[])?;
    relay.revoke_invite(&mailbox, &invite_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "protocol": agentconnect_core::PROTOCOL_VERSION,
    }))
}

async fn metrics<S: Store>(State(relay): State<Arc<Relay<S>>>) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        relay.metrics().render(),
    )
        .into_response()
}

/// REST routes.
pub fn routes<S: Store>() -> Router<Arc<Relay<S>>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics::<S>))
        .route("/v0/invites", axum::routing::post(create_invite::<S>))
        .route(
            "/v0/invites/{invite_id}",
            get(get_invite::<S>).delete(delete_invite::<S>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY))
}
