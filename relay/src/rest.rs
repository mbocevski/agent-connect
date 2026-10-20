//! REST endpoints (SPEC §8.1), signed requests (SPEC §8.1.1) and the door
//! registry (ADR-006).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Serialize;

use crate::auth::{RestCredentials, verify_rest_auth};
use crate::proto::{ErrorCode, is_mailbox_id};
use crate::relay::{NewDoorRequest, NewInviteRequest, Relay, RelayError};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
}

impl IntoResponse for RestError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = Json(ErrorBody {
            code: self.0.code.as_str(),
            detail: &self.0.detail,
            retry_after: self.0.retry_after,
        });
        match self.0.retry_after {
            Some(secs) => (status, [(header::RETRY_AFTER, secs.to_string())], body).into_response(),
            None => (status, body).into_response(),
        }
    }
}

/// A signed request whose signature verified and whose `(mailbox, sig)`
/// pair is claimed in the replay cache (SPEC §8.1.1), not yet authorized.
struct Verified {
    creds: RestCredentials,
    /// The client address the per-address limits count by.
    ip: Option<IpAddr>,
}

impl Verified {
    fn mailbox(&self) -> &str {
        &self.creds.mailbox
    }
}

fn denied(detail: &str) -> RestError {
    RestError(RelayError::new(ErrorCode::AuthFailed, detail))
}

/// Check the signature and timestamp, then claim the request in the
/// replay cache, with nothing awaited in between. A request whose
/// signature fails counts in its address's bucket for such requests and
/// claims nothing.
fn verify<S: Store>(
    relay: &Relay<S>,
    peer: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<Verified, RestError> {
    let ip = relay.client_ip(peer.map(|c| c.0.ip()), headers);
    let checked = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Authorization header")
        .and_then(|value| {
            verify_rest_auth(
                value,
                method.as_str(),
                uri.path(),
                body,
                relay.host(),
                relay.now_secs(),
            )
        });
    let creds = checked.map_err(|d| {
        RestError(relay.refuse_unverified(ip, RelayError::new(ErrorCode::AuthFailed, d)))
    })?;
    relay.claim_signed(&creds)?;
    Ok(Verified { creds, ip })
}

/// The body names the signer as the invite's inviter or the door's owner
/// (`field`), else `auth_failed`; a malformed mailbox is `bad_request`.
fn names_signer(v: &Verified, mailbox: &str, field: &str) -> Result<(), RestError> {
    if !is_mailbox_id(mailbox) {
        return Err(RestError(RelayError::new(
            ErrorCode::BadRequest,
            format!("malformed {field}"),
        )));
    }
    if mailbox != v.mailbox() {
        return Err(denied(&format!(
            "{field} does not match the authenticated mailbox"
        )));
    }
    Ok(())
}

/// Authorize a verified request: `check` decides. Whatever it decides, the
/// request keeps its replay-cache entry, so a refused request can't be
/// replayed to succeed later. An authorized one is counted against its
/// mailbox (and, for a creation, its address).
fn authorize<S: Store>(
    relay: &Relay<S>,
    v: &Verified,
    check: Result<(), RestError>,
    creation: bool,
) -> Result<(), RestError> {
    check?;
    relay.charge_signed(&v.creds, v.ip, creation)?;
    Ok(())
}

async fn create_invite<S: Store>(
    State(relay): State<Arc<Relay<S>>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<InviteMeta>), RestError> {
    let v = verify(&relay, peer.as_deref(), &headers, &method, &uri, &body)?;
    let req = serde_json::from_slice::<NewInviteRequest>(&body)
        .map_err(|_| RestError(RelayError::new(ErrorCode::BadRequest, "malformed invite")));
    let check = req
        .as_ref()
        .map_err(|e| RestError(e.0.clone()))
        .and_then(|r| names_signer(&v, &r.inviter_mailbox, "inviter_mailbox"));
    authorize(&relay, &v, check, true)?;
    let record = relay.create_invite_from(v.mailbox(), v.ip, req?).await?;
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
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(invite_id): Path<String>,
) -> Result<StatusCode, RestError> {
    let v = verify(&relay, peer.as_deref(), &headers, &method, &uri, &[])?;
    let check = match relay.invite(&invite_id).await {
        Ok(i) if i.inviter_mailbox == v.mailbox() => Ok(()),
        Ok(_) => Err(denied("only the inviter mailbox may revoke an invite")),
        Err(e) => Err(RestError(e)),
    };
    authorize(&relay, &v, check, false)?;
    relay.revoke_invite(v.mailbox(), &invite_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v0/doors` reply: what was registered, minus the owner's mailbox.
#[derive(Debug, Serialize)]
pub struct DoorRegistered {
    door_id: String,
    expires_at: u64,
}

async fn create_door<S: Store>(
    State(relay): State<Arc<Relay<S>>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<DoorRegistered>), RestError> {
    let v = verify(&relay, peer.as_deref(), &headers, &method, &uri, &body)?;
    let req = serde_json::from_slice::<NewDoorRequest>(&body)
        .map_err(|_| RestError(RelayError::new(ErrorCode::BadRequest, "malformed door")));
    let check = req
        .as_ref()
        .map_err(|e| RestError(e.0.clone()))
        .and_then(|r| names_signer(&v, &r.owner_mailbox, "owner_mailbox"));
    authorize(&relay, &v, check, true)?;
    let door = relay.create_door(v.mailbox(), req?).await?;
    Ok((
        StatusCode::CREATED,
        Json(DoorRegistered {
            door_id: door.door_id,
            expires_at: door.expires_at,
        }),
    ))
}

async fn delete_door<S: Store>(
    State(relay): State<Arc<Relay<S>>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(door_id): Path<String>,
) -> Result<StatusCode, RestError> {
    let v = verify(&relay, peer.as_deref(), &headers, &method, &uri, &[])?;
    let check = match relay.door(&door_id).await {
        Ok(d) if d.owner_mailbox == v.mailbox() => Ok(()),
        Ok(_) => Err(denied("only the owner mailbox may close a door")),
        Err(e) => Err(RestError(e)),
    };
    authorize(&relay, &v, check, false)?;
    relay.close_door(v.mailbox(), &door_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "protocol": agentconnect_core::PROTOCOL_VERSION,
    }))
}

pub(crate) async fn metrics<S: Store>(State(relay): State<Arc<Relay<S>>>) -> Response {
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
        .route("/v0/invites", axum::routing::post(create_invite::<S>))
        .route(
            "/v0/invites/{invite_id}",
            get(get_invite::<S>).delete(delete_invite::<S>),
        )
        // No GET: everything a knocker needs is in the signed listing.
        .route("/v0/doors", axum::routing::post(create_door::<S>))
        .route(
            "/v0/doors/{door_id}",
            axum::routing::delete(delete_door::<S>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY))
}
