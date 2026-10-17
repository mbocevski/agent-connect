//! AgentConnect relay (SPEC §8). Forwards ciphertext only and never sees
//! plaintext or invite secrets.
#![warn(clippy::pedantic, missing_docs)]

use axum::{Json, Router, routing::get};
use serde::Serialize;

/// Build the relay's HTTP router.
pub fn app() -> Router {
    Router::new().route("/healthz", get(healthz))
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    protocol: u32,
}

async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok",
        protocol: agentconnect_core::PROTOCOL_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, http::StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_reports_ok() {
        let response = app()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let response = app()
            .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
