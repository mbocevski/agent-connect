//! AgentConnect relay (SPEC §8): the MLS Delivery Service, mailbox store and
//! invite registry. It handles ciphertext and public metadata only, routes on
//! the outer envelope (SPEC §7.1) and never sees plaintext or invite secrets.
#![warn(clippy::pedantic, missing_docs)]

use std::sync::Arc;

use agentconnect_core::operator::OperatorLinks;
use axum::Router;
use axum::routing::get;

pub mod auth;
pub mod config;
pub mod conn;
pub mod landing;
pub mod logging;
pub mod phase;
pub mod proto;
pub mod quota;
pub mod relay;
mod replay;
pub mod rest;
pub mod restart;
pub mod server;
pub mod sqlite;
pub mod store;
pub mod timer;
pub mod ws;

pub use quota::Quotas;
pub use relay::Relay;
pub use server::{Server, ServerLimits};
pub use sqlite::SqliteStore;
pub use store::{DEFAULT_FRAME_MAX, Limits, Store};
pub use ws::WsLimits;

/// The operator's router: `/metrics` and `/healthz`, for a private
/// listener (`AC_RELAY_METRICS_ADDR`), never the public one.
pub fn metrics_app<S: Store>(relay: Arc<Relay<S>>) -> Router {
    Router::new()
        .route("/metrics", get(rest::metrics::<S>))
        .route("/healthz", get(rest::healthz))
        .with_state(relay)
}

/// Build the relay's HTTP router: REST, landing page and WebSocket.
pub fn app<S: Store>(relay: Arc<Relay<S>>) -> Router {
    app_with_links(relay, OperatorLinks::default())
}

/// [`app`], with the operator's terms and abuse links in the landing page's
/// footer (`AC_RELAY_TERMS`, `AC_RELAY_ABUSE`).
pub fn app_with_links<S: Store>(relay: Arc<Relay<S>>, links: OperatorLinks) -> Router {
    Router::new()
        .merge(rest::routes::<S>())
        .merge(landing::routes::<S>(links))
        .route("/v0/ws", get(ws::ws_handler::<S>))
        .with_state(relay)
}
