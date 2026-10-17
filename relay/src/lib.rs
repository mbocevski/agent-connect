//! AgentConnect relay (SPEC §8): the MLS Delivery Service, mailbox store and
//! invite registry. It handles ciphertext and public metadata only, routes on
//! the outer envelope (SPEC §7.1) and never sees plaintext or invite secrets.
#![warn(clippy::pedantic, missing_docs)]

use std::sync::Arc;

use axum::Router;
use axum::routing::get;

pub mod auth;
pub mod config;
pub mod proto;
pub mod relay;
pub mod rest;
pub mod sqlite;
pub mod store;
pub mod ws;

pub use relay::Relay;
pub use sqlite::SqliteStore;
pub use store::{Limits, Store};

/// Build the relay's HTTP router: REST, landing page and WebSocket.
pub fn app<S: Store>(relay: Arc<Relay<S>>) -> Router {
    Router::new()
        .merge(rest::routes::<S>())
        .route("/v0/ws", get(ws::ws_handler::<S>))
        .with_state(relay)
}
