//! `agentconnect-relay` binary.

use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::clock::SystemClock;
use agentconnect_relay::config::Config;
use agentconnect_relay::{Limits, Relay, SqliteStore, app};
use axum::serve::ListenerExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config =
        Config::from_env().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let store = SqliteStore::open(&config.db)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let relay = Arc::new(Relay::new(
        store,
        Arc::new(SystemClock),
        config.host.clone(),
        Limits::default(),
    ));

    let janitor = Arc::clone(&relay);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(e) = janitor.purge().await {
                tracing::warn!(code = e.code.as_str(), "purge failed");
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(config.addr)
        .await?
        .tap_io(|tcp| {
            // Small request/reply frames must not wait on Nagle.
            let _ = tcp.set_nodelay(true);
        });
    tracing::info!(addr = %config.addr, "relay listening");
    axum::serve(listener, app(relay))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}
