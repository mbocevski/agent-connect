//! `agentconnect-relay` binary.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::clock::SystemClock;
use agentconnect_relay::config::Config;
use agentconnect_relay::{Limits, Relay, SqliteStore, app_with_links, restart};
use axum::serve::ListenerExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config =
        Config::from_env().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // The replay cache starts empty (SPEC 8.1.1): after a clean shutdown
    // refuse what the last process could have accepted, after a crash
    // everything from before the start plus 300 s.
    let floor = restart::floor_at_start(&config.db);
    let store = SqliteStore::open(&config.db)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut relay = Relay::new(
        store,
        Arc::new(SystemClock),
        config.host.clone(),
        Limits::default(),
    )
    .with_quotas(config.quotas.clone());
    relay = match floor {
        Some(ts) => relay.with_replay_floor(ts),
        None => relay.with_restart_guard(),
    };
    let relay = Arc::new(relay);
    relay
        .refresh_counts()
        .await
        .map_err(|e| std::io::Error::other(e.detail))?;

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
    // The peer address feeds the per-address limits (SPEC 8.1.1); it is
    // never logged.
    axum::serve(
        listener,
        app_with_links(Arc::clone(&relay), config.links.clone())
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    // No request is taken any more: tell the next process what this one
    // accepted.
    if let Err(e) = restart::write_marker(&config.db, relay.highest_accepted_ts()) {
        tracing::warn!(error = %e, "clean-shutdown marker not written");
    }
    Ok(())
}

/// Ctrl-C, or SIGTERM (what a service manager or container runtime sends).
async fn shutdown() {
    #[cfg(unix)]
    if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}
