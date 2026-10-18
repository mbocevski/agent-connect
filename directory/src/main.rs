//! `agentconnect-directory` binary (Heimdall).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::clock::SystemClock;
use agentconnect_directory::config::{Config, MEMORY_DB};
use agentconnect_directory::owner::HttpsFetcher;
use agentconnect_directory::verify::{CoreVerifier, Verifier};
use agentconnect_directory::{Directory, HttpConfig, MemoryStore, PgStore, Settings, Store, app};
use axum::http::HeaderName;
use tracing_subscriber::EnvFilter;

async fn serve<S: Store>(
    store: S,
    config: Config,
    verifier: Arc<dyn Verifier>,
) -> std::io::Result<()> {
    let fetcher = Arc::new(HttpsFetcher::new()?);
    let dir = Arc::new(Directory::new(
        store,
        verifier,
        fetcher,
        Arc::new(SystemClock),
        Settings {
            host: config.host.clone(),
            relays: config.relays.clone(),
        },
    ));

    let worker = Arc::clone(&dir);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(e) = worker.maintain().await {
                tracing::warn!(code = e.code, "maintenance failed");
            }
        }
    });

    let http = HttpConfig {
        client_ip_header: config
            .client_ip_header
            .as_deref()
            .and_then(|h| HeaderName::from_bytes(h.as_bytes()).ok()),
    };
    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    tracing::info!(addr = %config.addr, "directory listening");
    axum::serve(
        listener,
        app(dir, http).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config =
        Config::from_env().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // Every signature, token and canonical-form check, under the pinned
    // operator keys.
    let verifier: Arc<dyn Verifier> = Arc::new(
        CoreVerifier::new(&config.host, &config.token_keys)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
    );
    if config.db == MEMORY_DB {
        serve(MemoryStore::new(), config, verifier).await
    } else {
        let store = PgStore::open(&config.db)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        serve(store, config, verifier).await
    }
}
