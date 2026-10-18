//! `agentconnect-directory` binary.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::clock::SystemClock;
use agentconnect_directory::config::{Config, MEMORY_DB};
use agentconnect_directory::http::metrics_app;
use agentconnect_directory::owner::HttpsFetcher;
use agentconnect_directory::postgres::connect_options;
use agentconnect_directory::verify::{CoreVerifier, Verifier};
use agentconnect_directory::{
    Directory, HttpConfig, MemoryStore, PgStore, Settings, Store, app, log_filter,
};
use axum::http::HeaderName;

fn invalid(e: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.into())
}

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

    // Rate windows are swept on their own timer, so slow owner checks in
    // the maintenance pass can't hold them up.
    let sweeper = Arc::clone(&dir);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            sweeper.sweep_limits();
        }
    });
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

    if let Some(addr) = config.metrics_addr {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let metrics = metrics_app(Arc::clone(&dir));
        tracing::info!(%addr, "metrics listening");
        tokio::spawn(async move {
            let _ = axum::serve(listener, metrics).await;
        });
    }

    let http = HttpConfig {
        client_ip_header: config
            .client_ip_header
            .as_deref()
            .and_then(|h| HeaderName::from_bytes(h.as_bytes()).ok()),
        trusted_proxies: config.trusted_proxies.clone(),
        hide_metrics: config.metrics_addr.is_some(),
        stylesheet: match &config.stylesheet {
            Some(path) => Some(std::fs::read_to_string(path)?.into()),
            None => None,
        },
        font_dir: match &config.font_dir {
            Some(path) => Some(agentconnect_directory::http::resolve_font_dir(path)?),
            None => None,
        },
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
    let spec = std::env::var("RUST_LOG").ok();
    tracing_subscriber::fmt()
        .with_env_filter(log_filter(spec.as_deref()))
        .init();

    let config = Config::from_env().map_err(invalid)?;
    // Every signature, token and canonical-form check, under the pinned
    // operator keys.
    let verifier: Arc<dyn Verifier> =
        Arc::new(CoreVerifier::new(&config.host, &config.token_keys).map_err(invalid)?);
    if config.client_ip_header.is_none() {
        if config.addr.ip().is_loopback() {
            tracing::warn!(
                "no trusted proxy configured: if a reverse proxy forwards to this loopback \
                 address, every client shares the proxy's rate-limit bucket"
            );
        } else {
            tracing::warn!(
                "listening on a public address with no trusted proxy: rate limits are per TCP peer"
            );
        }
    }
    if config.db == MEMORY_DB {
        tracing::warn!(
            "in-memory store: every listing, tombstone and name mark is lost on restart"
        );
        serve(MemoryStore::new(), config, verifier).await
    } else {
        let (opts, insecure) = connect_options(&config.db, config.db_insecure).map_err(invalid)?;
        if insecure {
            tracing::warn!(
                "the Postgres connection is not verified TLS (AC_DIRECTORY_DB_INSECURE)"
            );
        }
        let store = PgStore::open_with(opts)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        serve(store, config, verifier).await
    }
}
