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
    Directory, HttpConfig, MemoryStore, PgStore, Settings, Store, app, logging,
};
use axum::http::HeaderName;
use tracing_subscriber::util::SubscriberInitExt as _;

fn invalid(e: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.into())
}

/// SIGINT (Ctrl-C) or SIGTERM (what docker, systemd and Kubernetes send).
/// The handlers are installed by the call, not on the first poll, so a
/// signal that arrives after the "listening" line still stops the
/// directory gracefully. As PID 1 in a container, a process without a
/// SIGTERM handler ignores SIGTERM until it is killed.
/// A signal whose handler can't be installed is logged and never fires.
fn stop_signal() -> impl Future<Output = ()> {
    #[cfg(unix)]
    let (int, term) = {
        use tokio::signal::unix::{SignalKind, signal};
        let install = |kind: SignalKind, name: &'static str| {
            signal(kind)
                .inspect_err(|e| {
                    tracing::warn!(signal = name, error = %e, "cannot install a signal handler");
                })
                .ok()
        };
        (
            install(SignalKind::interrupt(), "SIGINT"),
            install(SignalKind::terminate(), "SIGTERM"),
        )
    };
    async move {
        #[cfg(unix)]
        {
            async fn fired(sig: Option<tokio::signal::unix::Signal>) {
                match sig {
                    Some(mut s) => {
                        s.recv().await;
                    }
                    None => std::future::pending().await,
                }
            }
            tokio::select! {
                () = fired(int) => {}
                () = fired(term) => {}
            }
        }
        #[cfg(not(unix))]
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(signal = "Ctrl-C", error = %e, "cannot install a signal handler");
            std::future::pending::<()>().await;
        }
    }
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
        name: config.name.clone(),
        home: config.home.clone(),
        notice: config.notice.clone(),
        links: config.links.clone(),
    };
    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    let stop = stop_signal();
    tracing::info!(addr = %listener.local_addr()?, "directory listening");
    // On the signal the listener closes and connections drain, for at most
    // the grace: an unfinished request mustn't hold the exit up until the
    // supervisor kills the process.
    let (stopping, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(
        listener,
        app(dir, http).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        stop.await;
        tracing::info!("shutting down");
        let _ = stopping.send(());
    });
    let grace = config.shutdown_grace;
    tokio::select! {
        result = server => result,
        () = async {
            if stopped.await.is_ok() {
                tokio::time::sleep(grace).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::warn!(grace_secs = grace.as_secs(), "connections still open after the shutdown grace");
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let spec = std::env::var("RUST_LOG").ok();
    // Colours only on a terminal, so log files and collectors get plain text.
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    logging::subscriber(spec.as_deref(), ansi, std::io::stdout).init();

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
