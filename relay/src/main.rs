//! `agentconnect-relay` binary.

use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::clock::SystemClock;
use agentconnect_relay::config::Config;
use agentconnect_relay::{Relay, Server, SqliteStore, logging, restart};
use tokio::sync::watch;
use tracing_subscriber::util::SubscriberInitExt as _;

/// SIGINT (Ctrl-C) or SIGTERM (what docker, systemd and Kubernetes send).
/// The handlers are installed by the call, not on the first poll, so a
/// signal that arrives after the "listening" line still stops the relay
/// gracefully and writes the clean-shutdown marker. As PID 1 in a container,
/// a process without a SIGTERM handler ignores SIGTERM until it is killed.
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

/// `agentconnect-relay healthcheck`: `GET /healthz` on the operator
/// listener (`AC_RELAY_METRICS_ADDR`), for a container health check in an
/// image without a shell or `curl`. 0 when healthy, 1 with the reason on
/// stderr otherwise.
fn healthcheck() -> i32 {
    let checked = Config::from_env().and_then(|config| {
        agentconnect_core::healthcheck::probe(
            config.metrics_addr,
            agentconnect_core::healthcheck::TIMEOUT,
        )
    });
    match checked {
        Ok(()) => 0,
        Err(reason) => {
            eprintln!("unhealthy: {reason}");
            1
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next()) {
        (None, _) => {}
        (Some(cmd), None) if cmd == "healthcheck" => std::process::exit(healthcheck()),
        _ => {
            eprintln!(
                "usage: agentconnect-relay [healthcheck] (configured by AC_RELAY_* variables)"
            );
            std::process::exit(2);
        }
    }
    let rust_log = std::env::var("RUST_LOG").ok();
    logging::subscriber(rust_log.as_deref(), std::io::stdout).init();

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
        config.limits(),
    )
    .with_quotas(config.quotas.clone())
    .with_ws_limits(config.ws.clone());
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

    let (stop_tx, stop_rx) = watch::channel(false);
    let stopped = |mut rx: watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|stop| *stop).await;
    };

    let metrics_listener = tokio::net::TcpListener::bind(config.metrics_addr).await?;
    tracing::info!(addr = %metrics_listener.local_addr()?, "metrics listening");
    let metrics = Server::metrics(Arc::clone(&relay), config.server.clone())
        .serve(metrics_listener, stopped(stop_rx.clone()));
    let metrics = tokio::spawn(metrics);

    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    // Before the readiness line: a signal right after it must not find the
    // default action.
    let stop = stop_signal();
    tracing::info!(addr = %listener.local_addr()?, "relay listening");
    // The peer address (or the client address a trusted proxy reports)
    // feeds the per-source and per-address limits; it is never logged.
    let public = Server::with_links(
        Arc::clone(&relay),
        config.links.clone(),
        config.server.clone(),
    );
    let signal_relay = Arc::clone(&relay);
    tokio::spawn(async move {
        stop.await;
        tracing::info!("stopping");
        // WebSocket sessions close with 1001, the knock worker writes what
        // it holds, and the listeners stop accepting.
        signal_relay.stop();
        let _ = stop_tx.send(true);
    });
    let served = public.serve(listener, stopped(stop_rx)).await;
    let _ = metrics.await;
    // Knocks answered `accepted` and not written yet, with a deadline.
    let _ = tokio::time::timeout(config.server.shutdown_grace, relay.flush_knocks()).await;
    // No request is taken any more: tell the next process what this one
    // accepted.
    if let Err(e) = restart::write_marker(&config.db, relay.highest_accepted_ts()) {
        tracing::warn!(error = %e, "clean-shutdown marker not written");
    }
    served
}
