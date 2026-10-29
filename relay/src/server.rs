//! The HTTP server: the accept loop and one HTTP/1.1 connection per task.
//!
//! Unlike `axum::serve` it bounds every stage of the HTTP phase: how long a
//! client may take to send its request headers, how long a request (body
//! read and handling) may take, how long a write to the client may stall,
//! how large a body may be, how many connections may be in the HTTP phase at
//! once and how many of them one source may hold. A connection leaves that
//! phase when it becomes a WebSocket, which
//! [`WsLimits`](crate::ws::WsLimits) caps on its own. It never logs or
//! keeps client addresses (see [`crate::conn`]).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agentconnect_core::operator::OperatorLinks;
use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::conn::{ConnCtx, Fair, Io, Refused, SourceKey};
use crate::phase::ConnState;
use crate::proto::ErrorCode;
use crate::relay::{ConnRefusal, Eviction, Relay, Timeout, until_true};
use crate::store::Store;

/// Limits on the HTTP phase of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerLimits {
    /// How long a client has to send a request's headers, from their first
    /// byte (from the connection's start, for the first request).
    pub header_timeout: Duration,
    /// How long a kept-alive connection may stay open between a response
    /// and the next request.
    pub idle_timeout: Duration,
    /// How long a request may take once its headers are in: reading its
    /// body and handling it. Past it the answer is 408 and the connection
    /// closes.
    pub request_timeout: Duration,
    /// How long a write to the client may make no progress (an HTTP response
    /// or a WebSocket frame) before the connection is dropped.
    pub write_timeout: Duration,
    /// The largest request body (413 past it).
    pub max_body_bytes: usize,
    /// TCP connections in the HTTP phase at once. At the limit a new one
    /// closes the oldest of the source holding the most; accepting never
    /// pauses.
    pub max_http_connections: usize,
    /// TCP connections in the HTTP phase one source (an IPv4 address or an
    /// IPv6 /64) may hold. Past it a new one is closed at once.
    pub max_http_per_source: usize,
    /// How long, once asked to stop, the server waits for requests in
    /// flight before it returns anyway.
    pub shutdown_grace: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(75),
            request_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            max_body_bytes: 64 << 10,
            max_http_connections: 512,
            max_http_per_source: 8,
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

/// The per-request deadline's state.
struct Deadline<S: Store> {
    relay: Arc<Relay<S>>,
    limit: Duration,
}

impl<S: Store> Clone for Deadline<S> {
    fn clone(&self) -> Self {
        Self {
            relay: Arc::clone(&self.relay),
            limit: self.limit,
        }
    }
}

/// Answer 408 if a request (body read included) isn't done in time.
async fn deadline<S: Store>(State(d): State<Deadline<S>>, req: Request, next: Next) -> Response {
    if let Some(resp) = d.relay.timer().timeout(d.limit, next.run(req)).await {
        return resp;
    }
    d.relay.metrics().timeout(Timeout::Request);
    let body = serde_json::json!({
        "code": ErrorCode::BadRequest.as_str(),
        "detail": "request timed out",
    });
    (
        StatusCode::REQUEST_TIMEOUT,
        [(header::CONNECTION, "close")],
        axum::Json(body),
    )
        .into_response()
}

/// The relay's HTTP server.
pub struct Server<S: Store> {
    relay: Arc<Relay<S>>,
    router: Router,
    limits: ServerLimits,
    phase: Arc<Fair>,
}

impl<S: Store> Server<S> {
    /// A server for `relay` with the public routes of [`crate::app`]. It
    /// starts the relay's knock worker.
    #[must_use]
    pub fn new(relay: Arc<Relay<S>>, limits: ServerLimits) -> Self {
        Self::with_links(relay, OperatorLinks::default(), limits)
    }

    /// [`Server::new`], with the operator's terms and abuse links on the
    /// landing page ([`crate::app_with_links`]).
    #[must_use]
    pub fn with_links(relay: Arc<Relay<S>>, links: OperatorLinks, limits: ServerLimits) -> Self {
        relay.start_knock_worker();
        let router = crate::app_with_links(Arc::clone(&relay), links);
        Self::with_router(relay, router, limits)
    }

    /// A server for the operator's routes of [`crate::metrics_app`], meant
    /// for a private address.
    #[must_use]
    pub fn metrics(relay: Arc<Relay<S>>, limits: ServerLimits) -> Self {
        let router = crate::metrics_app(Arc::clone(&relay));
        Self::with_router(relay, router, limits)
    }

    /// A server for `router`, under the same request deadline and body
    /// limit as the relay's own routes.
    #[must_use]
    pub fn with_router(relay: Arc<Relay<S>>, router: Router, limits: ServerLimits) -> Self {
        let state = Deadline {
            relay: Arc::clone(&relay),
            limit: limits.request_timeout,
        };
        let router = router
            .layer(DefaultBodyLimit::max(limits.max_body_bytes))
            .layer(middleware::from_fn_with_state(state, deadline::<S>));
        Self {
            relay,
            router,
            limits,
            phase: Fair::new(),
        }
    }

    /// Serve one connection from an unknown source until it closes or
    /// becomes a WebSocket (which then runs on its own task).
    pub fn connection<I>(&self, io: I) -> impl Future<Output = ()> + Send + 'static
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.connection_from(io, SourceKey::unknown())
    }

    /// [`Server::connection`] for a connection from `source`. Past the
    /// source's cap it is closed at once; at the total cap it closes the
    /// oldest connection of the source holding the most.
    pub fn connection_from<I>(
        &self,
        io: I,
        source: SourceKey,
    ) -> impl Future<Output = ()> + Send + 'static
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let conn = self.connection_until(io, None, source, watch::channel(false).1);
        async move {
            if let Some(conn) = conn {
                conn.await;
            }
        }
    }

    fn connection_until<I>(
        &self,
        io: I,
        peer: Option<SocketAddr>,
        source: SourceKey,
        mut stop: watch::Receiver<bool>,
    ) -> Option<impl Future<Output = ()> + Send + 'static>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let relay = Arc::clone(&self.relay);
        // Before its headers, a connection from a trusted proxy can't be
        // told apart from the proxy's other clients: it has no per-source
        // share, only the total (where the proxy is the source holding the
        // most).
        let client_ip = &relay.quotas().client_ip;
        let trusted = client_ip.header.is_some()
            && peer.is_some_and(|p| client_ip.trusted_proxies.iter().any(|c| c.contains(p.ip())));
        let per_source = if trusted {
            usize::MAX
        } else {
            self.limits.max_http_per_source
        };
        let state = ConnState::new(relay.timer().clone(), trusted);
        let slot = match self.phase.admit(
            source,
            per_source,
            self.limits.max_http_connections,
            true,
            Some(&state),
        ) {
            Ok(slot) => slot,
            Err(Refused::Source | Refused::Full) => {
                relay.metrics().refused(ConnRefusal::HttpSource);
                return None;
            }
        };
        if slot.evicted {
            relay.metrics().evicted(Eviction::Http);
        }
        let open = relay.metrics().http_open();
        let rx = relay.read_budget().counter(source);
        let io = Io::new(
            io,
            Arc::clone(&rx),
            relay.timer().clone(),
            self.limits.write_timeout,
        )
        .noting(Arc::clone(&state));
        let mut service = self
            .router
            .clone()
            .layer(axum::Extension(ConnCtx { source, rx }));
        if let Some(peer) = peer {
            // The peer address for the per-address limits (SPEC 8.1.1),
            // resolved against a trusted proxy's header by the handlers.
            service = service.layer(axum::Extension(ConnectInfo(peer)));
        }
        // The request's phase, from its head to the end of its answer, for
        // the connection's deadlines and for eviction.
        let inner = TowerToHyperService::new(service);
        let begin = Arc::clone(&state);
        let service =
            hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let req = begin.begin(req);
                let answer = hyper::service::Service::call(&inner, req);
                let end = Arc::clone(&begin);
                async move { answer.await.map(|resp| end.finish(resp)) }
            });
        let conn = http1::Builder::new()
            .serve_connection(TokioIo::new(io), service)
            .with_upgrades();
        let (header, idle) = (self.limits.header_timeout, self.limits.idle_timeout);
        Some(async move {
            let _open = open;
            let kick = Arc::clone(&slot.kick);
            let _slot = slot;
            let timer = relay.timer().clone();
            let mut conn = std::pin::pin!(conn);
            let mut stopping = false;
            loop {
                let due = state.deadline(header, idle);
                let expired = async {
                    match due {
                        Some((at, _)) => timer.sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    _ = conn.as_mut() => return,
                    // A newcomer took this connection's place: drop it.
                    () = kick.notified() => return,
                    () = until_true(&mut stop), if !stopping => {
                        stopping = true;
                        conn.as_mut().graceful_shutdown();
                    }
                    () = expired => {
                        if let Some((_, why)) = due {
                            relay.metrics().timeout(why);
                        }
                        return;
                    }
                    // The phase changed: look at the deadline again.
                    () = state.changed() => {}
                }
            }
        })
    }

    /// Accept connections on `listener` until `shutdown` completes, then
    /// let the connections in the HTTP phase finish their requests, for at
    /// most the shutdown grace.
    ///
    /// # Errors
    ///
    /// None so far; accept errors (such as running out of file
    /// descriptors) are logged and retried.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send,
    ) -> std::io::Result<()> {
        let (stop_tx, stop_rx) = watch::channel(false);
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            let (tcp, source) = tokio::select! {
                r = listener.accept() => match r {
                    Ok((tcp, addr)) => (tcp, addr),
                    Err(e) => {
                        // Never with an address: accept errors are about
                        // the relay (out of descriptors), not the client.
                        tracing::warn!(error = %e, "accept failed");
                        self.relay
                            .timer()
                            .sleep_until(self.relay.timer().now() + Duration::from_millis(100))
                            .await;
                        continue;
                    }
                },
                () = &mut shutdown => break,
            };
            // Small request/reply frames must not wait on Nagle.
            let _ = tcp.set_nodelay(true);
            let Some(conn) =
                self.connection_until(tcp, Some(source), source_of(source), stop_rx.clone())
            else {
                continue;
            };
            tokio::spawn(conn);
        }
        let _ = stop_tx.send(true);
        // Every connection in the HTTP phase holds a slot until it ends.
        let _ = self
            .relay
            .timer()
            .timeout(self.limits.shutdown_grace, self.phase.until_empty())
            .await;
        Ok(())
    }
}

/// The source key of a peer address; the address itself goes no further.
fn source_of(addr: SocketAddr) -> SourceKey {
    SourceKey::of(addr.ip())
}
