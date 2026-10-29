//! The public listener's connection limits: timeouts for a slow head, an
//! idle connection and a slow request, and a cap on open connections, in
//! all and per source.
//!
//! A client that sends part of a request head and stops would otherwise hold
//! a connection (a descriptor and some memory) for as long as it likes, and
//! many of them could use the directory up (slowloris). Modelled on the
//! relay's HTTP limits:
//!
//! - the request head has to arrive within the header timeout, counted from
//!   its first byte (from the connection's start, for the first request);
//! - an idle connection, between a response and the next request, is closed
//!   after the idle timeout, which stays above a reverse proxy's keep-alive
//!   so the proxy never reuses a connection that is closing;
//! - a request, from its head to its response with the body read, has to
//!   finish within the request timeout, or it is answered 408;
//! - a source (an IPv4 address or an IPv6 /64) holds at most its cap of
//!   connections, and the next one from it is closed at once;
//! - at the total cap a newcomer closes the connection of the source
//!   holding the most that is not serving a request: a connection that has
//!   not completed a request goes before one that has, then the oldest.
//!   A request in flight is never pushed out; with nothing to push out the
//!   newcomer is closed;
//! - before its headers a connection from a trusted proxy can't be told
//!   from the proxy's other clients, so only the total limits it.
//!
//! Addresses stay in process memory, are never logged and never become a
//! metric label.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse as _, Response};
use http_body_util::BodyExt as _;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};
use tokio::time::Instant;
use tower::ServiceExt as _;

use crate::ratelimit::bucket;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What the listener enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long a request head may take, from its first byte.
    pub header_timeout: Duration,
    /// How long a connection may stay open between requests.
    pub idle_timeout: Duration,
    /// How long a request may take from its head to its response.
    pub request_timeout: Duration,
    /// Connections open at once.
    pub max_connections: usize,
    /// Connections open at once from one source.
    pub max_per_source: usize,
    /// How long connections still open after the shutdown signal may hold
    /// the exit up.
    pub shutdown_grace: Duration,
}

/// Counts what the limits did, under fixed names (`("connection",
/// "refused")`): never a label with an address in it.
pub type Events = Arc<dyn Fn(&'static str, &'static str) + Send + Sync>;

/// Where a connection is in its requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the first byte of a request.
    Idle,
    /// Part of a request head has arrived.
    Head,
    /// A request is being served: its head is in, its response not done.
    InFlight,
}

#[derive(Debug)]
struct Inner {
    phase: Phase,
    since: Instant,
    /// A request has completed on this connection.
    served: bool,
    /// Bytes of the next request arrived while a response was still going.
    early: bool,
}

/// What the listener knows about one connection: the phase it is in, for
/// the timeouts, and whether it is serving a request, for eviction.
#[derive(Debug)]
pub struct ConnState {
    inner: Mutex<Inner>,
    wake: Notify,
}

impl ConnState {
    /// A new connection, waiting for its first request.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                phase: Phase::Idle,
                since: Instant::now(),
                served: false,
                early: false,
            }),
            wake: Notify::new(),
        })
    }

    /// Bytes arrived from the client.
    fn bytes_read(&self) {
        let mut inner = lock(&self.inner);
        match inner.phase {
            Phase::Idle => {
                inner.phase = Phase::Head;
                inner.since = Instant::now();
                drop(inner);
                self.wake.notify_one();
            }
            Phase::InFlight => inner.early = true,
            Phase::Head => {}
        }
    }

    /// The server took a request's head: the request is in flight.
    fn request_started(&self) {
        let mut inner = lock(&self.inner);
        inner.phase = Phase::InFlight;
        inner.since = Instant::now();
        drop(inner);
        self.wake.notify_one();
    }

    /// The response is done (or the connection went).
    fn request_ended(&self) {
        let mut inner = lock(&self.inner);
        inner.served = true;
        inner.since = Instant::now();
        inner.phase = if std::mem::take(&mut inner.early) {
            Phase::Head
        } else {
            Phase::Idle
        };
        drop(inner);
        self.wake.notify_one();
    }

    /// True while a request is being served.
    #[must_use]
    pub fn in_flight(&self) -> bool {
        lock(&self.inner).phase == Phase::InFlight
    }

    /// True once a request has completed on the connection.
    #[must_use]
    pub fn served(&self) -> bool {
        lock(&self.inner).served
    }

    /// When the connection runs out of time and why, or `None` while a
    /// request is in flight (the request deadline covers it).
    fn deadline(&self, limits: &Limits) -> Option<(Instant, &'static str)> {
        let inner = lock(&self.inner);
        match inner.phase {
            Phase::Head => Some((inner.since + limits.header_timeout, "header_timeout")),
            // Before its first request a connection has only the header
            // timeout to send a head; between requests, the idle timeout.
            Phase::Idle if !inner.served => {
                Some((inner.since + limits.header_timeout, "header_timeout"))
            }
            Phase::Idle => Some((inner.since + limits.idle_timeout, "idle_timeout")),
            Phase::InFlight => None,
        }
    }
}

/// The connection's socket, noting when bytes arrive.
struct Tracked<T> {
    inner: T,
    state: Arc<ConnState>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Tracked<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.state.bytes_read();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Tracked<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Ends the request when the response body is finished or dropped.
struct EndGuard(Arc<ConnState>);

impl Drop for EndGuard {
    fn drop(&mut self) {
        self.0.request_ended();
    }
}

/// Why [`Fair::admit`] turned a connection away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Its source holds its share already.
    Source,
    /// The total is reached and every connection is serving a request.
    Full,
}

/// Connections under a total cap and a per-source cap, fairly: at the total
/// cap a newcomer closes a connection that is not serving a request, of the
/// source holding the most.
#[derive(Debug, Default)]
pub struct Fair {
    state: Mutex<FairState>,
    changed: Notify,
}

#[derive(Debug)]
struct Entry {
    id: u64,
    kick: Arc<Notify>,
    state: Arc<ConnState>,
}

#[derive(Debug, Default)]
struct FairState {
    next: u64,
    held: usize,
    by_source: HashMap<IpAddr, VecDeque<Entry>>,
}

/// One connection held in a [`Fair`] until dropped.
#[derive(Debug)]
pub struct Slot {
    fair: Arc<Fair>,
    source: IpAddr,
    id: u64,
    /// Fires when a newcomer took this connection's place.
    pub kick: Arc<Notify>,
    /// True if admitting this connection closed another.
    pub evicted: bool,
}

impl Slot {
    /// True if a newcomer has taken this connection's place.
    #[must_use]
    pub fn was_evicted(&self) -> bool {
        let state = lock(&self.fair.state);
        !state
            .by_source
            .get(&self.source)
            .is_some_and(|q| q.iter().any(|e| e.id == self.id))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = lock(&self.fair.state);
        if let Some(q) = state.by_source.get_mut(&self.source)
            && let Some(i) = q.iter().position(|e| e.id == self.id)
        {
            q.remove(i);
            if q.is_empty() {
                state.by_source.remove(&self.source);
            }
            state.held -= 1;
        }
        drop(state);
        self.fair.changed.notify_waiters();
    }
}

impl Fair {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Connections held now (an evicted one stops counting at once).
    #[must_use]
    pub fn held(&self) -> usize {
        lock(&self.state).held
    }

    /// Admit a connection from `source` (an address already grouped by
    /// [`bucket`]), whose phase is tracked by `conn`: at most `per_source`
    /// for the source and `total` in all. At the total, one connection
    /// that is not serving a request is closed: of the source with the most
    /// of them, the one that has not completed a request yet, if any, then
    /// the oldest. A source with an equal number of candidates is chosen by
    /// its best candidate in that order.
    ///
    /// # Errors
    ///
    /// [`Refused::Source`] past the source's cap, [`Refused::Full`] at the
    /// total when every connection is serving a request.
    pub fn admit(
        self: &Arc<Self>,
        source: IpAddr,
        per_source: usize,
        total: usize,
        conn: &Arc<ConnState>,
    ) -> Result<Slot, Refused> {
        let mut state = lock(&self.state);
        let own = state.by_source.get(&source).map_or(0, VecDeque::len);
        if own >= per_source {
            return Err(Refused::Source);
        }
        let mut evicted = false;
        if state.held >= total.max(1) {
            let (top, id) = Self::victim(&state).ok_or(Refused::Full)?;
            if let Some(q) = state.by_source.get_mut(&top)
                && let Some(i) = q.iter().position(|e| e.id == id)
                && let Some(entry) = q.remove(i)
            {
                entry.kick.notify_one();
                if q.is_empty() {
                    state.by_source.remove(&top);
                }
                state.held -= 1;
                evicted = true;
            }
        }
        state.next += 1;
        let id = state.next;
        let kick = Arc::new(Notify::new());
        state.by_source.entry(source).or_default().push_back(Entry {
            id,
            kick: Arc::clone(&kick),
            state: Arc::clone(conn),
        });
        state.held += 1;
        drop(state);
        Ok(Slot {
            fair: Arc::clone(self),
            source,
            id,
            kick,
            evicted,
        })
    }

    /// The connection to close for a newcomer: the best candidate of the
    /// source with the most candidates.
    fn victim(state: &FairState) -> Option<(IpAddr, u64)> {
        state
            .by_source
            .iter()
            .filter_map(|(source, q)| {
                let mut candidates = q.iter().filter(|e| !e.state.in_flight()).peekable();
                candidates.peek()?;
                let (count, best) = candidates.fold((0_usize, None), |(n, best), e| {
                    let key = (e.state.served(), e.id);
                    (n + 1, Some(best.map_or(key, |b: (bool, u64)| b.min(key))))
                });
                best.map(|(served, id)| (count, std::cmp::Reverse((served, id)), *source, id))
            })
            .max_by_key(|(count, best, _, _)| (*count, *best))
            .map(|(_, _, source, id)| (source, id))
    }

    /// Wait until no connection is held.
    pub async fn until_empty(&self) {
        loop {
            let changed = self.changed.notified();
            if self.held() == 0 {
                return;
            }
            changed.await;
        }
    }
}

async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// The request deadline's state.
#[derive(Clone)]
struct Deadline {
    limit: Duration,
    events: Events,
}

/// Answer 408 if a request (its body read included) isn't done in time.
async fn deadline(State(d): State<Deadline>, req: Request, next: Next) -> Response {
    if let Ok(resp) = tokio::time::timeout(d.limit, next.run(req)).await {
        return resp;
    }
    (d.events)("connection", "request_timeout");
    (
        StatusCode::REQUEST_TIMEOUT,
        [(header::CONNECTION, "close")],
        "request timed out\n",
    )
        .into_response()
}

/// Serve `router` on `listener` under `limits` until `shutdown` completes,
/// then let the open connections finish their requests for at most the
/// shutdown grace. `trusted` says whether a peer address is a trusted
/// proxy, which the per-source cap does not apply to.
///
/// # Errors
///
/// None so far; accept errors (such as running out of file descriptors) are
/// logged and retried.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    limits: Limits,
    trusted: impl Fn(IpAddr) -> bool + Send + Sync + 'static,
    events: Events,
    shutdown: impl Future<Output = ()> + Send,
) -> std::io::Result<()> {
    let router = router.layer(middleware::from_fn_with_state(
        Deadline {
            limit: limits.request_timeout,
            events: Arc::clone(&events),
        },
        deadline,
    ));
    let fair = Fair::new();
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (tcp, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(accepted) => accepted,
                Err(e) => {
                    // Never with an address: accept errors are about the
                    // directory (out of descriptors), not the client.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let per_source = if trusted(peer.ip()) {
            usize::MAX
        } else {
            limits.max_per_source
        };
        let state = ConnState::new();
        let Ok(slot) = fair.admit(
            bucket(peer.ip()),
            per_source,
            limits.max_connections,
            &state,
        ) else {
            events("connection", "refused");
            continue;
        };
        if slot.evicted {
            events("connection", "evicted");
        }
        tokio::spawn(connection(
            tcp,
            peer,
            (slot, state),
            router.clone(),
            limits,
            stop_rx.clone(),
            Arc::clone(&events),
        ));
    }
    let _ = stop_tx.send(true);
    // Every connection holds a slot until it ends.
    if tokio::time::timeout(limits.shutdown_grace, fair.until_empty())
        .await
        .is_err()
    {
        tracing::warn!(
            grace_secs = limits.shutdown_grace.as_secs(),
            "connections still open after the shutdown grace"
        );
    }
    Ok(())
}

/// One connection: its requests, until it ends, is evicted, runs out of
/// time, or the shutdown signal asks it to finish its request and close.
async fn connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    (slot, state): (Slot, Arc<ConnState>),
    router: Router,
    limits: Limits,
    mut stop: watch::Receiver<bool>,
    events: Events,
) {
    let started = Arc::clone(&state);
    let finished = Arc::clone(&state);
    // The peer address for the per-address limits, resolved against a
    // trusted proxy's header by the handlers.
    let service = router
        .layer(axum::Extension(ConnectInfo(peer)))
        .map_request(move |req: Request<hyper::body::Incoming>| {
            started.request_started();
            req
        })
        .map_response(move |resp: Response| {
            // The request ends with its response body, or when hyper drops
            // it unread.
            let guard = EndGuard(Arc::clone(&finished));
            resp.map(|body| {
                Body::new(body.map_frame(move |frame| {
                    let _end = &guard;
                    frame
                }))
            })
        });
    let io = TokioIo::new(Tracked {
        inner: tcp,
        state: Arc::clone(&state),
    });
    let conn = http1::Builder::new().serve_connection(io, TowerToHyperService::new(service));
    let kick = Arc::clone(&slot.kick);
    let _slot = slot;
    let mut conn = std::pin::pin!(conn);
    loop {
        let due = state.deadline(&limits);
        let expired = async {
            match due {
                Some((at, _)) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = conn.as_mut() => return,
            // A newcomer took this connection's place: drop it.
            () = kick.notified() => return,
            () = stopped(&mut stop) => {
                conn.as_mut().graceful_shutdown();
                let _ = conn.await;
                return;
            }
            () = expired => {
                if let Some((_, why)) = due {
                    events("connection", why);
                }
                return;
            }
            // The phase changed: look at the deadline again.
            () = state.wake.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        bucket(s.parse().unwrap())
    }

    fn admit(
        fair: &Arc<Fair>,
        source: &str,
        per_source: usize,
        total: usize,
    ) -> Result<(Slot, Arc<ConnState>), Refused> {
        let conn = ConnState::new();
        fair.admit(ip(source), per_source, total, &conn)
            .map(|slot| (slot, conn))
    }

    #[test]
    fn a_source_holds_at_most_its_cap_and_slots_come_back() {
        let fair = Fair::new();
        let (first, _c1) = admit(&fair, "192.0.2.1", 2, 100).unwrap();
        let _second = admit(&fair, "192.0.2.1", 2, 100).unwrap();
        assert_eq!(
            admit(&fair, "192.0.2.1", 2, 100).unwrap_err(),
            Refused::Source
        );
        // Another source has its own share.
        let _other = admit(&fair, "192.0.2.2", 2, 100).unwrap();
        drop(first);
        assert_eq!(fair.held(), 2);
        let _again = admit(&fair, "192.0.2.1", 2, 100).unwrap();
        assert_eq!(fair.held(), 3);
        assert_eq!(
            admit(&fair, "192.0.2.1", 0, 100).unwrap_err(),
            Refused::Source
        );
    }

    #[test]
    fn sources_are_ipv4_addresses_and_ipv6_slash_64s() {
        let fair = Fair::new();
        let _a = admit(&fair, "2001:db8:1:2::1", 1, 100).unwrap();
        // The same /64 shares the cap; another /64 does not.
        assert!(admit(&fair, "2001:db8:1:2:ffff::9", 1, 100).is_err());
        assert!(admit(&fair, "2001:db8:1:3::1", 1, 100).is_ok());
        // An IPv4-mapped address is the IPv4 source.
        let _v4 = admit(&fair, "192.0.2.1", 1, 100).unwrap();
        assert!(admit(&fair, "::ffff:192.0.2.1", 1, 100).is_err());
    }

    #[test]
    fn at_the_total_the_oldest_of_the_source_holding_the_most_makes_room() {
        let fair = Fair::new();
        let (a1, _) = admit(&fair, "192.0.2.1", 10, 4).unwrap();
        let _b1 = admit(&fair, "192.0.2.2", 10, 4).unwrap();
        let (a2, _) = admit(&fair, "192.0.2.1", 10, 4).unwrap();
        let _a3 = admit(&fair, "192.0.2.1", 10, 4).unwrap();
        assert_eq!(fair.held(), 4);
        // Full: a newcomer from c pushes out a's oldest.
        let (c1, _) = admit(&fair, "192.0.2.3", 10, 4).unwrap();
        assert!(c1.evicted);
        assert!(a1.was_evicted());
        assert!(!a2.was_evicted());
        assert_eq!(fair.held(), 4);
        // The source holding the most pushes out its own oldest.
        let (a4, _) = admit(&fair, "192.0.2.1", 10, 4).unwrap();
        assert!(a4.evicted);
        assert!(a2.was_evicted());
        assert!(!c1.was_evicted());
        // The per-source cap holds whatever the total.
        assert!(admit(&fair, "192.0.2.2", 1, 100).is_err());
    }

    #[test]
    fn a_request_in_flight_is_never_pushed_out() {
        let fair = Fair::new();
        // The honest client's request is in flight; sixteen sources with one
        // idle connection each fill a total of 17, then keep coming.
        let (honest, honest_conn) = admit(&fair, "198.51.100.1", 8, 17).unwrap();
        honest_conn.request_started();
        let mut others = Vec::new();
        for i in 1..=16 {
            others.push(admit(&fair, &format!("192.0.2.{i}"), 8, 17).unwrap());
        }
        for i in 17..=40 {
            let (slot, conn) = admit(&fair, &format!("192.0.2.{i}"), 8, 17).unwrap();
            assert!(slot.evicted);
            others.push((slot, conn));
        }
        assert!(!honest.was_evicted());
        assert_eq!(fair.held(), 17);
    }

    #[test]
    fn a_connection_that_never_completed_a_request_goes_before_one_that_did() {
        let fair = Fair::new();
        // Two singletons: the older one has served a request, the newer
        // has not.
        let (served, served_conn) = admit(&fair, "192.0.2.1", 8, 2).unwrap();
        served_conn.request_started();
        served_conn.request_ended();
        let (fresh, _fresh_conn) = admit(&fair, "192.0.2.2", 8, 2).unwrap();
        let (newcomer, _c) = admit(&fair, "192.0.2.3", 8, 2).unwrap();
        assert!(newcomer.evicted);
        assert!(fresh.was_evicted());
        assert!(!served.was_evicted());
    }

    #[test]
    fn a_source_with_more_candidates_loses_one_before_a_single_connection() {
        let fair = Fair::new();
        let (single, _s) = admit(&fair, "192.0.2.9", 8, 3).unwrap();
        let (a1, _a1c) = admit(&fair, "192.0.2.1", 8, 3).unwrap();
        let (a2, _a2c) = admit(&fair, "192.0.2.1", 8, 3).unwrap();
        let (_newcomer, _c) = admit(&fair, "192.0.2.3", 8, 3).unwrap();
        assert!(a1.was_evicted());
        assert!(!a2.was_evicted());
        assert!(!single.was_evicted());
    }

    #[test]
    fn with_every_connection_in_flight_a_newcomer_is_refused() {
        let fair = Fair::new();
        let (_a, ac) = admit(&fair, "192.0.2.1", 8, 2).unwrap();
        let (_b, bc) = admit(&fair, "192.0.2.2", 8, 2).unwrap();
        ac.request_started();
        bc.request_started();
        assert_eq!(admit(&fair, "192.0.2.3", 8, 2).unwrap_err(), Refused::Full);
        assert_eq!(fair.held(), 2);
    }

    #[test]
    fn the_phase_decides_which_timeout_applies() {
        let limits = Limits {
            header_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(75),
            request_timeout: Duration::from_secs(30),
            max_connections: 1,
            max_per_source: 1,
            shutdown_grace: Duration::from_secs(8),
        };
        let conn = ConnState::new();
        let why = |c: &ConnState| c.deadline(&limits).map(|(_, why)| why);
        // Before its first request: the header timeout.
        assert_eq!(why(&conn), Some("header_timeout"));
        conn.bytes_read();
        assert_eq!(why(&conn), Some("header_timeout"));
        // In flight: the request deadline covers it, not a connection timer.
        conn.request_started();
        assert!(conn.in_flight());
        assert_eq!(why(&conn), None);
        // After the response: the idle timeout, which is the longer one.
        conn.request_ended();
        assert!(conn.served() && !conn.in_flight());
        let (idle_at, idle_why) = conn.deadline(&limits).unwrap();
        assert_eq!(idle_why, "idle_timeout");
        assert!(idle_at >= Instant::now() + Duration::from_secs(70));
        // The next head's first byte starts the header timeout again.
        conn.bytes_read();
        assert_eq!(why(&conn), Some("header_timeout"));
        // Bytes that arrive while a response is going count as a head
        // already begun.
        conn.request_started();
        conn.bytes_read();
        conn.request_ended();
        assert_eq!(why(&conn), Some("header_timeout"));
    }

    #[tokio::test]
    async fn until_empty_waits_for_the_last_slot() {
        let fair = Fair::new();
        let (slot, _conn) = admit(&fair, "192.0.2.1", 1, 1).unwrap();
        let waiting = tokio::spawn({
            let fair = Arc::clone(&fair);
            async move { fair.until_empty().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(slot);
        waiting.await.unwrap();
        assert_eq!(fair.held(), 0);
    }
}
