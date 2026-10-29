//! Where an HTTP connection is in its requests: waiting for the first byte
//! of one, receiving its head, or serving it. The server reads it for two
//! things: the connection's own deadline (a head has the header timeout,
//! counted from its first byte, and an idle connection between requests has
//! the idle timeout), and whether the connection may be pushed out at the
//! HTTP cap (a request is protected once its body is in and until its answer
//! is done, see [`Fair`](crate::conn::Fair)).
//!
//! The state sits in memory only and holds no address.

use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes, HttpBody};
use tokio::sync::Notify;

use crate::relay::Timeout;
use crate::timer::Timer;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where a connection is in its requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the first byte of a request.
    Idle,
    /// Part of a request head has arrived.
    Head,
    /// A request is being served: its head is in, its answer is not done.
    InFlight,
}

#[derive(Debug)]
struct Inner {
    phase: Phase,
    since: Instant,
    /// A request has completed on this connection.
    served: bool,
    /// Bytes of the next request arrived while an answer was still going.
    early: bool,
    /// The body of the request in flight has been read to its end.
    body_done: bool,
}

/// What the server knows about one HTTP connection's requests.
#[derive(Debug)]
pub struct ConnState {
    inner: Mutex<Inner>,
    wake: Notify,
    timer: Timer,
}

impl ConnState {
    /// A new connection, waiting for its first request.
    #[must_use]
    pub fn new(timer: Timer) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                phase: Phase::Idle,
                since: timer.now(),
                served: false,
                early: false,
                body_done: false,
            }),
            wake: Notify::new(),
            timer,
        })
    }

    /// Bytes arrived from the client.
    pub(crate) fn bytes_read(&self) {
        let mut inner = lock(&self.inner);
        match inner.phase {
            Phase::Idle => {
                inner.phase = Phase::Head;
                inner.since = self.timer.now();
                drop(inner);
                self.wake.notify_one();
            }
            Phase::InFlight => inner.early = true,
            Phase::Head => {}
        }
    }

    /// The server took a request's head: the request is in flight. One
    /// without a body (`body_done`) is ready to be served at once.
    pub(crate) fn request_started(&self, body_done: bool) {
        let mut inner = lock(&self.inner);
        inner.phase = Phase::InFlight;
        inner.since = self.timer.now();
        inner.body_done = body_done;
        drop(inner);
        self.wake.notify_one();
    }

    /// The request's body has been read to its end.
    pub(crate) fn body_done(&self) {
        lock(&self.inner).body_done = true;
    }

    /// The answer is done (or the connection went).
    pub(crate) fn request_ended(&self) {
        let mut inner = lock(&self.inner);
        inner.served = true;
        inner.since = self.timer.now();
        inner.body_done = false;
        inner.phase = if std::mem::take(&mut inner.early) {
            Phase::Head
        } else {
            Phase::Idle
        };
        drop(inner);
        self.wake.notify_one();
    }

    /// True while a request is being served: its head and body are in, and
    /// its answer is not done. Only such a connection is shielded from
    /// eviction (see [`Fair::admit`](crate::conn::Fair::admit)); while a
    /// body is still arriving the connection is at the client's pace, as a
    /// head is.
    #[must_use]
    pub fn protected(&self) -> bool {
        let inner = lock(&self.inner);
        inner.phase == Phase::InFlight && inner.body_done
    }

    /// True once a request has completed on the connection.
    #[must_use]
    pub fn served(&self) -> bool {
        lock(&self.inner).served
    }

    /// When the connection runs out of time and why, or `None` while a
    /// request is in flight (the request deadline and the write timeout
    /// cover it).
    pub(crate) fn deadline(&self, header: Duration, idle: Duration) -> Option<(Instant, Timeout)> {
        let inner = lock(&self.inner);
        match inner.phase {
            Phase::Head => Some((inner.since + header, Timeout::Header)),
            // Before its first request a connection has only the header
            // timeout to send a head; between requests, the idle timeout.
            Phase::Idle if !inner.served => Some((inner.since + header, Timeout::Header)),
            Phase::Idle => Some((inner.since + idle, Timeout::HttpIdle)),
            Phase::InFlight => None,
        }
    }

    /// Wait for the phase to change: the deadline is worth looking at again.
    pub(crate) async fn changed(&self) {
        self.wake.notified().await;
    }

    /// The service wrapper's hooks for a request: its head is in, and its
    /// body, when it has one, ends the wait for it.
    pub(crate) fn begin(
        self: &Arc<Self>,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> hyper::Request<BodyEnd> {
        let (parts, inner) = req.into_parts();
        self.request_started(inner.is_end_stream());
        hyper::Request::from_parts(
            parts,
            BodyEnd {
                inner,
                state: Arc::clone(self),
            },
        )
    }

    /// An answer whose end ends the request: when its body is done, or
    /// dropped unread.
    pub(crate) fn finish(
        self: &Arc<Self>,
        resp: axum::response::Response,
    ) -> axum::response::Response {
        let guard = EndGuard(Arc::clone(self));
        resp.map(|inner| Body::new(Answer { inner, _end: guard }))
    }
}

/// Ends the request when the answer's body is finished or dropped.
struct EndGuard(Arc<ConnState>);

impl Drop for EndGuard {
    fn drop(&mut self) {
        self.0.request_ended();
    }
}

/// A request body that notes when it has been read to its end.
pub(crate) struct BodyEnd {
    inner: hyper::body::Incoming,
    state: Arc<ConnState>,
}

impl HttpBody for BodyEnd {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        let done = match &polled {
            Poll::Ready(None) => true,
            Poll::Ready(Some(Ok(_))) => self.inner.is_end_stream(),
            _ => false,
        };
        if done {
            self.state.body_done();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// An answer's body, carrying the guard that ends the request with it.
struct Answer {
    inner: Body,
    _end: EndGuard,
}

impl HttpBody for Answer {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timer::ManualTimer;

    fn state() -> (Arc<ConnState>, Arc<ManualTimer>) {
        let timer = ManualTimer::new();
        (ConnState::new(Timer::Manual(timer.clone())), timer)
    }

    const HEADER: Duration = Duration::from_secs(10);
    const IDLE: Duration = Duration::from_secs(75);

    fn why(c: &ConnState) -> Option<Timeout> {
        c.deadline(HEADER, IDLE).map(|(_, why)| why)
    }

    #[test]
    fn the_phase_decides_which_timeout_applies() {
        let (conn, timer) = state();
        // Before its first request: the header timeout, from the start.
        assert_eq!(why(&conn), Some(Timeout::Header));
        timer.advance(Duration::from_secs(3));
        conn.bytes_read();
        // The first byte of the head starts the header clock again.
        let (at, _) = conn.deadline(HEADER, IDLE).unwrap();
        assert_eq!(at, timer.now() + HEADER);
        // In flight: the request deadline covers it, not a connection timer.
        conn.request_started(true);
        assert!(conn.protected());
        assert_eq!(why(&conn), None);
        // After the answer: the idle timeout, the longer one.
        conn.request_ended();
        assert!(conn.served() && !conn.protected());
        let (at, kind) = conn.deadline(HEADER, IDLE).unwrap();
        assert_eq!((at, kind), (timer.now() + IDLE, Timeout::HttpIdle));
        // The next head's first byte starts the header timeout again.
        conn.bytes_read();
        assert_eq!(why(&conn), Some(Timeout::Header));
        // Bytes that arrive while an answer is going count as a head begun.
        conn.request_started(true);
        conn.bytes_read();
        conn.request_ended();
        assert_eq!(why(&conn), Some(Timeout::Header));
    }

    #[test]
    fn a_request_is_protected_once_its_body_is_in() {
        let (conn, _timer) = state();
        conn.request_started(false);
        assert!(!conn.protected(), "the body is still arriving");
        conn.body_done();
        assert!(conn.protected());
        conn.request_ended();
        assert!(!conn.protected());
        // A request without a body is protected from its start.
        conn.request_started(true);
        assert!(conn.protected());
    }
}
