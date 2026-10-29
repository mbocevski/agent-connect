//! The public listener's connection limits: a header-read timeout, and
//! a cap on open connections, in all and per source.
//!
//! A client that sends part of a request head and stops would otherwise hold
//! a connection (a descriptor and some memory) for as long as it likes, and
//! many of them could use the directory up (slowloris). Modelled on the
//! relay's HTTP limits:
//!
//! - the request head has to arrive within the header timeout, on a new
//!   connection and between requests;
//! - a source (an IPv4 address or an IPv6 /64) holds at most its cap of
//!   connections, and the next one from it is closed at once;
//! - at the total cap a newcomer closes the oldest connection of the source
//!   holding the most, instead of being refused, so one source can't fill
//!   the directory against everybody else;
//! - before its headers a connection from a trusted proxy can't be told
//!   from the proxy's other clients, so only the total limits it.
//!
//! Addresses stay in process memory, are never logged and never become a
//! metric label.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};

use crate::ratelimit::bucket;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What the listener enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long a connection may take to send a request head.
    pub header_timeout: Duration,
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

/// Why [`Fair::admit`] turned a connection away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Its source holds its share already.
    Source,
}

/// Connections under a total cap and a per-source cap, fairly: at the total
/// cap a newcomer closes the oldest connection of the source holding the
/// most.
#[derive(Debug, Default)]
pub struct Fair {
    state: Mutex<FairState>,
    changed: Notify,
}

#[derive(Debug, Default)]
struct FairState {
    next: u64,
    held: usize,
    by_source: HashMap<IpAddr, VecDeque<(u64, Arc<Notify>)>>,
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
            .is_some_and(|q| q.iter().any(|(id, _)| *id == self.id))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = lock(&self.fair.state);
        if let Some(q) = state.by_source.get_mut(&self.source)
            && let Some(i) = q.iter().position(|(id, _)| *id == self.id)
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
    /// [`bucket`]): at most `per_source` for it and `total` in all. At the
    /// total, the source holding the most loses its oldest connection; on
    /// a tie, the one whose oldest connection is oldest.
    ///
    /// # Errors
    ///
    /// [`Refused::Source`] past the source's cap.
    pub fn admit(
        self: &Arc<Self>,
        source: IpAddr,
        per_source: usize,
        total: usize,
    ) -> Result<Slot, Refused> {
        let mut state = lock(&self.state);
        let own = state.by_source.get(&source).map_or(0, VecDeque::len);
        if own >= per_source {
            return Err(Refused::Source);
        }
        let mut evicted = false;
        if state.held >= total.max(1) {
            let top = state
                .by_source
                .iter()
                .filter(|(_, q)| !q.is_empty())
                .max_by_key(|(_, q)| (q.len(), std::cmp::Reverse(q[0].0)))
                .map(|(k, _)| *k);
            if let Some(top) = top
                && let Some(q) = state.by_source.get_mut(&top)
                && let Some((_, kick)) = q.pop_front()
            {
                kick.notify_one();
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
        state
            .by_source
            .entry(source)
            .or_default()
            .push_back((id, Arc::clone(&kick)));
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
        let Ok(slot) = fair.admit(bucket(peer.ip()), per_source, limits.max_connections) else {
            events("connection", "refused");
            continue;
        };
        if slot.evicted {
            events("connection", "evicted");
        }
        tokio::spawn(connection(
            tcp,
            peer,
            slot,
            router.clone(),
            limits.header_timeout,
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

/// One connection: its requests, until it ends, is evicted, or the
/// shutdown signal asks it to finish its request and close.
async fn connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    slot: Slot,
    router: Router,
    header_timeout: Duration,
    mut stop: watch::Receiver<bool>,
    events: Events,
) {
    // The peer address for the per-address limits, resolved against a
    // trusted proxy's header by the handlers.
    let service = TowerToHyperService::new(router.layer(axum::Extension(ConnectInfo(peer))));
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .serve_connection(TokioIo::new(tcp), service);
    let kick = Arc::clone(&slot.kick);
    let _slot = slot;
    let mut conn = std::pin::pin!(conn);
    let result = tokio::select! {
        r = conn.as_mut() => r,
        // A newcomer took this connection's place: drop it.
        () = kick.notified() => return,
        () = stopped(&mut stop) => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(e) = result
        && e.is_timeout()
    {
        events("connection", "header_timeout");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        bucket(s.parse().unwrap())
    }

    #[test]
    fn a_source_holds_at_most_its_cap_and_slots_come_back() {
        let fair = Fair::new();
        let (a, b) = (ip("192.0.2.1"), ip("192.0.2.2"));
        let first = fair.admit(a, 2, 100).unwrap();
        let _second = fair.admit(a, 2, 100).unwrap();
        assert_eq!(fair.admit(a, 2, 100).unwrap_err(), Refused::Source);
        // Another source has its own share.
        let _other = fair.admit(b, 2, 100).unwrap();
        drop(first);
        assert_eq!(fair.held(), 2);
        let _again = fair.admit(a, 2, 100).unwrap();
        assert_eq!(fair.held(), 3);
        assert_eq!(fair.admit(a, 0, 100).unwrap_err(), Refused::Source);
    }

    #[test]
    fn sources_are_ipv4_addresses_and_ipv6_slash_64s() {
        let fair = Fair::new();
        let _a = fair.admit(ip("2001:db8:1:2::1"), 1, 100).unwrap();
        // The same /64 shares the cap; another /64 does not.
        assert!(fair.admit(ip("2001:db8:1:2:ffff::9"), 1, 100).is_err());
        assert!(fair.admit(ip("2001:db8:1:3::1"), 1, 100).is_ok());
        // An IPv4-mapped address is the IPv4 source.
        let _v4 = fair.admit(ip("192.0.2.1"), 1, 100).unwrap();
        assert!(fair.admit(ip("::ffff:192.0.2.1"), 1, 100).is_err());
    }

    #[test]
    fn at_the_total_the_oldest_of_the_source_holding_the_most_makes_room() {
        let fair = Fair::new();
        let (a, b, c) = (ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3"));
        let a1 = fair.admit(a, 10, 4).unwrap();
        let _b1 = fair.admit(b, 10, 4).unwrap();
        let a2 = fair.admit(a, 10, 4).unwrap();
        let _a3 = fair.admit(a, 10, 4).unwrap();
        assert_eq!(fair.held(), 4);
        // Full: a newcomer from c pushes out a's oldest.
        let c1 = fair.admit(c, 10, 4).unwrap();
        assert!(c1.evicted);
        assert!(a1.was_evicted());
        assert!(!a2.was_evicted());
        assert_eq!(fair.held(), 4);
        // The source holding the most pushes out its own oldest.
        let a4 = fair.admit(a, 10, 4).unwrap();
        assert!(a4.evicted);
        assert!(a2.was_evicted());
        assert!(!c1.was_evicted());
        // The per-source cap holds whatever the total.
        assert!(fair.admit(b, 1, 100).is_err());
    }

    #[tokio::test]
    async fn until_empty_waits_for_the_last_slot() {
        let fair = Fair::new();
        let slot = fair.admit(ip("192.0.2.1"), 1, 1).unwrap();
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
