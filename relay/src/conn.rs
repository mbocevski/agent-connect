//! Per-connection plumbing below HTTP and WebSocket: which source a
//! connection comes from, how many connections each source holds, the bytes
//! a connection has read and not yet handed on as messages, and a deadline on
//! writes that stall.
//!
//! A source is the peer's IPv4 address or IPv6 /64, but the relay never keeps
//! the address: it keeps a [`SourceKey`], an HMAC of the prefix under a key
//! drawn when the process starts. The counts live in memory only and are never
//! logged.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::timer::Timer;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Drawn once per process, never stored: source keys can't be computed
/// from an address by anyone else, nor matched across restarts.
static SOURCE_KEY: std::sync::LazyLock<[u8; 32]> =
    std::sync::LazyLock::new(crate::auth::random_bytes);

/// An opaque per-process key for a connection's source: the peer's IPv4
/// address, or its IPv6 /64 (an IPv4-mapped IPv6 address counts as IPv4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceKey([u8; 16]);

impl SourceKey {
    /// The key for `ip`.
    #[must_use]
    pub fn of(ip: IpAddr) -> Self {
        use sha2::Digest as _;
        // The same grouping as the per-address rate limits
        // (`quota::address_key`), so both count one client the same way.
        let address = crate::quota::address_key(Some(ip));
        // A fixed-length secret prefix, then the key: no extension or
        // collision games apply to a key that is never shown.
        let digest = Sha256::new()
            .chain_update(SOURCE_KEY.as_slice())
            .chain_update(address.as_bytes())
            .finalize();
        let mut key = [0_u8; 16];
        key.copy_from_slice(&digest[..16]);
        Self(key)
    }

    /// The key every connection without a known peer shares (in-memory test
    /// connections).
    #[must_use]
    pub const fn unknown() -> Self {
        Self([0; 16])
    }
}

/// Connections held per source, capped.
#[derive(Debug, Default)]
pub struct SourceCounts {
    counts: Mutex<HashMap<SourceKey, usize>>,
}

/// One connection counted against its source until dropped.
#[derive(Debug)]
pub struct SourceSlot {
    counts: Arc<SourceCounts>,
    key: SourceKey,
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut counts = lock(&self.counts.counts);
        if let Some(n) = counts.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

impl SourceCounts {
    /// Count one more connection for `key`, unless it holds `max` already.
    pub fn take(self: &Arc<Self>, key: SourceKey, max: usize) -> Option<SourceSlot> {
        let mut counts = lock(&self.counts);
        let n = counts.entry(key).or_default();
        if *n >= max {
            if *n == 0 {
                counts.remove(&key);
            }
            return None;
        }
        *n += 1;
        Some(SourceSlot {
            counts: Arc::clone(self),
            key,
        })
    }

    /// Connections counted for `key` now.
    #[must_use]
    pub fn held(&self, key: SourceKey) -> usize {
        lock(&self.counts).get(&key).copied().unwrap_or(0)
    }
}

/// The relay-wide budget for bytes connections have read and not yet handed
/// on as whole messages: partial WebSocket messages and read buffers. Past
/// it, the connection holding the most is told to close.
#[derive(Debug)]
pub struct ReadBudget {
    limit: u64,
    total: Arc<AtomicU64>,
    next_id: AtomicU64,
    conns: Mutex<HashMap<u64, Arc<Rx>>>,
}

impl ReadBudget {
    /// A budget of `limit` bytes, keeping its running total in `total` (the
    /// metrics gauge).
    #[must_use]
    pub fn new(limit: u64, total: Arc<AtomicU64>) -> Arc<Self> {
        Arc::new(Self {
            limit,
            total,
            next_id: AtomicU64::new(0),
            conns: Mutex::default(),
        })
    }

    /// Bytes held across connections now.
    #[must_use]
    pub fn held(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// A counter for a new connection from `source`; it counts against the
    /// budget once [`Rx::track`] is called.
    #[must_use]
    pub fn counter(self: &Arc<Self>, source: SourceKey) -> Arc<Rx> {
        Arc::new(Rx {
            budget: Arc::clone(self),
            source: Mutex::new(source),
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            read: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            tracking: AtomicBool::new(false),
            shed: AtomicBool::new(false),
            write_stall: AtomicBool::new(true),
            evict: Notify::new(),
        })
    }

    /// Over the budget: tell the tracked connections holding the most to
    /// close, until what is left would fit.
    fn shed(&self) {
        let conns = lock(&self.conns);
        // Connections already told to close are as good as gone.
        let leaving: u64 = conns
            .values()
            .filter(|rx| rx.shed.load(Ordering::Relaxed))
            .map(|rx| rx.pending())
            .sum();
        let mut over = self
            .held()
            .saturating_sub(leaving)
            .saturating_sub(self.limit);
        // The source holding the most goes first, its largest connection
        // first: many small partial messages from one source don't push out
        // another source's one large message.
        let mut staying: Vec<&Arc<Rx>> = conns
            .values()
            .filter(|rx| !rx.shed.load(Ordering::Relaxed))
            .collect();
        while over > 0 && !staying.is_empty() {
            let mut per_source: HashMap<SourceKey, u64> = HashMap::new();
            for rx in &staying {
                *per_source.entry(rx.source()).or_default() += rx.pending();
            }
            let Some((&top, _)) = per_source.iter().max_by_key(|(_, held)| **held) else {
                break;
            };
            let Some(i) = staying
                .iter()
                .enumerate()
                .filter(|(_, rx)| rx.source() == top)
                .max_by_key(|(_, rx)| rx.pending())
                .map(|(i, _)| i)
            else {
                break;
            };
            let rx = staying.swap_remove(i);
            over = over.saturating_sub(rx.pending());
            rx.shed.store(true, Ordering::Relaxed);
            rx.evict.notify_one();
        }
    }
}

/// What one connection has read.
#[derive(Debug)]
pub struct Rx {
    budget: Arc<ReadBudget>,
    /// The source the budget sheds by: the TCP peer's at first, the
    /// client's address once the connection is a WebSocket.
    source: Mutex<SourceKey>,
    id: u64,
    /// Every byte read, ever.
    read: AtomicU64,
    /// Bytes read and not yet handed on as messages (while tracked).
    pending: AtomicU64,
    tracking: AtomicBool,
    shed: AtomicBool,
    /// Whether [`Io`] times out stalled writes (off once a WebSocket's own
    /// send deadline takes over).
    write_stall: AtomicBool,
    /// Fires when the budget sheds this connection.
    pub evict: Notify,
}

impl Rx {
    /// The source the budget counts this connection under.
    #[must_use]
    pub fn source(&self) -> SourceKey {
        *lock(&self.source)
    }

    /// Every byte the connection has read.
    #[must_use]
    pub fn read(&self) -> u64 {
        self.read.load(Ordering::Relaxed)
    }

    /// Bytes read and not yet handed on as messages.
    #[must_use]
    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Relaxed)
    }

    /// Stop timing out stalled writes on this connection.
    pub fn stop_write_stall(&self) {
        self.write_stall.store(false, Ordering::Relaxed);
    }

    /// Start counting against the budget (when the connection becomes a
    /// WebSocket); stops when the counter is dropped by every holder.
    pub fn track(self: &Arc<Self>, source: SourceKey) {
        *lock(&self.source) = source;
        if !self.tracking.swap(true, Ordering::Relaxed) {
            lock(&self.budget.conns).insert(self.id, Arc::clone(self));
        }
    }

    /// Stop counting against the budget and give back what is held.
    pub fn untrack(&self) {
        if self.tracking.swap(false, Ordering::Relaxed) {
            lock(&self.budget.conns).remove(&self.id);
            let held = self.pending.swap(0, Ordering::Relaxed);
            self.budget.total.fetch_sub(held, Ordering::Relaxed);
        }
    }

    fn add(&self, n: u64) {
        self.read.fetch_add(n, Ordering::Relaxed);
        if self.tracking.load(Ordering::Relaxed) {
            self.pending.fetch_add(n, Ordering::Relaxed);
            let total = self.budget.total.fetch_add(n, Ordering::Relaxed) + n;
            if total > self.budget.limit {
                self.budget.shed();
            }
        }
    }

    /// A message of about `wire_len` bytes (frame headers included) has been
    /// handed on.
    pub fn consumed(&self, wire_len: u64) {
        if !self.tracking.load(Ordering::Relaxed) {
            return;
        }
        let mut cur = self.pending.load(Ordering::Relaxed);
        loop {
            let take = cur.min(wire_len);
            match self.pending.compare_exchange_weak(
                cur,
                cur - take,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.budget.total.fetch_sub(take, Ordering::Relaxed);
                    return;
                }
                Err(now) => cur = now,
            }
        }
    }
}

/// Why [`Fair::admit`] turned a connection away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Its source holds its share already.
    Source,
    /// The total is reached and no other source holds more.
    Full,
}

/// Connections under a total cap and a per-source cap, fairly: at the total
/// cap a newcomer closes the oldest connection of the source holding the
/// most, instead of waiting or being refused.
#[derive(Debug, Default)]
pub struct Fair {
    state: Mutex<FairState>,
    changed: Notify,
}

#[derive(Debug, Default)]
struct FairState {
    next: u64,
    held: usize,
    by_source: HashMap<SourceKey, std::collections::VecDeque<(u64, Arc<Notify>)>>,
}

/// One connection held in a [`Fair`] until dropped.
#[derive(Debug)]
pub struct FairSlot {
    fair: Arc<Fair>,
    source: SourceKey,
    id: u64,
    /// Fires when a newcomer took this connection's place.
    pub kick: Arc<Notify>,
    /// True if admitting this connection closed another.
    pub evicted: bool,
}

impl FairSlot {
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

impl Drop for FairSlot {
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

    /// Admit a connection from `source`: at most `per_source` for it and
    /// `total` in all. At the total, the source holding the most loses its
    /// oldest connection; if that is `source` itself, only when `evict_own`.
    ///
    /// # Errors
    ///
    /// [`Refused::Source`] past the source's cap, [`Refused::Full`] at the
    /// total when nobody else may make room.
    pub fn admit(
        self: &Arc<Self>,
        source: SourceKey,
        per_source: usize,
        total: usize,
        evict_own: bool,
    ) -> Result<FairSlot, Refused> {
        let mut state = lock(&self.state);
        let own = state
            .by_source
            .get(&source)
            .map_or(0, std::collections::VecDeque::len);
        if own >= per_source {
            return Err(Refused::Source);
        }
        let mut evicted = false;
        if state.held >= total.max(1) {
            // The source holding the most; on a tie, the one whose oldest
            // connection is oldest.
            let top = state
                .by_source
                .iter()
                .filter(|(_, q)| !q.is_empty())
                .max_by_key(|(_, q)| (q.len(), std::cmp::Reverse(q[0].0)))
                .map(|(k, _)| *k);
            let Some(top) = top.filter(|t| evict_own || *t != source) else {
                return Err(Refused::Full);
            };
            if let Some(q) = state.by_source.get_mut(&top)
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
        Ok(FairSlot {
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

/// What the HTTP server knows about a connection, handed to every request
/// on it: its source and its read counter.
#[derive(Debug, Clone)]
pub struct ConnCtx {
    /// The connection's source.
    pub source: SourceKey,
    /// What the connection has read.
    pub rx: Arc<Rx>,
}

/// The wire size of a client WebSocket frame carrying `payload` bytes:
/// header, extended length and the 4-byte mask.
#[must_use]
pub fn ws_wire_len(payload: usize) -> u64 {
    let ext = match payload {
        0..=125 => 0,
        126..=65_535 => 2,
        _ => 8,
    };
    u64::try_from(payload).unwrap_or(u64::MAX) + 2 + ext + 4
}

type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A connection's I/O: counts what it reads into an [`Rx`], and fails a
/// write that makes no progress for the write timeout.
pub struct Io<I> {
    inner: I,
    rx: Arc<Rx>,
    timer: Timer,
    write_timeout: Duration,
    stalled: Option<SleepFuture>,
}

impl<I> Io<I> {
    /// Wrap `inner`.
    pub fn new(inner: I, rx: Arc<Rx>, timer: Timer, write_timeout: Duration) -> Self {
        Self {
            inner,
            rx,
            timer,
            write_timeout,
            stalled: None,
        }
    }

    /// The write made no progress: start (or keep) the stall deadline, and
    /// fail once it has passed.
    fn check_stall(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.rx.write_stall.load(Ordering::Relaxed) {
            self.stalled = None;
            return Poll::Pending;
        }
        let timer = self.timer.clone();
        let deadline = self.timer.now() + self.write_timeout;
        let sleep = self
            .stalled
            .get_or_insert_with(|| Box::pin(async move { timer.sleep_until(deadline).await }));
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "write stalled",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for Io<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            let n = buf.filled().len() - before;
            self.rx.add(u64::try_from(n).unwrap_or(u64::MAX));
        }
        r
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Io<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(r) => {
                self.stalled = None;
                Poll::Ready(r)
            }
            Poll::Pending => self.check_stall(cx).map(|r| r.map(|()| 0)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(r) => {
                self.stalled = None;
                Poll::Ready(r)
            }
            Poll::Pending => self.check_stall(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn sources_are_ipv4_addresses_and_ipv6_slash_64s() {
        let a = |s: &str| SourceKey::of(s.parse().unwrap());
        assert_eq!(a("192.0.2.1"), a("192.0.2.1"));
        assert_ne!(a("192.0.2.1"), a("192.0.2.2"));
        assert_eq!(a("2001:db8:1:2::1"), a("2001:db8:1:2:ffff::9"));
        assert_ne!(a("2001:db8:1:2::1"), a("2001:db8:1:3::1"));
        // An IPv4-mapped address is the IPv4 source.
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
        assert_eq!(SourceKey::of(mapped), a("192.0.2.1"));
        assert_ne!(
            SourceKey::of(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            SourceKey::unknown()
        );
    }

    #[test]
    fn a_source_holds_at_most_its_cap_and_slots_come_back() {
        let counts = Arc::new(SourceCounts::default());
        let k = SourceKey::of("192.0.2.1".parse().unwrap());
        let other = SourceKey::of("192.0.2.2".parse().unwrap());
        let a = counts.take(k, 2).unwrap();
        let _b = counts.take(k, 2).unwrap();
        assert!(counts.take(k, 2).is_none());
        let _c = counts.take(other, 2).unwrap();
        drop(a);
        assert_eq!(counts.held(k), 1);
        let _d = counts.take(k, 2).unwrap();
        assert!(counts.take(k, 0).is_none());
        assert_eq!(counts.held(k), 2);
    }

    #[test]
    fn the_budget_sheds_the_connection_holding_the_most() {
        let budget = ReadBudget::new(1000, Arc::default());
        let small = budget.counter(SourceKey::unknown());
        let big = budget.counter(SourceKey::unknown());
        let untracked = budget.counter(SourceKey::unknown());
        small.track(SourceKey::unknown());
        big.track(SourceKey::unknown());
        untracked.add(5000);
        assert_eq!(budget.held(), 0);
        assert_eq!(untracked.read(), 5000);
        small.add(300);
        big.add(600);
        assert!(!big.shed.load(Ordering::Relaxed));
        big.add(200);
        assert!(big.shed.load(Ordering::Relaxed));
        assert!(!small.shed.load(Ordering::Relaxed));
        // More reads while the shed one is still closing shed nobody else.
        small.add(100);
        assert!(!small.shed.load(Ordering::Relaxed));
        small.consumed(100);
        // A message handed on gives its bytes back.
        small.consumed(ws_wire_len(294));
        assert_eq!(small.pending(), 0);
        assert_eq!(budget.held(), 800);
        big.untrack();
        assert_eq!(budget.held(), 0);
        small.consumed(10);
        assert_eq!(budget.held(), 0);
    }

    #[test]
    fn the_budget_sheds_the_source_holding_the_most_first() {
        let budget = ReadBudget::new(1000, Arc::default());
        let attacker = SourceKey::of("192.0.2.1".parse().unwrap());
        let honest = SourceKey::of("198.51.100.1".parse().unwrap());
        // One honest upload, larger than any one of the attacker's partials.
        let welcome = budget.counter(honest);
        welcome.track(honest);
        welcome.add(400);
        let partials: Vec<_> = (0..4).map(|_| budget.counter(attacker)).collect();
        for rx in &partials {
            rx.track(attacker);
            rx.add(175);
        }
        assert!(!welcome.shed.load(Ordering::Relaxed));
        // 1100 held: the attacker's 700 go first, one connection at a time.
        let shed: Vec<bool> = partials
            .iter()
            .map(|rx| rx.shed.load(Ordering::Relaxed))
            .collect();
        assert_eq!(shed.iter().filter(|s| **s).count(), 1);
        assert!(!welcome.shed.load(Ordering::Relaxed));
        partials[0].add(300);
        assert!(!welcome.shed.load(Ordering::Relaxed));
    }

    #[test]
    fn at_the_cap_the_oldest_of_the_source_holding_the_most_makes_room() {
        let fair = Fair::new();
        let a = SourceKey::of("192.0.2.1".parse().unwrap());
        let b = SourceKey::of("192.0.2.2".parse().unwrap());
        let c = SourceKey::of("192.0.2.3".parse().unwrap());
        let a1 = fair.admit(a, 10, 4, true).unwrap();
        let _b1 = fair.admit(b, 10, 4, true).unwrap();
        let a2 = fair.admit(a, 10, 4, true).unwrap();
        let _a3 = fair.admit(a, 10, 4, true).unwrap();
        assert_eq!(fair.held(), 4);
        // Full: a newcomer from c pushes out a's oldest.
        let c1 = fair.admit(c, 10, 4, true).unwrap();
        assert!(c1.evicted);
        assert!(a1.was_evicted());
        assert!(!a2.was_evicted());
        assert_eq!(fair.held(), 4);
        // A newcomer from the source holding the most is refused when it
        // may not push out its own.
        let _a4 = fair.admit(c, 10, 5, true).unwrap();
        assert!(matches!(fair.admit(a, 10, 5, false), Err(Refused::Full)));
        // The per-source cap holds whatever the total.
        assert!(matches!(fair.admit(b, 1, 100, true), Err(Refused::Source)));
        drop(c1);
        assert_eq!(fair.held(), 4);
    }

    #[tokio::test]
    async fn until_empty_waits_for_the_last_slot() {
        let fair = Fair::new();
        let slot = fair.admit(SourceKey::unknown(), 1, 1, true).unwrap();
        let waiting = fair.until_empty();
        tokio::pin!(waiting);
        assert!(futures_poll(&mut waiting).is_pending());
        drop(slot);
        waiting.await;
    }

    fn futures_poll<F: Future + Unpin>(f: &mut F) -> Poll<F::Output> {
        let waker = std::task::Waker::noop();
        Pin::new(f).poll(&mut Context::from_waker(waker))
    }

    #[test]
    fn wire_lengths_follow_rfc_6455() {
        assert_eq!(ws_wire_len(0), 6);
        assert_eq!(ws_wire_len(125), 131);
        assert_eq!(ws_wire_len(126), 134);
        assert_eq!(ws_wire_len(70_000), 70_014);
    }

    #[tokio::test]
    async fn io_counts_reads_and_fails_a_stalled_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let timer = crate::timer::ManualTimer::new();
        let budget = ReadBudget::new(u64::MAX, Arc::default());
        let rx = budget.counter(SourceKey::unknown());
        let (client, server) = tokio::io::duplex(16);
        let mut io = Io::new(
            server,
            Arc::clone(&rx),
            Timer::Manual(Arc::clone(&timer)),
            Duration::from_secs(5),
        );
        let mut client = client;
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0_u8; 5];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(rx.read(), 5);
        // Fill the 16-byte pipe; the next write stalls until the deadline.
        io.write_all(&[0; 16]).await.unwrap();
        let write = io.write_all(&[1; 4]);
        let advance = async {
            timer.until_sleepers(1).await;
            timer.advance(Duration::from_secs(5));
        };
        let (r, ()) = tokio::join!(write, advance);
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
