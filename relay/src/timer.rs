//! Connection deadlines: tokio's clock in production, a manual clock in
//! tests.
//!
//! Every timeout on a connection (header read, authentication, idle, ping,
//! stalled send, frame pacing) reads and sleeps through a [`Timer`], so the
//! fast test tier can move time with [`ManualTimer::advance`] instead of
//! waiting for it. Message TTLs and rate windows use the relay's
//! [`Clock`](agentconnect_core::clock::Clock) instead.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// The time source for connection deadlines.
#[derive(Debug, Clone, Default)]
pub enum Timer {
    /// tokio's timers (production).
    #[default]
    Tokio,
    /// A clock that moves only through [`ManualTimer::advance`] (tests).
    Manual(Arc<ManualTimer>),
}

impl Timer {
    /// The current instant.
    #[must_use]
    pub fn now(&self) -> Instant {
        match self {
            Timer::Tokio => tokio::time::Instant::now().into_std(),
            Timer::Manual(m) => m.now(),
        }
    }

    /// Wait until `deadline`.
    pub async fn sleep_until(&self, deadline: Instant) {
        match self {
            Timer::Tokio => {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            }
            Timer::Manual(m) => ManualSleep::new(m, deadline).await,
        }
    }

    /// Run `fut` for at most `limit`; `None` if the time ran out first.
    pub async fn timeout<F: Future>(&self, limit: Duration, fut: F) -> Option<F::Output> {
        let deadline = self.now() + limit;
        tokio::select! {
            biased;
            out = fut => Some(out),
            () = self.sleep_until(deadline) => None,
        }
    }
}

impl hyper::rt::Timer for Timer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        hyper::rt::Timer::sleep_until(self, self.now() + duration)
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        match self {
            Timer::Tokio => hyper_util::rt::TokioTimer::new().sleep_until(deadline),
            Timer::Manual(m) => Box::pin(ManualSleep::new(m, deadline)),
        }
    }

    fn now(&self) -> Instant {
        Timer::now(self)
    }
}

#[derive(Debug, Default)]
struct State {
    elapsed: Duration,
    next_id: u64,
    /// Sleeps that are waiting: id -> (deadline, waker).
    sleepers: HashMap<u64, (Instant, Waker)>,
}

/// A clock for tests: it starts at the instant it is created and moves only
/// when [`ManualTimer::advance`] is called.
#[derive(Debug)]
pub struct ManualTimer {
    base: Instant,
    state: Mutex<State>,
    /// Pulsed whenever a sleep starts waiting.
    changed: Notify,
}

impl ManualTimer {
    /// A new manual clock.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            state: Mutex::default(),
            changed: Notify::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The current instant.
    #[must_use]
    pub fn now(&self) -> Instant {
        self.base + self.lock().elapsed
    }

    /// Move time forward and wake every sleep whose deadline has come.
    pub fn advance(&self, by: Duration) {
        let mut s = self.lock();
        s.elapsed += by;
        let now = self.base + s.elapsed;
        let due: Vec<u64> = s
            .sleepers
            .iter()
            .filter(|(_, (at, _))| *at <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            if let Some((_, waker)) = s.sleepers.remove(&id) {
                waker.wake();
            }
        }
    }

    /// Sleeps waiting now (not yet due, not dropped).
    #[must_use]
    pub fn sleepers(&self) -> usize {
        self.lock().sleepers.len()
    }

    /// Wait until at least `n` sleeps are waiting, so a test advances time
    /// only once the code under test is blocked on its deadline.
    pub async fn until_sleepers(&self, n: usize) {
        loop {
            let changed = self.changed.notified();
            if self.sleepers() >= n {
                return;
            }
            changed.await;
        }
    }
}

struct ManualSleep {
    timer: Arc<ManualTimer>,
    deadline: Instant,
    id: Option<u64>,
}

impl ManualSleep {
    fn new(timer: &Arc<ManualTimer>, deadline: Instant) -> Self {
        Self {
            timer: Arc::clone(timer),
            deadline,
            id: None,
        }
    }
}

impl hyper::rt::Sleep for ManualSleep {}

impl Future for ManualSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let mut s = this.timer.lock();
        if this.timer.base + s.elapsed >= this.deadline {
            if let Some(id) = this.id.take() {
                s.sleepers.remove(&id);
            }
            return Poll::Ready(());
        }
        let id = *this.id.get_or_insert_with(|| {
            s.next_id += 1;
            s.next_id
        });
        let new = s
            .sleepers
            .insert(id, (this.deadline, cx.waker().clone()))
            .is_none();
        drop(s);
        if new {
            this.timer.changed.notify_waiters();
        }
        Poll::Pending
    }
}

impl Drop for ManualSleep {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.timer.lock().sleepers.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll_once<F: Future + Unpin>(f: &mut F) -> Poll<F::Output> {
        let waker = Waker::noop();
        Pin::new(f).poll(&mut Context::from_waker(waker))
    }

    #[test]
    fn a_manual_sleep_waits_for_advance() {
        let m = ManualTimer::new();
        let start = m.now();
        let timer = Timer::Manual(Arc::clone(&m));
        let mut sleep = Box::pin(timer.sleep_until(start + Duration::from_secs(5)));
        assert!(poll_once(&mut sleep).is_pending());
        assert_eq!(m.sleepers(), 1);
        m.advance(Duration::from_secs(4));
        assert!(poll_once(&mut sleep).is_pending());
        m.advance(Duration::from_secs(1));
        assert!(poll_once(&mut sleep).is_ready());
        assert_eq!(m.sleepers(), 0);
        assert_eq!(m.now() - start, Duration::from_secs(5));
    }

    #[test]
    fn a_dropped_sleep_stops_waiting() {
        let m = ManualTimer::new();
        let mut sleep = Box::pin(ManualSleep::new(&m, m.now() + Duration::from_secs(1)));
        assert!(poll_once(&mut sleep).is_pending());
        assert_eq!(m.sleepers(), 1);
        drop(sleep);
        assert_eq!(m.sleepers(), 0);
    }

    #[test]
    fn a_past_deadline_is_ready_at_once() {
        let m = ManualTimer::new();
        let mut sleep = Box::pin(ManualSleep::new(&m, m.now()));
        assert!(poll_once(&mut sleep).is_ready());
        assert_eq!(m.sleepers(), 0);
    }

    #[tokio::test]
    async fn timeout_gives_up_only_when_time_moves() {
        let m = ManualTimer::new();
        let t = Timer::Manual(Arc::clone(&m));
        assert_eq!(
            t.timeout(Duration::from_secs(1), async { 7 }).await,
            Some(7)
        );
        let pending = t.timeout(Duration::from_secs(1), std::future::pending::<()>());
        let advance = async {
            m.until_sleepers(1).await;
            m.advance(Duration::from_secs(1));
        };
        let (out, ()) = tokio::join!(pending, advance);
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn the_tokio_timer_reads_tokio_time() {
        let t = Timer::Tokio;
        let a = t.now();
        t.sleep_until(a).await;
        assert!(t.now() >= a);
        let h: &dyn hyper::rt::Timer = &t;
        h.sleep(Duration::ZERO).await;
        assert!(h.now() >= a);
    }
}
