//! Injectable time source.
//!
//! Protocol code must never call [`SystemTime::now`] directly: it takes a
//! [`Clock`] so tests can control time with [`FakeClock`] instead of sleeping.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A source of wall-clock time.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> SystemTime;

    /// Milliseconds since the Unix epoch (saturating at `u64::MAX`; times
    /// before the epoch read as 0).
    fn unix_millis(&self) -> u64 {
        let since_epoch = self.now().duration_since(UNIX_EPOCH).unwrap_or_default();
        u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX)
    }
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn now(&self) -> SystemTime {
        (**self).now()
    }
}

/// The real clock, backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A manually driven clock for tests. Time only moves through [`advance`]
/// and [`set`]; it is safe to share across threads (wrap it in an [`Arc`]).
///
/// Resolution is one nanosecond and the range is 584 years after the epoch.
///
/// [`advance`]: FakeClock::advance
/// [`set`]: FakeClock::set
#[derive(Debug)]
pub struct FakeClock {
    nanos_since_epoch: AtomicU64,
}

impl FakeClock {
    /// A clock that starts at the Unix epoch plus `start`.
    ///
    /// # Panics
    ///
    /// Panics if `start` is out of the representable range.
    #[must_use]
    pub fn new(start: Duration) -> Self {
        Self {
            nanos_since_epoch: AtomicU64::new(Self::to_nanos(start)),
        }
    }

    /// Moves the clock forward by `by`.
    ///
    /// # Panics
    ///
    /// Panics if the clock would leave its representable range.
    pub fn advance(&self, by: Duration) {
        let by = Self::to_nanos(by);
        self.nanos_since_epoch
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(by))
            .expect("fake clock overflow");
    }

    /// Sets the clock to an absolute time.
    ///
    /// # Panics
    ///
    /// Panics if `to` is before the Unix epoch or out of range.
    pub fn set(&self, to: SystemTime) {
        let since_epoch = to
            .duration_since(UNIX_EPOCH)
            .expect("time before the epoch");
        self.nanos_since_epoch
            .store(Self::to_nanos(since_epoch), Ordering::SeqCst);
    }

    fn to_nanos(d: Duration) -> u64 {
        u64::try_from(d.as_nanos()).expect("duration out of range for fake clock")
    }
}

impl Default for FakeClock {
    /// Starts at 2025-01-01T00:00:00Z, a fixed, recognisable instant.
    fn default() -> Self {
        Self::new(Duration::from_hours(482_136))
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.nanos_since_epoch.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_only_moves_when_told() {
        let clock = FakeClock::new(Duration::from_secs(10));
        assert_eq!(clock.now(), UNIX_EPOCH + Duration::from_secs(10));
        assert_eq!(clock.now(), clock.now());
        clock.advance(Duration::from_millis(1500));
        assert_eq!(clock.unix_millis(), 11_500);
    }

    #[test]
    fn fake_clock_set_can_move_backwards() {
        let clock = FakeClock::default();
        clock.set(UNIX_EPOCH + Duration::from_secs(5));
        assert_eq!(clock.unix_millis(), 5_000);
    }

    #[test]
    fn default_fake_clock_is_2025() {
        assert_eq!(FakeClock::default().unix_millis(), 1_735_689_600_000);
    }

    #[test]
    fn fake_clock_is_shared_through_arc_and_dyn() {
        let fake = Arc::new(FakeClock::default());
        let dynamic: Arc<dyn Clock> = fake.clone();
        let before = dynamic.unix_millis();
        fake.advance(Duration::from_secs(2));
        assert_eq!(dynamic.unix_millis(), before + 2_000);
    }

    #[test]
    fn fake_clock_advances_across_threads() {
        let clock = Arc::new(FakeClock::new(Duration::ZERO));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let clock = Arc::clone(&clock);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        clock.advance(Duration::from_millis(1));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(clock.unix_millis(), 800);
    }

    #[test]
    fn pre_epoch_time_reads_as_zero_millis() {
        struct Before;
        impl Clock for Before {
            fn now(&self) -> SystemTime {
                UNIX_EPOCH - Duration::from_secs(1)
            }
        }
        assert_eq!(Before.unix_millis(), 0);
    }

    #[test]
    #[should_panic(expected = "fake clock overflow")]
    fn advance_past_range_panics() {
        let clock = FakeClock::new(Duration::ZERO);
        clock.advance(Duration::from_nanos(u64::MAX));
        clock.advance(Duration::from_nanos(1));
    }

    #[test]
    #[should_panic(expected = "time before the epoch")]
    fn set_before_epoch_panics() {
        FakeClock::default().set(UNIX_EPOCH - Duration::from_secs(1));
    }

    #[test]
    fn system_clock_is_after_2025() {
        assert!(SystemClock.unix_millis() > 1_735_689_600_000);
    }
}
