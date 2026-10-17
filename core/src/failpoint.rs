//! Test-only fault injection at the step boundaries of processing.
//!
//! Every [`crate::Client`] has a [`Failpoints`] set. It is empty unless a
//! test arms a point, and an empty set costs one relaxed atomic load per
//! point, so the points are inert in production. An armed point either
//! fails the operation with a storage error (which the daemon treats as
//! transient) or panics, both inside the operation's transaction, so the
//! store rolls back exactly as it would after a crash at that point.
//!
//! The point names are listed in [`POINTS`] and in TESTING.md.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Error, Result};

/// Every failpoint in `core`, in processing order.
pub const POINTS: &[&str] = &[
    // Group::process (application messages, proposals, commits, own
    // commits arriving in the fan-out).
    "process.before_mls",
    "process.after_mls",
    "process.after_merge",
    "process.before_commit",
    // Group::confirm_pending_commit (the relay's `accepted`).
    "confirm.after_merge",
    "confirm.before_commit",
    // Client::join_from_wrapped_welcome.
    "join.after_stage",
    "join.before_commit",
    // Client::journal_consume.
    "consume.before_commit",
];

/// What an armed failpoint does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Fail with `Error::Storage("failpoint <name>")`.
    Error,
    /// Panic.
    Panic,
}

/// A client's armed failpoints.
#[derive(Debug, Default)]
pub struct Failpoints {
    armed: AtomicBool,
    points: Mutex<HashMap<String, (Action, u32)>>,
}

impl Failpoints {
    /// Arms `name` to fire `times` times. **Tests only.**
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a name not in [`POINTS`].
    pub fn arm(&self, name: &str, action: Action, times: u32) -> Result<()> {
        if !POINTS.contains(&name) {
            return Err(Error::Malformed("failpoint name"));
        }
        let mut points = self.lock();
        points.insert(name.to_owned(), (action, times));
        self.armed.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Disarms every point.
    pub fn clear(&self) {
        self.lock().clear();
        self.armed.store(false, Ordering::SeqCst);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Action, u32)>> {
        self.points
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Fires `name` if it is armed.
    pub(crate) fn hit(&self, name: &'static str) -> Result<()> {
        if !self.armed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let action = {
            let mut points = self.lock();
            let Some((action, left)) = points.get_mut(name) else {
                return Ok(());
            };
            let action = *action;
            *left -= 1;
            if *left == 0 {
                points.remove(name);
            }
            if points.is_empty() {
                self.armed.store(false, Ordering::SeqCst);
            }
            action
        };
        match action {
            Action::Error => Err(Error::Storage(format!("failpoint {name}"))),
            Action::Panic => panic!("failpoint {name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn points_fire_as_often_as_armed() {
        let f = Failpoints::default();
        assert_eq!(f.hit("process.after_mls"), Ok(()));
        assert_eq!(
            f.arm("nope", Action::Error, 1),
            Err(Error::Malformed("failpoint name"))
        );
        f.arm("process.after_mls", Action::Error, 2).unwrap();
        assert_eq!(f.hit("process.before_mls"), Ok(()));
        for _ in 0..2 {
            assert_eq!(
                f.hit("process.after_mls"),
                Err(Error::Storage("failpoint process.after_mls".into()))
            );
        }
        assert_eq!(f.hit("process.after_mls"), Ok(()));
        f.arm("join.after_stage", Action::Panic, 1).unwrap();
        assert!(std::panic::catch_unwind(|| f.hit("join.after_stage")).is_err());
        f.arm("join.after_stage", Action::Error, 1).unwrap();
        f.clear();
        assert_eq!(f.hit("join.after_stage"), Ok(()));
    }
}
