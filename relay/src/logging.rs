//! Log setup. `RUST_LOG` selects what the relay's own code logs; every other
//! crate is held at `warn` and above whatever it says.
//!
//! At `trace`, `tungstenite` logs whole WebSocket frames (`ct` included) and
//! `axum::serve` and `hyper` log client addresses. The relay logs neither
//! (SPEC §8.3, "Logging"), so their debug and trace output never gets
//! through.

use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{FilterExt as _, filter_fn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::{Layer as _, fmt};

/// Targets whose debug and trace output may be shown. Everything they log
/// follows the relay's logging rules.
const OWN_TARGETS: [&str; 2] = ["agentconnect_relay", "agentconnect_core"];

/// True if `meta` may be logged at its level whatever `RUST_LOG` says: the
/// relay's own events, and anyone's warnings and errors.
#[must_use]
pub fn allowed(meta: &Metadata<'_>) -> bool {
    *meta.level() <= Level::WARN
        || OWN_TARGETS.iter().any(|own| {
            meta.target()
                .strip_prefix(own)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
        })
}

/// The relay's subscriber: `rust_log` (the `RUST_LOG` syntax, `info` when
/// unset or invalid) narrowed by [`allowed`], written to `writer`.
pub fn subscriber<W>(rust_log: Option<&str>, writer: W) -> impl Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let env = rust_log
        .and_then(|s| EnvFilter::builder().parse(s).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let layer = fmt::layer()
        .with_writer(writer)
        .with_filter(env.and(filter_fn(allowed)));
    tracing_subscriber::registry().with(layer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn logs_with(rust_log: Option<&str>, emit: impl FnOnce()) -> String {
        let captured = Captured::default();
        let writer = captured.clone();
        let sub = subscriber(rust_log, move || writer.clone());
        tracing::subscriber::with_default(sub, emit);
        String::from_utf8(captured.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn third_party_debug_and_trace_never_get_through() {
        for rust_log in [
            Some("trace"),
            Some("tungstenite=trace,axum=trace,hyper=trace"),
            Some("off,tungstenite::protocol=trace"),
        ] {
            let logs = logs_with(rust_log, || {
                tracing::trace!(target: "tungstenite::protocol", "frame-contents");
                tracing::debug!(target: "axum::serve", "client-address");
                tracing::trace!(target: "hyper::proto", "client-address");
                tracing::debug!(target: "hyper_util::server", "client-address");
                tracing::trace!(target: "agentconnect_relayx", "lookalike");
                tracing::warn!(target: "tungstenite::protocol", "a warning");
            });
            assert!(!logs.contains("frame-contents"), "{rust_log:?}: {logs}");
            assert!(!logs.contains("client-address"), "{rust_log:?}: {logs}");
            assert!(!logs.contains("lookalike"), "{rust_log:?}: {logs}");
            if rust_log == Some("trace") {
                assert!(logs.contains("a warning"), "{logs}");
            }
        }
    }

    #[test]
    fn rust_log_still_selects_the_relays_own_output() {
        let emit = || {
            tracing::trace!(target: "agentconnect_relay::ws", "own-trace");
            tracing::info!(target: "agentconnect_relay", "own-info");
            tracing::debug!(target: "agentconnect_core::group", "core-debug");
        };
        let all = logs_with(Some("trace"), emit);
        assert!(
            all.contains("own-trace") && all.contains("own-info") && all.contains("core-debug")
        );
        let default = logs_with(None, emit);
        assert!(default.contains("own-info"));
        assert!(!default.contains("own-trace") && !default.contains("core-debug"));
        let invalid = logs_with(Some("=[not a filter"), emit);
        assert!(invalid.contains("own-info") && !invalid.contains("own-trace"));
    }
}
