//! Log setup. `RUST_LOG` selects what the directory's own code logs; every
//! other crate is held at `warn` and above (the MCP library at `error`)
//! whatever it says.
//!
//! At `trace`, `axum::serve` logs client addresses, and the HTTP and MCP
//! libraries can log request details. The directory logs no addresses and
//! no request data (SPEC §13.2), so their debug and trace output never gets
//! through.

use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{FilterExt as _, filter_fn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::{Layer as _, fmt};

/// Targets whose debug and trace output may be shown. Everything they log
/// follows the directory's logging rules.
const OWN_TARGETS: [&str; 2] = ["agentconnect_directory", "agentconnect_core"];

/// The MCP library's warnings quote request headers, so it gets errors only.
const ERRORS_ONLY: [&str; 1] = ["rmcp"];

fn within(target: &str, prefix: &str) -> bool {
    target
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
}

/// True if `meta` may be logged at its level whatever `RUST_LOG` says: the
/// directory's own events, the MCP library's errors, and anyone else's
/// warnings and errors.
#[must_use]
pub fn allowed(meta: &Metadata<'_>) -> bool {
    let target = meta.target();
    if OWN_TARGETS.iter().any(|own| within(target, own)) {
        return true;
    }
    let ceiling = if ERRORS_ONLY.iter().any(|t| within(target, t)) {
        Level::ERROR
    } else {
        Level::WARN
    };
    *meta.level() <= ceiling
}

/// The directory's subscriber: `rust_log` (the `RUST_LOG` syntax, `info`
/// when unset, empty or invalid) narrowed by [`allowed`], written to
/// `writer`.
pub fn subscriber<W>(rust_log: Option<&str>, writer: W) -> impl Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let env = rust_log
        .filter(|s| !s.trim().is_empty())
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
    fn third_party_output_is_clamped_whatever_rust_log_says() {
        for rust_log in [
            Some("trace"),
            Some("axum=trace,hyper=trace,rmcp=trace,sqlx=trace"),
            Some("off,axum::serve=trace"),
        ] {
            let logs = logs_with(rust_log, || {
                tracing::trace!(target: "axum::serve", "client-address");
                tracing::debug!(target: "hyper::proto", "request-contents");
                tracing::debug!(target: "sqlx::query", "statement");
                tracing::warn!(target: "rmcp::transport", "quoted-header");
                tracing::trace!(target: "agentconnect_directoryx", "lookalike");
                tracing::warn!(target: "hyper::proto", "a warning");
                tracing::error!(target: "rmcp::transport", "an mcp error");
            });
            for leak in [
                "client-address",
                "request-contents",
                "statement",
                "quoted-header",
                "lookalike",
            ] {
                assert!(!logs.contains(leak), "{rust_log:?}: {leak} in {logs}");
            }
            if rust_log == Some("trace") {
                assert!(
                    logs.contains("a warning") && logs.contains("an mcp error"),
                    "{logs}"
                );
            }
        }
    }

    #[test]
    fn rust_log_still_selects_the_own_crates_output() {
        let emit = || {
            tracing::trace!(target: "agentconnect_directory::http", "own-trace");
            tracing::info!(target: "agentconnect_directory", "own-info");
            tracing::debug!(target: "agentconnect_core::listing", "core-debug");
        };
        let all = logs_with(Some("trace"), emit);
        assert!(
            all.contains("own-trace") && all.contains("own-info") && all.contains("core-debug")
        );
        for quiet in [None, Some(""), Some("=[not a filter")] {
            let logs = logs_with(quiet, emit);
            assert!(logs.contains("own-info"), "{quiet:?}");
            assert!(
                !logs.contains("own-trace") && !logs.contains("core-debug"),
                "{quiet:?}"
            );
        }
    }
}
