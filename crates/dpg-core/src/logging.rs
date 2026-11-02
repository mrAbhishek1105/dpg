//! Tracing initialization for stderr logging.
//!
//! Enforces metadata-only logging per `docs/security/DATA_HANDLING.md`.

use std::sync::atomic::{AtomicBool, Ordering};
use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use crate::error::{DpgError, ErrorCode, SafeDetail};

static LOGGING_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes global tracing output to stderr according to the requested log level string.
///
/// Can be safely invoked multiple times; subsequent calls after the first are no-ops.
pub fn init_logging(level_str: &str) -> Result<(), DpgError> {
    if LOGGING_INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }

    let level = match level_str.trim().to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let filter = EnvFilter::default()
        .add_directive(level.into())
        .add_directive("dpg=trace".parse().map_err(|_| DpgError::Configuration {
            code: ErrorCode::C001,
            detail: SafeDetail::from_static("Invalid log filter directive"),
        })?);

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_span_events(FmtSpan::NONE)
        .with_ansi(false)
        .finish();

    if tracing::subscriber::set_global_default(subscriber).is_ok() {
        LOGGING_INITIALIZED.store(true, Ordering::Release);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logging_idempotent() {
        assert!(init_logging("info").is_ok());
        assert!(init_logging("debug").is_ok());
    }
}
