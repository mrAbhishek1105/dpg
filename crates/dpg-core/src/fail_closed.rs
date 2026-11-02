//! Fail-closed execution wrappers and panic hooks.
//!
//! Enforces security requirements FC-1 and FC-2 (no code path forwards or reveals
//! uninspected content after an inspection failure or panic).

use std::panic::{catch_unwind, set_hook, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{DpgError, ErrorCode};

static PANIC_HOOK_SET: AtomicBool = AtomicBool::new(false);

/// Installs a security panic hook that prints location and error code DPG-Z001,
/// strictly suppressing any payload message content to avoid leaking sensitive data.
pub fn set_fail_closed_panic_hook() {
    if PANIC_HOOK_SET.swap(true, Ordering::SeqCst) {
        return;
    }

    set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());

        // Strictly print code DPG-Z001 and source location; NEVER print payload value
        eprintln!("[DPG] Internal panic caught [DPG-Z001] at {location}");
    }));
}

/// Executes a closure inside a `catch_unwind` safety boundary.
///
/// Any panic is intercepted and converted to `DpgError::Internal { code: ErrorCode::Z001 }`.
pub fn fail_closed_wrap<F, T>(f: F) -> Result<T, DpgError>
where
    F: FnOnce() -> Result<T, DpgError>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(res) => res,
        Err(_) => Err(DpgError::Internal {
            code: ErrorCode::Z001,
        }),
    }
}

/// Trait implemented by entry point adapters to provide fail-closed fallback responses.
pub trait FailClosed {
    /// The fail-safe output type (e.g. CLI exit code, JSON response, HTTP status).
    type Output;

    /// Produces the guaranteed fail-closed response for any error or caught panic.
    fn fail_closed(&self, error: &DpgError) -> Self::Output;
}

/// Executes an operation under fail-closed protection, returning the handler's
/// fallback output if an error or panic occurs.
pub fn run_fail_closed<H, F>(handler: &H, action: F) -> H::Output
where
    H: FailClosed,
    F: FnOnce() -> Result<H::Output, DpgError>,
{
    match fail_closed_wrap(action) {
        Ok(output) => output,
        Err(err) => handler.fail_closed(&err),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    struct TestHandler;

    impl FailClosed for TestHandler {
        type Output = String;

        fn fail_closed(&self, error: &DpgError) -> Self::Output {
            format!("[DPG] Output withheld: [{}]", error.code())
        }
    }

    #[test]
    fn test_fail_closed_wrap_converts_panic_to_z001() {
        let res = fail_closed_wrap(|| {
            if true {
                panic!("sensitive_secret_token_in_panic_payload");
            }
            Ok("success")
        });

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Z001);

        // Verify the panic payload string was discarded
        let err_str = err.to_string();
        assert!(!err_str.contains("sensitive_secret_token"));
    }

    #[test]
    fn test_run_fail_closed_handles_errors_and_panics() {
        let handler = TestHandler;

        // Normal success
        let ok_out = run_fail_closed(&handler, || Ok("healthy result".to_string()));
        assert_eq!(ok_out, "healthy result");

        // Engine error
        let err_out = run_fail_closed(&handler, || {
            Err(DpgError::Timeout {
                code: ErrorCode::T001,
            })
        });
        assert_eq!(err_out, "[DPG] Output withheld: [DPG-T001]");

        // Panic caught
        let panic_out = run_fail_closed(&handler, || {
            panic!("crash with secret value");
        });
        assert_eq!(panic_out, "[DPG] Output withheld: [DPG-Z001]");
    }
}
