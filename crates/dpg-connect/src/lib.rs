//! Agent hook adapters, local loopback proxy, SSE restorer, installer, and doctor diagnostics for DPG.
//!
//! This crate owns:
//! - Claude Code hook protocol integration (stdin/stdout JSON payloads and exit codes).
//! - Local loopback proxy server (HTTP/SSE pass-through to provider APIs).
//! - Server-Sent Events (SSE) streaming placeholder restorer.
//! - Automated hook and proxy installation in agent settings.
//! - System diagnostic checks (`dpg doctor`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

/// Returns the version of the `dpg-connect` crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_connect() {
        assert_eq!(version(), "0.0.1");
    }
}
