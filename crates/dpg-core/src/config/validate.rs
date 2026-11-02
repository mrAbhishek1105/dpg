//! Configuration validation for DPG.

use std::net::IpAddr;

use crate::config::model::Config;
use crate::error::{DpgError, ErrorCode, SafeDetail};

/// Validates a merged configuration.
///
/// Enforces:
/// - Proxy bind address must be loopback (PX-1, ErrorCode::C003).
/// - Non-zero timeouts and valid ranges.
pub fn validate_config(config: &Config) -> Result<(), DpgError> {
    validate_proxy_bind_address(&config.proxy.bind_address)?;
    validate_timeouts(config)?;
    Ok(())
}

fn validate_proxy_bind_address(addr_str: &str) -> Result<(), DpgError> {
    if addr_str.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }

    match addr_str.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => Ok(()),
        _ => Err(DpgError::Configuration {
            code: ErrorCode::C003,
            detail: SafeDetail::from_static("Proxy bind address must be a loopback address"),
        }),
    }
}

fn validate_timeouts(config: &Config) -> Result<(), DpgError> {
    if config.hook.timeout_seconds == 0 {
        return Err(DpgError::Configuration {
            code: ErrorCode::C001,
            detail: SafeDetail::from_static("Hook timeout must be greater than zero"),
        });
    }

    if config.hook.internal_deadline_ratio <= 0.0 || config.hook.internal_deadline_ratio >= 1.0 {
        return Err(DpgError::Configuration {
            code: ErrorCode::C001,
            detail: SafeDetail::from_static(
                "Hook internal deadline ratio must be strictly between 0.0 and 1.0",
            ),
        });
    }

    if config.proxy.max_body_bytes == 0 {
        return Err(DpgError::Configuration {
            code: ErrorCode::C001,
            detail: SafeDetail::from_static("Proxy max_body_bytes must be greater than zero"),
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_default_config() {
        let config = Config::default();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_non_loopback_proxy_address_rejected() {
        let mut config = Config::default();
        config.proxy.bind_address = "0.0.0.0".to_string();
        let res = validate_config(&config);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.code(), ErrorCode::C003);

        config.proxy.bind_address = "192.168.1.100".to_string();
        let err2 = validate_config(&config).unwrap_err();
        assert_eq!(err2.code(), ErrorCode::C003);
    }

    #[test]
    fn test_loopback_proxy_addresses_accepted() {
        let mut config = Config::default();

        config.proxy.bind_address = "127.0.0.1".to_string();
        assert!(validate_config(&config).is_ok());

        config.proxy.bind_address = "127.0.0.2".to_string();
        assert!(validate_config(&config).is_ok());

        config.proxy.bind_address = "::1".to_string();
        assert!(validate_config(&config).is_ok());

        config.proxy.bind_address = "localhost".to_string();
        assert!(validate_config(&config).is_ok());
    }
}
