//! Error taxonomy and safe error reporting for DPG.
//!
//! See `docs/engineering/ERROR_TAXONOMY.md` for taxonomy documentation and
//! fail-closed semantics for each error code.

use std::fmt;

/// All standard error codes in DPG.
///
/// Every error code formats as `DPG-XNNN` where `X` is the category prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    // Configuration (C)
    /// DPG-C001: Invalid TOML.
    C001,
    /// DPG-C002: Project config tried to loosen policy (warning/ignored).
    C002,
    /// DPG-C003: Proxy bind address not loopback.
    C003,

    // Detection (D)
    /// DPG-D001: Built-in rule failed to compile.
    D001,
    /// DPG-D002: Input exceeds size limit.
    D002,

    // Policy (P)
    /// DPG-P001: Ignore list unreadable.
    P001,

    // MappingStore (M)
    /// DPG-M001: Cannot open / decrypt store.
    M001,
    /// DPG-M002: Busy timeout.
    M002,

    // Keychain (K)
    /// DPG-K001: Key unavailable.
    K001,

    // Restoration (R)
    /// DPG-R001: Placeholders present but store unavailable.
    R001,

    // PathValidation (V)
    /// DPG-V001: Outside project root.
    V001,
    /// DPG-V002: `.git` target path.
    V002,
    /// DPG-V003: Symlink escape attempt.
    V003,
    /// DPG-V004: Invalid path.
    V004,

    // Proxy (X)
    /// DPG-X001: Auth token missing or invalid.
    X001,
    /// DPG-X002: Host or Origin rejected.
    X002,
    /// DPG-X003: Body too large.
    X003,
    /// DPG-X004: Unparseable request on protected route.
    X004,

    // Provider (U)
    /// DPG-U001: Upstream connect or TLS failure.
    U001,
    /// DPG-U002: Upstream returned error.
    U002,

    // Integration (I)
    /// DPG-I001: Hook stdin is not valid JSON.
    I001,
    /// DPG-I002: Unknown tool output shape for masking.
    I002,

    // Timeout (T)
    /// DPG-T001: Internal deadline exceeded.
    T001,

    // Internal (Z)
    /// DPG-Z001: Panic caught.
    Z001,
}

impl ErrorCode {
    /// Returns the canonical string representation of the error code, e.g. `"DPG-C001"`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::C001 => "DPG-C001",
            Self::C002 => "DPG-C002",
            Self::C003 => "DPG-C003",
            Self::D001 => "DPG-D001",
            Self::D002 => "DPG-D002",
            Self::P001 => "DPG-P001",
            Self::M001 => "DPG-M001",
            Self::M002 => "DPG-M002",
            Self::K001 => "DPG-K001",
            Self::R001 => "DPG-R001",
            Self::V001 => "DPG-V001",
            Self::V002 => "DPG-V002",
            Self::V003 => "DPG-V003",
            Self::V004 => "DPG-V004",
            Self::X001 => "DPG-X001",
            Self::X002 => "DPG-X002",
            Self::X003 => "DPG-X003",
            Self::X004 => "DPG-X004",
            Self::U001 => "DPG-U001",
            Self::U002 => "DPG-U002",
            Self::I001 => "DPG-I001",
            Self::I002 => "DPG-I002",
            Self::T001 => "DPG-T001",
            Self::Z001 => "DPG-Z001",
        }
    }

    /// Returns the category name for this error code.
    pub const fn category(&self) -> &'static str {
        match self {
            Self::C001 | Self::C002 | Self::C003 => "Configuration",
            Self::D001 | Self::D002 => "Detection",
            Self::P001 => "Policy",
            Self::M001 | Self::M002 => "MappingStore",
            Self::K001 => "Keychain",
            Self::R001 => "Restoration",
            Self::V001 | Self::V002 | Self::V003 | Self::V004 => "PathValidation",
            Self::X001 | Self::X002 | Self::X003 | Self::X004 => "Proxy",
            Self::U001 | Self::U002 => "Provider",
            Self::I001 | Self::I002 => "Integration",
            Self::T001 => "Timeout",
            Self::Z001 => "Internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A non-sensitive detail string associated with an error.
///
/// `SafeDetail` is strictly constructible only from static strings or vetted builders
/// (such as rule IDs, item counts, or configuration keys). It never holds secret values,
/// payload contents, plaintext paths, or HTTP headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeDetail {
    /// A static compile-time string.
    Static(&'static str),
    /// A vetted rule identifier.
    RuleId(String),
    /// An integer count.
    Count(usize),
    /// A configuration key name.
    ConfigKey(String),
    /// An empty detail.
    None,
}

impl SafeDetail {
    /// Constructs a safe detail from a static string.
    pub const fn from_static(msg: &'static str) -> Self {
        Self::Static(msg)
    }

    /// Constructs a safe detail from a validated rule ID.
    pub fn from_rule_id(rule_id: impl Into<String>) -> Self {
        Self::RuleId(rule_id.into())
    }

    /// Constructs a safe detail from an integer count.
    pub const fn from_count(count: usize) -> Self {
        Self::Count(count)
    }

    /// Constructs a safe detail from a configuration key name.
    pub fn from_config_key(key: impl Into<String>) -> Self {
        Self::ConfigKey(key.into())
    }

    /// Constructs an empty safe detail.
    pub const fn none() -> Self {
        Self::None
    }
}

impl From<&'static str> for SafeDetail {
    fn from(s: &'static str) -> Self {
        Self::Static(s)
    }
}

impl fmt::Display for SafeDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(s) => f.write_str(s),
            Self::RuleId(id) => write!(f, "rule_id: {id}"),
            Self::Count(c) => write!(f, "count: {c}"),
            Self::ConfigKey(k) => write!(f, "config_key: {k}"),
            Self::None => Ok(()),
        }
    }
}

/// Unified error enum for DPG operations.
///
/// Defined per `docs/engineering/ERROR_TAXONOMY.md`.
#[derive(Debug, thiserror::Error)]
pub enum DpgError {
    /// Configuration error variant.
    #[error("configuration error [{code}]")]
    Configuration {
        /// Associated error code.
        code: ErrorCode,
        /// Non-sensitive detail.
        detail: SafeDetail,
    },

    /// Detection error variant.
    #[error("detection error [{code}]")]
    Detection {
        /// Associated error code.
        code: ErrorCode,
        /// Non-sensitive detail.
        detail: SafeDetail,
    },

    /// Policy evaluation error variant.
    #[error("policy error [{code}]")]
    Policy {
        /// Associated error code.
        code: ErrorCode,
        /// Non-sensitive detail.
        detail: SafeDetail,
    },

    /// Mapping store persistence or decryption error variant.
    #[error("mapping store error [{code}]")]
    MappingStore {
        /// Associated error code.
        code: ErrorCode,
        /// Non-sensitive detail.
        detail: SafeDetail,
    },

    /// Keychain access error variant.
    #[error("keychain error [{code}]")]
    Keychain {
        /// Associated error code.
        code: ErrorCode,
        /// Non-sensitive detail.
        detail: SafeDetail,
    },

    /// Restoration error variant.
    #[error("restoration error [{code}]")]
    Restoration {
        /// Associated error code.
        code: ErrorCode,
        /// Non-sensitive detail.
        detail: SafeDetail,
    },

    /// Path validation boundary check error variant.
    #[error("path validation error [{code}]")]
    PathValidation {
        /// Associated error code.
        code: ErrorCode,
        /// Non-sensitive detail.
        detail: SafeDetail,
    },

    /// Local proxy handling error variant.
    #[error("proxy error [{code}]")]
    Proxy {
        /// Associated error code.
        code: ErrorCode,
        /// Non-sensitive detail.
        detail: SafeDetail,
    },

    /// Upstream AI provider error variant.
    #[error("provider error [{code}]")]
    Provider {
        /// Associated error code.
        code: ErrorCode,
        /// Upstream HTTP status code, if received.
        status: Option<u16>,
    },

    /// Agent integration protocol error variant.
    #[error("integration error [{code}]")]
    Integration {
        /// Associated error code.
        code: ErrorCode,
        /// Non-sensitive detail.
        detail: SafeDetail,
    },

    /// Execution deadline overrun error variant.
    #[error("timeout [{code}]")]
    Timeout {
        /// Associated error code.
        code: ErrorCode,
    },

    /// Internal panic or invariant failure error variant.
    #[error("internal error [{code}]")]
    Internal {
        /// Associated error code.
        code: ErrorCode,
    },
}

impl DpgError {
    /// Returns the error code for this error.
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Configuration { code, .. }
            | Self::Detection { code, .. }
            | Self::Policy { code, .. }
            | Self::MappingStore { code, .. }
            | Self::Keychain { code, .. }
            | Self::Restoration { code, .. }
            | Self::PathValidation { code, .. }
            | Self::Proxy { code, .. }
            | Self::Provider { code, .. }
            | Self::Integration { code, .. }
            | Self::Timeout { code }
            | Self::Internal { code } => *code,
        }
    }

    /// Returns a reference to the safe detail if present on this error variant.
    pub fn safe_detail(&self) -> Option<&SafeDetail> {
        match self {
            Self::Configuration { detail, .. }
            | Self::Detection { detail, .. }
            | Self::Policy { detail, .. }
            | Self::MappingStore { detail, .. }
            | Self::Keychain { detail, .. }
            | Self::Restoration { detail, .. }
            | Self::PathValidation { detail, .. }
            | Self::Proxy { detail, .. }
            | Self::Integration { detail, .. } => Some(detail),
            Self::Provider { .. } | Self::Timeout { .. } | Self::Internal { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CODES: &[ErrorCode] = &[
        ErrorCode::C001,
        ErrorCode::C002,
        ErrorCode::C003,
        ErrorCode::D001,
        ErrorCode::D002,
        ErrorCode::P001,
        ErrorCode::M001,
        ErrorCode::M002,
        ErrorCode::K001,
        ErrorCode::R001,
        ErrorCode::V001,
        ErrorCode::V002,
        ErrorCode::V003,
        ErrorCode::V004,
        ErrorCode::X001,
        ErrorCode::X002,
        ErrorCode::X003,
        ErrorCode::X004,
        ErrorCode::U001,
        ErrorCode::U002,
        ErrorCode::I001,
        ErrorCode::I002,
        ErrorCode::T001,
        ErrorCode::Z001,
    ];

    #[test]
    fn test_all_codes_format_as_dpg_prefix() {
        assert_eq!(ALL_CODES.len(), 24);
        for code in ALL_CODES {
            let s = code.to_string();
            assert!(s.starts_with("DPG-"), "Code {s} should start with 'DPG-'");
            assert_eq!(s.len(), 8, "Code {s} should be 8 characters long");
            assert_eq!(code.as_str(), s.as_str());
        }
    }

    #[test]
    fn test_safe_detail_formatting() {
        assert_eq!(SafeDetail::from_static("sample").to_string(), "sample");
        assert_eq!(
            SafeDetail::from_rule_id("aws_secret_key").to_string(),
            "rule_id: aws_secret_key"
        );
        assert_eq!(SafeDetail::from_count(42).to_string(), "count: 42");
        assert_eq!(
            SafeDetail::from_config_key("proxy.port").to_string(),
            "config_key: proxy.port"
        );
        assert_eq!(SafeDetail::none().to_string(), "");
    }

    #[test]
    fn test_dpg_error_display_never_includes_uninspected_content() {
        let err = DpgError::Configuration {
            code: ErrorCode::C001,
            detail: SafeDetail::from_static("syntax error"),
        };
        let msg = err.to_string();
        assert_eq!(msg, "configuration error [DPG-C001]");
        assert_eq!(err.code(), ErrorCode::C001);
        assert_eq!(
            err.safe_detail(),
            Some(&SafeDetail::from_static("syntax error"))
        );

        let timeout = DpgError::Timeout {
            code: ErrorCode::T001,
        };
        assert_eq!(timeout.to_string(), "timeout [DPG-T001]");
        assert_eq!(timeout.code(), ErrorCode::T001);
        assert_eq!(timeout.safe_detail(), None);
    }
}
