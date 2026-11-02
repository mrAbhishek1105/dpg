//! Foundational domain types for DPG.
//!
//! Defined per `docs/components/CORE.md` §6.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{DpgError, ErrorCode, SafeDetail};

/// Byte offsets in a UTF-8 string, guaranteed to align with character boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Span {
    /// Byte index of the start of the span (inclusive).
    pub start: usize,
    /// Byte index of the end of the span (exclusive).
    pub end: usize,
}

impl Span {
    /// Creates a span without performing boundary checks.
    pub const fn new_raw(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Creates and validates a span against the given text.
    ///
    /// Verifies that `start <= end <= text.len()` and that both offsets
    /// fall on valid UTF-8 character boundaries.
    pub fn new(text: &str, start: usize, end: usize) -> Result<Self, DpgError> {
        if start > end || end > text.len() {
            return Err(DpgError::Detection {
                code: ErrorCode::D002,
                detail: SafeDetail::from_static("Span offset out of text bounds"),
            });
        }

        if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            return Err(DpgError::Detection {
                code: ErrorCode::D002,
                detail: SafeDetail::from_static("Span does not lie on UTF-8 char boundaries"),
            });
        }

        Ok(Self { start, end })
    }

    /// Returns the length of the span in bytes.
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns true if the span is zero bytes long.
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Extracts the subslice corresponding to this span from the text.
    pub fn as_str<'a>(&self, text: &'a str) -> &'a str {
        &text[self.start..self.end]
    }
}

/// Unique identifier for a detection rule (e.g. `"gitleaks.aws-access-token"`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RuleId(pub Cow<'static, str>);

impl RuleId {
    /// Constructs a rule ID from a static string slice.
    pub const fn from_static(id: &'static str) -> Self {
        Self(Cow::Borrowed(id))
    }

    /// Returns the rule identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&'static str> for RuleId {
    fn from(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl From<String> for RuleId {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RuleId({})", self.0)
    }
}

/// Category classification of sensitive findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Category {
    /// High-confidence secret matching a known provider format.
    KnownSecret,
    /// Cryptographic private key (PEM, RSA, EC, etc.).
    PrivateKey,
    /// Generic secret in a key-value or assignment context.
    KeyValueSecret,
    /// Database or service connection string with credentials.
    ConnectionString,
    /// User-configured confidential term or project keyword.
    CustomTerm,
    /// Indian national identity number (Aadhaar, PAN, GSTIN, etc.).
    IndianId,
    /// Personally Identifiable Information (email, phone number).
    Pii,
    /// High Shannon entropy candidate finding.
    Entropy,
}

/// Confidence rating of a detector finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Confidence {
    /// Low confidence (e.g. entropy heuristic alone).
    Low = 0,
    /// Medium confidence (e.g. format match without checksum).
    Medium = 1,
    /// High confidence (e.g. exact regex match with valid checksum).
    High = 2,
}

/// Granular sub-component kind of a finding (e.g. for connection strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PartKind {
    /// The complete finding span.
    Whole,
    /// Username component of a credential.
    User,
    /// Password or secret token component.
    Password,
    /// Host or address component.
    Host,
}

/// A sensitive finding identified by the detection engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The rule that identified this finding.
    pub rule_id: RuleId,
    /// Classification category.
    pub category: Category,
    /// Full byte span in the input text.
    pub span: Span,
    /// Sub-spans within the finding (if any).
    pub parts: Vec<(PartKind, Span)>,
    /// Confidence level of detection.
    pub confidence: Confidence,
}

/// Policy action to apply to a finding, strictly ordered by severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Action {
    /// Allow the content through without masking or warning.
    Allow = 0,
    /// Allow the content through but record a warning.
    Warn = 1,
    /// Replace the sensitive content with a placeholder token.
    Mask = 2,
    /// Block the content or request entirely.
    Block = 3,
}

/// A policy decision reached for a specific finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Index of the associated finding.
    pub finding: usize,
    /// Action resolved by policy.
    pub action: Action,
    /// Rule ID of the finding.
    pub rule_id: RuleId,
    /// Explanation reason for the decision.
    pub reason: Cow<'static, str>,
}

/// Ingress entry point route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Route {
    /// Claude Code PostToolUse hook.
    HookPostToolUse,
    /// Claude Code PreToolUse hook.
    HookPreToolUse,
    /// Claude Code UserPromptSubmit hook.
    HookUserPrompt,
    /// Local proxy server pass-through.
    Proxy,
    /// Command-line tool invocation (`dpg inspect`, `dpg sanitize`).
    Cli,
}

/// An audit entry for a warned finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarnItem {
    /// Rule that triggered the warning.
    pub rule_id: RuleId,
    /// Category of the finding.
    pub category: Category,
    /// Line number where finding occurred (1-indexed).
    pub line_number: usize,
}

/// An audit entry for a blocked finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockItem {
    /// Rule that triggered the block.
    pub rule_id: RuleId,
    /// Category of the finding.
    pub category: Category,
    /// Line number where finding occurred (1-indexed).
    pub line_number: usize,
    /// Reason explanation.
    pub reason: Cow<'static, str>,
}

/// Audit report returned after a protect or restore operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Number of distinct findings masked.
    pub masked: u32,
    /// Items that triggered warnings.
    pub warned: Vec<WarnItem>,
    /// Items that caused content to be blocked.
    pub blocked: Vec<BlockItem>,
    /// Whether protection operated in degraded mode (e.g. ephemeral placeholders).
    pub degraded: bool,
}

/// Outcome of an `Engine::protect` operation.
#[derive(Clone, PartialEq, Eq)]
pub enum ProtectOutcome {
    /// Protection succeeded; content is allowed with placeholders applied.
    Allowed {
        /// Masked text.
        text: String,
        /// Audit report.
        report: Report,
    },
    /// Content was blocked by policy or failure.
    Blocked {
        /// Audit report detailing reasons.
        report: Report,
    },
}

impl fmt::Debug for ProtectOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed { text, report } => f
                .debug_struct("ProtectOutcome::Allowed")
                .field("text", &format_args!("<redacted {} bytes>", text.len()))
                .field("report", report)
                .finish(),
            Self::Blocked { report } => f
                .debug_struct("ProtectOutcome::Blocked")
                .field("report", report)
                .finish(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_action_severity_ordering() {
        assert!(Action::Allow < Action::Warn);
        assert!(Action::Warn < Action::Mask);
        assert!(Action::Mask < Action::Block);
    }

    #[test]
    fn test_span_validation_utf8_char_boundaries() {
        let text = "Hello, 🦀 Crab!";
        // The crab emoji 🦀 is 4 bytes, starting at byte index 7 and ending at byte index 11.
        assert!(Span::new(text, 0, 5).is_ok());
        assert_eq!(Span::new(text, 0, 5).unwrap().as_str(text), "Hello");

        assert!(Span::new(text, 7, 11).is_ok());
        assert_eq!(Span::new(text, 7, 11).unwrap().as_str(text), "🦀");

        // Invalid span cutting inside the 4-byte crab emoji
        assert!(Span::new(text, 7, 9).is_err());
        assert!(Span::new(text, 8, 11).is_err());

        // Invalid span out of bounds
        assert!(Span::new(text, 0, 100).is_err());

        // Inverted span (start > end)
        assert!(Span::new(text, 5, 2).is_err());
    }

    #[test]
    fn test_protect_outcome_redacted_debug() {
        let text = "super_secret_payload_content";
        let outcome = ProtectOutcome::Allowed {
            text: text.to_string(),
            report: Report::default(),
        };

        let debug_str = format!("{outcome:?}");
        assert!(
            !debug_str.contains("super_secret"),
            "Debug output must NEVER contain payload content"
        );
        assert!(debug_str.contains(&format!("<redacted {} bytes>", text.len())));
    }
}
