//! Key-value and .env secret detection for shell exports, JSON, YAML, TOML, and INI.

use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::{Category, Confidence, Finding, PartKind, RuleId, Span};
use regex::Regex;

/// Scanner for sensitive key-value pairs across common configuration formats.
#[derive(Debug, Clone)]
pub struct KvScanner {
    re_double_quoted: Regex,
    re_single_quoted: Regex,
    re_unquoted: Regex,
}

impl KvScanner {
    /// Constructs and compiles a new `KvScanner`.
    pub fn new() -> Result<Self, DpgError> {
        let re_double_quoted = Regex::new(
            r#"(?i)(?:^|[\r\n\s,{;])(?:export\s+)?["']?([a-zA-Z0-9_.-]*(?:pass(?:word)?|pwd|secret|token|api[_-]?key|private[_-]?key|credential|auth)[a-zA-Z0-9_.-]*)["']?[ \t]*[:=][ \t]*"([^"\r\n]*)""#,
        )
        .map_err(|_| DpgError::Detection {
            code: ErrorCode::D001,
            detail: SafeDetail::from_static("Failed to compile KV double-quoted regex"),
        })?;

        let re_single_quoted = Regex::new(
            r#"(?i)(?:^|[\r\n\s,{;])(?:export\s+)?["']?([a-zA-Z0-9_.-]*(?:pass(?:word)?|pwd|secret|token|api[_-]?key|private[_-]?key|credential|auth)[a-zA-Z0-9_.-]*)["']?[ \t]*[:=][ \t]*'([^'\r\n]*)'"#,
        )
        .map_err(|_| DpgError::Detection {
            code: ErrorCode::D001,
            detail: SafeDetail::from_static("Failed to compile KV single-quoted regex"),
        })?;

        let re_unquoted = Regex::new(
            r#"(?i)(?:^|[\r\n\s,{;])(?:export\s+)?["']?([a-zA-Z0-9_.-]*(?:pass(?:word)?|pwd|secret|token|api[_-]?key|private[_-]?key|credential|auth)[a-zA-Z0-9_.-]*)["']?[ \t]*[:=][ \t]*([^"'\s\r\n,;}{][^\s\r\n,;}{]*)"#,
        )
        .map_err(|_| DpgError::Detection {
            code: ErrorCode::D001,
            detail: SafeDetail::from_static("Failed to compile KV unquoted regex"),
        })?;

        Ok(KvScanner {
            re_double_quoted,
            re_single_quoted,
            re_unquoted,
        })
    }

    /// Scans text for key-value assignments and configuration secrets.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Double-quoted values
        for caps in self.re_double_quoted.captures_iter(text) {
            if let Some(val_mat) = caps.get(2) {
                let val = val_mat.as_str();
                if is_dummy_or_placeholder(val) {
                    continue;
                }
                if let Ok(span) = Span::new(text, val_mat.start(), val_mat.end()) {
                    findings.push(Finding {
                        rule_id: RuleId::from_static("dpg.key-value-secret"),
                        category: Category::KeyValueSecret,
                        span,
                        parts: vec![(PartKind::Whole, span)],
                        confidence: Confidence::High,
                    });
                }
            }
        }

        // 2. Single-quoted values
        for caps in self.re_single_quoted.captures_iter(text) {
            if let Some(val_mat) = caps.get(2) {
                let val = val_mat.as_str();
                if is_dummy_or_placeholder(val) {
                    continue;
                }
                if let Ok(span) = Span::new(text, val_mat.start(), val_mat.end()) {
                    findings.push(Finding {
                        rule_id: RuleId::from_static("dpg.key-value-secret"),
                        category: Category::KeyValueSecret,
                        span,
                        parts: vec![(PartKind::Whole, span)],
                        confidence: Confidence::High,
                    });
                }
            }
        }

        // 3. Unquoted values (first char is guaranteed not quote)
        for caps in self.re_unquoted.captures_iter(text) {
            if let Some(val_mat) = caps.get(2) {
                let val = val_mat.as_str();
                if is_dummy_or_placeholder(val) {
                    continue;
                }
                if let Ok(span) = Span::new(text, val_mat.start(), val_mat.end()) {
                    findings.push(Finding {
                        rule_id: RuleId::from_static("dpg.key-value-secret"),
                        category: Category::KeyValueSecret,
                        span,
                        parts: vec![(PartKind::Whole, span)],
                        confidence: Confidence::High,
                    });
                }
            }
        }

        findings.sort_by_key(|f| f.span.start);
        findings
    }
}

/// Checks whether a detected value is a placeholder, variable expansion, or dummy test string.
pub fn is_dummy_or_placeholder(val: &str) -> bool {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return true;
    }

    // Placeholders like DPG_SECRET_...
    if trimmed.starts_with("DPG_SECRET_") {
        return true;
    }

    // Variable expansions like ${VAR} or $VAR
    if (trimmed.starts_with("${") && trimmed.ends_with('}'))
        || (trimmed.starts_with('$') && !trimmed.contains(' '))
    {
        return true;
    }

    // Obvious template tags like <...>, [TODO], {{...}}
    if (trimmed.starts_with('<') && trimmed.ends_with('>'))
        || (trimmed.starts_with("{{") && trimmed.ends_with("}}"))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
    {
        return true;
    }

    let lower = trimmed.to_ascii_lowercase();

    const DUMMIES: &[&str] = &[
        "changeme",
        "change_me",
        "change-me",
        "xxx",
        "xxxx",
        "xxxxx",
        "******",
        "123456",
        "12345678",
        "password",
        "pass",
        "secret",
        "test",
        "testing",
        "sample",
        "example",
        "placeholder",
        "your_key",
        "your-key",
        "your_api_key",
        "your-api-key",
        "your_token",
        "your_secret",
        "replace_me",
        "replace-me",
        "todo",
        "tbd",
        "dummy",
        "null",
        "none",
        "undefined",
        "true",
        "false",
        "nil",
    ];

    if DUMMIES.contains(&lower.as_str()) {
        return true;
    }

    if trimmed.len() < 3 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_env_syntax_detection() {
        let scanner = KvScanner::new().expect("scanner init");
        let env_text = r#"
# .env file
DATABASE_PASSWORD="super-secret-password-123"
API_KEY='single-quoted-secret-token'
AUTH_TOKEN=unquoted-secret-string-987
export CLIENT_SECRET="exported-oauth-client-secret"
"#;
        let findings = scanner.scan(env_text);
        assert_eq!(findings.len(), 4);

        assert_eq!(
            findings[0].span.as_str(env_text),
            "super-secret-password-123"
        );
        assert_eq!(
            findings[1].span.as_str(env_text),
            "single-quoted-secret-token"
        );
        assert_eq!(
            findings[2].span.as_str(env_text),
            "unquoted-secret-string-987"
        );
        assert_eq!(
            findings[3].span.as_str(env_text),
            "exported-oauth-client-secret"
        );
    }

    #[test]
    fn test_json_yaml_toml_syntax_detection() {
        let scanner = KvScanner::new().expect("scanner init");

        let json_text = r#"{ "api_key": "my-json-secret-key-1122" }"#;
        let findings_json = scanner.scan(json_text);
        assert_eq!(findings_json.len(), 1);
        assert_eq!(
            findings_json[0].span.as_str(json_text),
            "my-json-secret-key-1122"
        );

        let yaml_text = "credentials:\n  app_secret: \"my-yaml-app-secret-4455\"\n";
        let findings_yaml = scanner.scan(yaml_text);
        assert_eq!(findings_yaml.len(), 1);
        assert_eq!(
            findings_yaml[0].span.as_str(yaml_text),
            "my-yaml-app-secret-4455"
        );

        let toml_text = "admin_password = 'toml-secret-pass-7788'\n";
        let findings_toml = scanner.scan(toml_text);
        assert_eq!(findings_toml.len(), 1);
        assert_eq!(
            findings_toml[0].span.as_str(toml_text),
            "toml-secret-pass-7788"
        );
    }

    #[test]
    fn test_dummy_and_placeholder_skips() {
        let scanner = KvScanner::new().expect("scanner init");
        let dummy_text = r#"
PASSWORD=""
API_KEY="changeme"
SECRET_TOKEN="<ENTER_YOUR_API_KEY_HERE>"
AUTH="${AUTH_ENV_VAR}"
OLD_PASS=xxx
DPG_SECRET=DPG_SECRET_A1B2C3D4E5F6
TODO_PASS="[TODO]"
SAFE_PORT=8080
"#;
        let findings = scanner.scan(dummy_text);
        assert!(
            findings.is_empty(),
            "Expected 0 findings on dummy values, got: {:?}",
            findings
        );
    }
}
