//! Connection string detection and component parsing (user, password, host, IPv6, URL-encoded).

use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::{Category, Confidence, Finding, PartKind, RuleId, Span};
use regex::Regex;

/// Parsed components of a database or service connection string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnParts {
    /// Full span of the connection string.
    pub whole: Span,
    /// Span of the username component, if present.
    pub user: Option<Span>,
    /// Span of the password or secret token component, if present.
    pub password: Option<Span>,
    /// Span of the host/server component (hostname, IPv4, or `[IPv6]`).
    pub host: Option<Span>,
}

/// Scanner that detects and parses database connection strings.
#[derive(Debug, Clone)]
pub struct ConnScanner {
    regex: Regex,
}

impl ConnScanner {
    /// Compiles a new `ConnScanner`.
    pub fn new() -> Result<Self, DpgError> {
        let pattern = r#"(?i)\b(?:jdbc:)?(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis[s]?|amqp[s]?|mssql|sqlserver)://(?:([^/:@\s]*)(?::([^/@\s]+))?@)?(\[[0-9a-fA-F:]+\]|[^/:@\s]+)(?::[0-9]{1,5})?(?:/[^?\s"']*)?(?:\?[^\s"'`<>)]*)?"#;
        let regex = Regex::new(pattern).map_err(|_| DpgError::Detection {
            code: ErrorCode::D001,
            detail: SafeDetail::from_static("Failed to compile connection string regex"),
        })?;

        Ok(ConnScanner { regex })
    }

    /// Scans text and returns `Finding`s for connection strings with granular sub-parts.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for caps in self.regex.captures_iter(text) {
            let whole_mat = match caps.get(0) {
                Some(m) => m,
                None => continue,
            };

            let whole_span = match Span::new(text, whole_mat.start(), whole_mat.end()) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let mut parts = vec![(PartKind::Whole, whole_span)];

            // User part
            if let Some(user_mat) = caps.get(1) {
                if !user_mat.as_str().is_empty() {
                    if let Ok(user_span) = Span::new(text, user_mat.start(), user_mat.end()) {
                        parts.push((PartKind::User, user_span));
                    }
                }
            }

            // Password part
            if let Some(pass_mat) = caps.get(2) {
                if let Ok(pass_span) = Span::new(text, pass_mat.start(), pass_mat.end()) {
                    parts.push((PartKind::Password, pass_span));
                }
            }

            // Host part
            if let Some(host_mat) = caps.get(3) {
                if let Ok(host_span) = Span::new(text, host_mat.start(), host_mat.end()) {
                    parts.push((PartKind::Host, host_span));
                }
            }

            findings.push(Finding {
                rule_id: RuleId::from_static("dpg.connection-string"),
                category: Category::ConnectionString,
                span: whole_span,
                parts,
                confidence: Confidence::High,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_sr_dt_10_url_encoded_password() {
        let scanner = ConnScanner::new().expect("scanner init");
        let text =
            "DATABASE_URL=\"postgresql://db_user:p%40ss%23w0rd@db.internal:5432/prod_db?ssl=true\"";

        let findings = scanner.scan(text);
        assert_eq!(findings.len(), 1, "Must detect connection string");

        let finding = &findings[0];
        assert_eq!(finding.category, Category::ConnectionString);

        // Verify password part is isolated and exact
        let pass_part = finding
            .parts
            .iter()
            .find(|(kind, _)| *kind == PartKind::Password)
            .expect("password part must be present");

        assert_eq!(pass_part.1.as_str(text), "p%40ss%23w0rd");

        // Verify host part
        let host_part = finding
            .parts
            .iter()
            .find(|(kind, _)| *kind == PartKind::Host)
            .expect("host part must be present");
        assert_eq!(host_part.1.as_str(text), "db.internal");
    }

    #[test]
    fn test_connection_string_schemes_and_ipv6() {
        let scanner = ConnScanner::new().expect("scanner init");
        let samples = [
            (
                "postgres://user:secret@[2001:db8::1]:5432/dbname",
                Some("user"),
                Some("secret"),
                "[2001:db8::1]",
            ),
            (
                "mysql://root:toor@127.0.0.1:3306/app",
                Some("root"),
                Some("toor"),
                "127.0.0.1",
            ),
            (
                "mongodb+srv://admin:pass123@cluster0.mongodb.net/test",
                Some("admin"),
                Some("pass123"),
                "cluster0.mongodb.net",
            ),
            (
                "redis://:redis_secret_auth@cache.redis.internal:6379/0",
                None,
                Some("redis_secret_auth"),
                "cache.redis.internal",
            ),
            (
                "amqps://guest:guest@mq.broker:5671",
                Some("guest"),
                Some("guest"),
                "mq.broker",
            ),
            (
                "jdbc:sqlserver://sa:Password123@sqlserver:1433;databaseName=master",
                Some("sa"),
                Some("Password123"),
                "sqlserver",
            ),
        ];

        for (url, expected_user, expected_pass, expected_host) in samples {
            let text = format!("Connecting with {url} in environment");
            let findings = scanner.scan(&text);
            assert_eq!(findings.len(), 1, "Failed to scan: {url}");

            let f = &findings[0];
            let user = f
                .parts
                .iter()
                .find(|(k, _)| *k == PartKind::User)
                .map(|(_, s)| s.as_str(&text));
            let pass = f
                .parts
                .iter()
                .find(|(k, _)| *k == PartKind::Password)
                .map(|(_, s)| s.as_str(&text));
            let host = f
                .parts
                .iter()
                .find(|(k, _)| *k == PartKind::Host)
                .map(|(_, s)| s.as_str(&text));

            assert_eq!(user, expected_user, "User mismatch for {url}");
            assert_eq!(pass, expected_pass, "Password mismatch for {url}");
            assert_eq!(host, Some(expected_host), "Host mismatch for {url}");
        }
    }

    #[test]
    fn test_missing_credentials_connection_string() {
        let scanner = ConnScanner::new().expect("scanner init");
        let text = "redis://localhost:6379/0";
        let findings = scanner.scan(text);
        assert_eq!(findings.len(), 1);

        let f = &findings[0];
        let has_pass = f.parts.iter().any(|(k, _)| *k == PartKind::Password);
        assert!(!has_pass, "Missing password should not emit password part");
    }
}
