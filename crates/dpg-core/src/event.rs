//! Metadata-only JSONL event logging with file rotation.
//!
//! Defined per `docs/security/DATA_HANDLING.md`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{DpgError, ErrorCode};

/// Schema version for DPG event logs.
pub const EVENT_LOG_SCHEMA_VERSION: u32 = 1;

/// Default maximum size before rotating event log (10 MiB).
pub const DEFAULT_MAX_LOG_BYTES: u64 = 10_485_760;

/// Default number of rotated files to retain.
pub const DEFAULT_ROTATION_FILES: usize = 3;

/// Formats a SystemTime timestamp into an ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_iso8601(time: SystemTime) -> String {
    let dur = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();

    let days = (secs / 86400) as i64;
    let rem_secs = (secs % 86400) as u32;

    let hour = rem_secs / 3600;
    let minute = (rem_secs % 3600) / 60;
    let second = rem_secs % 60;

    // Date computation from civil day
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Hashes an arbitrary identifier (session ID, project root) into a 16-character hex string.
pub fn hash_identifier(salt: &[u8], id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(id.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex[..16.min(hex.len())].to_string()
}

/// Hashes a filesystem path into a 16-character hex string.
pub fn hash_path(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex[..16.min(hex.len())].to_string()
}

/// Strictly typed metadata-only audit event.
///
/// Contains NO sensitive content, values, headers, prompts, or clear paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// ISO-8601 timestamp in UTC.
    pub ts: String,
    /// Schema version (always 1).
    pub v: u32,
    /// Ingress route (e.g. "hook.post_tool_use", "proxy", "cli").
    pub route: String,
    /// Tool name if from an agent hook (e.g. "Read", "Write", "Edit").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Salted hash of the project identifier.
    pub project: String,
    /// Salted hash of the session identifier.
    pub session: String,
    /// Event type string (e.g. "masked", "blocked", "warned", "restored", "scan").
    pub event: String,
    /// Finding rule ID if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Finding category name if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Policy action executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Finding or item count.
    pub count: u32,
    /// End-to-end operation latency in milliseconds.
    pub latency_ms: u64,
}

impl Event {
    /// Constructs a new Event with current timestamp and schema version 1.
    pub fn new(
        route: impl Into<String>,
        project: impl Into<String>,
        session: impl Into<String>,
        event: impl Into<String>,
        count: u32,
        latency_ms: u64,
    ) -> Self {
        Self {
            ts: format_iso8601(SystemTime::now()),
            v: EVENT_LOG_SCHEMA_VERSION,
            route: route.into(),
            tool: None,
            project: project.into(),
            session: session.into(),
            event: event.into(),
            rule_id: None,
            category: None,
            action: None,
            count,
            latency_ms,
        }
    }
}

struct EventLogInner {
    file_path: PathBuf,
    current_size: u64,
    max_file_bytes: u64,
    max_rotation_files: usize,
}

impl EventLogInner {
    fn new(
        file_path: PathBuf,
        max_file_bytes: u64,
        max_rotation_files: usize,
    ) -> Result<Self, DpgError> {
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).map_err(|_| DpgError::Internal {
                code: ErrorCode::Z001,
            })?;
        }

        let current_size = if file_path.is_file() {
            fs::metadata(&file_path)
                .map(|m| m.len())
                .unwrap_or_default()
        } else {
            0
        };

        Ok(Self {
            file_path,
            current_size,
            max_file_bytes,
            max_rotation_files,
        })
    }

    fn write_line(&mut self, line: &[u8]) -> Result<(), DpgError> {
        let line_len = line.len() as u64;

        if self.current_size + line_len > self.max_file_bytes && self.current_size > 0 {
            self.rotate()?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .map_err(|_| DpgError::Internal {
                code: ErrorCode::Z001,
            })?;

        file.write_all(line).map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;
        file.flush().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;

        self.current_size += line_len;
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), DpgError> {
        // Rotates files: file.2 -> deleted, file.1 -> file.2, file -> file.1
        let base = &self.file_path;
        let ext = base.extension().unwrap_or_default().to_string_lossy();
        let stem = base.file_stem().unwrap_or_default().to_string_lossy();
        let parent = base.parent().unwrap_or_else(|| Path::new("."));

        for i in (1..self.max_rotation_files).rev() {
            let src_name = if i == 1 {
                if ext.is_empty() {
                    stem.to_string()
                } else {
                    format!("{stem}.{ext}")
                }
            } else {
                let prev = i - 1;
                if ext.is_empty() {
                    format!("{stem}.{prev}")
                } else {
                    format!("{stem}.{prev}.{ext}")
                }
            };

            let dst_name = if ext.is_empty() {
                format!("{stem}.{i}")
            } else {
                format!("{stem}.{i}.{ext}")
            };

            let src = parent.join(src_name);
            let dst = parent.join(dst_name);

            if src.exists() {
                let _ = fs::rename(&src, &dst);
            }
        }

        self.current_size = 0;
        Ok(())
    }
}

/// Thread-safe event log writer.
pub struct EventLog {
    inner: Mutex<EventLogInner>,
}

impl EventLog {
    /// Opens or creates an event log at the specified path.
    pub fn open(
        file_path: impl Into<PathBuf>,
        max_file_bytes: u64,
        max_rotation_files: usize,
    ) -> Result<Self, DpgError> {
        let inner = EventLogInner::new(file_path.into(), max_file_bytes, max_rotation_files)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Appends a structured Event to the log file.
    pub fn record(&self, event: &Event) -> Result<(), DpgError> {
        let mut line = serde_json::to_vec(event).map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;
        line.push(b'\n');

        let mut lock = self.inner.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;
        lock.write_line(&line)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_format_iso8601() {
        let s = format_iso8601(UNIX_EPOCH);
        assert_eq!(s, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_hash_identifier_deterministic() {
        let h1 = hash_identifier(b"salt1", "project-x");
        let h2 = hash_identifier(b"salt1", "project-x");
        let h3 = hash_identifier(b"salt2", "project-x");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn test_event_log_schema_fields_only() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");

        let log = EventLog::open(&log_path, 10_000, 3).expect("open log");
        let mut event = Event::new("hook.post_tool_use", "proj123", "sess456", "masked", 2, 14);
        event.tool = Some("Read".to_string());
        event.rule_id = Some("gitleaks.aws-key".to_string());
        event.category = Some("KnownSecret".to_string());
        event.action = Some("mask".to_string());

        log.record(&event).expect("record event");

        let content = fs::read_to_string(&log_path).expect("read content");
        let parsed: serde_json::Value =
            serde_json::from_str(content.trim()).expect("parse json line");

        let allowed_keys: HashSet<&str> = [
            "ts",
            "v",
            "route",
            "tool",
            "project",
            "session",
            "event",
            "rule_id",
            "category",
            "action",
            "count",
            "latency_ms",
        ]
        .into_iter()
        .collect();

        if let serde_json::Value::Object(map) = parsed {
            for key in map.keys() {
                assert!(
                    allowed_keys.contains(key.as_str()),
                    "Disallowed key in event log: {key}"
                );
            }
        } else {
            panic!("Event line must be a JSON object");
        }
    }

    #[test]
    fn test_event_log_rotation_at_size() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");

        // Set max file bytes small (e.g. 250 bytes)
        let log = EventLog::open(&log_path, 250, 3).expect("open log");

        for i in 0..10 {
            let ev = Event::new("cli", "p", "s", "scan", i, 1);
            log.record(&ev).expect("record");
        }

        let rotated_1 = temp.path().join("events.1.jsonl");
        assert!(
            rotated_1.exists(),
            "Rotated file events.1.jsonl must exist after exceeding size limit"
        );
    }

    #[test]
    fn test_concurrent_appends_no_interleaved_lines() {
        let temp = tempfile::tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");

        let log = Arc::new(EventLog::open(&log_path, 1_000_000, 3).expect("open log"));
        let mut handles = Vec::new();

        for t in 0..8 {
            let log_clone = Arc::clone(&log);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    let ev = Event::new(
                        "hook",
                        format!("proj_{t}"),
                        format!("sess_{i}"),
                        "test",
                        1,
                        2,
                    );
                    log_clone.record(&ev).expect("record concurrent");
                }
            }));
        }

        for h in handles {
            h.join().expect("thread finished cleanly");
        }

        let content = fs::read_to_string(&log_path).expect("read content");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 400);

        for line in lines {
            let _: Event =
                serde_json::from_str(line).expect("Each line must be valid complete JSON");
        }
    }

    proptest! {
        #[test]
        fn test_random_secrets_never_appear_in_event_log(
            secret in "[a-zA-Z0-9_\\-]{16,64}",
        ) {
            let temp = tempfile::tempdir().expect("tempdir");
            let log_path = temp.path().join("events.jsonl");
            let log = EventLog::open(&log_path, 100_000, 3).expect("open log");

            // Build an event where salt/hash is derived from secret, but secret is never placed in typed fields
            let proj_hash = hash_identifier(b"salt", &secret);
            let sess_hash = hash_identifier(b"sess", &secret);
            let ev = Event::new("hook.post_tool_use", proj_hash, sess_hash, "masked", 1, 10);

            log.record(&ev).expect("record");

            let content = fs::read_to_string(&log_path).expect("read");
            prop_assert!(
                !content.contains(&secret),
                "Event log must NEVER contain secret value substring"
            );
        }
    }
}
