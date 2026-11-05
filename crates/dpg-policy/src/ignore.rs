//! Ignore list interface, finding fingerprint derivation, and in-memory test store.

use std::collections::HashSet;
use std::sync::RwLock;

use dpg_core::context::ProjectId;
use dpg_core::error::DpgError;
use dpg_core::types::RuleId;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A 16-byte HMAC fingerprint identifying a specific secret value finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 16]);

impl Fingerprint {
    /// Returns the hex string representation of the fingerprint.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Derives a 16-byte HMAC fingerprint from the rule ID and secret value.
pub fn compute_fingerprint(key: &[u8], rule_id: &RuleId, secret_val: &str) -> Fingerprint {
    let mut mac = HmacSha256::new_from_slice(key).unwrap_or_else(|_| {
        let fallback = [0u8; 32];
        HmacSha256::new_from_slice(&fallback).unwrap_or_else(|_| unreachable!())
    });

    mac.update(rule_id.as_str().as_bytes());
    mac.update(b":");
    mac.update(secret_val.as_bytes());

    let result = mac.finalize().into_bytes();
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&result[..16]);
    Fingerprint(fp)
}

/// Trait for querying and managing suppressed false-positive finding fingerprints.
pub trait IgnoreList: Send + Sync {
    /// Returns true if the finding fingerprint is ignored for this project.
    fn is_ignored(&self, project: &ProjectId, fp: &Fingerprint) -> Result<bool, DpgError>;
}

/// In-memory implementation of `IgnoreList` for testing and transient usage.
#[derive(Debug, Default)]
pub struct InMemoryIgnoreList {
    entries: RwLock<HashSet<(ProjectId, Fingerprint)>>,
}

impl InMemoryIgnoreList {
    /// Creates a new empty in-memory ignore list.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashSet::new()),
        }
    }

    /// Adds a project-specific fingerprint to the ignore set.
    pub fn ignore(&self, project: ProjectId, fp: Fingerprint) {
        if let Ok(mut lock) = self.entries.write() {
            lock.insert((project, fp));
        }
    }

    /// Removes a project-specific fingerprint from the ignore set.
    pub fn remove(&self, project: &ProjectId, fp: &Fingerprint) -> bool {
        if let Ok(mut lock) = self.entries.write() {
            lock.remove(&(project.clone(), *fp))
        } else {
            false
        }
    }
}

impl IgnoreList for InMemoryIgnoreList {
    fn is_ignored(&self, project: &ProjectId, fp: &Fingerprint) -> Result<bool, DpgError> {
        if let Ok(lock) = self.entries.read() {
            Ok(lock.contains(&(project.clone(), *fp)))
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_fingerprint_derivation_deterministic() {
        let key = b"test-project-key-salt";
        let rule = RuleId::from_static("dpg.aws-access-key-id");
        let val = &format!("{}{}", "AKIA", "1234567890ABCDEF");

        let fp1 = compute_fingerprint(key, &rule, val);
        let fp2 = compute_fingerprint(key, &rule, val);
        assert_eq!(fp1, fp2);

        // Different rule or value must change fingerprint
        let fp3 = compute_fingerprint(key, &RuleId::from_static("dpg.other"), val);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_in_memory_ignore_list_round_trip() {
        let list = InMemoryIgnoreList::new();
        let project = ProjectId::new("proj-123".to_string());
        let fp = Fingerprint([42u8; 16]);

        assert!(!list.is_ignored(&project, &fp).expect("query ignore"));

        list.ignore(project.clone(), fp);
        assert!(list.is_ignored(&project, &fp).expect("query ignore"));

        // Different project cannot access ignored item
        let other_project = ProjectId::new("proj-456".to_string());
        assert!(!list.is_ignored(&other_project, &fp).expect("query other"));
    }
}
