//! Project and session context resolution.
//!
//! Defined per `docs/components/CORE.md` §6 and §11.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{DpgError, ErrorCode, SafeDetail};
use crate::event::hash_identifier;
use crate::types::Route;

type HmacSha256 = Hmac<Sha256>;

/// Unique 16-byte hex project identifier derived via HMAC-SHA256 from the canonical root path.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProjectId(pub String);

impl ProjectId {
    /// Creates a ProjectId from an already-validated hex string.
    pub const fn new(id: String) -> Self {
        Self(id)
    }

    /// Returns the project ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ProjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProjectId({})", self.0)
    }
}

/// Source provider for project HMAC secret keys.
pub trait ProjectKeySource: Send + Sync {
    /// Retrieves or derives the 256-bit project key.
    fn get_project_key(&self) -> Result<[u8; 32], DpgError>;
}

/// Fixed key source implementation used in tests and standalone contexts.
#[derive(Debug, Clone)]
pub struct FixedProjectKeySource(pub [u8; 32]);

impl ProjectKeySource for FixedProjectKeySource {
    fn get_project_key(&self) -> Result<[u8; 32], DpgError> {
        Ok(self.0)
    }
}

/// Resolved canonical project context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectContext {
    /// Canonicalized filesystem path to the project root.
    pub root: PathBuf,
    /// Deterministic HMAC-SHA256 project identifier.
    pub id: ProjectId,
}

/// Derives a deterministic `ProjectId` from a canonical root path and 256-bit key.
pub fn derive_project_id(key: &[u8; 32], canonical_root: &Path) -> ProjectId {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => unreachable!("HMAC-SHA256 accepts 32-byte key"),
    };
    mac.update(canonical_root.to_string_lossy().as_bytes());
    let bytes = mac.finalize().into_bytes();
    let hex = format!("{:x}", bytes);
    // 16 bytes = 32 hex characters
    let truncated = if hex.len() > 32 { &hex[..32] } else { &hex };
    ProjectId(truncated.to_string())
}

/// Walks up from `cwd` to resolve the canonical project root and derive `ProjectId`.
///
/// Looks for the first ancestor directory containing `.git` or `.dpg.toml`.
/// Falls back to `cwd` if no root marker is found.
pub fn resolve_project(
    cwd: &Path,
    key_source: &dyn ProjectKeySource,
) -> Result<ProjectContext, DpgError> {
    let mut current = if cwd.is_relative() {
        std::env::current_dir()
            .map_err(|_| DpgError::PathValidation {
                code: ErrorCode::V004,
                detail: SafeDetail::from_static("Could not get current working directory"),
            })?
            .join(cwd)
    } else {
        cwd.to_path_buf()
    };

    let mut found_root = None;

    loop {
        if current.join(".git").exists() || current.join(".dpg.toml").exists() {
            found_root = Some(current.clone());
            break;
        }

        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    let root_path = found_root.unwrap_or_else(|| cwd.to_path_buf());

    // Canonicalize with dunce to strip Windows \\?\ prefixes
    let canonical = dunce::canonicalize(&root_path).unwrap_or(root_path);

    let key = key_source.get_project_key()?;
    let id = derive_project_id(&key, &canonical);

    Ok(ProjectContext {
        root: canonical,
        id,
    })
}

/// Opaque session identifier for agent conversations or proxy sessions.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    /// Creates a new SessionId.
    pub const fn new(id: String) -> Self {
        Self(id)
    }

    /// Returns the session string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Computes a salted 16-hex hash suitable for metadata event logging.
    pub fn hash_for_log(&self, salt: &[u8]) -> String {
        hash_identifier(salt, &self.0)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted preview
        let preview = if self.0.len() > 8 {
            &self.0[..8]
        } else {
            &self.0
        };
        write!(f, "SessionId({}…)", preview)
    }
}

/// Request execution context across the DPG engine.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Resolved project context.
    pub project: ProjectContext,
    /// Current session ID.
    pub session: SessionId,
    /// Ingress entry point route.
    pub route: Route,
    /// Execution deadline after which fail-closed response is enforced.
    pub deadline: Instant,
}

impl RequestContext {
    /// Returns true if the deadline has elapsed.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Checks if deadline has passed; returns ErrorCode::T001 on overrun.
    pub fn check_deadline(&self) -> Result<(), DpgError> {
        if self.is_expired() {
            Err(DpgError::Timeout {
                code: ErrorCode::T001,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    #[test]
    fn test_resolve_project_git_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let git_dir = temp.path().join(".git");
        fs::create_dir(&git_dir).expect("create .git");

        let sub_dir = temp.path().join("sub").join("nested");
        fs::create_dir_all(&sub_dir).expect("create sub nested");

        let key_source = FixedProjectKeySource([7u8; 32]);
        let ctx = resolve_project(&sub_dir, &key_source).expect("resolve project");

        let canonical_temp = dunce::canonicalize(temp.path()).expect("canonical temp");
        assert_eq!(ctx.root, canonical_temp);
        assert_eq!(ctx.id.as_str().len(), 32);
    }

    #[test]
    fn test_resolve_project_dpg_toml_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dpg_toml = temp.path().join(".dpg.toml");
        fs::write(&dpg_toml, "# config").expect("write .dpg.toml");

        let sub_dir = temp.path().join("src");
        fs::create_dir(&sub_dir).expect("create src");

        let key_source = FixedProjectKeySource([9u8; 32]);
        let ctx = resolve_project(&sub_dir, &key_source).expect("resolve project");

        let canonical_temp = dunce::canonicalize(temp.path()).expect("canonical temp");
        assert_eq!(ctx.root, canonical_temp);
    }

    #[test]
    fn test_resolve_project_fallback_to_cwd() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_source = FixedProjectKeySource([1u8; 32]);

        let ctx = resolve_project(temp.path(), &key_source).expect("resolve project");
        let canonical_temp = dunce::canonicalize(temp.path()).expect("canonical temp");
        assert_eq!(ctx.root, canonical_temp);
    }

    #[test]
    fn test_request_context_deadline_check() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_source = FixedProjectKeySource([0u8; 32]);
        let project = resolve_project(temp.path(), &key_source).expect("project");

        let unexpired = RequestContext {
            project: project.clone(),
            session: SessionId::new("sess-1".to_string()),
            route: Route::HookPostToolUse,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        assert!(unexpired.check_deadline().is_ok());

        let expired = RequestContext {
            project,
            session: SessionId::new("sess-2".to_string()),
            route: Route::HookPostToolUse,
            deadline: Instant::now() - Duration::from_secs(1),
        };
        let err = expired.check_deadline().unwrap_err();
        assert_eq!(err.code(), ErrorCode::T001);
    }
}
