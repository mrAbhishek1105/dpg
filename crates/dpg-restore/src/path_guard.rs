//! Path guard implementing containment and safety checks for file restoration.
//!
//! Defined per `docs/security/RESTORE_GUARD.md` and `docs/components/RESTORE.md`.

use std::path::{Component, Path, PathBuf};

use dpg_core::error::{DpgError, ErrorCode, SafeDetail};

/// Path containment and traversal guard for project file writes.
#[derive(Debug, Clone)]
pub struct PathGuard {
    root: PathBuf,
}

impl PathGuard {
    /// Creates a new `PathGuard` anchored at the canonical project root.
    ///
    /// Fails closed with `DPG-V004` if the root cannot be canonicalized: a guard
    /// anchored at an unresolved path could not prove containment.
    pub fn new(project_root: &Path) -> Result<Self, DpgError> {
        let canonical_root =
            dunce::canonicalize(project_root).map_err(|_| DpgError::PathValidation {
                code: ErrorCode::V004,
                detail: SafeDetail::from_static("Project root cannot be canonicalized"),
            })?;

        Ok(Self {
            root: canonical_root,
        })
    }

    /// Returns the canonical root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Validates candidate path against project root boundaries, symlink escapes, and `.git` access.
    pub fn check(&self, candidate: &Path) -> Result<PathBuf, DpgError> {
        self.check_with_cwd(candidate, None)
    }

    /// Validates candidate path using an optional current working directory.
    ///
    /// Algorithm (fails closed at every step):
    /// 1. reject NUL bytes, Windows device/verbatim namespaces, and any `.`/`..`
    ///    component anywhere in the candidate (lexically, before touching the FS);
    /// 2. split into the longest ancestor that exists *without following a final
    ///    link* (`symlink_metadata`) and the non-existent remainder;
    /// 3. canonicalize that ancestor (following symlinks); failure denies;
    /// 4. re-join the remainder and require containment in the canonical root;
    /// 5. deny any `.git` component below the root.
    pub fn check_with_cwd(
        &self,
        candidate: &Path,
        cwd: Option<&Path>,
    ) -> Result<PathBuf, DpgError> {
        let candidate_str = candidate.to_string_lossy();

        // 1a. Reject NUL bytes
        if candidate_str.contains('\0') {
            return Err(DpgError::PathValidation {
                code: ErrorCode::V004,
                detail: SafeDetail::from_static("Path contains NUL byte"),
            });
        }

        // 1b. Reject Windows device and verbatim namespaces
        if cfg!(windows) {
            let s = candidate_str.as_ref();
            if s.starts_with(r"\\.\")
                || s.starts_with(r"\\?\")
                || s.starts_with("//./")
                || s.starts_with("//?/")
            {
                return Err(DpgError::PathValidation {
                    code: ErrorCode::V001,
                    detail: SafeDetail::from_static("Device paths are forbidden"),
                });
            }
        }

        // 2. Resolve initial path p
        let p = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else if let Some(dir) = cwd {
            dir.join(candidate)
        } else {
            self.root.join(candidate)
        };

        // 1c. Lexically reject traversal components anywhere. Agents send plain
        // absolute paths; `..` has no legitimate use here and resolving it against
        // non-existent directories is OS-dependent (this was a containment bypass).
        if p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(DpgError::PathValidation {
                code: ErrorCode::V001,
                detail: SafeDetail::from_static("Path traversal components are forbidden"),
            });
        }

        // 3. Split p into the longest existing ancestor A (lstat, so a dangling
        // symlink counts as existing and is then rejected by canonicalize) and remainder R.
        let mut ancestor = p.clone();
        let mut remainder_components = Vec::new();
        while std::fs::symlink_metadata(&ancestor).is_err() {
            let (Some(file_name), Some(parent)) = (ancestor.file_name(), ancestor.parent()) else {
                return Err(DpgError::PathValidation {
                    code: ErrorCode::V001,
                    detail: SafeDetail::from_static("Path has no existing ancestor"),
                });
            };
            remainder_components.push(file_name.to_os_string());
            ancestor = parent.to_path_buf();
        }
        remainder_components.reverse();

        // 4. Canonicalize ancestor A (following symlinks). Failure (dangling symlink,
        // permission error) denies: containment cannot be proven.
        let lexically_inside = is_path_within(&ancestor, &self.root);
        let Ok(c_a) = dunce::canonicalize(&ancestor) else {
            return Err(DpgError::PathValidation {
                code: ErrorCode::V003,
                detail: SafeDetail::from_static("Path component cannot be resolved"),
            });
        };

        // 5. Join remainder R
        let mut target = c_a;
        for comp in remainder_components {
            target.push(comp);
        }

        // 6. Check containment in self.root
        if !is_path_within(&target, &self.root) {
            return Err(if lexically_inside {
                DpgError::PathValidation {
                    code: ErrorCode::V003,
                    detail: SafeDetail::from_static("Symlink resolves outside project root"),
                }
            } else {
                DpgError::PathValidation {
                    code: ErrorCode::V001,
                    detail: SafeDetail::from_static("Path outside project root"),
                }
            });
        }

        // 7. Reject any component relative to root equal to ".git" (case-insensitive)
        if contains_git_component(&target, &self.root) {
            return Err(DpgError::PathValidation {
                code: ErrorCode::V002,
                detail: SafeDetail::from_static("Target path enters .git directory"),
            });
        }

        Ok(target)
    }
}

/// Checks if `target` is contained within `root`, accounting for OS case sensitivity.
fn is_path_within(target: &Path, root: &Path) -> bool {
    let target_comps: Vec<Component> = target.components().collect();
    let root_comps: Vec<Component> = root.components().collect();

    if target_comps.len() < root_comps.len() {
        return false;
    }

    let is_case_insensitive = cfg!(windows) || cfg!(target_os = "macos");

    for (r, t) in root_comps.iter().zip(target_comps.iter()) {
        let r_str = r.as_os_str().to_string_lossy();
        let t_str = t.as_os_str().to_string_lossy();

        if is_case_insensitive {
            if !r_str.eq_ignore_ascii_case(&t_str) {
                return false;
            }
        } else if r_str != t_str {
            return false;
        }
    }

    true
}

/// Checks if any component of `target` relative to `root` equals `.git` (case-insensitive).
fn contains_git_component(target: &Path, root: &Path) -> bool {
    let target_comps: Vec<Component> = target.components().collect();
    let root_comps: Vec<Component> = root.components().collect();

    if target_comps.len() <= root_comps.len() {
        return false;
    }

    for comp in &target_comps[root_comps.len()..] {
        let s = comp.as_os_str().to_string_lossy();
        if s.eq_ignore_ascii_case(".git") {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_sr_pg_01_relative_escape_denied_v001() {
        let temp = tempfile::tempdir().expect("tempdir");
        let guard = PathGuard::new(temp.path()).expect("guard init");

        let err = guard
            .check(Path::new("../../etc/passwd"))
            .expect_err("PG-01: ../../ escape must be denied");
        assert_eq!(err.code(), ErrorCode::V001);
    }

    #[test]
    fn test_sr_pg_02_absolute_outside_denied_v001() {
        let temp = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let guard = PathGuard::new(temp.path()).expect("guard init");

        let target_file = outside.path().join("secret.txt");
        let err = guard
            .check(&target_file)
            .expect_err("PG-02: Absolute path outside root must be denied");
        assert_eq!(err.code(), ErrorCode::V001);
    }

    #[test]
    fn test_sr_pg_05_new_nested_dirs_allowed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let guard = PathGuard::new(temp.path()).expect("guard init");

        let candidate = Path::new("sub/new_dir/deeper/file.txt");
        let res = guard
            .check(candidate)
            .expect("PG-05: Non-existent nested dirs within root must be allowed");

        assert!(res.starts_with(guard.root()));
        assert!(res.ends_with(candidate));
    }

    #[test]
    fn test_sr_pg_06_git_directory_denied_v002() {
        let temp = tempfile::tempdir().expect("tempdir");
        let guard = PathGuard::new(temp.path()).expect("guard init");

        let targets = [
            ".git/hooks/pre-commit",
            ".GIT/config",
            "subdir/.git/config",
            "sub/.Git/HEAD",
        ];

        for t in &targets {
            let err = guard
                .check(Path::new(t))
                .expect_err("PG-06: .git target must be denied");
            assert_eq!(
                err.code(),
                ErrorCode::V002,
                "PG-06: .git path {t} must fail with V002"
            );
        }
    }

    #[test]
    fn test_sr_pg_07_windows_drive_letter_case_and_slashes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let guard = PathGuard::new(temp.path()).expect("guard init");

        let rel = "subdir/nested/file.txt";
        let full_path = guard.root().join(rel);

        // Test with forward slashes
        let res1 = guard.check(&full_path).expect("forward slash path");
        assert!(is_path_within(&res1, guard.root()));

        // Test with different case on Windows
        if cfg!(windows) {
            let full_str = full_path.to_string_lossy().to_string();
            let switched_case = if full_str.starts_with('C') {
                full_str.replacen('C', "c", 1)
            } else if full_str.starts_with('c') {
                full_str.replacen('c', "C", 1)
            } else {
                full_str
            };

            let res2 = guard
                .check(Path::new(&switched_case))
                .expect("case-switched drive path");
            assert!(is_path_within(&res2, guard.root()));
        }
    }

    #[test]
    fn test_sr_pg_08_windows_device_paths_denied() {
        let temp = tempfile::tempdir().expect("tempdir");
        let guard = PathGuard::new(temp.path()).expect("guard init");

        if cfg!(windows) {
            let err = guard
                .check(Path::new(r"\\.\PhysicalDrive0"))
                .expect_err("PG-08: Device paths must be denied");
            assert_eq!(err.code(), ErrorCode::V001);
        }
    }

    #[test]
    fn test_sr_pg_09_root_is_symlink() {
        let temp = tempfile::tempdir().expect("tempdir");
        let real_dir = temp.path().join("real_dir");
        std::fs::create_dir_all(&real_dir).expect("create real_dir");

        let symlink_root = temp.path().join("link_to_real");

        let symlink_created = if cfg!(windows) {
            #[cfg(windows)]
            {
                std::os::windows::fs::symlink_dir(&real_dir, &symlink_root).is_ok()
            }
            #[cfg(not(windows))]
            {
                false
            }
        } else {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&real_dir, &symlink_root).is_ok()
            }
            #[cfg(not(unix))]
            {
                false
            }
        };

        if !symlink_created {
            eprintln!("SKIPPED: Symlink creation not permitted in this environment (PG-09)");
            return;
        }

        let guard = PathGuard::new(&symlink_root).expect("guard on symlink root");
        let candidate = Path::new("sub/file.txt");
        let checked = guard.check(candidate).expect("check under symlink root");

        assert!(is_path_within(&checked, guard.root()));
    }

    #[test]
    fn test_sr_pg_03_and_pg_04_symlink_escape_v003() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project_root = temp.path().join("project");
        let outside_dir = temp.path().join("outside");
        std::fs::create_dir_all(&project_root).expect("create project");
        std::fs::create_dir_all(&outside_dir).expect("create outside");

        let outside_file = outside_dir.join("outside.txt");
        std::fs::write(&outside_file, "outside secret").expect("write outside file");

        let symlink_dir_path = project_root.join("symlink_dir");
        let symlink_file_path = project_root.join("symlink_file.txt");

        let (dir_link_ok, file_link_ok) = if cfg!(windows) {
            #[cfg(windows)]
            {
                let d = std::os::windows::fs::symlink_dir(&outside_dir, &symlink_dir_path).is_ok();
                let f =
                    std::os::windows::fs::symlink_file(&outside_file, &symlink_file_path).is_ok();
                (d, f)
            }
            #[cfg(not(windows))]
            {
                (false, false)
            }
        } else {
            #[cfg(unix)]
            {
                let d = std::os::unix::fs::symlink(&outside_dir, &symlink_dir_path).is_ok();
                let f = std::os::unix::fs::symlink(&outside_file, &symlink_file_path).is_ok();
                (d, f)
            }
            #[cfg(not(unix))]
            {
                (false, false)
            }
        };

        if !dir_link_ok && !file_link_ok {
            eprintln!("SKIPPED: Symlink creation not permitted in this environment (PG-03/PG-04)");
            return;
        }

        let guard = PathGuard::new(&project_root).expect("guard init");

        if dir_link_ok {
            // PG-03: Symlinked dir inside root pointing outside
            let err = guard
                .check(&symlink_dir_path.join("escaped_file.txt"))
                .expect_err("PG-03: Symlink directory escape must be denied");
            assert_eq!(err.code(), ErrorCode::V003);
        }

        if file_link_ok {
            // PG-04: Symlinked file inside root pointing outside
            let err = guard
                .check(&symlink_file_path)
                .expect_err("PG-04: Symlink file escape must be denied");
            assert_eq!(err.code(), ErrorCode::V003);
        }
    }

    #[test]
    fn test_sr_pg_10_dotdot_through_missing_dir_denied() {
        // Regression: `<root>/missing/../../x` used to pass on Linux/macOS because the
        // non-existent ancestor kept its `..` and containment was a prefix compare.
        let temp = tempfile::tempdir().expect("tempdir");
        let guard = PathGuard::new(temp.path()).expect("guard init");
        let escape = guard
            .root()
            .join("missing")
            .join("..")
            .join("..")
            .join("escaped.txt");
        let err = guard.check(&escape).expect_err("must deny");
        assert_eq!(err.code(), ErrorCode::V001);

        // Relative `..` that would stay inside the root is still refused.
        let err = guard
            .check(Path::new("sub/../file.txt"))
            .expect_err("`..` components must be denied");
        assert_eq!(err.code(), ErrorCode::V001);
    }

    #[test]
    fn test_sr_pg_11_unresolvable_root_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let err = PathGuard::new(&temp.path().join("does-not-exist")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::V004);
    }

    #[cfg(unix)]
    #[test]
    fn test_sr_pg_12_dangling_symlink_in_middle_denied() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("project");
        std::fs::create_dir_all(&root).expect("root");
        let outside = temp.path().join("outside-not-yet-created");
        std::os::unix::fs::symlink(&outside, root.join("dlink")).expect("symlink");
        let guard = PathGuard::new(&root).expect("guard init");
        let err = guard
            .check(&root.join("dlink").join("file.txt"))
            .expect_err("dangling symlink must deny");
        assert_eq!(err.code(), ErrorCode::V003);
    }
}
