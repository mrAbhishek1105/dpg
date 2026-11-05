//! Master key management and key provider implementations.

use std::fs;
use std::path::PathBuf;

use dpg_core::context::ProjectKeySource;
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use rand::RngCore;
use zeroize::Zeroizing;

/// Provider of the 256-bit cryptographic master key used for mapping storage.
pub trait KeyProvider: Send + Sync {
    /// Returns the 256-bit master key inside a `Zeroizing` memory wrapper.
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, DpgError>;
}

/// A fixed in-memory key provider primarily used for testing and reproducible sessions.
#[derive(Debug, Clone)]
pub struct FixedKeyProvider {
    key: [u8; 32],
}

impl FixedKeyProvider {
    /// Creates a key provider with a predetermined key.
    pub const fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl KeyProvider for FixedKeyProvider {
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, DpgError> {
        Ok(Zeroizing::new(self.key))
    }
}

impl ProjectKeySource for FixedKeyProvider {
    fn get_project_key(&self) -> Result<[u8; 32], DpgError> {
        let key = self.master_key()?;
        Ok(*key)
    }
}

/// Key provider that securely stores a 256-bit key in a local file with strict permissions.
#[derive(Debug, Clone)]
pub struct FileKeyProvider {
    path: PathBuf,
}

impl FileKeyProvider {
    /// Initializes a file key provider targeting the given path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Loads the key from disk or securely generates a new one if not present.
    pub fn get_or_create_key(&self) -> Result<Zeroizing<[u8; 32]>, DpgError> {
        self.load(true)
    }

    /// Loads the key from disk; generates one only when `allow_create` is true,
    /// otherwise a missing key is reported as `DPG-K001` (store locked).
    pub fn load(&self, allow_create: bool) -> Result<Zeroizing<[u8; 32]>, DpgError> {
        if !self.path.exists() && !allow_create {
            return Err(key_missing_error());
        }
        if self.path.exists() {
            let bytes = fs::read(&self.path).map_err(|_| DpgError::Internal {
                code: ErrorCode::Z001,
            })?;

            if bytes.len() != 32 {
                return Err(DpgError::Configuration {
                    code: ErrorCode::C001,
                    detail: SafeDetail::from_static("Master key file must be exactly 32 bytes"),
                });
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(Zeroizing::new(key))
        } else {
            // Generate 32 bytes using OS CSPRNG
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);

            if let Some(parent) = self.path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            // Create the key file exclusively (never clobber a key written by a racing
            // process) and owner-only (0600) on Unix. On Windows the per-user profile
            // directory ACL restricts access to the current user.
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(&self.path) {
                Ok(mut f) => {
                    use std::io::Write;
                    f.write_all(&key).and_then(|()| f.sync_all()).map_err(|_| {
                        DpgError::Internal {
                            code: ErrorCode::Z001,
                        }
                    })?;
                    Ok(Zeroizing::new(key))
                }
                // Another process created it first: use theirs.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    key.fill(0);
                    self.get_or_create_key()
                }
                Err(_) => Err(DpgError::Internal {
                    code: ErrorCode::Z001,
                }),
            }
        }
    }
}

impl KeyProvider for FileKeyProvider {
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, DpgError> {
        self.get_or_create_key()
    }
}

impl ProjectKeySource for FileKeyProvider {
    fn get_project_key(&self) -> Result<[u8; 32], DpgError> {
        let key = self.master_key()?;
        Ok(*key)
    }
}

/// Keychain service name and account for the mapping master key
/// (`docs/security/KEY_MANAGEMENT.md`).
pub const KEYCHAIN_SERVICE: &str = "dpg";
/// Keychain account holding the mapping master key.
pub const KEYCHAIN_ACCOUNT: &str = "mapping-master-key-v1";

/// Which backend actually supplied the master key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBackend {
    /// OS keychain (Windows Credential Manager, macOS Keychain).
    Keychain,
    /// 0600 key file in the DPG data directory.
    File,
}

impl KeyBackend {
    /// Stable lowercase name used in config and diagnostics.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Keychain => "keychain",
            Self::File => "file",
        }
    }
}

fn key_missing_error() -> DpgError {
    DpgError::Keychain {
        code: ErrorCode::K001,
        detail: SafeDetail::from_static(
            "mapping store locked: key missing (run 'dpg forget --all --reset' to start over)",
        ),
    }
}

/// Loads the master key from the OS keychain, creating it only when `allow_create`.
#[cfg(any(windows, target_os = "macos"))]
fn keychain_master_key(allow_create: bool) -> Result<Zeroizing<[u8; 32]>, DpgError> {
    let unavailable = || DpgError::Keychain {
        code: ErrorCode::K001,
        detail: SafeDetail::from_static("OS keychain unavailable"),
    };
    let entry =
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).map_err(|_| unavailable())?;
    match entry.get_secret() {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            if bytes.len() != 32 {
                return Err(DpgError::Keychain {
                    code: ErrorCode::K001,
                    detail: SafeDetail::from_static("Keychain master key has wrong length"),
                });
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(Zeroizing::new(key))
        }
        Err(keyring::Error::NoEntry) if allow_create => {
            let mut key = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut key[..]);
            entry.set_secret(&key[..]).map_err(|_| unavailable())?;
            Ok(key)
        }
        Err(keyring::Error::NoEntry) => Err(key_missing_error()),
        Err(_) => Err(unavailable()),
    }
}

/// Resolves the master key per `storage.key_backend`.
///
/// * `"keychain"` (default): OS keychain on Windows and macOS. On other platforms
///   (Linux: Secret Service is not wired in v1) it falls back to the 0600 key file
///   and reports [`KeyBackend::File`] so `dpg doctor` can warn.
/// * `"file"`: 0600 key file `<data_dir>/master.key`.
///
/// `allow_create` must be false when a mapping database already exists: a new key
/// over an existing store would orphan every mapping, so DPG reports K001 instead.
pub fn resolve_master_key(
    backend: &str,
    data_dir: &std::path::Path,
    allow_create: bool,
) -> Result<(Zeroizing<[u8; 32]>, KeyBackend), DpgError> {
    let file = FileKeyProvider::new(data_dir.join("master.key"));
    match backend {
        "file" => Ok((file.load(allow_create)?, KeyBackend::File)),
        "keychain" => {
            #[cfg(any(windows, target_os = "macos"))]
            {
                Ok((keychain_master_key(allow_create)?, KeyBackend::Keychain))
            }
            #[cfg(not(any(windows, target_os = "macos")))]
            {
                Ok((file.load(allow_create)?, KeyBackend::File))
            }
        }
        _ => Err(DpgError::Configuration {
            code: ErrorCode::C001,
            detail: SafeDetail::from_static("storage.key_backend must be 'keychain' or 'file'"),
        }),
    }
}

/// Deletes the master key from the selected backend (used by `dpg forget --all --reset`).
pub fn delete_master_key(backend: &str, data_dir: &std::path::Path) -> Result<(), DpgError> {
    let _ = fs::remove_file(data_dir.join("master.key"));
    #[cfg(any(windows, target_os = "macos"))]
    if backend == "keychain" {
        if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(_) => {
                    return Err(DpgError::Keychain {
                        code: ErrorCode::K001,
                        detail: SafeDetail::from_static("Could not delete keychain entry"),
                    })
                }
            }
        }
    }
    let _ = backend;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_fixed_key_provider() {
        let key_bytes = [7u8; 32];
        let provider = FixedKeyProvider::new(key_bytes);
        let key = provider.master_key().expect("master key");
        assert_eq!(*key, key_bytes);
    }

    #[test]
    fn test_file_key_provider_create_and_reload() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = temp.path().join("dpg.key");

        let provider = FileKeyProvider::new(&key_path);
        let key1 = provider.master_key().expect("create key");

        // Reload existing key
        let provider2 = FileKeyProvider::new(&key_path);
        let key2 = provider2.master_key().expect("reload key");

        assert_eq!(*key1, *key2, "Reloaded key must match generated key");
    }

    #[cfg(unix)]
    #[test]
    fn test_file_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let key_path = temp.path().join("dpg.key");
        FileKeyProvider::new(&key_path)
            .master_key()
            .expect("create");
        let mode = std::fs::metadata(&key_path)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "key file must not be group/world accessible"
        );
    }
}
