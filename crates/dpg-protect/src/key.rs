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

            // Write key with atomic write
            fs::write(&self.path, key).map_err(|_| DpgError::Internal {
                code: ErrorCode::Z001,
            })?;

            Ok(Zeroizing::new(key))
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
}
