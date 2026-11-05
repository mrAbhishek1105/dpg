//! Encrypted persistent mapping store on SQLite with AES-256-GCM.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use dpg_core::context::ProjectId;
use dpg_core::error::{DpgError, ErrorCode, SafeDetail};
use dpg_core::types::RuleId;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{params, Connection};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::key::KeyProvider;
use crate::placeholder::{generate_csprng, PlaceholderCat};

type HmacSha256 = Hmac<Sha256>;

mod subtle_eq {
    /// Constant-time byte-slice equality.
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn derive_key(master_key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master_key).unwrap_or_else(|_| {
        let fallback = [0u8; 32];
        <HmacSha256 as Mac>::new_from_slice(&fallback).unwrap_or_else(|_| unreachable!())
    });
    mac.update(label);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Persistent, encrypted store mapping sensitive original values to placeholder tokens.
pub struct MappingStore {
    conn: Mutex<Connection>,
    k_enc: Zeroizing<[u8; 32]>,
    k_index: Zeroizing<[u8; 32]>,
    k_ignore: Zeroizing<[u8; 32]>,
}

/// Associated data binding a ciphertext to its row, so a ciphertext copied into
/// another project's (or placeholder's) row fails authentication.
fn row_aad(project_id: &str, placeholder: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(project_id.len() + placeholder.len() + 8);
    aad.extend_from_slice(b"dpg/v1\0");
    aad.extend_from_slice(project_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(placeholder.as_bytes());
    aad
}

impl MappingStore {
    /// Opens or creates the SQLite mapping database at the given path.
    pub fn open(path: &Path, keys: &dyn KeyProvider) -> Result<Self, DpgError> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let conn = Connection::open(path).map_err(|_| DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Failed to open mapping database"),
        })?;

        Self::init_connection(conn, keys)
    }

    /// Creates an in-memory mapping database primarily for unit testing.
    pub fn in_memory(keys: &dyn KeyProvider) -> Result<Self, DpgError> {
        let conn = Connection::open_in_memory().map_err(|_| DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Failed to open in-memory database"),
        })?;

        Self::init_connection(conn, keys)
    }

    fn init_connection(conn: Connection, keys: &dyn KeyProvider) -> Result<Self, DpgError> {
        let master = keys.master_key()?;
        let k_enc = Zeroizing::new(derive_key(&master, b"dpg/encryption/v1"));
        let k_index = Zeroizing::new(derive_key(&master, b"dpg/index/v1"));
        let k_ignore = Zeroizing::new(derive_key(&master, b"dpg/ignore/v1"));

        // Configure SQLite performance and concurrency
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 2000;
             PRAGMA synchronous = NORMAL;",
        )
        .map_err(|_| DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Failed to set SQLite PRAGMAs"),
        })?;

        // Initialize schema
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS mapping (
                project_id   TEXT NOT NULL,
                placeholder  TEXT NOT NULL,
                value        BLOB NOT NULL,
                value_mac    BLOB NOT NULL,
                category     TEXT NOT NULL,
                created_at   INTEGER NOT NULL,
                last_used_at INTEGER NOT NULL,
                PRIMARY KEY (project_id, placeholder),
                UNIQUE (project_id, value_mac)
            );
            CREATE TABLE IF NOT EXISTS ignore_fp (
                project_id   TEXT NOT NULL,
                fingerprint  BLOB NOT NULL,
                rule_id      TEXT NOT NULL,
                created_at   INTEGER NOT NULL,
                PRIMARY KEY (project_id, fingerprint)
            );
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS key_check (
                id  INTEGER PRIMARY KEY CHECK (id = 1),
                mac BLOB NOT NULL
            );",
        )
        .map_err(|_| DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Failed to create database schema"),
        })?;

        // PM-05: verify the key before any use. A wrong key fails `open`, and the
        // database is left untouched.
        let expected = derive_key(&master, b"dpg/key-check/v1");
        let stored: Option<Vec<u8>> = conn
            .query_row("SELECT mac FROM key_check WHERE id = 1", [], |r| r.get(0))
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to read key check"),
            })?;
        match stored {
            Some(mac) => {
                use subtle_eq::ct_eq;
                if !ct_eq(&mac, &expected) {
                    return Err(DpgError::MappingStore {
                        code: ErrorCode::M001,
                        detail: SafeDetail::from_static("Mapping store key mismatch"),
                    });
                }
            }
            None => {
                let rows: i64 = conn
                    .query_row("SELECT COUNT(*) FROM mapping", [], |r| r.get(0))
                    .unwrap_or(1);
                if rows > 0 {
                    // Legacy store without a verifier: cannot prove the key matches.
                    return Err(DpgError::MappingStore {
                        code: ErrorCode::M001,
                        detail: SafeDetail::from_static("Mapping store has no key check"),
                    });
                }
                conn.execute(
                    "INSERT INTO key_check (id, mac) VALUES (1, ?1)",
                    params![&expected[..]],
                )
                .map_err(|_| DpgError::MappingStore {
                    code: ErrorCode::M001,
                    detail: SafeDetail::from_static("Failed to write key check"),
                })?;
            }
        }

        Ok(Self {
            conn: Mutex::new(conn),
            k_enc,
            k_index,
            k_ignore,
        })
    }

    /// Key for ignore-list fingerprints (`HMAC(k_ignore, rule || value)`), derived from
    /// the master key so fingerprints cannot be brute-forced without it.
    pub fn ignore_fingerprint_key(&self) -> [u8; 32] {
        *self.k_ignore
    }

    fn compute_value_mac(&self, project_id: &str, value: &str) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.k_index[..]).unwrap_or_else(|_| {
            let fallback = [0u8; 32];
            <HmacSha256 as Mac>::new_from_slice(&fallback).unwrap_or_else(|_| unreachable!())
        });
        // Scope the index MAC to the project so equal values are unlinkable across projects.
        mac.update(project_id.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        let res = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    fn encrypt_value(&self, value: &str, aad: &[u8]) -> Result<Vec<u8>, DpgError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.k_enc[..]).map_err(|_| DpgError::Internal {
                code: ErrorCode::Z001,
            })?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: value.as_bytes(),
                    aad,
                },
            )
            .map_err(|_| DpgError::Internal {
                code: ErrorCode::Z001,
            })?;

        let mut payload = Vec::with_capacity(12 + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);
        Ok(payload)
    }

    fn decrypt_value(&self, payload: &[u8], aad: &[u8]) -> Result<String, DpgError> {
        if payload.len() < 12 {
            return Err(DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Payload too short for AES-GCM"),
            });
        }

        let cipher =
            Aes256Gcm::new_from_slice(&self.k_enc[..]).map_err(|_| DpgError::Internal {
                code: ErrorCode::Z001,
            })?;

        let nonce = Nonce::from_slice(&payload[..12]);
        let ciphertext = &payload[12..];

        let plaintext = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to decrypt secret with master key"),
            })?;

        String::from_utf8(plaintext).map_err(|_| DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Decrypted secret is not valid UTF-8"),
        })
    }

    /// Retrieves an existing placeholder for `(project_id, value)` or generates and persists a new one.
    pub fn get_or_create(
        &self,
        project_id: &ProjectId,
        value: &str,
        cat: PlaceholderCat,
    ) -> Result<String, DpgError> {
        let value_mac = self.compute_value_mac(project_id.as_str(), value);
        let now = current_timestamp();
        let proj_str = project_id.as_str();

        let conn = self.conn.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;

        // 1. Check if mapping already exists
        let mut select_stmt = conn
            .prepare(
                "SELECT placeholder FROM mapping WHERE project_id = ?1 AND value_mac = ?2 LIMIT 1",
            )
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to prepare lookup query"),
            })?;

        let mut rows = select_stmt
            .query(params![proj_str, &value_mac[..]])
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to execute lookup query"),
            })?;

        if let Some(row) = rows.next().map_err(|_| DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Failed to read lookup row"),
        })? {
            let placeholder: String = row.get(0).map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to read placeholder column"),
            })?;

            // Update last_used_at
            let _ = conn.execute(
                "UPDATE mapping SET last_used_at = ?1 WHERE project_id = ?2 AND placeholder = ?3",
                params![now, proj_str, &placeholder],
            );

            return Ok(placeholder);
        }
        drop(rows);
        drop(select_stmt);

        // 2. Generate and encrypt new mapping (ciphertext is bound to project + placeholder)
        for _ in 0..10 {
            let candidate_placeholder = generate_csprng(cat);
            let encrypted_payload =
                self.encrypt_value(value, &row_aad(proj_str, &candidate_placeholder))?;

            let res = conn.execute(
                "INSERT INTO mapping (project_id, placeholder, value, value_mac, category, created_at, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    proj_str,
                    &candidate_placeholder,
                    &encrypted_payload,
                    &value_mac[..],
                    cat.as_str(),
                    now,
                    now,
                ],
            );

            match res {
                Ok(_) => return Ok(candidate_placeholder),
                Err(rusqlite::Error::SqliteFailure(err, _))
                    if err.extended_code == 2067 /* SQLITE_CONSTRAINT_UNIQUE */ =>
                {
                    // Unique constraint violation: check if another thread inserted same value_mac
                    let mut check_stmt = conn
                        .prepare(
                            "SELECT placeholder FROM mapping WHERE project_id = ?1 AND value_mac = ?2 LIMIT 1",
                        )
                        .map_err(|_| DpgError::MappingStore {
                            code: ErrorCode::M001,
                            detail: SafeDetail::from_static("Failed to prepare conflict lookup"),
                        })?;

                    if let Ok(mut check_rows) = check_stmt.query(params![proj_str, &value_mac[..]]) {
                        if let Ok(Some(existing_row)) = check_rows.next() {
                            if let Ok(existing_ph) = existing_row.get(0) {
                                return Ok(existing_ph);
                            }
                        }
                    }
                    // Otherwise placeholder collision; retry with new candidate
                    continue;
                }
                Err(_) => {
                    return Err(DpgError::MappingStore {
                        code: ErrorCode::M001,
                        detail: SafeDetail::from_static("Failed to insert mapping row"),
                    });
                }
            }
        }

        Err(DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Exhausted retries generating unique placeholder"),
        })
    }

    /// Looks up and decrypts the original secret value for a given placeholder.
    pub fn lookup(
        &self,
        project_id: &ProjectId,
        placeholder: &str,
    ) -> Result<Option<String>, DpgError> {
        let conn = self.conn.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;

        let mut stmt = conn
            .prepare("SELECT value FROM mapping WHERE project_id = ?1 AND placeholder = ?2 LIMIT 1")
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to prepare lookup statement"),
            })?;

        let mut rows = stmt
            .query(params![project_id.as_str(), placeholder])
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to query placeholder"),
            })?;

        if let Some(row) = rows.next().map_err(|_| DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Failed to read row"),
        })? {
            let payload: Vec<u8> = row.get(0).map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to read value blob"),
            })?;

            let decrypted =
                self.decrypt_value(&payload, &row_aad(project_id.as_str(), placeholder))?;

            // Touch last_used_at
            let now = current_timestamp();
            let _ = conn.execute(
                "UPDATE mapping SET last_used_at = ?1 WHERE project_id = ?2 AND placeholder = ?3",
                params![now, project_id.as_str(), placeholder],
            );

            Ok(Some(decrypted))
        } else {
            Ok(None)
        }
    }

    /// Forgets all stored mappings for a specific project.
    pub fn forget_project(&self, project_id: &ProjectId) -> Result<u64, DpgError> {
        let conn = self.conn.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;

        let rows_deleted = conn
            .execute(
                "DELETE FROM mapping WHERE project_id = ?1",
                params![project_id.as_str()],
            )
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to delete project mappings"),
            })?;

        let _ = conn.execute(
            "DELETE FROM ignore_fp WHERE project_id = ?1",
            params![project_id.as_str()],
        );

        Ok(rows_deleted as u64)
    }

    /// Forgets all stored mappings across all projects.
    pub fn forget_all(&self) -> Result<u64, DpgError> {
        let conn = self.conn.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;

        let rows_deleted =
            conn.execute("DELETE FROM mapping", [])
                .map_err(|_| DpgError::MappingStore {
                    code: ErrorCode::M001,
                    detail: SafeDetail::from_static("Failed to purge mapping table"),
                })?;

        let _ = conn.execute("DELETE FROM ignore_fp", []);

        Ok(rows_deleted as u64)
    }

    /// Purges mappings not used within the given retention period in days.
    pub fn purge_expired(&self, now: i64, days: u32) -> Result<u64, DpgError> {
        let cutoff = now - (days as i64 * 86400);

        let conn = self.conn.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;

        let rows_deleted = conn
            .execute(
                "DELETE FROM mapping WHERE last_used_at < ?1",
                params![cutoff],
            )
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to purge expired mappings"),
            })?;

        Ok(rows_deleted as u64)
    }

    /// Adds a finding fingerprint to the persistent ignore list for a project.
    pub fn ignore(
        &self,
        project_id: &ProjectId,
        fp: &dpg_policy::Fingerprint,
        rule_id: &RuleId,
    ) -> Result<(), DpgError> {
        let now = current_timestamp();
        let conn = self.conn.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;

        conn.execute(
            "INSERT OR REPLACE INTO ignore_fp (project_id, fingerprint, rule_id, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![project_id.as_str(), &fp.0[..], rule_id.as_str(), now],
        )
        .map_err(|_| DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Failed to insert ignore fingerprint"),
        })?;

        Ok(())
    }

    /// Lists `(rule_id, created_at)` of ignored findings for a project (never values).
    pub fn list_ignores(&self, project_id: &ProjectId) -> Result<Vec<(String, i64)>, DpgError> {
        let err = || DpgError::MappingStore {
            code: ErrorCode::M001,
            detail: SafeDetail::from_static("Failed to list ignore entries"),
        };
        let conn = self.conn.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;
        let mut stmt = conn
            .prepare(
                "SELECT rule_id, created_at FROM ignore_fp WHERE project_id = ?1 ORDER BY created_at",
            )
            .map_err(|_| err())?;
        let rows = stmt
            .query_map(params![project_id.as_str()], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|_| err())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|_| err())
    }

    /// Removes a finding fingerprint from the ignore list.
    pub fn remove_ignore(
        &self,
        project_id: &ProjectId,
        fp: &dpg_policy::Fingerprint,
    ) -> Result<bool, DpgError> {
        let conn = self.conn.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;

        let deleted = conn
            .execute(
                "DELETE FROM ignore_fp WHERE project_id = ?1 AND fingerprint = ?2",
                params![project_id.as_str(), &fp.0[..]],
            )
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to delete ignore fingerprint"),
            })?;

        Ok(deleted > 0)
    }
}

impl dpg_policy::IgnoreList for MappingStore {
    fn is_ignored(
        &self,
        project: &ProjectId,
        fp: &dpg_policy::Fingerprint,
    ) -> Result<bool, DpgError> {
        let conn = self.conn.lock().map_err(|_| DpgError::Internal {
            code: ErrorCode::Z001,
        })?;

        let mut stmt = conn
            .prepare("SELECT 1 FROM ignore_fp WHERE project_id = ?1 AND fingerprint = ?2 LIMIT 1")
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to prepare ignore query"),
            })?;

        let mut rows = stmt
            .query(params![project.as_str(), &fp.0[..]])
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to execute ignore query"),
            })?;

        Ok(rows
            .next()
            .map_err(|_| DpgError::MappingStore {
                code: ErrorCode::M001,
                detail: SafeDetail::from_static("Failed to read ignore row"),
            })?
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::key::FixedKeyProvider;
    use dpg_policy::IgnoreList;

    #[test]
    fn test_sr_pm_01_same_value_same_placeholder() {
        let keys = FixedKeyProvider::new([1u8; 32]);
        let store = MappingStore::in_memory(&keys).expect("store init");
        let project = ProjectId::new("proj-alpha".to_string());
        let secret = &format!("{}{}", "sk-live-", "1234567890abcdef");

        let ph1 = store
            .get_or_create(&project, secret, PlaceholderCat::Secret)
            .expect("first insert");
        let ph2 = store
            .get_or_create(&project, secret, PlaceholderCat::Secret)
            .expect("second insert");

        assert_eq!(
            ph1, ph2,
            "PM-01: Same value in same project must yield identical placeholder"
        );
    }

    #[test]
    fn test_sr_pm_02_different_projects_independent_placeholders() {
        let keys = FixedKeyProvider::new([1u8; 32]);
        let store = MappingStore::in_memory(&keys).expect("store init");
        let proj_a = ProjectId::new("proj-a".to_string());
        let proj_b = ProjectId::new("proj-b".to_string());
        let secret = "same-shared-secret-val-1234";

        let ph_a = store
            .get_or_create(&proj_a, secret, PlaceholderCat::Secret)
            .expect("proj A insert");
        let ph_b = store
            .get_or_create(&proj_b, secret, PlaceholderCat::Secret)
            .expect("proj B insert");

        assert_ne!(
            ph_a, ph_b,
            "PM-02: Different projects must produce different placeholders"
        );

        // Project B cannot restore Project A's placeholder
        let lookup_cross = store.lookup(&proj_b, &ph_a).expect("cross lookup");
        assert!(
            lookup_cross.is_none(),
            "PM-02: Project B must not restore Project A placeholder"
        );
    }

    #[test]
    fn test_sr_pm_05_wrong_key_fails_decryption() {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("store.db");

        let key1 = FixedKeyProvider::new([10u8; 32]);
        let store1 = MappingStore::open(&db_path, &key1).expect("open store 1");
        let project = ProjectId::new("proj-1".to_string());

        let ph = store1
            .get_or_create(&project, "secret-data-123", PlaceholderCat::Secret)
            .expect("insert store 1");
        drop(store1);

        let before = std::fs::read(&db_path).expect("read db");

        // Open with completely different key: open itself must fail, DB untouched.
        let key2 = FixedKeyProvider::new([20u8; 32]);
        let err = match MappingStore::open(&db_path, &key2) {
            Ok(_) => panic!("PM-05: open with wrong key must fail"),
            Err(e) => e,
        };
        assert_eq!(err.code(), ErrorCode::M001);
        assert_eq!(std::fs::read(&db_path).expect("read db"), before);

        // Right key still works.
        let store1 = MappingStore::open(&db_path, &key1).expect("reopen");
        assert_eq!(
            store1.lookup(&project, &ph).expect("lookup").as_deref(),
            Some("secret-data-123")
        );
    }

    #[test]
    fn test_sr_pm_04_no_plaintext_secrets_in_db_bytes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("store.db");

        let keys = FixedKeyProvider::new([42u8; 32]);
        let store = MappingStore::open(&db_path, &keys).expect("open store");
        let project = ProjectId::new("proj-sec".to_string());

        let secret = "SUPER_SECRET_PLAINTEXT_CANARY_VALUE_XYZ999";
        store
            .get_or_create(&project, secret, PlaceholderCat::Secret)
            .expect("insert canary");
        drop(store);

        // Read all raw bytes of the SQLite database file
        let db_bytes = std::fs::read(&db_path).expect("read db bytes");
        let db_str = String::from_utf8_lossy(&db_bytes);

        assert!(
            !db_str.contains(secret),
            "PM-04: Plaintext secret CANARY must NEVER appear in raw database file bytes!"
        );
    }

    #[test]
    fn test_sr_pm_06_forget_and_purge() {
        let keys = FixedKeyProvider::new([1u8; 32]);
        let store = MappingStore::in_memory(&keys).expect("store init");
        let project = ProjectId::new("proj-forget".to_string());

        let ph = store
            .get_or_create(&project, "test-secret-to-forget", PlaceholderCat::Secret)
            .expect("insert");

        let deleted = store.forget_project(&project).expect("forget");
        assert_eq!(deleted, 1);

        let lookup = store.lookup(&project, &ph).expect("lookup after forget");
        assert!(lookup.is_none(), "Forgotten mapping must not be found");
    }

    #[test]
    fn test_store_ignore_list_integration() {
        let keys = FixedKeyProvider::new([1u8; 32]);
        let store = MappingStore::in_memory(&keys).expect("store init");
        let project = ProjectId::new("proj-ignore".to_string());
        let fp = dpg_policy::Fingerprint([99u8; 16]);
        let rule = RuleId::from_static("dpg.rule");

        assert!(!store.is_ignored(&project, &fp).expect("is_ignored"));

        store.ignore(&project, &fp, &rule).expect("ignore");
        assert!(store.is_ignored(&project, &fp).expect("is_ignored"));

        store.remove_ignore(&project, &fp).expect("remove_ignore");
        assert!(!store.is_ignored(&project, &fp).expect("is_ignored"));
    }

    #[test]
    fn test_sr_pm_03_concurrent_access() {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("concurrent.db");

        let key = FixedKeyProvider::new([55u8; 32]);
        // Initial open to initialize schema
        {
            let _ = MappingStore::open(&db_path, &key).expect("init open");
        }

        let mut handles = vec![];
        for thread_idx in 0..8 {
            let path = db_path.clone();
            let key_clone = key.clone();
            handles.push(std::thread::spawn(move || {
                let store = MappingStore::open(&path, &key_clone).expect("thread open");
                let project = ProjectId::new("proj-concurrent".to_string());
                for i in 0..20 {
                    let secret = format!("thread-{thread_idx}-secret-{i}");
                    let ph = store
                        .get_or_create(&project, &secret, PlaceholderCat::Secret)
                        .expect("thread insert");
                    let restored = store
                        .lookup(&project, &ph)
                        .expect("thread lookup")
                        .expect("found");
                    assert_eq!(restored, secret);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread join");
        }
    }

    #[test]
    fn test_ciphertext_moved_to_other_project_fails_auth() {
        let keys = crate::key::FixedKeyProvider::new([21u8; 32]);
        let store = MappingStore::in_memory(&keys).expect("store");
        let a = ProjectId::new("proj-a".to_string());
        let b = ProjectId::new("proj-b".to_string());
        let ph = store
            .get_or_create(&a, "moved_secret_value_1234", PlaceholderCat::Secret)
            .expect("insert");
        store
            .conn
            .lock()
            .expect("lock")
            .execute("UPDATE mapping SET project_id = 'proj-b'", [])
            .expect("tamper");
        let err = store
            .lookup(&b, &ph)
            .expect_err("AAD must reject moved row");
        assert_eq!(err.code(), ErrorCode::M001);
    }
}
