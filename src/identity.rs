//! File-backed peer identity: the ed25519 secret key persisted on disk and the
//! `PeerId` derived from it.
//!
//! - **`FileKeyStorage`**: a `KeyStorage` implementation that reads/writes the
//!   raw 32-byte secret key to `.sync/daemon.key` within a vault directory.
//! - **`IdentityKey`**: the loaded ed25519 secret key, from which the device's
//!   `PeerId` is derived.

use anyhow::{Context, Result};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::key_storage::{KeyStorage, KeyStorageError};
use crate::peer_id::PeerId;

const KEY_FILE: &str = ".sync/daemon.key";

/// Filesystem-based ed25519 key storage.
///
/// Reads/writes the key as 32 raw bytes to `.sync/daemon.key` inside the vault.
pub struct FileKeyStorage {
    path: PathBuf,
}

impl FileKeyStorage {
    /// Create a new `FileKeyStorage` rooted at `vault_path`.
    ///
    /// The key file will be read from and written to `{vault_path}/.sync/daemon.key`.
    pub fn new(vault_path: &Path) -> Self {
        Self {
            path: vault_path.join(KEY_FILE),
        }
    }
}

#[async_trait]
impl KeyStorage for FileKeyStorage {
    async fn load_key(&self) -> crate::key_storage::Result<Option<[u8; 32]>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let bytes = tokio::fs::read(&self.path)
            .await
            .map_err(|e| KeyStorageError::Io(e.to_string()))?;

        let key: [u8; 32] = bytes.try_into().map_err(|_| KeyStorageError::InvalidKey)?;

        Ok(Some(key))
    }

    async fn save_key(&self, key: &[u8; 32]) -> crate::key_storage::Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| KeyStorageError::Io(e.to_string()))?;
        }

        tokio::fs::write(&self.path, key.as_slice())
            .await
            .map_err(|e| KeyStorageError::Io(e.to_string()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&self.path, perms)
                .await
                .map_err(|e| KeyStorageError::Io(e.to_string()))?;
        }

        Ok(())
    }
}

/// The daemon's ed25519 secret key, persisted in `.sync/daemon.key`.
///
/// The public key (derived from this secret) is used as the daemon's `PeerId`.
/// On first run, a new keypair is generated and the secret key is written to disk.
/// On subsequent runs, the secret key is loaded to reconstruct a stable identity.
pub struct IdentityKey {
    signing_key: SigningKey,
}

impl IdentityKey {
    /// Load or generate the default identity key at `.sync/daemon.key`.
    ///
    /// Delegates I/O to `FileKeyStorage`, which handles file creation,
    /// permissions, and atomic loading.
    pub async fn load_or_generate(vault_path: &Path) -> Result<Self> {
        let storage = FileKeyStorage::new(vault_path);
        let bytes = storage
            .load_or_generate()
            .await
            .map_err(|e| anyhow::anyhow!("Key storage error: {}", e))?;
        let key = Self::from_bytes(bytes);
        info!(peer_id = %key.peer_id(), "Loaded or generated daemon identity key");
        Ok(key)
    }

    /// Load an identity key from a custom key file path.
    ///
    /// The file must contain exactly 32 bytes (the ed25519 secret key).
    pub fn load_from(key_path: &Path) -> Result<Self> {
        let bytes = fs::read(key_path)
            .with_context(|| format!("Failed to read key file: {}", key_path.display()))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!("Key file must be exactly 32 bytes: {}", key_path.display())
        })?;
        Ok(Self::from_bytes(bytes))
    }

    /// Build an `IdentityKey` from raw secret key bytes.
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    /// Derive the `PeerId` from this identity key's public key.
    ///
    /// Delegates to `PeerId::from_secret_bytes` so the secret-key → device
    /// PeerId derivation lives in one place, shared with the WASM plugin.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_secret_bytes(self.signing_key.to_bytes())
    }

    /// Return the raw 32-byte ed25519 secret key.
    ///
    /// Used to initialize the iroh `SyncNode`, which needs the secret key to
    /// derive a stable `EndpointId` (the iroh equivalent of our `PeerId`).
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ==================== FileKeyStorage tests ====================

    #[tokio::test]
    async fn test_load_key_returns_none_when_file_missing() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path());

        assert!(storage.load_key().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_save_and_load_key() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path());
        let key = [7u8; 32];

        storage.save_key(&key).await.unwrap();

        let loaded = storage.load_key().await.unwrap();
        assert_eq!(loaded, Some(key));
    }

    #[tokio::test]
    async fn test_save_creates_sync_directory() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path());
        let key = [1u8; 32];

        storage.save_key(&key).await.unwrap();

        assert!(temp_dir.path().join(".sync").exists());
        assert!(temp_dir.path().join(".sync/daemon.key").exists());
    }

    #[tokio::test]
    async fn test_key_file_contains_raw_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path());
        let key = [42u8; 32];

        storage.save_key(&key).await.unwrap();

        let raw = tokio::fs::read(temp_dir.path().join(".sync/daemon.key"))
            .await
            .unwrap();
        assert_eq!(raw, key.as_slice());
        assert_eq!(raw.len(), 32);
    }

    #[tokio::test]
    async fn test_load_key_rejects_wrong_length() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join(".sync/daemon.key");

        // Write garbage with wrong length
        tokio::fs::create_dir_all(key_path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&key_path, b"too short").await.unwrap();

        let storage = FileKeyStorage::new(temp_dir.path());
        let result = storage.load_key().await;

        assert!(matches!(result, Err(KeyStorageError::InvalidKey)));
    }

    #[tokio::test]
    async fn test_load_or_generate_persists_across_instances() {
        let temp_dir = TempDir::new().unwrap();

        // First instance generates and saves a key
        let key1 = {
            let storage = FileKeyStorage::new(temp_dir.path());
            storage.load_or_generate().await.unwrap()
        };

        // Second instance should load the same key
        let key2 = {
            let storage = FileKeyStorage::new(temp_dir.path());
            storage.load_or_generate().await.unwrap()
        };

        assert_eq!(key1, key2);
    }

    // ==================== IdentityKey tests ====================

    #[tokio::test]
    async fn test_identity_key_generates_and_saves() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let key = IdentityKey::load_or_generate(vault_path).await.unwrap();
        let peer_id = key.peer_id();

        // Key file should exist with 32 bytes
        let key_path = vault_path.join(".sync/daemon.key");
        assert!(key_path.exists());
        assert_eq!(fs::read(&key_path).unwrap().len(), 32);

        // PeerId should be valid (64-char hex)
        assert_eq!(peer_id.to_string().len(), 64);
        assert_ne!(peer_id.as_u64(), 0);
    }

    #[tokio::test]
    async fn test_identity_key_loads_and_matches() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let key1 = IdentityKey::load_or_generate(vault_path).await.unwrap();
        let peer_id1 = key1.peer_id();

        // Second call should load the same key from disk
        let key2 = IdentityKey::load_or_generate(vault_path).await.unwrap();
        let peer_id2 = key2.peer_id();

        // Should produce the same PeerId after loading
        assert_eq!(peer_id1, peer_id2);
    }

    #[tokio::test]
    async fn test_identity_key_load_from_custom_path() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // Generate a key in a separate location via load_or_generate
        let alt_dir = TempDir::new().unwrap();
        let alt_key = IdentityKey::load_or_generate(alt_dir.path()).await.unwrap();
        let alt_key_path = alt_dir.path().join(".sync/daemon.key");
        let alt_peer_id = alt_key.peer_id();

        // Load via custom path
        let loaded = IdentityKey::load_from(&alt_key_path).unwrap();
        assert_eq!(loaded.peer_id(), alt_peer_id);

        // Should differ from what a default generate would produce
        let default_key = IdentityKey::load_or_generate(vault_path).await.unwrap();
        assert_ne!(default_key.peer_id(), alt_peer_id);
    }

    #[tokio::test]
    async fn test_identity_key_secret_key_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let key = IdentityKey::load_or_generate(vault_path).await.unwrap();
        let bytes = key.secret_key_bytes();

        // Verify round-trip: reconstructing from bytes produces the same PeerId
        let reconstructed = IdentityKey::from_bytes(bytes);
        assert_eq!(reconstructed.peer_id(), key.peer_id());
    }
}
