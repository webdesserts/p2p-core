//! Exclusive daemon lock to prevent multiple daemons on the same vault.
//!
//! Uses `flock(2)` via the `fs2` crate to hold an exclusive advisory lock on
//! `.sync/daemon.lock`. The OS automatically releases the lock when the process
//! exits (even on SIGKILL), so stale lock files from crashed daemons are harmless.

use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use thiserror::Error;

const LOCK_FILE: &str = ".sync/daemon.lock";

#[derive(Error, Debug)]
pub enum LockError {
    #[error("another daemon is already running on this vault")]
    AlreadyLocked,
    #[error("failed to acquire daemon lock: {0}")]
    Io(#[from] std::io::Error),
}

/// Holds an exclusive flock on `.sync/daemon.lock` for the daemon's lifetime.
///
/// The lock is synchronous (flock is a syscall with no async benefit).
/// On drop, the flock is released by the OS when the File handle closes,
/// and we best-effort delete the lock file.
pub struct DaemonLock {
    _file: File,
    path: PathBuf,
}

impl DaemonLock {
    /// Try to acquire an exclusive flock on `.sync/daemon.lock`.
    ///
    /// Creates `.sync/` if it doesn't exist. Returns `LockError::AlreadyLocked`
    /// if another process holds the lock.
    pub fn acquire(vault_path: &Path) -> Result<Self, LockError> {
        let path = vault_path.join(LOCK_FILE);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;

        file.try_lock_exclusive()
            .map_err(|_| LockError::AlreadyLocked)?;

        Ok(DaemonLock { _file: file, path })
    }

    /// Release the lock and delete the lock file.
    pub fn release(self) -> Result<(), LockError> {
        self._file.unlock()?;
        let _ = fs::remove_file(&self.path);
        Ok(())
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        // flock auto-releases when File drops, but we also best-effort delete the file
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_vault() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".sync")).unwrap();
        dir
    }

    #[test]
    fn acquire_succeeds_on_fresh_vault() {
        let dir = setup_vault();
        let lock = DaemonLock::acquire(dir.path());
        assert!(lock.is_ok(), "Should acquire lock on fresh vault");
    }

    #[test]
    fn acquire_fails_when_another_lock_is_held() {
        let dir = setup_vault();
        let _lock1 = DaemonLock::acquire(dir.path()).unwrap();
        let lock2 = DaemonLock::acquire(dir.path());
        assert!(lock2.is_err(), "Should fail when another lock is held");
    }

    #[test]
    fn release_allows_reacquisition() {
        let dir = setup_vault();
        let lock = DaemonLock::acquire(dir.path()).unwrap();
        lock.release().unwrap();
        let lock2 = DaemonLock::acquire(dir.path());
        assert!(lock2.is_ok(), "Should acquire after explicit release");
    }

    #[test]
    fn drop_releases_lock() {
        let dir = setup_vault();
        {
            let _lock = DaemonLock::acquire(dir.path()).unwrap();
            // lock drops here
        }
        let lock2 = DaemonLock::acquire(dir.path());
        assert!(lock2.is_ok(), "Should acquire after drop releases lock");
    }

    #[test]
    fn stale_lock_file_is_cleaned_up_on_acquire() {
        let dir = setup_vault();
        let lock_path = dir.path().join(".sync/daemon.lock");

        // Simulate a stale lock file left by a crashed process (no flock held)
        fs::write(&lock_path, "stale").unwrap();
        assert!(lock_path.exists());

        let lock = DaemonLock::acquire(dir.path());
        assert!(lock.is_ok(), "Should acquire despite stale lock file");
    }
}
