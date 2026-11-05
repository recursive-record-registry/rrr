//! Locks on dedicated lock files.
//!
//! A lock file only exists to be locked: it is never read, written to, truncated or deleted.
//! The files whose access it synchronizes are not locked themselves. Instead, writers replace
//! them atomically, by writing a temporary file and renaming it over the original.
//!
//! Lock files are never deleted, because a process waiting to lock a deleted file would end
//! up holding a lock on a file that no longer exists at that path, while another process
//! locks a new file created at the same path.

use std::{fmt::Debug, io::ErrorKind, path::Path};

use async_fd_lock::{LockRead, LockWrite, RwLockReadGuard, RwLockWriteGuard};
use async_trait::async_trait;
use tokio::fs::File;
use tracing::warn;

use crate::error::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileLockType {
    Write,
    Read,
}

/// A lock on a lock file, held until it is dropped.
#[async_trait]
pub trait FileLock: Debug + Send + Sync + Sized {
    const TYPE: FileLockType;

    /// Waits for and acquires a lock on the lock file at `lock_path`, creating the lock file if
    /// it does not exist.
    async fn lock(lock_path: impl AsRef<Path> + Send) -> Result<Self>;
}

/// An exclusive lock, held by writers.
#[derive(Debug)]
pub struct WriteLock {
    _guard: RwLockWriteGuard<File>,
}

#[async_trait]
impl FileLock for WriteLock {
    const TYPE: FileLockType = FileLockType::Write;

    async fn lock(lock_path: impl AsRef<Path> + Send) -> Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(lock_path)
            .await?;

        Ok(Self {
            _guard: file.lock_write().await?,
        })
    }
}

/// A shared lock, held by readers.
///
/// If the lock file does not exist and cannot be created, such as on a read-only file system,
/// no lock is held. See [`ReadLock::is_locked`].
#[derive(Debug)]
pub struct ReadLock {
    guard: Option<RwLockReadGuard<File>>,
}

impl ReadLock {
    /// Returns `false` if no lock is held, because the lock file does not exist and could not be
    /// created.
    pub fn is_locked(&self) -> bool {
        self.guard.is_some()
    }
}

#[async_trait]
impl FileLock for ReadLock {
    const TYPE: FileLockType = FileLockType::Read;

    async fn lock(lock_path: impl AsRef<Path> + Send) -> Result<Self> {
        let lock_path = lock_path.as_ref();
        let file = match File::open(lock_path).await {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let result = File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(lock_path)
                    .await;

                match result {
                    Ok(file) => file,
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
                        ) =>
                    {
                        warn!(
                            ?lock_path,
                            %error,
                            "The lock file does not exist and cannot be created. \
                            Proceeding without a lock."
                        );
                        return Ok(Self { guard: None });
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        };

        Ok(Self {
            guard: Some(file.lock_read().await?),
        })
    }
}
