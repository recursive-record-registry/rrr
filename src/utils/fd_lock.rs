use std::{fmt::Debug, path::Path};

use async_fd_lock::{LockRead, LockWrite};
use async_trait::async_trait;
use tokio::fs::{File, OpenOptions};

use crate::error::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileLockType {
    Write,
    Read,
}

#[async_trait]
pub trait FileLock: Debug + Send + Sync {
    const TYPE: FileLockType;
    type Guard;

    async fn lock(file_path: impl AsRef<Path> + Send, open_options: &OpenOptions) -> Result<Self>
    where
        Self: Sized;
    fn inner(&self) -> &Self::Guard;
    fn inner_mut(&mut self) -> &mut Self::Guard;
    fn file(&self) -> &File;
    fn file_mut(&mut self) -> &mut File;
}

#[derive(Debug)]
pub struct WriteLock {
    guard: async_fd_lock::RwLockWriteGuard<File>,
}

#[async_trait]
impl FileLock for WriteLock {
    const TYPE: FileLockType = FileLockType::Write;
    type Guard = async_fd_lock::RwLockWriteGuard<File>;

    async fn lock(file_path: impl AsRef<Path> + Send, open_options: &OpenOptions) -> Result<Self> {
        let file = open_options.open(file_path).await?;
        let guard = file.lock_write().await?;

        Ok(Self { guard })
    }

    fn inner(&self) -> &Self::Guard {
        &self.guard
    }

    fn inner_mut(&mut self) -> &mut Self::Guard {
        &mut self.guard
    }

    fn file(&self) -> &File {
        self.guard.inner()
    }

    fn file_mut(&mut self) -> &mut File {
        self.guard.inner_mut()
    }
}

#[derive(Debug)]
pub struct ReadLock {
    guard: async_fd_lock::RwLockReadGuard<File>,
}

#[async_trait]
impl FileLock for ReadLock {
    const TYPE: FileLockType = FileLockType::Read;
    type Guard = async_fd_lock::RwLockReadGuard<File>;

    async fn lock(file_path: impl AsRef<Path> + Send, open_options: &OpenOptions) -> Result<Self> {
        let file = open_options.open(file_path).await?;
        let guard = file.lock_read().await?;

        Ok(Self { guard })
    }

    fn inner(&self) -> &Self::Guard {
        &self.guard
    }

    fn inner_mut(&mut self) -> &mut Self::Guard {
        &mut self.guard
    }

    fn file(&self) -> &File {
        self.guard.inner()
    }

    fn file_mut(&mut self) -> &mut File {
        self.guard.inner_mut()
    }
}
