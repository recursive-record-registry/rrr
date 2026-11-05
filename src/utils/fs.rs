//! File system utilities.

use std::{
    ffi::OsString,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use tokio::{fs::File, io::AsyncWriteExt};
use tracing::warn;

use crate::error::Result;

/// Returns the path of the temporary file used by [`replace_file`] to replace the file at `path`:
/// the same path with `.tmp` appended to the file name.
/// Returns `None` if `path` does not end with a file name.
pub fn temporary_path(path: impl AsRef<Path>) -> Option<PathBuf> {
    let path = path.as_ref();
    let mut file_name = OsString::from(path.file_name()?);

    file_name.push(".tmp");

    Some(path.with_file_name(file_name))
}

/// Atomically replaces the file at `path`, or creates it, with one whose contents are written by
/// `write`.
///
/// The contents are written to a temporary file next to `path` (see [`temporary_path`]), which is
/// then renamed over `path`, so that the file is never left incomplete, even if writing fails.
/// If anything fails, the temporary file is removed.
///
/// The temporary file has a fixed name, so the caller must hold a lock that prevents concurrent
/// replacements of the same file, such as a [`crate::utils::fd_lock::WriteLock`].
pub async fn replace_file<W>(path: impl AsRef<Path>, write: W) -> Result<()>
where
    W: AsyncFnOnce(&mut File) -> Result<()>,
{
    let path = path.as_ref();
    let temporary_path = temporary_path(path).ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("not a path to a file: {}", path.display()),
        )
    })?;

    if let Err(error) = write_and_rename(path, &temporary_path, write).await {
        // Do not leave an incomplete file behind.
        match tokio::fs::remove_file(&temporary_path).await {
            Err(remove_error) if remove_error.kind() != ErrorKind::NotFound => {
                warn!(
                    ?temporary_path,
                    %remove_error,
                    "Failed to remove a temporary file."
                );
            }
            _ => {}
        }

        return Err(error);
    }

    // Persist the rename. Not possible on Windows, where directories cannot be opened as files.
    #[cfg(unix)]
    {
        let directory_path = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };

        File::open(directory_path).await?.sync_all().await?;
    }

    Ok(())
}

/// Writes the temporary file, and renames it over `path`.
/// The temporary file is closed when this returns, so that it can be removed on Windows.
async fn write_and_rename<W>(path: &Path, temporary_path: &Path, write: W) -> Result<()>
where
    W: AsyncFnOnce(&mut File) -> Result<()>,
{
    let mut temporary_file = File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(temporary_path)
        .await?;

    write(&mut temporary_file).await?;
    temporary_file.flush().await?;
    temporary_file.sync_all().await?;
    drop(temporary_file);
    tokio::fs::rename(temporary_path, path).await?;

    Ok(())
}
