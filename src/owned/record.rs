use chrono::{DateTime, Utc};
use futures::future::{BoxFuture, FutureExt};
use std::{
    collections::HashSet,
    fmt::Debug,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncWriteExt};

#[derive(Debug, Serialize, Deserialize)]
pub struct OwnedRecordMetadata {
    pub created_at: Option<toml::value::Datetime>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OwnedRecordConfig {
    pub name: ByteBuf,
    pub metadata: OwnedRecordMetadata,
}

#[derive(Debug)]
pub struct OwnedRecord {
    pub directory_path: PathBuf,
    pub config: OwnedRecordConfig,
    pub successive_records: Vec<OwnedRecord>,
}

impl OwnedRecord {
    pub fn load_from_directory<'a>(
        directory_path: impl AsRef<Path> + Send + Sync + 'a,
    ) -> BoxFuture<'a, Result<Self>> {
        async move {
            let config = Self::load_config(&directory_path).await?;
            let mut successive_records_stream = tokio::fs::read_dir(&directory_path).await?;
            let mut successive_records = Vec::new();
            let mut successive_record_names = HashSet::new();

            while let Some(entry) = successive_records_stream.next_entry().await? {
                if entry.metadata().await?.is_dir() {
                    let successive_record_directory = entry.path();
                    let successive_record =
                        OwnedRecord::load_from_directory(&successive_record_directory).await?;
                    let successive_record_name_unique =
                        successive_record_names.insert(successive_record.config.name.clone());

                    if successive_record_name_unique {
                        successive_records.push(successive_record);
                    } else {
                        return Err(Error::DuplicateSuccessiveRecord {
                            parent: directory_path.as_ref().to_owned(),
                            name: successive_record.config.name.to_vec(),
                        });
                    }
                }
            }

            Ok(Self {
                directory_path: directory_path.as_ref().to_owned(),
                config,
                successive_records,
            })
        }
        .boxed()
    }

    pub async fn save(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.directory_path).await?;

        let config_string = toml::to_string_pretty(&self.config)?;
        let mut config_file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&self.get_config_path())
            .await?;

        config_file.write_all(config_string.as_bytes()).await?;

        Ok(())
    }

    pub async fn load_config(directory_path: impl AsRef<Path>) -> Result<OwnedRecordConfig> {
        match tokio::fs::read_to_string(Self::get_config_path_from_record_directory_path(
            &directory_path,
        ))
        .await
        {
            Ok(config_string) => {
                toml::from_str::<OwnedRecordConfig>(&config_string).map_err(Into::into)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let file_name = directory_path.as_ref().file_name().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "The record in directory {:?} lacks a name.",
                            directory_path.as_ref()
                        ),
                    )
                })?;
                let file_name_utf8 = file_name.to_str().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Cannot derive a record name from the path segment {file_name:?}, as it is not a valid UTF-8 string.")
                    )
                })?;
                let created_at_system = tokio::fs::metadata(&directory_path).await?.created()?;
                let created_at_chrono = DateTime::<Utc>::from(created_at_system);
                let created_at =
                    toml::value::Datetime::from_str(&created_at_chrono.to_rfc3339()).unwrap();
                Ok(OwnedRecordConfig {
                    name: ByteBuf::from(file_name_utf8.as_bytes()),
                    metadata: OwnedRecordMetadata {
                        created_at: Some(created_at),
                    },
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn read(&self) -> Result<Option<impl AsyncRead>> {
        match tokio::fs::OpenOptions::new()
            .read(true)
            .open(self.get_data_path())
            .await
        {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn get_config_path_from_record_directory_path(directory_path: impl AsRef<Path>) -> PathBuf {
        directory_path.as_ref().join("record.toml")
    }

    pub fn get_config_path(&self) -> PathBuf {
        Self::get_config_path_from_record_directory_path(&self.directory_path)
    }

    pub fn get_data_path(&self) -> PathBuf {
        self.directory_path.join("data")
    }
}
