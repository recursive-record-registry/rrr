use std::fmt::Display;

use crate::{error::Result, registry::Registry, utils::serde::BytesOrAscii};
use async_trait::async_trait;
use derive_more::{Deref, DerefMut};
use futures::TryStreamExt;
use itertools::Itertools;
use thiserror::Error;

use super::{HashRecordPath, HashedRecordKey, RecordKey};

pub type RecordName = BytesOrAscii<Vec<u8>>;

#[derive(Clone, Debug, Deref, DerefMut)]
pub struct RecordPath {
    record_names: Vec<RecordName>,
}

impl RecordPath {
    pub fn first(&self) -> &RecordName {
        self.record_names
            .first()
            .expect("`record_names` must not be empty")
    }

    pub fn last(&self) -> &RecordName {
        self.record_names
            .last()
            .expect("`record_names` must not be empty")
    }
}

impl Default for RecordPath {
    fn default() -> Self {
        Self {
            record_names: vec![Default::default()],
        }
    }
}

impl IntoIterator for RecordPath {
    type IntoIter = std::vec::IntoIter<Self::Item>;
    type Item = RecordName;

    fn into_iter(self) -> Self::IntoIter {
        self.record_names.into_iter()
    }
}

#[derive(Error, Debug)]
#[error("the record path must contain at least one record name")]
pub struct EmptyRecordPathError;

impl TryFrom<Vec<RecordName>> for RecordPath {
    type Error = EmptyRecordPathError;

    fn try_from(record_names: Vec<RecordName>) -> std::result::Result<Self, Self::Error> {
        if record_names.is_empty() {
            Err(EmptyRecordPathError)
        } else {
            Ok(Self { record_names })
        }
    }
}

impl Display for RecordPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.iter().format(" "))
    }
}

#[async_trait]
impl HashRecordPath for RecordPath {
    async fn hash_record_path<L>(&self, registry: &Registry<L>) -> Result<HashedRecordKey>
    where
        L: Sync,
    {
        let mut record_names_iter = self.iter();
        let hashed_record_key_root = RecordKey {
            record_name: record_names_iter
                .next()
                .expect("record path should never be empty")
                .clone(),
            predecessor_nonce: registry
                .config
                .kdf
                .get_root_record_predecessor_nonce()
                .clone(),
        }
        .hash(&registry.config.hash)
        .await?;
        let predecessor_nonce = futures::stream::iter(record_names_iter.cloned().map(Ok))
            .try_fold(
                hashed_record_key_root,
                async |hashed_record_key: HashedRecordKey, record_name| {
                    let predecessor_nonce = hashed_record_key
                        .derive_succession_nonce(&registry.config.kdf)
                        .await?;
                    let record_key = RecordKey {
                        record_name,
                        predecessor_nonce,
                    };

                    record_key.hash(&registry.config.hash).await
                },
            )
            .await?;

        Ok(predecessor_nonce)
    }
}
