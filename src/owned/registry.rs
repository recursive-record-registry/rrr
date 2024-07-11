use crate::crypto::kdf::hkdf::HkdfParams;
use crate::crypto::kdf::KdfAlgorithm;
use crate::crypto::password_hash::{argon2::Argon2Params, PasswordHashAlgorithm};
use crate::crypto::signature::{SigningKey, SigningKeyEd25519};
use crate::registry::{
    ConfigParam, KdfInputLengthInBytes, RegistryConfigHash, RegistryConfigKdf,
    SuccessorNonceLengthInBytes,
};
use crate::serde_utils::Secret;
use crate::{crypto::encryption::EncryptionAlgorithm, record::RecordKey};
use serde_with::serde_as;
use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::error::{Error, Result};
use aes_gcm::aead::OsRng;
use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, DecodePrivateKey, EncodePrivateKey};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use super::record::{OwnedRecord, OwnedRecordConfig, OwnedRecordMetadata};

/// Represents a registry with cryptographic credentials for editing.
#[serde_as]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedRegistryConfig {
    pub hash: RegistryConfigHash,
    pub kdf: RegistryConfigKdf,
    pub encryption_algorithm: EncryptionAlgorithm,
    pub root_record_path: PathBuf,
    /// Paths to files with signing keys.
    /// These paths are relative to the directory containing the registry config.
    pub signing_key_paths: Vec<PathBuf>,
}

impl OwnedRegistryConfig {
    pub async fn get_root_record_key(&self) -> RecordKey {
        Default::default()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct OwnedRegistry {
    pub directory_path: PathBuf,
    pub config: OwnedRegistryConfig,
    /// Keys loaded from files at `config.signing_key_paths`, in the same order.
    pub signing_keys: Vec<SigningKey>,
}

impl OwnedRegistry {
    pub async fn load(directory_path: impl Into<PathBuf>) -> Result<Self> {
        let directory_path = directory_path.into();
        let config_string = tokio::fs::read_to_string(
            Self::get_config_path_from_record_directory_path(&directory_path),
        )
        .await?;
        let config = toml::from_str::<OwnedRegistryConfig>(&config_string)?;
        let signing_keys = {
            let mut signing_keys = Vec::new();

            for key_path in &config.signing_key_paths {
                let key_path =
                    Self::get_key_path_from_record_directory_path(&directory_path, key_path);
                let mut file = File::open(&key_path).await?;
                let mut key_bytes = Default::default();

                file.read_to_string(&mut key_bytes).await?;

                let key = SigningKey::from_pkcs8_pem(&key_bytes).unwrap();

                signing_keys.push(key);
            }

            signing_keys
        };

        Ok(Self {
            config,
            directory_path,
            signing_keys,
        })
    }

    /// Creates a new registry with generated cryptographic keys, and the provided root record.
    /// The root record is signed but **not encrypted**, it is the record displayed to the user
    /// upon opening the registry.
    pub async fn generate(directory_path: impl Into<PathBuf>, overwrite: bool) -> Result<Self> {
        let directory_path = directory_path.into();

        // Ensure the registry directory exists.
        match tokio::fs::metadata(&directory_path).await {
            Ok(directory_metadata) if directory_metadata.is_dir() => {
                if !overwrite {
                    let mut dir_entries = tokio::fs::read_dir(&directory_path).await?;

                    if dir_entries.next_entry().await?.is_some() {
                        return Err(Error::RegistryAlreadyExists {
                            path: directory_path,
                        });
                    }
                }
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Not a directory: {:?}", directory_path),
                )
                .into())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::fs::create_dir_all(&directory_path).await?
            }
            Err(error) => return Err(error.into()),
        }

        let signing_keys_directory_relative = PathBuf::from("keys");
        let signing_keys_directory_absolute = directory_path.join(&signing_keys_directory_relative);

        // TODO: Unify with save_config
        tokio::fs::create_dir_all(&directory_path).await?;
        tokio::fs::create_dir(&signing_keys_directory_absolute).await?;

        let mut csprng = OsRng;
        let signing_keys = vec![SigningKey::Ed25519(Secret(SigningKeyEd25519(
            ed25519_dalek::SigningKey::generate(&mut csprng),
        )))];
        let signing_key_paths = {
            let mut signing_key_paths = Vec::new();

            for signing_key in &signing_keys {
                let signing_key_path_relative = signing_keys_directory_relative
                    .join(format!("key_{}.pem", signing_key.key_type_name()));
                let signing_key_path_absolute = directory_path.join(&signing_key_path_relative);
                let pem = signing_key.to_pkcs8_pem(LineEnding::default()).unwrap();
                let mut file = File::create_new(&signing_key_path_absolute).await?;

                file.write_all(pem.as_bytes()).await?;
                signing_key_paths.push(signing_key_path_relative);
            }

            signing_key_paths
        };

        let config = OwnedRegistryConfig {
            hash: RegistryConfigHash {
                algorithm: PasswordHashAlgorithm::Argon2(
                    Argon2Params::default_with_random_pepper_of_recommended_length(&mut csprng),
                ),
                kdf_input_length_in_bytes: ConfigParam::<KdfInputLengthInBytes>::try_from(32)
                    .unwrap(),
                successor_nonce_length_in_bytes:
                    ConfigParam::<SuccessorNonceLengthInBytes>::try_from(32).unwrap(),
            },
            kdf: RegistryConfigKdf {
                algorithm: KdfAlgorithm::Hkdf(HkdfParams::default()),
                file_name_length_in_bytes: ConfigParam::try_from(8).unwrap(),
            },
            encryption_algorithm: EncryptionAlgorithm::A256GCM,
            root_record_path: PathBuf::from("root"),
            signing_key_paths,
        };

        let registry = Self {
            directory_path,
            config,
            signing_keys,
        };

        registry.save_config(overwrite).await?;

        let default_root_record = OwnedRecord {
            directory_path: registry.get_root_record_path(),
            config: OwnedRecordConfig {
                name: Default::default(),
                metadata: OwnedRecordMetadata {
                    created_at: Some(
                        toml::value::Datetime::from_str("1970-01-01T00:00:00Z").unwrap(),
                    ),
                },
            },
            successive_records: Default::default(),
        };

        default_root_record.save().await?;

        Ok(registry)
    }

    pub async fn save_config(&self, overwrite: bool) -> Result<()> {
        let config_string = toml::to_string_pretty(&self.config)?;
        let open_options = {
            let mut open_options = File::options();
            open_options.create(overwrite);
            open_options.create_new(!overwrite);
            open_options.write(true);
            open_options.truncate(true);
            open_options
        };
        let mut config_file = open_options.open(self.get_config_path()).await?;

        config_file.write_all(config_string.as_bytes()).await?;

        Ok(())
    }

    fn get_config_path_from_record_directory_path(directory_path: impl AsRef<Path>) -> PathBuf {
        directory_path.as_ref().join("registry.toml")
    }

    fn get_config_path(&self) -> PathBuf {
        Self::get_config_path_from_record_directory_path(&self.directory_path)
    }

    fn get_key_path_from_record_directory_path(
        directory_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> PathBuf {
        directory_path.as_ref().join(key_path)
    }

    fn get_key_path(&self, key_path: impl AsRef<Path>) -> PathBuf {
        Self::get_key_path_from_record_directory_path(&self.directory_path, key_path)
    }

    fn get_root_record_path(&self) -> PathBuf {
        self.directory_path.join(&self.root_record_path)
    }

    pub async fn load_root_record(&self) -> Result<OwnedRecord> {
        OwnedRecord::load_from_directory(self.get_root_record_path()).await
    }
}

impl Deref for OwnedRegistry {
    type Target = OwnedRegistryConfig;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl DerefMut for OwnedRegistry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}
