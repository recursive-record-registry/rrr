use crate::cbor::{TAG_RRR_REGISTRY, TAG_SELF_DESCRIBED_CBOR};
use crate::crypto::kdf::KdfAlgorithm;
use crate::crypto::password_hash::PasswordHashAlgorithm;
use crate::crypto::signature::{SigningKey, VerifyingKey};
use crate::error::{Error, InvalidParameterError, OptionExt, Result};
use crate::record::segment::{
    FragmentFileNameBytes, RecordNonce, RecordVersion, SegmentEncryption,
};
use crate::record::{
    HashRecordPath, Record, RecordListVersionsItem, RecordReadVersionSuccess, SuccessionNonce,
};
use crate::utils::fd_lock::{FileLock, ReadLock, WriteLock};
use crate::utils::serde::{BytesOrHexString, Secret};
use async_scoped::TokioScope;
use casey::pascal;
use coset::{cbor::tag, CoseKey};
use derive_more::{Deref, DerefMut};
use proptest::arbitrary::{any, Arbitrary};
use proptest::collection::vec;
use proptest::prop_compose;
use proptest::strategy::{BoxedStrategy, Just, Strategy};
use proptest_derive::Arbitrary;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt::Display;
use std::ops::{Add, RangeInclusive};
use std::{
    fmt::Debug,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncRead, AsyncWrite},
};
use tokio_util::io::SyncIoBridge;
use tracing::instrument;

pub const BYTES_HASH_PEPPER_RECOMMENDED: usize = 32;

pub trait ConfigParamTrait {
    type T: Ord + Debug + Send + Sync + 'static;
    const LABEL: &'static str;
    // Better readability than `std::any::type_name`, because it does not contain the full path to the type.
    const TYPE_NAME: &'static str;
    const MIN: Self::T;
    const RECOMMENDED: Self::T;
}

#[derive(Error)]
pub struct ConfigParamTooLowError<P: ConfigParamTrait>(P::T);

impl<P> Display for ConfigParamTooLowError<P>
where
    P: ConfigParamTrait,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "parameter {label:?} is set to the value {value:?} lower than the minimum value of {min:?}",
            label = P::LABEL,
            value = self.0,
            min = P::MIN
        )
    }
}

impl<P> Debug for ConfigParamTooLowError<P>
where
    P: ConfigParamTrait,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ConfigParamTooLowError<{type_name}>({inner:?})",
            type_name = P::TYPE_NAME,
            inner = self.0
        )
    }
}

#[derive(Deref, DerefMut)]
pub struct ConfigParam<P: ConfigParamTrait>(P::T);

impl<P> ConfigParam<P>
where
    P: ConfigParamTrait,
{
    pub fn try_from(value: P::T) -> std::result::Result<Self, ConfigParamTooLowError<P>> {
        if value < P::MIN {
            return Err(ConfigParamTooLowError(value));
        }

        if value < P::RECOMMENDED {
            tracing::warn!(
                "parameter {label:?} is set to the value {value:?} lower than the recommended value of {recommended:?}",
                label = P::LABEL,
                value = value,
                recommended = P::RECOMMENDED,
            );
        }

        Ok(Self(value))
    }
}

impl<P> Default for ConfigParam<P>
where
    P: ConfigParamTrait,
{
    fn default() -> Self {
        Self(P::RECOMMENDED)
    }
}

impl<P> Serialize for ConfigParam<P>
where
    P: ConfigParamTrait,
    P::T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, P> Deserialize<'de> for ConfigParam<P>
where
    P: ConfigParamTrait,
    P::T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = P::T::deserialize(deserializer)?;

        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

impl<P> Clone for ConfigParam<P>
where
    P: ConfigParamTrait,
    P::T: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P> Debug for ConfigParam<P>
where
    P: ConfigParamTrait,
    P::T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ConfigParam<{type_name}>({inner:?})",
            type_name = P::TYPE_NAME,
            inner = self.0
        )
    }
}

impl<P> PartialEq for ConfigParam<P>
where
    P: ConfigParamTrait,
    P::T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<P> Eq for ConfigParam<P>
where
    P: ConfigParamTrait,
    P::T: Eq,
{
}

pub fn arb_config_param<P>(max: P::T) -> impl Strategy<Value = ConfigParam<P>>
where
    P: ConfigParamTrait,
    RangeInclusive<P::T>: Strategy<Value = P::T>,
{
    (P::MIN..=max).prop_map(ConfigParam)
}

impl<P> Arbitrary for ConfigParam<P>
where
    P: ConfigParamTrait + 'static,
    P::T: Add<P::T, Output = P::T>,
    RangeInclusive<P::T>: Strategy<Value = P::T>,
{
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        arb_config_param(P::RECOMMENDED + P::RECOMMENDED).boxed()
    }
}

macro_rules! define_config_params {
    ($($label:ident: $ty:ty = $recommended:literal >= $min:literal),+$(,)?) => {
        use stringify as Stringify;

        $(
            const _: () = const { assert!($min <= $recommended); };
            pascal!(pub struct $label;);

            impl ConfigParamTrait for pascal!($label) {
                type T = $ty;
                const LABEL: &'static str = stringify!($label);
                const TYPE_NAME: &'static str = pascal!(stringify!($label));
                const MIN: Self::T = $min;
                const RECOMMENDED: Self::T = $recommended;
            }
        )+
    };
}

define_config_params! {
    output_length_in_bytes: u64 = 32 >= 16,
    succession_nonce_length_in_bytes: u64 = 32 >= 16,
    file_name_length_in_bytes: u64 = 8 >= 1,
    file_tag_length_in_bytes: u64 = 32 >= 16,
    segment_padding_to_bytes: u64 = 1024 >= 256,
}

#[derive(Arbitrary, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryConfigHash {
    pub algorithm: PasswordHashAlgorithm,
    pub output_length_in_bytes: ConfigParam<OutputLengthInBytes>, // TODO/FIXME: Bad type name
}

#[derive(Clone, Debug)]
pub struct RegistryConfigKdfBuilder {
    algorithm: Option<KdfAlgorithm>,
    file_name_length_in_bytes: <FileNameLengthInBytes as ConfigParamTrait>::T,
    file_tag_length_in_bytes: <FileTagLengthInBytes as ConfigParamTrait>::T,
    succession_nonce_length_in_bytes: <SuccessionNonceLengthInBytes as ConfigParamTrait>::T,
}

impl Default for RegistryConfigKdfBuilder {
    fn default() -> Self {
        Self {
            algorithm: Default::default(),
            file_name_length_in_bytes: <FileNameLengthInBytes as ConfigParamTrait>::RECOMMENDED,
            file_tag_length_in_bytes: <FileTagLengthInBytes as ConfigParamTrait>::RECOMMENDED,
            succession_nonce_length_in_bytes:
                <SuccessionNonceLengthInBytes as ConfigParamTrait>::RECOMMENDED,
        }
    }
}

impl RegistryConfigKdfBuilder {
    pub fn with_algorithm(&mut self, algorithm: KdfAlgorithm) -> &mut Self {
        self.algorithm = Some(algorithm);
        self
    }

    pub fn with_file_name_length_in_bytes(
        &mut self,
        file_name_length_in_bytes: <FileNameLengthInBytes as ConfigParamTrait>::T,
    ) -> &mut Self {
        self.file_name_length_in_bytes = file_name_length_in_bytes;
        self
    }

    pub fn with_file_tag_length_in_bytes(
        &mut self,
        file_tag_length_in_bytes: <FileTagLengthInBytes as ConfigParamTrait>::T,
    ) -> &mut Self {
        self.file_tag_length_in_bytes = file_tag_length_in_bytes;
        self
    }

    pub fn with_succession_nonce_length_in_bytes(
        &mut self,
        succession_nonce_length_in_bytes: <SuccessionNonceLengthInBytes as ConfigParamTrait>::T,
    ) -> &mut Self {
        self.succession_nonce_length_in_bytes = succession_nonce_length_in_bytes;
        self
    }

    pub fn build(&self, root_predecessor_nonce: SuccessionNonce) -> Result<RegistryConfigKdf> {
        let algorithm = self.algorithm.unwrap_builder_parameter("algorithm")?;
        let file_name_length_in_bytes = ConfigParam::try_from(self.file_name_length_in_bytes)
            .map_err(InvalidParameterError::from)?;
        let file_tag_length_in_bytes = ConfigParam::try_from(self.file_tag_length_in_bytes)
            .map_err(InvalidParameterError::from)?;
        let succession_nonce_length_in_bytes =
            ConfigParam::try_from(self.succession_nonce_length_in_bytes)
                .map_err(InvalidParameterError::from)?;
        Ok(RegistryConfigKdf {
            root_predecessor_nonce,
            algorithm,
            file_name_length_in_bytes,
            file_tag_length_in_bytes,
            succession_nonce_length_in_bytes,
        })
    }

    pub fn build_with_random_root_predecessor_nonce(
        &self,
        csprng: impl RngCore + CryptoRng,
    ) -> Result<RegistryConfigKdf> {
        self.build(RegistryConfigKdf::generate_random_root_predecessor_nonce(
            csprng,
            Some(self.succession_nonce_length_in_bytes),
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryConfigKdf {
    algorithm: KdfAlgorithm,
    file_name_length_in_bytes: ConfigParam<FileNameLengthInBytes>,
    file_tag_length_in_bytes: ConfigParam<FileTagLengthInBytes>,
    succession_nonce_length_in_bytes: ConfigParam<SuccessionNonceLengthInBytes>,
    root_predecessor_nonce: SuccessionNonce,
}

impl RegistryConfigKdf {
    pub fn builder() -> RegistryConfigKdfBuilder {
        Default::default()
    }

    pub fn generate_random_root_predecessor_nonce(
        mut csprng: impl RngCore + CryptoRng,
        succession_nonce_length_in_bytes: Option<u64>,
    ) -> SuccessionNonce {
        let succession_nonce_length_in_bytes =
            succession_nonce_length_in_bytes.unwrap_or(SuccessionNonceLengthInBytes::RECOMMENDED);
        let mut bytes = vec![0_u8; succession_nonce_length_in_bytes as usize].into_boxed_slice();
        csprng.fill_bytes(&mut bytes);
        SuccessionNonce(Secret(BytesOrHexString(bytes)))
    }

    pub fn get_algorithm(&self) -> &KdfAlgorithm {
        &self.algorithm
    }

    pub fn get_file_name_length_in_bytes(&self) -> <FileNameLengthInBytes as ConfigParamTrait>::T {
        *self.file_name_length_in_bytes
    }

    pub fn get_file_tag_length_in_bytes(&self) -> <FileTagLengthInBytes as ConfigParamTrait>::T {
        *self.file_tag_length_in_bytes
    }

    pub fn get_succession_nonce_length_in_bytes(
        &self,
    ) -> <SuccessionNonceLengthInBytes as ConfigParamTrait>::T {
        *self.succession_nonce_length_in_bytes
    }

    pub fn get_root_record_predecessor_nonce(&self) -> &SuccessionNonce {
        &self.root_predecessor_nonce
    }
}

prop_compose! {
    fn arb_registry_config_kdf()(
        algorithm in any::<KdfAlgorithm>(),
        succession_nonce_length_in_bytes in arb_config_param(128),
        file_name_length_in_bytes in arb_config_param(64),
        file_tag_length_in_bytes in arb_config_param(64),
    )(
        root_predecessor_nonce in vec(any::<u8>(), (*succession_nonce_length_in_bytes as usize)..=128),
        algorithm in Just(algorithm),
        succession_nonce_length_in_bytes in Just(succession_nonce_length_in_bytes),
        file_name_length_in_bytes in Just(file_name_length_in_bytes),
        file_tag_length_in_bytes in Just(file_tag_length_in_bytes),
    ) -> RegistryConfigKdf {
        RegistryConfigKdf {
            algorithm,
            file_name_length_in_bytes,
            file_tag_length_in_bytes,
            succession_nonce_length_in_bytes,
            root_predecessor_nonce: SuccessionNonce(Secret(BytesOrHexString(root_predecessor_nonce.into()))),
        }
    }
}

impl Arbitrary for RegistryConfigKdf {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        arb_registry_config_kdf().boxed()
    }
}

#[derive(Arbitrary, Clone, Debug, PartialEq, Eq)]
pub struct RegistryConfig {
    pub hash: RegistryConfigHash,
    pub kdf: RegistryConfigKdf,
    pub verifying_keys: Vec<VerifyingKey>,
}

/// An intermediate type used for the serialization/deserialization of `RegistryConfig`.
/// This allows for the usage of [`serde`] and [`serde_with`] macros along with wrapping the
/// result in a CBOR tag. See the implementation of [`Serialize`] and [`Deserialize`] for
/// [`RegistryConfig`].
#[serde_as]
#[derive(Serialize, Deserialize)]
struct RegistryConfigSerde {
    hash: RegistryConfigHash,
    kdf: RegistryConfigKdf,
    #[serde_as(as = "Vec<CoseKey>")]
    verifying_keys: Vec<VerifyingKey>,
}

impl From<RegistryConfig> for RegistryConfigSerde {
    fn from(value: RegistryConfig) -> Self {
        Self {
            hash: value.hash,
            kdf: value.kdf,
            verifying_keys: value.verifying_keys,
        }
    }
}

impl From<RegistryConfigSerde> for RegistryConfig {
    fn from(value: RegistryConfigSerde) -> Self {
        Self {
            hash: value.hash,
            kdf: value.kdf,
            verifying_keys: value.verifying_keys,
        }
    }
}

impl Serialize for RegistryConfig {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        tag::Accepted::<tag::Accepted<RegistryConfigSerde, TAG_RRR_REGISTRY>, TAG_SELF_DESCRIBED_CBOR>(tag::Accepted(self.clone().into()))
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RegistryConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        tag::Accepted::<tag::Accepted<RegistryConfigSerde, TAG_RRR_REGISTRY>, TAG_SELF_DESCRIBED_CBOR>::deserialize(deserializer)
            .map(|tag::Accepted(tag::Accepted(tagged))| tagged.into())
    }
}

impl RegistryConfig {
    pub async fn write(&self, write: impl AsyncWrite + Unpin + Send) -> Result<()> {
        let self_cloned = self.clone();
        let sync_write = SyncIoBridge::new(write);
        let ((), results) = unsafe {
            TokioScope::scope_and_collect(move |scope| {
                scope.spawn_blocking(move || -> Result<()> {
                    coset::cbor::into_writer(&self_cloned, sync_write).map_err(Error::CborSer)?;
                    Ok(())
                })
            })
        }
        .await;
        for result in results {
            result??;
        }
        Ok(())
    }

    pub async fn read(read: impl AsyncRead + Unpin + Send) -> Result<Self> {
        let sync_read = SyncIoBridge::new(read);
        let ((), results) = unsafe {
            TokioScope::scope_and_collect(move |scope| {
                scope.spawn_blocking(move || -> Result<Self> {
                    let config =
                        coset::cbor::from_reader::<Self, _>(sync_read).map_err(Error::CborDe)?;
                    Ok(config)
                })
            })
        }
        .await;
        let [result] = results.try_into().unwrap();
        let config = result??;
        Ok(config)
    }
}

#[derive(Debug, Eq)]
pub struct Registry<L: FileLock> {
    pub directory_path: PathBuf,
    pub config: RegistryConfig,
    /// A file lock on the registry config file.
    file_lock: L,
}

impl<L: FileLock> Registry<L> {
    pub const RELATIVE_PATH_CONFIG: &'static str = "registry.cbor";
    pub const RELATIVE_PATH_RECORDS: &'static str = "records";

    async fn lock_from_registry_directory<L2: FileLock>(
        directory_path: impl AsRef<Path>,
        open_options: &OpenOptions,
    ) -> Result<L2> {
        let config_path = Self::get_config_path_from_registry_directory(directory_path.as_ref());

        L2::lock(config_path, open_options).await
    }

    pub fn get_config_path_from_registry_directory(directory_path: impl AsRef<Path>) -> PathBuf {
        directory_path.as_ref().join(Self::RELATIVE_PATH_CONFIG)
    }

    pub fn get_config_path(&self) -> PathBuf {
        Self::get_config_path_from_registry_directory(&self.directory_path)
    }

    pub fn get_records_directory_from_registry_directory(
        directory_path: impl AsRef<Path>,
    ) -> PathBuf {
        directory_path.as_ref().join(Self::RELATIVE_PATH_RECORDS)
    }

    pub fn get_records_directory(&self) -> PathBuf {
        Self::get_records_directory_from_registry_directory(&self.directory_path)
    }

    pub fn get_fragment_path(&self, file_name_bytes: &FragmentFileNameBytes) -> PathBuf {
        let mut path = self.get_records_directory();
        path.push(file_name_bytes.to_string());
        path
    }

    pub async fn load_record(
        &self,
        hash_record_path: &(impl HashRecordPath + Debug),
        record_version: RecordVersion,
        max_collision_resolution_attempts: u64,
    ) -> Result<Option<RecordReadVersionSuccess>> {
        Record::read_version(
            self,
            hash_record_path,
            record_version,
            max_collision_resolution_attempts,
        )
        .await
    }

    pub async fn list_record_versions(
        &self,
        hash_record_path: &(impl HashRecordPath + Debug),
        max_version_lookahead: u64,
        max_collision_resolution_attempts: u64,
    ) -> Result<Vec<RecordListVersionsItem>> {
        Record::list_versions(
            self,
            hash_record_path,
            max_version_lookahead,
            max_collision_resolution_attempts,
        )
        .await
    }
}

impl<L: FileLock> PartialEq for Registry<L> {
    fn eq(&self, other: &Self) -> bool {
        self.directory_path == other.directory_path && self.config == other.config
    }
}

impl Registry<ReadLock> {
    #[instrument]
    pub async fn open(directory_path: PathBuf) -> Result<Self> {
        let open_options = {
            let mut open_options = File::options();
            open_options.read(true);
            open_options
        };
        let mut file_lock: ReadLock =
            Self::lock_from_registry_directory(&directory_path, &open_options).await?;
        let config = RegistryConfig::read(&mut file_lock.inner_mut()).await?;

        Ok(Self {
            directory_path,
            config,
            file_lock,
        })
    }

    #[instrument]
    pub async fn lock_write(self) -> Result<Registry<WriteLock>> {
        let open_options = {
            let mut open_options = File::options();
            open_options.read(true);
            open_options.write(true);
            open_options.truncate(true);
            open_options
        };

        drop(self.file_lock);

        Ok(Registry {
            file_lock: Self::lock_from_registry_directory(&self.directory_path, &open_options)
                .await?,
            directory_path: self.directory_path,
            config: self.config,
        })
    }
}

impl Registry<WriteLock> {
    #[instrument]
    pub async fn create(
        directory_path: PathBuf,
        config: RegistryConfig,
        overwrite: bool,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(&directory_path).await?;

        let open_options = {
            let mut open_options = File::options();
            open_options.create(overwrite);
            open_options.create_new(!overwrite);
            open_options.write(true);
            open_options.truncate(true);
            open_options
        };
        let mut registry = Self {
            file_lock: Self::lock_from_registry_directory(&directory_path, &open_options).await?,
            directory_path,
            config,
        };

        tokio::fs::create_dir_all(registry.get_records_directory()).await?;
        registry.save_config().await?;

        Ok(registry)
    }

    pub async fn save_config(&mut self) -> Result<()> {
        self.config.write(self.file_lock.inner_mut()).await?;
        Ok(())
    }

    pub async fn save_record(
        &mut self,
        signing_keys: &[SigningKey],
        hash_record_path: &(impl HashRecordPath + Debug),
        record: &Record,
        record_version: RecordVersion,
        max_collision_resolution_attempts: u64,
        split_at: &[usize],
        encryption: Option<&SegmentEncryption>,
        overwrite: bool,
    ) -> Result<RecordNonce> {
        let open_options = {
            let mut open_options = tokio::fs::OpenOptions::new();
            open_options.create_new(!overwrite);
            open_options.create(overwrite);
            open_options.truncate(true);
            open_options.write(true);
            open_options.read(cfg!(debug_assertions));
            open_options
        };

        record
            .write_version(
                signing_keys,
                self,
                hash_record_path,
                record_version,
                max_collision_resolution_attempts,
                split_at,
                encryption,
                &open_options,
            )
            .await
    }

    #[instrument]
    pub async fn lock_read(self) -> Result<Registry<ReadLock>> {
        let open_options = {
            let mut open_options = File::options();
            open_options.read(true);
            open_options
        };

        drop(self.file_lock);

        Ok(Registry {
            file_lock: Self::lock_from_registry_directory(&self.directory_path, &open_options)
                .await?,
            directory_path: self.directory_path,
            config: self.config,
        })
    }
}
