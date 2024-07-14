use crate::cbor::{self, DateTimeParseError, TAG_RRR_RECORD};
use crate::crypto::encryption::EncryptionAlgorithm;
use crate::crypto::signature::SigningKey;
use crate::error::{Error, Result};
use crate::registry::{Registry, WriteLock};
use crate::utils::serde::{BytesOrAscii, BytesOrHexString, Secret};
use async_fd_lock::{LockRead, LockWrite};
use chrono::{DateTime, FixedOffset, TimeZone};
use coset::cbor::tag;
use derive_more::{Deref, DerefMut};
use itertools::Itertools;
use proptest::arbitrary::Arbitrary;
use proptest::prop_compose;
use proptest::strategy::{BoxedStrategy, Strategy};
use proptest_arbitrary_interop::arb;
use proptest_derive::Arbitrary;
use segment::{
    FragmentFileNameBytes, FragmentKey, FragmentReadSuccess, KdfUsageFragmentParameters,
    RecordNonce, RecordParameters, RecordVersion, Segment, SegmentMetadata,
};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use std::{borrow::Cow, fmt::Debug, io::Cursor};
use std::{io, iter};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::{debug, info, instrument, trace};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod segment;

mod key;
mod path;

pub use key::*;
pub use path::*;

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SuccessionNonce(pub(crate) Secret<BytesOrHexString<Box<[u8]>>>);

impl Deref for SuccessionNonce {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SuccessionNonce {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A CBOR map of metadata.
#[derive(Clone, Debug, Default, Deref, DerefMut, PartialEq, Serialize, Deserialize)]
pub struct RecordMetadata(pub cbor::Map);

impl RecordMetadata {
    pub const KEY_CREATED_AT: u64 = 1;

    pub fn get_created_at(
        &self,
    ) -> std::result::Result<Option<DateTime<FixedOffset>>, DateTimeParseError> {
        self.get_date_time(Self::KEY_CREATED_AT)
    }

    pub fn insert_created_at<Tz: TimeZone>(
        &mut self,
        date_time: DateTime<Tz>,
    ) -> Option<cbor::Value> {
        self.insert_date_time(Self::KEY_CREATED_AT, date_time)
    }

    pub fn shift_remove_created_at(&mut self) -> Option<cbor::Value> {
        self.shift_remove(Self::KEY_CREATED_AT)
    }
}

prop_compose! {
    fn arb_record_metadata()(
        // FIXME: Filtering is suboptimal.
        created_at in arb::<Option<DateTime<FixedOffset>>>().prop_filter("Ability to parse from RFC3339 format", |datetime| {
            datetime.map(|datetime| DateTime::parse_from_rfc3339(&datetime.to_rfc3339()).is_ok()).unwrap_or(true)
        }),
    ) -> RecordMetadata {
        let mut result = RecordMetadata::default();

        if let Some(created_at) = created_at {
            result.insert_created_at(created_at);
        }

        result
    }
}

impl Arbitrary for RecordMetadata {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        arb_record_metadata().boxed()
    }
}

pub type RecordData = BytesOrAscii<Vec<u8>, 32>;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct RecordSerde<'a>(Cow<'a, RecordMetadata>, Cow<'a, RecordData>);

/// A record, loaded from its CBOR representation.
#[derive(Arbitrary, Clone, Debug, Default, PartialEq)]
pub struct Record {
    pub metadata: RecordMetadata,
    pub data: RecordData,
}

impl Serialize for Record {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        tag::Accepted::<_, TAG_RRR_RECORD>(RecordSerde::from(self)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Record {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        tag::Accepted::<RecordSerde, TAG_RRR_RECORD>::deserialize(deserializer)
            .map(|tag::Accepted(segment)| segment.into())
    }
}

impl From<RecordSerde<'_>> for Record {
    fn from(value: RecordSerde) -> Self {
        Self {
            metadata: value.0.into_owned(),
            data: value.1.into_owned(),
        }
    }
}

impl From<Record> for RecordSerde<'static> {
    fn from(value: Record) -> Self {
        Self(Cow::Owned(value.metadata), Cow::Owned(value.data))
    }
}

impl<'a> From<&'a Record> for RecordSerde<'a> {
    fn from(value: &'a Record) -> Self {
        Self(Cow::Borrowed(&value.metadata), Cow::Borrowed(&value.data))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecordReadVersionSuccessSegment {
    pub segment_bytes: usize,
    pub fragment_file_name: FragmentFileNameBytes,
    pub fragment_encryption_algorithm: Option<EncryptionAlgorithm>,
}

#[derive(Debug, Clone, Deref, DerefMut, PartialEq)]
pub struct RecordReadVersionSuccess {
    #[deref]
    #[deref_mut]
    pub record: Record,
    pub record_nonce: RecordNonce,
    pub segments: Vec<RecordReadVersionSuccessSegment>,
}

impl Record {
    // pub async fn list_versions<L>(
    //     registry: &Registry<L>,
    //     hashed_key: &HashedRecordKey,
    // ) -> Result<impl TryStream<Ok = u64, Error = Error>> {
    //     todo!()
    // }

    #[instrument]
    pub async fn read_version<L: Debug + Sync>(
        registry: &Registry<L>,
        hash_record_path: &(impl HashRecordPath + Debug),
        record_version: RecordVersion,
        max_collision_resolution_attempts: u64,
    ) -> Result<Option<RecordReadVersionSuccess>> {
        let hashed_key = hash_record_path.hash_record_path(registry).await?;
        let mut errors = Vec::<Error>::new();

        'collision_resolution_loop: for record_nonce in
            0..max_collision_resolution_attempts.checked_add(1).unwrap()
        {
            let record_parameters = RecordParameters {
                version: record_version,
                nonce: record_nonce.into(),
            };
            let mut segments = Vec::new();
            let mut data_buffer = Vec::<u8>::new();

            'segment_loop: loop {
                let fragment_key = FragmentKey {
                    hashed_record_key: hashed_key.clone(),
                    fragment_parameters: KdfUsageFragmentParameters {
                        record_parameters: record_parameters.clone(),
                        segment_index: (segments.len() as u64).into(),
                    },
                };
                let fragment_file_name =
                    fragment_key.derive_file_name(&registry.config.kdf).await?;
                let fragment_path = registry.get_fragment_path(&fragment_file_name);

                let segment_result: Result<FragmentReadSuccess> = try {
                    let fragment_file = File::open(&fragment_path).await?;
                    let fragment_file_guard = fragment_file.lock_read().await?;

                    Segment::read_fragment(
                        &registry.config.verifying_keys,
                        &registry.config.kdf,
                        fragment_file_guard,
                        &fragment_key,
                    )
                    .await?
                };

                trace!(
                    ?fragment_key,
                    ?fragment_file_name,
                    ?fragment_path,
                    error = ?segment_result.as_ref().err(),
                    "Attempted to load a record fragment"
                );

                let segment = match segment_result {
                    Ok(segment) => segment,
                    Err(error) => {
                        if segments.is_empty() {
                            errors.push(error);
                            continue 'collision_resolution_loop;
                        } else {
                            return Err(error);
                        }
                    }
                };

                data_buffer.extend_from_slice(&segment.data);

                segments.push(RecordReadVersionSuccessSegment {
                    segment_bytes: segment.data.len(),
                    fragment_file_name,
                    fragment_encryption_algorithm: segment.encryption_algorithm,
                });

                if segment.metadata.get_last()? {
                    break 'segment_loop;
                }
            }

            let record = coset::cbor::from_reader::<Self, _>(Cursor::new(&data_buffer))
                .map_err(Error::CborDe)?;

            info!(%record_nonce, "Record read successfully");

            return Ok(Some(RecordReadVersionSuccess {
                record,
                record_nonce: record_nonce.into(),
                segments,
            }));
        }

        errors.retain(|error| {
            if let Error::Io(error) = error {
                error.kind() != io::ErrorKind::NotFound
            } else {
                true
            }
        });

        if let Some(error) = errors.into_iter().next() {
            Err(error)
        } else {
            Ok(None)
        }
    }

    #[instrument]
    pub async fn write_version(
        &self,
        signing_keys: &[SigningKey],
        registry: &Registry<WriteLock>,
        hash_record_path: &(impl HashRecordPath + Debug),
        record_version: RecordVersion,
        max_collision_resolution_attempts: u64,
        split_at: &[usize], // TODO: Should be generated from the serialized record length.
        encryption_algorithm: Option<&EncryptionAlgorithm>,
        open_options: &OpenOptions,
    ) -> Result<RecordNonce> {
        let hashed_key = hash_record_path.hash_record_path(registry).await?;
        let mut data_buffer = Vec::<u8>::new();
        coset::cbor::into_writer(&self, &mut data_buffer).map_err(Error::CborSer)?;

        let segment_sizes = {
            let mut segment_sizes = Vec::<usize>::new();

            segment_sizes.reserve_exact(split_at.len() + 1);

            for (a, b) in std::iter::once(0)
                .chain(split_at.iter().copied())
                .tuple_windows()
            {
                let Some(segment_size) = b.checked_sub(a) else {
                    panic!("`split_at` must be non-decreasing");
                };
                segment_sizes.push(segment_size);
            }

            if let Some(&last) = split_at.last() {
                let Some(last_segment_size) = data_buffer.len().checked_sub(last) else {
                    panic!("`split_at` must not exceed the serialized record length");
                };
                segment_sizes.push(last_segment_size);
            } else {
                segment_sizes.push(data_buffer.len());
            }

            segment_sizes
        };

        // Find a record nonce such that no record fragment file names collide with existing files.
        #[allow(clippy::never_loop)]
        let (record_nonce, fragments) = 'collision_resolution_loop: loop {
            let mut fragments = Vec::with_capacity(segment_sizes.len());

            'next_nonce: for record_nonce in
                0..max_collision_resolution_attempts.checked_add(1).unwrap()
            {
                trace!(%record_nonce, "Checking collisions");
                fragments.clear();

                let record_parameters = RecordParameters {
                    version: record_version,
                    nonce: record_nonce.into(),
                };

                for segment_index in 0..segment_sizes.len() {
                    let fragment_key = FragmentKey {
                        hashed_record_key: hashed_key.clone(),
                        fragment_parameters: KdfUsageFragmentParameters {
                            record_parameters: record_parameters.clone(),
                            segment_index: (segment_index as u64).into(),
                        },
                    };
                    let fragment_file_name =
                        fragment_key.derive_file_name(&registry.config.kdf).await?;
                    let fragment_path = registry.get_fragment_path(&fragment_file_name);
                    let collides_with_existing_fragment =
                        tokio::fs::try_exists(&fragment_path).await?;

                    trace!(
                        ?fragment_key,
                        ?fragment_file_name,
                        ?fragment_path,
                        ?collides_with_existing_fragment,
                        "Segment name collision check performed"
                    );

                    if collides_with_existing_fragment {
                        // TODO: Check whether the colliding file is actually encrypted with the same key?
                        continue 'next_nonce;
                    }

                    fragments.push((fragment_key, fragment_path));
                }

                break 'collision_resolution_loop (record_parameters.nonce, fragments);
            }

            return Err(Error::CollisionResolutionFailed);
        };

        debug!(?record_nonce, "Record nonce without any collisions found");
        assert_eq!(fragments.len(), segment_sizes.len());

        let mut rest = data_buffer.as_slice();

        for (segment_index, ((fragment_key, fragment_path), &segment_size)) in
            iter::zip(&fragments, &segment_sizes).enumerate()
        {
            let segment_data;
            (segment_data, rest) = rest.split_at(segment_size);
            let segment = Segment {
                metadata: {
                    let mut metadata = SegmentMetadata::default();
                    if segment_index == segment_sizes.len() - 1 {
                        metadata.insert_last();
                    }
                    metadata
                },
                data: BytesOrAscii(segment_data.into()),
            };
            let fragment_file = open_options.open(&fragment_path).await?;
            let mut fragment_file_guard = fragment_file.lock_write().await?;

            segment
                .write_fragment(
                    signing_keys,
                    &registry.config.kdf,
                    &mut fragment_file_guard,
                    fragment_key,
                    encryption_algorithm,
                )
                .await?;

            if cfg!(debug_assertions) {
                let mut buf = Vec::new();

                fragment_file_guard.rewind().await?;
                fragment_file_guard.read_to_end(&mut buf).await?;
                println!("{:?}:\n{:02x}", fragment_path, buf.iter().format(""));
            }
        }

        info!(?record_nonce, "Record written successfully");

        Ok(record_nonce)
    }
}

/// Data known when opening a record.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct RecordContext {
    pub key: RecordKey,
}

#[derive(Debug)]
pub struct RecordWithContext<'record> {
    // TODO: Zeroize, ZeroizeOnDrop
    pub record: Cow<'record, Record>,
    pub context: RecordContext,
}
