use crate::cbor::{self, DateTimeParseError, TAG_RRR_RECORD};
use crate::crypto::encryption::EncryptionAlgorithm;
use crate::crypto::signature::SigningKey;
use crate::error::{Error, IoResultExt, Result};
use crate::registry::Registry;
use crate::utils::fd_lock::{FileLock, WriteLock};
use crate::utils::serde::{BytesOrAscii, BytesOrHexString, Secret};
use async_fd_lock::LockWrite;
use chrono::{DateTime, FixedOffset, TimeZone};
use coset::cbor::tag;
use derive_more::{Deref, DerefMut};
use futures::{pin_mut, Stream, StreamExt};
use itertools::Itertools;
use proptest::arbitrary::Arbitrary;
use proptest::prop_compose;
use proptest::strategy::{BoxedStrategy, Strategy};
use proptest_arbitrary_interop::arb;
use proptest_derive::Arbitrary;
use segment::{
    FragmentFileNameBytes, FragmentKey, KdfUsageFragmentParameters, RecordNonce, RecordParameters,
    RecordVersion, Segment, SegmentEncryption, SegmentMetadata,
};
use serde::{Deserialize, Serialize};
use std::iter;
use std::ops::{Deref, DerefMut};
use std::{borrow::Cow, fmt::Debug, io::Cursor};
use tokio::fs::OpenOptions;
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

pub struct RecordListVersionsItem {
    pub record_metadata: RecordMetadata,
    pub record_version: RecordVersion,
    pub record_nonce: RecordNonce,
    pub segments: Vec<RecordReadVersionSuccessSegment>,
}

// TODO: Consider replacing this or making it an alias of `FragmentReadSuccess`.
#[derive(Debug, Clone, PartialEq, Deref, DerefMut)]
pub struct RecordReadSegment {
    #[deref]
    #[deref_mut]
    pub segment: Segment,
    pub fragment_file_name: FragmentFileNameBytes,
    pub fragment_encryption_algorithm: Option<EncryptionAlgorithm>,
}

impl Record {
    #[instrument]
    pub async fn read_segments<'a, L>(
        registry: &'a Registry<L>,
        hash_record_path: &'a (impl HashRecordPath + Debug),
        record_version: RecordVersion,
        record_nonce: RecordNonce,
    ) -> Result<impl Stream<Item = Result<Option<RecordReadSegment>>> + 'a>
    where
        L: FileLock,
    {
        let hashed_key = hash_record_path.hash_record_path(registry).await?;
        let record_parameters = RecordParameters {
            version: record_version,
            nonce: record_nonce,
        };

        #[derive(Default)]
        struct StreamState {
            segment_index: u64,
            closed: bool,
        }

        let stream_state = StreamState::default();
        let stream =
            futures::stream::try_unfold(stream_state, move |mut stream_state: StreamState| {
                let hashed_key = hashed_key.clone();
                let record_parameters = record_parameters.clone();

                async move {
                    if stream_state.closed {
                        return Ok(None);
                    }

                    let fragment_key = FragmentKey {
                        hashed_record_key: hashed_key,
                        fragment_parameters: KdfUsageFragmentParameters {
                            record_parameters,
                            segment_index: stream_state.segment_index.into(),
                        },
                    };
                    let segment_result = Segment::read_fragment(registry, &fragment_key).await;
                    stream_state.segment_index += 1;
                    let fragment_read_success = match segment_result.map_err_not_found_to_none() {
                        Ok(Some(segment)) => segment,
                        Ok(None) => return Ok(Some((None, stream_state))),
                        Err(err) => return Err(err),
                    };
                    let result = RecordReadSegment {
                        segment: fragment_read_success.segment,
                        fragment_file_name: fragment_read_success.fragment_file_name,
                        fragment_encryption_algorithm: fragment_read_success.encryption_algorithm,
                    };

                    if result.segment.metadata.get_last()? {
                        stream_state.closed = true;
                    }

                    Ok(Some((Some(result), stream_state)))
                }
            });

        Ok(stream)
    }

    /// Attempts to read a record with the specified record version and record nonce.
    #[instrument]
    pub async fn read_version_with_nonce<L>(
        registry: &Registry<L>,
        hash_record_path: &(impl HashRecordPath + Debug),
        record_version: RecordVersion,
        record_nonce: RecordNonce,
    ) -> Result<Option<RecordReadVersionSuccess>>
    where
        L: FileLock,
    {
        let mut data_buffer = Vec::<u8>::new();
        let mut segments = Vec::<RecordReadVersionSuccessSegment>::new();
        let stream =
            Self::read_segments(registry, hash_record_path, record_version, record_nonce).await?;

        pin_mut!(stream);

        while let Some(item) = stream.next().await {
            if let Some(segment) = item? {
                data_buffer.extend_from_slice(&segment.data);
                segments.push(RecordReadVersionSuccessSegment {
                    segment_bytes: segment.data.len(),
                    fragment_encryption_algorithm: segment.fragment_encryption_algorithm,
                    fragment_file_name: segment.fragment_file_name,
                })
            } else {
                // TODO: Better support for reading incomplete records.
                return Err(Error::IncompleteRecord {
                    missing_segment_index: segments.len() as u64,
                });
            }
        }

        let record = coset::cbor::from_reader::<Self, _>(Cursor::new(&data_buffer))
            .map_err(Error::CborDe)?;

        info!(record_nonce = %*record_nonce, "Record read successfully");

        Ok(Some(RecordReadVersionSuccess {
            record,
            record_nonce,
            segments,
        }))
    }

    #[instrument]
    pub async fn read_version<L>(
        registry: &Registry<L>,
        hash_record_path: &(impl HashRecordPath + Debug),
        record_version: RecordVersion,
        max_collision_resolution_attempts: u64,
    ) -> Result<Option<RecordReadVersionSuccess>>
    where
        L: FileLock,
    {
        let hashed_key = hash_record_path.hash_record_path(registry).await?;
        let mut errors = Vec::<Error>::new();

        for record_nonce in (0..=max_collision_resolution_attempts).map(RecordNonce) {
            let record_result =
                Self::read_version_with_nonce(registry, &hashed_key, record_version, record_nonce)
                    .await;

            match record_result {
                Ok(Some(record)) => return Ok(Some(record)),
                Ok(None) | Err(Error::FileTagMismatch) => continue,
                Err(error) => {
                    errors.push(error);
                    continue;
                }
            };
        }

        if let Some(error) = errors.into_iter().next() {
            Err(error)
        } else {
            Ok(None)
        }
    }

    #[instrument]
    pub async fn list_versions<L>(
        registry: &Registry<L>,
        hash_record_path: &(impl HashRecordPath + Debug),
        max_version_lookahead: u64,
        max_collision_resolution_attempts: u64,
    ) -> Result<Vec<RecordListVersionsItem>>
    where
        L: FileLock,
    {
        let hashed_key = hash_record_path.hash_record_path(registry).await?;
        let mut versions = Vec::<RecordListVersionsItem>::new();

        'version_loop: loop {
            let version_lookahead_start = versions
                .last()
                .map(|item| RecordVersion(*item.record_version + 1))
                .unwrap_or(RecordVersion(0));

            'version_lookahead_loop: for version_lookahead in 0..=max_version_lookahead {
                let record_version = RecordVersion(version_lookahead_start.0 + version_lookahead);
                let record_success = Self::read_version(
                    registry,
                    &hashed_key,
                    record_version,
                    max_collision_resolution_attempts,
                )
                .await?;

                if let Some(record_success) = record_success {
                    versions.push(RecordListVersionsItem {
                        // TODO/FIXME: Currently reads the entire record, even though just the metadata would be sufficient.
                        record_metadata: record_success.record.metadata,
                        record_version,
                        record_nonce: record_success.record_nonce,
                        segments: record_success.segments,
                    });
                    continue 'version_loop;
                } else {
                    continue 'version_lookahead_loop;
                }
            }

            break;
        }

        Ok(versions)
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
        encryption: Option<&SegmentEncryption>,
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
                        // TODO: Check whether the colliding file has the same fragment file tag?
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
                    metadata
                        .insert_file_tag(fragment_key.derive_file_tag(&registry.config.kdf).await?);
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
                    encryption,
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
