use crate::cbor::{
    self, HasHeadersExt, TAG_RRR_FRAGMENT, TAG_RRR_SEGMENT, TAG_SELF_DESCRIBED_CBOR,
};
use crate::crypto::encryption::{Decrypt, Encrypt, EncryptionAlgorithm};
use crate::crypto::signature::{SigningKey, VerifyingKey};
use crate::error::{Error, Result};
use crate::record::{HashedRecordKey, RecordKey};
use crate::registry::RegistryConfigKdf;
use crate::serde_utils::{BytesOrAscii, BytesOrHexString, Secret};
use async_scoped::TokioScope;
use coset::cbor::tag;
use coset::TaggedCborSerializable;
use coset::{
    iana::{Algorithm, CoapContentFormat},
    AsCborValue, CborSerializable, CoseEncrypt0, CoseSign, CoseSignatureBuilder, HeaderBuilder,
};
use derive_more::{Deref, DerefMut};
use itertools::Itertools;
use proptest::arbitrary::{any, Arbitrary};
use proptest::prop_compose;
use proptest::strategy::{BoxedStrategy, Strategy};
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::ops::{Deref, DerefMut};
use std::{borrow::Cow, fmt::Debug};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_util::io::SyncIoBridge;
use tracing::warn;
use zeroize::{Zeroize, ZeroizeOnDrop};

// /// A UTF-8 string with no `'/'` characters.
// /// The forward slash character is not allowed, so that record paths can be created by joining names
// /// with the forward slash as a separator.
// pub struct RecordName(String);

// pub struct RecordNameContainsForwardSlash;

// impl TryFrom<String> for RecordName {
//     type Error = RecordNameContainsForwardSlash;

//     fn try_from(string: String) -> std::prelude::v1::Result<Self, RecordNameContainsForwardSlash> {
//         if string.chars().any(|c| c == '/') {
//             Err(RecordNameContainsForwardSlash)
//         } else {
//             Ok(RecordName(string))
//         }
//     }
// }

// impl Deref for RecordName {
//     type Target = str;

//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FragmentKey {
    /// The output of the slow password hashing function.
    pub hashed_record_key: HashedRecordKey,
    pub fragment_parameters: KdfUsageFragmentParameters,
}

impl FragmentKey {
    pub async fn derive_file_name(
        &self,
        kdf_params: &RegistryConfigKdf,
    ) -> Result<FragmentFileNameBytes> {
        self.hashed_record_key
            .derive_fragment_file_name(kdf_params, &self.fragment_parameters)
            .await
    }

    pub async fn derive_encryption_key(
        &self,
        kdf_params: &RegistryConfigKdf,
        encryption_algorithm: &EncryptionAlgorithm,
    ) -> Result<FragmentEncryptionKeyBytes> {
        self.hashed_record_key
            .derive_fragment_encryption_key(
                kdf_params,
                encryption_algorithm,
                &self.fragment_parameters,
            )
            .await
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KdfUsage {
    SuccessionNonce,
    Fragment {
        usage: KdfUsageFragmentUsage,
        parameters: KdfUsageFragmentParameters,
    },
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KdfUsageFragmentUsage {
    EncryptionKey,
    FileName,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KdfUsageFragmentParameters {
    /// Records are versioned, so that updated versions of records can be published.
    /// This field is used to ensure that encryption keys are unique for each version
    /// of a published record. Publishing different versions of the same record with an equal
    /// version number is a security violation.
    pub record_version: u64,
    /// Used to resolve collisions in file names. Starts at 0, and is incremented if a collision is
    /// encountered for any of the record fragemnts. It is assumed that for each version of a
    /// record, a single nonce is chosen. In other words, for a given record version, record fragments
    /// with varying record nonces should **not** exist. This fact is used to optimize record
    /// browsing, such that only the record with the lowest nonce is shown, and record fragments with
    /// higher nonces are not even considered.
    pub record_nonce: u64,
    /// Records are made up of one or more segments/fragments. This number identifies a record's segments/fragments.
    pub segment_index: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct FragmentFileNameBytes(pub BytesOrHexString<Box<[u8]>>);

impl Deref for FragmentFileNameBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FragmentFileNameBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for FragmentFileNameBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}.cbor", self.0.iter().format(""))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct FragmentEncryptionKeyBytes(pub Secret<Box<[u8]>>);

impl Deref for FragmentEncryptionKeyBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FragmentEncryptionKeyBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct HashedFragmentKey {
    pub file_name: FragmentFileNameBytes,
    pub encryption_key: FragmentEncryptionKeyBytes,
}

/// A CBOR map of metadata.
#[derive(Clone, Debug, Default, Deref, DerefMut, PartialEq, Serialize, Deserialize)]
pub struct SegmentMetadata(pub cbor::Map);

impl SegmentMetadata {
    pub const KEY_LAST: u64 = 1;

    pub fn get_last(&self) -> Result<bool> {
        let Some(value) = self.get(Self::KEY_LAST) else {
            return Ok(false);
        };
        let last = value.as_bool().ok_or_else(|| Error::MalformedSegment)?;

        Ok(last)
    }

    pub fn insert_last(&mut self) -> Option<cbor::Value> {
        self.insert(Self::KEY_LAST, true)
    }

    pub fn shift_remove_last(&mut self) -> Option<cbor::Value> {
        self.shift_remove(Self::KEY_LAST)
    }
}

prop_compose! {
    fn arb_segment_metadata()(
        last in any::<bool>(),
    ) -> SegmentMetadata {
        let mut result = SegmentMetadata::default();

        if last {
            result.insert_last();
        }

        result
    }
}

impl Arbitrary for SegmentMetadata {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        arb_segment_metadata().boxed()
    }
}

pub type SegmentData = BytesOrAscii<Vec<u8>, 32>;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct SegmentSerde<'a>(Cow<'a, SegmentMetadata>, Cow<'a, SegmentData>);

/// A record, loaded from its CBOR representation.
#[derive(Arbitrary, Clone, Debug, Default, PartialEq)]
pub struct Segment {
    pub metadata: SegmentMetadata,
    pub data: SegmentData,
}

impl Serialize for Segment {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        tag::Accepted::<_, TAG_RRR_SEGMENT>(SegmentSerde::from(self)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Segment {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        tag::Accepted::<SegmentSerde, TAG_RRR_SEGMENT>::deserialize(deserializer)
            .map(|tag::Accepted(segment)| segment.into())
    }
}

impl From<SegmentSerde<'_>> for Segment {
    fn from(value: SegmentSerde) -> Self {
        Self {
            metadata: value.0.into_owned(),
            data: value.1.into_owned(),
        }
    }
}

impl From<Segment> for SegmentSerde<'static> {
    fn from(value: Segment) -> Self {
        Self(Cow::Owned(value.metadata), Cow::Owned(value.data))
    }
}

impl<'a> From<&'a Segment> for SegmentSerde<'a> {
    fn from(value: &'a Segment) -> Self {
        Self(Cow::Borrowed(&value.metadata), Cow::Borrowed(&value.data))
    }
}

impl Segment {
    pub async fn read_fragment(
        verifying_keys: &[VerifyingKey],
        kdf_params: &RegistryConfigKdf,
        mut read: impl AsyncRead + Unpin + Send,
        fragment_key: &FragmentKey,
    ) -> Result<Self> {
        let input_value = {
            let mut input_bytes = Vec::new();
            read.read_to_end(&mut input_bytes).await?;
            cbor::Value::from_slice(&input_bytes).map_err(Error::Coset)?
        };

        // Unwrap recommended self-described CBOR tag.
        let input_value = match input_value {
            cbor::Value::Tag(tag, input_value) if tag == TAG_SELF_DESCRIBED_CBOR => *input_value,
            input_value => input_value,
        };

        // Unwrap recommended RRR fragment CBOR tag.
        let input_value = match input_value {
            cbor::Value::Tag(tag, input_value) if tag == TAG_RRR_FRAGMENT => *input_value,
            input_value => input_value,
        };

        // Check the cryptographic signatures of the fragment.
        let input_value = match input_value {
            cbor::Value::Tag(tag, input_value) if tag == CoseSign::TAG => {
                let signed = CoseSign::from_cbor_value(*input_value).map_err(Error::Coset)?;

                signed.ensure_no_critical_fields()?;

                for verifying_key in verifying_keys {
                    let verified = (0..signed.signatures.len()).any(|signature_index| {
                        signed
                            .verify_signature(signature_index, &[], verifying_key)
                            .is_ok()
                    });

                    if !verified {
                        return Err(Error::SignatureVerificationFailed);
                    }
                }

                let payload = signed.payload.ok_or(Error::MalformedSegment)?;

                cbor::Value::from_slice(&payload).map_err(Error::Coset)?
            }
            input_value => {
                // The fragment is not cryptographically signed.
                if !verifying_keys.is_empty() {
                    return Err(Error::SignatureVerificationFailed);
                }

                input_value
            }
        };

        // Decrypt the fragment, if necessary.
        let input_value = match input_value {
            cbor::Value::Tag(tag, input_value) if tag == CoseEncrypt0::TAG => {
                let encrypted =
                    CoseEncrypt0::from_cbor_value(*input_value).map_err(Error::Coset)?;

                encrypted.ensure_no_critical_fields()?;

                let encryption_algorithm: EncryptionAlgorithm = encrypted
                    .protected
                    .header
                    .alg
                    .as_ref()
                    .or(encrypted.unprotected.alg.as_ref())
                    .ok_or_else(|| Error::UnrecognizedEncryptionAlgorithm { alg: None })
                    .and_then(|alg| {
                        alg.clone()
                            .try_into()
                            .map_err(|_| Error::UnrecognizedEncryptionAlgorithm {
                                alg: Some(alg.clone()),
                            })
                    })?;
                let encryption_key = fragment_key
                    .derive_encryption_key(kdf_params, &encryption_algorithm)
                    .await?;
                let plaintext = encrypted.decrypt(
                    &[],
                    Decrypt {
                        algorithm: &encryption_algorithm,
                        key: &encryption_key,
                    },
                )?;

                cbor::Value::from_slice(&plaintext).map_err(Error::Coset)?
            }
            input_value => {
                // The fragment is not encrypted.
                input_value
            }
        };

        let record = input_value.deserialized::<Self>().map_err(Error::Cbor)?;

        Ok(record)
    }

    pub async fn write_fragment(
        &self,
        signing_keys: &[SigningKey],
        kdf_params: &RegistryConfigKdf,
        write: impl AsyncWrite + Unpin + Send,
        fragment_key: &FragmentKey,
        encryption_algorithm: Option<&EncryptionAlgorithm>,
    ) -> Result<()> {
        let output_value = cbor::Value::serialized(self).map_err(Error::Cbor)?;

        // Encrypt the fragment data, if an encryption algorithm was provided.
        let output_value = if let Some(encryption_algorithm) = encryption_algorithm {
            let plaintext = output_value.to_vec().map_err(Error::Coset)?;
            let encryption_key = fragment_key
                .derive_encryption_key(kdf_params, encryption_algorithm)
                .await?;
            let encrypted = coset::CoseEncrypt0Builder::new()
                .protected(
                    HeaderBuilder::new()
                        // Placed in the `protected` fields according to
                        // https://datatracker.ietf.org/doc/html/rfc8152#section-3.1
                        .algorithm((*encryption_algorithm).into())
                        // .content_type("application/binary".to_string()) // TODO
                        .build(),
                )
                .try_create_ciphertext(
                    &plaintext,
                    &[],
                    Encrypt {
                        algorithm: encryption_algorithm,
                        key: &encryption_key,
                    },
                )?
                .build();
            let untagged = encrypted.to_cbor_value().map_err(Error::Coset)?;

            cbor::Value::Tag(CoseEncrypt0::TAG, Box::new(untagged))
        } else {
            warn!("Record fragment is being written without encryption! This means that it will not be possible to recover the contents of the record without knowing its key!");
            output_value
        };

        // Sign the fragment data, if signing keys were provided.
        let output_value = if !signing_keys.is_empty() {
            let plaintext = output_value.to_vec().map_err(Error::Coset)?;
            let mut builder = coset::CoseSignBuilder::new().payload(plaintext);
            for signing_key in signing_keys {
                builder = builder.try_add_created_signature(
                    CoseSignatureBuilder::new()
                        .protected(
                            HeaderBuilder::new()
                                .content_format(CoapContentFormat::CoseEncrypt0)
                                .algorithm(Algorithm::EdDSA)
                                .build(),
                        )
                        .build(),
                    &[],
                    signing_key,
                )?;
            }
            let signed = builder.build();
            let untagged = signed.to_cbor_value().map_err(Error::Coset)?;

            cbor::Value::Tag(CoseSign::TAG, Box::new(untagged))
        } else {
            warn!("Record fragment is being written without any cryptographic signatures! This means that it will not be possible to verify that it was created by you!");
            output_value
        };

        // Add RRR fragment CBOR tag for persistent storage.
        let output_value = cbor::Value::Tag(TAG_RRR_FRAGMENT, Box::new(output_value));

        // Add self-described CBOR tag for persistent storage.
        let output_value = cbor::Value::Tag(TAG_SELF_DESCRIBED_CBOR, Box::new(output_value));

        // Write the result to the output.
        let sync_write = SyncIoBridge::new(write);
        let ((), results) = unsafe {
            TokioScope::scope_and_collect(move |scope| {
                scope.spawn_blocking(move || -> Result<()> {
                    coset::cbor::into_writer(&output_value, sync_write).map_err(Error::CborSer)?;
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
}

/// Data known when opening a record.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SegmentContext {
    pub record_key: RecordKey,
    pub fragment_key: FragmentKey,
}

#[derive(Debug)]
pub struct SegmentWithContext<'record> {
    // TODO: Zeroize, ZeroizeOnDrop
    pub record: Cow<'record, Segment>,
    pub context: SegmentContext,
}
