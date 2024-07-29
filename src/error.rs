use std::borrow::Cow;

use async_fd_lock::LockError;
use coset::RegisteredLabel;
use derive_more::From;
use thiserror::Error;

use crate::registry::{ConfigParamTooLowError, ConfigParamTrait};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Argon2: {0}")]
    Argon2(#[from] argon2::Error),
    #[error("Coset: {0}")]
    Coset(coset::CoseError),
    #[error("CBOR Deserialization: {0}")]
    CborDe(coset::cbor::de::Error<std::io::Error>),
    #[error("CBOR Serialization: {0}")]
    CborSer(coset::cbor::ser::Error<std::io::Error>),
    #[error("CBOR: {0}")]
    Cbor(coset::cbor::value::Error),
    #[error("Cipher: {0}")]
    Cipher(#[from] aes_gcm::Error),
    #[error("Sign: {0}")]
    Sign(#[from] ed25519_dalek::ed25519::signature::Error),
    #[error("Unexpected item: {0}")]
    UnexpectedItem(Cow<'static, str>),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Tokio Join: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("Unrecognized critical field in header: {field:?}")]
    UnrecognizedCriticalField {
        field: RegisteredLabel<coset::iana::HeaderParameter>,
    },
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Malformed record")]
    MalformedRecord,
    #[error("Malformed segment")]
    MalformedSegment,
    #[error("Malformed fragment")]
    MalformedFragment,
    #[error("Unrecognized encryption algorithm: {alg:?}")]
    UnrecognizedEncryptionAlgorithm { alg: Option<coset::Algorithm> },
    #[error("Failed to resolve collisions")]
    CollisionResolutionFailed,
    #[error(transparent)]
    InvalidParameter(#[from] InvalidParameterError),
    #[error("File tag mismatch")]
    FileTagMismatch,
    #[error("Segment too large ({length} bytes) to store in a block of {max_length} bytes")]
    SegmentTooLarge { length: u64, max_length: u64 },
}

impl<T> From<LockError<T>> for Error {
    fn from(value: LockError<T>) -> Self {
        Error::Io(value.error)
    }
}

pub struct SignatureMismatch;

#[derive(Error, Debug)]
#[error("Invalid parameter `{label}`: {source}")]
pub struct InvalidParameterError {
    pub label: &'static str,
    #[source]
    pub source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl<P> From<ConfigParamTooLowError<P>> for InvalidParameterError
where
    P: ConfigParamTrait + 'static,
{
    fn from(value: ConfigParamTooLowError<P>) -> Self {
        InvalidParameterError {
            label: P::LABEL,
            source: Box::new(value),
        }
    }
}

#[derive(Error, Debug, From)]
#[error("{0}")]
pub struct GenericError(pub Cow<'static, str>);

impl From<&'static str> for GenericError {
    fn from(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl From<String> for GenericError {
    fn from(value: String) -> Self {
        Self(Cow::Owned(value))
    }
}

pub(crate) trait OptionExt<T> {
    fn unwrap_builder_parameter(
        &self,
        label: &'static str,
    ) -> std::result::Result<T, InvalidParameterError>;
}

impl<T: Clone> OptionExt<T> for Option<T> {
    fn unwrap_builder_parameter(
        &self,
        label: &'static str,
    ) -> std::result::Result<T, InvalidParameterError> {
        self.as_ref().cloned().ok_or_else(|| InvalidParameterError {
            label,
            source: Box::new(GenericError::from(
                "value is required but was not specified",
            )),
        })
    }
}

pub(crate) trait IoResultExt<T, E> {
    fn map_err_not_found_to_none(self) -> std::result::Result<Option<T>, E>;
}

impl<T> IoResultExt<T, std::io::Error> for std::io::Result<T> {
    fn map_err_not_found_to_none(self) -> std::io::Result<Option<T>> {
        match self {
            Ok(ok) => Ok(Some(ok)),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }
}

impl<T> IoResultExt<T, Error> for std::result::Result<T, Error> {
    fn map_err_not_found_to_none(self) -> std::result::Result<Option<T>, Error> {
        match self {
            Ok(ok) => Ok(Some(ok)),
            Err(Error::Io(io_err)) => {
                if io_err.kind() == std::io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(Error::Io(io_err))
                }
            }
            Err(err) => Err(err),
        }
    }
}
