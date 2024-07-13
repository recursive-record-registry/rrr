use std::{borrow::Cow, path::PathBuf};

use async_fd_lock::LockError;
use coset::RegisteredLabel;
use thiserror::Error;

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
    #[error("Duplicate successive record {name:?} of parent {parent:?}")]
    DuplicateSuccessiveRecord { parent: PathBuf, name: Vec<u8> },
    #[error("Registry already exists at path {path:?}")]
    RegistryAlreadyExists { path: PathBuf },
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
}

impl<T> From<LockError<T>> for Error {
    fn from(value: LockError<T>) -> Self {
        Error::Io(value.error)
    }
}

pub struct SignatureMismatch;
