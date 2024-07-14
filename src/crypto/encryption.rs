use std::{
    fmt::{Debug, Display},
    ops::Deref,
};

use crate::record::segment::FragmentEncryptionKeyBytes;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

// TODO: Incomplete implementation
#[derive(Arbitrary, Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
}

impl EncryptionAlgorithm {
    pub fn key_length_in_bytes(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,
        }
    }
}

impl Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
        }
    }
}

impl TryFrom<coset::iana::Algorithm> for EncryptionAlgorithm {
    type Error = ();

    fn try_from(value: coset::iana::Algorithm) -> Result<Self, Self::Error> {
        match value {
            coset::iana::Algorithm::A256GCM => Ok(Self::Aes256Gcm),
            _ => Err(()),
        }
    }
}

impl TryFrom<coset::Algorithm> for EncryptionAlgorithm {
    type Error = ();

    fn try_from(value: coset::Algorithm) -> Result<Self, Self::Error> {
        use coset::RegisteredLabelWithPrivate::*;
        match value {
            Assigned(assigned) => assigned.try_into(),
            _ => Err(()),
        }
    }
}

impl From<EncryptionAlgorithm> for coset::iana::Algorithm {
    fn from(value: EncryptionAlgorithm) -> Self {
        match value {
            EncryptionAlgorithm::Aes256Gcm => Self::A256GCM,
        }
    }
}

impl From<EncryptionAlgorithm> for coset::Algorithm {
    fn from(value: EncryptionAlgorithm) -> Self {
        coset::Algorithm::Assigned(coset::iana::Algorithm::from(value))
    }
}

pub(crate) struct Encrypt<'a> {
    pub algorithm: &'a EncryptionAlgorithm,
    pub key: &'a FragmentEncryptionKeyBytes,
}

impl FnOnce<(&[u8], &[u8])> for Encrypt<'_> {
    type Output = std::result::Result<Vec<u8>, aes_gcm::Error>;

    extern "rust-call" fn call_once(self, (plaintext, aad): (&[u8], &[u8])) -> Self::Output {
        match self.algorithm {
            EncryptionAlgorithm::Aes256Gcm => {
                let key: [u8; 32] = self.key.deref().try_into().unwrap();
                Aes256Gcm::new(&key.into()).encrypt(
                    // The nonce is intentionally 0.
                    // Encryption keys are not reused, as long as `FragmentKey`s are not reused either.
                    // The user must be prevented from publishing multiple fragments with the same
                    // `FragmentKey`, and hence the same encryption key.
                    &Default::default(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
            }
        }
    }
}

pub(crate) struct Decrypt<'a> {
    pub algorithm: &'a EncryptionAlgorithm,
    pub key: &'a FragmentEncryptionKeyBytes,
}

impl FnOnce<(&[u8], &[u8])> for Decrypt<'_> {
    type Output = std::result::Result<Vec<u8>, aes_gcm::Error>;

    extern "rust-call" fn call_once(self, (ciphertext, aad): (&[u8], &[u8])) -> Self::Output {
        match self.algorithm {
            EncryptionAlgorithm::Aes256Gcm => {
                let key: [u8; 32] = self.key.deref().try_into().unwrap();
                Aes256Gcm::new(&key.into()).decrypt(
                    &Default::default(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
            }
        }
    }
}
