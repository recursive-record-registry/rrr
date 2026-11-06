use std::{
    fmt::{Debug, Display},
    ops::Deref,
};

use crate::record::segment::FragmentEncryptionKeyBytes;
use aes_gcm_siv::{
    Aes256GcmSiv, KeyInit,
    aead::{Aead, Payload},
};
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

// TODO: Incomplete implementation
#[derive(Arbitrary, Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM-SIV, as specified in [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452).
    ///
    /// Unlike AES-GCM, it is resistant to nonce misuse: encrypting different plaintexts with the
    /// same key and nonce only reveals whether the plaintexts are equal.
    Aes256GcmSiv,
}

impl EncryptionAlgorithm {
    /// The COSE algorithm identifier of AES-256-GCM-SIV.
    ///
    /// The IANA "COSE Algorithms" registry has no entry for AES-GCM-SIV, so a value from the
    /// range reserved for private use (less than -65536) is used.
    // TODO: Register a standard value above -65535 for AES-256-GCM-SIV, and use it instead.
    pub const COSE_LABEL_AES_256_GCM_SIV: i64 = -69173;

    pub fn key_length_in_bytes(&self) -> usize {
        match self {
            Self::Aes256GcmSiv => 32,
        }
    }
}

impl Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes256GcmSiv => write!(f, "AES-256-GCM-SIV"),
        }
    }
}

impl TryFrom<coset::Algorithm> for EncryptionAlgorithm {
    type Error = ();

    fn try_from(value: coset::Algorithm) -> Result<Self, Self::Error> {
        use coset::RegisteredLabelWithPrivate::*;
        match value {
            PrivateUse(Self::COSE_LABEL_AES_256_GCM_SIV) => Ok(Self::Aes256GcmSiv),
            _ => Err(()),
        }
    }
}

impl From<EncryptionAlgorithm> for coset::Algorithm {
    fn from(value: EncryptionAlgorithm) -> Self {
        match value {
            EncryptionAlgorithm::Aes256GcmSiv => {
                coset::Algorithm::PrivateUse(EncryptionAlgorithm::COSE_LABEL_AES_256_GCM_SIV)
            }
        }
    }
}

/// Encrypts `plaintext` with the given algorithm and key, authenticating `aad`.
pub(crate) fn encrypt(
    algorithm: &EncryptionAlgorithm,
    key: &FragmentEncryptionKeyBytes,
    plaintext: &[u8],
    aad: &[u8],
) -> std::result::Result<Vec<u8>, aes_gcm_siv::Error> {
    match algorithm {
        EncryptionAlgorithm::Aes256GcmSiv => {
            let key: [u8; 32] = key.deref().try_into().unwrap();
            Aes256GcmSiv::new(&key.into()).encrypt(
                // The nonce is intentionally 0.
                // Each `FragmentKey` derives its own encryption key, so a key is only reused
                // when the same fragment is written again, such as when a published record
                // version is overwritten. AES-GCM-SIV derives the IV from the plaintext, so
                // this only reveals whether the two plaintexts are equal.
                &Default::default(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
        }
    }
}

/// Decrypts `ciphertext` with the given algorithm and key, verifying `aad`.
pub(crate) fn decrypt(
    algorithm: &EncryptionAlgorithm,
    key: &FragmentEncryptionKeyBytes,
    ciphertext: &[u8],
    aad: &[u8],
) -> std::result::Result<Vec<u8>, aes_gcm_siv::Error> {
    match algorithm {
        EncryptionAlgorithm::Aes256GcmSiv => {
            let key: [u8; 32] = key.deref().try_into().unwrap();
            Aes256GcmSiv::new(&key.into()).decrypt(
                &Default::default(),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
        }
    }
}
