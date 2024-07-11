//! Key derivation functions (KDF's) are used to derive secrets of arbitrary length from
//! an input key material. In the case of _rrr_, the input key material is the output of
//! a password hashing function.
//! The idea is that once we have the password hash, it is quick to compute secrets using
//! the KDF.

use hkdf::HkdfParams;
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

use crate::{cbor::SerializeExt, error::Result};

pub mod hkdf;

pub trait Kdf {
    fn derive_key(&self, ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()>;
}

#[derive(Arbitrary, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KdfAlgorithm {
    Hkdf(HkdfParams),
}

impl Kdf for KdfAlgorithm {
    fn derive_key(&self, ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
        match self {
            Self::Hkdf(params) => params.derive_key(ikm, info, okm),
        }
    }
}

pub trait KdfExt {
    fn derive_key_from_canonicalized_cbor(
        &self,
        ikm: &[u8],
        info: impl Serialize,
        okm: &mut [u8],
    ) -> Result<()>;
}

impl<T: Kdf> KdfExt for T {
    fn derive_key_from_canonicalized_cbor(
        &self,
        ikm: &[u8],
        info: impl Serialize,
        okm: &mut [u8],
    ) -> Result<()> {
        let cbor_bytes = info.as_canonical_cbor_bytes()?;

        self.derive_key(ikm, &cbor_bytes, okm)
    }
}
