//! Password hashing algorithms are used to seed key derivation functions (KDF's).
//! They are intentionally slow, to make brute-force attacks difficult.
//! See the [`crate::crypto::kdf`] module.

use argon2::Argon2Params;
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Result;

pub mod argon2;

pub trait PasswordHash {
    fn hash_password(&self, password: &[u8], salt: &[u8], output: &mut [u8]) -> Result<()>;
}

#[derive(
    Arbitrary, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop,
)]
#[serde(rename_all = "snake_case")]
pub enum PasswordHashAlgorithm {
    Argon2(Argon2Params),
}

impl PasswordHash for PasswordHashAlgorithm {
    fn hash_password(&self, password: &[u8], salt: &[u8], output: &mut [u8]) -> Result<()> {
        match self {
            Self::Argon2(params) => params.hash_password(password, salt, output),
        }
    }
}
