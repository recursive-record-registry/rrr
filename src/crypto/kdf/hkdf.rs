use ::hkdf::Hkdf;
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};

use crate::error::Result;

use super::Kdf;

#[derive(Arbitrary, Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HkdfPrf {
    #[default]
    Sha256,
    Sha512,
}

#[derive(Arbitrary, Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HkdfParams {
    /// Underlying pseudo-random function.
    pub prf: HkdfPrf,
}

impl Kdf for HkdfParams {
    fn derive_key(&self, ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
        match self.prf {
            HkdfPrf::Sha256 => Hkdf::<Sha256>::new(None, ikm).expand(info, okm).unwrap(),
            HkdfPrf::Sha512 => Hkdf::<Sha512>::new(None, ikm).expand(info, okm).unwrap(),
        }

        Ok(())
    }
}
