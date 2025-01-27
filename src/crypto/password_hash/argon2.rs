use crate::utils::serde::{BytesOrHexString, Secret};
use proptest::{
    arbitrary::{any, Arbitrary},
    prop_compose,
    strategy::{BoxedStrategy, Just, Strategy},
};
use proptest_derive::Arbitrary;
use std::fmt::Debug;

use crate::error::Result;
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::PasswordHash;

#[derive(Arbitrary, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Variant {
    // #[serde(rename = "argon2d")]
    Argon2d,
    // #[serde(rename = "argon2i")]
    Argon2i,
    // #[serde(rename = "argon2id")]
    Argon2id,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Argon2Params {
    /// The specific Argon2 algorithm to be used.
    #[zeroize(skip)]
    pub variant: Variant,
    /// Memory size in 1 KiB blocks. Between 8\*`p_cost` and (2^32)-1.
    #[zeroize(skip)]
    pub m_cost: u32,
    /// Number of iterations. Between 1 and (2^32)-1.
    #[zeroize(skip)]
    pub t_cost: u32,
    /// Degree of parallelism. Between 1 and (2^24)-1.
    #[zeroize(skip)]
    pub p_cost: u32,
    pub pepper: Option<Secret<BytesOrHexString<Vec<u8>>>>,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            variant: Variant::Argon2id,
            m_cost: 1 << 10, // 1 MiB
            t_cost: 1 << 10,
            p_cost: 1,
            pepper: None,
        }
    }
}

impl PasswordHash for Argon2Params {
    fn hash_password(&self, password: &[u8], salt: &[u8], output: &mut [u8]) -> Result<()> {
        let variant = match self.variant {
            Variant::Argon2d => argon2::Algorithm::Argon2d,
            Variant::Argon2i => argon2::Algorithm::Argon2i,
            Variant::Argon2id => argon2::Algorithm::Argon2id,
        };
        let argon2 = if let Some(pepper) = self.pepper.as_ref() {
            Argon2::new_with_secret(
                pepper,
                variant,
                argon2::Version::V0x13,
                argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(output.len()))?,
            )?
        } else {
            Argon2::new(
                variant,
                argon2::Version::V0x13,
                argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(output.len()))?,
            )
        };
        argon2.hash_password_into(password, salt, output)?;

        Ok(())
    }
}

prop_compose! {
    fn arb_hash_params(log_max_cost: u32)(
        t_cost in 1_u32..(1 << log_max_cost),
        p_cost in 1_u32..(1 << log_max_cost),
    )(
        variant in any::<Variant>(),
        m_cost in (8 * p_cost)..(std::cmp::max(8 * p_cost + 1, 1 << log_max_cost)),
        t_cost in Just(t_cost),
        p_cost in Just(p_cost),
        pepper in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..(1 << 10))),
    ) -> Argon2Params {
        Argon2Params {
            variant,
            m_cost,
            t_cost,
            p_cost,
            pepper: pepper.map(|pepper| Secret(BytesOrHexString(pepper))),
        }
    }
}

impl Arbitrary for Argon2Params {
    type Parameters = ();
    type Strategy = BoxedStrategy<Argon2Params>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        arb_hash_params(6).boxed()
    }
}
