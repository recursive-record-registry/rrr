use std::fmt::Debug;

use coset::{AsCborValue, CoseKey, CoseKeyBuilder, KeyType, RegisteredLabelWithPrivate};
use derive_more::{Deref, DerefMut};
use ed25519_dalek::{
    ed25519::signature::Signer,
    pkcs8::{
        self, spki::der::Decode, DecodePrivateKey, EncodePrivateKey, ObjectIdentifier,
        PrivateKeyInfo,
    },
};
use itertools::Itertools;
use proptest::{
    arbitrary::{any, Arbitrary},
    prop_compose, prop_oneof,
    strategy::{BoxedStrategy, Strategy},
};
use serde::{Deserialize, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    cbor,
    error::{Result, SignatureMismatch},
    utils::serde::Secret,
};

#[derive(Clone, PartialEq, Eq, Deref, DerefMut)]
pub struct SigningKeyEd25519(pub ed25519_dalek::SigningKey);

impl Zeroize for SigningKeyEd25519 {
    fn zeroize(&mut self) {
        self.0 = ed25519_dalek::SigningKey::from_bytes(&Default::default());
    }
}

impl Drop for SigningKeyEd25519 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SigningKeyEd25519 {}

#[derive(Clone, PartialEq, Eq)]
pub enum SigningKey {
    Ed25519(Secret<SigningKeyEd25519>),
}

impl SigningKey {
    // pub async fn write_pem(&self, write: impl AsyncWrite) -> Result<()> {
    //     match self {
    //         Self::Ed25519(key) => {
    //             let pem = ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_pem(
    //                 key,
    //                 LineEnding::default(),
    //             )?;
    //         }
    //     }
    // }

    pub fn try_sign(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Ed25519(key) => Ok(key.try_sign(plaintext)?.to_vec()),
        }
    }

    pub fn key_type_name(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "ed25519",
        }
    }
}

impl EncodePrivateKey for SigningKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        match self {
            Self::Ed25519(key) => key.to_pkcs8_der(),
        }
    }
}

impl DecodePrivateKey for SigningKey {
    fn from_pkcs8_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        let info = PrivateKeyInfo::from_der(bytes)?;

        match info.algorithm.oid {
            oid if oid == ObjectIdentifier::new_unwrap("1.3.101.112") => Ok(Self::Ed25519(Secret(
                SigningKeyEd25519(ed25519_dalek::SigningKey::try_from(info)?),
            ))),
            _ => Err(pkcs8::Error::KeyMalformed),
        }
    }
}

impl FnOnce<(&[u8],)> for &'_ SigningKey {
    type Output = Result<Vec<u8>>;

    extern "rust-call" fn call_once(self, (plaintext,): (&[u8],)) -> Self::Output {
        self.try_sign(plaintext)
    }
}

// impl Serialize for SigningKey {
//     fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         Bytes::new(self.0.as_bytes()).serialize(serializer)
//     }
// }

// impl<'de> Deserialize<'de> for SigningKey {
//     fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         let bytes = ByteBuf::deserialize(deserializer)?;

//         Ok(SigningKey(ed25519_dalek::SigningKey::from_bytes(
//             bytes.as_ref().try_into().unwrap(),
//         )))
//     }
// }

// impl From<[u8; ed25519_dalek::SECRET_KEY_LENGTH]> for SigningKey {
//     fn from(bytes: [u8; ed25519_dalek::SECRET_KEY_LENGTH]) -> Self {
//         Self(ed25519_dalek::SigningKey::from_bytes(&bytes))
//     }
// }

// impl TryFrom<&[u8]> for SigningKey {
//     type Error = TryFromSliceError;

//     fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
//         Ok(Self(ed25519_dalek::SigningKey::from_bytes(
//             slice.try_into()?,
//         )))
//     }
// }

// impl Deref for SigningKey {
//     type Target = [u8; ed25519_dalek::SECRET_KEY_LENGTH];

//     fn deref(&self) -> &Self::Target {
//         self.0.as_bytes()
//     }
// }

impl Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            SigningKey::Ed25519(_) => "Ed25519",
        };
        f.debug_struct(&format!("SigningKey::{}", variant))
            .finish_non_exhaustive()
    }
}

fn arb_signing_key() -> impl Strategy<Value = SigningKey> {
    prop_oneof![
        proptest::array::uniform(any::<u8>()).prop_map(|bytes| SigningKey::Ed25519(Secret(
            SigningKeyEd25519(ed25519_dalek::SigningKey::from_bytes(&bytes))
        ))),
    ]
}

impl Arbitrary for SigningKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        arb_signing_key().boxed()
    }
}

#[derive(Clone, PartialEq, Eq, Deref, DerefMut)]
pub struct VerifyingKeyEd25519(pub(crate) ed25519_dalek::VerifyingKey);

impl Debug for VerifyingKeyEd25519 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VerifyingKeyEd25519({:02x})",
            self.as_bytes().iter().format("")
        )
    }
}

/// # Serialization/Deserialization
/// This type can be serialized into/deserialized from `CoseKey` using `serde_with`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyingKey {
    Ed25519(VerifyingKeyEd25519),
}

impl VerifyingKey {
    pub fn try_verify(
        &self,
        signature: &[u8],
        tbs_data: &[u8],
    ) -> std::result::Result<(), SignatureMismatch> {
        match self {
            Self::Ed25519(key) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| SignatureMismatch)?;
                key.verify_strict(tbs_data, &signature)
                    .map_err(|_| SignatureMismatch)?;
                Ok(())
            }
        }
    }
}

impl FnOnce<(&[u8], &[u8])> for &'_ VerifyingKey {
    type Output = std::result::Result<(), SignatureMismatch>;

    extern "rust-call" fn call_once(self, (signature, tbs_data): (&[u8], &[u8])) -> Self::Output {
        self.try_verify(signature, tbs_data)
    }
}

prop_compose! {
    fn arb_verifying_key()(signing_key in any::<SigningKey>()) -> VerifyingKey {
        VerifyingKey::from(&signing_key)
    }
}

impl Arbitrary for VerifyingKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        arb_verifying_key().boxed()
    }
}

impl SerializeAs<VerifyingKey> for CoseKey {
    fn serialize_as<S>(source: &VerifyingKey, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let cose_key = match source {
            VerifyingKey::Ed25519(key) => CoseKeyBuilder::new_okp_key()
                .algorithm(coset::iana::Algorithm::EdDSA)
                .param(
                    coset::iana::Ec2KeyParameter::Crv as i64,
                    cbor::Value::from(coset::iana::EllipticCurve::Ed25519 as u64),
                )
                .param(
                    coset::iana::Ec2KeyParameter::X as i64,
                    cbor::Value::Bytes(key.to_bytes().into()),
                )
                .build(),
        };
        let cbor_value = cose_key.to_cbor_value().unwrap();

        cbor_value.serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, VerifyingKey> for CoseKey {
    fn deserialize_as<D>(deserializer: D) -> std::result::Result<VerifyingKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cbor_value = cbor::Value::deserialize(deserializer)?;
        let cose_key = CoseKey::from_cbor_value(cbor_value).unwrap();

        if cose_key.kty != KeyType::Assigned(coset::iana::KeyType::OKP) {
            return Err(serde::de::Error::custom(
                "Unsupported CoseKey key type `kty`.",
            ));
        }

        let crv = cose_key
            .params
            .iter()
            .filter_map(|(label, value)| {
                if label == &coset::Label::Int(coset::iana::Ec2KeyParameter::Crv as i64) {
                    Some(value)
                } else {
                    None
                }
            })
            .next()
            .ok_or_else(|| serde::de::Error::custom("CoseKey is missing a `crv` parameter."))?;

        match crv {
            crv if crv == &cbor::Value::from(coset::iana::EllipticCurve::Ed25519 as u64) => {
                if let Some(algorithm) = cose_key.alg.as_ref() {
                    if algorithm
                        != &RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA)
                    {
                        return Err(serde::de::Error::custom(
                            "CoseKey is restricted to an unsupported algorithm `alg`.",
                        ));
                    }
                }

                let bytes = cose_key
                    .params
                    .iter()
                    .filter_map(|(label, value)| {
                        if label == &coset::Label::Int(coset::iana::Ec2KeyParameter::X as i64) {
                            if let cbor::Value::Bytes(bytes) = value {
                                Some(bytes)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .next()
                    .ok_or_else(|| {
                        serde::de::Error::custom("CoseKey is missing a `crv` parameter.")
                    })?;
                let key =
                    ed25519_dalek::VerifyingKey::from_bytes(&bytes.as_slice().try_into().unwrap())
                        .unwrap();

                Ok(VerifyingKey::Ed25519(VerifyingKeyEd25519(key)))
            }
            _ => Err(serde::de::Error::custom(
                "CoseKey has an unsupported `crv` value.",
            )),
        }
    }
}

impl From<&SigningKey> for VerifyingKey {
    fn from(signing_key: &SigningKey) -> Self {
        match signing_key {
            SigningKey::Ed25519(signing_key) => {
                Self::Ed25519(VerifyingKeyEd25519(signing_key.verifying_key()))
            }
        }
    }
}

// impl Serialize for VerifyingKey {
//     fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         match self {
//             VerifyingKey::Ed25519(key) => Bytes::new(key.as_bytes()).serialize(serializer),
//         }
//     }
// }

// impl<'de> Deserialize<'de> for VerifyingKey {
//     fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         let bytes = ByteBuf::deserialize(deserializer)?;

//         Ok(VerifyingKey::Ed25519(
//             ed25519_dalek::VerifyingKey::from_bytes(bytes.as_ref().try_into().unwrap()).unwrap(),
//         ))
//     }
// }

impl Zeroize for VerifyingKey {
    fn zeroize(&mut self) {
        match self {
            VerifyingKey::Ed25519(VerifyingKeyEd25519(key)) => *key = Default::default(),
        }
    }
}

impl Drop for VerifyingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifyingKey {}

#[cfg(test)]
mod test {
    #[tokio::test]
    pub async fn test_pem() {
        // TODO
    }
}
