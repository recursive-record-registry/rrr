use std::{
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use async_trait::async_trait;
use chrono::{DateTime, FixedOffset, TimeZone};
use coset::{
    cbor::value::CanonicalValue, CoseEncrypt0, CoseSign, CoseSignature, Header, ProtectedHeader,
};
use derive_more::{Deref, DerefMut};

pub use coset::cbor::Value;
use indexmap::{Equivalent, IndexMap};
use serde::{Deserialize, Serialize};
use serde_with::SerializeAs;

use crate::error::{Error, Result};

pub const TAG_SELF_DESCRIBED_CBOR: u64 = 55799;

// TODO: These are not yet registered at IANA.
pub const TAG_RRR_REGISTRY: u64 = 0x52525243; // ASCII 'RRRC', C stands for config
pub const TAG_RRR_FRAGMENT: u64 = 0x52525246; // ASCII 'RRRF', F stands for fragment
pub const TAG_RRR_SEGMENT: u64 = 0x52525253; // ASCII 'RRRS', S stands for segment
pub const TAG_RRR_RECORD: u64 = 0x52525252; // ASCII 'RRRR', R stands for record

#[derive(Clone, Debug, Deref, DerefMut, PartialEq)]
pub struct HashableCborValue(pub Value);

// TODO: Might be a hack.
impl Eq for HashableCborValue {}

impl Hash for HashableCborValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        HashableCborValueRef(&self.0).hash(state)
    }
}

// impl Borrow<HashableCborValueRef<'_>> for HashableCborValue {
//     fn borrow(&self) -> &Value {
//         &self
//     }
// }

// impl Equivalent<Value> for HashableCborValue {
//     fn equivalent(&self, key: &Value) -> bool {
//         &self.0 == key
//     }
// }

#[derive(Clone, Copy, Debug, Deref, DerefMut, PartialEq)]
pub struct HashableCborValueRef<'a>(pub &'a Value);

// TODO: Might be a hack.
impl Eq for HashableCborValueRef<'_> {}

impl Hash for HashableCborValueRef<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut bytes = Vec::<u8>::new();
        coset::cbor::into_writer(&self.0, &mut bytes)
            .expect("Failed to serialize a CBOR value for hashing.");
        bytes.hash(state);
    }
}

impl Equivalent<HashableCborValue> for HashableCborValueRef<'_> {
    fn equivalent(&self, key: &HashableCborValue) -> bool {
        self.0 == &key.0
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Map(IndexMap<HashableCborValue, Value>);

impl Map {
    pub fn get_ref(&self, key: &Value) -> Option<&Value> {
        self.0.get(&HashableCborValueRef(key))
    }

    pub fn get(&self, key: impl Into<Value>) -> Option<&Value> {
        self.0.get(&HashableCborValue(key.into()))
    }

    pub fn insert(&mut self, key: impl Into<Value>, value: impl Into<Value>) -> Option<Value> {
        self.0.insert(HashableCborValue(key.into()), value.into())
    }

    pub fn shift_remove(&mut self, key: impl Into<Value>) -> Option<Value> {
        self.0.shift_remove(&HashableCborValue(key.into()))
    }

    pub fn shift_remove_ref(&mut self, key: &Value) -> Option<Value> {
        self.0.shift_remove(&HashableCborValueRef(key))
    }

    pub fn get_date_time(&self, key: impl Into<Value>) -> Option<DateTime<FixedOffset>> {
        self.get(key)?.as_datetime()
    }

    pub fn insert_date_time<Tz: TimeZone>(
        &mut self,
        key: impl Into<Value>,
        date_time: DateTime<Tz>,
    ) -> Option<Value> {
        self.insert(key, Value::new_datetime(&date_time))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&HashableCborValue, &Value)> {
        self.0.iter()
    }
}

impl Serialize for Map {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Value::Map(
            self.0
                .iter()
                .map(|(HashableCborValue(k), v)| (k.clone(), v.clone()))
                .collect(),
        )
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Map {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if let Value::Map(vec) = Value::deserialize(deserializer)? {
            Ok(Self(
                vec.into_iter()
                    .map(|(k, v)| (HashableCborValue(k), v))
                    .collect(),
            ))
        } else {
            Err(serde::de::Error::custom("Expected a CBOR map."))
        }
    }
}

pub trait HasHeaders {
    fn headers(&self) -> impl Iterator<Item = &Header>;
}

impl HasHeaders for Header {
    fn headers(&self) -> impl Iterator<Item = &Header> {
        std::iter::once(self)
    }
}

impl HasHeaders for ProtectedHeader {
    fn headers(&self) -> impl Iterator<Item = &Header> {
        self.header.headers()
    }
}

impl HasHeaders for CoseSign {
    fn headers(&self) -> impl Iterator<Item = &Header> {
        self.protected
            .headers()
            .chain(self.unprotected.headers())
            .chain(self.signatures.iter().flat_map(HasHeaders::headers))
    }
}

impl HasHeaders for CoseSignature {
    fn headers(&self) -> impl Iterator<Item = &Header> {
        self.protected.headers().chain(self.unprotected.headers())
    }
}

impl HasHeaders for CoseEncrypt0 {
    fn headers(&self) -> impl Iterator<Item = &Header> {
        self.protected.headers().chain(self.unprotected.headers())
    }
}

pub trait HasHeadersExt {
    fn ensure_no_critical_fields(&self) -> Result<()>;
}

impl<T> HasHeadersExt for T
where
    T: HasHeaders,
{
    fn ensure_no_critical_fields(&self) -> Result<()> {
        for header in self.headers() {
            if let Some(critical_field) = header.crit.first() {
                return Err(Error::UnrecognizedCriticalField {
                    field: critical_field.clone(),
                });
            }
        }

        Ok(())
    }
}

// pub trait CborDeserialize: Sized {
//     fn try_from_cbor(value: &Value) -> Result<Self>;
// }

// pub trait CborSerialize {
//     fn try_into_cbor(&self) -> Result<Value>;
// }

// impl<T> CborDeserialize for T
// where
//     T: AsCborValue,
// {
//     fn try_from_cbor(value: &Value) -> Result<Self> {
//         <T as AsCborValue>::from_cbor_value(value.clone()).map_err(Error::Coset)
//     }
// }

// impl<T> CborSerialize for T
// where
//     T: AsCborValue + Clone,
// {
//     fn try_into_cbor(&self) -> Result<Value> {
//         self.clone().to_cbor_value().map_err(Error::Coset)
//     }
// }

pub mod iana {
    #[repr(u64)]
    pub enum CborTag {
        DateTime = 0,
    }
}

// #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// #[serde(transparent)]
// pub struct Timestamp(pub tag::Required<DateTime<Utc>, { iana::CborTag::DateTime as u64 }>);

// // impl CborDeserialize for Timestamp {
// //     fn try_from_cbor(value: &Value) -> Result<Self> {
// //         let (tag, tagged_value) = value
// //             .as_tag()
// //             .ok_or_else(|| Error::UnexpectedItem(Cow::Borrowed("tag")))?;

// //         if tag != iana::CborTag::DateTime as u64 {
// //             // Standard Date/Time String
// //             return Err(Error::UnexpectedItem(Cow::Borrowed("tag")));
// //         }

// //         let text = tagged_value
// //             .as_text()
// //             .ok_or_else(|| Error::UnexpectedItem(Cow::Borrowed("tstr")))?;
// //         let timestamp = DateTime::parse_from_rfc3339(&text)
// //             .map_err(|_| Error::UnexpectedItem(Cow::Borrowed("RFC3339 date")))?;

// //         Ok(Self(timestamp.into()))
// //     }
// // }

// // impl CborSerialize for Timestamp {
// //     fn try_into_cbor(&self) -> Result<Value> {
// //         Ok(Value::Tag(
// //             iana::CborTag::DateTime as u64, // Standard Date/Time String
// //             Box::new(Value::Text(self.0.to_rfc3339())),
// //         ))
// //     }
// // }

// impl Zeroize for Timestamp {
//     fn zeroize(&mut self) {
//         let &mut Timestamp(Required(ref mut inner)) = self;
//         *inner = DateTime::UNIX_EPOCH;
//     }
// }

// pub struct AsTagged<T, const TAG: u64>(pub PhantomData<[T; TAG]>);

// impl<T: Serialize, const TAG: u64> SerializeAs<T> for AsTagged<T, TAG> {
//     fn serialize_as<S>(source: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         T::serialize(coset::cbor::tag::Accepted::<&T, TAG>(source), serializer)
//         // <Self as ConstHex<T, N>>::serialize(source, serializer)
//     }
// }

// impl<'de, T: Deserialize<'de>, const TAG: usize> DeserializeAs<'de, T> for AsTagged<T, TAG> {
//     fn deserialize_as<D>(deserializer: D) -> std::result::Result<T, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         coset::cbor::tag::Accepted::<T, TAG>::deserialize(deserializer).map()
//     }
// }

pub trait ValueExt
where
    Self: Sized,
{
    fn canonicalize(&mut self);
    fn is_canonical(&self) -> bool;
    fn new_datetime(datetime: &DateTime<impl TimeZone>) -> Self;
    fn is_datetime(&self) -> bool;
    fn as_datetime(&self) -> Option<DateTime<FixedOffset>>;
    fn into_datetime(self) -> ::std::result::Result<DateTime<FixedOffset>, Self>;
}

impl ValueExt for Value {
    fn canonicalize(&mut self) {
        match self {
            Value::Integer(_) => (),
            Value::Bytes(_) => (),
            Value::Float(_) => (),
            Value::Text(_) => (),
            Value::Bool(_) => (),
            Value::Null => (),
            Value::Tag(_, value) => value.canonicalize(),
            Value::Array(array) => {
                for value in array.iter_mut() {
                    value.canonicalize();
                }
            }
            Value::Map(map) => {
                for (key, value) in map.iter_mut() {
                    key.canonicalize();
                    value.canonicalize();
                }

                // TODO: This clones on every comparison. Optimize.
                map.sort_unstable_by_key(|(key, _)| CanonicalValue::from(key.clone()));
                map.dedup_by(|(key_a, _), (key_b, _)| key_a == key_b);
            }
            _ => panic!("Unsupported CBOR type."),
        }
    }

    fn is_canonical(&self) -> bool {
        match self {
            Value::Integer(_) => true,
            Value::Bytes(_) => true,
            Value::Float(_) => true,
            Value::Text(_) => true,
            Value::Bool(_) => true,
            Value::Null => true,
            Value::Tag(_, value) => value.is_canonical(),
            Value::Array(array) => array.iter().all(Self::is_canonical),
            Value::Map(map) => {
                for [(a_key, _), (b_key, _)] in map.array_windows() {
                    // Keys must be sorted and there must be no duplicates.
                    // TODO: This clones on every comparison. Optimize.
                    if CanonicalValue::from(a_key.clone()) >= CanonicalValue::from(b_key.clone()) {
                        return false;
                    }
                }

                map.iter().map(|(_, value)| value).all(Self::is_canonical)
            }
            _ => panic!("Unsupported CBOR type."),
        }
    }

    fn new_datetime(datetime: &DateTime<impl TimeZone>) -> Self {
        Value::Tag(
            iana::CborTag::DateTime as u64,
            Box::new(Value::Text(datetime.to_rfc3339())),
        )
    }

    fn is_datetime(&self) -> bool {
        self.as_datetime().is_some()
    }

    fn as_datetime(&self) -> Option<DateTime<FixedOffset>> {
        // A shorthand that requires deref patterns.
        // let string = match self {
        //     Value::Tag(tag, deref!(Value::Text(string)))
        //         if *tag == iana::CborTag::DateTime as u64 =>
        //     {
        //         string
        //     }
        //     _ => return None,
        // };

        let Value::Tag(tag, inner) = self else {
            return None;
        };

        if *tag != iana::CborTag::DateTime as u64 {
            return None;
        }

        let Value::Text(string) = &**inner else {
            return None;
        };

        let date_time = DateTime::parse_from_rfc3339(string).ok()?;

        Some(date_time)
    }

    fn into_datetime(self) -> ::std::result::Result<DateTime<FixedOffset>, Self> {
        self.as_datetime().ok_or(self)
    }
}

pub struct AsCanonicalValue<T>(pub PhantomData<T>);

impl<T: Serialize> SerializeAs<T> for AsCanonicalValue<T> {
    fn serialize_as<S>(source: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut value = Value::serialized(source).map_err(serde::ser::Error::custom)?;

        value.canonicalize();
        value.serialize(serializer)
    }
}

#[async_trait]
pub trait SerializeExt {
    fn as_canonical_cbor_value(&self) -> Result<Value>;
    fn as_canonical_cbor_bytes(&self) -> Result<Vec<u8>>;
    fn as_cbor_bytes(&self) -> Result<Vec<u8>>;
}

#[async_trait]
impl<T: Serialize> SerializeExt for T {
    fn as_canonical_cbor_value(&self) -> Result<Value> {
        let mut value = Value::serialized(self).map_err(Error::Cbor)?;

        value.canonicalize();

        Ok(value)
    }

    fn as_canonical_cbor_bytes(&self) -> Result<Vec<u8>> {
        self.as_canonical_cbor_value()?.as_cbor_bytes()
    }

    fn as_cbor_bytes(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        // TODO: This is a blocking operation. Defer to a blocking task.
        coset::cbor::into_writer(&self, &mut result).map_err(Error::CborSer)?;

        Ok(result)
    }
}
