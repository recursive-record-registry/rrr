use std::{
    array::TryFromSliceError,
    borrow::Cow,
    fmt::{Debug, Display, LowerHex, UpperHex},
    marker::PhantomData,
    ops::Deref,
};

use derive_more::{Deref, DerefMut};
use hex_buffer_serde::{ConstHex, Hex};
use itertools::Itertools;
use proptest::{
    arbitrary::Arbitrary,
    strategy::{BoxedStrategy, Strategy},
};
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeAs, SerializeAs};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Serialization/Deserialization utility for serializing/deserializing byte arrays as hex strings
/// for human-readable formats, and as-is for binary formats, using the `serde_with` crate.
///
/// ```
/// use core::{array::TryFromSliceError, convert::TryFrom};
/// use serde::{Serialize, Deserialize};
/// use serde_with::serde_as;
/// use hex_buffer_serde::Hex;
/// use rrr::serde_utils::BytesOrHexStringOf;
///
/// pub struct OurBuffer(Vec<u8>);
///
/// impl From<&[u8]> for OurBuffer {
///     fn from(slice: &[u8]) -> Self {
///         Self(slice.into())
///     }
/// }
///
/// impl AsRef<[u8]> for OurBuffer {
///     fn as_ref(&self) -> &[u8] {
///         &self.0
///     }
/// }
///
/// #[serde_as]
/// #[derive(Serialize, Deserialize)]
/// pub struct Example {
///     #[serde_as(as = "Vec<BytesOrHexStringOf::<OurBuffer>>")]
///     buffer: Vec<OurBuffer>,
///     // other fields...
/// }
/// ```
#[derive(Debug)]
pub struct BytesOrHexStringOf<T>(PhantomData<T>);

impl<T, E> Hex<T> for BytesOrHexStringOf<T>
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>,
    E: std::fmt::Display,
{
    type Error = E;

    fn create_bytes(buffer: &T) -> Cow<'_, [u8]> {
        Cow::Borrowed(buffer.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> std::result::Result<T, Self::Error> {
        T::try_from(bytes)
    }
}

impl<T, E> SerializeAs<T> for BytesOrHexStringOf<T>
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>,
    E: std::fmt::Display,
{
    fn serialize_as<S>(source: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <Self as Hex<T>>::serialize(source, serializer)
    }
}

impl<'de, T, E> DeserializeAs<'de, T> for BytesOrHexStringOf<T>
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>,
    E: std::fmt::Display,
{
    fn deserialize_as<D>(deserializer: D) -> std::result::Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <Self as Hex<T>>::deserialize(deserializer)
    }
}

#[derive(
    Clone, Serialize, Deserialize, Deref, DerefMut, Default, PartialEq, Eq, PartialOrd, Ord, Zeroize,
)]
#[serde(transparent)]
pub struct BytesOrHexString<T, E = <T as TryFrom<&'static [u8]>>::Error>(
    #[serde(with = "BytesOrHexStringOf")] pub T,
)
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>,
    E: std::fmt::Display;

impl<T, E> From<T> for BytesOrHexString<T, E>
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>,
    E: std::fmt::Display,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T, E> LowerHex for BytesOrHexString<T, E>
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>,
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.as_ref().iter().format(""))
    }
}

impl<T, E> UpperHex for BytesOrHexString<T, E>
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>,
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X}", self.as_ref().iter().format(""))
    }
}

impl<T, E> Display for BytesOrHexString<T, E>
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>,
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl<T, E> Debug for BytesOrHexString<T, E>
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E>,
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<T, E> Arbitrary for BytesOrHexString<T, E>
where
    T: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = E> + Arbitrary,
    E: std::fmt::Display,
    T::Strategy: 'static,
{
    type Parameters = T::Parameters;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        T::arbitrary_with(args)
            .prop_map(|value| Self(value))
            .boxed()
    }
}

/// Serialization/Deserialization utility for serializing/deserializing constant-length byte arrays as hex strings
/// for human-readable formats, and as-is for binary formats, using the `serde_with` crate.
///
/// ```
/// use core::ops::Deref;
/// use serde::{Serialize, Deserialize};
/// use serde_with::serde_as;
/// use hex_buffer_serde::ConstHex;
/// use rrr::serde_utils::ConstBytesOrHexStringOf;
///
/// pub struct OurBuffer([u8; 8]);
///
/// impl From<[u8; 8]> for OurBuffer {
///     fn from(slice: [u8; 8]) -> Self {
///         Self(slice)
///     }
/// }
///
/// impl Deref for OurBuffer {
///     type Target = [u8; 8];
///
///     fn deref(&self) -> &Self::Target {
///         &self.0
///     }
/// }
///
/// #[serde_as]
/// #[derive(Serialize, Deserialize)]
/// pub struct Example {
///     #[serde_as(as = "Vec<ConstBytesOrHexStringOf::<OurBuffer>>")]
///     buffer: Vec<OurBuffer>,
///     // other fields...
/// }
/// ```
#[derive(Debug)]
pub struct ConstBytesOrHexStringOf<T>(PhantomData<T>);

impl<const N: usize, T> ConstHex<T, N> for ConstBytesOrHexStringOf<T>
where
    T: Deref<Target = [u8; N]> + From<[u8; N]>,
{
    type Error = TryFromSliceError;

    fn create_bytes(buffer: &T) -> [u8; N] {
        *buffer.deref()
    }

    fn from_bytes(bytes: [u8; N]) -> Result<T, Self::Error> {
        Ok(T::from(bytes))
    }
}

impl<const N: usize, T> SerializeAs<T> for ConstBytesOrHexStringOf<T>
where
    T: Deref<Target = [u8; N]> + From<[u8; N]>,
{
    fn serialize_as<S>(source: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <Self as ConstHex<T, N>>::serialize(source, serializer)
    }
}

impl<'de, const N: usize, T> DeserializeAs<'de, T> for ConstBytesOrHexStringOf<T>
where
    T: Deref<Target = [u8; N]> + From<[u8; N]>,
{
    fn deserialize_as<D>(deserializer: D) -> std::result::Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <Self as ConstHex<T, N>>::deserialize(deserializer)
    }
}

#[derive(
    Arbitrary,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    Deref,
    DerefMut,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Zeroize,
)]
#[serde(transparent)]
pub struct ConstBytesOrHexString<const N: usize, T>(
    #[serde(with = "ConstBytesOrHexStringOf")] pub T,
)
where
    T: Deref<Target = [u8; N]> + From<[u8; N]>;

impl<const N: usize, T> From<T> for ConstBytesOrHexString<N, T>
where
    T: Deref<Target = [u8; N]> + From<[u8; N]>,
{
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<const N: usize, T> LowerHex for ConstBytesOrHexString<N, T>
where
    T: Deref<Target = [u8; N]> + From<[u8; N]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.iter().format(""))
    }
}

impl<const N: usize, T> UpperHex for ConstBytesOrHexString<N, T>
where
    T: Deref<Target = [u8; N]> + From<[u8; N]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02X}", self.iter().format(""))
    }
}

impl<const N: usize, T> Display for ConstBytesOrHexString<N, T>
where
    T: Deref<Target = [u8; N]> + From<[u8; N]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl<const N: usize, T> Debug for ConstBytesOrHexString<N, T>
where
    T: Deref<Target = [u8; N]> + From<[u8; N]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

/// A wrapper with a custom [`Display`] and [`Debug`] implementation to hide the underlying data.
#[derive(
    Arbitrary,
    Clone,
    Default,
    Deref,
    DerefMut,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Zeroize,
    ZeroizeOnDrop,
)]
#[serde(transparent)]
pub struct Secret<T: Zeroize>(pub T);

impl<T> Display for Secret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret")
    }
}

impl<T> Debug for Secret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
        // write!(f, "Secret<{}>", std::any::type_name::<T>())
    }
}

#[derive(
    Arbitrary,
    Clone,
    Default,
    Deref,
    DerefMut,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Zeroize,
)]
#[serde(transparent)]
pub struct BytesOrAscii<T, const DEBUG_TRIM_LEN: usize = { usize::MAX }>(
    #[serde(with = "BytesOrHexStringOf")] pub T,
)
where
    T: AsRef<[u8]> + for<'a> From<&'a [u8]>;

impl<T, const DEBUG_TRIM_LEN: usize> Display for BytesOrAscii<T, DEBUG_TRIM_LEN>
where
    T: AsRef<[u8]> + for<'a> From<&'a [u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let slice = self.as_ref();
        let string = slice
            .iter()
            .flat_map(|byte| byte.escape_ascii().map(char::from))
            .collect::<String>();

        write!(f, r#"b"{string}""#,)
    }
}

impl<T, const DEBUG_TRIM_LEN: usize> Debug for BytesOrAscii<T, DEBUG_TRIM_LEN>
where
    T: AsRef<[u8]> + for<'a> From<&'a [u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let slice = self.as_ref();
        let trimmed = DEBUG_TRIM_LEN != usize::MAX && slice.len() > DEBUG_TRIM_LEN;
        let slice = if trimmed {
            &slice[0..DEBUG_TRIM_LEN]
        } else {
            slice
        };
        let string = slice
            .iter()
            .flat_map(|byte| byte.escape_ascii().map(char::from))
            .collect::<String>();

        write!(
            f,
            r#"b"{string}"{ellipsis}"#,
            ellipsis = if trimmed { "…" } else { "" }
        )
    }
}
