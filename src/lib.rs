#![feature(array_windows)]
#![feature(fn_traits)]
#![feature(try_blocks)]
#![feature(unboxed_closures)]

use coset::cbor::cbor;

#[macro_use]
pub mod utils;

pub mod cbor;
pub mod crypto;
pub mod error;
pub mod record;
pub mod registry;

#[cfg(feature = "cmd")]
pub mod cmd;
