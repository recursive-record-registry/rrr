//! # TODO
//! * [ ] Replace Argon2's pepper with configured initial succession nonce, do not use pepper by default.
//! * [ ] Splitting records into multiple files.
//!     * [x] Basic library implementation
//!     * [ ] Record splitting strategies
//!     * [ ] Tests
//!     * [ ] Random segment content padding
//!     * [ ] Command line implementation
//! * [ ] Support multiple versions of records.
//!     * [x] Basic library implementation
//!     * [ ] Version listing
//!     * [ ] Tests
//!     * [ ] Command line implementation
//! * [ ] Support multiple encryption algorithms, that are supported by the COSE and PEM specs.
//!     * [x] AES-256-GCM
//!     * [ ] ChaCha20-Poly1305
//!     * [ ] Make them optional at compile-time.
//! * [ ] Support multiple signing algorithms, that are supported by the COSE and PEM specs.
//!     * [x] Ed25519
//!     * [ ] Ed448 -- No RustCrypto implementation available yet.
//!     * [ ] Make them optional at compile-time.
//! * [ ] Support multiple KDF algorithms.
//!     * [x] HKDF
//!         * [x] SHA256
//!         * [x] SHA512
//!     * [ ] An alternative
//!     * [ ] Make them optional at compile-time.
//! * [ ] Support multiple password hashing algorithms.
//!     * [x] Argon2
//!         * [x] Argon2d
//!         * [x] Argon2id
//!         * [x] Argon2i
//!     * [ ] An alternative
//!     * [ ] Make them optional at compile-time.
//! * [ ] Versioning of formats of registries and record fragments.
//! * [ ] CDDL verification
//!     * [ ] Documents
//!         * [x] Registry config
//!         * [x] Record
//!         * [x] Segment
//!         * [ ] Fragment
//!     * [ ] Use generics to conditionally enable lenient matching for input data
//! * [ ] Use `cargo-mutants` to test proper handling and reporting of malformed data
//! * [ ] Address the `unwrap` situation.
//! * [ ] More granularity in errors.
//! * [ ] Feature for proptest stuff
//! * [ ] Consider making the encryption algorithm a config parameter
//! * [ ] Register IANA CBOR tags for `registry.cbor`, record, segment and fragment. Files should have the
//!       form #6.55799(#MYTAG(_)), as per https://www.rfc-editor.org/rfc/rfc9277.html#section-2.2.1
//!       See https://www.rfc-editor.org/rfc/rfc9277.html#name-the-cbor-protocol-specific- for
//!       registration instructions.
#![feature(array_windows)]
#![feature(async_closure)]
#![feature(deref_patterns)]
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
