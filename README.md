<img src="https://raw.githubusercontent.com/recursive-record-registry/rrr-assets/1b1ca5e008fb990e35de10a1a4ecdd4a5f94e2be/logo/logo_framed_white.svg" width="64px" align="right" />

# Recursive Record Registry (RRR)
Implementation of the Recursive Record Registry data format in Rust.

This repository contains a basic command-line tool for reading Recursive Record Registries, as well as a Rust library for reading and creating record registries.

## About the RRR data format
A specification for the secure storage of digital information in a tree structure, where each subtree is password-protected.
Without knowing the passwords (and thus being able to browse the registry), the structure and the contents of the tree is unknown to the user.
The intention is for the registry to be distributed with 3rd parties.
The specification guarantees integrity, authentication, and non-repudiation of the stored records, from the author of the registry, provided that the reader trusts the registry's `registry.cbor` file (see [Trust model](#trust-model)).
The aim of this project is to provide an interesting platform for storytelling and the creation of puzzles.

### Trust model
The `registry.cbor` file is the trust anchor of a registry.
It contains the verifying keys of the registry's author, as well as the parameters needed to locate and decrypt records.
The record fragments in the `records` directory may be obtained from anyone, because each fragment is verified against the keys in `registry.cbor`.
The `registry.cbor` file itself is not signed, so it must be obtained from the author, or from a source that the reader trusts to have left it unmodified.
Whoever can replace it can substitute their own keys, and then replace or re-sign any record.
If `registry.cbor` lists no verifying keys, record fragments are not authenticated at all.

A trusted `registry.cbor` does not protect against omission: whoever distributes the record fragments can withhold some of them, or withhold newer versions of records.
Readers then see an older version of a record, or an incomplete one, and the signatures cannot detect this.

## Compiling the executable binary
1. Install Rust via [rustup.rs](https://rustup.rs/)
2. Clone this repository using Git or download it as an archive
3. Open the repository in your shell, and compile the executable binary by running:
    ```sh
    cargo build --release --bin rrr --features cmd
    ```
4. If the compilation was successful, the executable binary is now located in the `target/release` directory.
Launch it by running the following:
    ```sh
    # On Windows
    target\release\rrr.exe
    # On Unix
    target/release/rrr
    ```

## Cargo features
* `cmd` -- the `rrr` command-line tool.
* `proptest` -- [`proptest`](https://crates.io/crates/proptest) strategies and `Arbitrary`
  implementations for the library's types, for property-based tests of crates that depend on
  this one. This crate's own tests enable it automatically.

## TODO
* [ ] Splitting records into multiple files.
    * [x] Basic library implementation
    * [x] Pad contents to a registry-wide constant length.
    * [ ] Record splitting strategies
    * [ ] Tests
    * [x] Command line implementation
* [ ] Support multiple versions of records.
    * [x] Basic library implementation
    * [ ] Version listing
    * [x] Tests
    * [x] Command line implementation
* [ ] Support multiple encryption algorithms, that are supported by the COSE and PEM specs.
    * [x] AES-256-GCM-SIV
    * [ ] ChaCha20-Poly1305
    * [ ] Make them optional at compile-time.
* [ ] Support multiple signing algorithms, that are supported by the COSE and PEM specs.
    * [x] Ed25519
    * [ ] Ed448 -- No RustCrypto implementation available yet.
    * [ ] Make them optional at compile-time.
* [ ] Support multiple KDF algorithms.
    * [x] HKDF
        * [x] SHA256
        * [x] SHA512
    * [ ] An alternative
    * [ ] Make them optional at compile-time.
* [ ] Support multiple password hashing algorithms.
    * [x] Argon2
        * [x] Argon2d
        * [x] Argon2id
        * [x] Argon2i
    * [ ] An alternative
    * [ ] Make them optional at compile-time.
* [ ] Versioning of formats of registries and record fragments.
* [ ] Use `cargo-mutants` to test proper handling and reporting of malformed data
* [ ] Address the `unwrap` situation.
* [ ] More granularity in errors.
* [x] Feature for proptest stuff
* [ ] Consider making the encryption algorithm a config parameter
* [ ] Register IANA CBOR tags for `registry.cbor`, record, segment and fragment. Files should have the
      form #6.55799(#MYTAG(_)), as per https://www.rfc-editor.org/rfc/rfc9277.html#section-2.2.1
      See https://www.rfc-editor.org/rfc/rfc9277.html#name-the-cbor-protocol-specific- for
      registration instructions.
* [ ] Make it possible to read a record with missing fragments.
* [ ] Fragment compression
* [ ] Segment Content-Type header parameter
