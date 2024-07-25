# Recursive Record Registry (RRR)
Implementation of the Recursive Record Registry data format in Rust.

This repository contains a basic command-line tool for reading Recursive Record Registries, as well as a Rust library for reading and creating record registries.

## About the RRR data format
A specification for the secure storage of digital information in a tree structure, where each subtree is password-protected.
Without knowing the passwords (and thus being able to browse the registry), the structure and the contents of the tree is unknown to the user.
The intention is for the registry to be distributed with 3rd parties.
The specification guarantees integrity, authentication, and non-repudiation of the stored records, from the author of the registry.
The aim of this project is to provide an interesting platform for storytelling and the creation of puzzles.

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
    * [x] AES-256-GCM
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
* [ ] Feature for proptest stuff
* [ ] Consider making the encryption algorithm a config parameter
* [ ] Register IANA CBOR tags for `registry.cbor`, record, segment and fragment. Files should have the
      form #6.55799(#MYTAG(_)), as per https://www.rfc-editor.org/rfc/rfc9277.html#section-2.2.1
      See https://www.rfc-editor.org/rfc/rfc9277.html#name-the-cbor-protocol-specific- for
      registration instructions.
* [ ] Make it possible to read a record with missing fragments.
* [ ] Fragment compression
* [ ] Segment Content-Type header parameter
