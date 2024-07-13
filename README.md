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
