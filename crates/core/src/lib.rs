#![forbid(unsafe_code)]

//! Cryptographic formats and link share roles for the Tightlip v1 suite.

pub mod aead;
pub mod b64;
pub mod kdf;
pub mod labels;
pub mod manifest;
pub mod oprf;
pub mod pad;
pub mod share;
pub mod stream;

mod secret;

pub use secret::{Plaintext, RandomError, Secret32};

#[cfg(test)]
mod tests;
