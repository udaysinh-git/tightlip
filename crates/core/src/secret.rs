use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error, PartialEq, Eq)]
#[error("system randomness unavailable")]
pub struct RandomError;

/// A key, token, or other 32-byte secret. The owned bytes are erased on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret32([u8; 32]);

/// An owned plaintext buffer. The contents are erased on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Plaintext(pub(crate) Vec<u8>);

impl Plaintext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Secret32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Result<Self, RandomError> {
        let mut secret = Self([0; 32]);
        fill_random(&mut secret.0)?;
        Ok(secret)
    }

    /// Borrows the secret for use at a protocol boundary.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn fill_random(bytes: &mut [u8]) -> Result<(), RandomError> {
    getrandom::fill(bytes).map_err(|_| RandomError)
}
