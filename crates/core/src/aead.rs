use crate::{Plaintext, RandomError, Secret32, kdf, labels, secret::fill_random};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{AeadInOut, inout::InOutBuf},
};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const NONCE_LEN: usize = 24;
pub const COMMITMENT_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const MAX_AAD_LEN: usize = 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SealError {
    #[error(transparent)]
    Random(#[from] RandomError),
    #[error("encryption failed")]
    InvalidInput,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("decryption failed")]
pub struct OpenError;

pub fn seal(key: &Secret32, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut nonce = [0; NONCE_LEN];
    fill_random(&mut nonce)?;
    seal_inner(key, aad, plaintext, &nonce)
}

#[cfg(test)]
pub(crate) fn seal_with_nonce(
    key: &Secret32,
    aad: &[u8],
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, SealError> {
    seal_inner(key, aad, plaintext, nonce)
}

fn seal_inner(
    key: &Secret32,
    aad: &[u8],
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, SealError> {
    if aad.len() > MAX_AAD_LEN {
        return Err(SealError::InvalidInput);
    }
    let keys = kdf::committing_keys(nonce, key.as_bytes(), labels::AEAD, aad)
        .map_err(|_| SealError::InvalidInput)?;
    let (cipher_key, commitment) = keys.split_at(32);
    let cipher =
        XChaCha20Poly1305::new_from_slice(cipher_key).map_err(|_| SealError::InvalidInput)?;
    let mut out = Vec::with_capacity(NONCE_LEN + COMMITMENT_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(nonce);
    out.extend_from_slice(commitment);
    encrypt(&cipher, nonce, aad, plaintext, &mut out)?;
    Ok(out)
}

pub fn open(key: &Secret32, aad: &[u8], ciphertext: &[u8]) -> Result<Plaintext, OpenError> {
    if aad.len() > MAX_AAD_LEN || ciphertext.len() < NONCE_LEN + COMMITMENT_LEN + TAG_LEN {
        return Err(OpenError);
    }
    let (nonce, body) = ciphertext
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(OpenError)?;
    let (received_commitment, body) = body.split_at(COMMITMENT_LEN);
    let keys =
        kdf::committing_keys(nonce, key.as_bytes(), labels::AEAD, aad).map_err(|_| OpenError)?;
    let (cipher_key, commitment) = keys.split_at(32);
    if !bool::from(commitment.ct_eq(received_commitment)) {
        return Err(OpenError);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(cipher_key).map_err(|_| OpenError)?;
    let mut plaintext = Plaintext(Vec::new());
    decrypt(&cipher, nonce, aad, body, &mut plaintext.0)?;
    Ok(plaintext)
}

pub(crate) fn encrypt(
    cipher: &XChaCha20Poly1305,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), SealError> {
    let start = out.len();
    out.resize(start + plaintext.len(), 0);
    let buffer =
        InOutBuf::new(plaintext, &mut out[start..]).map_err(|_| SealError::InvalidInput)?;
    let tag = cipher
        .encrypt_inout_detached(nonce.into(), aad, buffer)
        .map_err(|_| SealError::InvalidInput)?;
    out.extend_from_slice(&tag);
    Ok(())
}

pub(crate) fn decrypt(
    cipher: &XChaCha20Poly1305,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), OpenError> {
    let (body, tag) = ciphertext.split_last_chunk::<TAG_LEN>().ok_or(OpenError)?;
    let start = out.len();
    out.resize(start + body.len(), 0);
    let buffer = InOutBuf::new(body, &mut out[start..]).map_err(|_| OpenError)?;
    #[cfg(test)]
    DECRYPT_CALLS.set(DECRYPT_CALLS.get() + 1);
    cipher
        .decrypt_inout_detached(nonce.into(), aad, buffer, tag.into())
        .map_err(|_| OpenError)
}

#[cfg(test)]
thread_local! {
    pub(crate) static DECRYPT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
