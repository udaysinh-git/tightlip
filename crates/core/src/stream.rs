//! Incremental STREAM encryption for a key used with exactly one file.

use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Plaintext, Secret32,
    aead::{self, COMMITMENT_LEN, NONCE_LEN, OpenError, SealError, TAG_LEN},
    kdf, labels,
    secret::fill_random,
};

pub const CHUNK_LEN: usize = 65536;
pub const CHUNK_CIPHERTEXT_LEN: usize = CHUNK_LEN + TAG_LEN;
pub const PREFIX_LEN: usize = 19;
pub const HEADER_LEN: usize = PREFIX_LEN + COMMITMENT_LEN;

#[derive(Zeroize, ZeroizeOnDrop)]
struct State {
    prefix: [u8; PREFIX_LEN],
    key: Secret32,
    aad: Vec<u8>,
    next: u32,
    pending: Vec<u8>,
}

impl State {
    fn new(prefix: [u8; PREFIX_LEN], key: &[u8; 32], aad: &[u8], block_len: usize) -> Self {
        Self {
            prefix,
            key: Secret32::from_bytes(*key),
            aad: aad.to_vec(),
            next: 0,
            pending: Vec::with_capacity(block_len),
        }
    }
}

/// Holds at most one pending plaintext chunk between calls.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Encryptor(Option<State>);

impl Encryptor {
    /// Returns the header to write first, followed by the encryptor.
    pub fn init(key: &Secret32, aad: &[u8]) -> Result<([u8; HEADER_LEN], Self), SealError> {
        let mut prefix = [0; PREFIX_LEN];
        fill_random(&mut prefix)?;
        Self::with_prefix(key, aad, prefix)
    }

    fn with_prefix(
        key: &Secret32,
        aad: &[u8],
        prefix: [u8; PREFIX_LEN],
    ) -> Result<([u8; HEADER_LEN], Self), SealError> {
        let keys = kdf::committing_keys(&prefix, key.as_bytes(), labels::STREAM, aad)
            .map_err(|_| SealError::InvalidInput)?;
        let (cipher_key, commitment) = keys
            .split_first_chunk::<32>()
            .ok_or(SealError::InvalidInput)?;
        let mut header = [0; HEADER_LEN];
        header[..PREFIX_LEN].copy_from_slice(&prefix);
        header[PREFIX_LEN..].copy_from_slice(commitment);
        let state = State::new(prefix, cipher_key, aad, CHUNK_LEN);
        Ok((header, Self(Some(state))))
    }

    /// Emits complete non-final chunks. Call `finish` after the last input.
    pub fn update(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let state = self.0.as_mut().ok_or(SealError::InvalidInput)?;
        let cipher = XChaCha20Poly1305::new(state.key.as_bytes().into());
        let mut out = Vec::new();
        let result = process_nonfinal(&mut state.pending, plaintext, CHUNK_LEN, |chunk| {
            let nonce = nonce(&state.prefix, state.next, false).ok_or(SealError::InvalidInput)?;
            aead::encrypt(&cipher, &nonce, &state.aad, chunk, &mut out)?;
            state.next += 1;
            Ok(())
        });
        if result.is_err() {
            self.zeroize();
        }
        result.map(|()| out)
    }

    /// Emits the required final chunk, including for empty plaintext.
    pub fn finish(self) -> Result<Vec<u8>, SealError> {
        let state = self.0.as_ref().ok_or(SealError::InvalidInput)?;
        let cipher = XChaCha20Poly1305::new(state.key.as_bytes().into());
        let nonce = nonce(&state.prefix, state.next, true).ok_or(SealError::InvalidInput)?;
        let mut out = Vec::with_capacity(state.pending.len() + TAG_LEN);
        aead::encrypt(&cipher, &nonce, &state.aad, &state.pending, &mut out)?;
        Ok(out)
    }
}

/// Holds at most one pending ciphertext chunk between calls.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Decryptor(Option<State>);

impl Decryptor {
    /// Checks the commitment in the 51-byte header before accepting chunks.
    pub fn init(key: &Secret32, aad: &[u8], header: &[u8]) -> Result<Self, OpenError> {
        if header.len() != HEADER_LEN {
            return Err(OpenError);
        }
        let (prefix, received_commitment) =
            header.split_first_chunk::<PREFIX_LEN>().ok_or(OpenError)?;
        let keys = kdf::committing_keys(prefix, key.as_bytes(), labels::STREAM, aad)
            .map_err(|_| OpenError)?;
        let (cipher_key, commitment) = keys.split_first_chunk::<32>().ok_or(OpenError)?;
        if !bool::from(commitment.ct_eq(received_commitment)) {
            return Err(OpenError);
        }
        Ok(Self(Some(State::new(
            *prefix,
            cipher_key,
            aad,
            CHUNK_CIPHERTEXT_LEN,
        ))))
    }

    /// Releases authenticated non-final chunks. Completion requires a successful `finish`.
    pub fn update(&mut self, ciphertext: &[u8]) -> Result<Plaintext, OpenError> {
        let state = self.0.as_ref().ok_or(OpenError)?;
        let len = state
            .pending
            .len()
            .checked_add(ciphertext.len())
            .ok_or(OpenError)?;
        let blocks = len.saturating_sub(1) / CHUNK_CIPHERTEXT_LEN;
        let mut out = Plaintext(Vec::with_capacity(blocks * CHUNK_LEN));
        self.update_into(ciphertext, &mut out.0)?;
        Ok(out)
    }

    fn update_into(&mut self, ciphertext: &[u8], out: &mut Vec<u8>) -> Result<(), OpenError> {
        let state = self.0.as_mut().ok_or(OpenError)?;
        let cipher = XChaCha20Poly1305::new(state.key.as_bytes().into());
        let result = process_nonfinal(
            &mut state.pending,
            ciphertext,
            CHUNK_CIPHERTEXT_LEN,
            |chunk| {
                let nonce = nonce(&state.prefix, state.next, false).ok_or(OpenError)?;
                aead::decrypt(&cipher, &nonce, &state.aad, chunk, out)?;
                state.next += 1;
                Ok(())
            },
        );
        if result.is_err() {
            self.zeroize();
        }
        result
    }

    /// Authenticates and releases the final chunk. A missing final chunk fails.
    pub fn finish(self) -> Result<Plaintext, OpenError> {
        let mut out = Plaintext(Vec::new());
        self.finish_into(&mut out.0)?;
        Ok(out)
    }

    fn finish_into(self, out: &mut Vec<u8>) -> Result<(), OpenError> {
        let state = self.0.as_ref().ok_or(OpenError)?;
        if state.next != 0 && state.pending.len() <= TAG_LEN {
            return Err(OpenError);
        }
        let cipher = XChaCha20Poly1305::new(state.key.as_bytes().into());
        let nonce = nonce(&state.prefix, state.next, true).ok_or(OpenError)?;
        aead::decrypt(&cipher, &nonce, &state.aad, &state.pending, out)
    }
}

pub fn stream_seal(key: &Secret32, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let (header, encryptor) = Encryptor::init(key, aad)?;
    seal_stream(header, encryptor, plaintext)
}

#[cfg(test)]
pub(crate) fn seal_with_prefix(
    key: &Secret32,
    aad: &[u8],
    plaintext: &[u8],
    prefix: [u8; PREFIX_LEN],
) -> Result<Vec<u8>, SealError> {
    let (header, encryptor) = Encryptor::with_prefix(key, aad, prefix)?;
    seal_stream(header, encryptor, plaintext)
}

fn seal_stream(
    header: [u8; HEADER_LEN],
    mut encryptor: Encryptor,
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let mut out = header.to_vec();
    out.extend(encryptor.update(plaintext)?);
    out.extend(encryptor.finish()?);
    Ok(out)
}

pub fn stream_open(key: &Secret32, aad: &[u8], ciphertext: &[u8]) -> Result<Plaintext, OpenError> {
    let (header, body) = ciphertext
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(OpenError)?;
    let mut decryptor = Decryptor::init(key, aad, header)?;
    let chunks = body.len().div_ceil(CHUNK_CIPHERTEXT_LEN);
    let mut out = Plaintext(Vec::with_capacity(
        body.len().saturating_sub(chunks * TAG_LEN),
    ));
    decryptor.update_into(body, &mut out.0)?;
    decryptor.finish_into(&mut out.0)?;
    Ok(out)
}

fn nonce(prefix: &[u8; PREFIX_LEN], index: u32, final_chunk: bool) -> Option<[u8; NONCE_LEN]> {
    if index == u32::MAX || (!final_chunk && index == u32::MAX - 1) {
        return None;
    }
    let mut nonce = [0; NONCE_LEN];
    nonce[..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN..PREFIX_LEN + 4].copy_from_slice(&index.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(final_chunk);
    Some(nonce)
}

// A full block is non-final only when at least one more byte has arrived.
fn process_nonfinal<E>(
    pending: &mut Vec<u8>,
    mut input: &[u8],
    block_len: usize,
    mut process: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E> {
    while !input.is_empty() {
        if pending.is_empty() && input.len() > block_len {
            let (block, rest) = input.split_at(block_len);
            process(block)?;
            input = rest;
            continue;
        }
        let (fill, rest) = input.split_at(input.len().min(block_len - pending.len()));
        pending.extend_from_slice(fill);
        if !rest.is_empty() {
            process(pending)?;
            pending.zeroize();
        }
        input = rest;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_counter_is_reserved_for_the_final_chunk() {
        let prefix = [0; PREFIX_LEN];
        let last = u32::MAX - 1;
        let final_nonce = nonce(&prefix, last, true).unwrap();
        assert_eq!(&final_nonce[PREFIX_LEN..], &[255, 255, 255, 254, 1]);
        assert!(nonce(&prefix, last, false).is_none());
        assert!(nonce(&prefix, u32::MAX, true).is_none());
    }
}
