//! RFC 9497 base-mode OPRF over ristretto255 and SHA-512.

use std::num::NonZeroU32;

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use thiserror::Error;
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer, Ristretto255};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{RandomError, Secret32, secret::fill_random};

type Client = OprfClient<Ristretto255>;
type Server = OprfServer<Ristretto255>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OprfError {
    #[error(transparent)]
    Random(#[from] RandomError),
    #[error("invalid OPRF input")]
    InvalidInput,
}

/// An OPRF blind and its input, consumed by `finalize`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientState {
    input: Vec<u8>,
    blind: Secret32,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Output([u8; 64]);

impl Output {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Blinds the 32-byte input produced by the Tightlip share key schedule.
pub fn blind(input: &Secret32) -> Result<([u8; 32], ClientState), OprfError> {
    blind_with_rng(input, fill_random)
}

fn blind_with_rng(
    input: &Secret32,
    fill: fn(&mut [u8]) -> Result<(), RandomError>,
) -> Result<([u8; 32], ClientState), OprfError> {
    let mut rng = SystemRng {
        fill,
        failed: false,
    };
    let exchange = Client::blind(input.as_bytes(), &mut rng);
    if rng.failed {
        return Err(RandomError.into());
    }
    let exchange = exchange.map_err(|_| OprfError::InvalidInput)?;
    let blind = Zeroizing::new(exchange.state.serialize());
    Ok((
        exchange.message.serialize().into(),
        ClientState {
            input: input.as_bytes().to_vec(),
            blind: Secret32::from_bytes(*blind.as_ref()),
        },
    ))
}

struct SystemRng {
    fill: fn(&mut [u8]) -> Result<(), RandomError>,
    failed: bool,
}

impl CryptoRng for SystemRng {}

impl RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.try_fill_bytes(dest).is_err() {
            // The infallible API needs a nonzero scalar to finish its sampling loop.
            // The caller discards the entire result if system randomness failed.
            dest.fill(0);
            if let Some(first) = dest.first_mut() {
                *first = 1;
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        (self.fill)(dest).map_err(|_| {
            self.failed = true;
            rand_core::Error::from(NonZeroU32::MAX)
        })
    }
}

#[cfg(test)]
pub(crate) fn blind_with_scalar(
    input: &[u8],
    blind: Secret32,
) -> Result<([u8; 32], ClientState), OprfError> {
    use voprf::Group;

    let scalar =
        Ristretto255::deserialize_scalar(blind.as_bytes()).map_err(|_| OprfError::InvalidInput)?;
    let exchange = Client::deterministic_blind_unchecked(input, scalar)
        .map_err(|_| OprfError::InvalidInput)?;
    Ok((
        exchange.message.serialize().into(),
        ClientState {
            input: input.to_vec(),
            blind,
        },
    ))
}

impl ClientState {
    pub fn finalize(self, evaluated: &[u8]) -> Result<Output, OprfError> {
        self.finalize_ref(evaluated)
    }

    pub(crate) fn finalize_ref(&self, evaluated: &[u8]) -> Result<Output, OprfError> {
        if evaluated.len() != 32 {
            return Err(OprfError::InvalidInput);
        }
        let element = EvaluationElement::<Ristretto255>::deserialize(evaluated)
            .map_err(|_| OprfError::InvalidInput)?;
        let client =
            Client::deserialize(self.blind.as_bytes()).map_err(|_| OprfError::InvalidInput)?;
        let output = Zeroizing::new(
            client
                .finalize(&self.input, &element)
                .map_err(|_| OprfError::InvalidInput)?,
        );
        let mut bytes = Output([0; 64]);
        bytes.0.copy_from_slice(&output);
        Ok(bytes)
    }
}

/// A server's canonical RFC 9497 private scalar, stored only in wrapped form.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ServerKey(Secret32);

impl ServerKey {
    pub fn generate() -> Result<Self, RandomError> {
        random_scalar().map(Self)
    }

    pub fn blind_evaluate(&self, blinded: &[u8]) -> Result<[u8; 32], OprfError> {
        if blinded.len() != 32 {
            return Err(OprfError::InvalidInput);
        }
        // This decoder rejects the identity and noncanonical encodings.
        let element = BlindedElement::<Ristretto255>::deserialize(blinded)
            .map_err(|_| OprfError::InvalidInput)?;
        let server =
            Server::new_with_key(self.0.as_bytes()).map_err(|_| OprfError::InvalidInput)?;
        Ok(server.blind_evaluate(&element).serialize().into())
    }

    pub(crate) fn from_secret(secret: Secret32) -> Result<Self, OprfError> {
        Server::new_with_key(secret.as_bytes()).map_err(|_| OprfError::InvalidInput)?;
        Ok(Self(secret))
    }

    pub(crate) fn secret(&self) -> &Secret32 {
        &self.0
    }
}

fn random_scalar() -> Result<Secret32, RandomError> {
    loop {
        // Wide reduction as used by dalek's scalar sampler and RFC 9497 section 4.7.
        let mut uniform = Zeroizing::new([0; 64]);
        fill_random(&mut *uniform)?;
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&uniform));
        let secret = Secret32::from_bytes(scalar.to_bytes());
        if !bool::from(secret.as_bytes().ct_eq(&[0; 32])) {
            return Ok(secret);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blinding_returns_an_error_when_system_randomness_fails() {
        assert!(matches!(
            blind_with_rng(&Secret32::from_bytes([0; 32]), |_| Err(RandomError)),
            Err(OprfError::Random(RandomError))
        ));
    }
}
