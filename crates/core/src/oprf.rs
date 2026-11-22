//! RFC 9497 base-mode OPRF over ristretto255 and SHA-512.

use curve25519_dalek::scalar::Scalar;
use subtle::ConstantTimeEq;
use thiserror::Error;
use voprf::{BlindedElement, EvaluationElement, Group, OprfClient, OprfServer, Ristretto255};
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
    blind_inner(input.as_bytes(), random_scalar()?)
}

#[cfg(test)]
pub(crate) fn blind_with_scalar(
    input: &[u8],
    blind: Secret32,
) -> Result<([u8; 32], ClientState), OprfError> {
    blind_inner(input, blind)
}

fn blind_inner(input: &[u8], blind: Secret32) -> Result<([u8; 32], ClientState), OprfError> {
    // Supply the sampled scalar through the library's checked canonical decoder.
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
