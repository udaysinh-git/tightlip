use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid unpadded base64url")]
pub struct DecodeError;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| DecodeError)
}

pub(crate) fn decode_slice(text: &str, output: &mut [u8]) -> Result<usize, DecodeError> {
    URL_SAFE_NO_PAD
        .decode_slice(text, output)
        .map_err(|_| DecodeError)
}
