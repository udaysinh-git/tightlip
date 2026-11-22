use thiserror::Error;

use crate::Plaintext;

pub const MANIFEST_FLOOR: usize = 512;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid padding target")]
pub struct PadError;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid padding")]
pub struct UnpadError;

/// Rounds a length up according to Padmé, or fails if the result exceeds `usize`.
pub fn padme(length: usize) -> Result<usize, PadError> {
    let Some(exponent) = length.checked_ilog2().filter(|&e| e != 0) else {
        return Ok(length);
    };
    let significant = exponent.ilog2() + 1;
    let mask = (1 << (exponent - significant)) - 1;
    Ok(length.checked_add(mask).ok_or(PadError)? & !mask)
}

pub fn pad(bytes: &[u8], target: usize) -> Result<Plaintext, PadError> {
    if target <= bytes.len() {
        return Err(PadError);
    }
    let mut padded = Vec::new();
    padded.try_reserve_exact(target).map_err(|_| PadError)?;
    padded.extend_from_slice(bytes);
    padded.push(0x80);
    padded.resize(target, 0);
    Ok(Plaintext(padded))
}

pub fn unpad(padded: &[u8]) -> Result<&[u8], UnpadError> {
    match padded.iter().rposition(|&byte| byte != 0) {
        Some(marker) if padded[marker] == 0x80 => Ok(&padded[..marker]),
        _ => Err(UnpadError),
    }
}

pub(crate) fn target(length: usize, floor: usize) -> Result<usize, PadError> {
    Ok(padme(length.checked_add(1).ok_or(PadError)?)?.max(floor))
}
