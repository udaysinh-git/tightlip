use hkdf::Hkdf;
use sha2::Sha512;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("HKDF output exceeds its length limit")]
pub struct DeriveError;

/// HKDF-SHA-512 extract and expand. Pass an empty slice for an empty salt.
pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), DeriveError> {
    expand(salt, ikm, &[info], output)
}

pub(crate) fn expand(
    salt: &[u8],
    ikm: &[u8],
    info: &[&[u8]],
    output: &mut [u8],
) -> Result<(), DeriveError> {
    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand_multi_info(info, output)
        .map_err(|_| DeriveError)
}

pub(crate) fn committing_keys(
    salt: &[u8],
    key: &[u8; 32],
    label: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<[u8; 64]>, DeriveError> {
    let len = u32::try_from(aad.len()).map_err(|_| DeriveError)?;
    let mut keys = Zeroizing::new([0; 64]);
    expand(salt, key, &[label, &len.to_be_bytes(), aad], &mut *keys)?;
    Ok(keys)
}
