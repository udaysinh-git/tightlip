//! Padded, authenticated JSON manifests and the files they describe.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Plaintext, Secret32,
    aead::{self, OpenError, SealError},
    labels,
    pad::{self, PadError},
    share::{ShareId, share_aad},
    stream,
};

pub const VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Manifest {
    pub v: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Login>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileEntry>>,
}

#[derive(Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Login {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FileEntry {
    pub name: String,
    pub mime: String,
    pub size: u64,
    #[serde(with = "file_key")]
    pub key: Secret32,
}

#[derive(Debug, Error)]
pub enum PayloadSealError {
    #[error("invalid manifest or file size")]
    InvalidPayload,
    #[error("manifest serialization failed")]
    Json,
    #[error(transparent)]
    Pad(#[from] PadError),
    #[error(transparent)]
    Seal(#[from] SealError),
}

impl Manifest {
    fn is_valid(&self) -> bool {
        self.v == VERSION && (self.note.is_some() || self.login.is_some() || self.files.is_some())
    }
}

pub fn seal_manifest(
    manifest_key: &Secret32,
    share_id: &ShareId,
    manifest: &Manifest,
) -> Result<Vec<u8>, PayloadSealError> {
    if !manifest.is_valid() {
        return Err(PayloadSealError::InvalidPayload);
    }
    let mut json = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *json, manifest).map_err(|_| PayloadSealError::Json)?;
    let padded = pad::pad(&json, pad::target(json.len(), pad::MANIFEST_FLOOR)?)?;
    Ok(aead::seal(
        manifest_key,
        &share_aad(labels::MANIFEST, share_id),
        padded.as_bytes(),
    )?)
}

pub fn open_manifest(
    manifest_key: &Secret32,
    share_id: &ShareId,
    ciphertext: &[u8],
    blob_count: usize,
) -> Result<Manifest, OpenError> {
    let padded = aead::open(
        manifest_key,
        &share_aad(labels::MANIFEST, share_id),
        ciphertext,
    )?;
    let json = pad::unpad(padded.as_bytes()).map_err(|_| OpenError)?;
    let manifest: Manifest = serde_json::from_slice(json).map_err(|_| OpenError)?;
    if !manifest.is_valid() || manifest.files.as_ref().map_or(0, Vec::len) != blob_count {
        return Err(OpenError);
    }
    Ok(manifest)
}

pub fn seal_file(
    share_id: &ShareId,
    index: u32,
    entry: &FileEntry,
    plaintext: &[u8],
) -> Result<Vec<u8>, PayloadSealError> {
    if u64::try_from(plaintext.len()).ok() != Some(entry.size) {
        return Err(PayloadSealError::InvalidPayload);
    }
    let padded = pad::pad(plaintext, pad::target(plaintext.len(), 0)?)?;
    Ok(stream::stream_seal(
        &entry.key,
        &file_aad(share_id, index),
        padded.as_bytes(),
    )?)
}

pub fn open_file(
    share_id: &ShareId,
    index: u32,
    entry: &FileEntry,
    ciphertext: &[u8],
) -> Result<Plaintext, OpenError> {
    let mut padded = stream::stream_open(&entry.key, &file_aad(share_id, index), ciphertext)?;
    let unpadded_len = pad::unpad(padded.as_bytes()).map_err(|_| OpenError)?.len();
    let size = usize::try_from(entry.size).map_err(|_| OpenError)?;
    if unpadded_len < size {
        return Err(OpenError);
    }
    padded.0[size..].zeroize();
    padded.0.truncate(size);
    Ok(padded)
}

pub(crate) fn file_aad(share_id: &ShareId, index: u32) -> Vec<u8> {
    let mut aad = share_aad(labels::FILE, share_id);
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

mod file_key {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use zeroize::Zeroizing;

    use crate::{Secret32, b64};

    pub(super) fn serialize<S: Serializer>(
        key: &Secret32,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(b64::encode(key.as_bytes()));
        serializer.serialize_str(&encoded)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Secret32, D::Error> {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        let mut bytes = Zeroizing::new([0; 33]);
        let len = b64::decode_slice(&encoded, &mut *bytes).map_err(D::Error::custom)?;
        if len != 32 {
            return Err(D::Error::custom("file key must be 32 bytes"));
        }
        let key = bytes[..32].try_into().map_err(D::Error::custom)?;
        Ok(Secret32::from_bytes(key))
    }
}
