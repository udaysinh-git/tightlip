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
    stream::{CHUNK_LEN, Decryptor, Encryptor, HEADER_LEN},
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orientation: Option<u8>,
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
        self.v == VERSION
            && (self.note.as_ref().is_some_and(|note| !note.is_empty())
                || self.login.as_ref().is_some_and(Login::has_fields)
                || self.files.as_ref().is_some_and(|files| !files.is_empty()))
            && self.files.iter().flatten().all(|file| {
                file.orientation
                    .is_none_or(|value| (1..=8).contains(&value))
            })
    }
}

impl Login {
    fn has_fields(&self) -> bool {
        [
            &self.title,
            &self.username,
            &self.password,
            &self.url,
            &self.totp,
            &self.note,
        ]
        .iter()
        .any(|field| field.is_some())
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
    let mut seal = FileSeal::init(share_id, index, entry)?;
    let mut out = seal.header().to_vec();
    out.extend(seal.update(plaintext)?);
    out.extend(seal.finish()?);
    Ok(out)
}

pub fn open_file(
    share_id: &ShareId,
    index: u32,
    entry: &FileEntry,
    ciphertext: &[u8],
) -> Result<Plaintext, OpenError> {
    let (header, body) = ciphertext
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(OpenError)?;
    let mut open = FileOpen::init(share_id, index, entry, header)?;
    let mut out = Plaintext(Vec::new());
    for chunk in body.chunks(CHUNK_LEN) {
        open.update(chunk, |bytes| out.0.extend_from_slice(bytes))?;
    }
    open.finish(|bytes| out.0.extend_from_slice(bytes))?;
    Ok(out)
}

/// Incrementally seals a file with STREAM and appends its Padmé padding at finish.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileSeal {
    encryptor: Option<Encryptor>,
    header: [u8; HEADER_LEN],
    remaining: usize,
    padding: usize,
}

impl FileSeal {
    pub fn init(
        share_id: &ShareId,
        index: u32,
        entry: &FileEntry,
    ) -> Result<Self, PayloadSealError> {
        let size = usize::try_from(entry.size).map_err(|_| PayloadSealError::InvalidPayload)?;
        let padding = pad::target(size, 0)? - size;
        let (header, encryptor) = Encryptor::init(&entry.key, &file_aad(share_id, index))?;
        Ok(Self {
            encryptor: Some(encryptor),
            header,
            remaining: size,
            padding,
        })
    }

    pub fn header(&self) -> &[u8; HEADER_LEN] {
        &self.header
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<Vec<u8>, PayloadSealError> {
        let remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or(PayloadSealError::InvalidPayload)?;
        let encryptor = self
            .encryptor
            .as_mut()
            .ok_or(PayloadSealError::InvalidPayload)?;
        let out = encryptor.update(bytes)?;
        self.remaining = remaining;
        Ok(out)
    }

    pub fn finish(&mut self) -> Result<Vec<u8>, PayloadSealError> {
        let mut encryptor = self
            .encryptor
            .take()
            .ok_or(PayloadSealError::InvalidPayload)?;
        if self.remaining != 0 {
            return Err(PayloadSealError::InvalidPayload);
        }
        let mut out = encryptor.update(&[0x80])?;
        let zeros = [0; CHUNK_LEN];
        let mut remaining = self.padding - 1;
        while remaining > 0 {
            let count = remaining.min(zeros.len());
            out.extend(encryptor.update(&zeros[..count])?);
            remaining -= count;
        }
        out.extend(encryptor.finish()?);
        Ok(out)
    }
}

/// Releases authenticated file bytes up to the manifest's size.
/// The file is complete only after `finish` validates the final chunk and padding.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FileOpen {
    decryptor: Option<Decryptor>,
    size: usize,
    received: usize,
    last_nonzero: Option<(usize, u8)>,
}

impl FileOpen {
    pub fn init(
        share_id: &ShareId,
        index: u32,
        entry: &FileEntry,
        header: &[u8],
    ) -> Result<Self, OpenError> {
        let size = usize::try_from(entry.size).map_err(|_| OpenError)?;
        let decryptor = Decryptor::init(&entry.key, &file_aad(share_id, index), header)?;
        Ok(Self {
            decryptor: Some(decryptor),
            size,
            received: 0,
            last_nonzero: None,
        })
    }

    pub fn update<T>(
        &mut self,
        bytes: &[u8],
        copy: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, OpenError> {
        let plaintext = self.decryptor.as_mut().ok_or(OpenError)?.update(bytes)?;
        Ok(copy(self.visible(plaintext.as_bytes())?))
    }

    pub fn finish<T>(&mut self, copy: impl FnOnce(&[u8]) -> T) -> Result<T, OpenError> {
        let plaintext = self.decryptor.take().ok_or(OpenError)?.finish()?;
        let visible = self.visible(plaintext.as_bytes())?;
        if !self
            .last_nonzero
            .is_some_and(|(index, byte)| index >= self.size && byte == 0x80)
        {
            return Err(OpenError);
        }
        Ok(copy(visible))
    }

    fn visible<'a>(&mut self, bytes: &'a [u8]) -> Result<&'a [u8], OpenError> {
        let start = self.received;
        self.received = start.checked_add(bytes.len()).ok_or(OpenError)?;
        if let Some(index) = bytes.iter().rposition(|&byte| byte != 0) {
            self.last_nonzero = Some((start + index, bytes[index]));
        }
        Ok(&bytes[..self.size.saturating_sub(start).min(bytes.len())])
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream;

    fn entry(size: usize) -> FileEntry {
        FileEntry {
            name: "image.jpg".into(),
            mime: "image/jpeg".into(),
            size: size as u64,
            key: Secret32::generate().unwrap(),
            orientation: None,
        }
    }

    #[test]
    fn optional_orientation_round_trips_and_is_checked_on_both_sides() {
        let key = Secret32::generate().unwrap();
        let id = [1; 16];
        let mut draft = Manifest {
            v: VERSION,
            note: None,
            login: None,
            files: Some(vec![entry(1)]),
        };
        let json = Zeroizing::new(serde_json::to_string(&draft).unwrap());
        assert!(!json.contains("orientation"));
        for orientation in [1, 8, 0, 9] {
            draft.files.as_mut().unwrap()[0].orientation = Some(orientation);
            let serialized = Zeroizing::new(serde_json::to_vec(&draft).unwrap());
            let padded = pad::pad(&serialized, pad::MANIFEST_FLOOR).unwrap();
            let ciphertext =
                aead::seal(&key, &share_aad(labels::MANIFEST, &id), padded.as_bytes()).unwrap();
            if (1..=8).contains(&orientation) {
                assert!(seal_manifest(&key, &id, &draft).is_ok());
                let opened = open_manifest(&key, &id, &ciphertext, 1).unwrap();
                assert_eq!(
                    opened.files.as_ref().unwrap()[0].orientation,
                    Some(orientation)
                );
            } else {
                assert!(seal_manifest(&key, &id, &draft).is_err());
                assert!(open_manifest(&key, &id, &ciphertext, 1).is_err());
            }
        }
    }

    #[test]
    fn incremental_file_format_matches_stream_and_requires_completion() {
        let id = [1; 16];
        for size in [0, CHUNK_LEN - 1, CHUNK_LEN, CHUNK_LEN * 2 + 10] {
            let entry = entry(size);
            let plaintext = vec![7; size];
            let mut seal = FileSeal::init(&id, 0, &entry).unwrap();
            let mut ciphertext = seal.header().to_vec();
            for chunk in plaintext.chunks(31_000) {
                ciphertext.extend(seal.update(chunk).unwrap());
            }
            ciphertext.extend(seal.finish().unwrap());
            let padded = stream::stream_open(&entry.key, &file_aad(&id, 0), &ciphertext).unwrap();
            assert_eq!(padded.as_bytes().len(), pad::target(size, 0).unwrap());
            assert_eq!(pad::unpad(padded.as_bytes()).unwrap(), plaintext);

            let (header, body) = ciphertext.split_at(HEADER_LEN);
            let mut open = FileOpen::init(&id, 0, &entry, header).unwrap();
            let mut output = Vec::new();
            for chunk in body.chunks(30_000) {
                open.update(chunk, |bytes| output.extend_from_slice(bytes))
                    .unwrap();
            }
            open.finish(|bytes| output.extend_from_slice(bytes))
                .unwrap();
            assert_eq!(output, plaintext);

            let mut open = FileOpen::init(&id, 0, &entry, header).unwrap();
            open.update(&body[..body.len() - 1], |_| ()).unwrap();
            assert!(open.finish(|_| ()).is_err());
        }
        let entry = entry(2);
        let mut short = FileSeal::init(&id, 0, &entry).unwrap();
        assert!(short.update(&[1, 2, 3]).is_err());
        short.update(&[1]).unwrap();
        assert!(short.finish().is_err());
    }
}
