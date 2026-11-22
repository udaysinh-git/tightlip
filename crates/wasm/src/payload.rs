use serde::{Deserialize, Serialize};
use tightlip_core::{
    Secret32, aead, labels,
    manifest::{FileEntry, Login, VERSION},
    pad,
    share::ShareId,
    stream::{Decryptor, Encryptor, HEADER_LEN},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Manifest {
    v: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<Login>,
    #[serde(skip_serializing_if = "Option::is_none")]
    files: Option<Vec<ImageFileEntry>>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct ImageFileEntry {
    #[serde(flatten)]
    file: FileEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    orientation: Option<u8>,
}

// This projection is the only manifest data returned across the wasm boundary.
#[derive(Serialize)]
struct VisibleFile<'a> {
    name: &'a str,
    mime: &'a str,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    orientation: Option<u8>,
}

#[derive(Serialize)]
struct VisibleContent<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<&'a Login>,
    files: Vec<VisibleFile<'a>>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Content {
    note: Option<String>,
    login: Option<Login>,
}

fn associated_data(label: &[u8], id: &ShareId, index: Option<u32>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(label.len() + id.len() + index.map_or(0, |_| 4));
    aad.extend_from_slice(label);
    aad.extend_from_slice(id);
    if let Some(index) = index {
        aad.extend_from_slice(&index.to_be_bytes());
    }
    aad
}

fn padded_length(size: usize) -> Result<usize, Error> {
    pad::padme(size.checked_add(1).ok_or(Error::Prepare)?).map_err(|_| Error::Prepare)
}

impl Manifest {
    pub(crate) fn from_content(content: Zeroizing<String>) -> Result<Self, Error> {
        let mut content: Content = serde_json::from_str(&content).map_err(|_| Error::Prepare)?;
        Ok(Self {
            v: VERSION,
            note: content.note.take(),
            login: content.login.take(),
            files: None,
        })
    }

    fn valid(&self) -> bool {
        self.v == VERSION
            && (self.note.is_some() || self.login.is_some() || self.files.is_some())
            && self.files.iter().flatten().all(|entry| {
                entry
                    .orientation
                    .is_none_or(|value| (1..=8).contains(&value))
                    && usize::try_from(entry.file.size).is_ok()
            })
    }

    pub(crate) fn seal(&self, key: &Secret32, id: &ShareId) -> Result<Vec<u8>, Error> {
        if !self.valid() {
            return Err(Error::Prepare);
        }
        let mut json = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *json, self).map_err(|_| Error::Prepare)?;
        let padded = pad::pad(&json, padded_length(json.len())?.max(pad::MANIFEST_FLOOR))
            .map_err(|_| Error::Prepare)?;
        aead::seal(
            key,
            &associated_data(labels::MANIFEST, id, None),
            padded.as_bytes(),
        )
        .map_err(|_| Error::Prepare)
    }

    pub(crate) fn open(
        key: &Secret32,
        id: &ShareId,
        ciphertext: &[u8],
        blob_count: usize,
    ) -> Result<Self, Error> {
        let padded = aead::open(
            key,
            &associated_data(labels::MANIFEST, id, None),
            ciphertext,
        )
        .map_err(|_| Error::Open)?;
        let json = pad::unpad(padded.as_bytes()).map_err(|_| Error::Open)?;
        let manifest: Self = serde_json::from_slice(json).map_err(|_| Error::Open)?;
        if !manifest.valid() || manifest.files.as_ref().map_or(0, Vec::len) != blob_count {
            return Err(Error::Open);
        }
        Ok(manifest)
    }

    pub(crate) fn visible_content(&self) -> Result<String, Error> {
        let content = VisibleContent {
            note: self.note.as_deref(),
            login: self.login.as_ref(),
            files: self
                .files
                .iter()
                .flatten()
                .map(|entry| VisibleFile {
                    name: &entry.file.name,
                    mime: &entry.file.mime,
                    size: entry.file.size,
                    orientation: entry.orientation,
                })
                .collect(),
        };
        serde_json::to_string(&content).map_err(|_| Error::Open)
    }

    pub(crate) fn add_file(
        &mut self,
        id: &ShareId,
        name: String,
        mime: String,
        size: usize,
        orientation: Option<u8>,
    ) -> Result<FileSeal, Error> {
        let files = self.files.get_or_insert_default();
        let index = files.len().try_into().map_err(|_| Error::Prepare)?;
        let key = Secret32::generate().map_err(|_| Error::Prepare)?;
        let padding = padded_length(size)? - size;
        let (header, encryptor) =
            Encryptor::init(&key, &associated_data(labels::FILE, id, Some(index)))
                .map_err(|_| Error::Prepare)?;
        files.push(ImageFileEntry {
            file: FileEntry {
                name,
                mime,
                size: size as u64,
                key,
            },
            orientation,
        });
        Ok(FileSeal {
            encryptor: Some(encryptor),
            header,
            remaining: size,
            padding,
        })
    }

    pub(crate) fn open_file(
        &self,
        id: &ShareId,
        index: u32,
        header: &[u8],
    ) -> Result<FileOpen, Error> {
        let entry = self
            .files
            .as_ref()
            .and_then(|files| files.get(index as usize))
            .ok_or(Error::Open)?;
        let decryptor = Decryptor::init(
            &entry.file.key,
            &associated_data(labels::FILE, id, Some(index)),
            header,
        )
        .map_err(|_| Error::Open)?;
        let size = usize::try_from(entry.file.size).map_err(|_| Error::Open)?;
        Ok(FileOpen {
            decryptor: Some(decryptor),
            size,
            received: 0,
            marker_at: 0,
            marker: 0,
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct FileSeal {
    encryptor: Option<Encryptor>,
    header: [u8; HEADER_LEN],
    remaining: usize,
    padding: usize,
}

impl FileSeal {
    pub(crate) fn header(&self) -> &[u8; HEADER_LEN] {
        &self.header
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or(Error::Prepare)?;
        let encryptor = self.encryptor.as_mut().ok_or(Error::Prepare)?;
        let out = encryptor.update(bytes).map_err(|_| Error::Prepare)?;
        self.remaining = remaining;
        Ok(out)
    }

    pub(crate) fn finish(&mut self) -> Result<Vec<u8>, Error> {
        let mut encryptor = self.encryptor.take().ok_or(Error::Prepare)?;
        if self.remaining != 0 {
            return Err(Error::Prepare);
        }
        let mut padding = vec![0; self.padding];
        padding[0] = 0x80;
        let mut out = encryptor.update(&padding).map_err(|_| Error::Prepare)?;
        out.extend(encryptor.finish().map_err(|_| Error::Prepare)?);
        Ok(out)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct FileOpen {
    decryptor: Option<Decryptor>,
    size: usize,
    received: usize,
    marker_at: usize,
    marker: u8,
}

impl FileOpen {
    // Track the last nonzero byte across chunks to validate ISO 7816 padding.
    fn visible_len(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let start = self.received;
        self.received = start.checked_add(bytes.len()).ok_or(Error::Open)?;
        if let Some(index) = bytes.iter().rposition(|&byte| byte != 0) {
            self.marker = bytes[index];
            self.marker_at = start + index + 1;
        }
        Ok(self.size.saturating_sub(start).min(bytes.len()))
    }

    pub(crate) fn update<T>(
        &mut self,
        bytes: &[u8],
        copy: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, Error> {
        let plaintext = self
            .decryptor
            .as_mut()
            .ok_or(Error::Open)?
            .update(bytes)
            .map_err(|_| Error::Open)?;
        let bytes = plaintext.as_bytes();
        let len = self.visible_len(bytes)?;
        Ok(copy(&bytes[..len]))
    }

    pub(crate) fn finish<T>(&mut self, copy: impl FnOnce(&[u8]) -> T) -> Result<T, Error> {
        let plaintext = self
            .decryptor
            .take()
            .ok_or(Error::Open)?
            .finish()
            .map_err(|_| Error::Open)?;
        let bytes = plaintext.as_bytes();
        let len = self.visible_len(bytes)?;
        if self.marker != 0x80 || self.marker_at <= self.size {
            return Err(Error::Open);
        }
        Ok(copy(&bytes[..len]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tightlip_core::{manifest, stream::CHUNK_LEN};

    #[test]
    fn orientation_manifest_interoperates_with_core() {
        let mut draft = Manifest::from_content(Zeroizing::new("{}".into())).unwrap();
        draft
            .add_file(
                &[1; 16],
                "image.jpg".into(),
                "image/jpeg".into(),
                0,
                Some(6),
            )
            .unwrap();
        let key = Secret32::from_bytes([2; 32]);
        let ciphertext = draft.seal(&key, &[1; 16]).unwrap();
        assert!(manifest::open_manifest(&key, &[1; 16], &ciphertext, 1).is_ok());
        let opened = Manifest::open(&key, &[1; 16], &ciphertext, 1).unwrap();
        let visible: serde_json::Value =
            serde_json::from_str(&opened.visible_content().unwrap()).unwrap();
        assert_eq!(visible["files"][0]["orientation"], 6);
        assert!(visible["files"][0].get("key").is_none());
        assert!(Manifest::open(&key, &[1; 16], &ciphertext, 0).is_err());
    }

    #[test]
    fn incremental_stream_interoperates_and_checks_completion() {
        let id = [1; 16];
        let mut draft = Manifest::from_content(Zeroizing::new("{}".into())).unwrap();
        for size in [0, CHUNK_LEN - 1, CHUNK_LEN, CHUNK_LEN * 2 + 10] {
            let plaintext = vec![7; size];
            let mut seal = draft
                .add_file(&id, "file".into(), "".into(), size, None)
                .unwrap();
            let mut ciphertext = seal.header().to_vec();
            for chunk in plaintext.chunks(31_000) {
                ciphertext.extend(seal.update(chunk).unwrap());
            }
            ciphertext.extend(seal.finish().unwrap());
            let files = draft.files.as_ref().unwrap();
            let index = (files.len() - 1) as u32;
            assert_eq!(
                manifest::open_file(&id, index, &files[index as usize].file, &ciphertext)
                    .unwrap()
                    .as_bytes(),
                plaintext
            );
            let mut open = draft
                .open_file(&id, index, &ciphertext[..HEADER_LEN])
                .unwrap();
            let mut output = Vec::new();
            for chunk in ciphertext[HEADER_LEN..].chunks(30_000) {
                output.extend(open.update(chunk, <[u8]>::to_vec).unwrap());
            }
            output.extend(open.finish(<[u8]>::to_vec).unwrap());
            assert_eq!(output, plaintext);

            let mut open = draft
                .open_file(&id, index, &ciphertext[..HEADER_LEN])
                .unwrap();
            open.update(&ciphertext[HEADER_LEN..ciphertext.len() - 1], |_| ())
                .unwrap();
            assert!(open.finish(|_| ()).is_err());
        }
    }
}
