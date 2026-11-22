use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    pin::Pin,
};

use axum::body::Body;
use tightlip_core::{b64, share::generate_share_id};
use tokio::io::AsyncWrite;

use crate::file_body::file_body;

use super::{BlobKey, Blobs, Error, Result, StagedBlob};

pub(crate) struct Disk {
    root: PathBuf,
    _lock: File,
}

impl Disk {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let root = data_dir.join("blobs");
        fs::create_dir_all(&root)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(data_dir.join("tightlip.lock"))?;
        lock.try_lock().map_err(std::io::Error::from)?;
        Ok(Self { root, _lock: lock })
    }

    // Run with the data-directory lock, before accepting any requests.
    pub fn reconcile(&self, live: &HashSet<BlobKey>) -> Result<()> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some((encoded, ext)) = name.to_str().and_then(|name| name.rsplit_once('.')) else {
                continue;
            };
            let Ok(key) = b64::decode(encoded)
                .and_then(|bytes| <BlobKey>::try_from(bytes).map_err(|_| b64::DecodeError))
            else {
                continue;
            };
            if ext == "tmp" || (ext == "blob" && !live.contains(&key)) {
                unlink(&entry.path())?;
            }
        }
        Ok(())
    }

    fn path(&self, key: &BlobKey, suffix: &str) -> PathBuf {
        self.root.join(format!("{}.{suffix}", b64::encode(key)))
    }
}

impl Blobs for Disk {
    fn stage(&self) -> Result<Box<dyn StagedBlob>> {
        let key = generate_share_id().map_err(|_| Error::Internal)?;
        let path = self.path(&key, "tmp");
        let destination = self.path(&key, "blob");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Box::new(Stage {
            key,
            path,
            destination,
            writer: Some(tokio::fs::File::from_std(file)),
            published: false,
            keep: false,
        }))
    }

    fn download(&self, key: &BlobKey, start: u64, len: u64) -> Result<Body> {
        let file = File::open(self.path(key, "blob")).map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                Error::Missing
            } else {
                error.into()
            }
        })?;
        Ok(file_body(file, start, len)?)
    }

    fn remove(&self, key: &BlobKey) -> Result<()> {
        unlink(&self.path(key, "blob"))
    }
}

struct Stage {
    key: BlobKey,
    path: PathBuf,
    destination: PathBuf,
    writer: Option<tokio::fs::File>,
    published: bool,
    keep: bool,
}

impl StagedBlob for Stage {
    fn key(&self) -> BlobKey {
        self.key
    }

    fn writer(&mut self) -> Result<Pin<&mut (dyn AsyncWrite + Send)>> {
        self.writer
            .as_mut()
            .map(|file| Pin::new(file) as Pin<&mut (dyn AsyncWrite + Send)>)
            .ok_or(Error::Internal)
    }

    fn publish(&mut self) -> Result<()> {
        drop(self.writer.take());
        OpenOptions::new()
            .write(true)
            .open(&self.path)?
            .sync_all()?;
        if self.destination.try_exists()? {
            return Err(Error::Internal);
        }
        fs::rename(&self.path, &self.destination)?;
        self.published = true;
        #[cfg(unix)]
        if let Some(directory) = self.destination.parent() {
            File::open(directory)?.sync_all()?;
        }
        Ok(())
    }

    fn keep(mut self: Box<Self>) {
        self.keep = true;
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        drop(self.writer.take());
        if !self.keep {
            let path = if self.published {
                &self.destination
            } else {
                &self.path
            };
            let _ = unlink(path);
        }
    }
}

fn unlink(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
