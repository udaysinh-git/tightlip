use std::pin::Pin;

use axum::body::Body;
use serde::Serialize;
use thiserror::Error;
use tightlip_core::{
    Secret32,
    share::{ShareId, Verifier},
};
use tokio::io::AsyncWrite;

pub(crate) mod disk;
pub(crate) mod sqlite;

pub(crate) type BlobKey = [u8; 16];
pub(crate) type Hash = [u8; 32];

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("storage failure")]
    Sql(#[from] rusqlite::Error),
    #[error("blob I/O failure")]
    Io(#[from] std::io::Error),
    #[error("internal failure")]
    Internal,
    #[error("share unavailable")]
    Missing,
    #[error("invalid credential")]
    Unauthorized,
    #[error("invalid request")]
    Invalid,
    #[error("size limit exceeded")]
    TooLarge,
    #[error("uploads must use contiguous file indices")]
    FileGap,
    #[error("rate limit exceeded")]
    RateLimited { retry_after: i64 },
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) struct Pending {
    pub id: ShareId,
    pub expires_at: i64,
    pub pending_until: i64,
    pub has_password: bool,
    pub views: u32,
    pub attempts: u32,
    pub upload_hash: Hash,
    pub wrapped_key: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct ShareInfo {
    pub suite: &'static str,
    pub has_password: bool,
    pub expires_at: i64,
    pub views_left: u32,
}

#[derive(Serialize)]
pub(crate) struct FileInfo {
    pub n: u32,
    pub size: u64,
}

pub(crate) struct Opened {
    pub manifest: Vec<u8>,
    pub files: Vec<FileInfo>,
    pub views_left: u32,
}

pub(crate) struct OpenRequest {
    pub tag: Secret32,
    pub request_hash: Hash,
}

#[derive(Clone, Copy)]
pub(crate) enum UploadTarget {
    Manifest,
    File(u32),
}

pub(crate) struct Upload {
    pub id: ShareId,
    pub hash: Option<Hash>,
    pub target: UploadTarget,
    pub manifest_cap: u64,
    pub file_cap: u32,
    pub total_cap: u64,
    pub storage_cap: u64,
}

pub(crate) struct Blob {
    pub key: BlobKey,
    pub size: u64,
}

pub(crate) type Evaluate<'a> = dyn FnOnce(Option<&[u8]>) -> Result<[u8; 32]> + 'a;

pub(crate) trait Metadata: Send + Sync {
    fn check_storage(&self, storage_cap: u64) -> Result<()>;
    fn create(&self, pending: &Pending, storage_cap: u64) -> Result<()>;
    fn check_pending_upload(&self, id: &ShareId, now: i64, hash: Option<&Hash>) -> Result<()>;
    fn upload_limit(&self, upload: &Upload, now: i64) -> Result<u64>;
    fn put_manifest(&self, upload: &Upload, now: i64, contents: &[u8]) -> Result<()>;
    fn put_file(
        &self,
        upload: &Upload,
        now: i64,
        blob: &Blob,
        publish: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;
    fn commit(
        &self,
        id: &ShareId,
        now: i64,
        upload_hash: Option<&Hash>,
        verifiers: Result<(Verifier, Verifier)>,
    ) -> Result<()>;
    fn info(&self, id: &ShareId, now: i64) -> Result<ShareInfo>;
    fn eval(&self, id: &ShareId, now: i64, evaluate: Box<Evaluate<'_>>) -> Result<([u8; 32], u32)>;
    fn open(
        &self,
        id: &ShareId,
        now: i64,
        request: Result<OpenRequest>,
        grant: &Hash,
    ) -> Result<Opened>;
    fn file(&self, id: &ShareId, now: i64, n: u32, grant: Option<&Hash>) -> Result<Blob>;
    fn delete(&self, id: &ShareId, now: i64, owner: Option<&Secret32>) -> Result<()>;
    fn sweep(&self, now: i64) -> Result<()>;
    fn collect_garbage(&self, blobs: &dyn Blobs) -> Result<()>;
}

pub(crate) trait Blobs: Send + Sync {
    fn stage(&self) -> Result<Box<dyn StagedBlob>>;
    fn download(&self, key: &BlobKey) -> Result<Body>;
    fn remove(&self, key: &BlobKey) -> Result<()>;
}

pub(crate) trait StagedBlob: Send {
    fn key(&self) -> BlobKey;
    fn writer(&mut self) -> Result<Pin<&mut (dyn AsyncWrite + Send)>>;
    fn publish(&mut self) -> Result<()>;
    fn keep(self: Box<Self>);
}
