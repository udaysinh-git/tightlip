#![forbid(unsafe_code)]

mod api;
pub mod config;
mod connection;
mod credentials;
mod file_body;
mod rate;
mod storage;
mod web;

use std::{
    future::Future,
    io,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::Router;
use thiserror::Error;
use tightlip_core::{
    Secret32,
    oprf::{self, ServerKey},
    share::{self, ShareId},
};
use tokio::sync::Semaphore;

use config::{Config, Limits};
use connection::Peer;
use rate::RateLimiter;
use storage::{Blobs, Error, Metadata, Result, disk::Disk, sqlite::Sqlite};

pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
            Err(_) => 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("could not initialize storage")]
    Storage,
    #[error("could not initialize cryptography")]
    Crypto,
    #[error("could not sweep storage")]
    Sweep,
}

#[derive(Clone)]
pub struct Server(Arc<State>);

struct State {
    meta: Box<dyn Metadata>,
    blobs: Box<dyn Blobs>,
    clock: Arc<dyn Clock>,
    kek: Secret32,
    dummy: Dummy,
    trust_proxy: bool,
    limits: Limits,
    rate: RateLimiter,
    uploads: Arc<Semaphore>,
    web_dir: PathBuf,
}

struct Dummy {
    id: ShareId,
    wrapped: Vec<u8>,
    blinded: [u8; 32],
}

impl Server {
    pub fn open(config: Config, clock: Arc<dyn Clock>) -> std::result::Result<Self, ServerError> {
        let dummy = Dummy::new(&config.kek).map_err(|_| ServerError::Crypto)?;
        let blobs = Disk::open(&config.data_dir).map_err(|_| ServerError::Storage)?;
        let meta = Sqlite::open(&config.data_dir.join("tightlip.sqlite3"))
            .map_err(|_| ServerError::Storage)?;
        meta.sweep(clock.now()).map_err(|_| ServerError::Storage)?;
        blobs
            .reconcile(&meta.live_blobs().map_err(|_| ServerError::Storage)?)
            .map_err(|_| ServerError::Storage)?;
        meta.collect_garbage(&blobs)
            .map_err(|_| ServerError::Storage)?;
        Ok(Self(Arc::new(State {
            meta: Box::new(meta),
            blobs: Box::new(blobs),
            clock,
            kek: config.kek,
            dummy,
            trust_proxy: config.trust_proxy,
            limits: config.limits,
            rate: RateLimiter::new(config.limits.creates_per_ip),
            uploads: Arc::new(Semaphore::new(8)),
            web_dir: config.web_dir,
        })))
    }

    pub fn router(&self) -> Router {
        api::router(self.clone())
    }

    pub async fn serve(
        &self,
        listener: tokio::net::TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<()> {
        axum::serve(
            connection::CappedListener::new(listener),
            self.router().into_make_service_with_connect_info::<Peer>(),
        )
        .with_graceful_shutdown(shutdown)
        .await
    }

    pub async fn sweep(&self) -> std::result::Result<(), ServerError> {
        self.run(|state| {
            let now = state.clock.now();
            state.rate.sweep(now)?;
            state.meta.sweep(now)?;
            state.meta.collect_garbage(&*state.blobs)
        })
        .await
        .map_err(|_| ServerError::Sweep)
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(&State) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let state = self.0.clone();
        tokio::task::spawn_blocking(move || work(&state))
            .await
            .map_err(|_| Error::Internal)?
    }
}

impl Dummy {
    fn new(kek: &Secret32) -> Result<Self> {
        let id = share::generate_share_id().map_err(|_| Error::Internal)?;
        let key = ServerKey::generate().map_err(|_| Error::Internal)?;
        let wrapped = share::wrap_oprf_key(kek, &id, &key).map_err(|_| Error::Internal)?;
        let input = Secret32::generate().map_err(|_| Error::Internal)?;
        let (blinded, _) = oprf::blind(&input).map_err(|_| Error::Internal)?;
        Ok(Self {
            id,
            wrapped,
            blinded,
        })
    }
}
