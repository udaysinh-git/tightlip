#![forbid(unsafe_code)]

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use thiserror::Error;
use tightlip_server::{
    Server, ServerError, SystemClock,
    config::{Config, ConfigError},
};
use tokio::{
    net::TcpListener,
    sync::oneshot,
    time::{self, MissedTickBehavior},
};

#[derive(Debug, Error)]
enum Error {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Server(#[from] ServerError),
    #[error("could not initialize HTTP or signal handling")]
    Io(#[from] io::Error),
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_level(false)
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tightlip: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Error> {
    let config = Config::from_env()?;
    let port = config.port;
    let server = Server::open(config, Arc::new(SystemClock))?;
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await?;
    let shutdown = shutdown_signal()?;
    let (done, mut stop) = oneshot::channel();
    let sweeper = {
        let server = server.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = &mut stop => break,
                    _ = interval.tick() => { let _ = server.sweep().await; }
                }
            }
        })
    };
    let result = axum::serve(
        listener,
        server
            .router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await;
    let _ = done.send(());
    let _ = sweeper.await;
    result?;
    Ok(())
}

fn shutdown_signal() -> io::Result<impl Future<Output = ()>> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    #[cfg(windows)]
    let mut interrupt = tokio::signal::windows::ctrl_c()?;

    Ok(async move {
        #[cfg(unix)]
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(windows)]
        let _ = interrupt.recv().await;
        #[cfg(not(any(windows, unix)))]
        let _ = tokio::signal::ctrl_c().await;
    })
}
