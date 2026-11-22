#![forbid(unsafe_code)]

use std::{
    env,
    future::Future,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
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

fn main() -> ExitCode {
    if env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--healthcheck")
    {
        return if Config::port_from_env().is_ok_and(|port| probe_health(port).unwrap_or(false)) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_level(false)
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tightlip: {error}");
            ExitCode::FAILURE
        }
    }
}

fn probe_health(port: u16) -> io::Result<bool> {
    const OK: &[u8] = b"HTTP/1.1 200 ";
    let timeout = Duration::from_secs(2);
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;

    let mut status = [0; OK.len()];
    stream.read_exact(&mut status)?;
    Ok(status == OK)
}

#[tokio::main]
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
