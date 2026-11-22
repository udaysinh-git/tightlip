use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{Extension, Router, extract::ConnectInfo, serve::Listener};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::graceful::GracefulShutdown,
    service::TowerToHyperService,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};

const MAX_CONNECTIONS: usize = 128;

pub(crate) struct CappedListener {
    listener: TcpListener,
    slots: Arc<Semaphore>,
}

impl CappedListener {
    pub(crate) fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }
}

impl Listener for CappedListener {
    type Io = Connection;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Connection, SocketAddr) {
        let Ok(permit) = self.slots.clone().acquire_owned().await else {
            // Axum's listener cannot return an error. This semaphore is never closed.
            return std::future::pending().await;
        };
        let (stream, peer) = Listener::accept(&mut self.listener).await;
        (
            Connection {
                stream,
                _permit: permit,
            },
            peer,
        )
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Peer(pub SocketAddr);

fn http1_builder() -> http1::Builder {
    let mut builder = http1::Builder::new();
    // Hyper starts this timer again when waiting for the next keep-alive request.
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10));
    builder
}

pub(crate) async fn serve(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let mut listener = CappedListener::new(listener);
    let graceful = GracefulShutdown::new();
    let builder = http1_builder();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            (stream, peer) = listener.accept() => {
                let service = router.clone().layer(Extension(ConnectInfo(Peer(peer))));
                let connection = builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(service));
                let connection = graceful.watch(connection);
                tokio::spawn(async move { let _ = connection.await; });
            }
        }
    }
    drop(listener);
    graceful.shutdown().await;
    Ok(())
}

pub(crate) struct Connection {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, bytes)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn incomplete_first_and_keep_alive_headers_expire_after_ten_seconds() {
        use axum::{http::StatusCode, routing::get};
        use tokio::{
            io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex},
            time::{Instant, timeout},
        };

        let router = Router::new().route("/", get(|| async { StatusCode::NO_CONTENT }));
        for keep_alive in [false, true] {
            let (socket, client) = duplex(2048);
            let mut client = BufReader::new(client);
            let connection = http1_builder().serve_connection(
                TokioIo::new(socket),
                TowerToHyperService::new(router.clone()),
            );
            let serving = tokio::spawn(connection);
            if keep_alive {
                client
                    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .await
                    .unwrap();
                let mut line = String::new();
                client.read_line(&mut line).await.unwrap();
                assert_eq!(line, "HTTP/1.1 204 No Content\r\n");
                while line != "\r\n" {
                    line.clear();
                    assert_ne!(client.read_line(&mut line).await.unwrap(), 0);
                }
            }
            let start = Instant::now();
            client.write_all(b"GET / HTTP/1.1\r\nHost: ").await.unwrap();
            let error = timeout(Duration::from_secs(11), serving)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert!(error.is_timeout());
            assert_eq!(start.elapsed(), Duration::from_secs(10));
        }
    }

    #[tokio::test]
    async fn a_connection_holds_its_slot_until_dropped() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let mut listener = CappedListener {
            listener: tcp,
            slots: Arc::new(Semaphore::new(1)),
        };
        let _client = TcpStream::connect(address).await.unwrap();
        let (first, _) = listener.accept().await;
        let _waiting = TcpStream::connect(address).await.unwrap();
        let mut accept = Box::pin(listener.accept());
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(accept.as_mut().poll(&mut context).is_pending());
        drop(first);
        assert!(accept.await.1.ip().is_loopback());
    }
}
