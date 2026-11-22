use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
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

impl Connected<IncomingStream<'_, CappedListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, CappedListener>) -> Self {
        Self(*stream.remote_addr())
    }
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
