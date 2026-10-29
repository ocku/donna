//! Keep QUIC's endpoint driver alive across transient UDP receive failures.

use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit, UdpSocketState},
};
use tokio::{
    io::Interest,
    net::UdpSocket,
    time::{self, Sleep},
};

use crate::listener_io::Retry;

#[derive(Debug)]
pub(super) struct ServerSocket {
    io: UdpSocket,
    state: UdpSocketState,
    receive: Mutex<ReceiveRetry>,
}

impl ServerSocket {
    pub(super) fn bind(address: SocketAddr) -> io::Result<Arc<Self>> {
        let socket = std::net::UdpSocket::bind(address)?;
        let state = UdpSocketState::new((&socket).into())?;
        socket.set_nonblocking(true)?;
        Ok(Arc::new(Self {
            io: UdpSocket::from_std(socket)?,
            state,
            receive: Mutex::new(ReceiveRetry::default()),
        }))
    }
}

impl AsyncUdpSocket for ServerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(WritePoller {
            socket: self,
            ready: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.state.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut receive = self
            .receive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        receive.poll(cx, |cx| {
            loop {
                ready!(self.io.poll_recv_ready(cx))?;
                match self.io.try_io(Interest::READABLE, || {
                    self.state.recv((&self.io).into(), buffers, meta)
                }) {
                    // try_io clears readiness after another task wins a receive.
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    result => return Poll::Ready(result),
                }
            }
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }
}

#[derive(Debug, Default)]
struct ReceiveRetry {
    retry: Retry,
    waiting: Option<Pin<Box<Sleep>>>,
}

impl ReceiveRetry {
    fn poll<T>(
        &mut self,
        cx: &mut Context<'_>,
        receive: impl FnOnce(&mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if let Some(waiting) = &mut self.waiting {
            ready!(waiting.as_mut().poll(cx));
            self.waiting = None;
        }
        match receive(cx) {
            Poll::Ready(Ok(packet)) => {
                self.retry.reset();
                Poll::Ready(Ok(packet))
            }
            Poll::Ready(Err(error)) => {
                let delay = self.retry.next_delay(error)?;
                let mut waiting = Box::pin(time::sleep(delay));
                // Register the endpoint driver's waker before returning Pending.
                let _ = waiting.as_mut().poll(cx);
                self.waiting = Some(waiting);
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

type WriteReady = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

struct WritePoller {
    socket: Arc<ServerSocket>,
    ready: Option<WriteReady>,
}

impl std::fmt::Debug for WritePoller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WritePoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for WritePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let ready = this.ready.get_or_insert_with(|| {
            let socket = Arc::clone(&this.socket);
            Box::pin(async move { socket.io.writable().await })
        });
        let result = ready.as_mut().poll(cx);
        if result.is_ready() {
            this.ready = None;
        }
        result
    }
}

#[cfg(test)]
mod tests;
