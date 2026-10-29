//! Receive and accept failures affect individual peers, not the listener.

use std::{
    future::poll_fn,
    io,
    net::SocketAddr,
    task::{Context, Poll},
    time::Duration,
};

use tokio::net::{TcpListener, TcpStream};

const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(10);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(1);

#[cfg(any(feature = "udp", feature = "dnscrypt"))]
pub(crate) fn require_concrete_udp_address(address: SocketAddr) -> io::Result<()> {
    // recv_from does not report the query's destination. A concrete bind is
    // required to preserve the reply's source address (RFC 2181 section 4.1).
    if address.ip().is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RFC 2181 UDP service requires an explicit local address",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct Retry {
    delay: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            delay: INITIAL_RETRY_DELAY,
        }
    }
}

impl Retry {
    #[cfg(any(all(feature = "udp", target_os = "linux"), feature = "doq", test))]
    pub(crate) fn reset(&mut self) {
        self.delay = INITIAL_RETRY_DELAY;
    }

    pub(crate) fn next_delay(&mut self, error: io::Error) -> io::Result<Duration> {
        if !recoverable(&error) {
            return Err(error);
        }
        let delay = self.delay;
        self.delay = self.delay.saturating_mul(2).min(MAX_RETRY_DELAY);
        tracing::debug!(?error, ?delay, "listener I/O failed; retrying");
        Ok(delay)
    }

    pub(crate) async fn wait(&mut self, error: io::Error) -> io::Result<()> {
        tokio::time::sleep(self.next_delay(error)?).await;
        Ok(())
    }
}

fn recoverable(error: &io::Error) -> bool {
    use io::ErrorKind::*;

    if matches!(
        error.kind(),
        Interrupted
            | WouldBlock
            | TimedOut
            | ConnectionAborted
            | ConnectionReset
            | ConnectionRefused
            | NetworkDown
            | NetworkUnreachable
            | HostUnreachable
            | OutOfMemory
    ) {
        return true;
    }

    // std has no portable ErrorKind for descriptor exhaustion or socket-buffer
    // pressure. Keep OS codes symbolic, and leave invalid descriptors fatal.
    #[cfg(unix)]
    if matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS)
    ) {
        return true;
    }

    // Linux accept(2) can report a pending connection's protocol/network error
    // through the listening descriptor, without invalidating that descriptor.
    #[cfg(target_os = "linux")]
    if matches!(
        error.raw_os_error(),
        Some(libc::EPROTO | libc::ENOPROTOOPT | libc::EHOSTDOWN | libc::ENONET)
    ) {
        return true;
    }

    false
}

async fn next<T>(
    mut operation: impl FnMut(&mut Context<'_>) -> Poll<io::Result<T>>,
) -> io::Result<T> {
    let mut retry = Retry::default();
    loop {
        match poll_fn(&mut operation).await {
            Ok(event) => return Ok(event),
            Err(error) => retry.wait(error).await?,
        }
    }
}

pub(crate) async fn accept(listener: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    next(|cx| listener.poll_accept(cx)).await
}

#[cfg(any(feature = "udp", feature = "dnscrypt"))]
pub(crate) async fn recv_from(
    socket: &tokio::net::UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    next(|cx| {
        let mut read = tokio::io::ReadBuf::new(buffer);
        match socket.poll_recv_from(cx, &mut read) {
            Poll::Ready(Ok(peer)) => Poll::Ready(Ok((read.filled().len(), peer))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[cfg(test)]
mod tests;
