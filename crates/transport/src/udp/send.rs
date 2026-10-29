//! Sends only completely validated replies, retaining admission until send/drop.
use std::{future::Future, io, os::fd::AsRawFd, sync::Arc, task::Poll};

use nix::libc;
use socket2::SockAddr;
use tokio::{io::Interest, net::UdpSocket, time};

use super::server::PreparedPacket;

const MAX_BATCH: usize = 16;

/// Keep the ready-path allocation for reuse. Backpressured sends continue
/// independently so they cannot prevent this worker receiving more packets.
pub(super) async fn dispatch(
    socket: Arc<UdpSocket>,
    mut packets: Vec<PreparedPacket>,
    capacity: usize,
) -> Vec<PreparedPacket> {
    let mut sending = Box::pin(async move {
        flush(&socket, &mut packets).await;
        packets
    });
    let polled = std::future::poll_fn(|cx| {
        Poll::Ready(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || sending.as_mut().poll(cx),
        )))
    })
    .await;
    match polled {
        Ok(Poll::Ready(packets)) => packets,
        Ok(Poll::Pending) => {
            tokio::spawn(async move {
                drop(sending.await);
            });
            Vec::with_capacity(capacity)
        }
        Err(_) => {
            tracing::error!("UDP response batch panicked");
            Vec::with_capacity(capacity)
        }
    }
}

async fn flush(socket: &UdpSocket, packets: &mut Vec<PreparedPacket>) {
    while !packets.is_empty() {
        let now = time::Instant::now();
        packets.retain(|packet| packet.deadline > now);
        let Some(deadline) = packets.iter().map(|packet| packet.deadline).min() else {
            break;
        };
        let result = time::timeout_at(deadline, async {
            loop {
                if time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "sending UDP response batch",
                    ));
                }
                socket.writable().await?;
                match socket.try_io(Interest::WRITABLE, || send_ready(socket, packets)) {
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    result => return result,
                }
            }
        })
        .await;
        match result {
            Ok(Ok(sent)) if sent > 0 && sent <= packets.len() => {
                // Only the committed prefix releases its admission permits.
                packets.drain(..sent);
            }
            Err(_) => {
                // Expire only the due packets; later deadlines stay valid.
                continue;
            }
            _ => {
                // A bad peer, oversized packet, or restricted syscall must
                // not suppress valid neighbours in the batch.
                for packet in packets.drain(..) {
                    packet.send(socket).await;
                }
            }
        }
    }
}

fn send_ready(socket: &UdpSocket, packets: &[PreparedPacket]) -> io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }
    let count = packets.len().min(MAX_BATCH);
    let addresses: [_; MAX_BATCH] =
        std::array::from_fn(|index| SockAddr::from(packets.get(index).unwrap_or(&packets[0]).peer));
    let iovecs: [_; MAX_BATCH] = std::array::from_fn(|index| {
        let bytes = packets
            .get(index)
            .map_or(&[][..], |packet| packet.wire.as_slice());
        libc::iovec {
            // Linux sendmmsg reads, but does not write, the data at this pointer.
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        }
    });
    let mut headers: [libc::mmsghdr; MAX_BATCH] = std::array::from_fn(|index| {
        // SAFETY: A zeroed Linux mmsghdr is valid: its fields are integers,
        // pointers, and a nested msghdr with the same field categories.
        // Starting zeroed initializes every named field, including optional
        // control-message pointers and lengths, before they are passed to Linux.
        let mut header: libc::mmsghdr = unsafe { std::mem::zeroed() };
        header.msg_hdr.msg_name = addresses[index].as_ptr().cast_mut().cast();
        header.msg_hdr.msg_namelen = addresses[index].len();
        header.msg_hdr.msg_iov = std::ptr::from_ref(&iovecs[index]).cast_mut();
        header.msg_hdr.msg_iovlen = 1;
        header
    });
    // SAFETY: The socket is alive for this synchronous call. The first `count`
    // initialized headers point to stable address and iovec arrays above;
    // each iovec points to its packet's live wire bytes. Linux sendmmsg reads
    // those inputs and writes only header results. All arrays remain in scope
    // and are not moved or mutated until the syscall returns. count <= 16.
    let sent = unsafe {
        libc::sendmmsg(
            socket.as_raw_fd(),
            headers.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, time::Duration};
    use tokio::sync::Semaphore;

    async fn packet(
        bytes: Vec<u8>,
        peer: SocketAddr,
        deadline: time::Instant,
        permits: &Arc<Semaphore>,
    ) -> PreparedPacket {
        PreparedPacket::for_test(
            bytes,
            peer,
            deadline,
            Arc::clone(permits).acquire_owned().await.unwrap(),
        )
    }

    #[tokio::test]
    async fn sends_separate_datagrams_and_preserves_source_for_both_families() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let socket = UdpSocket::bind(address).await.unwrap();
            let client = UdpSocket::bind(address).await.unwrap();
            let peer = client.local_addr().unwrap();
            let permits = Arc::new(Semaphore::new(3));
            let deadline = time::Instant::now() + Duration::from_secs(1);
            let mut packets = Vec::new();
            for bytes in [b"one".as_slice(), b"", b"three"] {
                packets.push(packet(bytes.to_vec(), peer, deadline, &permits).await);
            }
            flush(&socket, &mut packets).await;
            assert!(packets.is_empty());
            assert_eq!(permits.available_permits(), 3);
            let mut buffer = [0; 32];
            for expected in [b"one".as_slice(), b"", b"three"] {
                let (length, source) =
                    time::timeout(Duration::from_secs(1), client.recv_from(&mut buffer))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(&buffer[..length], expected);
                assert_eq!(source, socket.local_addr().unwrap());
            }
        }
    }

    #[tokio::test]
    async fn batch_routes_each_packet_to_its_own_peer_without_duplicating_data() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let socket = UdpSocket::bind(address).await.unwrap();
            let permits = Arc::new(Semaphore::new(MAX_BATCH));
            let deadline = time::Instant::now() + Duration::from_secs(1);
            let mut clients = Vec::new();
            let mut packets = Vec::new();
            for id in 0..MAX_BATCH {
                let client = UdpSocket::bind(address).await.unwrap();
                let data = vec![id as u8, 0, 255 - id as u8];
                packets.push(packet(data, client.local_addr().unwrap(), deadline, &permits).await);
                clients.push(client);
            }
            assert_eq!(send_ready(&socket, &[]).unwrap(), 0);
            flush(&socket, &mut packets).await;
            assert!(packets.is_empty());
            assert_eq!(permits.available_permits(), MAX_BATCH);
            for (id, client) in clients.iter().enumerate() {
                let mut buffer = [0; 16];
                let (size, peer) =
                    time::timeout(Duration::from_secs(1), client.recv_from(&mut buffer))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(&buffer[..size], &[id as u8, 0, 255 - id as u8]);
                assert_eq!(peer, socket.local_addr().unwrap());
                assert_eq!(
                    client.try_recv(&mut buffer).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
        }
    }

    #[tokio::test]
    async fn send_ready_caps_batch_and_retains_tail_for_the_next_send() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let permits = Arc::new(Semaphore::new(MAX_BATCH + 3));
        let deadline = time::Instant::now() + Duration::from_secs(1);
        let mut packets = Vec::new();
        for id in 0..MAX_BATCH + 3 {
            packets.push(
                packet(
                    vec![id as u8],
                    client.local_addr().unwrap(),
                    deadline,
                    &permits,
                )
                .await,
            );
        }
        let sent = send_ready(&socket, &packets).unwrap();
        assert_eq!(sent, MAX_BATCH);
        packets.drain(..sent);
        assert_eq!(packets.len(), 3);
        flush(&socket, &mut packets).await;
        assert!(packets.is_empty());
        assert_eq!(permits.available_permits(), MAX_BATCH + 3);
        let mut buffer = [0; 8];
        for id in 0..MAX_BATCH + 3 {
            let (size, _) = time::timeout(Duration::from_secs(1), client.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..size], &[id as u8]);
        }
        assert_eq!(
            client.try_recv(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn oversized_first_datagram_reports_os_error_without_consuming_packet() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let permits = Arc::new(Semaphore::new(1));
        let deadline = time::Instant::now() + Duration::from_secs(1);
        let packets = vec![
            packet(
                vec![0; 65536],
                client.local_addr().unwrap(),
                deadline,
                &permits,
            )
            .await,
        ];
        let error = send_ready(&socket, &packets).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EMSGSIZE));
        assert_eq!(packets.len(), 1);
        assert_eq!(permits.available_permits(), 0);
        drop(packets);
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn partial_send_does_not_duplicate_prefix_or_suppress_valid_tail() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client.local_addr().unwrap();
        let permits = Arc::new(Semaphore::new(3));
        let deadline = time::Instant::now() + Duration::from_secs(1);
        let mut packets = vec![
            packet(b"first".to_vec(), peer, deadline, &permits).await,
            packet(vec![0; 65536], peer, deadline, &permits).await,
            packet(b"last".to_vec(), peer, deadline, &permits).await,
        ];
        flush(&socket, &mut packets).await;
        assert_eq!(permits.available_permits(), 3);
        let mut buffer = [0; 32];
        for expected in [b"first".as_slice(), b"last"] {
            let length = time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..length], expected);
        }
        assert_eq!(
            client.try_recv(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn expired_reply_releases_capacity_without_being_sent() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client.local_addr().unwrap();
        let permits = Arc::new(Semaphore::new(2));
        let now = time::Instant::now();
        let mut packets = vec![
            packet(
                b"expired".to_vec(),
                peer,
                now - Duration::from_secs(1),
                &permits,
            )
            .await,
            packet(
                b"live".to_vec(),
                peer,
                now + Duration::from_secs(1),
                &permits,
            )
            .await,
        ];
        flush(&socket, &mut packets).await;
        assert_eq!(permits.available_permits(), 2);
        let mut buffer = [0; 32];
        let length = time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], b"live");
        assert_eq!(
            client.try_recv(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
