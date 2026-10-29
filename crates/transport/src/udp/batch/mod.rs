//! Bounded nonblocking Linux receive batching through nix's safe socket API.
use std::{
    cell::RefCell,
    io::{self, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::Arc,
};

use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrIn, SockaddrIn6, SockaddrLike, recvmmsg};
use tokio::{io::Interest, net::UdpSocket, sync::Semaphore};

use super::{
    RECEIVE_BUFFER_OCTETS, UdpServerPolicy,
    server::{PacketActivity, acquire_packet_permit, prepare_packet},
};
use crate::{DnsRequestHandler, MAX_EDNS_UDP_MESSAGE_OCTETS};

const MAX_BATCH: usize = 16;

#[cfg(test)]
mod first_reply;

thread_local! {
    // MultiHeaders retains raw IO pointers and is !Send. Keep it on its OS
    // thread and borrow it only during the synchronous syscall. Separate
    // address types also preserve msg_namelen when workers serve both families.
    static V4_HEADERS: RefCell<MultiHeaders<SockaddrIn>> =
        RefCell::new(MultiHeaders::preallocate(MAX_BATCH, None));
    static V6_HEADERS: RefCell<MultiHeaders<SockaddrIn6>> =
        RefCell::new(MultiHeaders::preallocate(MAX_BATCH, None));
}

pub(super) async fn receive_packets<H>(
    socket: UdpSocket,
    handler: Arc<H>,
    policy: UdpServerPolicy,
    activity: Option<Arc<PacketActivity>>,
    permits: Arc<Semaphore>,
    batch_size: usize,
) -> Result<(), io::Error>
where
    H: DnsRequestHandler + 'static,
{
    if !(1..=MAX_BATCH).contains(&batch_size) || policy.packet_limit == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid UDP batch admission policy",
        ));
    }
    let ipv6 = socket.local_addr()?.is_ipv6();
    let socket = Arc::new(socket);
    let mut buffers: Vec<_> = (0..batch_size)
        .map(|_| vec![0; RECEIVE_BUFFER_OCTETS])
        .collect();
    let mut replies = Vec::with_capacity(batch_size);
    let mut retry = crate::listener_io::Retry::default();
    loop {
        if let Err(error) = socket.readable().await {
            retry.wait(error).await?;
            continue;
        }
        // Acquire one permit fairly, then reserve additional capacity without
        // waiting. A batch can never consume an unadmitted datagram or wait
        // for a full batch to arrive.
        let mut reserved = acquire_packet_permit(&permits).await?;
        let extra_count = permits.available_permits().min(batch_size - 1);
        if extra_count > 0
            && let Ok(extra) = Arc::clone(&permits).try_acquire_many_owned(extra_count as u32)
        {
            reserved.merge(extra);
        }
        let mut packets = [None; MAX_BATCH];
        let received = socket.try_io(Interest::READABLE, || {
            read_batch(
                &socket,
                ipv6,
                &mut buffers,
                reserved.num_permits(),
                &mut packets,
            )
        });
        let count = match received {
            Ok(count) => count,
            // try_io clears readiness on WouldBlock. Let readable() wait for
            // a fresh readiness notification instead of sleeping after races
            // between receive workers sharing the same kernel socket queue.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(nix::libc::ENOSYS | nix::libc::EPERM)
                ) =>
            {
                // Older kernels or restricted syscall profiles can retain the
                // original receive path, with the same shared budget.
                drop(reserved);
                let fallback = socket2::SockRef::from(socket.as_ref()).try_clone()?;
                let fallback = UdpSocket::from_std(fallback.into())?;
                drop(socket);
                drop(buffers);
                return super::server::receive_packets(
                    fallback, handler, policy, activity, permits, true,
                )
                .await;
            }
            Err(error) => {
                drop(reserved);
                retry.wait(error).await?;
                continue;
            }
        };
        retry.reset();
        let mut first_ready = true;
        for index in 0..count {
            let permit = reserved
                .split(1)
                .expect("one permit was reserved per receive slot");
            let Some((length, peer)) = packets[index] else {
                continue;
            };
            if length > MAX_EDNS_UDP_MESSAGE_OCTETS {
                continue;
            }
            if let Some(activity) = &activity {
                activity.record_received();
            }
            if let Some(reply) = prepare_packet(
                &socket,
                peer,
                Arc::clone(&handler),
                &buffers[index][..length],
                policy,
                permit,
                activity.clone(),
            )
            .await
            {
                if first_ready {
                    first_ready = false;
                    if reply.deadline <= tokio::time::Instant::now() {
                        continue;
                    }
                    match socket.try_send_to(&reply.wire, reply.peer) {
                        Ok(_) => continue,
                        Err(error) if error.kind() != io::ErrorKind::WouldBlock => {
                            tracing::debug!(%peer, ?error, "UDP response send failed");
                            continue;
                        }
                        Err(_) => {}
                    }
                }
                replies.push(reply);
            }
        }
        drop(reserved);
        if !replies.is_empty() {
            replies = super::send::dispatch(Arc::clone(&socket), replies, batch_size).await;
        }
    }
}

fn read_batch(
    socket: &UdpSocket,
    ipv6: bool,
    buffers: &mut [Vec<u8>],
    limit: usize,
    packets: &mut [Option<(usize, SocketAddr)>; MAX_BATCH],
) -> Result<usize, io::Error> {
    if ipv6 {
        V6_HEADERS
            .with(|headers| receive(socket, &mut headers.borrow_mut(), buffers, limit, packets))
    } else {
        V4_HEADERS
            .with(|headers| receive(socket, &mut headers.borrow_mut(), buffers, limit, packets))
    }
}

fn receive<S>(
    socket: &UdpSocket,
    headers: &mut MultiHeaders<S>,
    buffers: &mut [Vec<u8>],
    limit: usize,
    packets: &mut [Option<(usize, SocketAddr)>; MAX_BATCH],
) -> Result<usize, io::Error>
where
    S: Copy + SockaddrLike + Into<SocketAddr>,
{
    let mut slices = std::array::from_fn::<_, MAX_BATCH, _>(|_| [IoSliceMut::new(&mut [])]);
    for (slices, buffer) in slices.iter_mut().zip(buffers) {
        *slices = [IoSliceMut::new(buffer)];
    }
    let received = recvmmsg(
        socket.as_raw_fd(),
        headers,
        slices[..limit].iter_mut(),
        MsgFlags::MSG_DONTWAIT,
        None,
    )
    .map_err(io::Error::from)?;
    let mut count = 0;
    for (index, packet) in received.enumerate() {
        packets[index] = if packet.flags.contains(MsgFlags::MSG_TRUNC) {
            None
        } else {
            packet.address.map(|peer| (packet.bytes, peer.into()))
        };
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{FromWire, Message};
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[tokio::test]
    async fn batch_slots_preserve_peers_limits_empty_datagrams_and_truncation() {
        for address in ["127.0.0.1:0", "[::1]:0", "127.0.0.1:0"] {
            let socket = UdpSocket::bind(address).await.unwrap();
            let client = UdpSocket::bind(address).await.unwrap();
            for bytes in [b"one".as_slice(), b"two", b"too long for buffer", b""] {
                client
                    .send_to(bytes, socket.local_addr().unwrap())
                    .await
                    .unwrap();
            }
            let mut buffers = vec![vec![0; 8]; 4];
            let mut packets = [None; MAX_BATCH];
            socket.readable().await.unwrap();
            let peer = client.local_addr().unwrap();
            let ipv6 = peer.is_ipv6();
            assert_eq!(
                read_batch(&socket, ipv6, &mut buffers, 2, &mut packets).unwrap(),
                2
            );
            assert_eq!(packets[..2], [Some((3, peer)), Some((3, peer))]);
            assert_eq!(&buffers[0][..3], b"one");
            assert_eq!(&buffers[1][..3], b"two");
            assert_eq!(
                read_batch(&socket, ipv6, &mut buffers, 2, &mut packets).unwrap(),
                2
            );
            assert_eq!(packets[..2], [None, Some((0, peer))]);
            assert_eq!(
                read_batch(&socket, ipv6, &mut buffers, 2, &mut packets)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[tokio::test]
    async fn batch_reserves_only_the_shared_admission_budget() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(address).await.unwrap();
        for id in 0..6 {
            client.send(&query(id)).await.unwrap();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let releases = Arc::new(Semaphore::new(0));
        let handler_calls = Arc::clone(&calls);
        let handler_releases = Arc::clone(&releases);
        let activity = Arc::new(PacketActivity::default());
        let server = tokio::spawn(receive_packets(
            socket,
            Arc::new(move |query: Message| {
                let calls = Arc::clone(&handler_calls);
                let releases = Arc::clone(&handler_releases);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    releases.acquire().await.unwrap().forget();
                    query
                }
            }),
            UdpServerPolicy {
                packet_limit: 2,
                handler_reply_timeout: Duration::from_secs(30),
                response_send_timeout: Duration::from_secs(30),
            },
            Some(Arc::clone(&activity)),
            Arc::new(Semaphore::new(2)),
            MAX_BATCH,
        ));
        activity.wait_for_active(2).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(activity.maximum.load(Ordering::SeqCst), 2);
        releases.add_permits(6);
        let mut ids = BTreeSet::new();
        let mut buffer = [0; 512];
        for _ in 0..6 {
            let length = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            ids.insert(Message::from_wire(&buffer[..length]).unwrap().headers.id);
        }
        assert_eq!(ids, BTreeSet::from([0, 1, 2, 3, 4, 5]));
        activity.wait_for_active(0).await;
        assert_eq!(activity.maximum.load(Ordering::SeqCst), 2);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(start_paused = true)]
    async fn timed_out_batch_handler_releases_capacity_for_the_next_packet() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(socket.local_addr().unwrap()).await.unwrap();
        let activity = Arc::new(PacketActivity::default());
        let timeout = Duration::from_secs(1);
        let server = tokio::spawn(receive_packets(
            socket,
            Arc::new(|query: Message| async move {
                if query.headers.id == 1 {
                    std::future::pending::<()>().await;
                }
                query
            }),
            UdpServerPolicy {
                packet_limit: 1,
                handler_reply_timeout: timeout,
                response_send_timeout: timeout,
            },
            Some(Arc::clone(&activity)),
            Arc::new(Semaphore::new(1)),
            MAX_BATCH,
        ));
        client.send(&query(1)).await.unwrap();
        activity.wait_for_active(1).await;
        client.send(&query(2)).await.unwrap();
        tokio::time::advance(timeout).await;
        let mut buffer = [0; 512];
        let length = tokio::time::timeout(timeout, client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Message::from_wire(&buffer[..length]).unwrap().headers.id, 2);
        activity.wait_for_active(0).await;
        assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);
        server.abort();
        let _ = server.await;
    }

    fn query(id: u16) -> Vec<u8> {
        let mut bytes = vec![0; 12];
        bytes[..2].copy_from_slice(&id.to_be_bytes());
        bytes[2] = 1;
        bytes[5] = 1;
        bytes.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        bytes
    }
}
