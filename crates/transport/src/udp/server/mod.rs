use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use dns::Message;
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore},
    time,
};
use tracing::{Instrument, instrument};

mod activity;
pub(super) use activity::PacketActivity;
#[cfg(target_os = "linux")]
use activity::PacketActivityGuard;

use super::response::response_for_peer_with_timeout;
use super::{RECEIVE_BUFFER_OCTETS, SERVER_POLICY, UdpServerPolicy, UdpTransport};
use crate::{DnsRequestHandler, MAX_EDNS_UDP_MESSAGE_OCTETS, TransportServer};

impl TransportServer for UdpTransport {
    /// Serves RFC 1035 UDP queries. Each datagram is handled independently.
    #[instrument(level = "debug", skip(handler), fields(address = %address))]
    fn serve<'future, H>(
        self,
        address: SocketAddr,
        handler: H,
    ) -> crate::BoxFuture<'future, Result<(), std::io::Error>>
    where
        H: DnsRequestHandler + 'static,
        Self: 'future,
    {
        Box::pin(async move {
            crate::listener_io::require_concrete_udp_address(address)?;
            let socket = UdpSocket::bind(address).await?;
            #[cfg(target_os = "linux")]
            {
                serve_workers(socket, handler).await
            }
            #[cfg(not(target_os = "linux"))]
            serve_socket(socket, handler).await
        })
    }
}

/// Each Linux worker registers its own descriptor for the same bound socket.
/// Keeping the kernel socket exclusive prevents independent reuse-port
/// listeners from joining the service, while workers share its receive queue.
#[cfg(target_os = "linux")]
pub(super) async fn serve_workers<H>(socket: UdpSocket, handler: H) -> Result<(), io::Error>
where
    H: DnsRequestHandler + 'static,
{
    let worker_count = tokio::runtime::Handle::current()
        .metrics()
        .num_workers()
        .clamp(1, 64);
    let mut sockets = vec![socket];
    for _ in 1..worker_count {
        let socket = socket2::SockRef::from(&sockets[0]).try_clone()?;
        sockets.push(UdpSocket::from_std(socket.into())?);
    }
    let handler = Arc::new(handler);
    let permits = Arc::new(Semaphore::new(SERVER_POLICY.packet_limit));
    let mut workers = tokio::task::JoinSet::new();
    for socket in sockets {
        workers.spawn(super::batch::receive_packets(
            socket,
            Arc::clone(&handler),
            SERVER_POLICY,
            None,
            Arc::clone(&permits),
            (64 / worker_count).clamp(1, 16),
        ));
    }
    match workers.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(error)) => Err(io::Error::other(error)),
        None => unreachable!("UDP service always has at least one worker"),
    }
}

#[cfg(any(not(target_os = "linux"), test))]
pub(super) async fn serve_socket<H>(socket: UdpSocket, handler: H) -> Result<(), io::Error>
where
    H: DnsRequestHandler + 'static,
{
    serve_socket_with_policy(socket, handler, SERVER_POLICY, None).await
}

/// Test seam for small deterministic admission limits and deadlines. One
/// bounded packet is received before admission, so at most one datagram waits
/// in userspace while the semaphore is exhausted; further overflow remains in
/// the kernel socket queue.
#[cfg(any(not(target_os = "linux"), test))]
pub(super) async fn serve_socket_with_policy<H>(
    socket: UdpSocket,
    handler: H,
    policy: UdpServerPolicy,
    activity: Option<Arc<PacketActivity>>,
) -> Result<(), io::Error>
where
    H: DnsRequestHandler + 'static,
{
    if policy.packet_limit == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP packet limit must be non-zero",
        ));
    }

    let permits = Arc::new(Semaphore::new(policy.packet_limit));
    receive_packets(socket, Arc::new(handler), policy, activity, permits, false).await
}

pub(super) async fn receive_packets<H>(
    socket: UdpSocket,
    handler: Arc<H>,
    policy: UdpServerPolicy,
    activity: Option<Arc<PacketActivity>>,
    permits: Arc<Semaphore>,
    admit_before_receive: bool,
) -> Result<(), io::Error>
where
    H: DnsRequestHandler + 'static,
{
    let socket = Arc::new(socket);
    let mut buffer = vec![0_u8; RECEIVE_BUFFER_OCTETS];
    loop {
        // Worker-local receive buffers consume the shared budget before
        // receiving; adding workers cannot multiply queued userspace packets.
        let reserved = if admit_before_receive {
            Some(acquire_packet_permit(&permits).await?)
        } else {
            None
        };
        let (length, peer) = crate::listener_io::recv_from(&socket, &mut buffer).await?;
        if length > MAX_EDNS_UDP_MESSAGE_OCTETS {
            continue;
        }
        let packet = buffer[..length].to_vec();
        if let Some(activity) = &activity {
            activity.record_received();
        }
        if permits.available_permits() == 0 {
            tracing::debug!(
                packet_limit = policy.packet_limit,
                "UDP packet limit reached; pausing receives after one buffered packet"
            );
        }
        let permit = match reserved {
            Some(permit) => permit,
            None => acquire_packet_permit(&permits).await?,
        };
        dispatch_packet(
            Arc::clone(&socket),
            peer,
            Arc::clone(&handler),
            packet,
            policy,
            permit,
            activity.clone(),
        )
        .await;
    }
}

pub(super) async fn acquire_packet_permit(
    permits: &Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, io::Error> {
    Arc::clone(permits)
        .acquire_owned()
        .await
        .map_err(|_| io::Error::other("UDP packet admission semaphore unexpectedly closed"))
}

/// RFC 1035 §4.2.1: "UDP is not acceptable for zone transfers."
pub(super) fn is_zone_transfer(query: &Message) -> bool {
    query
        .questions
        .iter()
        .any(|question| question.qtype == dns::QueryType::AXFR)
}

pub(super) fn is_ixfr_request(query: &Message) -> bool {
    matches!(
        query.questions.as_slice(),
        [question] if question.qtype == dns::QueryType::IXFR
    )
}

pub(super) fn unspecified_address_for(server: SocketAddr) -> SocketAddr {
    match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

pub(super) async fn dispatch_packet<H>(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    handler: Arc<H>,
    packet: Vec<u8>,
    policy: UdpServerPolicy,
    permit: OwnedSemaphorePermit,
    activity: Option<Arc<PacketActivity>>,
) where
    H: DnsRequestHandler + 'static,
{
    let span = tracing::debug_span!("udp_packet", %peer, packet_length = packet.len());
    let mut processing = Box::pin(
        async move {
            let _activity = activity.map(PacketActivity::start);
            // Declared after the observer so the admission permit is released
            // before tests observe that packet processing has ended.
            let _permit = permit;
            serve_packet(socket, peer, handler, packet, policy).await;
        }
        .instrument(span),
    );
    // Warm cache replies commonly finish without yielding. Give them one
    // poll on the receiving task, avoiding a scheduler handoff for each packet.
    // Pending handlers (including detached responses), backpressured sends,
    // and exhausted Tokio cooperation budgets still run independently. The
    // same future retains admission, deadlines, and all response validation.
    let polled = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || processing.as_mut().poll(cx),
        )))
    })
    .await;
    if matches!(polled, Ok(std::task::Poll::Pending)) {
        tokio::spawn(processing);
    } else if polled.is_err() {
        // A handler panic used to terminate only its packet task. Preserve
        // that isolation when processing a ready reply on the receive task.
        tracing::error!(%peer, "UDP packet handler panicked");
    }
}

#[cfg(target_os = "linux")]
pub(super) struct PreparedPacket {
    pub(super) wire: Vec<u8>,
    pub(super) peer: SocketAddr,
    pub(super) deadline: time::Instant,
    _guards: PacketGuards,
}

#[cfg(target_os = "linux")]
struct PacketGuards {
    // Field drop order preserves permit release before observer notification.
    _permit: OwnedSemaphorePermit,
    _activity: Option<PacketActivityGuard>,
}

#[cfg(target_os = "linux")]
impl PreparedPacket {
    pub(super) async fn send(self, socket: &UdpSocket) {
        if self.deadline <= time::Instant::now() {
            return;
        }
        match time::timeout_at(self.deadline, socket.send_to(&self.wire, self.peer)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::debug!(peer = %self.peer, ?error, "UDP response send failed")
            }
            Err(error) => tracing::debug!(peer = %self.peer, ?error, "UDP response send timed out"),
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(
        wire: Vec<u8>,
        peer: SocketAddr,
        deadline: time::Instant,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            wire,
            peer,
            deadline,
            _guards: PacketGuards {
                _permit: permit,
                _activity: None,
            },
        }
    }
}

/// Performs the same handler and wire validation as direct dispatch. A ready
/// reply can join the current receive batch; pending handlers keep their own
/// independent task and deadlines.
#[cfg(target_os = "linux")]
pub(super) async fn prepare_packet<H>(
    socket: &Arc<UdpSocket>,
    peer: SocketAddr,
    handler: Arc<H>,
    packet: &[u8],
    policy: UdpServerPolicy,
    permit: OwnedSemaphorePermit,
    activity: Option<Arc<PacketActivity>>,
) -> Option<PreparedPacket>
where
    H: DnsRequestHandler + 'static,
{
    let span = tracing::debug_span!("udp_packet", %peer, packet_length = packet.len());
    let guards = PacketGuards {
        _permit: permit,
        _activity: activity.map(PacketActivity::start),
    };
    // Cached replies borrow the receive buffer and need neither an owned wire
    // copy nor a pinned processing future. Keep panic isolation around decoding,
    // the immediate handler, validation, and encoding just as on the async path.
    let started = time::Instant::now();
    let ready = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        span.in_scope(|| super::response::response_if_ready(handler.as_ref(), peer, packet))
    }));
    let query = match ready {
        Ok(super::response::PacketResponse::Ready(wire)) => {
            if started.elapsed() >= policy.handler_reply_timeout {
                return None;
            }
            return Some(PreparedPacket {
                wire: wire?,
                peer,
                deadline: time::Instant::now().checked_add(policy.response_send_timeout)?,
                _guards: guards,
            });
        }
        Ok(super::response::PacketResponse::Deferred(query)) => query,
        Err(_) => {
            tracing::error!(%peer, "UDP packet handler panicked");
            return None;
        }
    };
    let packet = packet.to_vec();
    let mut processing = Box::pin(
        async move {
            let wire = super::response::response_for_query(
                handler.as_ref(),
                peer,
                query,
                packet,
                policy.handler_reply_timeout,
                Some((
                    std::any::TypeId::of::<H>(),
                    std::ptr::from_ref(handler.as_ref()).addr(),
                )),
            )
            .await?;
            let deadline = time::Instant::now().checked_add(policy.response_send_timeout)?;
            Some(PreparedPacket {
                wire,
                peer,
                deadline,
                _guards: guards,
            })
        }
        .instrument(span),
    );
    let polled = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || processing.as_mut().poll(cx),
        )))
    })
    .await;
    match polled {
        Ok(std::task::Poll::Ready(reply)) => reply,
        Ok(std::task::Poll::Pending) => {
            let socket = Arc::clone(socket);
            tokio::spawn(async move {
                if let Some(reply) = processing.await {
                    reply.send(&socket).await;
                }
            });
            None
        }
        Err(_) => {
            tracing::error!(%peer, "UDP packet handler panicked");
            None
        }
    }
}

#[instrument(
    level = "debug",
    skip(socket, handler, packet, policy),
    fields(%peer, packet_length = packet.len())
)]
async fn serve_packet<H>(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    handler: Arc<H>,
    packet: Vec<u8>,
    policy: UdpServerPolicy,
) where
    H: DnsRequestHandler + 'static,
{
    let Some(response) = response_for_peer_with_timeout(
        handler.as_ref(),
        peer,
        packet,
        policy.handler_reply_timeout,
        Some((
            std::any::TypeId::of::<H>(),
            std::ptr::from_ref(handler.as_ref()).addr(),
        )),
    )
    .await
    else {
        return;
    };
    if let Err(error) = send_datagram_with_timeout(
        socket.send_to(&response, peer),
        policy.response_send_timeout,
    )
    .await
    {
        if error.kind() == io::ErrorKind::TimedOut {
            tracing::debug!(%peer, "UDP response send timed out");
        } else {
            tracing::debug!(%peer, ?error, "UDP response send failed");
        }
    }
}

pub(super) async fn send_datagram_with_timeout<F>(
    send: F,
    timeout: Duration,
) -> Result<usize, io::Error>
where
    F: Future<Output = Result<usize, io::Error>>,
{
    time::timeout(timeout, send)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "sending DNS-over-UDP response"))?
}
