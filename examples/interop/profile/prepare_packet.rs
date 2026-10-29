//! Private actual serving-path component wrappers, copied into the frozen crate.
use crate::DnsRequestHandler;
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::Semaphore};

/// Reusable reply storage preserving the current batch's guard retention.
#[derive(Default)]
pub struct UdpPrepareProfileBatch {
    replies: Vec<super::server::PreparedPacket>,
}

/// Calls the unchanged synchronous transport decode/policy/handler/encoder.
pub fn udp_profile_response<H: DnsRequestHandler>(
    handler: &H,
    peer: SocketAddr,
    packet: &[u8],
) -> Vec<u8> {
    match super::response::response_if_ready(handler, peer, packet) {
        super::response::PacketResponse::Ready(Some(wire)) => wire,
        _ => panic!("component fixture must have an immediate reply"),
    }
}

/// Prepares sixteen packets using the current admission, guard and clock path.
/// Kernel I/O and send-dispatch are excluded. The first guard drops immediately;
/// later guards and buffers remain retained until the complete batch is ready.
pub async fn udp_profile_prepare<H: DnsRequestHandler + 'static>(
    socket: &Arc<UdpSocket>,
    handler: &Arc<H>,
    peer: SocketAddr,
    packet: &[u8],
    permits: &Arc<Semaphore>,
    storage: &mut UdpPrepareProfileBatch,
    expected: &[u8],
    verify: bool,
) -> usize {
    let mut reserved = super::server::acquire_packet_permit(permits).await.unwrap();
    let extra_count = permits.available_permits().min(15);
    if extra_count > 0
        && let Ok(extra) = Arc::clone(permits).try_acquire_many_owned(extra_count as u32)
    {
        reserved.merge(extra);
    }
    assert_eq!(reserved.num_permits(), 16);
    let mut checksum = 0;
    for index in 0..16 {
        let permit = reserved.split(1).unwrap();
        let reply = super::server::prepare_packet(
            socket,
            peer,
            /* profile handler */ Arc::clone(handler),
            packet,
            super::SERVER_POLICY,
            permit,
            None,
        )
        .await
        .expect("component fixture must have a prepared reply");
        if verify {
            assert_eq!(reply.wire, expected);
        }
        checksum += reply.wire.len();
        if index != 0 {
            storage.replies.push(reply);
        }
    }
    drop(reserved);
    storage.replies.clear();
    checksum
}
