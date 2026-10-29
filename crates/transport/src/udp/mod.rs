//! DNS over UDP datagram exchange and serving.
//!
//! Each query gets a fresh connected socket. Connecting does not create a UDP
//! session; it asks the kernel to accept datagrams only from the selected DNS
//! server, which provides source-address correlation before DNS-level matching.

use std::{net::SocketAddr, time::Duration};

use dns::{FromWire, IntoWire, Message};
use tokio::{net::UdpSocket, time};
use tracing::instrument;

use crate::{
    MAX_EDNS_UDP_MESSAGE_OCTETS, MAX_UDP_MESSAGE_OCTETS, TransitionReason, Transport,
    TransportError, TransportProtocol, checked_deadline, constants::MAX_EDNS_UDP_QUERY_OCTETS,
    matches_query, reject_cleartext_padding,
};
#[cfg(target_os = "linux")]
mod batch;
mod response;
#[cfg(target_os = "linux")]
mod send;
mod server;
use response::udp_payload_limit;
#[cfg(test)]
use response::{response_for, response_for_peer};
#[cfg(test)]
use server::{PacketActivity, send_datagram_with_timeout, serve_socket, serve_socket_with_policy};
use server::{is_zone_transfer, unspecified_address_for};

static TCP_FALLBACK: crate::TcpTransport = crate::TcpTransport;

/// Includes one sentinel octet used only to detect oversized datagrams.
const RECEIVE_BUFFER_OCTETS: usize = MAX_EDNS_UDP_MESSAGE_OCTETS + 1;
/// Bounds packet tasks and therefore remotely induced userspace retention.
/// At most approximately `MAX_CONCURRENT_PACKETS * RECEIVE_BUFFER_OCTETS`
/// packet octets are retained by admitted tasks, plus one packet waiting for
/// admission and decoded messages, task, channel, and socket overhead.
const MAX_CONCURRENT_PACKETS: usize = 256;
/// Bounds application handler execution and its single-use reply wait.
const HANDLER_REPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounds the send operation while an admitted packet still owns its permit.
const RESPONSE_SEND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct UdpServerPolicy {
    packet_limit: usize,
    handler_reply_timeout: Duration,
    response_send_timeout: Duration,
}

const SERVER_POLICY: UdpServerPolicy = UdpServerPolicy {
    packet_limit: MAX_CONCURRENT_PACKETS,
    handler_reply_timeout: HANDLER_REPLY_TIMEOUT,
    response_send_timeout: RESPONSE_SEND_TIMEOUT,
};

/// Exchanges and serves DNS messages over UDP.
#[derive(Debug, Default, Clone, Copy)]
pub struct UdpTransport;

impl Transport for UdpTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }

    #[instrument(
        level = "debug",
        skip(query),
        fields(server = %server, transaction_id = query.headers.id, timeout = ?timeout)
    )]
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> crate::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            // A single deadline bounds the complete operation. Giving bind,
            // connect, send, and receive separate timeouts would let one exchange
            // consume several times the caller's requested duration.
            let deadline = checked_deadline(timeout)?;
            let request = encode_udp_query(query)?;
            let socket = connect_socket(server, deadline).await?;
            time::timeout_at(deadline, socket.send(&request))
                .await
                .map_err(|_| TransportError::Timeout)??;
            receive_matching_response(&socket, query, deadline).await
        })
    }

    fn transition(&self, reason: TransitionReason) -> Option<&dyn Transport> {
        match reason {
            // RFC 1035 section 4.2.1 and RFC 7766 sections 4-5 require TCP
            // support when a message cannot be carried intact over UDP.
            TransitionReason::QueryTooLarge | TransitionReason::TruncatedResponse => {
                Some(&TCP_FALLBACK)
            }
            TransitionReason::Timeout | TransitionReason::IoError => None,
        }
    }
}

fn encode_udp_query(query: &Message) -> Result<Vec<u8>, TransportError> {
    reject_cleartext_padding(query)?;
    // RFC 1035 §4.2.1: "UDP is not acceptable for zone transfers."
    if is_zone_transfer(query) {
        return Err(TransportError::InvalidTransfer(
            "zone transfers are not permitted over UDP",
        ));
    }

    let request = query.into_wire().map_err(TransportError::encode)?;
    let maximum = if query.edns().ok().flatten().is_some() {
        MAX_EDNS_UDP_QUERY_OCTETS
    } else {
        MAX_UDP_MESSAGE_OCTETS
    };
    if request.len() > maximum {
        return Err(TransportError::MessageTooLong {
            length: request.len(),
            maximum,
        });
    }
    Ok(request)
}

async fn connect_socket(
    server: SocketAddr,
    deadline: time::Instant,
) -> Result<UdpSocket, TransportError> {
    let socket = time::timeout_at(deadline, UdpSocket::bind(unspecified_address_for(server)))
        .await
        .map_err(|_| TransportError::Timeout)??;
    time::timeout_at(deadline, socket.connect(server))
        .await
        .map_err(|_| TransportError::Timeout)??;
    Ok(socket)
}

async fn receive_matching_response(
    socket: &UdpSocket,
    query: &Message,
    deadline: time::Instant,
) -> Result<Message, TransportError> {
    // One extra octet distinguishes a legal 512-octet packet from a larger
    // datagram truncated by the socket receive operation.
    let maximum = udp_payload_limit(query);
    let mut buffer = vec![0_u8; maximum.saturating_add(1)];
    loop {
        // A connected UDP socket admits datagrams only from the exact server
        // address and port selected for this query.
        let length = time::timeout_at(deadline, socket.recv(&mut buffer))
            .await
            .map_err(|_| TransportError::Timeout)??;
        if length > maximum {
            continue;
        }
        // RFC 2181 section 9: a correlated TC reply requests TCP even when
        // its partial record sections cannot be decoded as a complete message.
        if buffer[..length]
            .get(2)
            .is_some_and(|flags| flags & 0x02 != 0)
            && let Ok(reply) = Message::truncated_response_from_wire(&buffer[..length])
            && matches_query(&reply, query)
        {
            return Ok(reply);
        }
        let Ok(reply) = Message::from_wire(&buffer[..length]) else {
            continue;
        };
        if matches_query(&reply, query) {
            return Ok(reply);
        }
    }
}

#[cfg(test)]
mod tests;
