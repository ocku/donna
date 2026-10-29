#[cfg(test)]
use std::net::Ipv4Addr;
use std::{net::SocketAddr, time::Duration};

use dns::{FromWire, IntoWire, Message};
use tokio::time;
#[cfg(test)]
use tracing::instrument;

use crate::{
    DnsRequest, DnsRequestHandler, DnsResponse, ImmediateUdpResponse, MAX_UDP_MESSAGE_OCTETS,
    TransportProtocol, authenticated_response_headers_match, has_tsig, normalize_response_headers,
    remove_cleartext_padding, request_questions_are_safe_to_echo, same_questions,
    truncate_response, udp_format_error_response,
};

#[cfg(test)]
use super::HANDLER_REPLY_TIMEOUT;
use super::server::{is_ixfr_request, is_zone_transfer};

#[instrument(level = "debug", skip(handler, packet), fields(packet_length = packet.len()))]
#[cfg(test)]
pub(super) async fn response_for<H>(handler: &H, packet: &[u8]) -> Option<Vec<u8>>
where
    H: DnsRequestHandler,
{
    response_for_peer_with_timeout(
        handler,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        packet.to_vec(),
        HANDLER_REPLY_TIMEOUT,
        None,
    )
    .await
}

#[cfg(test)]
pub(super) async fn response_for_peer<H>(
    handler: &H,
    peer: SocketAddr,
    packet: &[u8],
) -> Option<Vec<u8>>
where
    H: DnsRequestHandler,
{
    response_for_peer_with_timeout(handler, peer, packet.to_vec(), HANDLER_REPLY_TIMEOUT, None)
        .await
}

pub(super) async fn response_for_peer_with_timeout<H>(
    handler: &H,
    peer: SocketAddr,
    packet: Vec<u8>,
    handler_reply_timeout: Duration,
    immediate_handler: Option<(std::any::TypeId, usize)>,
) -> Option<Vec<u8>>
where
    H: DnsRequestHandler,
{
    match response_if_ready(handler, peer, &packet) {
        PacketResponse::Ready(response) => response,
        PacketResponse::Deferred(query) => {
            response_for_query(
                handler,
                peer,
                query,
                packet,
                handler_reply_timeout,
                immediate_handler,
            )
            .await
        }
    }
}

pub(super) enum PacketResponse {
    Ready(Option<Vec<u8>>),
    Deferred(Message),
}

/// Decode once, retaining ownership only when an asynchronous handler needs it.
/// Both response paths use the same validation and encoding below.
pub(super) fn response_if_ready<H>(handler: &H, peer: SocketAddr, packet: &[u8]) -> PacketResponse
where
    H: DnsRequestHandler,
{
    let query = match Message::from_wire(packet) {
        Ok(query) if query.headers.qr => return PacketResponse::Ready(None),
        // Classic UDP requests are limited to 512 bytes without an OPT record.
        Ok(query) if packet.len() > MAX_UDP_MESSAGE_OCTETS && !contains_opt(&query) => {
            return PacketResponse::Ready(None);
        }
        Ok(query) => query,
        Err(_) => return PacketResponse::Ready(udp_format_error_response(packet)),
    };
    let maximum =
        udp_payload_limit(&query).min(usize::from(dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE));
    let response = if is_zone_transfer(&query) {
        let query_edns = query.edns();
        let malformed_edns = query_edns.as_ref().is_err()
            || query_edns
                .as_ref()
                .ok()
                .and_then(|edns| edns.as_ref())
                .is_some_and(|edns| edns.extended_rcode != 0 || edns.validate_options().is_err());
        let unsupported_edns = query_edns
            .as_ref()
            .ok()
            .and_then(|edns| edns.as_ref())
            .is_some_and(|edns| edns.version != dns::Edns::VERSION);
        // UDP cannot perform AXFR. Preserve malformed EDNS and BADVERS precedence.
        Some(ImmediateUdpResponse::Message(if malformed_edns {
            zone_transfer_error(dns::RCode::FormatError, contains_opt(&query))
        } else if unsupported_edns {
            unsupported_edns_version()
        } else {
            zone_transfer_error(
                dns::RCode::NotImplemented,
                query_edns.ok().flatten().is_some(),
            )
        }))
    } else {
        handler.try_handle_udp(&query, packet, peer, maximum)
    };
    match response {
        Some(response) => {
            let response = match response {
                ImmediateUdpResponse::Message(response) => response,
                ImmediateUdpResponse::Encoded(response) => {
                    if !response.matches_request(&query) {
                        return PacketResponse::Ready(None);
                    }
                    if response.as_bytes().len() <= maximum {
                        return PacketResponse::Ready(Some(response.into_bytes()));
                    }
                    match response.into_message() {
                        Ok(response) => response,
                        Err(_) => return PacketResponse::Ready(None),
                    }
                }
            };
            let mut context = ResponseContext::with_maximum(&query, Vec::new(), maximum);
            context.request_questions = query.questions;
            PacketResponse::Ready(finish_response(context, response))
        }
        None => PacketResponse::Deferred(query),
    }
}

fn contains_opt(message: &Message) -> bool {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .any(|record| record.rtype == dns::RecordType::OPT)
}

pub(super) async fn response_for_query<H>(
    handler: &H,
    peer: SocketAddr,
    query: Message,
    wire_query: Vec<u8>,
    handler_reply_timeout: Duration,
    immediate_handler: Option<(std::any::TypeId, usize)>,
) -> Option<Vec<u8>>
where
    H: DnsRequestHandler,
{
    let context = ResponseContext::new(&query, query.questions.clone());
    let (mut request, response) =
        DnsRequest::channel_with_wire(query, wire_query, peer, TransportProtocol::Udp);
    request.immediate_handler = immediate_handler;
    let response = match time::timeout(handler_reply_timeout, async {
        handler.handle(request).await;
        response.await
    })
    .await
    {
        Ok(Ok(DnsResponse::Buffered(responses))) => responses.into_single()?,
        Ok(Ok(DnsResponse::Stream(_))) | Ok(Err(_)) => return None,
        Err(_) => {
            tracing::debug!(%peer, "UDP request handler timed out");
            return None;
        }
    };
    finish_response(context, response)
}

struct ResponseContext {
    is_axfr: bool,
    request_headers: dns::Headers,
    request_questions: Vec<dns::Question>,
    ixfr_request: Option<Message>,
    request_questions_are_safe_to_echo: bool,
    response_maximum: usize,
    contains_opt: bool,
}

impl ResponseContext {
    fn new(query: &Message, request_questions: Vec<dns::Question>) -> Self {
        Self::with_maximum(
            query,
            request_questions,
            udp_payload_limit(query).min(usize::from(dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE)),
        )
    }

    fn with_maximum(
        query: &Message,
        request_questions: Vec<dns::Question>,
        maximum: usize,
    ) -> Self {
        Self {
            is_axfr: is_zone_transfer(query),
            request_headers: query.headers.clone(),
            request_questions,
            ixfr_request: is_ixfr_request(query).then(|| query.clone()),
            request_questions_are_safe_to_echo: request_questions_are_safe_to_echo(
                &query.questions,
            ),
            response_maximum: maximum,
            contains_opt: contains_opt(query),
        }
    }
}

fn finish_response(context: ResponseContext, mut response: Message) -> Option<Vec<u8>> {
    let ResponseContext {
        is_axfr,
        request_headers,
        request_questions,
        ixfr_request,
        request_questions_are_safe_to_echo,
        response_maximum,
        contains_opt,
    } = context;
    if has_tsig(&response) {
        if !authenticated_response_headers_match(&request_headers, &response)
            || (request_headers.opcode == dns::OpCode::Query
                && (!request_questions_are_safe_to_echo
                    || !same_questions(&response.questions, &request_questions)))
            || ixfr_request
                .as_ref()
                .is_some_and(|request| !crate::tcp::valid_ixfr_response(&response, request))
        {
            return None;
        }
        let wire = response.into_wire().ok()?;
        return (wire.len() <= response_maximum).then_some(wire);
    }

    normalize_response_headers(&request_headers, &mut response);
    if is_axfr || request_headers.opcode == dns::OpCode::Query {
        // Standard QUERY responses echo the question (RFC 1035 §4.1.2). AXFR
        // refusals also carry it so a client can associate the transfer error.
        // Treat the section atomically: decoded noncanonical values cannot be
        // re-encoded, and no handler-supplied substitute may replace them.
        if request_questions_are_safe_to_echo {
            response.questions = request_questions;
        } else {
            response.questions.clear();
        }
    }
    remove_cleartext_padding(&mut response);
    if let Some(request) = ixfr_request.as_ref() {
        if !crate::tcp::valid_ixfr_response(&response, request) {
            return None;
        }
        let candidate = truncate_response(response.clone(), response_maximum).ok()?;
        if Message::from_wire(&candidate)
            .ok()
            .is_some_and(|candidate| crate::tcp::valid_ixfr_response(&candidate, request))
        {
            return Some(candidate);
        }
        if response.extended_rcode() != 0 {
            return None;
        }
        // RFC 1995 requires an oversized UDP IXFR response to collapse to the
        // current SOA so the client knows to retry the transfer over TCP.
        response.answers.truncate(1);
        return truncate_response(response, response_maximum).ok();
    }
    let minimal_format_error = (response.headers.rcode == dns::RCode::FormatError).then(|| {
        let additionals = contains_opt
            .then(|| {
                let mut edns = response.edns().ok().flatten().unwrap_or_default();
                edns.options.clear();
                edns.into_record()
            })
            .into_iter()
            .collect();
        Message {
            headers: response.headers.clone(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals,
        }
    });
    match truncate_response(response, response_maximum) {
        Ok(response) => Some(response),
        Err(_) => {
            // An oversized malformed question section cannot be echoed, but
            // RFC 6891 §7 still requires a response OPT for an EDNS request.
            // Retain only its fixed metadata so optional handler payloads
            // cannot prevent delivery of this last-resort FORMERR.
            truncate_response(minimal_format_error?, response_maximum).ok()
        }
    }
}

pub(super) fn udp_payload_limit(message: &Message) -> usize {
    message
        .edns()
        .ok()
        .flatten()
        .map_or(MAX_UDP_MESSAGE_OCTETS, |edns| {
            usize::from(edns.effective_udp_payload_size())
        })
}

/// Refuses a zone transfer received over UDP, as RFC 1035 §4.2.1 forbids
/// running them on a datagram transport.
fn zone_transfer_error(rcode: dns::RCode, include_edns: bool) -> Message {
    Message {
        headers: dns::Headers {
            rcode,
            ..dns::Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: include_edns
            .then(|| dns::Edns::default().into_record())
            .into_iter()
            .collect(),
    }
}

/// Reports EDNS version negotiation before applying UDP's AXFR refusal.
fn unsupported_edns_version() -> Message {
    Message {
        headers: dns::Headers::default(),
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: vec![
            dns::Edns {
                // BADVERS is extended RCODE 16: upper eight bits 1, header bits 0.
                extended_rcode: 1,
                ..dns::Edns::default()
            }
            .into_record(),
        ],
    }
}
