//! DNS message exchange, server listeners, and transport transitions.
//!
//! This crate owns the boundary between semantic [`dns::Message`] values and
//! UDP datagrams, length-prefixed TCP/TLS frames, HTTPS messages, QUIC streams,
//! or DNSCrypt packets. It deliberately does not own resolver retry policy or
//! authoritative answer policy.
//!
//! The main data flows are:
//!
//! 1. A client [`Transport`] encodes a query, performs one exchange, and
//!    accepts only a response correlated with that query.
//! 2. A [`TransportServer`] decodes an inbound request and gives a
//!    [`DnsRequest`] to the application. The request's single-use channel
//!    guarantees that the reply returns on the same transport endpoint.
//! 3. A concrete transport exposes protocol-required transitions through
//!    [`Transport::transition`]. [`TransportRoute`] adds caller-selected
//!    policy transitions without hiding the protocol-required ones.
//!
//! UDP size handling and stream AXFR handling are intentionally stricter than a
//! simple encode/send loop. Responses are truncated only at whole-RRSet
//! boundaries, and AXFR is validated as a series rather than as unrelated DNS
//! messages. Those rules are documented next to the code that enforces them.

#![deny(missing_docs)]

use std::{fmt, net::SocketAddr};

use dns::Message;
use tokio::sync::{mpsc, oneshot};

mod constants;
mod future;
#[cfg(any(feature = "tcp", feature = "doh"))]
mod listener_io;
mod traits;
pub use future::BoxFuture;
pub use traits::{DnsRequestHandler, TransitionReason, Transport, TransportRoute, TransportServer};
#[cfg(any(feature = "tcp", feature = "udp", feature = "doh", test))]
mod message;
#[cfg(all(test, feature = "udp"))]
use message::format_error_response_with_limit;
#[cfg(any(feature = "udp", test))]
use message::matches_query;
#[cfg(test)]
use message::recover_questions_from_edns_request;
#[cfg(any(feature = "tcp", feature = "udp"))]
pub(crate) use message::truncate_response;
#[cfg(feature = "udp")]
use message::udp_format_error_response;
#[cfg(any(feature = "tcp", feature = "udp", feature = "doh"))]
use message::{authenticated_response_headers_match, checked_deadline, has_tsig};
#[cfg(any(feature = "tcp", feature = "udp", test))]
use message::{format_error_response, reject_cleartext_padding, remove_cleartext_padding};
#[cfg(any(feature = "tcp", feature = "udp", feature = "doh", test))]
use message::{normalize_response_headers, request_questions_are_safe_to_echo, same_questions};
#[cfg(feature = "dnscrypt")]
mod dnscrypt;
#[cfg(feature = "doh")]
mod doh;
#[cfg(feature = "doq")]
mod doq;
#[cfg(feature = "tcp")]
mod tcp;
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "udp")]
mod udp;

pub use constants::{MAX_EDNS_UDP_MESSAGE_OCTETS, MAX_TCP_MESSAGE_OCTETS, MAX_UDP_MESSAGE_OCTETS};
#[cfg(feature = "dnscrypt")]
pub use dnscrypt::{
    DNSCRYPT_PORT, DnscryptCertificate, DnscryptClientConfig, DnscryptConfigError,
    DnscryptResolverIdentity, DnscryptServerConfig, DnscryptTransport, DnscryptTransportServer,
    DnscryptUdpTransport, DnscryptUdpTransportServer,
};
#[cfg(feature = "doh")]
pub use doh::{
    DOH_MEDIA_TYPE, DOH_PORT, DohClientConfig, DohConfigError, DohMethod, DohServerConfig,
    DohTransport, DohTransportServer,
};
#[cfg(feature = "doq")]
pub use doq::{
    DOQ_ALPN, DOQ_PORT, DoqClientConfig, DoqConfigError, DoqServerConfig, DoqTransport,
    DoqTransportServer,
};
#[cfg(feature = "tcp")]
pub use tcp::{AxfrLimits, TcpTransport};
#[cfg(feature = "tls")]
pub use tls::{
    DOT_ALPN, DOT_PORT, TlsClientConfig, TlsClientConfigError, TlsServerConfig, TlsTransport,
    TlsTransportServer,
};
#[cfg(feature = "udp")]
pub use udp::UdpTransport;

/// Identifies the wire protocol used by a DNS transport or request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportProtocol {
    /// DNS over UDP.
    Udp,
    /// DNS over TCP.
    Tcp,
    /// DNS over TLS using TCP framing.
    Tls,
    /// DNS over HTTPS using one HTTP exchange per DNS message.
    Https,
    /// DNS over QUIC using one bidirectional stream per transaction.
    Quic,
    /// DNSCrypt v2 over authenticated TCP or UDP.
    Dnscrypt,
}

/// A decoded DNS request together with the state required to reply to it.
///
/// A request is created by a transport listener and owns a single-use reply
/// capability tied to that listener. Calling [`DnsRequest::respond`],
/// [`DnsRequest::respond_all`], or [`DnsRequest::respond_stream`] therefore
/// returns the response through the same protocol and socket or connection from
/// which the request arrived.
pub struct DnsRequest {
    message: Message,
    wire_message: Vec<u8>,
    peer: SocketAddr,
    protocol: TransportProtocol,
    response: oneshot::Sender<DnsResponse>,
    immediate_handler: Option<(std::any::TypeId, usize)>,
}

#[cfg_attr(not(any(feature = "tcp", feature = "doh")), allow(dead_code))]
pub(crate) enum DnsResponse {
    Buffered(BufferedMessages),
    Stream(mpsc::Receiver<Message>),
}

/// A single reply is the common case and needs no separate Vec allocation.
#[cfg_attr(not(any(feature = "tcp", feature = "doh")), allow(dead_code))]
pub(crate) enum BufferedMessages {
    Single(Message),
    Multiple(Vec<Message>),
}

impl BufferedMessages {
    #[cfg(feature = "tcp")]
    fn into_vec(self) -> Vec<Message> {
        match self {
            Self::Single(message) => vec![message],
            Self::Multiple(messages) => messages,
        }
    }

    #[cfg(any(feature = "udp", feature = "doh", feature = "dnscrypt"))]
    fn into_single(self) -> Option<Message> {
        match self {
            Self::Single(message) => Some(message),
            Self::Multiple(mut messages) if messages.len() == 1 => messages.pop(),
            Self::Multiple(_) => None,
        }
    }

    #[cfg(feature = "doh")]
    fn is_single(&self) -> bool {
        match self {
            Self::Single(_) => true,
            Self::Multiple(messages) => messages.len() == 1,
        }
    }
}

impl DnsRequest {
    #[cfg(any(feature = "tcp", feature = "udp", feature = "doh"))]
    fn channel_with_wire(
        message: Message,
        wire_message: Vec<u8>,
        peer: SocketAddr,
        protocol: TransportProtocol,
    ) -> (Self, oneshot::Receiver<DnsResponse>) {
        let (response, receiver) = oneshot::channel();
        (
            Self {
                message,
                wire_message,
                peer,
                protocol,
                response,
                immediate_handler: None,
            },
            receiver,
        )
    }

    /// Returns the decoded DNS request message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Returns the exact DNS wire image received from the remote peer.
    ///
    /// This differs from re-encoding [`Self::message`] when the sender used a
    /// different legal name-compression or letter-case representation. It is
    /// therefore the required input for transaction authentication such as
    /// TSIG.
    pub fn wire_message(&self) -> &[u8] {
        &self.wire_message
    }

    /// Returns the remote address that sent the request.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the protocol on which the request arrived.
    pub fn protocol(&self) -> TransportProtocol {
        self.protocol
    }

    /// Returns whether the listener called [`DnsRequestHandler::try_handle`] on
    /// this same handler instance.
    ///
    /// A deferred handler can use this to avoid repeating cache lookups or
    /// other preparation performed by its immediate implementation.
    /// Forwarding a request to a different handler does not transfer this
    /// preparation claim, even when the handlers have the same concrete type.
    pub fn immediate_handling_attempted_by<H: DnsRequestHandler + 'static>(
        &self,
        handler: &H,
    ) -> bool {
        self.immediate_handler
            == Some((
                std::any::TypeId::of::<H>(),
                std::ptr::from_ref(handler).addr(),
            ))
    }

    /// Replies to this request with one DNS message.
    ///
    /// Returns `false` if the listening connection or task has already gone
    /// away and can no longer accept the response.
    pub fn respond(self, response: Message) -> bool {
        self.response
            .send(DnsResponse::Buffered(BufferedMessages::Single(response)))
            .is_ok()
    }

    /// Replies to this request with a sequence of DNS messages.
    ///
    /// Multiple messages are intended for stream operations such as AXFR.
    /// The accepting transport validates whether the sequence is legal.
    /// Returns `false` if the listening connection or task has already gone
    /// away and can no longer accept the response.
    pub fn respond_all(self, responses: Vec<Message>) -> bool {
        self.response
            .send(DnsResponse::Buffered(BufferedMessages::Multiple(responses)))
            .is_ok()
    }

    /// Replies to this TCP, TLS, or QUIC request with messages from a bounded stream.
    ///
    /// The receiver must come from [`tokio::sync::mpsc::channel`]. The accepting
    /// stream transport validates and writes each message before receiving the next.
    /// Stream responses are intended for operations such as AXFR and are rejected
    /// for requests received over UDP.
    ///
    /// Returns `false` if this is not a TCP/TLS/QUIC request or if the listening
    /// connection or task has already gone away.
    pub fn respond_stream(self, responses: mpsc::Receiver<Message>) -> bool {
        if !matches!(
            self.protocol,
            TransportProtocol::Tcp | TransportProtocol::Tls | TransportProtocol::Quic
        ) {
            return false;
        }
        self.response.send(DnsResponse::Stream(responses)).is_ok()
    }
}

/// An immediate UDP response, either structured or encoded by a checked DNS builder.
pub enum ImmediateUdpResponse {
    /// Uses the ordinary normalization, validation and truncation pipeline.
    Message(Message),
    /// Uses immutable checked bytes when correlated and within the actual limit.
    Encoded(dns::wire::EncodedReply),
}

#[cfg(test)]
mod tests;
/// Reports a DNS exchange or zone transfer failure.
#[derive(Debug)]
pub enum TransportError {
    /// Network I/O failed.
    Io(std::io::Error),
    /// The exchange didn't finish before its deadline.
    Timeout,
    /// The encoded message exceeded the transport limit.
    MessageTooLong {
        /// The encoded message length in octets.
        length: usize,
        /// The transport limit in octets.
        maximum: usize,
    },
    /// The request or response couldn't be encoded.
    Encode(dns::wire::WireError),
    /// A response couldn't be decoded.
    Decode(dns::wire::WireError),
    /// An AXFR query or response violated transfer requirements.
    InvalidTransfer(&'static str),
    /// RFC 7830 Padding was requested on an unencrypted DNS transport.
    InsecureEdnsPadding,
    /// Encrypted DNS padding could not be applied safely.
    Padding(dns::PaddingPolicyError),
    /// TLS negotiated parameters did not identify DNS over TLS.
    InvalidTlsProtocol(&'static str),
    /// An HTTPS request or response violated the DNS-over-HTTPS profile.
    InvalidHttpProtocol(&'static str),
    /// A QUIC connection or stream violated the DNS-over-QUIC profile.
    InvalidQuicProtocol(&'static str),
    /// A DNSCrypt packet, certificate, or exchange violated the protocol.
    InvalidDnscryptProtocol(&'static str),
}

impl TransportError {
    #[cfg(any(feature = "tcp", feature = "udp", feature = "doh"))]
    fn encode(error: dns::wire::WireError) -> Self {
        Self::Encode(error)
    }
    #[cfg(any(feature = "tcp", feature = "doh"))]
    fn decode(error: dns::wire::WireError) -> Self {
        Self::Decode(error)
    }
}
impl From<std::io::Error> for TransportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "DNS transport I/O error: {error}"),
            Self::Timeout => f.write_str("DNS exchange timed out"),
            Self::MessageTooLong { length, maximum } => {
                write!(f, "DNS message is {length} bytes; maximum is {maximum}")
            }
            Self::Encode(error) => write!(f, "cannot encode DNS message: {error}"),
            Self::Decode(error) => write!(f, "cannot decode DNS message: {error}"),
            Self::InvalidTransfer(reason) => write!(f, "invalid AXFR transfer: {reason}"),
            Self::InsecureEdnsPadding => {
                f.write_str("EDNS Padding requires an encrypted DNS transport")
            }
            Self::Padding(error) => write!(f, "cannot pad encrypted DNS message: {error}"),
            Self::InvalidTlsProtocol(reason) => {
                write!(f, "invalid DNS-over-TLS session: {reason}")
            }
            Self::InvalidHttpProtocol(reason) => {
                write!(f, "invalid DNS-over-HTTPS exchange: {reason}")
            }
            Self::InvalidQuicProtocol(reason) => {
                write!(f, "invalid DNS-over-QUIC exchange: {reason}")
            }
            Self::InvalidDnscryptProtocol(reason) => {
                write!(f, "invalid DNSCrypt exchange: {reason}")
            }
        }
    }
}
impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Encode(error) | Self::Decode(error) => Some(error),
            Self::Padding(error) => Some(error),
            Self::Timeout
            | Self::MessageTooLong { .. }
            | Self::InvalidTransfer(_)
            | Self::InsecureEdnsPadding
            | Self::InvalidTlsProtocol(_)
            | Self::InvalidHttpProtocol(_)
            | Self::InvalidQuicProtocol(_)
            | Self::InvalidDnscryptProtocol(_) => None,
        }
    }
}
