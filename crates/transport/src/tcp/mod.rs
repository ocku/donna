//! DNS over TCP framing, exchanges, and server connections.
//!
//! Ordinary DNS messages are independent two-octet-length-prefixed frames.
//! AXFR uses the same framing but is handled as a validated response series in
//! [`axfr`], because its invariants span frame boundaries.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use dns::{FromWire, IntoWire, Message};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time,
};
use tracing::{Instrument, instrument};

#[cfg(feature = "tls")]
use tokio::sync::mpsc;

pub(crate) mod axfr;
mod client;
mod framing;
mod ixfr;
pub(crate) use ixfr::TransferSeriesValidator;
mod response;
mod server;
#[cfg(feature = "tls")]
mod tls_connection;

use crate::{
    DnsRequest, DnsRequestHandler, DnsResponse, MAX_TCP_MESSAGE_OCTETS, Transport, TransportError,
    TransportProtocol, TransportServer, authenticated_response_headers_match, checked_deadline,
    format_error_response, has_tsig, normalize_response_headers, reject_cleartext_padding,
    remove_cleartext_padding, request_questions_are_safe_to_echo, same_questions,
    truncate_response,
};
pub use axfr::AxfrLimits;
use axfr::AxfrSeriesValidator;
#[cfg(test)]
use axfr::valid_axfr_response_series;
pub use client::TcpTransport;
#[cfg(any(feature = "tls", feature = "doq", feature = "dnscrypt", test))]
pub(crate) use client::matches_tcp_query;
#[cfg(test)]
use framing::frame_packet;
pub(crate) use framing::{read_frame, write_frame};
use framing::{read_frame_with_timeout, write_frame_with_timeout};
#[cfg(test)]
use response::responses_for;
#[cfg(any(feature = "udp", test))]
pub(crate) use response::valid_ixfr_response;
use response::{is_axfr_request, is_ixfr_request};
pub(crate) use response::{
    prepare_axfr_response, prepare_axfr_responses, prepare_ixfr_response,
    prepare_standard_response_for,
};
use server::*;
#[cfg(feature = "tls")]
pub(crate) use tls_connection::serve_tls_connection;

/// Bounds live accepted TCP connections and therefore attacker-controlled
/// frame allocations. At most approximately
/// `MAX_CONCURRENT_CONNECTIONS * MAX_TCP_MESSAGE_OCTETS` payload octets can be
/// retained by incomplete frames, plus task, socket, and framing overhead.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;
/// RFC 7766 leaves the non-zero per-frame idle period to implementations.
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Bounds application handler execution and its single-use reply wait.
const HANDLER_REPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounds distinct RRSets retained while validating one server-side AXFR series.
/// One million is generous for ordinary zones while remaining finite for custom
/// streaming handlers that never send a closing SOA.
const MAX_AXFR_VALIDATION_RRSETS: usize = 1_000_000;
/// Bounds each response frame write independently, including AXFR frames.
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounds pipelined requests retained by one TLS connection. This permits
/// concurrent DoT and AXoT work without allowing one peer to create an
/// unbounded number of handler tasks.
#[cfg(feature = "tls")]
const MAX_CONCURRENT_TLS_REQUESTS: usize = 16;
#[cfg(feature = "tls")]
const TLS_RESPONSE_QUEUE_CAPACITY: usize = 16;

#[derive(Clone, Copy)]
struct TcpServerPolicy {
    connection_limit: usize,
    frame_read_timeout: Duration,
    handler_reply_timeout: Duration,
    max_axfr_validation_rrsets: usize,
    response_write_timeout: Duration,
}

const SERVER_POLICY: TcpServerPolicy = TcpServerPolicy {
    connection_limit: MAX_CONCURRENT_CONNECTIONS,
    frame_read_timeout: FRAME_READ_TIMEOUT,
    handler_reply_timeout: HANDLER_REPLY_TIMEOUT,
    max_axfr_validation_rrsets: MAX_AXFR_VALIDATION_RRSETS,
    response_write_timeout: RESPONSE_WRITE_TIMEOUT,
};

#[cfg(test)]
mod tests;
