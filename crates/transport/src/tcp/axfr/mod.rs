//! AXFR client assembly and server-side response-series validation.
//!
//! AXFR is stateful across TCP frames: the first answer must be the zone's
//! SOA, the last answer must be the same SOA, and records between them must
//! remain inside the requested zone and class. This module keeps that state
//! explicit instead of treating each response message independently.

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use dns::{FromWire, IntoWire, Message};
use tokio::{io::AsyncRead, net::TcpStream, time};

use super::{TcpTransport, read_frame, write_frame};
use crate::{TransportError, checked_deadline, reject_cleartext_padding};

mod records;

pub(super) use records::RrsetKey;
use records::add_transfer_record;

const DNS_FLAGS_HIGH_OCTET: usize = 2;
const DNS_FLAGS_LOW_OCTET: usize = 3;
const TRUNCATED_RESPONSE: u8 = 0b0000_0010;
const AXFR_MBZ_BITS: u8 = 0b0111_0000;
const DEFAULT_MAX_AXFR_WIRE_BYTES: usize = 512 * 1024 * 1024;
const DEFAULT_MAX_AXFR_RECORDS: usize = 5_000_000;

/// Bounds the resources accepted while receiving one AXFR transfer.
///
/// Wire bytes count DNS message payload octets and exclude each TCP frame's
/// two-octet length prefix. Record limits count every validated answer record,
/// including duplicates and the opening and closing SOA records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AxfrLimits {
    max_wire_bytes: usize,
    max_records: usize,
}

impl AxfrLimits {
    /// Creates limits for cumulative DNS payload bytes and observed answer records.
    pub const fn new(max_wire_bytes: usize, max_records: usize) -> Self {
        Self {
            max_wire_bytes,
            max_records,
        }
    }

    /// Returns the maximum cumulative DNS payload bytes.
    pub const fn max_wire_bytes(self) -> usize {
        self.max_wire_bytes
    }

    /// Returns the maximum number of observed answer records.
    pub const fn max_records(self) -> usize {
        self.max_records
    }
}

impl Default for AxfrLimits {
    /// Uses finite defaults of 512 MiB and 5,000,000 observed records.
    fn default() -> Self {
        Self::new(DEFAULT_MAX_AXFR_WIRE_BYTES, DEFAULT_MAX_AXFR_RECORDS)
    }
}

impl TcpTransport {
    /// Transfers a zone over one TCP connection.
    ///
    /// The returned records include the opening and closing SOA records.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the query isn't a valid AXFR request,
    /// requests EDNS Padding over cleartext TCP, the exchange times out,
    /// network I/O fails, or the server sends an invalid transfer.
    pub async fn transfer(
        &self,
        server: SocketAddr,
        query: &Message,
        timeout: Duration,
    ) -> Result<Vec<dns::ResourceRecord>, TransportError> {
        self.transfer_with_limits(server, query, timeout, AxfrLimits::default())
            .await
    }

    /// Transfers a zone over one TCP connection with explicit resource limits.
    ///
    /// The returned records include the opening and closing SOA records.
    /// Cumulative wire bytes are charged before decoding each response, and every
    /// validated answer record is charged before insertion or duplicate removal.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] for the same conditions as [`Self::transfer`],
    /// or when either resource limit is exceeded.
    pub async fn transfer_with_limits(
        &self,
        server: SocketAddr,
        query: &Message,
        timeout: Duration,
        limits: AxfrLimits,
    ) -> Result<Vec<dns::ResourceRecord>, TransportError> {
        let request = prepare_transfer_request(query)?;
        let deadline = checked_deadline(timeout)?;
        let mut stream = time::timeout_at(deadline, TcpStream::connect(server))
            .await
            .map_err(|_| TransportError::Timeout)??;
        time::timeout_at(deadline, write_frame(&mut stream, &request))
            .await
            .map_err(|_| TransportError::Timeout)??;

        receive_transfer(&mut stream, query, deadline, limits).await
    }
}

pub(crate) async fn receive_transfer<S>(
    stream: &mut S,
    query: &Message,
    deadline: time::Instant,
    limits: AxfrLimits,
) -> Result<Vec<dns::ResourceRecord>, TransportError>
where
    S: AsyncRead + Unpin,
{
    receive_transfer_checked(stream, query, deadline, limits, |_| Ok(())).await
}

pub(crate) async fn receive_transfer_checked<S>(
    stream: &mut S,
    query: &Message,
    deadline: time::Instant,
    limits: AxfrLimits,
    validate: impl Fn(&Message) -> Result<(), TransportError>,
) -> Result<Vec<dns::ResourceRecord>, TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut transfer = TransferReceiver::default();
    let mut first_message = true;
    let mut wire_bytes = 0_usize;
    let mut observed_records = 0_usize;
    loop {
        let mut packet = time::timeout_at(deadline, read_frame(&mut *stream))
            .await
            .map_err(|_| TransportError::Timeout)??;
        wire_bytes = wire_bytes
            .checked_add(packet.len())
            .filter(|&bytes| bytes <= limits.max_wire_bytes)
            .ok_or(TransportError::InvalidTransfer(
                "AXFR wire-byte limit exceeded",
            ))?;
        clear_ignored_axfr_flags(&mut packet);
        let response = Message::from_wire(&packet).map_err(TransportError::decode)?;
        validate(&response)?;
        validate_transfer_message(&response, query, first_message)?;
        first_message = false;
        let answer_count = response.answers.len();
        for (record_index, record) in response.answers.into_iter().enumerate() {
            validate_transfer_record(&record, &query.questions[0])?;
            observed_records = observed_records
                .checked_add(1)
                .filter(|&records| records <= limits.max_records)
                .ok_or(TransportError::InvalidTransfer(
                    "AXFR record limit exceeded",
                ))?;
            let is_last_answer = record_index + 1 == answer_count;
            if transfer.accept(record, &query.questions[0], is_last_answer)? {
                return Ok(transfer.finish());
            }
        }
    }
}

/// Clears flags that RFC 5936 §2.2.1 tells an AXFR client to ignore.
///
/// The general DNS decoder correctly validates these bits for ordinary DNS.
/// Sanitizing the wire bytes only on this AXFR path keeps the exception local.
fn clear_ignored_axfr_flags(packet: &mut [u8]) {
    if let Some(flags) = packet.get_mut(DNS_FLAGS_HIGH_OCTET) {
        *flags &= !TRUNCATED_RESPONSE;
    }
    if let Some(flags) = packet.get_mut(DNS_FLAGS_LOW_OCTET) {
        *flags &= !AXFR_MBZ_BITS;
    }
}

#[derive(Default)]
struct TransferReceiver {
    records: Vec<dns::ResourceRecord>,
    rrsets: HashMap<RrsetKey, records::TransferRrset>,
    opening_soa: Option<dns::ResourceRecord>,
}

impl TransferReceiver {
    /// Adds one validated answer and returns whether it closes the transfer.
    fn accept(
        &mut self,
        record: dns::ResourceRecord,
        question: &dns::Question,
        is_last_answer: bool,
    ) -> Result<bool, TransportError> {
        let is_apex_soa =
            record.rtype == dns::RecordType::SOA && record.name.eq_dns(&question.qname);

        if !is_apex_soa {
            if self.opening_soa.is_none() {
                return Err(TransportError::InvalidTransfer(
                    "first record is not the zone SOA",
                ));
            }
            add_transfer_record(&mut self.records, &mut self.rrsets, record, false);
            return Ok(false);
        }

        let Some(opening) = &self.opening_soa else {
            self.opening_soa = Some(record.clone());
            add_transfer_record(&mut self.records, &mut self.rrsets, record, false);
            return Ok(false);
        };

        if !is_last_answer {
            return Err(TransportError::InvalidTransfer(
                "closing SOA is not the final answer record",
            ));
        }
        if !same_rr_ignoring_ttl(opening, &record) {
            return Err(TransportError::InvalidTransfer(
                "closing SOA does not match opening SOA",
            ));
        }

        // The closing SOA intentionally duplicates the opening SOA. All other
        // duplicate records are collapsed by `add_transfer_record`.
        add_transfer_record(&mut self.records, &mut self.rrsets, record, true);
        Ok(true)
    }

    fn finish(self) -> Vec<dns::ResourceRecord> {
        self.records
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(super) use tests::valid_axfr_response_series;

mod validator;
#[cfg(test)]
pub(super) use validator::AxfrFrameStatus;
pub(crate) use validator::AxfrSeriesValidator;
use validator::same_rr_ignoring_ttl;
pub(super) use validator::{same_resource_record, validate_transfer_record};

/// Completes every deterministic AXFR request check before socket I/O.
pub(super) fn prepare_transfer_request(query: &Message) -> Result<Vec<u8>, TransportError> {
    prepare_transfer_request_for(query, false)
}

pub(crate) fn prepare_transfer_request_for(
    query: &Message,
    encrypted: bool,
) -> Result<Vec<u8>, TransportError> {
    validate_transfer_query(query)?;
    if !encrypted {
        reject_cleartext_padding(query)?;
    }
    // `into_wire` rejects messages larger than the two-octet TCP frame length
    // can express (RFC 1035 §4.2.2).
    query.into_wire().map_err(TransportError::encode)
}

fn validate_transfer_query(query: &Message) -> Result<(), TransportError> {
    if query.headers.qr {
        return Err(TransportError::InvalidTransfer(
            "AXFR request is marked as a response",
        ));
    }
    if query.headers.opcode != dns::OpCode::Query || query.headers.rcode != dns::RCode::Ok {
        return Err(TransportError::InvalidTransfer(
            "AXFR request has invalid header fields",
        ));
    }
    if !matches!(
        query.questions.as_slice(),
        [question]
            if question.qtype == dns::QueryType::AXFR
                && !matches!(question.qclass, dns::QClassType::ANY)
    ) {
        return Err(TransportError::InvalidTransfer(
            "AXFR request must contain one concrete-class AXFR question",
        ));
    }
    if !query.answers.is_empty() || !query.authorities.is_empty() {
        return Err(TransportError::InvalidTransfer(
            "AXFR request contains answer or authority records",
        ));
    }
    Ok(())
}

/// Validates all EDNS metadata before assembling its extended response code.
///
/// `Message::extended_rcode` deliberately falls back to the header nibble for
/// malformed OPT placement, cardinality, or fixed fields. That behavior is
/// useful to general callers, but an AXFR client must reject such a response
/// instead of allowing an upper RCODE to disappear and look like NOERROR.
pub(super) fn validated_extended_rcode(response: &Message) -> Result<u16, TransportError> {
    let edns = response
        .edns()
        .map_err(|_| TransportError::InvalidTransfer("AXFR response contains malformed EDNS"))?;
    let upper = match edns {
        Some(edns) => {
            edns.validate_options().map_err(|_| {
                TransportError::InvalidTransfer("AXFR response contains malformed EDNS")
            })?;
            u16::from(edns.extended_rcode)
        }
        None => 0,
    };
    Ok((upper << 4) | u16::from(u8::from(response.headers.rcode)))
}

pub(super) fn validate_transfer_message(
    response: &Message,
    query: &Message,
    first_message: bool,
) -> Result<(), TransportError> {
    if !response.headers.qr
        || response.headers.id != query.headers.id
        || response.headers.opcode != query.headers.opcode
    {
        return Err(TransportError::InvalidTransfer(
            "response header does not match query",
        ));
    }
    if validated_extended_rcode(response)? != 0 {
        return Err(TransportError::InvalidTransfer("server rejected transfer"));
    }
    // RFC 5936 §2.2.1 recommends that AXFR clients ignore AA for interoperability.
    // TC and the three AXFR MBZ bits were cleared before context-specific decoding.
    if !response.authorities.is_empty() {
        return Err(TransportError::InvalidTransfer(
            "AXFR authority section is not empty",
        ));
    }
    if first_message && response.questions.is_empty() {
        return Err(TransportError::InvalidTransfer(
            "first AXFR response omits the question",
        ));
    }
    if !response.questions.is_empty()
        && !crate::same_questions(&response.questions, &query.questions)
    {
        return Err(TransportError::InvalidTransfer(
            "response question does not match query",
        ));
    }
    if response.answers.is_empty() && (first_message || !is_padding_only_axfr_response(response)) {
        return Err(TransportError::InvalidTransfer(
            "AXFR answer section is empty",
        ));
    }
    if first_message
        && !response.answers.first().is_some_and(|record| {
            record.rtype == dns::RecordType::SOA && record.name.eq_dns(&query.questions[0].qname)
        })
    {
        return Err(TransportError::InvalidTransfer(
            "first AXFR response does not begin with the zone SOA",
        ));
    }
    Ok(())
}

pub(super) fn is_padding_only_axfr_response(response: &Message) -> bool {
    matches!(response.additionals.as_slice(), [record]
        if record.rtype == dns::RecordType::OPT
            && response
                .edns()
                .ok()
                .flatten()
                .is_some_and(|edns| edns.padding().is_some()))
}
