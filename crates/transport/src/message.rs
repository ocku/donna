#[cfg(any(feature = "tcp", feature = "udp", feature = "doh"))]
use std::time::Duration;

use dns::Message;
#[cfg(any(feature = "tcp", feature = "udp", test))]
use dns::{FromWire, IntoWire};

#[cfg(any(feature = "tcp", feature = "udp", test))]
use crate::MAX_TCP_MESSAGE_OCTETS;
use crate::TransportError;
#[cfg(feature = "udp")]
use crate::{MAX_EDNS_UDP_MESSAGE_OCTETS, MAX_UDP_MESSAGE_OCTETS};

#[cfg(any(feature = "tcp", feature = "udp", feature = "doh"))]
pub(super) fn checked_deadline(timeout: Duration) -> Result<tokio::time::Instant, TransportError> {
    tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or(TransportError::Timeout)
}

/// DoH and DoQ ignore the EDNS UDP payload size, including when padding a
/// query. Preserve its on-wire advertisement while measuring against the
/// encrypted stream's 65535-octet limit instead of the UDP limit.
#[cfg(any(feature = "doh", feature = "doq"))]
pub(super) fn pad_query_for_encrypted_stream(query: &mut Message) -> Result<(), TransportError> {
    let Some(index) = query
        .additionals
        .iter()
        .position(|record| record.rtype == dns::RecordType::OPT)
    else {
        return Ok(());
    };
    let udp_size = query.additionals[index].class;
    query.additionals[index].class = dns::ClassType::Unknown(u16::MAX);
    let result = query.pad_query_for_encrypted_transport(crate::MAX_TCP_MESSAGE_OCTETS);
    query.additionals[index].class = udp_size;
    result.map(|_| ()).map_err(TransportError::Padding)
}

#[cfg(any(feature = "doh", feature = "doq"))]
pub(super) fn stream_padding_request(request: &Message) -> Message {
    let mut request = request.clone();
    for record in &mut request.additionals {
        if record.rtype == dns::RecordType::OPT {
            record.class = dns::ClassType::Unknown(u16::MAX);
        }
    }
    request
}

#[cfg(any(feature = "tcp", feature = "udp", feature = "doh", test))]
pub(super) fn normalize_response_headers(request: &dns::Headers, response: &mut Message) {
    response.headers.id = request.id;
    response.headers.qr = true;
    response.headers.opcode = request.opcode;
    response.headers.rd = request.rd;
}

#[cfg(any(feature = "tcp", feature = "udp", feature = "doh"))]
pub(super) fn has_tsig(message: &Message) -> bool {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .any(|record| {
            record.rtype == dns::RecordType::TSIG
                || matches!(&record.rdata, dns::RData::SIG(sig) if sig.is_sig0())
        })
}

#[cfg(any(feature = "tcp", feature = "udp", feature = "doh"))]
pub(super) fn authenticated_response_headers_match(
    request: &dns::Headers,
    response: &Message,
) -> bool {
    response.headers.id == request.id
        && response.headers.qr
        && response.headers.opcode == request.opcode
        && response.headers.rd == request.rd
}

#[cfg(any(feature = "udp", test))]
pub(super) fn matches_query(reply: &Message, query: &Message) -> bool {
    reply.headers.qr
        && reply.headers.opcode == query.headers.opcode
        && reply.headers.id == query.headers.id
        && response_questions_match(reply, query)
}

#[cfg(any(feature = "tcp", feature = "udp", feature = "doh", test))]
pub(super) fn response_questions_match(reply: &Message, query: &Message) -> bool {
    match query.headers.opcode {
        // RFC 1035 §6.4.2: inverse responses supply the discovered names in
        // questions, while the inverse request has no questions to compare.
        dns::OpCode::IQuery => true,
        // RFC 2136 §3.8 permits UPDATE replies to omit the Zone Section.
        dns::OpCode::Update if reply.questions.is_empty() => true,
        _ => same_questions(&reply.questions, &query.questions),
    }
}

#[cfg(any(feature = "tcp", feature = "udp", feature = "doh", test))]
pub(super) fn same_questions(left: &[dns::Question], right: &[dns::Question]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.qname.eq_dns(&right.qname)
                && left.qtype == right.qtype
                && left.qclass == right.qclass
        })
}

#[cfg(any(feature = "tcp", feature = "udp", feature = "doh", test))]
pub(super) fn request_questions_are_safe_to_echo(questions: &[dns::Question]) -> bool {
    questions.iter().all(dns::Question::is_wire_canonical)
}

/// Enforces RFC 7830's prohibition on sending Padding over an unencrypted
/// DNS transport. Receiving remains permissive because Padding octets of every
/// value must be accepted and a peer's violation must not become a parser
/// interoperability failure.
#[cfg(any(feature = "tcp", feature = "udp", test))]
pub(super) fn reject_cleartext_padding(message: &Message) -> Result<(), TransportError> {
    if message_has_edns_padding(message) {
        Err(TransportError::InsecureEdnsPadding)
    } else {
        Ok(())
    }
}

#[cfg(any(feature = "tcp", feature = "udp", test))]
pub(super) fn message_has_edns_padding(message: &Message) -> bool {
    message.additionals.iter().any(|record| {
        matches!(
            &record.rdata,
            dns::RData::OPT(options) if options.iter().any(dns::EdnsOption::is_padding)
        )
    })
}

/// Prevents application-produced Padding from escaping through the built-in
/// cleartext servers while retaining the OPT record and all other options.
#[cfg(any(feature = "tcp", feature = "udp", test))]
pub(super) fn remove_cleartext_padding(message: &mut Message) {
    for record in &mut message.additionals {
        if let dns::RData::OPT(options) = &mut record.rdata {
            options.retain(|option| !option.is_padding());
        }
    }
}

/// Builds a structurally complete FORMERR reply when the request still
/// supplies a transaction ID.
///
/// TCP does not apply an EDNS UDP payload advertisement, but every result is
/// still bounded by its two-octet DNS frame length.
#[cfg(any(feature = "tcp", feature = "udp", test))]
pub(super) fn format_error_response(packet: &[u8]) -> Option<Vec<u8>> {
    let recovery = recover_questions_from_edns_request(packet);
    format_error_response_with_limit(packet, recovery, MAX_TCP_MESSAGE_OCTETS)
}

/// Applies the requestor's recovered EDNS payload size and this
/// implementation's UDP response ceiling without slicing any DNS section.
#[cfg(feature = "udp")]
pub(super) fn udp_format_error_response(packet: &[u8]) -> Option<Vec<u8>> {
    let recovery = recover_questions_from_edns_request(packet);
    let requestor_maximum = recovery.map_or(MAX_UDP_MESSAGE_OCTETS, |recovery| {
        usize::from(
            recovery
                .udp_payload_size
                .max(dns::Edns::MIN_UDP_PAYLOAD_SIZE),
        )
    });
    let maximum = requestor_maximum
        .min(usize::from(dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE))
        .min(MAX_EDNS_UDP_MESSAGE_OCTETS);
    format_error_response_with_limit(packet, recovery, maximum)
}

/// This operates on the raw header because malformed packets may use an opcode
/// which the semantic message model intentionally rejects. RFC 1035 §4.1.1
/// nevertheless requires a response to copy the request's OPCODE and RD bits.
/// Candidate responses are selected only when complete; no question or record
/// is ever truncated as raw bytes.
#[cfg(any(feature = "tcp", feature = "udp", test))]
pub(super) fn format_error_response_with_limit(
    packet: &[u8],
    recovery: Option<MalformedEdnsRecovery<'_>>,
    maximum: usize,
) -> Option<Vec<u8>> {
    // These masks describe the first DNS flags octet. Naming them here keeps
    // the raw-packet recovery path readable without pretending malformed input
    // can be represented as a semantic `Headers` value.
    const RESPONSE: u8 = 0b1000_0000;
    const OPCODE: u8 = 0b0111_1000;
    const RECURSION_DESIRED: u8 = 0b0000_0001;
    const FORMAT_ERROR_RCODE: u8 = 0b0000_0001;
    const DNS_HEADER_OCTETS: usize = 12;

    let id = [*packet.first()?, *packet.get(1)?];
    let query_flags = *packet.get(2).unwrap_or(&0);
    if query_flags & RESPONSE != 0 {
        return None;
    }
    let opcode = query_flags & OPCODE;
    let rd = query_flags & RECURSION_DESIRED;
    let mut minimal = vec![0; DNS_HEADER_OCTETS];
    minimal[..2].copy_from_slice(&id);
    minimal[2] = RESPONSE | opcode | rd;
    // RCODE=FORMERR; AA, TC, RA, Z, and all section counts remain clear.
    minimal[3] = FORMAT_ERROR_RCODE;

    if let Some(recovery) = recovery {
        let opt = dns::Edns::default()
            .into_record()
            .into_wire()
            .expect("the default OPT record is wire-valid");

        let mut rich = minimal.clone();
        rich[4..6].copy_from_slice(&packet[4..6]);
        rich[10..12].copy_from_slice(&1_u16.to_be_bytes());
        rich.extend_from_slice(recovery.questions);
        rich.extend_from_slice(&opt);
        if rich.len() <= maximum {
            return Some(rich);
        }

        let mut opt_bearing = minimal.clone();
        opt_bearing[10..12].copy_from_slice(&1_u16.to_be_bytes());
        opt_bearing.extend_from_slice(&opt);
        if opt_bearing.len() <= maximum {
            return Some(opt_bearing);
        }
    }

    (minimal.len() <= maximum).then_some(minimal)
}

#[derive(Clone, Copy)]
#[cfg(any(feature = "tcp", feature = "udp", test))]
pub(super) struct MalformedEdnsRecovery<'a> {
    questions: &'a [u8],
    #[cfg(any(feature = "udp", test))]
    pub(super) udp_payload_size: u16,
}

/// Locates a structurally recoverable OPT fixed header and returns its UDP
/// payload size with the canonical question section. Option tuples are
/// deliberately not decoded: this path exists specifically for tuple lengths
/// that made normal decoding fail. Record boundaries before the OPT still have
/// to be intact, preventing arbitrary trailing bytes from being mistaken for
/// EDNS.
#[cfg(any(feature = "tcp", feature = "udp", test))]
pub(super) fn recover_questions_from_edns_request(
    packet: &[u8],
) -> Option<MalformedEdnsRecovery<'_>> {
    const DNS_HEADER_OCTETS: usize = 12;
    let question_count = u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]);
    let answer_count = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
    let authority_count = u16::from_be_bytes([*packet.get(8)?, *packet.get(9)?]);
    let additional_count = u16::from_be_bytes([*packet.get(10)?, *packet.get(11)?]);

    let mut position = DNS_HEADER_OCTETS;
    for _ in 0..question_count {
        position = wire_name_end(packet, position)?;
        position = position.checked_add(4)?;
        packet.get(..position)?;
    }
    let question_end = position;

    // Independently decode and strictly validate the bytes before reflecting
    // them. This rejects noncanonical QTYPE/QCLASS values and unsafe name
    // compression while retaining valid compression between questions.
    let mut candidate = vec![0; DNS_HEADER_OCTETS];
    candidate[4..6].copy_from_slice(&question_count.to_be_bytes());
    candidate.extend_from_slice(&packet[DNS_HEADER_OCTETS..question_end]);
    let candidate = Message::from_wire(&candidate).ok()?;
    candidate.validate_strict().ok()?;

    let record_count =
        u32::from(answer_count) + u32::from(authority_count) + u32::from(additional_count);
    for _ in 0..record_count {
        position = wire_name_end(packet, position)?;
        let fixed = packet.get(position..position.checked_add(10)?)?;
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        if record_type == u16::from(dns::RecordType::OPT) {
            return Some(MalformedEdnsRecovery {
                questions: &packet[DNS_HEADER_OCTETS..question_end],
                #[cfg(any(feature = "udp", test))]
                udp_payload_size: u16::from_be_bytes([fixed[2], fixed[3]]),
            });
        }
        let rdata_length = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        position = position.checked_add(10)?.checked_add(rdata_length)?;
        packet.get(..position)?;
    }
    None
}

/// Returns the first octet after a wire-format name without dereferencing
/// compression pointers. Full pointer validation is supplied by the normal
/// decoder for the reflected question section.
#[cfg(any(feature = "tcp", feature = "udp", test))]
fn wire_name_end(packet: &[u8], mut position: usize) -> Option<usize> {
    loop {
        let length = *packet.get(position)?;
        position = position.checked_add(1)?;
        match length & 0xc0 {
            0 if length == 0 => return Some(position),
            0 => {
                position = position.checked_add(usize::from(length))?;
                packet.get(..position)?;
            }
            0xc0 => {
                packet.get(position)?;
                return position.checked_add(1);
            }
            _ => return None,
        }
    }
}

/// Applies a transport's wire-message ceiling (RFC 1035 §4.2.1 for UDP,
/// §4.2.2 for TCP) while preserving RFC 2181 RRSet boundaries.
#[cfg(any(feature = "tcp", feature = "udp"))]
pub(crate) fn truncate_response(
    mut message: Message,
    maximum: usize,
) -> Result<Vec<u8>, TransportError> {
    match encode_bounded(&message, maximum) {
        Ok(BoundedEncoding::Fits(encoded)) => return Ok(encoded),
        Ok(BoundedEncoding::TooLong(_)) | Err(_) => {}
    }

    // RFC 8914 section 3 makes EDE the first thing sacrificed when a response
    // exceeds the requestor's UDP payload size. EDE is diagnostic rather than
    // protocol data, but dropping it is still signalled with TC.
    if remove_extended_dns_errors(&mut message) {
        message.headers.tc = true;
        if let Ok(BoundedEncoding::Fits(encoded)) = encode_bounded(&message, maximum) {
            return Ok(encoded);
        }
    }

    if let Some(encoded) = encode_after_omitting_optional_rrsets(&mut message, maximum)? {
        return Ok(encoded);
    }

    // Answer and Authority RRSets are required response data. Only reaching
    // this point because they do not fit causes the transport to set TC.
    message.headers.tc = true;
    while remove_last_required_rrset(&mut message) {
        match encode_bounded(&message, maximum)? {
            BoundedEncoding::Fits(encoded) => return Ok(encoded),
            BoundedEncoding::TooLong(_) => {}
        }
    }

    // The header and question section are mandatory so the client can match
    // the response. Never emit them above the transport's ceiling.
    match encode_bounded(&message, maximum)? {
        BoundedEncoding::Fits(encoded) => Ok(encoded),
        BoundedEncoding::TooLong(length) => Err(TransportError::MessageTooLong { length, maximum }),
    }
}

#[cfg(any(feature = "tcp", feature = "udp"))]
fn remove_extended_dns_errors(message: &mut Message) -> bool {
    let mut removed = false;
    for record in &mut message.additionals {
        if let dns::RData::OPT(options) = &mut record.rdata {
            let old_length = options.len();
            options.retain(|option| !option.is_extended_dns_error());
            removed |= options.len() != old_length;
        }
    }
    removed
}

/// Tries to encode without declaring truncation, dropping complete Additional
/// RRSets from the end until the message is both valid and within the limit.
#[cfg(any(feature = "tcp", feature = "udp"))]
fn encode_after_omitting_optional_rrsets(
    message: &mut Message,
    maximum: usize,
) -> Result<Option<Vec<u8>>, TransportError> {
    loop {
        match encode_bounded(message, maximum) {
            Ok(BoundedEncoding::Fits(encoded)) => return Ok(Some(encoded)),
            Ok(BoundedEncoding::TooLong(_)) => {
                if !remove_last_optional_additional_rrset(&mut message.additionals) {
                    return Ok(None);
                }
            }
            Err(error) => {
                // Decoding is intentionally more permissive than outbound
                // validation. Optional malformed Additional RRSets can still
                // be omitted, but no invalid candidate is ever emitted.
                if !remove_last_optional_additional_rrset(&mut message.additionals) {
                    return Err(error);
                }
            }
        }
    }
}

#[cfg(any(feature = "tcp", feature = "udp"))]
fn remove_last_optional_additional_rrset(records: &mut Vec<dns::ResourceRecord>) -> bool {
    let Some(last) = records
        .iter()
        .rfind(|record| record.rtype != dns::RecordType::OPT)
    else {
        return false;
    };
    let name = last.name.clone();
    let rtype = last.rtype;
    let class = last.class;
    records.retain(|record| {
        record.rtype == dns::RecordType::OPT
            || !record.name.eq_dns(&name)
            || record.rtype != rtype
            || record.class != class
    });
    true
}

#[cfg(any(feature = "tcp", feature = "udp"))]
enum BoundedEncoding {
    Fits(Vec<u8>),
    TooLong(usize),
}

#[cfg(any(feature = "tcp", feature = "udp"))]
fn encode_bounded(message: &Message, maximum: usize) -> Result<BoundedEncoding, TransportError> {
    match message.into_wire() {
        Ok(encoded) if encoded.len() <= maximum => Ok(BoundedEncoding::Fits(encoded)),
        Ok(encoded) => Ok(BoundedEncoding::TooLong(encoded.len())),
        Err(dns::wire::WireError::LengthOverflow {
            field: "message",
            length,
            ..
        }) if length > maximum => Ok(BoundedEncoding::TooLong(length)),
        Err(error) => Err(TransportError::Encode(error)),
    }
}

#[cfg(any(feature = "tcp", feature = "udp"))]
fn remove_last_required_rrset(message: &mut Message) -> bool {
    // Authority follows Answer on the wire, so this removes RRSets from the
    // end of the encoded required-data sections rather than choosing a section
    // by perceived importance.
    remove_last_rrset(&mut message.authorities) || remove_last_rrset(&mut message.answers)
}

#[cfg(any(feature = "tcp", feature = "udp"))]
fn remove_last_rrset(records: &mut Vec<dns::ResourceRecord>) -> bool {
    let Some(last) = records.last() else {
        return false;
    };
    let name = last.name.clone();
    let rtype = last.rtype;
    let class = last.class;
    // An RRSet can be interrupted in a decoded Vec by records from another
    // set. Remove every member, not merely the contiguous tail, because RFC
    // 2181 forbids emitting a partial RRSet in a non-truncated response.
    records.retain(|record| {
        !record.name.eq_dns(&name) || record.rtype != rtype || record.class != class
    });
    true
}
