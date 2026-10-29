//! Checked ordinary recursive and authoritative UDP replies.
mod authoritative;
mod authoritative_positive;
pub use authoritative::PreparedAuthoritativeNodataReply;
mod encoded;
mod positive;
mod recursive;
use super::{Encoder, Result, encode_record};
use crate::constants::header::{AD_FLAG, CD_FLAG, RD_FLAG};
use crate::{
    Edns, IntoWire, Message, OpCode, QClassType, QueryType, Question, RCode, RData, RecordType,
    ResourceRecord,
};
pub use positive::PreparedPositiveReply;

const MAXIMUM: usize = Edns::RECOMMENDED_UDP_PAYLOAD_SIZE as usize;
const MAX_RECORDS: usize = 64;
// Root owner octet, ten fixed RR octets, and no option data (RFC 6891).
const EMPTY_OPT_OCTETS: usize = 11;

/// A bounded, immutable negative reply encoded through the normal checked writer.
///
/// This supports ordinary recursive QUERY replies with either DO policy and empty OPT
/// options. Unsupported shapes return `None`; callers retain ordinary Message
/// handling. It is not a general unchecked serialization interface.
#[derive(Debug)]
pub struct PreparedNegativeReply {
    reply: PreparedReply,
}

/// Private checked encoding shared by the eligible recursive reply shapes.
#[derive(Debug)]
struct PreparedReply {
    bytes: Box<[u8]>,
    question: Question,
    qtype_offset: usize,
    ttls: Box<[TtlSlot]>,
    authenticated: bool,
    nxdomain: bool,
    has_name_servers: bool,
    dnssec_ok: bool,
}

#[derive(Debug)]
struct TtlSlot {
    offset: usize,
    maximum: u32,
    group: usize,
}

/// One checked, correlated UDP reply with private bytes and checked mutations.
#[derive(Debug)]
pub struct EncodedReply {
    bytes: Vec<u8>,
    question: Question,
    id: u16,
    rd: bool,
    cd: bool,
    request_ad: bool,
    maximum: usize,
    request_opt_ttl: Option<u32>,
    has_name_servers: bool,
}

impl PreparedNegativeReply {
    /// Prepares a reply after complete ordinary message validation and encoding.
    ///
    /// # Errors
    /// Returns the same error as the normal checked message encoder.
    pub fn from_message(message: &Message) -> Result<Option<Self>> {
        let bytes = message.into_wire()?;
        let [question] = message.questions.as_slice() else {
            return Ok(None);
        };
        if bytes.len() > MAXIMUM
            || !message.headers.qr
            || !message.headers.ra
            || message.headers.aa
            || message.headers.tc
            || message.headers.cd
            || message.headers.opcode != OpCode::Query
            || !matches!(message.headers.rcode, RCode::Ok | RCode::NameError)
            || !message.answers.is_empty()
            || message.authorities.len() > MAX_RECORDS
            || !matches!(question.qclass, QClassType::Class(_))
            || matches!(question.qtype, QueryType::AXFR | QueryType::IXFR)
            || message.additionals.len() != 1
        {
            return Ok(None);
        }
        let Some(edns) = message.edns().ok().flatten() else {
            return Ok(None);
        };
        if edns.version != 0 || edns.extended_rcode != 0 || !edns.options.is_empty() {
            return Ok(None);
        }
        if !edns.dnssec_ok
            && message.authorities.iter().any(|record| {
                filtered_dnssec_type(u16::from(record.rtype))
                    && u16::from(record.rtype) != question.qtype.value()
            })
        {
            return Ok(None);
        }
        let mut soa = false;
        for record in &message.authorities {
            if record.class.value() != question.qclass.value() {
                return Ok(None);
            }
            match &record.rdata {
                RData::SOA { minimum, .. } if record.rtype == RecordType::SOA => {
                    if !question.qname.is_descendant_of(&record.name) || record.ttl > *minimum {
                        return Ok(None);
                    }
                    soa = true;
                }
                RData::NSEC(_) if record.rtype == RecordType::NSEC => {}
                RData::NSEC3(_) if record.rtype == RecordType::NSEC3 => {}
                RData::NS(_) if record.rtype == RecordType::NS => {}
                RData::RRSIG(signature)
                    if record.rtype == RecordType::RRSIG
                        && [RecordType::SOA, RecordType::NSEC, RecordType::NSEC3]
                            .map(u16::from)
                            .contains(&signature.type_covered) => {}
                _ => return Ok(None),
            }
        }
        if !soa {
            return Ok(None);
        }
        Ok(PreparedReply::from_checked_encoding(message, bytes)?.map(|reply| Self { reply }))
    }

    /// Prepares a bounded CNAME-to-negative reply through both ordinary message
    /// checks and the checked recursive-negative component writer.
    ///
    /// # Errors
    /// Returns ordinary record, RRset, scope or encoding errors.
    pub fn from_composed_message(message: &Message) -> Result<Option<Self>> {
        let bytes = message.into_wire()?;
        if bytes.len() > MAXIMUM
            || !message.headers.qr
            || !message.headers.ra
            || message.headers.aa
            || message.headers.tc
            || message.headers.cd
            || message.headers.opcode != OpCode::Query
            || !matches!(message.headers.rcode, RCode::Ok | RCode::NameError)
            || message.answers.is_empty()
            || message.additionals.len() != 1
        {
            return Ok(None);
        }
        let mut request = Message {
            headers: crate::Headers {
                rd: true,
                ..crate::Headers::default()
            },
            questions: message.questions.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: message.additionals.clone(),
        };
        // Authentication is prototype metadata, while rendering correlates AD
        // with each actual request. The checked constructor validates all data.
        request.headers.ad = true;
        let answers: Vec<_> = message.answers.iter().map(|rr| (rr, rr.ttl)).collect();
        let authorities: Vec<_> = message.authorities.iter().map(|rr| (rr, rr.ttl)).collect();
        if EncodedReply::recursive_negative(
            &request,
            &answers,
            &authorities,
            message.headers.rcode == RCode::NameError,
            message.headers.ad,
            MAXIMUM,
        )?
        .is_none()
        {
            return Ok(None);
        }
        let Some(edns) = message.edns().ok().flatten() else {
            return Ok(None);
        };
        let question = &message.questions[0];
        if !edns.dnssec_ok
            && message
                .answers
                .iter()
                .chain(&message.authorities)
                .any(|rr| {
                    filtered_dnssec_type(u16::from(rr.rtype))
                        && u16::from(rr.rtype) != question.qtype.value()
                })
        {
            return Ok(None);
        }
        Ok(PreparedReply::from_checked_encoding(message, bytes)?.map(|reply| Self { reply }))
    }

    /// Renders permitted request fields and nonincreasing TTLs in answer then
    /// authority order.
    /// The caller must derive TTLs from live admitted absolute deadlines.
    /// Unsupported requests and oversized packets retain ordinary handling.
    pub fn render(
        &self,
        request: &Message,
        ttls: &[u32],
        maximum: usize,
        allow_authenticated_data: bool,
    ) -> Option<EncodedReply> {
        let question = request.questions.first()?;
        // Owner-scoped direct NXDOMAIN may change QTYPE, but a composed reply
        // has an existing alias. Keep the component writer's exclusions when
        // rendering another type, especially CNAME queries at that alias.
        if read_u16(&self.reply.bytes, 6)? != 0
            && matches!(
                question.qtype,
                QueryType::CNAME | QueryType::ANY | QueryType::MAILA | QueryType::MAILB
            )
        {
            return None;
        }
        // NXDOMAIN is owner-scoped, but non-DO filtering depends on explicitly
        // requested DNSSEC types. Never rewrite between those distinct policies.
        if !self.reply.dnssec_ok
            && question.qtype != self.reply.question.qtype
            && (filtered_dnssec_type(question.qtype.value())
                || filtered_dnssec_type(self.reply.question.qtype.value()))
        {
            return None;
        }
        self.reply
            .render(request, ttls, maximum, allow_authenticated_data)
    }
}

impl PreparedReply {
    // Called only after the ordinary checked writer and shape eligibility.
    fn from_checked_encoding(message: &Message, bytes: Vec<u8>) -> Result<Option<Self>> {
        let [question] = message.questions.as_slice() else {
            return Ok(None);
        };
        // Offsets are derived only from this fully checked local encoding.
        // Compressed names occupy their literal labels plus an optional pointer;
        // RDATA is skipped by its checked RDLENGTH, never searched for byte patterns.
        let Some(qtype_offset) = name_end(&bytes, 12) else {
            return Ok(None);
        };
        let mut cursor = qtype_offset + 4;
        let mut ttls = Vec::with_capacity(message.answers.len() + message.authorities.len());
        for (index, record) in message
            .answers
            .iter()
            .chain(&message.authorities)
            .enumerate()
        {
            let Some(end) = name_end(&bytes, cursor) else {
                return Ok(None);
            };
            let ttl = end + 4;
            let Some(length) = read_u16(&bytes, end + 8) else {
                return Ok(None);
            };
            let group = if record.rtype == RecordType::RRSIG {
                index
            } else {
                message
                    .answers
                    .iter()
                    .chain(&message.authorities)
                    .take(index)
                    .enumerate()
                    .find_map(|(previous_index, previous)| {
                        ((previous_index < message.answers.len())
                            == (index < message.answers.len())
                            && previous.rtype == record.rtype
                            && previous.name.eq_dns(&record.name))
                        .then_some(previous_index)
                    })
                    .unwrap_or(index)
            };
            ttls.push(TtlSlot {
                offset: ttl,
                maximum: record.ttl,
                group,
            });
            cursor = end + 10 + usize::from(length);
            if cursor > bytes.len() {
                return Ok(None);
            }
        }
        let Some(edns) = message.edns().ok().flatten() else {
            return Ok(None);
        };
        Ok(Some(Self {
            bytes: bytes.into_boxed_slice(),
            question: question.clone(),
            qtype_offset,
            ttls: ttls.into_boxed_slice(),
            authenticated: message.headers.ad,
            nxdomain: message.headers.rcode == RCode::NameError,
            has_name_servers: message
                .authorities
                .iter()
                .any(|rr| rr.rtype == RecordType::NS),
            dnssec_ok: edns.dnssec_ok,
        }))
    }

    /// Renders only permitted request fields and nonincreasing ordinary TTLs.
    ///
    /// `ttls` follows the prototype answer then authority order. The caller must derive each
    /// value from admitted absolute deadlines, and reject expired proof bundles.
    /// No record, signature or compression target is rewritten. A checked
    /// non-DO prototype may omit its final empty OPT for a classic request.
    /// Ineligible requests and oversized replies return `None` for normal handling.
    fn render(
        &self,
        request: &Message,
        ttls: &[u32],
        maximum: usize,
        allow_authenticated_data: bool,
    ) -> Option<EncodedReply> {
        let [question] = request.questions.as_slice() else {
            return None;
        };
        if request.headers.qr
            || request.headers.opcode != OpCode::Query
            || !request.headers.rd
            || request.validate_for_forwarding().is_err()
            || !question.is_wire_canonical()
            || question.qname.as_ref() != self.question.qname.as_ref()
            || question.qclass != self.question.qclass
            || (!self.nxdomain && question.qtype != self.question.qtype)
            || matches!(question.qtype, QueryType::AXFR | QueryType::IXFR)
            || ttls.len() != self.ttls.len()
        {
            return None;
        }
        let edns = request.edns().ok()?;
        if request.additionals.len() != usize::from(edns.is_some()) {
            return None;
        }
        let payload = match &edns {
            Some(edns)
                if edns.version == 0
                    && edns.extended_rcode == 0
                    && edns.dnssec_ok == self.dnssec_ok
                    && edns.options.is_empty() =>
            {
                usize::from(edns.effective_udp_payload_size())
            }
            None if !self.dnssec_ok => usize::from(Edns::MIN_UDP_PAYLOAD_SIZE),
            _ => return None,
        };
        // All prototypes have exactly one final empty OPT from the checked
        // writer. A plain variant can omit its eleven-byte trailer for classic
        // DNS: earlier compression targets and TTL offsets cannot point forward.
        let length = if edns.is_none() {
            self.bytes.len().checked_sub(EMPTY_OPT_OCTETS)?
        } else {
            self.bytes.len()
        };
        let maximum = maximum.min(MAXIMUM).min(payload);
        if length > maximum
            || ttls
                .iter()
                .zip(&self.ttls)
                .any(|(&ttl, slot)| ttl > slot.maximum || ttl != ttls[slot.group])
        {
            return None;
        }
        let mut bytes = Vec::with_capacity((length + 64).min(maximum));
        bytes.extend_from_slice(&self.bytes[..length]);
        if edns.is_none() {
            bytes[10..12].copy_from_slice(&0_u16.to_be_bytes());
        }
        bytes[..2].copy_from_slice(&request.headers.id.to_be_bytes());
        let mut flags = read_u16(&bytes, 2)? & !(RD_FLAG | AD_FLAG | CD_FLAG);
        flags |= u16::from(request.headers.rd) * RD_FLAG;
        flags |= u16::from(request.headers.cd) * CD_FLAG;
        flags |= u16::from(
            self.authenticated
                && allow_authenticated_data
                && !request.headers.cd
                && (self.dnssec_ok || request.headers.ad),
        ) * AD_FLAG;
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        bytes[self.qtype_offset..self.qtype_offset + 2]
            .copy_from_slice(&question.qtype.value().to_be_bytes());
        for (&ttl, slot) in ttls.iter().zip(&self.ttls) {
            bytes[slot.offset..slot.offset + 4].copy_from_slice(&ttl.to_be_bytes());
        }
        Some(EncodedReply {
            bytes,
            question: question.clone(),
            id: request.headers.id,
            rd: request.headers.rd,
            cd: request.headers.cd,
            request_ad: request.headers.ad,
            maximum,
            request_opt_ttl: request.additionals.first().map(|record| record.ttl),
            has_name_servers: self.has_name_servers,
        })
    }
}

fn filtered_dnssec_type(value: u16) -> bool {
    [RecordType::RRSIG, RecordType::NSEC, RecordType::NSEC3]
        .map(u16::from)
        .contains(&value)
}

fn read_u16(bytes: &[u8], position: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(position..position + 2)?.try_into().ok()?,
    ))
}

fn name_end(bytes: &[u8], mut cursor: usize) -> Option<usize> {
    loop {
        let first = *bytes.get(cursor)?;
        match first & 0xc0 {
            0 => {
                cursor = cursor.checked_add(1 + usize::from(first))?;
                bytes.get(..cursor)?;
                if first == 0 {
                    return Some(cursor);
                }
            }
            0xc0 => {
                bytes.get(cursor + 1)?;
                return cursor.checked_add(2);
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests;
