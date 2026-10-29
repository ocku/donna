use super::*;

// Keep cached authoritative prototypes within the IPv6-safe UDP payload.
const MAX_PROTOTYPE_OCTETS: usize = 1232;

/// A bounded authoritative NODATA reply made by the checked component writer.
///
/// Only the exact question spelling, class and type can reuse these immutable
/// records. Callers must still select NODATA from the current zone snapshot.
/// Authority TTLs remain static, as on ordinary authoritative responses.
#[derive(Debug)]
pub struct PreparedAuthoritativeNodataReply {
    bytes: Box<[u8]>,
    question: Question,
    dnssec_ok: bool,
}

impl PreparedAuthoritativeNodataReply {
    /// Prepares the same selected authorities through full ordinary checks.
    /// Unsupported requests/records and prototypes above 1232 bytes decline.
    ///
    /// # Errors
    /// Returns the ordinary checked authority validation or encoding error.
    pub fn from_records(
        request: &Message,
        authorities: &[&ResourceRecord],
    ) -> Result<Option<Self>> {
        let Some((dnssec_ok, _)) = Self::request_policy(request) else {
            return Ok(None);
        };
        // Normalize a classic request to a final empty OPT prototype. Rendering
        // can omit its eleven-byte trailer without relocating earlier pointers.
        let mut prototype = request.clone();
        prototype.additionals = vec![
            Edns {
                dnssec_ok,
                ..Edns::default()
            }
            .into_record(),
        ];
        let Some(encoded) = EncodedReply::authoritative_negative(
            &prototype,
            authorities,
            false,
            MAX_PROTOTYPE_OCTETS,
        )?
        else {
            return Ok(None);
        };
        if encoded.bytes.len() > MAX_PROTOTYPE_OCTETS {
            return Ok(None);
        }
        Ok(Some(Self {
            question: encoded.question,
            bytes: encoded.bytes.into_boxed_slice(),
            dnssec_ok,
        }))
    }

    fn request_policy(request: &Message) -> Option<(bool, usize)> {
        let [question] = request.questions.as_slice() else {
            return None;
        };
        if request.headers.qr
            || request.headers.aa
            || request.headers.ra
            || request.headers.tc
            || request.headers.opcode != OpCode::Query
            || request.headers.rcode != RCode::Ok
            || !request.answers.is_empty()
            || !request.authorities.is_empty()
            || !matches!(question.qclass, QClassType::Class(_))
            || matches!(question.qtype, QueryType::AXFR | QueryType::IXFR)
            || request.validate_for_forwarding().is_err()
        {
            return None;
        }
        let edns = request.edns().ok()?;
        if request.additionals.len() != usize::from(edns.is_some()) {
            return None;
        }
        match edns {
            Some(edns)
                if edns.version == 0 && edns.extended_rcode == 0 && edns.options.is_empty() =>
            {
                Some((
                    edns.dnssec_ok,
                    usize::from(edns.effective_udp_payload_size()),
                ))
            }
            None => Some((false, usize::from(Edns::MIN_UDP_PAYLOAD_SIZE))),
            _ => None,
        }
    }

    /// Renders the exact selected question, retaining authoritative flag policy.
    /// Unsupported requests and replies above the current payload limit decline
    /// for the caller's ordinary complete-RRset truncation path.
    pub fn render(&self, request: &Message, maximum: usize) -> Option<EncodedReply> {
        let (dnssec_ok, payload) = Self::request_policy(request)?;
        let question = &request.questions[0];
        if dnssec_ok != self.dnssec_ok
            || question.qname.as_ref() != self.question.qname.as_ref()
            || question.qtype != self.question.qtype
            || question.qclass != self.question.qclass
        {
            return None;
        }
        let has_opt = !request.additionals.is_empty();
        let length = self
            .bytes
            .len()
            .checked_sub(if has_opt { 0 } else { EMPTY_OPT_OCTETS })?;
        let maximum = maximum.min(payload).min(MAX_PROTOTYPE_OCTETS);
        if length > maximum {
            return None;
        }
        let mut bytes = self.bytes[..length].to_vec();
        if !has_opt {
            bytes[10..12].copy_from_slice(&0_u16.to_be_bytes());
        }
        bytes[..2].copy_from_slice(&request.headers.id.to_be_bytes());
        // Authoritative answers copy RD and keep RA/AD/CD clear. Request AD/CD
        // are retained separately for transport correlation, never echoed here.
        let flags = (u16::from_be_bytes([bytes[2], bytes[3]]) & !RD_FLAG)
            | (u16::from(request.headers.rd) * RD_FLAG);
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        Some(EncodedReply {
            bytes,
            question: question.clone(),
            id: request.headers.id,
            rd: request.headers.rd,
            cd: request.headers.cd,
            request_ad: request.headers.ad,
            maximum,
            request_opt_ttl: request.additionals.first().map(|record| record.ttl),
            has_name_servers: false,
        })
    }
}

impl EncodedReply {
    /// Encodes an ordinary authoritative negative while borrowing its records.
    ///
    /// The authority section is validated in full, including SOA scope and
    /// RRset consistency. This does not validate a denial cryptographically or
    /// select proofs; callers supply the same records as their structured path.
    /// Unsupported request/record shapes return `None`. Oversized packets keep
    /// their selected contents for transport's ordinary whole-RRset truncation.
    ///
    /// # Errors
    /// Returns checked message/record encoding errors for supported shapes.
    pub fn authoritative_negative(
        request: &Message,
        authorities: &[&ResourceRecord],
        name_error: bool,
        maximum: usize,
    ) -> Result<Option<Self>> {
        let [question] = request.questions.as_slice() else {
            return Ok(None);
        };
        if request.headers.opcode != OpCode::Query
            || request.headers.qr
            || request.validate_for_forwarding().is_err()
            || !matches!(question.qclass, QClassType::Class(_))
            || matches!(question.qtype, QueryType::AXFR | QueryType::IXFR)
            || authorities.len() > MAX_RECORDS
            || authorities.iter().any(|rr| {
                !matches!(
                    rr.rtype,
                    RecordType::SOA
                        | RecordType::SIG
                        | RecordType::RRSIG
                        | RecordType::NSEC
                        | RecordType::NSEC3
                ) && u16::from(rr.rtype) != 30
            })
        {
            return Ok(None);
        }
        // No transaction authentication or hop-by-hop options are supported.
        if request.additionals.len() > 1 {
            return Ok(None);
        }
        let request_edns = request.edns().ok().flatten();
        if request.additionals.len() != usize::from(request_edns.is_some())
            || request_edns.as_ref().is_some_and(|edns| {
                edns.version != 0 || edns.extended_rcode != 0 || !edns.options.is_empty()
            })
            || authorities
                .iter()
                .any(|rr| matches!(&rr.rdata, RData::SIG(sig) if sig.is_sig0()))
        {
            return Ok(None);
        }
        let opt = request_edns.as_ref().map(|edns| {
            Edns {
                dnssec_ok: edns.dnssec_ok,
                ..Edns::default()
            }
            .into_record()
        });
        let headers = crate::Headers {
            id: request.headers.id,
            qr: true,
            aa: true,
            rd: request.headers.rd,
            rcode: if name_error {
                RCode::NameError
            } else {
                RCode::Ok
            },
            ..crate::Headers::default()
        };
        Message::validate_borrowed_negative(&headers, question, authorities, opt.as_ref())
            .map_err(super::super::message::message_validation_error_to_wire)?;
        let capacity = (12
            + question.qname.wire_len()
            + 4
            + (authorities.len() + usize::from(opt.is_some())) * 64)
            .clamp(128, MAXIMUM)
            .next_power_of_two();
        let mut encoder = Encoder::with_capacity(capacity);
        super::super::encode_header(
            &headers,
            crate::SectionCounts {
                questions: 1,
                answers: 0,
                authorities: authorities.len() as u16,
                additionals: u16::from(opt.is_some()),
            },
            &mut encoder,
        )?;
        super::super::encode_question(question, &mut encoder)?;
        for record in authorities.iter().copied().chain(opt.as_ref()) {
            super::super::encode_validated_record(record, &mut encoder)?;
        }
        let bytes = encoder.into_bytes();
        if bytes.len() > usize::from(u16::MAX) {
            return Err(super::super::WireError::LengthOverflow {
                field: "message",
                length: bytes.len(),
                maximum: usize::from(u16::MAX),
            });
        }
        Ok(Some(Self {
            bytes,
            question: question.clone(),
            id: request.headers.id,
            rd: request.headers.rd,
            cd: request.headers.cd,
            request_ad: request.headers.ad,
            maximum: maximum.min(MAXIMUM).min(
                request_edns
                    .as_ref()
                    .map_or(usize::from(Edns::MIN_UDP_PAYLOAD_SIZE), |edns| {
                        usize::from(edns.effective_udp_payload_size())
                    }),
            ),
            request_opt_ttl: request.additionals.first().map(|rr| rr.ttl),
            has_name_servers: false,
        }))
    }
}
