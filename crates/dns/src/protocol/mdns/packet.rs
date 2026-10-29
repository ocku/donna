use super::*;

/// A question plus the mDNS QU (unicast-response requested) bit.
#[derive(Debug, Clone)]
pub struct MdnsQuestion {
    /// Ordinary DNS question with the high QCLASS bit removed.
    pub question: Question,
    /// Whether the sender requested a unicast response.
    pub unicast_response: bool,
}

/// A resource record plus the mDNS cache-flush bit.
#[derive(Debug, Clone)]
pub struct MdnsRecord {
    /// Ordinary DNS record with the high CLASS bit removed.
    pub record: ResourceRecord,
    /// Whether receivers should flush older unique records in this RRset.
    pub cache_flush: bool,
}

/// An mDNS message retaining QU and cache-flush semantics.
#[derive(Debug, Clone)]
pub struct MdnsPacket {
    /// DNS header fields. Transaction ID must be zero.
    pub headers: Headers,
    /// Question section.
    pub questions: Vec<MdnsQuestion>,
    /// Answer section.
    pub answers: Vec<MdnsRecord>,
    /// Authority section, including probe proposals.
    pub authorities: Vec<MdnsRecord>,
    /// Additional section.
    pub additionals: Vec<MdnsRecord>,
}

impl MdnsPacket {
    /// Encodes the packet with QU and cache-flush bits in their overloaded
    /// class fields.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid mDNS headers, classes, records, or DNS
    /// wire limits.
    pub fn into_wire(&self) -> Result<Vec<u8>, MdnsError> {
        validate_outbound_headers(&self.headers)?;
        let counts = SectionCounts {
            questions: section_len(self.questions.len())?,
            answers: section_len(self.answers.len())?,
            authorities: section_len(self.authorities.len())?,
            additionals: section_len(self.additionals.len())?,
        };
        let mut encoder = Encoder::new();
        encode_header(&self.headers, counts, &mut encoder)?;
        for question in &self.questions {
            encoder.write_name(&question.question.qname)?;
            encoder.write_u16(question.question.qtype.value());
            let class = question.question.qclass.value();
            if class == 0 || class & 0x8000 != 0 {
                return Err(MdnsError::InvalidClass(class));
            }
            encoder.write_u16(class | (u16::from(question.unicast_response) << 15));
        }
        for record in &self.answers {
            if !self.headers.qr && record.cache_flush {
                return Err(MdnsError::InvalidCacheFlush);
            }
            encode_record(record, &mut encoder)?;
        }
        for record in &self.authorities {
            if record.cache_flush {
                return Err(MdnsError::InvalidCacheFlush);
            }
            encode_record(record, &mut encoder)?;
        }
        for record in &self.additionals {
            if !self.headers.qr && record.cache_flush {
                return Err(MdnsError::InvalidCacheFlush);
            }
            encode_record(record, &mut encoder)?;
        }
        let bytes = encoder.into_bytes();
        if bytes.len() > usize::from(u16::MAX) {
            return Err(MdnsError::Wire(WireError::LengthOverflow {
                field: "mDNS message",
                length: bytes.len(),
                maximum: usize::from(u16::MAX),
            }));
        }
        Ok(bytes)
    }

    /// Decodes an mDNS packet and validates link-local datagram scope.
    ///
    /// # Errors
    ///
    /// Returns an error for an off-link packet, invalid endpoint, malformed
    /// DNS data, or trailing octets.
    pub fn from_datagram(
        bytes: &[u8],
        source: SocketAddr,
        destination: SocketAddr,
        hop_limit: u8,
    ) -> Result<Self, MdnsError> {
        if hop_limit != MDNS_HOP_LIMIT {
            return Err(MdnsError::InvalidHopLimit(hop_limit));
        }
        let multicast_destination = match destination.ip() {
            IpAddr::V4(address) => address == MDNS_IPV4_GROUP,
            IpAddr::V6(address) => address == MDNS_IPV6_GROUP,
        };
        if multicast_destination && destination.port() != MDNS_PORT {
            return Err(MdnsError::InvalidDestination(destination));
        }
        if source.ip().is_unspecified() || source.ip().is_multicast() {
            return Err(MdnsError::InvalidSource(source));
        }

        let mut decoder = Decoder::new(bytes);
        let (headers, counts) = decode_mdns_header(&mut decoder)?;
        validate_received_headers(&headers)?;
        if headers.qr && source.port() != MDNS_PORT {
            return Err(MdnsError::InvalidSource(source));
        }
        let mut questions = Vec::with_capacity(usize::from(counts.questions));
        for _ in 0..counts.questions {
            let qname = decode_name(&mut decoder)?;
            let qtype = query_type(decoder.read_u16()?)?;
            let raw_class = decoder.read_u16()?;
            questions.push(MdnsQuestion {
                question: Question {
                    qname,
                    qtype,
                    qclass: qclass(raw_class & 0x7fff)?,
                },
                unicast_response: raw_class & 0x8000 != 0,
            });
        }
        let answers = decode_records(&mut decoder, counts.answers)?;
        let authorities = decode_records(&mut decoder, counts.authorities)?;
        let additionals = decode_records(&mut decoder, counts.additionals)?;
        if decoder.remaining() != 0 {
            return Err(MdnsError::Wire(WireError::InvalidValue {
                field: "mDNS trailing octets",
                value: decoder.remaining() as u64,
            }));
        }
        Ok(Self {
            headers,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

fn validate_outbound_headers(headers: &Headers) -> Result<(), MdnsError> {
    if headers.id != 0
        || headers.opcode != OpCode::Query
        || headers.rd
        || headers.ra
        || headers.ad
        || headers.cd
        || headers.rcode != RCode::Ok
        || (headers.qr && (!headers.aa || headers.tc))
        || (!headers.qr && headers.aa)
    {
        return Err(MdnsError::InvalidHeaders);
    }
    Ok(())
}

fn validate_received_headers(headers: &Headers) -> Result<(), MdnsError> {
    // RFC 6762 ignores ID, AA, response TC, RD, RA, AD, and CD on reception.
    // Query TC is meaningful for multi-packet known-answer lists.
    if headers.opcode != OpCode::Query || headers.rcode != RCode::Ok {
        return Err(MdnsError::InvalidHeaders);
    }
    Ok(())
}

fn section_len(length: usize) -> Result<u16, MdnsError> {
    u16::try_from(length).map_err(|_| {
        MdnsError::Wire(WireError::LengthOverflow {
            field: "mDNS section",
            length,
            maximum: usize::from(u16::MAX),
        })
    })
}

fn encode_record(record: &MdnsRecord, encoder: &mut Encoder) -> Result<(), MdnsError> {
    record.record.validate().map_err(MdnsError::InvalidRecord)?;
    let class = record.record.class.value();
    if class == 0 || class & 0x8000 != 0 {
        return Err(MdnsError::InvalidClass(class));
    }
    encoder.write_name(&record.record.name)?;
    encoder.write_u16(record.record.rtype.into());
    encoder.write_u16(class | (u16::from(record.cache_flush) << 15));
    encoder.write_u32(record.record.ttl);
    encoder.write_rdata(|encoder| encode_rdata(&record.record.rdata, encoder))?;
    Ok(())
}

fn decode_records(decoder: &mut Decoder<'_>, count: u16) -> Result<Vec<MdnsRecord>, MdnsError> {
    let mut records = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let name = decode_name(decoder)?;
        let rtype = record_type(decoder.read_u16()?)?;
        let raw_class = decoder.read_u16()?;
        let cache_flush = raw_class & 0x8000 != 0;
        let record_class = class(raw_class & 0x7fff)?;
        let received_ttl = decoder.read_u32()?;
        let ttl = if received_ttl > MAX_TTL {
            0
        } else {
            received_ttl
        };
        let length = usize::from(decoder.read_u16()?);
        let rdata = decode_rdata(rtype, record_class, decoder, length)?;
        records.push(MdnsRecord {
            record: ResourceRecord {
                name,
                rtype,
                class: record_class,
                ttl,
                rdata,
            },
            cache_flush,
        });
    }
    Ok(records)
}
