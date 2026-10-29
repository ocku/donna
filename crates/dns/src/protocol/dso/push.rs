use super::*;

/// Encodes a DNS Push SUBSCRIBE primary TLV.
///
/// # Errors
///
/// Returns an error if the name cannot be encoded or the payload exceeds the
/// TLV length field.
pub fn push_subscribe_tlv(question: &Question) -> Result<DsoTlv, DsoError> {
    let mut encoder = Encoder::new();
    encoder.write_uncompressed_name(&question.qname);
    encoder.write_u16(question.qtype.value());
    encoder.write_u16(question.qclass.value());
    let data = encoder.into_bytes();
    u16::try_from(data.len()).map_err(|_| DsoError::TlvTooLong {
        code: DNS_PUSH_SUBSCRIBE,
        length: data.len(),
    })?;
    Ok(DsoTlv {
        code: DNS_PUSH_SUBSCRIBE,
        data,
    })
}

/// Decodes a DNS Push SUBSCRIBE primary TLV.
///
/// # Errors
///
/// Returns an error unless the payload contains exactly one NAME, TYPE, and
/// CLASS.
pub fn parse_push_subscribe(tlv: &DsoTlv) -> Result<Question, DsoError> {
    if tlv.code != DNS_PUSH_SUBSCRIBE {
        return Err(DsoError::MalformedTlv(tlv.code));
    }
    let mut decoder = Decoder::new(&tlv.data);
    let qname = decode_name(&mut decoder)?;
    let qtype = query_type(decoder.read_u16()?)?;
    let qclass = qclass(decoder.read_u16()?)?;
    if decoder.remaining() != 0 {
        return Err(DsoError::MalformedTlv(tlv.code));
    }
    Ok(Question {
        qname,
        qtype,
        qclass,
    })
}

/// DNS Push change notification.
#[derive(Debug, Clone)]
pub enum PushChange {
    /// Add one record. TTL zero means subscription lifetime.
    Add(ResourceRecord),
    /// Remove one exact record.
    RemoveRecord(ResourceRecord),
    /// Remove an RRset at a name in one class.
    RemoveRrset {
        /// Owner name.
        name: DomainName,
        /// RR TYPE.
        rtype: RecordType,
        /// RR CLASS.
        class: ClassType,
    },
    /// Remove all RRsets at a name in one class.
    RemoveNameClass {
        /// Owner name.
        name: DomainName,
        /// RR CLASS.
        class: ClassType,
    },
    /// Remove all RRsets at a name in all classes.
    RemoveName {
        /// Owner name.
        name: DomainName,
    },
}

/// Encodes one PUSH primary TLV containing one or more changes.
///
/// # Errors
///
/// Returns an error for an empty list, invalid record, or oversized payload.
pub fn push_update_tlv(changes: &[PushChange]) -> Result<DsoTlv, DsoError> {
    if changes.is_empty() {
        return Err(DsoError::EmptyPushUpdate);
    }
    // Compression pointers in PUSH are relative to the start of the complete
    // DNS message.  The primary TLV's data begins after the 12-byte DSO header
    // and four-byte TLV header, so seed the encoder with that prefix and strip
    // it after encoding.
    let mut encoder = Encoder::new();
    encoder.write_exact(&[0; 16]);
    for change in changes {
        encode_change(change, &mut encoder)?;
    }
    let data = encoder.into_bytes().split_off(16);
    if data.len() > 16_382 - 16 {
        return Err(DsoError::PushMessageTooLong(data.len() + 16));
    }
    Ok(DsoTlv {
        code: DNS_PUSH_UPDATE,
        data,
    })
}

fn encode_change(change: &PushChange, encoder: &mut Encoder) -> Result<(), DsoError> {
    match change {
        PushChange::Add(record) | PushChange::RemoveRecord(record) => {
            record.validate().map_err(DsoError::InvalidRecord)?;
            encoder.write_name(&record.name)?;
            encoder.write_u16(record.rtype.into());
            encoder.write_u16(record.class.value());
            encoder.write_u32(if matches!(change, PushChange::RemoveRecord(_)) {
                u32::MAX
            } else {
                record.ttl
            });
            encoder.write_rdata(|encoder| encode_rdata(&record.rdata, encoder))?;
        }
        PushChange::RemoveRrset { name, rtype, class } => {
            encode_collective(name, u16::from(*rtype), class.value(), encoder)?;
        }
        PushChange::RemoveNameClass { name, class } => {
            encode_collective(name, 255, class.value(), encoder)?;
        }
        PushChange::RemoveName { name } => encode_collective(name, 0, 255, encoder)?,
    }
    Ok(())
}

fn encode_collective(
    name: &DomainName,
    rtype: u16,
    class: u16,
    encoder: &mut Encoder,
) -> Result<(), DsoError> {
    encoder.write_name(name)?;
    encoder.write_u16(rtype);
    encoder.write_u16(class);
    encoder.write_u32(u32::MAX - 1);
    encoder.write_u16(0);
    Ok(())
}

/// Decodes the changes in a PUSH TLV.
///
/// # Errors
///
/// Returns an error for invalid change forms or an empty PUSH.
pub fn parse_push_update(tlv: &DsoTlv) -> Result<Vec<PushChange>, DsoError> {
    if tlv.code != DNS_PUSH_UPDATE {
        return Err(DsoError::MalformedTlv(tlv.code));
    }
    // Reconstitute the bytes preceding a primary PUSH TLV so standard DNS
    // compression pointers retain their message-relative offsets.
    let mut message = vec![0; 16];
    message.extend_from_slice(&tlv.data);
    let mut decoder = Decoder::new(&message);
    decoder.read_exact(16)?;
    let mut changes = Vec::new();
    while decoder.remaining() != 0 {
        if let Some(change) = decode_change(&mut decoder)? {
            changes.push(change);
        }
    }
    if tlv.data.is_empty() {
        return Err(DsoError::EmptyPushUpdate);
    }
    Ok(changes)
}

fn decode_change(decoder: &mut Decoder<'_>) -> Result<Option<PushChange>, DsoError> {
    let name = decode_name(decoder)?;
    let type_code = decoder.read_u16()?;
    let class_code = decoder.read_u16()?;
    let ttl = decoder.read_u32()?;
    let length = usize::from(decoder.read_u16()?);
    if ttl == u32::MAX - 1 {
        if length != 0 {
            return Err(DsoError::MalformedPushChange);
        }
        return match (class_code, type_code) {
            (255, _) => Ok(Some(PushChange::RemoveName { name })),
            (_, 255) => Ok(Some(PushChange::RemoveNameClass {
                name,
                class: class(class_code)?,
            })),
            (_, _) => Ok(Some(PushChange::RemoveRrset {
                name,
                rtype: record_type(type_code)?,
                class: class(class_code)?,
            })),
        };
    }
    if (MAX_TTL + 1..u32::MAX - 1).contains(&ttl) {
        decoder.read_exact(length)?;
        return Ok(None);
    }
    if matches!(type_code, 255) || matches!(class_code, 255) {
        return Err(DsoError::MalformedPushChange);
    }
    let rtype = record_type(type_code)?;
    let record_class = class(class_code)?;
    let rdata = decode_rdata(rtype, record_class, decoder, length)?;
    let record = ResourceRecord {
        name,
        rtype,
        class: record_class,
        ttl: if ttl == u32::MAX { 0 } else { ttl },
        rdata,
    };
    if ttl == u32::MAX {
        Ok(Some(PushChange::RemoveRecord(record)))
    } else if ttl <= MAX_TTL {
        Ok(Some(PushChange::Add(record)))
    } else {
        Err(DsoError::MalformedPushChange)
    }
}

/// Encodes a RECONFIRM primary TLV for one disputed record.
///
/// The record TTL is not carried by RECONFIRM and is ignored.
///
/// # Errors
///
/// Returns an error for an invalid record, an ANY TYPE/CLASS, or an oversized
/// TLV payload.
pub fn push_reconfirm_tlv(record: &ResourceRecord) -> Result<DsoTlv, DsoError> {
    let mut validated = record.clone();
    validated.ttl = 0;
    validated.validate().map_err(DsoError::InvalidRecord)?;
    if u16::from(record.rtype) == 255 || record.class.value() == 255 {
        return Err(DsoError::MalformedPushChange);
    }

    let mut encoder = Encoder::new();
    encoder.write_exact(&[0; 16]);
    encoder.write_name(&record.name)?;
    encoder.write_u16(record.rtype.into());
    encoder.write_u16(record.class.value());
    encode_rdata(&record.rdata, &mut encoder)?;
    let data = encoder.into_bytes().split_off(16);
    u16::try_from(data.len()).map_err(|_| DsoError::TlvTooLong {
        code: DNS_PUSH_RECONFIRM,
        length: data.len(),
    })?;
    Ok(DsoTlv {
        code: DNS_PUSH_RECONFIRM,
        data,
    })
}

/// Decodes the single record in a RECONFIRM primary TLV.
///
/// The returned record has TTL zero because RECONFIRM does not carry a TTL.
///
/// # Errors
///
/// Returns an error unless the payload is exactly one non-ANY record.
pub fn parse_push_reconfirm(tlv: &DsoTlv) -> Result<ResourceRecord, DsoError> {
    if tlv.code != DNS_PUSH_RECONFIRM {
        return Err(DsoError::MalformedTlv(tlv.code));
    }
    let mut message = vec![0; 16];
    message.extend_from_slice(&tlv.data);
    let mut decoder = Decoder::new(&message);
    decoder.read_exact(16)?;
    let name = decode_name(&mut decoder)?;
    let type_code = decoder.read_u16()?;
    let class_code = decoder.read_u16()?;
    if type_code == 255 || class_code == 255 {
        return Err(DsoError::MalformedPushChange);
    }
    let rtype = record_type(type_code)?;
    let record_class = class(class_code)?;
    let length = decoder.remaining();
    let rdata = decode_rdata(rtype, record_class, &mut decoder, length)?;
    let record = ResourceRecord {
        name,
        rtype,
        class: record_class,
        ttl: 0,
        rdata,
    };
    record.validate().map_err(DsoError::InvalidRecord)?;
    Ok(record)
}

/// Encodes an UNSUBSCRIBE TLV naming the original subscription message ID.
pub fn push_unsubscribe_tlv(subscription_id: u16) -> DsoTlv {
    DsoTlv {
        code: DNS_PUSH_UNSUBSCRIBE,
        data: subscription_id.to_be_bytes().to_vec(),
    }
}

/// Parses an UNSUBSCRIBE TLV.
///
/// # Errors
///
/// Returns an error unless its payload is exactly two octets.
pub fn parse_push_unsubscribe(tlv: &DsoTlv) -> Result<u16, DsoError> {
    if tlv.code != DNS_PUSH_UNSUBSCRIBE || tlv.data.len() != 2 {
        return Err(DsoError::MalformedTlv(tlv.code));
    }
    Ok(u16::from_be_bytes([tlv.data[0], tlv.data[1]]))
}
