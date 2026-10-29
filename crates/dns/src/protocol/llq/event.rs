use super::*;

/// One resource-record change carried by an LLQ EVENT response.
#[derive(Debug, Clone)]
pub enum LlqEventChange {
    /// Record was added; its ordinary TTL is retained.
    Add(ResourceRecord),
    /// Record was removed; the wire TTL was `0xFFFFFFFF`.
    Remove(ResourceRecord),
}

/// LLQ EVENT message preserving the protocol's overloaded removal TTL.
#[derive(Debug, Clone)]
pub struct LlqEventMessage {
    /// Unpredictable DNS ID which the client must echo in its acknowledgment.
    pub message_id: u16,
    /// Questions identifying the LLQs represented in this batch.
    pub questions: Vec<Question>,
    /// Added and removed answer records.
    pub changes: Vec<LlqEventChange>,
    /// EVENT options in the same order as the questions.
    pub options: Vec<LlqOption>,
}

impl LlqEventMessage {
    /// Encodes a complete gratuitous LLQ response.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched question/option counts, invalid EVENT
    /// options or records, or DNS wire limits.
    pub fn into_wire(&self) -> Result<Vec<u8>, LlqError> {
        validate_event_options(&self.questions, &self.options)?;
        let mut encoder = Encoder::new();
        let counts = SectionCounts {
            questions: u16::try_from(self.questions.len()).map_err(|_| LlqError::SectionTooLong)?,
            answers: u16::try_from(self.changes.len()).map_err(|_| LlqError::SectionTooLong)?,
            authorities: 0,
            additionals: 1,
        };
        encode_header(
            &Headers {
                id: self.message_id,
                qr: true,
                aa: true,
                ..Headers::default()
            },
            counts,
            &mut encoder,
        )?;
        for question in &self.questions {
            encode_question(question, &mut encoder)?;
        }
        for change in &self.changes {
            let (record, ttl) = match change {
                LlqEventChange::Add(record) => (record, record.ttl),
                LlqEventChange::Remove(record) => (record, u32::MAX),
            };
            let mut validated = record.clone();
            if matches!(change, LlqEventChange::Remove(_)) {
                validated.ttl = 0;
            }
            validated
                .validate()
                .map_err(|_| LlqError::InvalidEventRecord)?;
            encoder.write_name(&record.name)?;
            encoder.write_u16(record.rtype.into());
            encoder.write_u16(record.class.value());
            encoder.write_u32(ttl);
            encoder.write_rdata(|encoder| encode_rdata(&record.rdata, encoder))?;
        }
        let mut edns = Edns::new(0);
        edns.options = self
            .options
            .iter()
            .copied()
            .map(LlqOption::into_edns_option)
            .collect();
        encode_record(&edns.into_record(), &mut encoder)?;
        let bytes = encoder.into_bytes();
        validate_message_length(bytes.len())?;
        Ok(bytes)
    }

    /// Decodes a complete gratuitous LLQ EVENT response.
    ///
    /// Unlike the ordinary DNS decoder, this preserves `0xFFFFFFFF` as a
    /// removal marker instead of applying RFC 2181's high-bit TTL rule.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed DNS, missing/malformed LLQ options, or
    /// mismatched question/option counts.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, LlqError> {
        validate_message_length(bytes.len())?;
        let mut decoder = Decoder::new(bytes);
        let (headers, counts) = decode_header(&mut decoder)?;
        if !headers.qr || headers.opcode != OpCode::Query || headers.rcode != RCode::Ok {
            return Err(LlqError::MalformedEvent);
        }
        let mut questions = Vec::with_capacity(usize::from(counts.questions));
        for _ in 0..counts.questions {
            questions.push(decode_question(&mut decoder)?);
        }
        let mut changes = Vec::with_capacity(usize::from(counts.answers));
        for _ in 0..counts.answers {
            changes.push(decode_event_change(&mut decoder)?);
        }
        for _ in 0..counts.authorities {
            decode_record(&mut decoder)?;
        }
        let mut options = None;
        for _ in 0..counts.additionals {
            let record = decode_record(&mut decoder)?;
            if record.rtype == crate::RecordType::OPT {
                if options.is_some() {
                    return Err(LlqError::MalformedEvent);
                }
                let edns = Edns::try_from_record(&record).map_err(|_| LlqError::MalformedEvent)?;
                options = Some(
                    edns.options
                        .iter()
                        .filter(|option| option.code == LLQ_OPTION_CODE)
                        .map(LlqOption::from_edns_option)
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
        }
        if decoder.remaining() != 0 {
            return Err(LlqError::MalformedEvent);
        }
        let options = options.ok_or(LlqError::MalformedEvent)?;
        validate_event_options(&questions, &options)?;
        Ok(Self {
            message_id: headers.id,
            questions,
            changes,
            options,
        })
    }
}

fn decode_event_change(decoder: &mut Decoder<'_>) -> Result<LlqEventChange, LlqError> {
    let name = decode_name(decoder)?;
    let rtype = record_type(decoder.read_u16()?)?;
    let record_class = class(decoder.read_u16()?)?;
    let raw_ttl = decoder.read_u32()?;
    let length = usize::from(decoder.read_u16()?);
    let rdata = decode_rdata(rtype, record_class, decoder, length)?;
    let removed = raw_ttl == u32::MAX;
    let record = ResourceRecord {
        name,
        rtype,
        class: record_class,
        ttl: if raw_ttl > MAX_TTL { 0 } else { raw_ttl },
        rdata,
    };
    record
        .validate()
        .map_err(|_| LlqError::InvalidEventRecord)?;
    Ok(if removed {
        LlqEventChange::Remove(record)
    } else {
        LlqEventChange::Add(record)
    })
}

fn validate_event_options(questions: &[Question], options: &[LlqOption]) -> Result<(), LlqError> {
    if options.len() != questions.len()
        || options.iter().any(|option| {
            option.version != LLQ_VERSION
                || option.opcode != LlqOpcode::Event
                || option.response_code != LlqResponseCode::NoError
                || option.id == 0
                || option.lease != 0
        })
    {
        return Err(LlqError::MalformedEvent);
    }
    Ok(())
}

fn validate_message_length(length: usize) -> Result<(), LlqError> {
    if length > usize::from(u16::MAX) {
        return Err(LlqError::Wire(WireError::LengthOverflow {
            field: "message",
            length,
            maximum: usize::from(u16::MAX),
        }));
    }
    Ok(())
}
