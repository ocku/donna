use tracing::{debug, instrument, warn};

use super::rdata::validation_error_to_wire;
use crate::constants::header::HEADER_OCTETS;
use crate::wire::{
    Decoder, Encoder, FromWire, IntoWire, Result, WireError, decode_header, decode_question,
    decode_record, decode_update_record, encode_header, encode_question, encode_record,
    encode_update_record, encode_validated_record,
};
use crate::{HeaderFieldValueError, Message, MessageValidationError, OpCode, QClassType};

/// Decodes one complete RFC 1035 DNS message.
#[instrument(level = "debug", skip(bytes), fields(message_length = bytes.len()))]
pub(crate) fn decode_message(bytes: &[u8]) -> Result<Message> {
    let result = (|| {
        if bytes.len() > usize::from(u16::MAX) {
            return Err(WireError::LengthOverflow {
                field: "message",
                length: bytes.len(),
                maximum: usize::from(u16::MAX),
            });
        }
        if bytes.len() < HEADER_OCTETS {
            return Err(WireError::Truncated {
                position: 0,
                needed: HEADER_OCTETS,
                remaining: bytes.len(),
            });
        }
        let mut decoder = Decoder::new(bytes);
        let (headers, counts) = decode_header(&mut decoder)?;
        if counts.questions == 1
            && counts.answers == 0
            && counts.authorities == 0
            && counts.additionals == 0
        {
            decoder.omit_name_cache();
        }
        let questions = decode_many(&mut decoder, counts.questions, decode_question)?;
        let update_zone_class = questions
            .first()
            .and_then(|question| match question.qclass {
                QClassType::Class(class) => Some(class),
                QClassType::ANY | QClassType::Unknown(_) => None,
            });
        let answers = if headers.opcode == OpCode::Update {
            decode_many_with(&mut decoder, counts.answers, |decoder| {
                decode_update_record(decoder, update_zone_class, true)
            })?
        } else {
            decode_many(&mut decoder, counts.answers, decode_record)?
        };
        let authorities = if headers.opcode == OpCode::Update {
            decode_many_with(&mut decoder, counts.authorities, |decoder| {
                decode_update_record(decoder, update_zone_class, false)
            })?
        } else {
            decode_many(&mut decoder, counts.authorities, decode_record)?
        };
        let additionals = decode_many(&mut decoder, counts.additionals, decode_record)?;
        if decoder.remaining() != 0 {
            return Err(WireError::InvalidValue {
                field: "message trailing octets",
                value: decoder.remaining() as u64,
            });
        }
        Ok(Message::builder()
            .headers(headers)
            .questions(questions)
            .answers(answers)
            .authorities(authorities)
            .additionals(additionals)
            .build_unchecked())
    })();

    match &result {
        Ok(message) => debug!(
            transaction_id = message.headers.id,
            question_count = message.questions.len(),
            answer_count = message.answers.len(),
            authority_count = message.authorities.len(),
            additional_count = message.additionals.len(),
            "decoded DNS message"
        ),
        // Invalid network input is routine and must not flood daemon logs.
        // Callers still receive the complete typed error.
        Err(error) => debug!(error = %error, "failed to decode DNS message"),
    }
    result
}

/// Encodes one RFC 1035 DNS message, deriving section counts and RDLENGTHs.
#[instrument(
    level = "debug",
    skip(message),
    fields(
        transaction_id = message.headers.id,
        question_count = message.questions.len(),
        answer_count = message.answers.len(),
        authority_count = message.authorities.len(),
        additional_count = message.additionals.len()
    )
)]
pub(crate) fn encode_message(message: &Message) -> Result<Vec<u8>> {
    encode_message_context(message, None)
}

fn encode_message_context(message: &Message, ixfr: Option<&crate::Question>) -> Result<Vec<u8>> {
    encode_message_context_with_record_checks(message, ixfr, false)
}

fn encode_message_context_with_record_checks(
    message: &Message,
    ixfr: Option<&crate::Question>,
    recheck_records: bool,
) -> Result<Vec<u8>> {
    let result = (|| {
        ixfr.map_or_else(
            || message.validate_for_forwarding(),
            |q| message.validate_ixfr(q),
        )
        .map_err(message_validation_error_to_wire)?;
        let counts = message
            .section_counts()
            .map_err(|_| WireError::LengthOverflow {
                field: "message section",
                length: usize::from(u16::MAX) + 1,
                maximum: u16::MAX as usize,
            })?;
        // A bounded hint avoids repeated buffer growth on multi-record replies.
        // This is only an allocation hint: record and message limits below are
        // unchanged, and unusually large records grow the buffer as before.
        let question_octets: usize = message
            .questions
            .iter()
            .map(|question| question.qname.wire_len() + 4)
            .sum();
        let record_count =
            message.answers.len() + message.authorities.len() + message.additionals.len();
        let capacity = (HEADER_OCTETS + question_octets + record_count * 64)
            .clamp(128, 4096)
            .next_power_of_two();
        let mut encoder = Encoder::with_capacity(capacity);
        // UPDATE and NOTIFY use specialized validators which can return
        // before the ordinary complete record walk. Keep their checked
        // record encoders; all other successful paths validated each record.
        let records_validated =
            !recheck_records && !matches!(message.headers.opcode, OpCode::Update | OpCode::Notify);
        encode_header(&message.headers, counts, &mut encoder)?;
        for question in &message.questions {
            encode_question(question, &mut encoder)?;
        }
        let update_zone_class =
            message
                .questions
                .first()
                .and_then(|question| match question.qclass {
                    QClassType::Class(class) => Some(class),
                    QClassType::ANY | QClassType::Unknown(_) => None,
                });
        for record in &message.answers {
            if message.headers.opcode == OpCode::Update {
                encode_update_record(record, update_zone_class, &mut encoder)?;
            } else if records_validated {
                encode_validated_record(record, &mut encoder)?;
            } else {
                encode_record(record, &mut encoder)?;
            }
        }
        for record in &message.authorities {
            if message.headers.opcode == OpCode::Update {
                encode_update_record(record, update_zone_class, &mut encoder)?;
            } else if records_validated {
                encode_validated_record(record, &mut encoder)?;
            } else {
                encode_record(record, &mut encoder)?;
            }
        }
        for record in &message.additionals {
            if records_validated {
                encode_validated_record(record, &mut encoder)?;
            } else {
                encode_record(record, &mut encoder)?;
            }
        }
        let bytes = encoder.into_bytes();
        // RFC 1035 §4.2.2 frames TCP messages with a two-byte length field, so
        // an encodable message can never exceed 65535 octets.
        if bytes.len() > usize::from(u16::MAX) {
            return Err(WireError::LengthOverflow {
                field: "message",
                length: bytes.len(),
                maximum: u16::MAX as usize,
            });
        }
        Ok(bytes)
    })();

    match &result {
        Ok(bytes) => debug!(message_length = bytes.len(), "encoded DNS message"),
        Err(error) => warn!(error = %error, "failed to encode DNS message"),
    }
    result
}

impl Message {
    /// Decodes only the header and complete questions of a truncated response.
    ///
    /// RFC 2181 section 9 requires clients to ignore TC response contents and
    /// retry using a transport permitting larger replies. Record sections may
    /// therefore be incomplete. This method returns no records and preserves
    /// the header and questions for the caller's ordinary response correlation.
    /// It does not authenticate the peer or match an outstanding request.
    /// Complete messages still use [`FromWire::from_wire`].
    ///
    /// # Errors
    /// Rejects oversized packets, missing QR/TC flags, malformed headers and
    /// incomplete or invalid questions, including unsafe compression pointers.
    pub fn truncated_response_from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > usize::from(u16::MAX) {
            return Err(WireError::LengthOverflow {
                field: "message",
                length: bytes.len(),
                maximum: usize::from(u16::MAX),
            });
        }
        let mut decoder = Decoder::new(bytes);
        let (headers, counts) = decode_header(&mut decoder)?;
        if !headers.qr || !headers.tc {
            return Err(WireError::InvalidValue {
                field: "truncated response QR/TC flags",
                value: 0,
            });
        }
        if counts.questions == 1 {
            decoder.omit_name_cache();
        }
        let questions = decode_many(&mut decoder, counts.questions, decode_question)?;
        Ok(Self::builder()
            .headers(headers)
            .questions(questions)
            .build_unchecked())
    }

    /// Encodes an IXFR response with explicit outstanding-question context.
    ///
    /// The question section is preserved, including on signed continuations.
    pub fn into_wire_ixfr(&self, question: &crate::Question) -> Result<Vec<u8>> {
        encode_message_context(self, Some(question))
    }
}

impl IntoWire for Message {
    fn into_wire(&self) -> Result<Vec<u8>> {
        encode_message(self)
    }
}

impl FromWire for Message {
    fn from_wire(bytes: &[u8]) -> Result<Self> {
        decode_message(bytes)
    }
}

pub(super) fn message_validation_error_to_wire(error: MessageValidationError) -> WireError {
    match error {
        MessageValidationError::SectionTooLong(error) => WireError::LengthOverflow {
            field: "message section",
            length: error.length,
            maximum: usize::from(u16::MAX),
        },
        MessageValidationError::InvalidHeader(error) => match error {
            HeaderFieldValueError::TooWide { field, value, .. }
            | HeaderFieldValueError::Reserved { field, value } => WireError::InvalidValue {
                field,
                value: u64::from(value),
            },
        },
        MessageValidationError::InvalidQuestion { field, value, .. } => WireError::InvalidValue {
            field,
            value: u64::from(value),
        },
        MessageValidationError::InvalidRecord { error, .. } => validation_error_to_wire(error),
        MessageValidationError::ResponseOnlyQueryFields => WireError::InvalidValue {
            field: "query response-only header fields",
            value: 1,
        },
        MessageValidationError::InvalidQueryRequestSections => WireError::InvalidValue {
            field: "QUERY request sections",
            value: 1,
        },
        MessageValidationError::InvalidIqueryRequestSections => WireError::InvalidValue {
            field: "IQUERY request sections",
            value: 1,
        },
        MessageValidationError::InvalidUpdateMessage => WireError::InvalidValue {
            field: "UPDATE message sections",
            value: 1,
        },
        MessageValidationError::InvalidNotifyMessage => WireError::InvalidValue {
            field: "NOTIFY message sections",
            value: 1,
        },
        MessageValidationError::InvalidAxfrResponseFields => WireError::InvalidValue {
            field: "AXFR response fields",
            value: 1,
        },
        MessageValidationError::AuthoritativeAnyClass => WireError::InvalidValue {
            field: "authoritative QCLASS ANY response",
            value: 1,
        },
        MessageValidationError::InvalidAuthoritativeNegativeResponse => WireError::InvalidValue {
            field: "authoritative negative response",
            value: 1,
        },
        MessageValidationError::OptOutsideAdditional => WireError::InvalidValue {
            field: "OPT section",
            value: 1,
        },
        MessageValidationError::MultipleOpt => WireError::InvalidValue {
            field: "OPT count",
            value: 2,
        },
        MessageValidationError::TsigOutsideAdditional => WireError::InvalidValue {
            field: "TSIG section",
            value: 1,
        },
        MessageValidationError::MultipleTsig => WireError::InvalidValue {
            field: "TSIG count",
            value: 2,
        },
        MessageValidationError::TsigNotLast => WireError::InvalidValue {
            field: "TSIG position",
            value: 1,
        },
        MessageValidationError::InvalidTsigMessage => WireError::InvalidValue {
            field: "TSIG message fields",
            value: 1,
        },
        MessageValidationError::Sig0OutsideAdditional => WireError::InvalidValue {
            field: "SIG(0) section",
            value: 1,
        },
        MessageValidationError::MultipleSig0 => WireError::InvalidValue {
            field: "SIG(0) count",
            value: 2,
        },
        MessageValidationError::Sig0NotLast => WireError::InvalidValue {
            field: "SIG(0) position",
            value: 1,
        },
        MessageValidationError::InvalidSig0Message => WireError::InvalidValue {
            field: "SIG(0) message fields",
            value: 1,
        },
        MessageValidationError::MultipleAuthenticationSchemes => WireError::InvalidValue {
            field: "DNS authentication schemes",
            value: 2,
        },
        MessageValidationError::ExtendedRcodeInRequest => WireError::InvalidValue {
            field: "request extended RCODE",
            value: 1,
        },
    }
}

fn decode_many<T>(
    decoder: &mut Decoder<'_>,
    count: u16,
    decode: fn(&mut Decoder<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    if count == 1 {
        // Decode before allocating. A singleton section needs one slot, not
        // Vec's minimum growth capacity; untrusted large counts stay lazy.
        return decode(decoder).map(|item| vec![item]);
    }
    (0..count).map(|_| decode(decoder)).collect()
}

fn decode_many_with<T>(
    decoder: &mut Decoder<'_>,
    count: u16,
    mut decode: impl FnMut(&mut Decoder<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    if count == 1 {
        // Decode before allocating. A singleton section needs one slot, not
        // Vec's minimum growth capacity; untrusted large counts stay lazy.
        return decode(decoder).map(|item| vec![item]);
    }
    (0..count).map(|_| decode(decoder)).collect()
}

#[cfg(test)]
mod tests;
