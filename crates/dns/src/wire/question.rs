use crate::protocol::{ClassType, QClassType, QueryType, Question, QuestionValidationError};
use crate::wire::{
    Decoder, Encoder, FromWire, IntoWire, Result, WireError, decode_complete, decode_name,
};

pub(crate) fn decode_question(decoder: &mut Decoder<'_>) -> Result<Question> {
    let qname = decode_name(decoder)?;
    let qtype = query_type(decoder.read_u16()?)?;
    let qclass = qclass(decoder.read_u16()?)?;
    Ok(Question {
        qname,
        qtype,
        qclass,
    })
}

pub(crate) fn encode_question(question: &Question, encoder: &mut Encoder) -> Result<()> {
    validate_question_codes(question)?;
    encoder.write_name(&question.qname)?;
    encoder.write_u16(question.qtype.into());
    encoder.write_u16(question.qclass.value());
    Ok(())
}

fn validate_question_codes(question: &Question) -> Result<()> {
    question.validate_wire().map_err(|error| match error {
        QuestionValidationError::NonCanonicalQueryType { value } => WireError::InvalidValue {
            field: "QTYPE",
            value: u64::from(value),
        },
        QuestionValidationError::NonCanonicalQueryClass { value } => WireError::InvalidValue {
            field: "QCLASS",
            value: u64::from(value),
        },
    })
}

impl IntoWire for Question {
    fn into_wire(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new();
        encode_question(self, &mut encoder)?;
        Ok(encoder.into_bytes())
    }
}

impl FromWire for Question {
    fn from_wire(bytes: &[u8]) -> Result<Self> {
        decode_complete(bytes, decode_question)
    }
}

pub(crate) fn class(code: u16) -> Result<ClassType> {
    match code {
        1 => Ok(ClassType::IN),
        3 => Ok(ClassType::CH),
        4 => Ok(ClassType::HS),
        // 255 is QCLASS=ANY and may not occur in a resource-record CLASS.
        255 => Err(WireError::InvalidValue {
            field: "CLASS",
            value: u64::from(code),
        }),
        _ => Ok(ClassType::Unknown(code)),
    }
}

pub(crate) fn qclass(code: u16) -> Result<QClassType> {
    Ok(match code {
        1 => QClassType::Class(ClassType::IN),
        3 => QClassType::Class(ClassType::CH),
        4 => QClassType::Class(ClassType::HS),
        255 => QClassType::ANY,
        value => QClassType::Unknown(value),
    })
}

pub(crate) fn record_type(code: u16) -> Result<crate::RecordType> {
    match code {
        1 => Ok(crate::RecordType::A),
        2 => Ok(crate::RecordType::NS),
        3 => Ok(crate::RecordType::MD),
        4 => Ok(crate::RecordType::MF),
        5 => Ok(crate::RecordType::CNAME),
        6 => Ok(crate::RecordType::SOA),
        7 => Ok(crate::RecordType::MB),
        8 => Ok(crate::RecordType::MG),
        9 => Ok(crate::RecordType::MR),
        10 => Ok(crate::RecordType::NULL),
        11 => Ok(crate::RecordType::WKS),
        12 => Ok(crate::RecordType::PTR),
        13 => Ok(crate::RecordType::HINFO),
        14 => Ok(crate::RecordType::MINFO),
        15 => Ok(crate::RecordType::MX),
        16 => Ok(crate::RecordType::TXT),
        24 => Ok(crate::RecordType::SIG),
        25 => Ok(crate::RecordType::KEY),
        28 => Ok(crate::RecordType::AAAA),
        33 => Ok(crate::RecordType::SRV),
        39 => Ok(crate::RecordType::DNAME),
        41 => Ok(crate::RecordType::OPT),
        43 => Ok(crate::RecordType::DS),
        46 => Ok(crate::RecordType::RRSIG),
        47 => Ok(crate::RecordType::NSEC),
        48 => Ok(crate::RecordType::DNSKEY),
        50 => Ok(crate::RecordType::NSEC3),
        51 => Ok(crate::RecordType::NSEC3PARAM),
        52 => Ok(crate::RecordType::TLSA),
        53 => Ok(crate::RecordType::SMIMEA),
        62 => Ok(crate::RecordType::CSYNC),
        250 => Ok(crate::RecordType::TSIG),
        257 => Ok(crate::RecordType::CAA),
        // RFC 1035 §3.2.3 and RFC 1995 reserve these values for QTYPE
        // only; a TYPE field in a resource record is a strict subset of
        // QTYPE.
        251..=255 => Err(WireError::InvalidValue {
            field: "TYPE",
            value: u64::from(code),
        }),
        _ => Ok(crate::RecordType::Unknown(code)),
    }
}

pub(crate) fn query_type(code: u16) -> Result<QueryType> {
    Ok(QueryType::from(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(qtype: QueryType, qclass: QClassType) -> Question {
        Question {
            qname: crate::DomainName::root(),
            qtype,
            qclass,
        }
    }

    /// The wire codec and the protocol types each map TYPE/QTYPE codes to
    /// enum variants; the two tables must agree exactly or one of them can
    /// silently mis-encode a record the other accepts.
    #[test]
    fn wire_code_tables_agree_with_the_protocol_type_conversions() {
        for code in (1..=16u16).chain([28, 33, 62, 250, 257]) {
            let record_type = record_type(code).unwrap();
            assert_eq!(u16::from(record_type), code);
            let query_type = query_type(code).unwrap();
            assert_eq!(query_type.value(), code);
        }
        for code in 251..=255u16 {
            assert!(record_type(code).is_err());
            assert_eq!(query_type(code).unwrap().value(), code);
        }
    }

    #[test]
    fn preserves_unassigned_question_codes() {
        let question = Question::from_wire(&[0, 0, 29, 0, 42]).unwrap();
        assert_eq!(question.qtype, QueryType::Unknown(29));
        assert_eq!(question.qclass, QClassType::Unknown(42));
        assert_eq!(question.into_wire().unwrap(), [0, 0, 29, 0, 42]);
    }

    /// RFC 6895 §3.2 makes the former CSNET assignment available for a future
    /// data CLASS, so code 2 has no assigned mnemonic and uses generic values.
    #[test]
    fn preserves_unassigned_class_2() {
        assert_eq!(class(2).unwrap(), ClassType::Unknown(2));

        let question = Question::from_wire(&[0, 0, 1, 0, 2]).unwrap();
        assert_eq!(question.qclass, QClassType::Unknown(2));
        assert_eq!(question.into_wire().unwrap(), [0, 0, 1, 0, 2]);
    }

    /// RFC 1035 §3.2.3/§3.2.5 and RFC 1995: QTYPE 251–255 (IXFR, AXFR,
    /// MAILB, MAILA, \*) and QCLASS \* (255) are valid only in the question
    /// section and must round-trip through the question codec with their defined
    /// codes.
    #[test]
    fn round_trips_query_only_qtype_and_qclass_codes() {
        for qtype in [
            QueryType::IXFR,
            QueryType::AXFR,
            QueryType::MAILB,
            QueryType::MAILA,
            QueryType::ANY,
        ] {
            let question = question(qtype, QClassType::ANY);
            let wire = question.into_wire().unwrap();
            assert_eq!(&wire[1..3], &qtype.value().to_be_bytes());
            assert_eq!(&wire[3..5], &[0, 255]);
            let decoded = Question::from_wire(&wire).unwrap();
            assert_eq!(decoded.qtype, qtype);
            assert_eq!(decoded.qclass, QClassType::ANY);
        }
    }

    #[test]
    fn rejects_known_or_reserved_qtype_codes_wrapped_as_unknown() {
        for value in [0, u16::MAX]
            .into_iter()
            .chain(1..=16)
            .chain([28, 33, 62])
            .chain([257])
            .chain(251..=255)
        {
            assert!(matches!(
                question(
                    QueryType::Unknown(value),
                    QClassType::Class(ClassType::IN)
                )
                .into_wire(),
                Err(WireError::InvalidValue {
                    field: "QTYPE",
                    value: actual
                }) if actual == u64::from(value)
            ));
        }
    }

    #[test]
    fn rejects_known_or_reserved_qclass_codes_wrapped_as_unknown() {
        for value in [0, 1, 3, 4, 255, u16::MAX] {
            assert!(matches!(
                question(QueryType::A, QClassType::Unknown(value)).into_wire(),
                Err(WireError::InvalidValue {
                    field: "QCLASS",
                    value: actual
                }) if actual == u64::from(value)
            ));
        }
    }

    #[test]
    fn rejects_noncanonical_class_unknown_values_in_qclass() {
        for value in [1, 2, 3, 4, 42, 255, u16::MAX] {
            assert!(matches!(
                question(
                    QueryType::A,
                    QClassType::Class(ClassType::Unknown(value))
                )
                .into_wire(),
                Err(WireError::InvalidValue {
                    field: "QCLASS",
                    value: actual
                }) if actual == u64::from(value)
            ));
        }
    }
}
