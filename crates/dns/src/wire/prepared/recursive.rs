use super::*;

impl EncodedReply {
    /// Encodes selected recursive positive components without cloning records.
    ///
    /// Each supplied TTL must not exceed its immutable record's TTL. The full
    /// ordinary record and RRset checks use those effective TTLs before writing.
    /// No cached bytes are concatenated and compression uses one fresh encoder.
    /// Unsupported shapes return `None` for same-selection ordinary handling.
    /// Oversized replies retain all selected records for whole-RRset truncation.
    ///
    /// # Errors
    /// Returns the ordinary validation or encoding error for supported replies.
    pub fn recursive_positive(
        request: &Message,
        answers: &[(&ResourceRecord, u32)],
        authorities: &[(&ResourceRecord, u32)],
        authenticated: bool,
        maximum: usize,
    ) -> Result<Option<Self>> {
        Self::recursive_reply(request, answers, authorities, authenticated, maximum, None)
    }

    /// Encodes selected recursive negative components without cloning records.
    ///
    /// Answers may contain a complete CNAME chain and its signatures. A checked
    /// SOA must enclose its terminal name with an effective TTL no greater than
    /// MINIMUM. Supplied records still undergo ordinary RRset validation;
    /// cryptographic authentication and proof selection remain caller duties.
    /// Unsupported shapes retain same-selection ordinary handling. Oversized
    /// encodings retain complete RRsets for the transport's normal truncation.
    ///
    /// # Errors
    /// Returns ordinary record, RRset, negative-scope or encoding errors.
    pub fn recursive_negative(
        request: &Message,
        answers: &[(&ResourceRecord, u32)],
        authorities: &[(&ResourceRecord, u32)],
        name_error: bool,
        authenticated: bool,
        maximum: usize,
    ) -> Result<Option<Self>> {
        Self::recursive_reply(
            request,
            answers,
            authorities,
            authenticated,
            maximum,
            Some(name_error),
        )
    }

    fn recursive_reply(
        request: &Message,
        answers: &[(&ResourceRecord, u32)],
        authorities: &[(&ResourceRecord, u32)],
        authenticated: bool,
        maximum: usize,
        negative: Option<bool>,
    ) -> Result<Option<Self>> {
        let [question] = request.questions.as_slice() else {
            return Ok(None);
        };
        if request.headers.qr
            || request.headers.opcode != OpCode::Query
            || !request.headers.rd
            || request.validate_for_forwarding().is_err()
            || !matches!(question.qclass, QClassType::Class(_))
            || matches!(
                question.qtype,
                QueryType::AXFR
                    | QueryType::IXFR
                    | QueryType::ANY
                    | QueryType::MAILA
                    | QueryType::MAILB
            )
            || request.additionals.len() > 1
            || (answers.is_empty() && negative.is_none())
            || (negative.is_some() && question.qtype == QueryType::CNAME)
            || answers.len() + authorities.len() > MAX_RECORDS
            || answers.iter().chain(authorities).any(|&(record, ttl)| {
                ttl > record.ttl
                    || record.class.value() != question.qclass.value()
                    || record.rtype.is_meta_type()
                    || matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0())
            })
            || authorities.iter().any(|&(record, _)| {
                !matches!(
                    record.rtype,
                    RecordType::NSEC | RecordType::NSEC3 | RecordType::RRSIG
                ) && !(negative.is_some()
                    && (matches!(
                        record.rtype,
                        RecordType::SOA | RecordType::NS | RecordType::SIG
                    ) || u16::from(record.rtype) == 30))
            })
        {
            return Ok(None);
        }
        if negative.is_some()
            && answers
                .iter()
                .any(|&(record, _)| match (&record.rtype, &record.rdata) {
                    (RecordType::CNAME, RData::CNAME(_)) => false,
                    (RecordType::RRSIG, RData::RRSIG(sig)) => {
                        sig.type_covered != 5
                            || !answers.iter().any(|&(cname, _)| {
                                cname.rtype == RecordType::CNAME && cname.name.eq_dns(&record.name)
                            })
                    }
                    (RecordType::SIG, RData::SIG(sig)) => {
                        sig.type_covered != 5
                            || !answers.iter().any(|&(cname, _)| {
                                cname.rtype == RecordType::CNAME && cname.name.eq_dns(&record.name)
                            })
                    }
                    _ => true,
                })
        {
            return Ok(None);
        }
        let Ok(edns) = request.edns() else {
            return Ok(None);
        };
        if request.additionals.len() != usize::from(edns.is_some())
            || edns.as_ref().is_some_and(|edns| {
                edns.version != 0 || edns.extended_rcode != 0 || !edns.options.is_empty()
            })
        {
            return Ok(None);
        }
        let dnssec_ok = edns.as_ref().is_some_and(|edns| edns.dnssec_ok);
        if !dnssec_ok
            && answers.iter().chain(authorities).any(|&(record, _)| {
                matches!(
                    record.rtype,
                    RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                ) && u16::from(record.rtype) != question.qtype.value()
            })
        {
            return Ok(None);
        }
        let opt = edns.as_ref().map(|_| {
            Edns {
                dnssec_ok,
                ..Edns::default()
            }
            .into_record()
        });
        Message::validate_borrowed_recursive(answers, authorities, opt.as_ref())
            .map_err(super::super::message::message_validation_error_to_wire)?;
        if negative.is_some() {
            Message::validate_borrowed_recursive_negative(question, answers, authorities)
                .map_err(super::super::message::message_validation_error_to_wire)?;
        }
        let headers = crate::Headers {
            id: request.headers.id,
            qr: true,
            rd: true,
            ra: true,
            ad: authenticated && !request.headers.cd && (dnssec_ok || request.headers.ad),
            cd: request.headers.cd,
            rcode: if negative == Some(true) {
                RCode::NameError
            } else {
                RCode::Ok
            },
            ..crate::Headers::default()
        };
        let capacity =
            (12 + question.qname.wire_len() + 4 + (answers.len() + authorities.len() + 1) * 64)
                .clamp(128, MAXIMUM)
                .next_power_of_two();
        let mut encoder = Encoder::with_capacity(capacity);
        super::super::encode_header(
            &headers,
            crate::SectionCounts {
                questions: 1,
                answers: answers.len() as u16,
                authorities: authorities.len() as u16,
                additionals: u16::from(opt.is_some()),
            },
            &mut encoder,
        )?;
        super::super::encode_question(question, &mut encoder)?;
        for &(record, ttl) in answers.iter().chain(authorities) {
            super::super::record::encode_validated_record_with_ttl(record, ttl, &mut encoder)?;
        }
        if let Some(opt) = &opt {
            super::super::encode_validated_record(opt, &mut encoder)?;
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
            rd: true,
            cd: request.headers.cd,
            request_ad: request.headers.ad,
            maximum: maximum.min(MAXIMUM).min(
                edns.as_ref()
                    .map_or(usize::from(Edns::MIN_UDP_PAYLOAD_SIZE), |edns| {
                        usize::from(edns.effective_udp_payload_size())
                    }),
            ),
            request_opt_ttl: request.additionals.first().map(|record| record.ttl),
            has_name_servers: authorities
                .iter()
                .any(|(record, _)| record.rtype == RecordType::NS),
        }))
    }
}
