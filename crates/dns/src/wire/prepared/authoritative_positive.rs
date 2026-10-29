use super::*;
use crate::DomainName;

impl EncodedReply {
    /// Encodes a fully checked authoritative positive without cloning RDATA.
    ///
    /// Each answer supplies its effective owner. The supported projection has
    /// one DNS source owner and one DNS effective owner, with authority owners
    /// disjoint from both; all ordinary RRset checks therefore remain exact.
    /// Unsupported shapes decline for same-selection ordinary handling.
    /// Oversized encodings retain complete RRsets for transport truncation.
    ///
    /// # Errors
    /// Returns ordinary effective-owner record/RRset and encoding errors.
    pub fn authoritative_positive(
        request: &Message,
        answers: &[(&ResourceRecord, &DomainName)],
        authorities: &[&ResourceRecord],
        maximum: usize,
    ) -> Result<Option<Self>> {
        let [question] = request.questions.as_slice() else {
            return Ok(None);
        };
        let Some(&(first, effective)) = answers.first() else {
            return Ok(None);
        };
        if request.headers.qr
            || request.headers.opcode != OpCode::Query
            || request.validate_for_forwarding().is_err()
            || !matches!(question.qclass, QClassType::Class(_))
            || matches!(question.qtype, QueryType::AXFR | QueryType::IXFR)
            || request.additionals.len() > 1
            || answers.len() + authorities.len() > MAX_RECORDS
            || !effective.eq_dns(&question.qname)
            || answers.iter().any(|&(record, owner)| {
                !record.name.eq_dns(&first.name)
                    || !owner.eq_dns(effective)
                    || record.class.value() != question.qclass.value()
                    || record.rtype.is_meta_type()
                    || matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0())
            })
            || authorities.iter().any(|record| {
                record.name.eq_dns(&first.name)
                    || record.name.eq_dns(effective)
                    || record.class.value() != question.qclass.value()
                    || !matches!(
                        record.rtype,
                        RecordType::NSEC | RecordType::NSEC3 | RecordType::RRSIG
                    )
            })
            || !answers.iter().any(|&(record, _)| match question.qtype {
                QueryType::ANY => true,
                QueryType::MAILA => matches!(record.rtype, RecordType::MD | RecordType::MF),
                QueryType::MAILB => matches!(
                    record.rtype,
                    RecordType::MB | RecordType::MG | RecordType::MR
                ),
                qtype => qtype.value() == u16::from(record.rtype),
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
        let opt = edns.as_ref().map(|edns| {
            Edns {
                dnssec_ok: edns.dnssec_ok,
                ..Edns::default()
            }
            .into_record()
        });
        Message::validate_borrowed_authoritative_positive(answers, authorities, opt.as_ref())
            .map_err(super::super::message::message_validation_error_to_wire)?;
        let headers = crate::Headers {
            id: request.headers.id,
            qr: true,
            aa: true,
            rd: request.headers.rd,
            ..crate::Headers::default()
        };
        let capacity = (12
            + question.qname.wire_len()
            + 4
            + (answers.len() + authorities.len() + usize::from(opt.is_some())) * 64)
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
        for &(record, owner) in answers {
            encoder.write_name(owner)?;
            encoder.write_u16(record.rtype.into());
            encoder.write_u16(record.class.value());
            encoder.write_u32(record.ttl);
            encoder.write_rdata(|encoder| {
                super::super::rdata::encode_validated_rdata(&record.rdata, encoder)
            })?;
        }
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
                edns.as_ref()
                    .map_or(usize::from(Edns::MIN_UDP_PAYLOAD_SIZE), |edns| {
                        usize::from(edns.effective_udp_payload_size())
                    }),
            ),
            request_opt_ttl: request.additionals.first().map(|record| record.ttl),
            has_name_servers: false,
        }))
    }
}
