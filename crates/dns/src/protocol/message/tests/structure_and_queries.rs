use super::*;

#[test]
fn section_counts_are_derived_and_enforce_the_u16_boundary() {
    let mut message = Message::builder().build().unwrap();

    assert_eq!(
        message.section_counts().unwrap(),
        SectionCounts {
            questions: 0,
            answers: 0,
            authorities: 0,
            additionals: 0,
        }
    );

    let question = Question {
        qname: DomainName::root(),
        qtype: QueryType::A,
        qclass: crate::QClassType::Class(crate::ClassType::IN),
    };
    message.questions = vec![question; usize::from(u16::MAX)];
    assert_eq!(message.section_counts().unwrap().questions, u16::MAX);

    let extra = message.questions[0].clone();
    message.questions.push(extra);
    assert_eq!(
        message.section_counts(),
        Err(SectionTooLongError {
            section: "question",
            length: usize::from(u16::MAX) + 1,
        })
    );
}

#[test]
fn strict_validation_enforces_tsig_cardinality_placement_and_request_fields() {
    let key_name = DomainName::from_labels(vec![b"key".to_vec()]).unwrap();
    let tsig_record = ResourceRecord {
        name: key_name,
        rtype: RecordType::TSIG,
        class: crate::ClassType::Unknown(255),
        ttl: 0,
        rdata: RData::TSIG(crate::Tsig {
            algorithm: crate::TsigAlgorithm::HmacSha256.name(),
            time_signed: 1,
            fudge: 300,
            mac: vec![0; 16],
            original_id: 7,
            error: crate::TsigErrorCode::NoError,
            other_data: Vec::new(),
        }),
    };
    let mut message = Message::builder()
        .headers(Headers {
            id: 7,
            ..Headers::default()
        })
        .additionals([tsig_record.clone()])
        .build()
        .unwrap();

    message.answers.push(tsig_record.clone());
    assert_eq!(
        message.validate_strict(),
        Err(MessageValidationError::TsigOutsideAdditional)
    );
    message.answers.clear();

    message.additionals.push(tsig_record.clone());
    assert_eq!(
        message.validate_strict(),
        Err(MessageValidationError::MultipleTsig)
    );
    message.additionals.pop();

    message.additionals.push(ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::Unknown(127),
        class: crate::ClassType::IN,
        ttl: 0,
        rdata: RData::Unknown(Vec::new()),
    });
    assert_eq!(
        message.validate_strict(),
        Err(MessageValidationError::TsigNotLast)
    );
    message.additionals.pop();

    let RData::TSIG(tsig) = &mut message.additionals[0].rdata else {
        unreachable!()
    };
    tsig.original_id = 8;
    assert_eq!(
        message.validate_strict(),
        Err(MessageValidationError::InvalidTsigMessage)
    );
}

#[test]
fn strict_validation_allows_only_padded_empty_transfer_responses() {
    let mut edns = Edns::new(1232);
    edns.set_padding(0);
    let response = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::AXFR,
            qclass: crate::QClassType::Class(crate::ClassType::IN),
        }])
        .additionals([edns.into_record()])
        .build()
        .unwrap();

    assert!(response.into_wire().is_ok());

    let mut questionless = response.clone();
    questionless.questions.clear();
    let wire = questionless.into_wire().unwrap();
    let decoded = Message::from_wire(&wire).unwrap();
    assert!(decoded.questions.is_empty());
    assert!(decoded.answers.is_empty());
    assert!(decoded.edns().unwrap().unwrap().padding().is_some());

    let unpadded = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::AXFR,
            qclass: crate::QClassType::Class(crate::ClassType::IN),
        }])
        .additionals([Edns::new(1232).into_record()])
        .build();

    assert!(matches!(
        unpadded,
        Err(MessageValidationError::InvalidAuthoritativeNegativeResponse)
    ));
}

#[test]
fn strict_validation_enforces_query_header_semantics() {
    for headers in [
        Headers {
            aa: true,
            ..Headers::default()
        },
        Headers {
            tc: true,
            ..Headers::default()
        },
        Headers {
            ra: true,
            ..Headers::default()
        },
        Headers {
            rcode: RCode::FormatError,
            ..Headers::default()
        },
    ] {
        let message = Message::builder().headers(headers).build_unchecked();
        assert!(matches!(
            message.validate_strict(),
            Err(MessageValidationError::ResponseOnlyQueryFields)
        ));
    }
}

#[test]
fn local_message_construction_rejects_reserved_caa_flags_but_forwarding_accepts_them() {
    let caa = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::CAA,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: crate::RData::CAA(Caa {
            flags: 0x01,
            tag: b"issue".to_vec(),
            value: b"ca.example".to_vec(),
        }),
    };
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .answers([caa])
        .build_unchecked();

    assert!(matches!(
        message.validate_strict(),
        Err(MessageValidationError::InvalidRecord {
            error: RecordValidationError::ReservedCaaFlags { value: 0x01 },
            ..
        })
    ));
    assert!(message.validate_for_forwarding().is_ok());
    assert!(message.into_wire().is_ok());
}

#[test]
fn forwarding_preserves_case_distinct_caa_tag_octets() {
    let mut wire = vec![
        0x12, 0x34, 0x80, 0x00, // ID and response flags
        0x00, 0x00, 0x00, 0x02, // zero questions, two answers
        0x00, 0x00, 0x00, 0x00, // zero authority and additional records
    ];
    for tag in [b"issue", b"ISSUE"] {
        wire.extend_from_slice(&[
            0x00, // root owner
            0x01, 0x01, // CAA
            0x00, 0x01, // IN
            0x00, 0x00, 0x00, 0x3c, // TTL 60
            0x00, 0x11, // RDLENGTH 17
            0x00, 0x05, // flags and tag length
        ]);
        wire.extend_from_slice(tag);
        wire.extend_from_slice(b"ca.example");
    }

    let decoded = Message::from_wire(&wire).unwrap();
    assert!(decoded.validate_for_forwarding().is_ok());
    let tags = decoded
        .answers
        .iter()
        .map(|record| match &record.rdata {
            crate::RData::CAA(caa) => caa.tag.as_slice(),
            _ => panic!("answer did not contain CAA RDATA"),
        })
        .collect::<Vec<_>>();
    assert_eq!(tags, [b"issue".as_slice(), b"ISSUE".as_slice()]);

    let reencoded = decoded.into_wire().unwrap();
    let forwarded = Message::from_wire(&reencoded).unwrap();
    assert!(matches!(
        forwarded.answers.as_slice(),
        [
            ResourceRecord {
                rdata: crate::RData::CAA(first),
                ..
            },
            ResourceRecord {
                rdata: crate::RData::CAA(second),
                ..
            }
        ] if first.tag == b"issue" && second.tag == b"ISSUE"
    ));
}

#[test]
fn message_encoding_rejects_a_directly_constructed_invalid_caa_tag() {
    let caa = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::CAA,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: crate::RData::CAA(Caa {
            flags: 0,
            tag: b"iss-ue".to_vec(),
            value: b"opaque\0value".to_vec(),
        }),
    };
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .answers([caa])
        .build_unchecked();

    assert!(matches!(
        message.into_wire(),
        Err(crate::wire::WireError::InvalidRData {
            record_type: "CAA",
            detail: "property tag must contain only ASCII letters and digits",
        })
    ));
}

#[test]
fn strict_validation_enforces_query_and_iquery_request_sections() {
    let answer = a_record(60, 1);
    for message in [
        Message::builder()
            .answers([answer.clone()])
            .build_unchecked(),
        Message::builder()
            .authorities([answer.clone()])
            .build_unchecked(),
    ] {
        assert_eq!(
            message.validate_strict(),
            Err(MessageValidationError::InvalidQueryRequestSections)
        );
    }

    let zone = DomainName::from_labels(vec![b"example".to_vec()]).unwrap();
    let ixfr_soa = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::SOA,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: crate::RData::SOA {
            mname: DomainName::root(),
            rname: DomainName::root(),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 1,
        },
    };
    let ixfr = Message::builder()
        .questions([Question {
            qname: zone,
            qtype: QueryType::IXFR,
            qclass: crate::QClassType::Class(crate::ClassType::IN),
        }])
        .authorities([ixfr_soa.clone()])
        .build()
        .unwrap();
    assert!(ixfr.validate_strict().is_ok());

    let mut missing_soa = ixfr.clone();
    missing_soa.authorities.clear();
    let mut extra_soa = ixfr.clone();
    extra_soa.authorities.push(ixfr_soa.clone());
    let mut wrong_owner = ixfr.clone();
    wrong_owner.authorities[0].name = DomainName::root();
    let mut wrong_class = ixfr.clone();
    wrong_class.authorities[0].class = crate::ClassType::CH;
    for invalid in [missing_soa, extra_soa, wrong_owner, wrong_class] {
        assert_eq!(
            invalid.validate_strict(),
            Err(MessageValidationError::InvalidQueryRequestSections)
        );
    }

    let inverse = Message::builder()
        .headers(Headers {
            opcode: OpCode::IQuery,
            ..Headers::default()
        })
        .answers([answer.clone()])
        .build()
        .unwrap();
    for invalid in 0..4 {
        let mut message = inverse.clone();
        match invalid {
            0 => message.questions.push(Question {
                qname: DomainName::root(),
                qtype: QueryType::A,
                qclass: crate::QClassType::Class(crate::ClassType::IN),
            }),
            1 => message.answers.clear(),
            2 => message.authorities.push(answer.clone()),
            3 => message.additionals.push(answer.clone()),
            _ => unreachable!(),
        }
        assert_eq!(
            message.validate_strict(),
            Err(MessageValidationError::InvalidIqueryRequestSections)
        );
    }
}
