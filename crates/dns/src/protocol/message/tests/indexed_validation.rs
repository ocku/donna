use super::*;

const PREFIX_LEN: usize = 40;

fn response_with_prefix() -> Message {
    Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: (0..PREFIX_LEN)
            .map(|index| ResourceRecord {
                name: DomainName::from_dotted(&format!("filler{index}.example.")).unwrap(),
                ..a_record(60, index as u8)
            })
            .collect(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn error(message: &Message) -> RecordValidationError {
    match message.validate_for_forwarding().unwrap_err() {
        MessageValidationError::InvalidRecord { error, .. } => error,
        other => panic!("unexpected validation failure: {other:?}"),
    }
}

#[test]
fn inline_overflow_and_indexed_checks_keep_error_order() {
    for prefix in [0, 1, 7, 8, 9, 31, 32, 33, 40] {
        let mut message = response_with_prefix();
        message.answers.truncate(prefix);
        message.answers.extend([a_record(60, 1), a_record(30, 1)]);
        assert!(matches!(
            message.validate_for_forwarding(),
            Err(MessageValidationError::InvalidRecord {
                section: "answer",
                index,
                error: RecordValidationError::InconsistentTtl { expected: 60, actual: 30 },
            }) if index == prefix + 1
        ));
        let record = message.answers.pop().unwrap();
        message.authorities.push(record);
        assert_eq!(
            error(&message),
            RecordValidationError::DuplicateRrSetAcrossSections
        );
        message.authorities.clear();
        message.answers.push(a_record(60, 1));
        assert_eq!(error(&message), RecordValidationError::DuplicateRecord);
    }
}

#[test]
fn indexed_rrsets_preserve_name_class_and_label_identity() {
    let mut message = response_with_prefix();
    let mut first = a_record(60, 1);
    first.name = DomainName::from_dotted("MiXeD.example.").unwrap();
    let mut duplicate = first.clone();
    duplicate.name = DomainName::from_dotted("mixed.EXAMPLE.").unwrap();
    message.answers.extend([first, duplicate.clone()]);
    assert_eq!(error(&message), RecordValidationError::DuplicateRecord);

    // Distinct classes and literal label boundaries remain distinct owners.
    message.answers.pop();
    duplicate.class = crate::ClassType::CH;
    duplicate.rdata = RData::Unknown(vec![1, 2, 3, 4]);
    message.answers.push(duplicate);
    message.answers.push(ResourceRecord {
        name: DomainName::from_labels(vec![b"mixed.example".to_vec()]).unwrap(),
        ..a_record(60, 1)
    });
    assert!(message.validate_for_forwarding().is_ok());
}

#[test]
fn indexed_rrsets_preserve_ttl_and_section_error_priority() {
    let mut message = response_with_prefix();
    message.answers.push(a_record(60, 1));
    message.answers.push(a_record(30, 1));
    assert_eq!(
        error(&message),
        RecordValidationError::InconsistentTtl {
            expected: 60,
            actual: 30
        }
    );
    let record = message.answers.pop().unwrap();
    message.authorities.push(record);
    assert_eq!(
        error(&message),
        RecordValidationError::DuplicateRrSetAcrossSections
    );
}

#[test]
fn indexed_duplicates_keep_dns_name_equality_and_exact_caa_tags() {
    let mut message = response_with_prefix();
    let ns = |target: &str| ResourceRecord {
        rtype: RecordType::NS,
        rdata: RData::NS(DomainName::from_dotted(target).unwrap()),
        ..a_record(60, 1)
    };
    message
        .answers
        .extend([ns("Ns1.example."), ns("ns1.EXAMPLE.")]);
    assert_eq!(error(&message), RecordValidationError::DuplicateRecord);
    message.answers.truncate(PREFIX_LEN);
    let caa = |tag: &[u8]| ResourceRecord {
        rtype: RecordType::CAA,
        rdata: RData::CAA(Caa {
            flags: 0,
            tag: tag.to_vec(),
            value: b"ca.example".to_vec(),
        }),
        ..a_record(60, 1)
    };
    message.answers.extend([caa(b"issue"), caa(b"ISSUE")]);
    assert!(message.validate_for_forwarding().is_ok());
    message.answers.push(caa(b"issue"));
    assert_eq!(error(&message), RecordValidationError::DuplicateRecord);
}

#[test]
fn indexed_signatures_retain_covered_types_and_cross_section_rules() {
    let mut message = response_with_prefix();
    message.answers.push(rrsig_record(60, 1));
    let mut other_type = rrsig_record(30, 1);
    if let RData::RRSIG(signature) = &mut other_type.rdata {
        signature.type_covered = 28;
    }
    message.authorities.push(other_type);
    assert!(message.validate_for_forwarding().is_ok());
    message.authorities.push(rrsig_record(30, 1));
    assert_eq!(error(&message), RecordValidationError::DuplicateRecord);
}

#[test]
fn indexed_cname_checks_preserve_companions_and_owner_conflicts() {
    let cname = |target: &str| ResourceRecord {
        rtype: RecordType::CNAME,
        rdata: RData::CNAME(DomainName::from_dotted(target).unwrap()),
        ..a_record(60, 1)
    };
    let mut message = response_with_prefix();
    message
        .answers
        .extend([cname("target.example."), rrsig_record(60, 1)]);
    assert!(message.validate_for_forwarding().is_ok());
    message.answers.push(cname("other.example."));
    assert_eq!(error(&message), RecordValidationError::MultipleCnameRecords);
    message.answers.pop();
    message.answers.push(a_record(60, 1));
    assert_eq!(error(&message), RecordValidationError::CnameWithOtherData);
    message.answers.swap(PREFIX_LEN, PREFIX_LEN + 2);
    assert_eq!(error(&message), RecordValidationError::CnameWithOtherData);
}

fn soa(serial: u32) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_dotted("example.").unwrap(),
        rtype: RecordType::SOA,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: RData::SOA {
            mname: DomainName::root(),
            rname: DomainName::root(),
            serial,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        },
    }
}

#[test]
fn indexed_axfr_keeps_only_the_boundary_soa_duplicate_exception() {
    let mut message = response_with_prefix();
    message.headers.aa = true;
    message.questions.push(Question {
        qname: soa(1).name,
        qtype: QueryType::AXFR,
        qclass: crate::QClassType::Class(crate::ClassType::IN),
    });
    message.answers.insert(0, soa(1));
    message.answers.push(soa(1));
    assert!(message.validate_for_forwarding().is_ok());
    message.additionals.push(
        Edns {
            extended_rcode: 1,
            ..Edns::default()
        }
        .into_record(),
    );
    assert_eq!(error(&message), RecordValidationError::DuplicateRecord);
}

#[test]
fn indexed_ixfr_resets_all_record_indexes_at_operation_boundaries() {
    let mut message = response_with_prefix();
    let question = Question {
        qname: soa(1).name,
        qtype: QueryType::IXFR,
        qclass: crate::QClassType::Class(crate::ClassType::IN),
    };
    let mut next_operation = message.answers.clone();
    for record in &mut next_operation {
        record.ttl = 30;
    }
    message.answers.insert(0, soa(1));
    message.answers.push(soa(2));
    message.answers.extend(next_operation);
    assert!(message.validate_ixfr(&question).is_ok());
    let duplicate = message.answers.last().unwrap().clone();
    message.answers.push(duplicate);
    assert!(matches!(
        message.validate_ixfr(&question),
        Err(MessageValidationError::InvalidRecord {
            error: RecordValidationError::DuplicateRecord,
            ..
        })
    ));
}

#[test]
fn indexed_large_rrset_detects_a_late_duplicate_without_losing_ttl_rules() {
    let mut message = response_with_prefix();
    message.answers = (0..2048)
        .map(|index| ResourceRecord {
            rdata: RData::A(std::net::Ipv4Addr::from(0xc0000200 + index)),
            ..a_record(60, 1)
        })
        .collect();
    assert!(message.validate_for_forwarding().is_ok());
    message.answers.push(message.answers[1024].clone());
    assert_eq!(error(&message), RecordValidationError::DuplicateRecord);
}
