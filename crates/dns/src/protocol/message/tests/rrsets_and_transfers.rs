use super::*;

#[test]
fn strict_validation_rejects_malformed_or_repeated_rrsets() {
    let response = |answers: Vec<ResourceRecord>, authorities: Vec<ResourceRecord>| {
        Message::builder()
            .headers(Headers {
                qr: true,
                ..Headers::default()
            })
            .answers(answers)
            .authorities(authorities)
            .build()
    };

    assert!(matches!(
        response(vec![a_record(60, 1), a_record(30, 2)], vec![]),
        Err(MessageValidationError::InvalidRecord {
            error: RecordValidationError::InconsistentTtl { .. },
            ..
        })
    ));
    assert!(matches!(
        response(vec![a_record(60, 1), a_record(60, 1)], vec![]),
        Err(MessageValidationError::InvalidRecord {
            error: RecordValidationError::DuplicateRecord,
            ..
        })
    ));
    assert!(matches!(
        response(vec![a_record(60, 1)], vec![a_record(60, 2)]),
        Err(MessageValidationError::InvalidRecord {
            error: RecordValidationError::DuplicateRrSetAcrossSections,
            ..
        })
    ));
}

#[test]
fn strict_validation_does_not_treat_rrsigs_as_an_rrset() {
    let response = |answers: Vec<ResourceRecord>, authorities: Vec<ResourceRecord>| {
        Message::builder()
            .headers(Headers {
                qr: true,
                ..Headers::default()
            })
            .answers(answers)
            .authorities(authorities)
            .build()
    };

    assert!(response(vec![rrsig_record(60, 1)], vec![rrsig_record(30, 2)]).is_ok());
    assert!(matches!(
        response(vec![rrsig_record(60, 1), rrsig_record(30, 1)], vec![]),
        Err(MessageValidationError::InvalidRecord {
            error: RecordValidationError::DuplicateRecord,
            ..
        })
    ));
}

#[test]
fn strict_validation_enforces_cname_coexistence_rules() {
    let owner = DomainName::from_labels(vec![b"alias".to_vec()]).unwrap();
    let cname = |target: &[u8]| ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::CNAME,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: crate::RData::CNAME(DomainName::from_labels(vec![target.to_vec()]).unwrap()),
    };
    let response = |answers| {
        Message::builder()
            .headers(Headers {
                qr: true,
                ..Headers::default()
            })
            .answers(answers)
            .build()
    };

    assert!(matches!(
        response(vec![cname(b"one"), cname(b"two")]),
        Err(MessageValidationError::InvalidRecord {
            error: RecordValidationError::MultipleCnameRecords,
            ..
        })
    ));
    assert!(matches!(
        response(vec![
            cname(b"one"),
            ResourceRecord {
                name: owner.clone(),
                ..a_record(60, 1)
            },
        ]),
        Err(MessageValidationError::InvalidRecord {
            error: RecordValidationError::CnameWithOtherData,
            ..
        })
    ));

    let mut signed_cname = vec![cname(b"one")];
    signed_cname.push(legacy_sig_record(owner.clone(), 60, 24));
    signed_cname.push(ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::KEY,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: crate::RData::KEY(crate::Key {
            flags: 0,
            protocol: 3,
            algorithm: 1,
            public_key: vec![25],
        }),
    });
    signed_cname.push(ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::RRSIG,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: rrsig_rdata(5, 60, 46),
    });
    signed_cname.push(ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::NSEC,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: crate::RData::NSEC(crate::Nsec {
            next_domain_name: DomainName::root(),
            type_bitmap: crate::TypeBitmap::new([5, 46, 47]).unwrap(),
        }),
    });
    signed_cname.extend([30].map(|code| ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::Unknown(code),
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: crate::RData::Unknown(vec![code as u8]),
    }));
    assert!(response(signed_cname).is_ok());
}

#[test]
fn strict_validation_enforces_transfer_fields_and_boundary_soa_duplicate() {
    let soa = ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::SOA,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: crate::RData::SOA {
            mname: DomainName::root(),
            rname: DomainName::root(),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        },
    };
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: soa.name.clone(),
            qtype: QueryType::AXFR,
            qclass: crate::QClassType::Class(crate::ClassType::IN),
        }])
        .answers([soa.clone(), a_record(60, 1), soa])
        .build()
        .unwrap();

    let mut extended_error = message.clone();
    extended_error.additionals.push(
        Edns {
            extended_rcode: 1,
            ..Edns::default()
        }
        .into_record(),
    );
    assert_eq!(extended_error.extended_rcode(), 16);
    assert!(matches!(
        extended_error.validate_strict(),
        Err(MessageValidationError::InvalidRecord {
            section: "answer",
            index: 2,
            error: RecordValidationError::DuplicateRecord,
        })
    ));

    let mut ixfr_fallback = message.clone();
    ixfr_fallback.questions[0].qtype = QueryType::IXFR;
    assert!(ixfr_fallback.validate_strict().is_ok());
    for field in 0..3 {
        let mut invalid = ixfr_fallback.clone();
        match field {
            0 => invalid.headers.opcode = OpCode::Status,
            1 => invalid.headers.rcode = RCode::NameError,
            2 => {
                invalid.headers.qr = false;
                invalid.headers.aa = false;
            }
            _ => unreachable!(),
        }
        assert!(invalid.validate_strict().is_err());
    }

    for field in 0..6 {
        let mut invalid = message.clone();
        match field {
            0 => invalid.headers.aa = false,
            1 => invalid.headers.tc = true,
            2 => invalid.headers.ad = true,
            3 => invalid.headers.cd = true,
            4 => invalid.headers.opcode = OpCode::Status,
            5 => invalid.authorities.push(a_record(60, 2)),
            _ => unreachable!(),
        }
        assert!(matches!(
            invalid.validate_strict(),
            Err(MessageValidationError::InvalidAxfrResponseFields)
        ));
    }
}
