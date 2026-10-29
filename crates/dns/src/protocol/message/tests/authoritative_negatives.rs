use super::*;

#[test]
fn strict_validation_enforces_authoritative_negative_and_any_class_semantics() {
    let question = Question {
        qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        qtype: QueryType::A,
        qclass: crate::QClassType::Class(crate::ClassType::IN),
    };
    let mut response = Message {
        headers: Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        questions: vec![question],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    assert_eq!(
        response.validate_strict(),
        Err(MessageValidationError::InvalidAuthoritativeNegativeResponse)
    );

    response.authorities.push(ResourceRecord {
        name: response.questions[0].qname.clone(),
        rtype: RecordType::SOA,
        class: crate::ClassType::IN,
        ttl: 31,
        rdata: crate::RData::SOA {
            mname: DomainName::root(),
            rname: DomainName::root(),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 30,
        },
    });
    assert_eq!(
        response.validate_strict(),
        Err(MessageValidationError::InvalidAuthoritativeNegativeResponse)
    );
    response.authorities[0].ttl = 30;
    assert!(response.validate_strict().is_ok());
    response.authorities[0].class = crate::ClassType::CH;
    assert_eq!(
        response.validate_strict(),
        Err(MessageValidationError::InvalidAuthoritativeNegativeResponse)
    );
    response.authorities[0].class = crate::ClassType::IN;

    response.headers.rcode = RCode::Ok;
    response.questions[0].qclass = crate::QClassType::ANY;
    response.answers.push(a_record(30, 1));
    response.authorities.clear();
    assert_eq!(
        response.validate_strict(),
        Err(MessageValidationError::AuthoritativeAnyClass)
    );
}

#[test]
fn authoritative_badvers_is_not_treated_as_nodata() {
    let response = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            rcode: RCode::Ok,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::A,
            qclass: crate::QClassType::Class(crate::ClassType::IN),
        }])
        .additionals([Edns {
            extended_rcode: 1,
            ..Edns::default()
        }
        .into_record()])
        .build_unchecked();

    assert_eq!(response.extended_rcode(), 16);
    assert!(response.validate_strict().is_ok());
}

#[test]
fn extended_error_with_name_error_low_nibble_is_not_treated_as_nxdomain() {
    let response = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::A,
            qclass: crate::QClassType::Class(crate::ClassType::IN),
        }])
        .answers([a_record(30, 1)])
        .additionals([Edns {
            extended_rcode: 1,
            ..Edns::default()
        }
        .into_record()])
        .build_unchecked();

    assert_eq!(response.extended_rcode(), 19);
    assert!(response.validate_strict().is_ok());
}

#[test]
fn authoritative_nxdomain_rejects_positive_answers_across_outbound_paths() {
    let question = Question {
        qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        qtype: QueryType::A,
        qclass: crate::QClassType::Class(crate::ClassType::IN),
    };
    let soa = ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::SOA,
        class: crate::ClassType::IN,
        ttl: 30,
        rdata: crate::RData::SOA {
            mname: DomainName::root(),
            rname: DomainName::root(),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 30,
        },
    };
    let builder = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        })
        .questions([question])
        .answers([a_record(30, 1)])
        .authorities([soa]);
    let response = builder.clone().build_unchecked();

    assert_eq!(
        response.validate_strict(),
        Err(MessageValidationError::InvalidAuthoritativeNegativeResponse)
    );
    assert!(matches!(
        builder.build(),
        Err(MessageValidationError::InvalidAuthoritativeNegativeResponse)
    ));
    assert!(response.into_wire().is_err());
}

#[test]
fn authoritative_cname_negatives_with_signatures_validate_against_the_final_target_zone() {
    let alias = DomainName::from_labels(vec![b"www".to_vec(), b"alias".to_vec()]).unwrap();
    let target = DomainName::from_labels(vec![b"missing".to_vec(), b"other".to_vec()]).unwrap();
    let other = DomainName::from_labels(vec![b"other".to_vec()]).unwrap();
    for rcode in [RCode::NameError, RCode::Ok] {
        let response = Message {
            headers: Headers {
                qr: true,
                aa: true,
                rcode,
                ..Headers::default()
            },
            questions: vec![Question {
                qname: alias.clone(),
                qtype: QueryType::A,
                qclass: crate::QClassType::Class(crate::ClassType::IN),
            }],
            answers: vec![
                ResourceRecord {
                    name: alias.clone(),
                    rtype: RecordType::CNAME,
                    class: crate::ClassType::IN,
                    ttl: 30,
                    rdata: crate::RData::CNAME(target.clone()),
                },
                ResourceRecord {
                    name: alias.clone(),
                    rtype: RecordType::SIG,
                    class: crate::ClassType::IN,
                    ttl: 30,
                    rdata: crate::RData::SIG(crate::Sig {
                        type_covered: 5,
                        algorithm: 1,
                        labels: 2,
                        original_ttl: 30,
                        signature_expiration: 2,
                        signature_inception: 1,
                        key_tag: 1,
                        signer_name: DomainName::root(),
                        signature: vec![24],
                    }),
                },
                ResourceRecord {
                    name: alias.clone(),
                    rtype: RecordType::RRSIG,
                    class: crate::ClassType::IN,
                    ttl: 30,
                    rdata: rrsig_rdata(5, 30, 46),
                },
            ],
            authorities: vec![ResourceRecord {
                name: other.clone(),
                rtype: RecordType::SOA,
                class: crate::ClassType::IN,
                ttl: 30,
                rdata: crate::RData::SOA {
                    mname: DomainName::root(),
                    rname: DomainName::root(),
                    serial: 1,
                    refresh: 2,
                    retry: 3,
                    expire: 4,
                    minimum: 30,
                },
            }],
            additionals: Vec::new(),
        };

        assert!(response.validate_strict().is_ok());
        assert!(response.into_wire().is_ok());
    }
}

#[test]
fn authoritative_nxdomain_allows_signature_only_answers() {
    let name = DomainName::from_labels(vec![b"example".to_vec()]).unwrap();
    let response = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        })
        .questions([Question {
            qname: name.clone(),
            qtype: QueryType::A,
            qclass: crate::QClassType::Class(crate::ClassType::IN),
        }])
        .answers([
            legacy_sig_record(name.clone(), 30, 24),
            ResourceRecord {
                name: name.clone(),
                rtype: RecordType::RRSIG,
                class: crate::ClassType::IN,
                ttl: 30,
                rdata: rrsig_rdata(1, 30, 46),
            },
        ])
        .authorities([ResourceRecord {
            name,
            rtype: RecordType::SOA,
            class: crate::ClassType::IN,
            ttl: 30,
            rdata: crate::RData::SOA {
                mname: DomainName::root(),
                rname: DomainName::root(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 30,
            },
        }])
        .build()
        .unwrap();

    assert!(response.validate_strict().is_ok());
    assert!(response.into_wire().is_ok());
}
