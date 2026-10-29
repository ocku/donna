use super::*;

#[tokio::test]
async fn edns_out_of_zone_refusal_includes_not_authoritative_ede() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["other"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([dns::Edns::new(1232).into_record()])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    let edns = response.edns().unwrap().unwrap();
    // RFC 6891 erratum 8348 restores the RFC 2671 meaning of OPT CLASS:
    // each sender advertises its own receive limit. The server must not copy
    // the requestor's 1232-octet value into its response.
    assert_eq!(
        edns.udp_payload_size,
        dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE
    );
    let errors = edns
        .extended_dns_errors()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].info_code,
        dns::ExtendedDnsErrorCode::NotAuthoritative
    );
}

#[tokio::test]
async fn cname_chains_within_hosted_zones_are_followed_to_the_final_answer() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    name(&["alias", "example"]),
                    RecordType::CNAME,
                    RData::CNAME(name(&["www", "example"])),
                ),
                record(
                    name(&["www", "example"]),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["alias", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert_eq!(response.answers.len(), 2);
    assert!(matches!(
        response.answers[0],
        ResourceRecord {
            rdata: RData::CNAME(_),
            ..
        }
    ));
    assert!(matches!(
        response.answers[1],
        ResourceRecord {
            rdata: RData::A(_),
            ..
        }
    ));
}

#[tokio::test]
async fn cname_chain_ending_in_same_zone_name_error_includes_terminal_negative() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["alias", "example"]),
                RecordType::CNAME,
                RData::CNAME(name(&["missing", "example"])),
            )],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["alias", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::NameError);
    assert!(response.headers.aa);
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::CNAME(target),
            ..
        }] if target.eq_dns(&name(&["missing", "example"]))
    ));
    assert!(matches!(
        response.authorities.as_slice(),
        [ResourceRecord {
            name: owner,
            rtype: RecordType::SOA,
            ttl: 60,
            ..
        }] if owner.eq_dns(&name(&["example"]))
    ));
}

#[tokio::test]
async fn cname_chain_ending_in_cross_zone_name_error_uses_the_terminal_zone_soa() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["alias", "example"]),
                RecordType::CNAME,
                RData::CNAME(name(&["missing", "other"])),
            )],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(name(&["other"]), ClassType::IN, 600, vec![]))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["alias", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::NameError);
    assert!(response.headers.aa);
    assert_eq!(response.answers.len(), 1);
    assert!(matches!(response.answers[0].rdata, RData::CNAME(_)));
    assert!(matches!(
        response.authorities.as_slice(),
        [ResourceRecord {
            name: owner,
            rtype: RecordType::SOA,
            ttl: 60,
            ..
        }] if owner.eq_dns(&name(&["other"]))
    ));
}

#[tokio::test]
async fn cname_chain_ending_in_no_data_includes_the_terminal_zone_soa() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    name(&["alias", "example"]),
                    RecordType::CNAME,
                    RData::CNAME(name(&["target", "example"])),
                ),
                record(
                    name(&["target", "example"]),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["alias", "example"]),
            qtype: QueryType::TXT,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert_eq!(response.answers.len(), 1);
    assert!(matches!(response.answers[0].rdata, RData::CNAME(_)));
    assert!(matches!(
        response.authorities.as_slice(),
        [ResourceRecord {
            name: owner,
            rtype: RecordType::SOA,
            ttl: 60,
            ..
        }] if owner.eq_dns(&name(&["example"]))
    ));
}

#[tokio::test]
async fn circular_cname_references_return_server_failure() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    name(&["first", "example"]),
                    RecordType::CNAME,
                    RData::CNAME(name(&["second", "example"])),
                ),
                record(
                    name(&["second", "example"]),
                    RecordType::CNAME,
                    RData::CNAME(name(&["first", "example"])),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["first", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::ServerFailure);
    assert!(!response.headers.aa);
    // RFC 1035 §4.1.1: RCODE=2 means the server could not process the query,
    // so no answer records may accompany it.
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert!(response.additionals.is_empty());
}

#[tokio::test]
async fn distinguishes_authoritative_nodata_from_name_error() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();

    let nodata = server
        .handle(
            Message::builder()
                .questions([Question {
                    qname: name(&["www", "example"]),
                    qtype: QueryType::TXT,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build()
                .unwrap(),
        )
        .await;
    assert_eq!(nodata.headers.rcode, RCode::Ok);
    assert!(nodata.headers.aa);
    assert!(nodata.answers.is_empty());
    assert!(matches!(
        nodata.authorities.as_slice(),
        [ResourceRecord {
            rtype: RecordType::SOA,
            ttl: 60,
            ..
        }]
    ));

    let name_error = server
        .handle(
            Message::builder()
                .questions([Question {
                    qname: name(&["missing", "example"]),
                    qtype: QueryType::A,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build()
                .unwrap(),
        )
        .await;
    assert_eq!(name_error.headers.rcode, RCode::NameError);
    assert!(name_error.headers.aa);
    assert!(name_error.answers.is_empty());
    assert!(matches!(
        name_error.authorities.as_slice(),
        [ResourceRecord {
            rtype: RecordType::SOA,
            ttl: 60,
            ..
        }]
    ));
}

fn signature(owner: DomainName, covered_type: u16, ttl: u32) -> ResourceRecord {
    record_with_ttl(
        owner,
        RecordType::SIG,
        ttl,
        RData::SIG(dns::Sig {
            type_covered: covered_type,
            algorithm: 1,
            labels: 1,
            original_ttl: ttl,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: DomainName::root(),
            signature: vec![1],
        }),
    )
}

fn nxt(owner: DomainName, next: &DomainName) -> ResourceRecord {
    let mut rdata = Vec::with_capacity(next.wire_len() + 1);
    for label in next.as_ref() {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label);
    }
    rdata.extend([0, 0x40]);
    record(owner, RecordType::Unknown(30), RData::Unknown(rdata))
}

#[tokio::test]
async fn signed_negative_answers_include_the_rfc2308_soa_and_nxt_proofs() {
    let apex = name(&["example"]);
    let existing = name(&["host", "example"]);
    let later = name(&["z", "example"]);
    let server = NameServer::new();
    server
        .install(make_zone(
            apex.clone(),
            ClassType::IN,
            30,
            vec![
                signature(apex.clone(), 6, 60),
                nxt(apex.clone(), &existing),
                signature(apex, 30, 60),
                record(
                    existing.clone(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                ),
                nxt(existing.clone(), &later),
                signature(existing.clone(), 30, 60),
                record(
                    later.clone(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 2)),
                ),
                nxt(later, &name(&["example"])),
            ],
        ))
        .await
        .unwrap();

    let nodata = server
        .handle(
            Message::builder()
                .questions([Question {
                    qname: existing.clone(),
                    qtype: QueryType::TXT,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build()
                .unwrap(),
        )
        .await;
    assert_eq!(nodata.headers.rcode, RCode::Ok);
    assert_eq!(
        nodata
            .authorities
            .iter()
            .map(|record| u16::from(record.rtype))
            .collect::<Vec<_>>(),
        [6, 24, 30, 24]
    );
    assert_eq!(nodata.authorities[0].ttl, 30);
    assert_eq!(nodata.authorities[1].ttl, 30);
    assert!(nodata.authorities[2].name.eq_dns(&existing));
    assert!(nodata.authorities[3].name.eq_dns(&existing));

    let name_error = server
        .handle(
            Message::builder()
                .questions([Question {
                    qname: name(&["missing", "example"]),
                    qtype: QueryType::A,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build()
                .unwrap(),
        )
        .await;
    assert_eq!(name_error.headers.rcode, RCode::NameError);
    assert_eq!(
        name_error
            .authorities
            .iter()
            .map(|record| u16::from(record.rtype))
            .collect::<Vec<_>>(),
        [6, 24, 30, 24]
    );
    assert!(name_error.authorities[2].name.eq_dns(&existing));
    assert!(name_error.authorities[3].name.eq_dns(&existing));
}

#[tokio::test]
async fn signed_wildcard_nodata_uses_the_wildcard_nxt_proof_owner() {
    let apex = name(&["example"]);
    let wildcard = name(&["*", "example"]);
    let synthesized = name(&["www", "example"]);
    let server = NameServer::new();
    server
        .install(make_zone(
            apex.clone(),
            ClassType::IN,
            30,
            vec![
                signature(apex.clone(), 6, 60),
                record(
                    wildcard.clone(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 99)),
                ),
                nxt(wildcard.clone(), &apex),
                signature(wildcard.clone(), 30, 60),
            ],
        ))
        .await
        .unwrap();

    let response = server
        .handle(
            Message::builder()
                .questions([Question {
                    qname: synthesized.clone(),
                    qtype: QueryType::TXT,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build()
                .unwrap(),
        )
        .await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert!(response.answers.is_empty());
    assert!(response.questions[0].qname.eq_dns(&synthesized));
    assert_eq!(response.questions[0].qtype, QueryType::TXT);
    assert_eq!(
        response
            .authorities
            .iter()
            .map(|record| u16::from(record.rtype))
            .collect::<Vec<_>>(),
        [6, 24, 30, 24]
    );
    assert!(response.authorities[0].name.eq_dns(&apex));
    assert!(response.authorities[1].name.eq_dns(&apex));
    assert!(response.authorities[2].name.eq_dns(&wildcard));
    assert!(response.authorities[3].name.eq_dns(&wildcard));
}
