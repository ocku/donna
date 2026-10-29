use super::*;

mod cname;
mod empty_nonterminal;
mod wildcard_nodata;

#[tokio::test]
async fn authoritative_responses_copy_the_dnssec_ok_bit() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let mut edns = dns::Edns::new(1232);
    edns.set_algorithm_signal(dns::DnssecAlgorithmSignal::Dau, [8, 10])
        .unwrap();
    edns.set_algorithm_signal(dns::DnssecAlgorithmSignal::Dhu, [2])
        .unwrap();
    edns.set_algorithm_signal(dns::DnssecAlgorithmSignal::N3u, [1])
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([edns.into_record()])
        .build()
        .unwrap();

    let response = server.handle(query).await;
    let response_edns = response.edns().unwrap().unwrap();
    assert!(response_edns.dnssec_ok);
    for signal in [
        dns::DnssecAlgorithmSignal::Dau,
        dns::DnssecAlgorithmSignal::Dhu,
        dns::DnssecAlgorithmSignal::N3u,
    ] {
        assert_eq!(response_edns.algorithm_signal(signal).unwrap(), None);
    }
}

#[tokio::test]
async fn dnssec_ok_requests_receive_rrsigs_for_positive_and_wildcard_answers() {
    let exact = name(&["www", "example"]);
    let wildcard = name(&["*", "example"]);
    let server = NameServer::new();
    server
        .install(add_nsec3_chain(
            make_zone(
                name(&["example"]),
                ClassType::IN,
                300,
                vec![
                    record(
                        exact.clone(),
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    ),
                    rrsig(exact.clone(), RecordType::A, 2),
                    record(
                        wildcard.clone(),
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 2)),
                    ),
                    rrsig(wildcard, RecordType::A, 1),
                ],
            ),
            false,
        ))
        .await
        .unwrap();

    let unsigned = server
        .handle(query_with_do(exact.clone(), QueryType::A, false))
        .await;
    assert!(
        unsigned
            .answers
            .iter()
            .all(|record| record.rtype != RecordType::RRSIG)
    );

    let signed = server
        .handle(query_with_do(exact, QueryType::A, true))
        .await;
    assert!(signed.answers.iter().any(|record| {
        matches!(&record.rdata, RData::RRSIG(signature)
            if signature.type_covered == u16::from(RecordType::A) && signature.labels == 2)
    }));

    let expanded = name(&["expanded", "example"]);
    let wildcard_answer = server
        .handle(query_with_do(expanded.clone(), QueryType::A, true))
        .await;
    assert!(wildcard_answer.answers.iter().any(|record| {
        record.name.eq_dns(&expanded)
            && matches!(&record.rdata, RData::RRSIG(signature)
                if signature.type_covered == u16::from(RecordType::A) && signature.labels == 1)
    }));
    assert!(
        wildcard_answer
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NSEC3)
    );
    assert!(wildcard_answer.authorities.iter().any(|record| {
        matches!(&record.rdata, RData::RRSIG(signature)
            if signature.type_covered == u16::from(RecordType::NSEC3))
    }));
}

#[tokio::test]
async fn dnssec_ok_negative_response_includes_signed_nsec_proof() {
    let apex = name(&["example"]);
    let server = NameServer::new();
    server
        .install(make_zone(
            apex.clone(),
            ClassType::IN,
            300,
            vec![
                rrsig(apex.clone(), RecordType::SOA, 1),
                record(
                    apex.clone(),
                    RecordType::NSEC,
                    RData::NSEC(dns::Nsec {
                        next_domain_name: apex.clone(),
                        type_bitmap: dns::TypeBitmap::new([
                            u16::from(RecordType::NS),
                            u16::from(RecordType::SOA),
                            u16::from(RecordType::RRSIG),
                            u16::from(RecordType::NSEC),
                        ])
                        .unwrap(),
                    }),
                ),
                rrsig(apex, RecordType::NSEC, 1),
            ],
        ))
        .await
        .unwrap();

    let missing = name(&["missing", "example"]);
    let unsigned = server
        .handle(query_with_do(missing.clone(), QueryType::A, false))
        .await;
    assert_eq!(unsigned.headers.rcode, RCode::NameError);
    assert!(
        unsigned
            .authorities
            .iter()
            .all(|record| { !matches!(record.rtype, RecordType::RRSIG | RecordType::NSEC) })
    );

    let signed = server
        .handle(query_with_do(missing, QueryType::A, true))
        .await;
    assert_eq!(signed.headers.rcode, RCode::NameError);
    assert!(
        signed
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NSEC)
    );
    for covered in [RecordType::SOA, RecordType::NSEC] {
        assert!(signed.authorities.iter().any(|record| {
            matches!(&record.rdata, RData::RRSIG(signature)
                if signature.type_covered == u16::from(covered))
        }));
    }
}

#[tokio::test]
async fn dnssec_ok_referrals_include_ds_or_authenticated_denial() {
    let apex = name(&["example"]);
    let child = name(&["child", "example"]);
    let secure_server = NameServer::new();
    secure_server
        .install(make_zone(
            apex.clone(),
            ClassType::IN,
            300,
            vec![
                record(child.clone(), RecordType::NS, RData::NS(DomainName::root())),
                record(
                    child.clone(),
                    RecordType::DS,
                    RData::DS(dns::Ds {
                        key_tag: 1,
                        algorithm: 8,
                        digest_type: 2,
                        digest: vec![1; 32],
                    }),
                ),
                rrsig(child.clone(), RecordType::DS, 2),
            ],
        ))
        .await
        .unwrap();

    let below_child = name(&["host", "child", "example"]);
    let unsigned = secure_server
        .handle(query_with_do(below_child.clone(), QueryType::A, false))
        .await;
    assert!(
        unsigned
            .authorities
            .iter()
            .all(|record| !matches!(record.rtype, RecordType::DS | RecordType::RRSIG))
    );

    let secure = secure_server
        .handle(query_with_do(below_child.clone(), QueryType::A, true))
        .await;
    assert!(
        secure
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::DS)
    );
    assert!(secure.authorities.iter().any(|record| {
        matches!(&record.rdata, RData::RRSIG(signature)
            if signature.type_covered == u16::from(RecordType::DS))
    }));

    let insecure_server = NameServer::new();
    insecure_server
        .install(make_zone(
            apex.clone(),
            ClassType::IN,
            300,
            vec![
                record(child.clone(), RecordType::NS, RData::NS(DomainName::root())),
                record(
                    child.clone(),
                    RecordType::NSEC,
                    RData::NSEC(dns::Nsec {
                        next_domain_name: apex,
                        type_bitmap: dns::TypeBitmap::new([
                            u16::from(RecordType::NS),
                            u16::from(RecordType::RRSIG),
                            u16::from(RecordType::NSEC),
                        ])
                        .unwrap(),
                    }),
                ),
                rrsig(child, RecordType::NSEC, 2),
            ],
        ))
        .await
        .unwrap();

    let insecure = insecure_server
        .handle(query_with_do(below_child, QueryType::A, true))
        .await;
    assert!(
        insecure
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NSEC)
    );
    assert!(insecure.authorities.iter().any(|record| {
        matches!(&record.rdata, RData::RRSIG(signature)
            if signature.type_covered == u16::from(RecordType::NSEC))
    }));
}

#[tokio::test]
async fn dnssec_ok_nsec3_negatives_and_opt_out_referrals_include_proofs() {
    let apex = name(&["example"]);
    let www = name(&["www", "example"]);
    let server = NameServer::new();
    server
        .install(add_nsec3_chain(
            make_zone(
                apex.clone(),
                ClassType::IN,
                300,
                vec![record(
                    www.clone(),
                    RecordType::A,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                )],
            ),
            false,
        ))
        .await
        .unwrap();

    for (qname, qtype, expected_rcode) in [
        (
            name(&["missing", "example"]),
            QueryType::A,
            RCode::NameError,
        ),
        (www, QueryType::TXT, RCode::Ok),
    ] {
        let response = server.handle(query_with_do(qname, qtype, true)).await;
        assert_eq!(response.headers.rcode, expected_rcode);
        assert!(
            response
                .authorities
                .iter()
                .any(|record| record.rtype == RecordType::NSEC3)
        );
        assert!(response.authorities.iter().any(|record| {
            matches!(&record.rdata, RData::RRSIG(signature)
                if signature.type_covered == u16::from(RecordType::NSEC3))
        }));
    }

    let child = name(&["child", "example"]);
    let opt_out_server = NameServer::new();
    opt_out_server
        .install(add_nsec3_chain(
            make_zone(
                apex,
                ClassType::IN,
                300,
                vec![record(child, RecordType::NS, RData::NS(DomainName::root()))],
            ),
            true,
        ))
        .await
        .unwrap();
    let referral = opt_out_server
        .handle(query_with_do(
            name(&["host", "child", "example"]),
            QueryType::A,
            true,
        ))
        .await;
    assert!(
        referral
            .authorities
            .iter()
            .any(|record| { matches!(&record.rdata, RData::NSEC3(nsec3) if nsec3.opt_out()) })
    );
    assert!(referral.authorities.iter().any(|record| {
        matches!(&record.rdata, RData::RRSIG(signature)
            if signature.type_covered == u16::from(RecordType::NSEC3))
    }));
}

#[tokio::test]
async fn follows_an_rfc2317_classless_reverse_delegation() {
    let parent_apex = name(&["2", "0", "192", "in-addr", "arpa"]);
    let child_apex = name(&["0/25", "2", "0", "192", "in-addr", "arpa"]);
    let reverse_name = name(&["1", "2", "0", "192", "in-addr", "arpa"]);
    let delegated_name = name(&["1", "0/25", "2", "0", "192", "in-addr", "arpa"]);
    let host = name(&["host1", "example"]);

    let parent = MasterFile::parse(
        "$ORIGIN 2.0.192.in-addr.arpa.\n\
         @ IN 60 SOA ns.parent.invalid. hostmaster.parent.invalid. 1 3600 600 86400 60\n\
         @ IN 60 NS ns.parent.invalid.\n\
         0/25 IN 60 NS ns.child.invalid.\n\
         1 IN 60 CNAME 1.0/25",
        None,
    )
    .unwrap();
    let child = MasterFile::parse(
        "$ORIGIN 0/25.2.0.192.in-addr.arpa.\n\
         @ IN 60 SOA ns.child.invalid. hostmaster.child.invalid. 1 3600 600 86400 60\n\
         @ IN 60 NS ns.child.invalid.\n\
         1 IN 60 PTR host1.example.",
        None,
    )
    .unwrap();

    let server = NameServer::new();
    server
        .install(Zone::from_master(parent_apex, parent).unwrap())
        .await
        .unwrap();
    server
        .install(Zone::from_master(child_apex, child).unwrap())
        .await
        .unwrap();

    let response = server
        .handle(
            Message::builder()
                .questions([Question {
                    qname: reverse_name.clone(),
                    qtype: QueryType::PTR,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .build()
                .unwrap(),
        )
        .await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            name: cname_owner,
            rdata: RData::CNAME(cname_target),
            ..
        }, ResourceRecord {
            name: ptr_owner,
            rdata: RData::PTR(ptr_target),
            ..
        }] if cname_owner.eq_dns(&reverse_name)
            && cname_target.eq_dns(&delegated_name)
            && ptr_owner.eq_dns(&delegated_name)
            && ptr_target.eq_dns(&host)
    ));
}

#[tokio::test]
async fn additional_address_records_preserve_ttls_from_another_hosted_zone() {
    let server = NameServer::new();
    let mail = name(&["mail", "other"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record_with_ttl(
                name(&["example"]),
                RecordType::MX,
                120,
                RData::MX {
                    preference: 10,
                    exchange: mail.clone(),
                },
            )],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(
            name(&["other"]),
            ClassType::IN,
            600,
            vec![
                record_with_ttl(
                    mail.clone(),
                    RecordType::A,
                    700,
                    RData::A(Ipv4Addr::new(192, 0, 2, 25)),
                ),
                record_with_ttl(
                    mail.clone(),
                    RecordType::AAAA,
                    800,
                    RData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 25)),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::MX,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].ttl, 120);
    assert!(matches!(
        response.additionals.as_slice(),
        [
            ResourceRecord {
                name: ipv4_owner,
                ttl: 700,
                rdata: RData::A(ipv4),
                ..
            },
            ResourceRecord {
                name: ipv6_owner,
                ttl: 800,
                rdata: RData::AAAA(ipv6),
                ..
            }
        ] if ipv4_owner.eq_dns(&mail)
            && ipv6_owner.eq_dns(&mail)
            && *ipv4 == Ipv4Addr::new(192, 0, 2, 25)
            && *ipv6 == Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 25)
    ));
}
