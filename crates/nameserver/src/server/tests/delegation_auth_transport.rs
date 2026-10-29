use super::*;

#[tokio::test]
async fn queries_at_a_delegation_cut_return_a_referral() {
    let server = NameServer::new();
    let child = name(&["child", "example"]);
    let nameserver = name(&["ns", "elsewhere"]);
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(
                child.clone(),
                RecordType::NS,
                RData::NS(nameserver.clone()),
            )],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: child.clone(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(!response.headers.aa);
    assert!(response.answers.is_empty());
    assert!(matches!(
        response.authorities.as_slice(),
        [ResourceRecord {
            rtype: RecordType::NS,
            ..
        }]
    ));
    assert!(response.additionals.is_empty());
}

#[tokio::test]
async fn parent_side_ds_at_a_delegation_is_an_authoritative_answer() {
    let server = NameServer::new();
    let child = name(&["child", "example"]);
    let ds_rdata = dns::Ds {
        key_tag: 1,
        algorithm: 15,
        digest_type: 2,
        digest: vec![5; 32],
    };
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record(
                    child.clone(),
                    RecordType::NS,
                    RData::NS(name(&["ns", "elsewhere"])),
                ),
                record(child.clone(), RecordType::DS, RData::DS(ds_rdata.clone())),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: child.clone(),
            qtype: QueryType::DS,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            name: owner,
            rtype: RecordType::DS,
            rdata: RData::DS(rdata),
            ..
        }] if owner.eq_dns(&child) && rdata == &ds_rdata
    ));
    assert!(response.authorities.is_empty());
}

#[tokio::test]
async fn cname_chains_cross_hosted_zone_boundaries() {
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["alias", "example"]),
                RecordType::CNAME,
                RData::CNAME(name(&["www", "other"])),
            )],
        ))
        .await
        .unwrap();
    server
        .install(make_zone(
            name(&["other"]),
            ClassType::IN,
            600,
            vec![record(
                name(&["www", "other"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 7)),
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
async fn queries_for_an_unhosted_class_are_refused() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::CH),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(!response.headers.aa);
    assert!(response.answers.is_empty());
}

#[tokio::test]
async fn serves_wire_canonical_unknown_classes() {
    let server = NameServer::new();
    server
        .install(test_zone_for_class(
            ClassType::Unknown(42),
            Some((RecordType::TXT, RData::TXT(vec![b"class-42".to_vec()]))),
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::TXT,
            qclass: QClassType::Unknown(42),
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            class: ClassType::Unknown(42),
            rdata: RData::TXT(strings),
            ..
        }] if strings == &[b"class-42".to_vec()]
    ));
    assert!(response.into_wire().is_ok());
}

#[tokio::test]
async fn any_class_queries_without_hosted_zones_are_refused() {
    let server = NameServer::new();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::A,
            qclass: QClassType::ANY,
        }])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(!response.headers.aa);
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
}

#[tokio::test]
async fn axfr_tcp_ignores_aa_tc_rd_and_ra_request_flags() {
    let server = axfr_server();
    server.install(test_zone()).await.unwrap();
    let query = Message {
        headers: Headers {
            aa: true,
            tc: true,
            rd: true,
            ra: true,
            ..Headers::default()
        },
        questions: vec![Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    let responses = server.handle_transfer(axfr_peer(), query).await;
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].headers.rcode, RCode::Ok);
    assert!(responses[0].headers.aa);
    assert!(!responses[0].headers.tc);
    assert!(responses[0].headers.rd);
    assert!(!responses[0].headers.ra);
    assert!(responses[0].answers.len() > 1);
}

#[tokio::test]
async fn malformed_question_values_return_encodable_formerr_without_a_question() {
    let server = NameServer::new();
    let base = Question {
        qname: name(&["example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let questions = [
        Question {
            qtype: QueryType::Unknown(1),
            ..base.clone()
        },
        Question {
            qtype: QueryType::Unknown(251),
            ..base.clone()
        },
        Question {
            qtype: QueryType::Unknown(u16::MAX),
            ..base.clone()
        },
        Question {
            qclass: QClassType::Unknown(1),
            ..base.clone()
        },
        Question {
            qclass: QClassType::Unknown(u16::MAX),
            ..base.clone()
        },
        Question {
            qclass: QClassType::Class(ClassType::Unknown(42)),
            ..base
        },
    ];

    for question in questions {
        let query = Message::builder().questions([question]).build_unchecked();
        let response = server.handle(query).await;

        assert_eq!(response.headers.rcode, RCode::FormatError);
        assert!(response.questions.is_empty());
        assert!(response.into_wire().is_ok());
    }
}

#[tokio::test]
async fn malformed_question_sections_are_sanitized_atomically() {
    let server = NameServer::new();
    let canonical = Question {
        qname: name(&["canonical", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let noncanonical = Question {
        qname: name(&["noncanonical", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Unknown(0),
    };
    let query = Message::builder()
        .questions([canonical, noncanonical])
        .build_unchecked();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(response.questions.is_empty());
    assert!(response.into_wire().is_ok());
}

#[tokio::test]
async fn malformed_axfr_question_returns_encodable_formerr_without_a_question() {
    let server = axfr_server();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Unknown(u16::MAX),
        }])
        .build_unchecked();

    let responses = server.handle_transfer(axfr_peer(), query).await;

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].headers.rcode, RCode::FormatError);
    assert!(responses[0].questions.is_empty());
    assert!(responses[0].clone().into_wire().is_ok());
}

#[tokio::test]
async fn loopback_transports_send_questionless_formerr_for_noncanonical_questions() {
    let udp_reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let udp_address = udp_reservation.local_addr().unwrap();
    drop(udp_reservation);
    let tcp_reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let tcp_address = tcp_reservation.local_addr().unwrap();
    drop(tcp_reservation);

    let udp_server = tokio::spawn(UdpTransport.serve(udp_address, NameServer::new()));
    let tcp_server = tokio::spawn(TcpTransport.serve(tcp_address, NameServer::new()));

    for query in [
        raw_query_with_question_codes(0, u16::from(ClassType::IN)),
        raw_query_with_question_codes(u16::from(QueryType::A), 0),
    ] {
        assert_header_only_formerr(&raw_udp_exchange(udp_address, &query).await);
        assert_header_only_formerr(&raw_tcp_exchange(tcp_address, &query).await);
    }

    let malformed_axfr = raw_query_with_question_codes(u16::from(QueryType::AXFR), 0);
    assert_header_only_formerr(&raw_tcp_exchange(tcp_address, &malformed_axfr).await);

    udp_server.abort();
    tcp_server.abort();
}

#[tokio::test]
async fn loopback_udp_authenticates_tsig_and_signs_the_response() {
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_tsig_key("transfer-key");
    let server = NameServer::with_config(NameServerConfig {
        tsig_keys: vec![key.clone()],
        ..NameServerConfig::default()
    });
    server.install(test_zone()).await.unwrap();
    let listener = tokio::spawn(UdpTransport.serve(address, server));

    let now = unix_time_now();
    let mut query = tsig_query(0x8945);
    let request_mac = key.sign_request(&mut query, now, 300, Some(16)).unwrap();
    let response_wire = raw_udp_exchange(address, &query.into_wire().unwrap()).await;
    listener.abort();

    let verified = key
        .verify_response(&response_wire, &request_mac, now)
        .unwrap();
    assert_eq!(verified.message.headers.rcode, RCode::Ok);
    assert!(verified.message.headers.aa);
    assert!(matches!(
        verified.message.answers.as_slice(),
        [ResourceRecord {
            rtype: RecordType::A,
            rdata: RData::A(address),
            ..
        }] if *address == Ipv4Addr::new(192, 0, 2, 1)
    ));
}

#[tokio::test]
async fn loopback_tcp_preserves_exact_tsig_request_and_response_macs() {
    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let key = test_tsig_key("transfer-key");
    let server = NameServer::with_config(NameServerConfig {
        tsig_keys: vec![key.clone()],
        ..NameServerConfig::default()
    });
    server.install(test_zone()).await.unwrap();
    let listener = tokio::spawn(TcpTransport.serve(address, server));

    let now = unix_time_now();
    let mut query = tsig_query(0x8946);
    let request_mac = key.sign_request(&mut query, now, 300, None).unwrap();
    let response_wire = raw_tcp_exchange(address, &query.into_wire().unwrap()).await;
    listener.abort();

    let verified = key
        .verify_response(&response_wire, &request_mac, now)
        .unwrap();
    assert_eq!(verified.message.headers.id, 0x8946);
    assert_eq!(verified.message.headers.rcode, RCode::Ok);
}
