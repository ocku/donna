use super::*;

#[tokio::test]
async fn wildcard_nodata_without_an_nxt_remains_soa_only() {
    let synthesized = name(&["www", "example"]);
    let server = NameServer::new();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![record(
                name(&["*", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, 99)),
            )],
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
    assert!(matches!(
        response.authorities.as_slice(),
        [ResourceRecord {
            name: owner,
            rtype: RecordType::SOA,
            ..
        }] if owner.eq_dns(&name(&["example"]))
    ));
}

#[test]
fn rejects_response_only_header_fields_in_a_query() {
    for headers in [
        Headers {
            aa: true,
            ..Headers::default()
        },
        Headers {
            ra: true,
            ..Headers::default()
        },
        Headers {
            rcode: RCode::Refused,
            ..Headers::default()
        },
    ] {
        let query = Message {
            headers,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        assert_eq!(request_error(&query), Some(RCode::FormatError));
    }
}

#[tokio::test]
async fn a_query_without_questions_is_a_format_error() {
    let server = NameServer::new();
    let query = Message::builder().build().unwrap();
    assert_eq!(query.questions.len(), 0);

    let response = server.handle(query).await;
    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(response.headers.qr);
    assert!(!response.headers.aa);
}

#[tokio::test]
async fn multiple_questions_are_a_format_error_that_still_echoes_the_question() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let question = Question {
        qname: name(&["www", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let query = Message::builder()
        .questions([question.clone(), question])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    // RFC 1035 §6.2: a standard query carries exactly one question; a
    // multi-question request is malformed. The FormErr reply is still a
    // response (QR set, no authority) that echoes the question section.
    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(response.headers.qr);
    assert!(!response.headers.aa);
    assert_eq!(response.questions.len(), 2);
    assert_eq!(response.questions[0].qname, name(&["www", "example"]));
    assert_eq!(response.questions[0].qtype, QueryType::A);
    assert_eq!(
        response.questions[0].qclass,
        QClassType::Class(ClassType::IN)
    );
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
}

#[test]
fn rejects_tc_answer_and_authority_fields_but_accepts_additionals_in_a_query() {
    let question = Question {
        qname: name(&["www", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let truncated = Message {
        headers: Headers {
            tc: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    assert_eq!(request_error(&truncated), Some(RCode::FormatError));

    for section in 0..2 {
        let mut malformed = Message {
            headers: Headers::default(),
            questions: vec![question.clone()],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let rr = record(
            name(&["www", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        );
        match section {
            0 => malformed.answers.push(rr),
            _ => malformed.authorities.push(rr),
        }
        assert_eq!(request_error(&malformed), Some(RCode::FormatError));
    }

    let mut with_additional = Message {
        headers: Headers::default(),
        questions: vec![question],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    with_additional.additionals.push(record(
        name(&["www", "example"]),
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    assert_eq!(request_error(&with_additional), None);
}

#[tokio::test]
async fn truncated_standard_query_returns_formerr_without_resolving() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message {
        headers: Headers {
            tc: true,
            ..Headers::default()
        },
        questions: vec![Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(response.headers.qr);
    assert!(!response.headers.aa);
    assert!(!response.headers.tc);
    assert_eq!(response.questions.len(), 1);
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
}

#[tokio::test]
async fn inverse_queries_return_not_implemented_before_standard_query_validation() {
    let server = NameServer::new();
    let query = Message::builder()
        .headers(Headers {
            opcode: OpCode::IQuery,
            ..Headers::default()
        })
        .answers([record(
            name(&["www", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )])
        .build()
        .unwrap();

    let response = server.handle(query).await;
    assert_eq!(response.headers.rcode, RCode::NotImplemented);
}

#[tokio::test]
async fn reserved_opcodes_return_not_implemented_without_panicking() {
    use dns::IntoWire;

    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    // A decodable query with a reserved OPCODE must draw a NOTIMP response
    // (RFC 1035 §4.1.1) that echoes the opcode, not a server panic.
    let query = Message::builder()
        .headers(Headers {
            opcode: OpCode::Unknown(3),
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build_unchecked();

    let response = server.handle(query).await;
    assert_eq!(response.headers.rcode, RCode::NotImplemented);
    assert_eq!(response.headers.opcode, OpCode::Unknown(3));
    // The reply must be wire-representable so it can actually be sent.
    assert!(response.into_wire().is_ok());
}

#[tokio::test]
async fn axfr_is_not_implemented_by_the_single_message_udp_path() {
    // The transport layer already refuses AXFR over UDP with NOTIMP; this only
    // checks the nameserver's own fallback if a query reaches it anyway.
    let server = NameServer::new();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    assert_eq!(
        server.handle(query).await.headers.rcode,
        RCode::NotImplemented
    );
}

#[tokio::test]
async fn axfr_tcp_is_not_implemented_by_default() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let responses = server.handle_transfer(axfr_peer(), query).await;
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].headers.rcode, RCode::NotImplemented);
    assert!(!responses[0].headers.aa);
    assert!(responses[0].answers.is_empty());
}

#[tokio::test]
async fn disabled_axfr_ignores_aa_tc_rd_and_ra_before_returning_not_implemented() {
    let server = NameServer::new();
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
    assert_eq!(responses[0].headers.rcode, RCode::NotImplemented);
    assert!(!responses[0].headers.aa);
    assert!(!responses[0].headers.tc);
    assert!(responses[0].headers.rd);
    assert!(!responses[0].headers.ra);
    assert!(responses[0].answers.is_empty());
}

#[tokio::test]
async fn disabled_axfr_validates_malformed_requests_before_policy() {
    let question = Question {
        qname: name(&["example"]),
        qtype: QueryType::AXFR,
        qclass: QClassType::Class(ClassType::IN),
    };
    let base_query = Message {
        headers: Headers::default(),
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    let mut bad_count = base_query.clone();
    bad_count.questions.push(question.clone());
    let mut bad_class = base_query.clone();
    bad_class.questions[0].qclass = QClassType::ANY;
    let mut noncanonical_question = base_query.clone();
    noncanonical_question.questions[0].qclass = QClassType::Unknown(u16::MAX);
    let mut with_opt = base_query;
    with_opt.additionals.push(ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::Unknown(41),
        class: ClassType::Unknown(1232),
        ttl: 0,
        rdata: RData::Unknown(Vec::new()),
    });

    let server = NameServer::new();
    for query in [bad_count, bad_class, noncanonical_question, with_opt] {
        let responses = server.handle_transfer(axfr_peer(), query).await;
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].headers.rcode, RCode::FormatError);
        assert!(responses[0].answers.is_empty());
        assert!(responses[0].authorities.is_empty());
        assert!(responses[0].additionals.is_empty());
    }
}

#[tokio::test]
async fn configured_axfr_denied_by_peer_policy_is_refused() {
    let server = axfr_server();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let denied_peer = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 53));

    let responses = server.handle_transfer(denied_peer, query).await;

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].headers.rcode, RCode::Refused);
    assert!(!responses[0].headers.aa);
    assert!(responses[0].answers.is_empty());
}

#[tokio::test]
async fn axfr_opens_and_closes_with_soa_and_preserves_record_ttls() {
    let server = axfr_server();
    server
        .install(make_zone(
            name(&["example"]),
            ClassType::IN,
            300,
            vec![
                record_with_ttl(
                    name(&["www", "example"]),
                    RecordType::A,
                    120,
                    RData::A(Ipv4Addr::new(192, 0, 2, 1)),
                ),
                record_with_ttl(
                    name(&["text", "example"]),
                    RecordType::TXT,
                    240,
                    RData::TXT(vec![b"value".to_vec()]),
                ),
            ],
        ))
        .await
        .unwrap();
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let responses = server.handle_transfer(axfr_peer(), query).await;
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].questions.len(), 1);
    assert!(responses.iter().all(|response| {
        response.headers.id == 42
            && response.headers.qr
            && response.headers.aa
            && !response.headers.tc
            && response.answers.len() > 1
    }));
    let records = &responses[0].answers;
    assert_eq!(records.first().unwrap().rtype, RecordType::SOA);
    assert_eq!(records.last().unwrap().rtype, RecordType::SOA);
    assert_eq!(
        records.first().unwrap().rdata,
        records.last().unwrap().rdata
    );
    assert_eq!(records.first().unwrap().ttl, 60);
    assert_eq!(records.last().unwrap().ttl, 60);
    assert_eq!(
        records
            .iter()
            .find(|record| record.rtype == RecordType::A)
            .unwrap()
            .ttl,
        120
    );
    assert_eq!(
        records
            .iter()
            .find(|record| record.rtype == RecordType::TXT)
            .unwrap()
            .ttl,
        240
    );
}
