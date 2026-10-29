use super::*;

#[tokio::test]
async fn unsupported_ixfr_with_client_soa_returns_not_implemented() {
    let zone_name = name(&["example"]);
    let query = Message::builder()
        .questions([Question {
            qname: zone_name.clone(),
            qtype: QueryType::IXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .authorities([record(
            zone_name,
            RecordType::SOA,
            RData::SOA {
                mname: DomainName::root(),
                rname: DomainName::root(),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 1,
            },
        )])
        .build()
        .unwrap();
    let server = NameServer::new();

    for response in [
        server.handle(query.clone()).await,
        server.handle_transfer(axfr_peer(), query).await.remove(0),
    ] {
        assert_eq!(response.headers.rcode, RCode::NotImplemented);
        assert!(matches!(response.questions.as_slice(), [question]
            if question.qtype == QueryType::IXFR));
        assert!(response.answers.is_empty());
        assert!(response.authorities.is_empty());
        assert!(response.additionals.is_empty());
        assert!(response.into_wire().is_ok());
    }
}

#[tokio::test]
async fn ixfr_returns_ordered_differences_from_retained_history() {
    let server = NameServer::with_config(NameServerConfig {
        allow_axfr_to: vec![
            (
                Ipv4Addr::new(192, 0, 2, 0).into(),
                Ipv4Addr::new(255, 255, 255, 0).into(),
            ),
            (
                Ipv4Addr::LOCALHOST.into(),
                Ipv4Addr::new(255, 255, 255, 255).into(),
            ),
        ],
        max_ixfr_history: 4,
        ..NameServerConfig::default()
    });
    let apex = name(&["example"]);
    let changed_owner = name(&["changed", "example"]);
    let mut data = (0_u8..20)
        .map(|value| {
            record(
                name(&[&format!("host-{value}"), "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::new(192, 0, 2, value)),
            )
        })
        .collect::<Vec<_>>();
    data.push(record(
        changed_owner.clone(),
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 100)),
    ));
    let old = make_zone(apex.clone(), ClassType::IN, 300, data);
    let old_soa = old.soa().clone();
    let mut new_records = old.records().to_vec();
    for record in &mut new_records {
        match &mut record.rdata {
            RData::SOA { serial, .. } => *serial = 2,
            RData::A(address) if record.name.eq_dns(&changed_owner) => {
                *address = Ipv4Addr::new(192, 0, 2, 101);
            }
            _ => {}
        }
    }
    let new = Zone::from_master(
        apex.clone(),
        MasterFile {
            records: new_records,
        },
    )
    .unwrap();
    server.install(old).await.unwrap();
    server.install(new).await.unwrap();

    let query = Message::builder()
        .headers(Headers {
            id: 1995,
            ..Headers::default()
        })
        .questions([Question {
            qname: apex,
            qtype: QueryType::IXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .authorities([old_soa])
        .build()
        .unwrap();
    let wire_query = query.clone().into_wire().unwrap();
    let responses = server.handle_transfer(axfr_peer(), query).await;

    assert_eq!(responses.len(), 1);
    let answers = &responses[0].answers;
    assert_eq!(answers.len(), 6);
    assert!(matches!(answers[0].rdata, RData::SOA { serial: 2, .. }));
    assert!(matches!(answers[1].rdata, RData::SOA { serial: 1, .. }));
    assert!(
        matches!(answers[2].rdata, RData::A(address) if address == Ipv4Addr::new(192, 0, 2, 100))
    );
    assert!(matches!(answers[3].rdata, RData::SOA { serial: 2, .. }));
    assert!(
        matches!(answers[4].rdata, RData::A(address) if address == Ipv4Addr::new(192, 0, 2, 101))
    );
    assert!(matches!(answers[5].rdata, RData::SOA { serial: 2, .. }));
    assert!(responses[0].clone().into_wire().is_ok());

    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let listener = tokio::spawn(TcpTransport.serve(address, server));
    let wire_response = raw_tcp_exchange(address, &wire_query).await;
    listener.abort();
    let response = Message::from_wire(&wire_response).unwrap();
    assert_eq!(response.answers.len(), 6);
}

#[tokio::test]
async fn ixfr_uses_full_tcp_fallback_and_single_soa_udp_fallback_without_history() {
    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let tcp_address = reservation.local_addr().unwrap();
    drop(reservation);
    let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let udp_address = reservation.local_addr().unwrap();
    drop(reservation);
    let server = NameServer::with_config(NameServerConfig {
        allow_axfr_to: vec![(
            Ipv4Addr::LOCALHOST.into(),
            Ipv4Addr::new(255, 255, 255, 255).into(),
        )],
        ..NameServerConfig::default()
    });
    let zone = test_zone_with_serial(2);
    let mut client_soa = zone.soa().clone();
    let RData::SOA { serial, .. } = &mut client_soa.rdata else {
        unreachable!()
    };
    *serial = 1;
    server.install(zone).await.unwrap();
    let query = Message::builder()
        .headers(Headers {
            id: 1996,
            ..Headers::default()
        })
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::IXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .authorities([client_soa])
        .build()
        .unwrap()
        .into_wire()
        .unwrap();
    let tcp_listener = tokio::spawn(TcpTransport.serve(tcp_address, server.clone()));
    let udp_listener = tokio::spawn(UdpTransport.serve(udp_address, server));

    let tcp = Message::from_wire(&raw_tcp_exchange(tcp_address, &query).await).unwrap();
    let udp = Message::from_wire(&raw_udp_exchange(udp_address, &query).await).unwrap();
    tcp_listener.abort();
    udp_listener.abort();

    assert!(tcp.answers.len() > 2);
    assert!(matches!(
        tcp.answers.first().unwrap().rdata,
        RData::SOA { serial: 2, .. }
    ));
    assert!(matches!(
        tcp.answers.last().unwrap().rdata,
        RData::SOA { serial: 2, .. }
    ));
    assert_eq!(udp.answers.len(), 1);
    assert!(matches!(udp.answers[0].rdata, RData::SOA { serial: 2, .. }));
}

#[tokio::test]
async fn valid_opt_is_supported_and_multiple_opt_records_return_formerr_with_opt() {
    let server = NameServer::new();
    let opt = dns::Edns::new(1232).into_record();

    for (additionals, expected) in [
        (vec![opt.clone()], RCode::Refused),
        (vec![opt.clone(), opt.clone()], RCode::FormatError),
    ] {
        let query = Message {
            headers: Headers::default(),
            questions: vec![Question {
                qname: name(&["example"]),
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals,
        };
        let response = server.handle(query).await;

        assert_eq!(response.headers.rcode, expected);
        assert_eq!(response.questions.len(), 1);
        assert!(response.answers.is_empty());
        assert!(response.authorities.is_empty());
        assert_eq!(
            response.edns().unwrap().unwrap().version,
            dns::Edns::VERSION
        );
        assert!(response.into_wire().is_ok());
    }

    let axfr_query = Message {
        headers: Headers::default(),
        questions: vec![Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: vec![opt],
    };
    let response = axfr_server()
        .handle_transfer(axfr_peer(), axfr_query)
        .await
        .remove(0);
    assert_eq!(response.headers.rcode, RCode::NotAuthoritative);
    assert!(response.edns().unwrap().is_some());
    assert!(response.into_wire().is_ok());
}

#[tokio::test]
async fn authoritative_requests_ignore_future_edns_z_flags() {
    let mut opt = dns::Edns::new(1232).into_record();
    opt.ttl |= 0x0123;
    let query = Message {
        headers: Headers::default(),
        questions: vec![Question {
            qname: name(&["example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: vec![opt],
    };

    let response = NameServer::new().handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Refused);
    assert!(response.edns().unwrap().is_some());
    assert!(response.into_wire().is_ok());
}

#[tokio::test]
async fn authoritative_requests_accept_nonfinal_padding() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([dns::Edns {
            options: vec![
                dns::EdnsOption::padding(3),
                dns::EdnsOption {
                    code: 65_000,
                    data: vec![1],
                },
            ],
            ..dns::Edns::new(1232)
        }
        .into_record()])
        .build_unchecked();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::A(_),
            ..
        }]
    ));
}

#[tokio::test]
async fn authoritative_requests_accept_non_nfc_ede_text() {
    let server = NameServer::new();
    server.install(test_zone()).await.unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["www", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([dns::Edns {
            options: vec![dns::EdnsOption {
                code: dns::EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
                data: [vec![0, 0], "Cafe\u{301}".as_bytes().to_vec()].concat(),
            }],
            ..dns::Edns::new(1232)
        }
        .into_record()])
        .build_unchecked();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert!(response.headers.aa);
    assert_eq!(response.answers.len(), 1);
}

#[tokio::test]
async fn malformed_known_edns_option_returns_minimal_opt_bearing_formerr() {
    let malformed_options = [
        dns::EdnsOption {
            code: dns::EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
            data: vec![0],
        },
        dns::EdnsOption {
            code: dns::EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
            data: vec![0, 0, 0xff],
        },
    ];

    for option in malformed_options {
        let query = Message::builder()
            .questions([Question {
                qname: name(&["example"]),
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            }])
            .additionals([dns::Edns {
                options: vec![option],
                ..dns::Edns::new(1232)
            }
            .into_record()])
            .build_unchecked();

        let response = NameServer::new().handle(query).await;

        assert_eq!(response.headers.rcode, RCode::FormatError);
        assert_eq!(response.questions.len(), 1);
        assert!(response.answers.is_empty());
        assert!(response.authorities.is_empty());
        assert_eq!(response.additionals.len(), 1);
        assert!(response.edns().unwrap().is_some());
        assert!(response.into_wire().is_ok());
    }
}

#[tokio::test]
async fn unsupported_edns_versions_return_badvers_at_version_zero() {
    let server = NameServer::new();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([dns::Edns {
            version: 1,
            ..dns::Edns::new(1232)
        }
        .into_record()])
        .build()
        .unwrap();

    let response = server.handle(query).await;

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert_eq!(response.extended_rcode(), 16);
    assert_eq!(response.edns().unwrap().unwrap().version, 0);
    assert_eq!(response.questions.len(), 1);
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert!(response.into_wire().is_ok());
}

#[tokio::test]
async fn unsupported_edns_versions_on_axfr_return_badvers_before_transfer_policy() {
    let server = NameServer::new();
    let query = Message::builder()
        .questions([Question {
            qname: name(&["example"]),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([dns::Edns {
            version: 1,
            ..dns::Edns::new(1232)
        }
        .into_record()])
        .build()
        .unwrap();

    let responses = server.handle_transfer(axfr_peer(), query).await;

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].headers.rcode, RCode::Ok);
    assert_eq!(responses[0].extended_rcode(), 16);
    assert_eq!(responses[0].edns().unwrap().unwrap().version, 0);
    assert!(responses[0].answers.is_empty());
    assert!(responses[0].into_wire().is_ok());
}

#[tokio::test]
async fn tcp_axfr_with_an_unsupported_edns_version_receives_badvers() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);

    let listener = tokio::spawn(TcpTransport.serve(address, NameServer::new()));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
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
        .additionals([dns::Edns {
            version: 1,
            ..dns::Edns::new(1232)
        }
        .into_record()])
        .build()
        .unwrap();

    let response = TcpTransport
        .exchange(address, &query, Duration::from_secs(1))
        .await
        .unwrap();
    listener.abort();

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert_eq!(response.extended_rcode(), 16);
    assert_eq!(
        response.edns().unwrap().unwrap().version,
        dns::Edns::VERSION
    );
    assert_eq!(response.questions.len(), 1);
    assert!(
        response.questions[0]
            .qname
            .eq_dns(&query.questions[0].qname)
    );
    assert_eq!(response.questions[0].qtype, QueryType::AXFR);
    assert_eq!(response.questions[0].qclass, query.questions[0].qclass);
    assert!(response.answers.is_empty());
}
