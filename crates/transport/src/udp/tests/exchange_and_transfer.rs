use super::*;

#[tokio::test]
async fn rejects_a_query_that_exceeds_the_udp_limit() {
    let questions = (0..10)
        .map(|index| Question {
            qname: DomainName::from_labels(vec![vec![b'a' + index; 63]]).unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .collect::<Vec<_>>();
    let query = Message::builder()
        .headers(Headers {
            id: 1,
            ..Headers::default()
        })
        .questions(questions)
        .build()
        .unwrap();
    assert!(query.into_wire().unwrap().len() > MAX_UDP_MESSAGE_OCTETS);

    let error = UdpTransport
        .exchange(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &query,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        TransportError::MessageTooLong {
            maximum: MAX_UDP_MESSAGE_OCTETS,
            ..
        }
    ));
}

#[tokio::test]
async fn refuses_to_send_a_zone_transfer_over_udp() {
    let mut query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    query.headers.rd = true;

    // The refusal happens before any socket is created, so an arbitrary
    // address is safe here.
    let error = UdpTransport
        .exchange(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &query,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, TransportError::InvalidTransfer(_)));
}

#[tokio::test]
async fn answers_a_zone_transfer_over_udp_with_not_implemented() {
    let mut query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    query.headers.rd = true;
    // If the handler were consulted the reply would carry RCODE=OK, so
    // this also proves the transport refuses the query itself.
    let handler = |_query: Message| async { Message::builder().build().unwrap() };

    let packet = response_for(&handler, &query.into_wire().unwrap())
        .await
        .unwrap();
    let response = Message::from_wire(&packet).unwrap();
    assert!(response.headers.qr);
    assert_eq!(response.headers.id, 42);
    assert_eq!(response.headers.rcode, RCode::NotImplemented);
    assert_eq!(response.questions[0].qtype, QueryType::AXFR);
}

#[tokio::test]
async fn rejects_a_malformed_single_message_ixfr_response_over_udp() {
    let query = ixfr_query();
    let handler = |query: Message| async move {
        Message {
            headers: Headers {
                id: query.headers.id,
                qr: true,
                aa: true,
                ..Headers::default()
            },
            questions: query.questions,
            answers: vec![ixfr_soa(2), ixfr_soa(0), ixfr_soa(2), ixfr_soa(2)],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    };

    assert!(
        response_for(&handler, &query.into_wire().unwrap())
            .await
            .is_none()
    );
}

#[tokio::test]
async fn newer_single_soa_ixfr_over_udp_requests_tcp_retry() {
    let query = ixfr_query();
    let handler = |query: Message| async move {
        Message {
            headers: Headers {
                id: query.headers.id,
                qr: true,
                aa: true,
                ..Headers::default()
            },
            questions: query.questions,
            answers: vec![ixfr_soa(2)],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    };
    let packet = response_for(&handler, &query.into_wire().unwrap())
        .await
        .unwrap();
    let response = Message::from_wire(&packet).unwrap();
    assert!(!response.headers.tc);
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::SOA { serial: 2, .. },
            ..
        }]
    ));
}

#[tokio::test]
async fn oversized_udp_ixfr_collapses_to_the_current_soa() {
    let query = ixfr_query();
    let handler = |query: Message| async move {
        let owner = DomainName::from_labels(vec![b"bulk".to_vec(), b"example".to_vec()]).unwrap();
        let mut answers = vec![ixfr_soa(2)];
        answers.extend((0_u8..10).map(|index| ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 300,
            rdata: RData::TXT(vec![vec![index; 100]]),
        }));
        answers.push(ixfr_soa(2));
        Message {
            headers: Headers {
                id: query.headers.id,
                qr: true,
                aa: true,
                ..Headers::default()
            },
            questions: query.questions,
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    };

    let packet = response_for(&handler, &query.into_wire().unwrap())
        .await
        .unwrap();
    let response = Message::from_wire(&packet).unwrap();
    assert!(!response.headers.tc);
    assert!(matches!(
        response.answers.as_slice(),
        [ResourceRecord {
            rdata: RData::SOA { serial: 2, .. },
            ..
        }]
    ));
}

#[tokio::test]
async fn negotiates_an_axfr_edns_version_before_udp_transfer_refusal() {
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .additionals([Edns {
            version: 1,
            ..Edns::new(1232)
        }
        .into_record()])
        .build()
        .unwrap();
    let handler = |_query: Message| async { panic!("UDP AXFR must not reach the handler") };

    let packet = response_for(&handler, &query.into_wire().unwrap())
        .await
        .unwrap();
    let response = Message::from_wire(&packet).unwrap();

    assert_eq!(response.headers.rcode, RCode::Ok);
    assert_eq!(response.extended_rcode(), 16);
    assert_eq!(response.edns().unwrap().unwrap().version, Edns::VERSION);
    assert_eq!(response.questions[0].qtype, QueryType::AXFR);
}

#[tokio::test]
async fn echoes_axfr_questions_for_a_non_query_opcode() {
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            opcode: OpCode::Status,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::AXFR,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let handler = |_query: Message| async { Message::builder().build().unwrap() };

    let packet = response_for(&handler, &query.into_wire().unwrap())
        .await
        .unwrap();
    let response = Message::from_wire(&packet).unwrap();

    assert_eq!(response.headers.opcode, OpCode::Status);
    assert_eq!(response.headers.rcode, RCode::NotImplemented);
    assert!(crate::same_questions(&response.questions, &query.questions));
}

#[tokio::test]
async fn server_ignores_a_well_formed_packet_marked_as_a_response() {
    // RFC 1035 §7.3: a server must not answer datagrams that are already
    // responses, even when they decode cleanly.
    let handler = |message: Message| async move { message };
    let packet = Message::builder()
        .headers(Headers {
            id: 0x1234,
            qr: true,
            ..Headers::default()
        })
        .build()
        .unwrap()
        .into_wire()
        .unwrap();

    assert!(response_for(&handler, &packet).await.is_none());
}

#[tokio::test]
async fn times_out_when_the_server_never_responds() {
    // A bound but silent socket: the query is delivered, no reply comes.
    let server = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let error = UdpTransport
        .exchange(
            server.local_addr().unwrap(),
            &query,
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, TransportError::Timeout));
}

#[tokio::test]
async fn omits_optional_data_from_an_oversized_handler_reply_without_tc() {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let handler = |_query: Message| async { oversized_response() };
    let server = tokio::spawn(serve_socket(socket, handler));

    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::root(),
            qtype: QueryType::ANY,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let mut buffer = [0_u8; MAX_UDP_MESSAGE_OCTETS + 1];
    client
        .send_to(&query.into_wire().unwrap(), address)
        .await
        .unwrap();
    let (length, _) = time::timeout(Duration::from_secs(1), client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    server.abort();

    assert!(length <= MAX_UDP_MESSAGE_OCTETS);
    let response = Message::from_wire(&buffer[..length]).unwrap();
    assert!(!response.headers.tc);
    assert_eq!(response.headers.id, 42);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.authorities.len(), 1);
    assert!(response.additionals.is_empty());
    assert_eq!(response.questions.len(), 1);
}
