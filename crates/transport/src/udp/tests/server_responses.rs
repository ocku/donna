use super::*;

#[tokio::test]
async fn standard_server_responses_echo_the_request_questions() {
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let handler = |_query: Message| async { Message::builder().build().unwrap() };

    let packet = response_for(&handler, &query.into_wire().unwrap())
        .await
        .unwrap();
    let response = Message::from_wire(&packet).unwrap();

    assert_eq!(response.questions.len(), 1);
    assert!(response.questions[0].qname.eq_dns(&DomainName::root()));
    assert_eq!(response.questions[0].qtype, QueryType::A);
    assert_eq!(
        response.questions[0].qclass,
        QClassType::Class(ClassType::IN)
    );
}

#[tokio::test]
async fn oversized_multi_question_formerr_falls_back_to_a_minimal_response() {
    let questions = (0..110)
        .map(|_| Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .collect::<Vec<_>>();
    let query = Message::builder()
        .headers(Headers {
            id: 0x1234,
            rd: true,
            ..Headers::default()
        })
        .questions(questions)
        .additionals([Edns::new(512).into_record()])
        .build()
        .unwrap();
    let request = query.into_wire().unwrap();
    assert!(request.len() > MAX_UDP_MESSAGE_OCTETS);
    let handler = |query: Message| async move {
        Message::builder()
            .headers(Headers {
                qr: true,
                rcode: RCode::FormatError,
                ..Headers::default()
            })
            .questions(query.questions)
            .additionals([Edns {
                dnssec_ok: true,
                options: vec![EdnsOption {
                    code: 65_001,
                    data: vec![1; 1024],
                }],
                ..Edns::default()
            }
            .into_record()])
            .build()
            .unwrap()
    };

    let response = response_for(&handler, &request).await.unwrap();
    assert!(response.len() <= MAX_UDP_MESSAGE_OCTETS);
    let response = Message::from_wire(&response).unwrap();

    assert_eq!(response.headers.id, 0x1234);
    assert!(response.headers.qr);
    assert!(response.headers.rd);
    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(response.questions.is_empty());
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert_eq!(response.additionals.len(), 1);
    let edns = response.edns().unwrap().unwrap();
    assert_eq!(edns.version, Edns::VERSION);
    assert!(edns.dnssec_ok);
    assert!(edns.options.is_empty());
}

#[tokio::test]
async fn noncanonical_standard_questions_keep_udp_formerr_questionless() {
    for packet in [
        query_with_question_codes(0, u16::from(ClassType::IN)),
        query_with_question_codes(u16::from(QueryType::A), 0),
    ] {
        let handler = |_query: Message| async { unrelated_formerr() };

        let packet = response_for(&handler, &packet).await.unwrap();
        let response = Message::from_wire(&packet).unwrap();

        assert_eq!(response.headers.rcode, RCode::FormatError);
        assert!(response.questions.is_empty());
    }
}

#[tokio::test]
async fn udp_request_owns_its_udp_reply_path() {
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 53000));
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .build()
        .unwrap();

    let packet = response_for_peer(
        &StatefulUdpHandler { peer },
        peer,
        &query.into_wire().unwrap(),
    )
    .await
    .unwrap();
    let response = Message::from_wire(&packet).unwrap();

    assert_eq!(response.headers.id, 42);
    assert!(response.headers.qr);
}

#[tokio::test]
async fn udp_server_omits_a_malformed_optional_handler_rrset() {
    let query = Message::builder()
        .questions([Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();
    let handler = |_query: Message| async {
        let mut response = oversized_response();
        response.additionals[0].rtype = RecordType::A;
        response.additionals[0].rdata = RData::Unknown(Vec::new());
        response
    };

    let packet = response_for(&handler, &query.into_wire().unwrap())
        .await
        .unwrap();
    let response = Message::from_wire(&packet).unwrap();

    assert!(!response.headers.tc);
    assert!(response.additionals.is_empty());
    assert!(response.validate_strict().is_ok());
}

#[tokio::test]
async fn server_ignores_a_malformed_packet_marked_as_a_response() {
    let handler = |message: Message| async move { message };

    assert!(response_for(&handler, &[0x12, 0x34, 0x80]).await.is_none());
}

#[tokio::test]
async fn ignores_an_oversized_datagram_before_a_matching_response() {
    let server = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let server_address = server.local_addr().unwrap();
    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; MAX_UDP_MESSAGE_OCTETS];
        let (length, client) = server.recv_from(&mut buffer).await.unwrap();
        let request = Message::from_wire(&buffer[..length]).unwrap();
        server
            .send_to(&[0_u8; MAX_UDP_MESSAGE_OCTETS + 1], client)
            .await
            .unwrap();
        let response = Message {
            headers: Headers {
                id: request.headers.id,
                qr: true,
                ..Headers::default()
            },
            questions: request.questions,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        server
            .send_to(&response.into_wire().unwrap(), client)
            .await
            .unwrap();
    });

    let response = UdpTransport
        .exchange(server_address, &query, Duration::from_secs(1))
        .await
        .unwrap();
    responder.await.unwrap();
    assert_eq!(response.headers.id, query.headers.id);
}

#[tokio::test]
async fn rejects_a_matching_response_from_a_different_source() {
    let server = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let server_address = server.local_addr().unwrap();
    let attacker = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    assert_ne!(attacker.local_addr().unwrap(), server_address);

    let query = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([Question {
            qname: dns::DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap();

    let responder = tokio::spawn(async move {
        let mut buffer = [0_u8; MAX_UDP_MESSAGE_OCTETS];
        let (length, client) = server.recv_from(&mut buffer).await.unwrap();
        let request = Message::from_wire(&buffer[..length]).unwrap();
        let mut response = Message {
            headers: Headers {
                id: request.headers.id,
                qr: true,
                ra: true,
                ..Headers::default()
            },
            questions: request.questions,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let bytes = response.into_wire().unwrap();
        attacker.send_to(&bytes, client).await.unwrap();

        time::sleep(Duration::from_millis(20)).await;
        response.headers.ra = false;
        response.headers.aa = true;
        response.headers.tc = true;
        server
            .send_to(&response.into_wire().unwrap(), client)
            .await
            .unwrap();
    });

    let response = UdpTransport
        .exchange(server_address, &query, Duration::from_secs(1))
        .await
        .unwrap();
    responder.await.unwrap();

    assert!(response.headers.aa);
    assert!(response.headers.tc);
    assert!(!response.headers.ra);
    assert_eq!(response.headers.id, query.headers.id);
    assert_eq!(response.questions.len(), 1);
    assert!(
        response.questions[0]
            .qname
            .eq_dns(&query.questions[0].qname)
    );
    assert_eq!(response.questions[0].qtype, query.questions[0].qtype);
    assert_eq!(response.questions[0].qclass, query.questions[0].qclass);
}
