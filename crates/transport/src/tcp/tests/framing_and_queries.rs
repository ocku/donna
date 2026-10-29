use super::*;

fn oversized_response() -> Message {
    let record = |octet| ResourceRecord {
        name: dns::DomainName::root(),
        rtype: RecordType::Unknown(65_000),
        class: dns::ClassType::IN,
        ttl: 0,
        rdata: RData::Unknown(vec![octet; 40_000]),
    };
    Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: vec![record(1), record(2)],
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

#[test]
fn truncates_a_complete_rrset_whose_full_encoding_exceeds_the_tcp_frame_limit() {
    let message = oversized_response();
    assert!(message.into_wire().is_err());

    let packet = truncate_response(message, MAX_TCP_MESSAGE_OCTETS).unwrap();
    let response = Message::from_wire(&packet).unwrap();

    assert!(packet.len() <= MAX_TCP_MESSAGE_OCTETS);
    assert!(response.headers.tc);
    assert!(response.answers.is_empty());
}

#[tokio::test]
async fn aborts_axfr_when_a_response_exceeds_the_tcp_frame_limit() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let handler = |_query: Message| async { oversized_response() };

    assert!(
        responses_for(
            &handler,
            "192.0.2.1:53".parse().unwrap(),
            &request.into_wire().unwrap(),
        )
        .await
        .is_none()
    );
}

#[tokio::test]
async fn rejects_a_query_that_exceeds_the_tcp_frame_limit() {
    // RFC 1035 §4.2.2: messages are prefixed by a two-octet length, so a
    // request larger than 65,535 octets cannot be framed at all. The
    // rejection must happen before any connection is attempted.
    let questions = (0..1000_u64)
        .map(|index| {
            // Unique labels defeat wire-format name compression, which
            // would otherwise collapse repeated names.
            let mut label = vec![b'a'; 63];
            label[..8].copy_from_slice(&index.to_be_bytes());
            Question {
                qname: dns::DomainName::from_labels(vec![label]).unwrap(),
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            }
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
    assert!(query.into_wire().is_err());

    let error = TcpTransport
        .exchange(
            "127.0.0.1:53".parse().unwrap(),
            &query,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, TransportError::Encode(_)));
}

#[tokio::test]
async fn axfr_rejects_cleartext_padding_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    request.additionals.push(
        dns::Edns {
            options: vec![dns::EdnsOption::padding(16)],
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );

    assert!(matches!(
        prepare_transfer_request(&request),
        Err(TransportError::InsecureEdnsPadding)
    ));
    let error = TcpTransport
        .transfer(address, &request, Duration::from_millis(10))
        .await
        .unwrap_err();

    assert!(matches!(error, TransportError::InsecureEdnsPadding));
    drop(listener);
}

#[tokio::test]
async fn axfr_allows_non_padding_edns_options_to_reach_the_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    request.additionals.push(
        dns::Edns {
            options: vec![dns::EdnsOption {
                code: 65_000,
                data: vec![1, 2, 3],
            }],
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );
    let expected = request.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let packet = read_frame(&mut stream).await.unwrap();
        let received = Message::from_wire(&packet).unwrap();
        assert!(crate::same_questions(
            &received.questions,
            &expected.questions
        ));
        let edns = received.edns().unwrap().unwrap();
        assert_eq!(edns.options.len(), 1);
        assert_eq!(edns.options[0].code, 65_000);

        let response = successful_axfr_response_for(&expected);
        write_frame(&mut stream, &response.into_wire().unwrap())
            .await
            .unwrap();
    });

    let records = TcpTransport
        .transfer(address, &request, Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| record.rtype == RecordType::SOA));
}

#[tokio::test]
async fn rejects_a_transfer_query_that_is_not_axfr() {
    // The rejection happens before any connection is made, so an
    // arbitrary address is safe here.
    let error = TcpTransport
        .transfer(
            "127.0.0.1:53".parse().unwrap(),
            &query(42),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, TransportError::InvalidTransfer(_)));
}

#[tokio::test]
async fn rejects_malformed_axfr_queries_before_connecting() {
    let mut response = query(42);
    response.questions[0].qtype = QueryType::AXFR;
    response.headers.qr = true;

    let mut wrong_opcode = query(42);
    wrong_opcode.questions[0].qtype = QueryType::AXFR;
    wrong_opcode.headers.opcode = dns::OpCode::Status;

    let mut answer = query(42);
    answer.questions[0].qtype = QueryType::AXFR;
    answer.answers.push(a_record());

    let mut authority = query(42);
    authority.questions[0].qtype = QueryType::AXFR;
    authority.authorities.push(soa(10));

    let mut any_class = query(42);
    any_class.questions[0].qtype = QueryType::AXFR;
    any_class.questions[0].qclass = QClassType::ANY;

    for malformed in [response, wrong_opcode, answer, authority, any_class] {
        assert!(matches!(
            TcpTransport
                .transfer(
                    "127.0.0.1:53".parse().unwrap(),
                    &malformed,
                    Duration::from_secs(1),
                )
                .await,
            Err(TransportError::InvalidTransfer(_))
        ));
    }
}

#[tokio::test]
async fn accepts_a_tcp_response_exceeding_the_udp_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_query = query(42);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        let mut response = response_for(&server_query, 42);
        response.answers.push(ResourceRecord {
            name: dns::DomainName::root(),
            rtype: RecordType::Unknown(65_000),
            class: dns::ClassType::IN,
            ttl: 0,
            rdata: RData::Unknown(vec![0; 600]),
        });
        let bytes = response.into_wire().unwrap();
        assert!(bytes.len() > MAX_UDP_MESSAGE_OCTETS);
        write_frame(&mut stream, &bytes).await.unwrap();
    });

    let response = TcpTransport
        .exchange(address, &query(42), Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(response.answers.len(), 1);
}

#[tokio::test]
async fn transfers_a_zone_while_ignoring_duplicates_aa_tc_and_mbz_bits() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let expected = request.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        let mut first = response_for(&expected, 42);
        first.headers.aa = true;
        first.answers = vec![soa(10), a_record()];
        write_frame(&mut stream, &first.into_wire().unwrap())
            .await
            .unwrap();
        let mut second = response_for(&expected, 42);
        second.questions.clear();
        second.headers.aa = false;
        second.headers.tc = true;
        second.answers = vec![a_record(), soa(10)];
        let mut packet = second.into_wire().unwrap();
        packet[3] |= 0x70;
        write_frame(&mut stream, &packet).await.unwrap();
    });

    let records = TcpTransport
        .transfer(address, &request, Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(records.len(), 3);
    assert_eq!(records[0].rtype, RecordType::SOA);
    assert_eq!(records[1].rtype, RecordType::A);
    assert_eq!(records[2].rtype, RecordType::SOA);
    assert!(same_resource_record(&records[0], &records[2]));
}
