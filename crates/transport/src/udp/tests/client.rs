use super::*;

#[test]
fn udp_transport_remains_zero_sized() {
    assert_eq!(std::mem::size_of::<UdpTransport>(), 0);
}

#[test]
fn udp_refuses_to_send_padding_over_cleartext() {
    let query = Message::builder()
        .additionals([padded_opt()])
        .build()
        .unwrap();

    assert!(matches!(
        encode_udp_query(&query),
        Err(TransportError::InsecureEdnsPadding)
    ));
}

#[tokio::test]
async fn udp_accepts_inbound_padding_but_never_emits_it_on_cleartext() {
    let query = Message::builder()
        .additionals([padded_opt()])
        .build()
        .unwrap();
    let handler = |_query: Message| async {
        let mut edns = Edns::new(1232);
        edns.options = vec![
            EdnsOption {
                code: 65000,
                data: vec![1],
            },
            EdnsOption::padding(8),
        ];
        Message::builder()
            .headers(Headers {
                qr: true,
                ..Headers::default()
            })
            .additionals([edns.into_record()])
            .build()
            .unwrap()
    };

    let packet = response_for(&handler, &query.into_wire().unwrap())
        .await
        .unwrap();
    let response = Message::from_wire(&packet).unwrap();
    let edns = response.edns().unwrap().unwrap();
    assert_eq!(edns.padding(), None);
    assert_eq!(edns.options.len(), 1);
    assert_eq!(edns.options[0].code, 65000);
}

#[tokio::test]
async fn udp_malformed_edns_gets_minimal_opt_bearing_formerr() {
    let (query, packet) = malformed_edns_query();
    let invoked = std::sync::atomic::AtomicBool::new(false);
    let handler = |_query: Message| async {
        invoked.store(true, std::sync::atomic::Ordering::Relaxed);
        Message::builder().build().unwrap()
    };

    let response = Message::from_wire(&response_for(&handler, &packet).await.unwrap()).unwrap();
    assert!(!invoked.load(std::sync::atomic::Ordering::Relaxed));
    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(crate::same_questions(&response.questions, &query.questions));
    assert!(response.edns().unwrap().is_some());
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert_eq!(response.additionals.len(), 1);
}

#[tokio::test]
async fn bounds_rich_malformed_edns_formerr_by_the_advertised_udp_payload() {
    let (_query, packet) = malformed_edns_query_with_questions(40, 512);
    let handler = |_query: Message| async { panic!("malformed EDNS must not reach the handler") };

    let response = response_for(&handler, &packet).await.unwrap();
    assert!(response.len() <= 512);
    let response = Message::from_wire(&response).unwrap();

    assert_eq!(response.headers.id, 0x1234);
    assert!(response.headers.qr);
    assert_eq!(response.headers.opcode, OpCode::Status);
    assert!(response.headers.rd);
    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(response.questions.is_empty());
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert_eq!(response.additionals.len(), 1);
}

#[tokio::test]
async fn bounds_malformed_edns_formerr_by_the_configured_udp_ceiling() {
    let (_query, packet) = malformed_edns_query_with_questions(300, u16::MAX);
    let handler = |_query: Message| async { panic!("malformed EDNS must not reach the handler") };

    let response = response_for(&handler, &packet).await.unwrap();
    assert!(response.len() <= usize::from(Edns::RECOMMENDED_UDP_PAYLOAD_SIZE));
    assert!(response.len() <= MAX_EDNS_UDP_MESSAGE_OCTETS);
    Message::from_wire(&response).unwrap();
}

#[test]
fn bounded_formerr_selects_only_complete_response_shapes() {
    let (_query, packet) = malformed_edns_query();
    let recovery = recover_questions_from_edns_request(&packet);

    let without_questions = format_error_response_with_limit(&packet, recovery, 23).unwrap();
    let decoded = Message::from_wire(&without_questions).unwrap();
    assert!(decoded.questions.is_empty());
    assert_eq!(decoded.additionals.len(), 1);

    let header_only = format_error_response_with_limit(&packet, recovery, 22).unwrap();
    let decoded = Message::from_wire(&header_only).unwrap();
    assert!(decoded.questions.is_empty());
    assert!(decoded.additionals.is_empty());
}

impl DnsRequestHandler for StatefulUdpHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            assert_eq!(request.peer(), self.peer);
            assert_eq!(request.protocol(), TransportProtocol::Udp);
            let _ = request.respond(Message::builder().build().unwrap());
        })
    }
}

#[test]
fn udp_defines_its_normative_tcp_transitions() {
    assert!(
        UdpTransport
            .transition(TransitionReason::QueryTooLarge)
            .is_some()
    );
    assert!(
        UdpTransport
            .transition(TransitionReason::TruncatedResponse)
            .is_some()
    );
    assert!(UdpTransport.transition(TransitionReason::Timeout).is_none());
    assert!(UdpTransport.transition(TransitionReason::IoError).is_none());
}

fn classic_query_with_wire_length(rdata_octets: usize) -> Message {
    Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .additionals([ResourceRecord {
            name: DomainName::root(),
            rtype: RecordType::Unknown(65_000),
            class: ClassType::IN,
            ttl: 0,
            rdata: RData::Unknown(vec![0; rdata_octets]),
        }])
        .build()
        .unwrap()
}

fn edns_query_with_wire_length(target_octets: usize) -> Message {
    let query = |rdata_octets| {
        Message::builder()
            .headers(Headers {
                id: 42,
                ..Headers::default()
            })
            .questions([Question {
                qname: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            }])
            .additionals([
                ResourceRecord {
                    name: DomainName::root(),
                    rtype: RecordType::Unknown(65_000),
                    class: ClassType::IN,
                    ttl: 0,
                    rdata: RData::Unknown(vec![0; rdata_octets]),
                },
                Edns::new(4096).into_record(),
            ])
            .build()
            .unwrap()
    };
    let fixed_octets = query(0).into_wire().unwrap().len();
    query(target_octets.checked_sub(fixed_octets).unwrap())
}

#[tokio::test]
async fn deadline_overflow_returns_timeout_before_udp_socket_io() {
    let server = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let query = Message::from_wire(&udp_query(42)).unwrap();

    let error = UdpTransport
        .exchange(server.local_addr().unwrap(), &query, Duration::MAX)
        .await
        .unwrap_err();

    assert!(matches!(error, TransportError::Timeout));
    let mut buffer = [0_u8; 1];
    assert_eq!(
        server.try_recv_from(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn udp_deadline_overflow_keeps_prevalidation_precedence() {
    let mut request = Message::from_wire(&udp_query(42)).unwrap();
    request.questions[0].qtype = QueryType::AXFR;

    assert!(matches!(
        UdpTransport
            .exchange(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
                &request,
                Duration::MAX,
            )
            .await,
        Err(TransportError::Timeout)
    ));
}

#[tokio::test]
async fn zero_udp_timeout_retains_timeout_behavior() {
    let server = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let query = Message::from_wire(&udp_query(42)).unwrap();

    assert!(matches!(
        UdpTransport
            .exchange(server.local_addr().unwrap(), &query, Duration::ZERO)
            .await,
        Err(TransportError::Timeout)
    ));
}

#[tokio::test]
async fn rejects_an_edns_query_above_the_outbound_udp_ceiling_before_socket_io() {
    let query = edns_query_with_wire_length(4097);

    assert!(matches!(
        UdpTransport
            .exchange("192.0.2.1:53".parse().unwrap(), &query, Duration::ZERO,)
            .await,
        Err(TransportError::MessageTooLong {
            length: 4097,
            maximum: 4096,
        })
    ));
}

#[test]
fn accepts_an_edns_query_at_the_outbound_udp_ceiling() {
    let query = edns_query_with_wire_length(4096);

    assert_eq!(encode_udp_query(&query).unwrap().len(), 4096);
}

#[tokio::test]
async fn drops_an_oversized_classic_query_before_handler_dispatch() {
    let query = classic_query_with_wire_length(490);
    let packet = query.into_wire().unwrap();
    assert_eq!(packet.len(), MAX_UDP_MESSAGE_OCTETS + 1);

    let invoked = std::sync::atomic::AtomicBool::new(false);
    let handler = |_query: Message| async {
        invoked.store(true, std::sync::atomic::Ordering::Relaxed);
        Message::builder().build().unwrap()
    };

    assert!(response_for(&handler, &packet).await.is_none());
    assert!(!invoked.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn accepts_a_classic_query_at_the_512_octet_boundary() {
    let query = classic_query_with_wire_length(489);
    let packet = query.into_wire().unwrap();
    assert_eq!(packet.len(), MAX_UDP_MESSAGE_OCTETS);

    let invoked = std::sync::atomic::AtomicBool::new(false);
    let handler = |_query: Message| async {
        invoked.store(true, std::sync::atomic::Ordering::Relaxed);
        Message::builder().build().unwrap()
    };

    assert!(response_for(&handler, &packet).await.is_some());
    assert!(invoked.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn accepts_an_oversized_query_when_it_carries_edns() {
    let mut query = classic_query_with_wire_length(490);
    query.additionals.push(Edns::new(1232).into_record());
    let packet = query.into_wire().unwrap();
    assert!(packet.len() > MAX_UDP_MESSAGE_OCTETS);

    let invoked = std::sync::atomic::AtomicBool::new(false);
    let handler = |_query: Message| async {
        invoked.store(true, std::sync::atomic::Ordering::Relaxed);
        Message::builder().build().unwrap()
    };

    assert!(response_for(&handler, &packet).await.is_some());
    assert!(invoked.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn oversized_malformed_input_keeps_the_formerr_path() {
    let mut packet = classic_query_with_wire_length(489).into_wire().unwrap();
    packet.push(0xff);
    assert_eq!(packet.len(), MAX_UDP_MESSAGE_OCTETS + 1);

    let invoked = std::sync::atomic::AtomicBool::new(false);
    let handler = |_query: Message| async {
        invoked.store(true, std::sync::atomic::Ordering::Relaxed);
        Message::builder().build().unwrap()
    };

    let response = Message::from_wire(&response_for(&handler, &packet).await.unwrap()).unwrap();
    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(!invoked.load(std::sync::atomic::Ordering::Relaxed));
}
