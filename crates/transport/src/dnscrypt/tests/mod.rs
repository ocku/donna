use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use dns::{ClassType, Headers, QClassType, QueryType, Question};

fn bytes(start: u8) -> [u8; 32] {
    std::array::from_fn(|index| start.wrapping_add(index as u8))
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |octet: u8| match octet {
                b'0'..=b'9' => octet - b'0',
                b'a'..=b'f' => octet - b'a' + 10,
                _ => panic!("invalid test hex"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

fn vector_certificate() -> DnscryptCertificate {
    let resolver = SecretKey::from(bytes(0x20));
    DnscryptCertificate::sign(
        &bytes(0),
        *resolver.public_key().as_bytes(),
        [0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8],
        1,
        0x6800_0000,
        0x6801_5180,
    )
    .unwrap()
}

#[test]
fn matches_the_published_certificate_and_response_vectors() {
    let certificate = vector_certificate();
    let expected_certificate = hex(concat!(
        "444e5343000200003a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aab",
        "c173a6a49b7a49ca55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c",
        "4659cac45961400c358072d6365880d1aeea329adf9121383851ed21a28e3b75",
        "e965d0d2cd166254b1b2b3b4b5b6b7b8000000016800000068015180"
    ));
    assert_eq!(certificate.as_bytes(), expected_certificate);

    let provider_public: [u8; 32] =
        hex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
            .try_into()
            .unwrap();
    assert_eq!(
        DnscryptCertificate::verify(&expected_certificate, &provider_public, 0x6800_0000).unwrap(),
        certificate
    );

    let response = hex(concat!(
        "7236666e76576a38a0a1a2a3a4a5a6a7a8a9aaabc0c1c2c3c4c5c6c7c8c9cacb",
        "f2670995c6d37c2f8d2016029dd5970b893de83c02815ece9b48d9fd0b0dca87",
        "41674142fbd8e12c1120b111f366326aa71c89823a2931ac5c860dad49685ed6",
        "cc22cc13e829d2e51d1c00ea64d1d39d"
    ));
    let plaintext = decrypt_response(
        &certificate,
        &SecretKey::from(bytes(0x40)),
        [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
        ],
        &response,
    )
    .unwrap();
    assert_eq!(
        plaintext,
        hex(concat!(
            "12348180000100010000000003777777076578616d706c6503636f6d00000100",
            "01c00c0001000100000e1000045db8d822"
        ))
    );

    let mut tampered = response;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        decrypt_response(
            &certificate,
            &SecretKey::from(bytes(0x40)),
            [
                0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
            ],
            &tampered,
        )
        .is_err()
    );
}

#[test]
fn padding_is_unambiguous_and_rejects_missing_delimiters() {
    let padded = pad(b"dns", 64, 0).unwrap();
    assert_eq!(padded.len(), 64);
    assert_eq!(unpad(&padded).unwrap(), b"dns");
    assert!(unpad(&[1, 2, 0, 0]).is_err());
    assert!(unpad(&[1, 0x80, 0, 1]).is_err());
}

#[test]
fn selects_the_highest_serial_valid_classical_certificate() {
    let now = 1_000;
    let provider = SigningKey::from_bytes(&bytes(1));
    let provider_name = dns::DomainName::from_dotted("2.dnscrypt-cert.example").unwrap();
    let make_certificate = |secret: [u8; 32], serial, magic| {
        let resolver = SecretKey::from(secret);
        DnscryptCertificate::sign(
            provider.as_bytes(),
            *resolver.public_key().as_bytes(),
            magic,
            serial,
            now - 1,
            now + 1,
        )
        .unwrap()
    };
    let older = make_certificate(bytes(33), 7, [1, 2, 3, 4, 5, 6, 7, 8]);
    let newer = make_certificate(bytes(65), 9, [9, 10, 11, 12, 13, 14, 15, 16]);
    let query = certificate_query(&provider_name, 42).unwrap();
    let answer = |certificate: &DnscryptCertificate| dns::ResourceRecord {
        name: provider_name.clone(),
        rtype: dns::RecordType::TXT,
        class: dns::ClassType::IN,
        ttl: 60,
        rdata: dns::RData::TXT(
            certificate
                .as_bytes()
                .chunks(255)
                .map(<[u8]>::to_vec)
                .collect(),
        ),
    };
    let response = Message {
        headers: Headers {
            id: query.headers.id,
            qr: true,
            ..Headers::default()
        },
        questions: query.questions.clone(),
        answers: vec![answer(&newer), answer(&older)],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let config = DnscryptClientConfig::with_provider_name(
        provider_name,
        provider.verifying_key().to_bytes(),
    )
    .unwrap();

    assert_eq!(
        select_certificate(&response, &query, &config, now)
            .unwrap()
            .serial(),
        9
    );
}

fn query(id: u16) -> Message {
    Message::builder()
        .headers(Headers {
            id,
            ..Headers::default()
        })
        .questions([Question {
            qname: dns::DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()
        .unwrap()
}

struct EchoHandler(Arc<AtomicUsize>);

impl DnsRequestHandler for EchoHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            assert_eq!(request.protocol(), TransportProtocol::Dnscrypt);
            self.0.fetch_add(1, Ordering::SeqCst);
            let response = request.message().clone();
            assert!(request.respond(response));
        })
    }
}

struct LargeHandler;

impl DnsRequestHandler for LargeHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let mut response = request.message().clone();
            response.answers = (0..100)
                .map(|index| dns::ResourceRecord {
                    name: dns::DomainName::from_labels(vec![
                        format!("host{index}").into_bytes(),
                        b"example".to_vec(),
                    ])
                    .unwrap(),
                    rtype: dns::RecordType::A,
                    class: dns::ClassType::IN,
                    ttl: 60,
                    rdata: dns::RData::A([192, 0, 2, index as u8].into()),
                })
                .collect();
            assert!(request.respond(response));
        })
    }
}

fn configurations() -> (dns::DomainName, DnscryptServerConfig, DnscryptClientConfig) {
    let now = unix_time().unwrap();
    let provider = SigningKey::from_bytes(&bytes(1));
    let resolver_secret = bytes(33);
    let resolver = SecretKey::from(resolver_secret);
    let certificate = DnscryptCertificate::sign(
        provider.as_bytes(),
        *resolver.public_key().as_bytes(),
        [1, 2, 3, 4, 5, 6, 7, 8],
        7,
        now - 1,
        now + 3600,
    )
    .unwrap();
    let provider_name = dns::DomainName::from_dotted("2.dnscrypt-cert.example").unwrap();
    let server = DnscryptServerConfig::new(
        provider_name.clone(),
        vec![DnscryptResolverIdentity::new(certificate, resolver_secret).unwrap()],
    )
    .unwrap();
    let client = DnscryptClientConfig::with_provider_name(
        provider_name.clone(),
        provider.verifying_key().to_bytes(),
    )
    .unwrap();
    (provider_name, server, client)
}

#[test]
fn nonce_sources_remain_exhausted_instead_of_wrapping() {
    let (_, mut server, client) = configurations();
    let transport = DnscryptTransport::with_deterministic_nonce(client, bytes(65), [9, 8, 7, 6]);
    transport
        .nonce_sequence
        .generated
        .store(u64::MAX - 1, Ordering::Relaxed);

    let final_client_nonce = transport.next_client_nonce().unwrap();
    assert_eq!(&final_client_nonce[4..], &(u64::MAX - 1).to_be_bytes());
    assert!(transport.next_client_nonce().is_err());
    assert!(transport.next_client_nonce().is_err());

    server.nonce_sequence = Arc::new(NonceSequence::deterministic([5, 4, 3, 2]));
    server
        .nonce_sequence
        .generated
        .store(u64::MAX - 1, Ordering::Relaxed);
    let final_resolver_nonce = server.next_resolver_nonce().unwrap();
    assert_eq!(&final_resolver_nonce[4..], &(u64::MAX - 1).to_be_bytes());
    assert!(server.next_resolver_nonce().is_none());
    assert!(server.next_resolver_nonce().is_none());
}

#[test]
fn separate_instances_do_not_restart_nonce_sequences_for_the_same_keys() {
    let (provider_name, first_server, client) = configurations();

    let first_client = DnscryptTransport::with_client_key(client.clone(), bytes(65)).unwrap();
    let second_client = DnscryptTransport::with_client_key(client, bytes(65)).unwrap();
    let first_client_nonce = first_client.next_client_nonce().unwrap();
    let second_client_nonce = second_client.next_client_nonce().unwrap();
    assert_ne!(
        &first_client_nonce[4..],
        &second_client_nonce[4..],
        "clients recreated with one key must not reset the counter portion"
    );

    let second_server =
        DnscryptServerConfig::new(provider_name, first_server.identities.clone()).unwrap();
    let first_resolver_nonce = first_server.next_resolver_nonce().unwrap();
    let second_resolver_nonce = second_server.next_resolver_nonce().unwrap();
    assert_ne!(
        &first_resolver_nonce[4..],
        &second_resolver_nonce[4..],
        "resolvers recreated with one certificate must not reset the counter portion"
    );
}

#[tokio::test]
async fn fetches_authenticates_and_uses_a_certificate_over_tcp() {
    let (provider_name, server_config, client_config) = configurations();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let server_calls = Arc::clone(&calls);
    assert_eq!(provider_name, server_config.provider_name);
    let server_task = tokio::spawn(async move {
        for _ in 0..3 {
            let (stream, peer) = listener.accept().await.unwrap();
            serve_connection(
                stream,
                peer,
                &server_config,
                Arc::new(EchoHandler(Arc::clone(&server_calls))),
            )
            .await;
        }
    });
    let transport =
        DnscryptTransport::with_deterministic_nonce(client_config, bytes(65), [9, 8, 7, 6]);

    for id in [41, 42] {
        let response = transport
            .exchange(address, &query(id), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.headers.id, id);
        assert!(response.headers.qr);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server_task.await.unwrap();
}

#[test]
fn udp_certificate_queries_are_padded_to_the_anti_amplification_budget() {
    let provider = dns::DomainName::from_dotted("2.dnscrypt-cert.example").unwrap();
    let query = padded_certificate_query(&provider, 0xabcd).unwrap();
    assert_eq!(query.into_wire().unwrap().len(), 512);
}

#[tokio::test]
async fn udp_prefers_datagrams_and_retries_a_truncated_answer_over_tcp() {
    let (_, server_config, client_config) = configurations();
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(address).await.unwrap();

    let udp_config = server_config.clone();
    let udp_socket = Arc::clone(&udp);
    let udp_task = tokio::spawn(async move {
        let handler = Arc::new(LargeHandler);
        for _ in 0..2 {
            let mut packet = vec![0; MAX_PACKET_LENGTH + 1];
            let (length, peer) = udp_socket.recv_from(&mut packet).await.unwrap();
            let response =
                serve_datagram(peer, &packet[..length], &udp_config, Arc::clone(&handler))
                    .await
                    .unwrap();
            assert!(response.len() <= length);
            udp_socket.send_to(&response, peer).await.unwrap();
        }
    });
    let tcp_task = tokio::spawn(async move {
        let (stream, peer) = tcp.accept().await.unwrap();
        serve_connection(stream, peer, &server_config, Arc::new(LargeHandler)).await;
    });

    let transport =
        DnscryptUdpTransport::with_deterministic_nonce(client_config, bytes(65), [9, 8, 7, 6]);
    let response = transport
        .exchange(address, &query(51), Duration::from_secs(2))
        .await
        .unwrap();

    assert!(!response.headers.tc);
    assert_eq!(response.answers.len(), 100);
    assert!(transport.padding_target.load(Ordering::Relaxed) > 256);
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
}

#[tokio::test]
async fn udp_retries_omitted_additional_data_over_tcp() {
    let (_, server_config, client_config) = configurations();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(address).await.unwrap();
    let handler = Arc::new(|mut response: Message| async move {
        response.additionals.push(dns::ResourceRecord {
            name: dns::DomainName::from_dotted("extra.example").unwrap(),
            rtype: dns::RecordType::TXT,
            class: dns::ClassType::IN,
            ttl: 60,
            rdata: dns::RData::TXT(vec![vec![b'x'; 255]; 4]),
        });
        response
    });
    let udp_config = server_config.clone();
    let udp_handler = Arc::clone(&handler);
    let udp_task = tokio::spawn(async move {
        for _ in 0..2 {
            let mut packet = vec![0; MAX_PACKET_LENGTH + 1];
            let (length, peer) = udp.recv_from(&mut packet).await.unwrap();
            let response = serve_datagram(
                peer,
                &packet[..length],
                &udp_config,
                Arc::clone(&udp_handler),
            )
            .await
            .unwrap();
            assert!(response.len() <= length);
            udp.send_to(&response, peer).await.unwrap();
        }
    });
    let tcp_task = tokio::spawn(async move {
        let (stream, peer) = tcp.accept().await.unwrap();
        serve_connection(stream, peer, &server_config, handler).await;
    });
    let transport = DnscryptUdpTransport::new(client_config).unwrap();
    let response = transport
        .exchange(address, &query(52), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(!response.headers.tc);
    assert_eq!(response.additionals.len(), 1);
    assert!(transport.padding_target.load(Ordering::Relaxed) > 256);
    udp_task.await.unwrap();
    time::timeout(Duration::from_secs(2), tcp_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn lost_udp_certificate_response_leaves_time_for_tcp_retrieval() {
    let (_, server_config, client_config) = configurations();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(address).await.unwrap();
    let handler = Arc::new(EchoHandler(Arc::new(AtomicUsize::new(0))));
    let udp_config = server_config.clone();
    let udp_handler = Arc::clone(&handler);
    let udp_task = tokio::spawn(async move {
        let mut packet = vec![0; MAX_PACKET_LENGTH + 1];
        // Receive the certificate request, but simulate a lost response.
        let (length, _) = udp.recv_from(&mut packet).await.unwrap();
        assert!(Message::from_wire(&packet[..length]).is_ok());
        let (length, peer) = udp.recv_from(&mut packet).await.unwrap();
        let response = serve_datagram(peer, &packet[..length], &udp_config, udp_handler)
            .await
            .unwrap();
        udp.send_to(&response, peer).await.unwrap();
    });
    let tcp_task = tokio::spawn(async move {
        let (stream, peer) = tcp.accept().await.unwrap();
        serve_connection(stream, peer, &server_config, handler).await;
    });
    let transport = DnscryptUdpTransport::new(client_config).unwrap();
    let result = transport
        .exchange(address, &query(53), Duration::from_secs(2))
        .await;
    if result.is_err() {
        udp_task.abort();
        tcp_task.abort();
    }
    let response = result.unwrap();
    assert!(response.headers.qr);
    assert_eq!(response.headers.id, 53);
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
}

mod signed_responses;

mod endpoint_cache;

mod security;

mod admission;
