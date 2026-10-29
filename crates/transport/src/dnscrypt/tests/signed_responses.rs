use super::*;

#[tokio::test]
async fn preserves_signed_questionless_update_responses() {
    for case in crate::tests::signed_responses::SignedResponse::cases(42) {
        let (_, server_config, client_config) = configurations();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handler = Arc::new(case.handler());
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, peer) = listener.accept().await.unwrap();
                serve_connection(stream, peer, &server_config, Arc::clone(&handler)).await;
            }
        });
        let transport =
            DnscryptTransport::with_deterministic_nonce(client_config, bytes(65), [9, 8, 7, 6]);
        let response = transport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn udp_preserves_signed_questionless_update_responses() {
    for case in crate::tests::signed_responses::SignedResponse::cases(42) {
        let (_, server_config, client_config) = configurations();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let handler = Arc::new(case.handler());
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut packet = vec![0; MAX_PACKET_LENGTH + 1];
                let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
                let response = serve_datagram(
                    peer,
                    &packet[..length],
                    &server_config,
                    Arc::clone(&handler),
                )
                .await
                .unwrap();
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let transport =
            DnscryptUdpTransport::with_deterministic_nonce(client_config, bytes(65), [9, 8, 7, 6]);
        let response = transport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn preserves_inverse_response_discovered_questions() {
    for case in crate::tests::signed_responses::SignedResponse::inverse_cases(42) {
        let (_, server_config, client_config) = configurations();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handler = Arc::new(case.handler());
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, peer) = listener.accept().await.unwrap();
                serve_connection(stream, peer, &server_config, Arc::clone(&handler)).await;
            }
        });
        let transport =
            DnscryptTransport::with_deterministic_nonce(client_config, bytes(65), [9, 8, 7, 6]);
        let response = transport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn udp_preserves_inverse_response_discovered_questions() {
    for case in crate::tests::signed_responses::SignedResponse::inverse_cases(42) {
        let (_, server_config, client_config) = configurations();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let handler = Arc::new(case.handler());
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut packet = vec![0; MAX_PACKET_LENGTH + 1];
                let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
                let response = serve_datagram(
                    peer,
                    &packet[..length],
                    &server_config,
                    Arc::clone(&handler),
                )
                .await
                .unwrap();
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let transport =
            DnscryptUdpTransport::with_deterministic_nonce(client_config, bytes(65), [9, 8, 7, 6]);
        let response = transport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn oversized_authenticated_responses_are_rejected_without_truncation() {
    for mut case in crate::tests::signed_responses::SignedResponse::cases(42) {
        let now = unix_time().unwrap();
        let certificate = DnscryptCertificate::sign(
            &bytes(1),
            *SecretKey::from(bytes(33)).public_key().as_bytes(),
            [1, 2, 3, 4, 5, 6, 7, 8],
            7,
            now - 1,
            now + 3600,
        )
        .unwrap();
        let server_config = DnscryptServerConfig::new(
            dns::DomainName::from_dotted("2.dnscrypt-cert.example").unwrap(),
            vec![DnscryptResolverIdentity::new(certificate.clone(), bytes(33)).unwrap()],
        )
        .unwrap();
        // Keep the authentication record in place while making the answer exceed
        // both the TCP plaintext bound and every possible UDP response budget.
        case.response.answers.push(dns::ResourceRecord {
            name: dns::DomainName::root(),
            rtype: dns::RecordType::TXT,
            class: dns::ClassType::IN,
            ttl: 60,
            rdata: dns::RData::TXT(vec![vec![b'x'; 255]; 20]),
        });
        let client_secret = SecretKey::from(bytes(65));
        let packet = encrypt_query(
            &certificate,
            &client_secret,
            [1; 12],
            &case.request.clone().into_wire().unwrap(),
        )
        .unwrap();
        let handler = Arc::new(case.handler());
        let peer = "127.0.0.1:12345".parse().unwrap();
        assert!(
            serve_datagram(peer, &packet, &server_config, Arc::clone(&handler))
                .await
                .is_none()
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, peer) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            serve_connection(stream, peer, &server_config, handler).await;
        });
        write_frame(&mut client, &packet).await.unwrap();
        assert!(read_packet(&mut client).await.is_err());
        task.await.unwrap();
    }
}
