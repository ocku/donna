use super::*;

fn endpoints() -> (
    DnscryptServerConfig,
    DnscryptServerConfig,
    DnscryptClientConfig,
) {
    let (name, first, client) = configurations();
    let secret = bytes(97);
    let now = unix_time().unwrap();
    let certificate = DnscryptCertificate::sign(
        &bytes(1),
        *SecretKey::from(secret).public_key().as_bytes(),
        [8, 7, 6, 5, 4, 3, 2, 1],
        8,
        now - 1,
        now + 3600,
    )
    .unwrap();
    let second = DnscryptServerConfig::new(
        name,
        vec![DnscryptResolverIdentity::new(certificate, secret).unwrap()],
    )
    .unwrap();
    (first, second, client)
}

#[tokio::test]
async fn tcp_certificates_are_bound_to_the_exact_endpoint() {
    let (first, second, config) = endpoints();
    let mut addresses = Vec::new();
    let mut tasks = Vec::new();
    let calls = Arc::new(AtomicUsize::new(0));
    for (config, transactions) in [(first, 4), (second, 2)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        addresses.push(listener.local_addr().unwrap());
        let calls = Arc::clone(&calls);
        tasks.push(tokio::spawn(async move {
            for _ in 0..transactions {
                let (stream, peer) = listener.accept().await.unwrap();
                serve_connection(
                    stream,
                    peer,
                    &config,
                    Arc::new(EchoHandler(Arc::clone(&calls))),
                )
                .await;
            }
        }));
    }
    let transport = DnscryptTransport::new(config).unwrap();
    for (id, endpoint) in [0, 1, 0].into_iter().enumerate() {
        let response = transport
            .exchange(
                addresses[endpoint],
                &query(id as u16),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(response.headers.id, id as u16);
        assert!(response.headers.qr);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn udp_certificates_are_bound_to_the_exact_endpoint() {
    let (first, second, config) = endpoints();
    let mut addresses = Vec::new();
    let mut tasks = Vec::new();
    let calls = Arc::new(AtomicUsize::new(0));
    for (config, transactions) in [(first, 4), (second, 2)] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        addresses.push(socket.local_addr().unwrap());
        let calls = Arc::clone(&calls);
        tasks.push(tokio::spawn(async move {
            for _ in 0..transactions {
                let mut packet = vec![0; MAX_PACKET_LENGTH + 1];
                let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
                let response = serve_datagram(
                    peer,
                    &packet[..length],
                    &config,
                    Arc::new(EchoHandler(Arc::clone(&calls))),
                )
                .await
                .unwrap();
                socket.send_to(&response, peer).await.unwrap();
            }
        }));
    }
    let transport = DnscryptUdpTransport::new(config).unwrap();
    for (id, endpoint) in [0, 1, 0].into_iter().enumerate() {
        let response = transport
            .exchange(
                addresses[endpoint],
                &query(id as u16),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(response.headers.id, id as u16);
        assert!(response.headers.qr);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn delayed_certificate_responses_cannot_reintroduce_expired_certificates() {
    for udp in [false, true] {
        let (_, mut config, client_config) = configurations();
        let now = unix_time().unwrap();
        let expires = now + 1;
        let certificate = DnscryptCertificate::sign(
            &bytes(1),
            *SecretKey::from(bytes(33)).public_key().as_bytes(),
            [1, 2, 3, 4, 5, 6, 7, 8],
            7,
            now - 1,
            expires,
        )
        .unwrap();
        config.identities = vec![DnscryptResolverIdentity::new(certificate, bytes(33)).unwrap()];
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(EchoHandler(Arc::clone(&calls)));
        let (address, task, transport): (_, _, Box<dyn Transport>) = if udp {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            let tcp = TcpListener::bind(address).await.unwrap();
            let task = tokio::spawn(async move {
                let datagrams = async {
                    for index in 0..2 {
                        let mut packet = vec![0; MAX_PACKET_LENGTH + 1];
                        let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
                        if index == 0 {
                            wait_until_expired(expires).await;
                        }
                        let response =
                            serve_datagram(peer, &packet[..length], &config, Arc::clone(&handler))
                                .await
                                .unwrap();
                        socket.send_to(&response, peer).await.unwrap();
                    }
                };
                let fallback = async {
                    let (stream, peer) = tcp.accept().await.unwrap();
                    wait_until_expired(expires).await;
                    serve_connection(stream, peer, &config, Arc::clone(&handler)).await;
                };
                tokio::select! {
                    () = datagrams => {},
                    () = fallback => {},
                }
            });
            (
                address,
                task,
                Box::new(DnscryptUdpTransport::new(client_config).unwrap()),
            )
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                for index in 0..2 {
                    let (stream, peer) = listener.accept().await.unwrap();
                    if index == 0 {
                        wait_until_expired(expires).await;
                    }
                    serve_connection(stream, peer, &config, Arc::clone(&handler)).await;
                }
            });
            (
                address,
                task,
                Box::new(DnscryptTransport::new(client_config).unwrap()),
            )
        };
        let result = transport
            .exchange(address, &query(42), Duration::from_secs(5))
            .await;
        task.abort();
        assert!(
            matches!(result, Err(TransportError::InvalidDnscryptProtocol(_))),
            "expired certificate was used: {result:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

async fn wait_until_expired(expires: u32) {
    while unix_time().unwrap() <= expires {
        time::sleep(Duration::from_millis(10)).await;
    }
}
