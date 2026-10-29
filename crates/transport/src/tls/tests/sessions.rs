use super::*;

#[tokio::test]
async fn authenticates_tls13_negotiates_dot_pads_and_reuses_the_session() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server(PaddedHandler {
        calls: Arc::clone(&calls),
    })
    .await;
    let transport = TlsTransport::new(client_config("localhost"));

    for id in [41, 42] {
        let response = transport
            .exchange(server, &query(id), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.headers.id, id);
        assert!(response.edns().unwrap().unwrap().padding().is_some());
    }

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    task.abort();
}

#[tokio::test]
async fn concurrent_cold_misses_share_one_tls_handshake() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server(PaddedHandler {
        calls: Arc::clone(&calls),
    })
    .await;
    let transport = TlsTransport::new(client_config("localhost"));
    let mut exchanges = tokio::task::JoinSet::new();
    for id in 1..=8 {
        let transport = transport.clone();
        exchanges.spawn(async move {
            transport
                .exchange(server, &query(id), Duration::from_secs(2))
                .await
                .unwrap()
        });
    }
    while let Some(result) = exchanges.join_next().await {
        assert!(result.unwrap().headers.qr);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 8);
    task.abort();
}

#[tokio::test]
async fn a_waiter_reconnects_when_an_exchange_is_cancelled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config().0);
    let first_request_received = Arc::new(Notify::new());
    let server_first_request_received = Arc::clone(&first_request_received);
    let server_task = tokio::spawn(async move {
        let (first, _) = listener.accept().await.unwrap();
        let mut first = acceptor.accept(first).await.unwrap();
        let request = Message::from_wire(&read_frame(&mut first).await.unwrap()).unwrap();
        assert_eq!(request.headers.id, 41);
        server_first_request_received.notify_one();

        // A cancellation-safe client must abandon `first` even when another
        // exchange already cloned that pool entry and is waiting for its lock.
        let (second, _) = listener.accept().await.unwrap();
        let mut second = acceptor.accept(second).await.unwrap();
        let request = Message::from_wire(&read_frame(&mut second).await.unwrap()).unwrap();
        assert_eq!(request.headers.id, 42);
        let response = Message::builder()
            .headers(Headers {
                id: request.headers.id,
                qr: true,
                ..Headers::default()
            })
            .questions(request.questions)
            .build()
            .unwrap();
        write_frame(&mut second, &response.into_wire().unwrap())
            .await
            .unwrap();
    });
    let transport = TlsTransport::new(client_config("localhost"));

    let first_transport = transport.clone();
    let first = tokio::spawn(async move {
        first_transport
            .exchange(server, &query(41), Duration::from_secs(2))
            .await
    });
    first_request_received.notified().await;

    let second_transport = transport.clone();
    let second = tokio::spawn(async move {
        second_transport
            .exchange(server, &query(42), Duration::from_secs(2))
            .await
    });
    tokio::task::yield_now().await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());

    let response = second.await.unwrap().unwrap();
    assert_eq!(response.headers.id, 42);
    server_task.await.unwrap();
}

#[tokio::test]
async fn accepts_pipelined_queries_without_serializing_handler_execution() {
    let started = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server(ConcurrentHandler {
        started: Arc::clone(&started),
        both_started: Arc::new(Notify::new()),
    })
    .await;
    let config = client_config("localhost");
    let tcp = TcpStream::connect(server).await.unwrap();
    let mut stream = TlsConnector::from(config.config)
        .connect(config.authentication_name, tcp)
        .await
        .unwrap();

    write_frame(&mut stream, &query(41).into_wire().unwrap())
        .await
        .unwrap();
    write_frame(&mut stream, &query(42).into_wire().unwrap())
        .await
        .unwrap();
    let responses = time::timeout(Duration::from_secs(2), async {
        let first = Message::from_wire(&read_frame(&mut stream).await.unwrap()).unwrap();
        let second = Message::from_wire(&read_frame(&mut stream).await.unwrap()).unwrap();
        [first.headers.id, second.headers.id]
    })
    .await
    .unwrap();

    assert_eq!(started.load(Ordering::SeqCst), 2);
    assert!(responses.contains(&41));
    assert!(responses.contains(&42));
    task.abort();
}

#[tokio::test]
async fn accepts_concurrent_axfr_sessions_on_one_tls_connection() {
    let started = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server(ConcurrentAxfrHandler {
        started: Arc::clone(&started),
        both_started: Arc::new(Notify::new()),
    })
    .await;
    let config = client_config("localhost");
    let tcp = TcpStream::connect(server).await.unwrap();
    let mut stream = TlsConnector::from(config.config)
        .connect(config.authentication_name, tcp)
        .await
        .unwrap();
    let mut first = query(41);
    first.questions[0].qtype = QueryType::AXFR;
    let mut second = query(42);
    second.questions[0].qtype = QueryType::AXFR;

    write_frame(&mut stream, &first.into_wire().unwrap())
        .await
        .unwrap();
    write_frame(&mut stream, &second.into_wire().unwrap())
        .await
        .unwrap();
    let responses = time::timeout(Duration::from_secs(2), async {
        let first = Message::from_wire(&read_frame(&mut stream).await.unwrap()).unwrap();
        let second = Message::from_wire(&read_frame(&mut stream).await.unwrap()).unwrap();
        [first, second]
    })
    .await
    .unwrap();

    assert_eq!(started.load(Ordering::SeqCst), 2);
    assert!(responses.iter().any(|response| response.headers.id == 41));
    assert!(responses.iter().any(|response| response.headers.id == 42));
    assert!(responses.iter().all(|response| response.answers.len() == 2));
    assert!(
        responses
            .iter()
            .all(|response| response.edns().unwrap().is_some())
    );
    task.abort();
}

#[tokio::test]
async fn retries_after_a_peer_closes_a_reused_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config().0);
    let first_closed = Arc::new(Notify::new());
    let server_closed = Arc::clone(&first_closed);
    let handshake_kinds = Arc::new(Mutex::new(Vec::new()));
    let server_handshake_kinds = Arc::clone(&handshake_kinds);
    let server_task = tokio::spawn(async move {
        for connection in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            server_handshake_kinds
                .lock()
                .unwrap()
                .push(stream.get_ref().1.handshake_kind());
            let request = Message::from_wire(&read_frame(&mut stream).await.unwrap()).unwrap();
            let response = Message::builder()
                .headers(Headers {
                    id: request.headers.id,
                    qr: true,
                    ..Headers::default()
                })
                .questions(request.questions)
                .build()
                .unwrap();
            write_frame(&mut stream, &response.into_wire().unwrap())
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
            if connection == 0 {
                server_closed.notify_one();
            }
        }
    });
    let transport = TlsTransport::new(client_config("localhost"));

    transport
        .exchange(server, &query(41), Duration::from_secs(2))
        .await
        .unwrap();
    first_closed.notified().await;
    let response = transport
        .exchange(server, &query(42), Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(response.headers.id, 42);
    server_task.await.unwrap();
    assert_eq!(
        *handshake_kinds.lock().unwrap(),
        [
            Some(rustls::HandshakeKind::Full),
            Some(rustls::HandshakeKind::Resumed),
        ]
    );
}

#[tokio::test]
async fn sends_an_oversized_tls_response_unpadded_instead_of_closing() {
    let (server, task) = one_connection_server(|request: Message| async move {
        assert!(request.edns().unwrap().unwrap().padding().is_some());
        let answers = (0_u8..80)
            .map(|index| ResourceRecord {
                name: dns::DomainName::from_labels(vec![
                    format!("host-{index}").into_bytes(),
                    b"example".to_vec(),
                ])
                .unwrap(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::A(std::net::Ipv4Addr::new(192, 0, 2, index)),
            })
            .collect::<Vec<_>>();
        Message::builder()
            .headers(Headers {
                qr: true,
                ..Headers::default()
            })
            .answers(answers)
            .additionals([dns::Edns::new(1232).into_record()])
            .build()
            .unwrap()
    })
    .await;
    let transport = TlsTransport::new(client_config("localhost"));

    let response = transport
        .exchange(server, &query(42), Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(response.answers.len(), 80);
    assert!(response.edns().unwrap().unwrap().padding().is_none());
    assert!(response.into_wire().unwrap().len() > 1232);
    task.abort();
}

#[tokio::test]
async fn removes_unsolicited_response_padding() {
    let (server, task) = one_connection_server(|request: Message| async move {
        assert!(request.edns().unwrap().is_none());
        let mut edns = dns::Edns::new(1232);
        edns.set_padding(16);
        Message::builder()
            .headers(Headers {
                qr: true,
                ..Headers::default()
            })
            .additionals([edns.into_record()])
            .build()
            .unwrap()
    })
    .await;
    let transport = TlsTransport::new(client_config("localhost"));
    let unpadded = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([question(QueryType::A)])
        .build()
        .unwrap();

    let response = transport
        .exchange(server, &unpadded, Duration::from_secs(2))
        .await
        .unwrap();

    assert!(response.edns().unwrap().unwrap().padding().is_none());
    task.abort();
}
