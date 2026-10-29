use super::*;

#[tokio::test]
async fn transfers_axfr_over_tls() {
    let (server, task) = one_connection_server(|request: Message| async move {
        assert!(request.edns().unwrap().unwrap().padding().is_some());
        Message {
            headers: Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            questions: Vec::new(),
            answers: vec![soa(), soa()],
            authorities: Vec::new(),
            // The TLS transport must add the OPT required by the request to
            // every AXFR response rather than delegating that wire invariant
            // to application handlers.
            additionals: Vec::new(),
        }
    })
    .await;
    let transport = TlsTransport::new(client_config("localhost"));
    let request = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([question(QueryType::AXFR)])
        .additionals([dns::Edns::new(1232).into_record()])
        .build()
        .unwrap();

    for _ in 0..2 {
        let records = transport
            .transfer(server, &request, Duration::from_secs(2))
            .await
            .unwrap();

        assert_eq!(records.len(), 2);
        assert!(records[0].eq_dns(&soa()));
        assert!(records[1].eq_dns(&soa()));
    }
    task.abort();
}

#[tokio::test]
async fn retries_an_interrupted_axfr_on_a_fresh_tls_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config().0);
    let server_task = tokio::spawn(async move {
        for connection in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let request = Message::from_wire(&read_frame(&mut stream).await.unwrap()).unwrap();
            let opening = Message::builder()
                .headers(Headers {
                    id: request.headers.id,
                    qr: true,
                    aa: true,
                    ..Headers::default()
                })
                .questions(request.questions)
                .answers([soa()])
                .build()
                .unwrap();
            write_frame(&mut stream, &opening.into_wire().unwrap())
                .await
                .unwrap();
            if connection == 1 {
                let closing = Message::builder()
                    .headers(Headers {
                        id: request.headers.id,
                        qr: true,
                        aa: true,
                        ..Headers::default()
                    })
                    .answers([soa()])
                    .build()
                    .unwrap();
                write_frame(&mut stream, &closing.into_wire().unwrap())
                    .await
                    .unwrap();
            }
            stream.shutdown().await.unwrap();
        }
    });
    let transport = TlsTransport::new(client_config("localhost"));
    let request = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([question(QueryType::AXFR)])
        .additionals([dns::Edns::new(1232).into_record()])
        .build()
        .unwrap();

    let records = transport
        .transfer(server, &request, Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(records.len(), 2);
    server_task.await.unwrap();
}

#[tokio::test]
async fn an_axfr_waiter_reconnects_when_a_transfer_is_cancelled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config().0);
    let first_response_started = Arc::new(Notify::new());
    let server_first_response_started = Arc::clone(&first_response_started);
    let server_task = tokio::spawn(async move {
        let (first, _) = listener.accept().await.unwrap();
        let mut first = acceptor.accept(first).await.unwrap();
        let request = Message::from_wire(&read_frame(&mut first).await.unwrap()).unwrap();
        assert_eq!(request.headers.id, 41);
        let opening = Message::builder()
            .headers(Headers {
                id: request.headers.id,
                qr: true,
                aa: true,
                ..Headers::default()
            })
            .questions(request.questions)
            .answers([soa()])
            .build()
            .unwrap();
        write_frame(&mut first, &opening.into_wire().unwrap())
            .await
            .unwrap();
        server_first_response_started.notify_one();

        let (second, _) = listener.accept().await.unwrap();
        let mut second = acceptor.accept(second).await.unwrap();
        let request = Message::from_wire(&read_frame(&mut second).await.unwrap()).unwrap();
        assert_eq!(request.headers.id, 42);
        let complete = Message::builder()
            .headers(Headers {
                id: request.headers.id,
                qr: true,
                aa: true,
                ..Headers::default()
            })
            .questions(request.questions)
            .answers([soa(), soa()])
            .build()
            .unwrap();
        write_frame(&mut second, &complete.into_wire().unwrap())
            .await
            .unwrap();
    });
    let transport = TlsTransport::new(client_config("localhost"));
    let mut first_request = query(41);
    first_request.questions[0].qtype = QueryType::AXFR;
    let mut second_request = query(42);
    second_request.questions[0].qtype = QueryType::AXFR;

    let first_transport = transport.clone();
    let first = tokio::spawn(async move {
        first_transport
            .transfer(server, &first_request, Duration::from_secs(2))
            .await
    });
    first_response_started.notified().await;

    let second_transport = transport.clone();
    let second = tokio::spawn(async move {
        second_transport
            .transfer(server, &second_request, Duration::from_secs(2))
            .await
    });
    tokio::task::yield_now().await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());

    let records = second.await.unwrap().unwrap();
    assert_eq!(records.len(), 2);
    server_task.await.unwrap();
}

#[tokio::test]
async fn accepts_padding_only_messages_during_axfr_over_tls() {
    let opening = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        })
        .answers([soa()])
        .additionals([dns::Edns::new(1232).into_record()])
        .build()
        .unwrap();
    let padding_only = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        })
        .additionals([dns::Edns::new(1232).into_record()])
        .build_unchecked();
    let closing = opening.clone();
    let (server, task) =
        one_connection_server(FixedTlsResponses(vec![opening, padding_only, closing])).await;
    let transport = TlsTransport::new(client_config("localhost"));
    let request = Message::builder()
        .headers(Headers {
            id: 42,
            ..Headers::default()
        })
        .questions([question(QueryType::AXFR)])
        .additionals([dns::Edns::new(1232).into_record()])
        .build()
        .unwrap();

    let records = transport
        .transfer(server, &request, Duration::from_secs(2))
        .await
        .unwrap();

    assert_eq!(records.len(), 2);
    assert!(records[0].eq_dns(&soa()));
    assert!(records[1].eq_dns(&soa()));
    task.abort();
}
