use super::*;

#[tokio::test]
async fn rejects_untrusted_certificates_and_wrong_authentication_names() {
    for wrong_name in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let (server, task) = one_connection_server(EchoHandler(Arc::clone(&calls))).await;
        let mut roots = RootCertStore::empty();
        if wrong_name {
            roots.add(certificate()).unwrap();
        }
        let name = if wrong_name {
            "wrong.example"
        } else {
            "localhost"
        };
        let config = DoqClientConfig::new(roots, name.to_owned()).unwrap();
        assert!(
            DoqTransport::new(config)
                .exchange(server, &query(7, QueryType::A), Duration::from_secs(2))
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        task.abort();
    }
}

#[tokio::test]
async fn stream_queries_ignore_the_edns_udp_size_up_to_the_dns_limit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server(EchoHandler(calls)).await;
    let transport = DoqTransport::new(client_config());
    // Repeat the full-size exchange so ACK-only traffic from either peer
    // cannot consume the connection's congestion credit and stall reuse.
    for length in [4096, 65535, 65535] {
        let request =
            crate::tests::fixtures::query_with_wire_length(query(73, QueryType::A), length);
        let response = transport
            .exchange(server, &request, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.headers.id, 73);
        assert_eq!(response.edns().unwrap().unwrap().udp_payload_size, 1232);
        assert!(!response.headers.tc);
        assert!(response.into_wire().unwrap().len() >= length);
    }
    task.abort();
}

#[tokio::test]
async fn dropped_and_timed_out_transactions_send_the_doq_cancellation_code() {
    for qtype in [QueryType::A, QueryType::AXFR] {
        for abort in [false, true] {
            let config = DoqServerConfig::new(vec![certificate()], private_key()).unwrap();
            let endpoint = Endpoint::server(config.0, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = endpoint.local_addr().unwrap();
            let (started, ready) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let (send, mut receive) = connection.accept_bi().await.unwrap();
                read_frame(&mut receive).await.unwrap();
                receive.read_to_end(0).await.unwrap();
                started.send(()).unwrap();
                assert_eq!(send.stopped().await.unwrap(), Some(DOQ_REQUEST_CANCELLED));
                // Cancelling a transaction must leave the shared connection usable.
                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                let packet = read_frame(&mut receive).await.unwrap();
                let mut response = Message::from_wire(&packet).unwrap();
                response.headers.qr = true;
                write_frame(&mut send, &response.into_wire().unwrap())
                    .await
                    .unwrap();
                send.finish().unwrap();
                connection.closed().await;
            });
            let transport = DoqTransport::new(client_config());
            let client = transport.clone();
            let transaction = tokio::spawn(async move {
                let request = query(0, qtype);
                let timeout = if abort {
                    Duration::from_secs(10)
                } else {
                    Duration::from_millis(250)
                };
                if qtype == QueryType::AXFR {
                    client
                        .transfer(address, &request, timeout)
                        .await
                        .map(|_| ())
                } else {
                    client
                        .exchange(address, &request, timeout)
                        .await
                        .map(|_| ())
                }
            });
            time::timeout(Duration::from_secs(2), ready)
                .await
                .unwrap()
                .unwrap();
            if abort {
                transaction.abort();
                assert!(transaction.await.unwrap_err().is_cancelled());
            } else {
                assert!(matches!(
                    transaction.await.unwrap(),
                    Err(TransportError::Timeout)
                ));
            }
            let response = transport
                .exchange(address, &query(17, QueryType::A), Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(response.headers.id, 17);
            drop(transport);
            time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }
}

fn with_keepalive(mut message: Message) -> Message {
    let mut edns = dns::Edns::new(1232);
    edns.options.push(dns::EdnsOption {
        code: 11,
        data: Vec::new(),
    });
    message.additionals = vec![edns.into_record()];
    message
}

#[test]
fn outgoing_queries_reject_tcp_keepalive() {
    for qtype in [QueryType::A, QueryType::AXFR, QueryType::IXFR] {
        let mut request = query(0, QueryType::A);
        request.questions[0].qtype = qtype;
        assert!(matches!(
            prepare_query(&with_keepalive(request)),
            Err(TransportError::InvalidQuicProtocol(_))
        ));
    }
}

#[tokio::test]
async fn malformed_peer_queries_close_the_connection() {
    for case in 0..3 {
        let (server, task) =
            one_connection_server(EchoHandler(Arc::new(AtomicUsize::new(0)))).await;
        let transport = DoqTransport::new(client_config());
        let connection = transport
            .connect(server, time::Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let (mut send, _receive) = connection.open_bi().await.unwrap();
        let message = match case {
            0 => with_keepalive(query(0, QueryType::A)),
            1 => query(7, QueryType::A),
            _ => query(0, QueryType::A),
        };
        let wire = message.into_wire().unwrap();
        write_frame(&mut send, &wire).await.unwrap();
        if case == 2 {
            write_frame(&mut send, &wire).await.unwrap();
        }
        send.finish().unwrap();
        let error = time::timeout(Duration::from_secs(2), connection.closed())
            .await
            .unwrap();
        assert!(
            matches!(error, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == DOQ_PROTOCOL_ERROR)
        );
        task.abort();
    }
}

struct KeepaliveHandler;

impl DnsRequestHandler for KeepaliveHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let response = with_keepalive(request.message().clone());
            assert!(request.respond(response));
        })
    }
}

#[tokio::test]
async fn rejects_handler_keepalive_without_sending_it() {
    let (server, task) = one_connection_server(KeepaliveHandler).await;
    let transport = DoqTransport::new(client_config());
    assert!(
        transport
            .exchange(server, &query(0, QueryType::A), Duration::from_secs(2))
            .await
            .is_err()
    );
    task.abort();
}

#[tokio::test]
async fn peer_keepalive_responses_close_standard_and_transfer_connections() {
    for qtype in [QueryType::A, QueryType::AXFR] {
        let config = DoqServerConfig::new(vec![certificate()], private_key()).unwrap();
        let endpoint = Endpoint::server(config.0, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let packet = read_frame(&mut receive).await.unwrap();
            let mut response = with_keepalive(Message::from_wire(&packet).unwrap());
            response.headers.qr = true;
            if qtype == QueryType::AXFR {
                response.headers.aa = true;
                let record = soa(response.questions[0].qname.clone());
                response.answers = vec![record.clone(), record];
            }
            write_frame(&mut send, &response.into_wire().unwrap())
                .await
                .unwrap();
            send.finish().unwrap();
            let error = connection.closed().await;
            assert!(
                matches!(error, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == DOQ_PROTOCOL_ERROR)
            );
        });
        let transport = DoqTransport::new(client_config());
        let result = if qtype == QueryType::AXFR {
            transport
                .transfer(address, &query(0, qtype), Duration::from_secs(2))
                .await
                .map(|_| ())
        } else {
            transport
                .exchange(address, &query(0, qtype), Duration::from_secs(2))
                .await
                .map(|_| ())
        };
        assert!(matches!(
            result,
            Err(TransportError::InvalidQuicProtocol(_))
        ));
        time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn peer_cancellation_does_not_close_connection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, task) = one_connection_server(EchoHandler(Arc::clone(&calls))).await;
    let transport = DoqTransport::new(client_config());
    let connection = transport
        .connect(server, time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    send.write_all(&[0, 100, 1]).await.unwrap();
    send.reset(DOQ_REQUEST_CANCELLED).unwrap();
    receive.stop(DOQ_REQUEST_CANCELLED).unwrap();
    let response = transport
        .exchange(server, &query(23, QueryType::A), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(response.headers.id, 23);
    assert!(connection.close_reason().is_none());
    task.abort();
}

#[tokio::test]
async fn invalid_peer_responses_close_standard_and_transfer_connections() {
    for qtype in [QueryType::A, QueryType::AXFR] {
        for case in 0..5 {
            let config = DoqServerConfig::new(vec![certificate()], private_key()).unwrap();
            let endpoint = Endpoint::server(config.0, "127.0.0.1:0".parse().unwrap()).unwrap();
            let address = endpoint.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                let packet = read_frame(&mut receive).await.unwrap();
                match case {
                    0 | 4 => {
                        let mut response = Message::from_wire(&packet).unwrap();
                        response.headers.qr = true;
                        response.headers.id = if case == 0 { 17 } else { 0 };
                        if qtype == QueryType::AXFR {
                            response.headers.aa = true;
                            let record = soa(response.questions[0].qname.clone());
                            response.answers = if case == 4 {
                                vec![record]
                            } else {
                                vec![record.clone(), record]
                            };
                        } else if case == 4 {
                            response.headers.qr = false;
                        }
                        write_frame(&mut send, &response.into_wire().unwrap())
                            .await
                            .unwrap();
                    }
                    1 => send.write_all(&[0]).await.unwrap(),
                    2 => send.write_all(&[0, 12, 0, 0]).await.unwrap(),
                    _ => write_frame(&mut send, &[0; 3]).await.unwrap(),
                }
                send.finish().unwrap();
                let error = connection.closed().await;
                assert!(
                    matches!(error, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == DOQ_PROTOCOL_ERROR)
                );
            });
            let transport = DoqTransport::new(client_config());
            let result = if qtype == QueryType::AXFR {
                transport
                    .transfer(address, &query(0, qtype), Duration::from_secs(2))
                    .await
                    .map(|_| ())
            } else {
                transport
                    .exchange(address, &query(0, qtype), Duration::from_secs(2))
                    .await
                    .map(|_| ())
            };
            assert!(result.is_err(), "case {case} {qtype:?}");
            time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }
}

#[tokio::test]
async fn server_stop_sending_is_a_protocol_error_for_queries_and_transfers() {
    for qtype in [QueryType::A, QueryType::AXFR] {
        let mut config = DoqServerConfig::new(vec![certificate()], private_key()).unwrap();
        // Hold the client in its write so a peer STOP_SENDING is observable
        // before the complete query and FIN can be acknowledged.
        Arc::get_mut(&mut config.0.transport)
            .unwrap()
            .stream_receive_window(16_u32.into());
        let endpoint = Endpoint::server(config.0, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (send, mut receive) = connection.accept_bi().await.unwrap();
            let mut first = [0; 1];
            receive.read_exact(&mut first).await.unwrap();
            receive.stop(VarInt::from_u32(77)).unwrap();
            let error = connection.closed().await;
            assert!(matches!(error,
                quinn::ConnectionError::ApplicationClosed(close)
                    if close.error_code == DOQ_PROTOCOL_ERROR));
            drop(send);
        });
        let transport = DoqTransport::new(client_config());
        let request = crate::tests::fixtures::query_with_wire_length(query(0, qtype), 65535);
        let result = if qtype == QueryType::AXFR {
            transport
                .transfer(address, &request, Duration::from_secs(2))
                .await
                .map(|_| ())
        } else {
            transport
                .exchange(address, &request, Duration::from_secs(2))
                .await
                .map(|_| ())
        };
        assert!(
            matches!(result, Err(TransportError::InvalidQuicProtocol(_))),
            "{result:?}"
        );
        time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
