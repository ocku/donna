use super::*;

struct ConcurrentTransfers(Arc<tokio::sync::Barrier>);

impl DnsRequestHandler for ConcurrentTransfers {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            // All four transactions must enter the handler before any may finish.
            self.0.wait().await;
            let question = &request.message().questions[0];
            let mut current = soa(question.qname.clone());
            if let RData::SOA { serial, .. } = &mut current.rdata {
                *serial = 2;
            }
            let answers = if question.qtype == QueryType::IXFR {
                vec![
                    current.clone(),
                    soa(question.qname.clone()),
                    current.clone(),
                    current,
                ]
            } else {
                vec![current.clone(), current]
            };
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            assert!(request.respond_stream(receiver));
            for answer in answers {
                sender
                    .send(Message {
                        headers: Headers {
                            aa: true,
                            ..Headers::default()
                        },
                        questions: Vec::new(),
                        answers: vec![answer],
                        authorities: Vec::new(),
                        additionals: Vec::new(),
                    })
                    .await
                    .unwrap();
            }
        })
    }
}

#[tokio::test]
async fn concurrent_axfr_and_ixfr_streams_share_one_connection() {
    let (server, task) =
        one_connection_server(ConcurrentTransfers(Arc::new(tokio::sync::Barrier::new(4)))).await;
    let transport = DoqTransport::new(client_config());
    let connection = transport
        .connect(server, time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let mut transfers = tokio::task::JoinSet::new();
    for qtype in [
        QueryType::AXFR,
        QueryType::IXFR,
        QueryType::AXFR,
        QueryType::IXFR,
    ] {
        let connection = connection.clone();
        transfers.spawn(async move {
            let mut request = query(0, QueryType::A);
            request.questions[0].qtype = qtype;
            if qtype == QueryType::IXFR {
                request
                    .authorities
                    .push(soa(request.questions[0].qname.clone()));
            }
            let request = prepare_query(&request).unwrap();
            let (mut send, mut receive) = connection.open_bi().await.unwrap();
            write_frame(&mut send, &request.into_wire().unwrap())
                .await
                .unwrap();
            send.finish().unwrap();
            let expected = if qtype == QueryType::IXFR { 4 } else { 2 };
            let mut serials = Vec::new();
            for index in 0..expected {
                let wire = read_frame(&mut receive).await.unwrap();
                let response = Message::from_wire(&wire).unwrap();
                assert!(response.headers.qr);
                assert_eq!(response.headers.id, 0);
                assert!(response.edns().unwrap().unwrap().padding().is_some());
                assert!(
                    (index > 0 && response.questions.is_empty())
                        || crate::same_questions(&response.questions, &request.questions)
                );
                if let RData::SOA { serial, .. } = response.answers[0].rdata {
                    serials.push(serial);
                }
            }
            receive.read_to_end(0).await.unwrap();
            assert_eq!(
                serials,
                if qtype == QueryType::IXFR {
                    vec![2, 1, 2, 2]
                } else {
                    vec![2, 2]
                }
            );
        });
    }
    time::timeout(Duration::from_secs(2), async {
        while let Some(result) = transfers.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(connection.close_reason().is_none());
    task.abort();
}

#[tokio::test]
async fn local_transfer_limits_leave_the_connection_usable() {
    let (server, task) = one_connection_server(TransferHandler).await;
    let transport = DoqTransport::new(client_config());
    let request = query(0, QueryType::AXFR);
    for limits in [
        crate::AxfrLimits::new(1, 100),
        crate::AxfrLimits::new(10000, 1),
    ] {
        assert!(matches!(
            transport
                .transfer_with_limits(server, &request, Duration::from_secs(2), limits)
                .await,
            Err(TransportError::InvalidTransfer(_))
        ));
    }
    let records = transport
        .transfer(server, &request, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    task.abort();
}

struct CancellationNotice(tokio::sync::mpsc::UnboundedSender<()>);

impl Drop for CancellationNotice {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

struct StalledTransferHandler(tokio::sync::mpsc::UnboundedSender<()>);

impl DnsRequestHandler for StalledTransferHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let mut response = request.message().clone();
            if response.questions[0].qtype == QueryType::A {
                assert!(request.respond(response));
                return;
            }
            let _notice = CancellationNotice(self.0.clone());
            response.headers.aa = true;
            response.authorities.clear();
            response.answers = vec![soa(response.questions[0].qname.clone())];
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            assert!(request.respond_stream(receiver));
            sender.send(response).await.unwrap();
            // Keep the producer alive without producing another frame. Cancellation
            // must interrupt the server's channel receive, not wait for its timeout.
            sender.closed().await;
        })
    }
}

#[tokio::test]
async fn cancelling_stalled_streamed_transfers_stops_the_handler_and_reuses_the_connection() {
    let (cancelled, mut cancellations) = tokio::sync::mpsc::unbounded_channel();
    let (server, task) = one_connection_server(StalledTransferHandler(cancelled)).await;
    let transport = DoqTransport::new(client_config());
    let connection = transport
        .connect(server, time::Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    for qtype in [QueryType::AXFR, QueryType::IXFR] {
        let mut request = query(0, QueryType::A);
        request.questions[0].qtype = qtype;
        if qtype == QueryType::IXFR {
            request
                .authorities
                .push(soa(request.questions[0].qname.clone()));
        }
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        write_frame(&mut send, &request.into_wire().unwrap())
            .await
            .unwrap();
        send.finish().unwrap();
        time::timeout(Duration::from_secs(2), read_frame(&mut receive))
            .await
            .unwrap()
            .unwrap();
        receive.stop(DOQ_REQUEST_CANCELLED).unwrap();
        time::timeout(Duration::from_secs(2), cancellations.recv())
            .await
            .expect("the cancelled transfer handler must stop promptly")
            .unwrap();
        assert!(connection.close_reason().is_none());
        assert!(
            transport
                .exchange(server, &query(17, QueryType::A), Duration::from_secs(2))
                .await
                .unwrap()
                .headers
                .qr
        );
    }
    task.abort();
}
