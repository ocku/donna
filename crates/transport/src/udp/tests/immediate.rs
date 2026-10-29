use super::*;

struct ImmediateHandler {
    wire: Vec<u8>,
    response: Message,
}

#[test]
fn deferred_preparation_is_not_inherited_by_another_handler_instance() {
    let first = ImmediateHandler {
        wire: vec![],
        response: unrelated_formerr(),
    };
    let second = ImmediateHandler {
        wire: vec![],
        response: unrelated_formerr(),
    };
    let (mut request, _reply) = DnsRequest::channel_with_wire(
        Message::from_wire(&udp_query(42)).unwrap(),
        udp_query(42),
        (Ipv4Addr::LOCALHOST, 1234).into(),
        crate::TransportProtocol::Udp,
    );
    request.immediate_handler = Some((
        std::any::TypeId::of::<ImmediateHandler>(),
        std::ptr::from_ref(&first).addr(),
    ));
    assert!(request.immediate_handling_attempted_by(&first));
    assert!(!request.immediate_handling_attempted_by(&second));
}

impl DnsRequestHandler for ImmediateHandler {
    fn try_handle(
        &self,
        message: &Message,
        wire: &[u8],
        peer: SocketAddr,
        protocol: crate::TransportProtocol,
    ) -> Option<Message> {
        assert_eq!(wire, self.wire);
        assert_eq!(
            message.into_wire().unwrap(),
            Message::from_wire(wire).unwrap().into_wire().unwrap()
        );
        assert_eq!(peer, SocketAddr::from((Ipv4Addr::LOCALHOST, 1234)));
        assert_eq!(protocol, crate::TransportProtocol::Udp);
        Some(self.response.clone())
    }

    fn handle<'future>(&'future self, _request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            panic!("an immediate reply must not create an asynchronous request");
        })
    }
}

async fn compare_paths(query: Message, response: Message) -> Option<Vec<u8>> {
    let wire = query.into_wire().unwrap();
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
    let immediate = ImmediateHandler {
        wire: wire.clone(),
        response: response.clone(),
    };
    let ordinary = move |_request: Message| {
        let response = response.clone();
        async move { response }
    };
    let expected = response_for_peer(&ordinary, peer, &wire).await;
    let actual = response_for_peer(&immediate, peer, &wire).await;
    assert_eq!(actual, expected);
    actual
}

#[tokio::test]
async fn immediate_replies_keep_normalization_padding_and_whole_record_truncation() {
    let query = Message::from_wire(&udp_query(42)).unwrap();
    let mut response = oversized_response();
    response.headers.id = 99;
    response.questions.clear();
    response.additionals.push(padded_opt());
    let wire = compare_paths(query.clone(), response).await.unwrap();
    let response = Message::from_wire(&wire).unwrap();
    assert_eq!(response.headers.id, 42);
    assert!(crate::same_questions(&response.questions, &query.questions));
    assert!(response.headers.tc);
    assert!(wire.len() <= 512);
    assert!(!crate::message::message_has_edns_padding(&response));
}

#[tokio::test]
async fn immediate_replies_preserve_authenticated_bytes_and_reject_wrong_headers() {
    for case in crate::tests::signed_responses::SignedResponse::cases(42) {
        let wire = compare_paths(case.request.clone(), case.response.clone())
            .await
            .unwrap();
        case.verify(&Message::from_wire(&wire).unwrap());
        if crate::has_tsig(&case.response) {
            let mut wrong = case.response.clone();
            wrong.headers.id = 43;
            assert!(compare_paths(case.request, wrong).await.is_none());
        }
    }
}

#[cfg(target_os = "linux")]
mod receive_buffers {
    use super::*;

    struct MixedHandler {
        releases: Arc<Semaphore>,
    }

    impl DnsRequestHandler for MixedHandler {
        fn try_handle(
            &self,
            message: &Message,
            _wire: &[u8],
            _peer: SocketAddr,
            _protocol: crate::TransportProtocol,
        ) -> Option<Message> {
            assert_ne!(message.headers.id, 1, "simulated immediate handler panic");
            (message.headers.id != 3).then(|| message.clone())
        }

        fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
            Box::pin(async move {
                assert!(request.immediate_handling_attempted_by(self));
                assert_eq!(request.message().headers.id, 3);
                self.releases.acquire().await.unwrap().forget();
                // Other packets have since reused the receive slot. Pending
                // authentication must retain the original received wire image.
                assert_eq!(request.wire_message(), udp_query(3));
                let response = request.message().clone();
                assert!(request.respond(response));
            })
        }
    }

    #[tokio::test]
    async fn immediate_panic_and_pending_wire_ownership_survive_buffer_reuse() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(socket.local_addr().unwrap()).await.unwrap();
        let activity = Arc::new(PacketActivity::default());
        let releases = Arc::new(Semaphore::new(0));
        let server = tokio::spawn(crate::udp::batch::receive_packets(
            socket,
            Arc::new(MixedHandler {
                releases: Arc::clone(&releases),
            }),
            test_server_policy(2),
            Some(Arc::clone(&activity)),
            Arc::new(Semaphore::new(2)),
            16,
        ));
        client.send(&udp_query(1)).await.unwrap();
        activity.wait_for_received(1).await;
        activity.wait_for_active(0).await;
        client.send(&udp_query(3)).await.unwrap();
        activity.wait_for_active(1).await;
        for id in [2, 4] {
            client.send(&udp_query(id)).await.unwrap();
            let response =
                tokio::time::timeout(Duration::from_secs(2), receive_udp_message(&client))
                    .await
                    .unwrap();
            assert_eq!(response.headers.id, id);
        }
        releases.add_permits(1);
        let response = tokio::time::timeout(Duration::from_secs(2), receive_udp_message(&client))
            .await
            .unwrap();
        assert_eq!(response.headers.id, 3);
        activity.wait_for_active(0).await;
        assert!(activity.maximum.load(Ordering::SeqCst) <= 2);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn single_worker_bursts_preserve_peers_and_pending_wire_after_panic() {
        assert_eq!(tokio::runtime::Handle::current().metrics().num_workers(), 1);
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let socket = UdpSocket::bind(bind).await.unwrap();
            let address = socket.local_addr().unwrap();
            let mut clients = Vec::new();
            for _ in 0..2 {
                let client = UdpSocket::bind(bind).await.unwrap();
                client.connect(address).await.unwrap();
                clients.push(client);
            }
            let releases = Arc::new(Semaphore::new(0));
            let server = tokio::spawn(super::super::super::server::serve_workers(
                socket,
                MixedHandler {
                    releases: Arc::clone(&releases),
                },
            ));
            // A panicking immediate handler must not kill this sole worker.
            // The pending request retains its own bytes across later batches.
            clients[0].send(&udp_query(1)).await.unwrap();
            clients[0].send(&udp_query(3)).await.unwrap();
            for id in 100..148 {
                clients[usize::from(id % 2)]
                    .send(&udp_query(id))
                    .await
                    .unwrap();
            }
            for (peer, client) in clients.iter().enumerate() {
                let mut received = std::collections::BTreeSet::new();
                for _ in 0..24 {
                    let reply =
                        tokio::time::timeout(Duration::from_secs(2), receive_udp_message(client))
                            .await
                            .unwrap();
                    assert_eq!(usize::from(reply.headers.id % 2), peer);
                    let expected = Message::from_wire(&udp_query(reply.headers.id)).unwrap();
                    assert!(crate::same_questions(&reply.questions, &expected.questions));
                    assert!(received.insert(reply.headers.id), "duplicate reply");
                }
                let expected = (100..148)
                    .filter(|id| usize::from(id % 2) == peer)
                    .collect::<std::collections::BTreeSet<u16>>();
                assert_eq!(received, expected);
            }
            releases.add_permits(1);
            let pending =
                tokio::time::timeout(Duration::from_secs(2), receive_udp_message(&clients[0]))
                    .await
                    .unwrap();
            assert_eq!(pending.headers.id, 3);
            assert!(!server.is_finished());
            server.abort();
            let _ = server.await;
            // Aborting the outer service must also drop its worker/socket.
            let rebound = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match UdpSocket::bind(address).await {
                        Ok(socket) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                            tokio::task::yield_now().await;
                        }
                        Err(error) => panic!("rebind failed: {error}"),
                    }
                }
            })
            .await
            .unwrap();
            drop(rebound);
        }
    }
}
