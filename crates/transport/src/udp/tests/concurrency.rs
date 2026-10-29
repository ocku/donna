use super::*;

#[tokio::test]
async fn panicking_udp_handler_does_not_stop_the_listener() {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let activity = Arc::new(PacketActivity::default());
    let server = tokio::spawn(serve_socket_with_policy(
        socket,
        |query: Message| async move {
            assert_ne!(query.headers.id, 1, "simulated application panic");
            query
        },
        test_server_policy(1),
        Some(Arc::clone(&activity)),
    ));
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    client.connect(address).await.unwrap();
    client.send(&udp_query(1)).await.unwrap();
    activity.wait_for_received(1).await;
    activity.wait_for_active(0).await;
    client.send(&udp_query(2)).await.unwrap();
    assert_eq!(receive_udp_message(&client).await.headers.id, 2);
    server.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_socket_service_preserves_exclusive_binding_and_replies() {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(super::super::server::serve_workers(
        socket,
        |query: Message| async move { query },
    ));
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    client.connect(address).await.unwrap();
    client.send(&udp_query(17)).await.unwrap();
    assert_eq!(receive_udp_message(&client).await.headers.id, 17);

    // A second independent invocation still fails to bind, even though this
    // invocation's workers share its socket internally.
    let error = UdpTransport
        .serve(address, |query: Message| async move { query })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    let reuse_listener = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    reuse_listener.set_reuse_port(true).unwrap();
    assert_eq!(
        reuse_listener.bind(&address.into()).unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn pending_handler_does_not_delay_a_ready_udp_reply() {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let activity = Arc::new(PacketActivity::default());
    let entered = Arc::new(Notify::new());
    let active = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(serve_socket_with_policy(
        socket,
        FirstRequestPendingHandler {
            entered: Arc::clone(&entered),
            active: Arc::clone(&active),
        },
        test_server_policy(2),
        Some(Arc::clone(&activity)),
    ));
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    client.connect(address).await.unwrap();

    client.send(&udp_query(1)).await.unwrap();
    entered.notified().await;
    client.send(&udp_query(2)).await.unwrap();
    assert_eq!(receive_udp_message(&client).await.headers.id, 2);
    assert_eq!(active.load(Ordering::SeqCst), 1);
    assert_eq!(activity.maximum.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn admits_only_one_udp_handler_until_its_permit_is_released() {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let activity = Arc::new(PacketActivity::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let releases = Arc::new(Semaphore::new(0));
    let server = tokio::spawn(serve_socket_with_policy(
        socket,
        BlockingUdpHandler {
            calls: Arc::clone(&calls),
            active: Arc::clone(&active),
            maximum: Arc::clone(&maximum),
            entered: Arc::clone(&entered),
            releases: Arc::clone(&releases),
        },
        test_server_policy(1),
        Some(Arc::clone(&activity)),
    ));
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    client.connect(address).await.unwrap();

    client.send(&udp_query(1)).await.unwrap();
    entered.notified().await;
    client.send(&udp_query(2)).await.unwrap();
    activity.wait_for_received(2).await;

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 1);
    assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);

    releases.add_permits(1);
    assert_eq!(receive_udp_message(&client).await.headers.id, 1);
    entered.notified().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    releases.add_permits(1);
    assert_eq!(receive_udp_message(&client).await.headers.id, 2);
    activity.wait_for_active(0).await;
    assert_eq!(maximum.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn handler_timeout_releases_the_udp_permit_and_serves_the_next_packet() {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let activity = Arc::new(PacketActivity::default());
    let entered = Arc::new(Notify::new());
    let active = Arc::new(AtomicUsize::new(0));
    let policy = test_server_policy(1);
    let server = tokio::spawn(serve_socket_with_policy(
        socket,
        FirstRequestPendingHandler {
            entered: Arc::clone(&entered),
            active: Arc::clone(&active),
        },
        policy,
        Some(Arc::clone(&activity)),
    ));
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    client.connect(address).await.unwrap();

    client.send(&udp_query(1)).await.unwrap();
    entered.notified().await;
    client.send(&udp_query(2)).await.unwrap();
    activity.wait_for_received(2).await;
    assert_eq!(active.load(Ordering::SeqCst), 1);

    time::advance(policy.handler_reply_timeout).await;
    tokio::task::yield_now().await;

    let response = receive_udp_message(&client).await;
    assert_eq!(response.headers.id, 2);
    activity.wait_for_active(0).await;
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn burst_handler_concurrency_never_exceeds_the_udp_policy_limit() {
    const PACKETS: usize = 6;
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let activity = Arc::new(PacketActivity::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let releases = Arc::new(Semaphore::new(0));
    let server = tokio::spawn(serve_socket_with_policy(
        socket,
        BlockingUdpHandler {
            calls: Arc::clone(&calls),
            active: Arc::clone(&active),
            maximum: Arc::clone(&maximum),
            entered,
            releases: Arc::clone(&releases),
        },
        test_server_policy(2),
        Some(Arc::clone(&activity)),
    ));
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    client.connect(address).await.unwrap();

    for id in 0..PACKETS as u16 {
        client.send(&udp_query(id)).await.unwrap();
    }
    activity.wait_for_received(3).await;
    activity.wait_for_active(2).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    releases.add_permits(PACKETS);
    for _ in 0..PACKETS {
        receive_udp_message(&client).await;
    }
    activity.wait_for_active(0).await;

    assert_eq!(calls.load(Ordering::SeqCst), PACKETS);
    assert_eq!(maximum.load(Ordering::SeqCst), 2);
    assert_eq!(activity.maximum.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn malformed_and_response_packets_release_udp_admission_permits() {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let activity = Arc::new(PacketActivity::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let handler = move |_query: Message| {
        handler_calls.fetch_add(1, Ordering::SeqCst);
        async { Message::builder().build().unwrap() }
    };
    let server = tokio::spawn(serve_socket_with_policy(
        socket,
        handler,
        test_server_policy(1),
        Some(Arc::clone(&activity)),
    ));
    let client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    client.connect(address).await.unwrap();

    client.send(&[0x12, 0x34, 0]).await.unwrap();
    assert_eq!(receive_udp_message(&client).await.headers.id, 0x1234);

    client.send(&[0x12, 0x35, 0x80]).await.unwrap();
    activity.wait_for_received(2).await;
    client.send(&udp_query(7)).await.unwrap();
    let response = receive_udp_message(&client).await;

    assert_eq!(response.headers.id, 7);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    activity.wait_for_active(0).await;
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn udp_response_send_timeout_is_bounded() {
    let start = time::Instant::now();
    let error = send_datagram_with_timeout(
        pending::<Result<usize, std::io::Error>>(),
        test_server_policy(1).response_send_timeout,
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        time::Instant::now().duration_since(start),
        test_server_policy(1).response_send_timeout
    );
}

#[tokio::test]
async fn rejects_a_zero_udp_packet_limit() {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let mut policy = test_server_policy(1);
    policy.packet_limit = 0;

    let error = serve_socket_with_policy(
        socket,
        |_query: Message| async { Message::builder().build().unwrap() },
        policy,
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn rejects_wildcard_server_bindings_that_cannot_preserve_the_query_destination() {
    let error = UdpTransport
        .serve(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            |query: Message| async move { query },
        )
        .await
        .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
