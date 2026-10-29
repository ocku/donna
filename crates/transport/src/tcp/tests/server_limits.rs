use super::*;

#[tokio::test]
async fn bounds_admitted_tcp_connection_tasks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let activity = Arc::new(ConnectionActivity::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(serve_listener_with_policy(
        listener,
        CountingTcpHandler {
            calls: Arc::clone(&calls),
        },
        test_server_policy(),
        Some(Arc::clone(&activity)),
    ));

    let mut first = TcpStream::connect(address).await.unwrap();
    activity.wait_for(1).await;
    first
        .write_all(&(MAX_TCP_MESSAGE_OCTETS as u16).to_be_bytes())
        .await
        .unwrap();

    let mut second = TcpStream::connect(address).await.unwrap();
    write_frame(&mut second, &query(2).into_wire().unwrap())
        .await
        .unwrap();
    tokio::task::yield_now().await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);

    drop(first);
    let response = Message::from_wire(&read_frame(&mut second).await.unwrap()).unwrap();
    assert_eq!(response.headers.id, 2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);

    drop(second);
    activity.wait_for(0).await;
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn partial_frame_timeout_releases_the_connection_permit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let activity = Arc::new(ConnectionActivity::default());
    let server = tokio::spawn(serve_listener_with_policy(
        listener,
        CountingTcpHandler {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        test_server_policy(),
        Some(Arc::clone(&activity)),
    ));

    let mut first = TcpStream::connect(address).await.unwrap();
    activity.wait_for(1).await;
    first
        .write_all(&(MAX_TCP_MESSAGE_OCTETS as u16).to_be_bytes())
        .await
        .unwrap();

    let mut second = TcpStream::connect(address).await.unwrap();
    write_frame(&mut second, &query(3).into_wire().unwrap())
        .await
        .unwrap();

    time::advance(test_server_policy().frame_read_timeout).await;
    tokio::task::yield_now().await;

    let mut closed = [0_u8; 1];
    // Closing a timed-out socket may reset the peer when request octets are
    // still queued. Both outcomes close this connection; the second response
    // below independently proves that its admission permit was released.
    match first.read(&mut closed).await {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("timed-out connection was not closed: {other:?}"),
    }
    let response = Message::from_wire(&read_frame(&mut second).await.unwrap()).unwrap();
    assert_eq!(response.headers.id, 3);
    assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);

    drop(second);
    activity.wait_for(0).await;
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn handler_timeout_closes_the_connection_and_releases_its_permit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let activity = Arc::new(ConnectionActivity::default());
    let entered = Arc::new(Notify::new());
    let server = tokio::spawn(serve_listener_with_policy(
        listener,
        PendingTcpHandler {
            entered: Arc::clone(&entered),
        },
        test_server_policy(),
        Some(Arc::clone(&activity)),
    ));

    let mut client = TcpStream::connect(address).await.unwrap();
    write_frame(&mut client, &query(4).into_wire().unwrap())
        .await
        .unwrap();
    entered.notified().await;

    time::advance(test_server_policy().handler_reply_timeout).await;
    tokio::task::yield_now().await;

    let mut closed = [0_u8; 1];
    assert_eq!(client.read(&mut closed).await.unwrap(), 0);
    activity.wait_for(0).await;
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn persistent_connections_refresh_the_frame_read_deadline() {
    let (mut client, server_stream) = tokio::io::duplex(4096);
    let server = tokio::spawn(serve_connection(
        server_stream,
        "192.0.2.1:53".parse().unwrap(),
        Arc::new(CountingTcpHandler {
            calls: Arc::new(AtomicUsize::new(0)),
        }),
        test_server_policy(),
    ));

    for id in [10, 11, 12] {
        write_frame(&mut client, &query(id).into_wire().unwrap())
            .await
            .unwrap();
        let response = Message::from_wire(&read_frame(&mut client).await.unwrap()).unwrap();
        assert_eq!(response.headers.id, id);
        if id != 12 {
            time::advance(Duration::from_secs(9)).await;
        }
    }

    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn releases_connection_permits_on_non_timeout_exit_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let activity = Arc::new(ConnectionActivity::default());
    let server = tokio::spawn(serve_listener_with_policy(
        listener,
        ConditionalTcpHandler,
        test_server_policy(),
        Some(Arc::clone(&activity)),
    ));

    // Clean EOF.
    let client = TcpStream::connect(address).await.unwrap();
    activity.wait_for(1).await;
    drop(client);
    activity.wait_for(0).await;

    // A frame prefix followed by a short payload and EOF.
    let mut client = TcpStream::connect(address).await.unwrap();
    activity.wait_for(1).await;
    client.write_all(&4_u16.to_be_bytes()).await.unwrap();
    client.write_all(&[0, 1]).await.unwrap();
    client.shutdown().await.unwrap();
    activity.wait_for(0).await;

    // A malformed packet marked as a response cannot receive FORMERR.
    let mut client = TcpStream::connect(address).await.unwrap();
    activity.wait_for(1).await;
    write_frame(&mut client, &[0, 0, 0x80]).await.unwrap();
    activity.wait_for(0).await;

    // Returning without consuming the reply capability closes its channel.
    let mut client = TcpStream::connect(address).await.unwrap();
    activity.wait_for(1).await;
    write_frame(&mut client, &query(99).into_wire().unwrap())
        .await
        .unwrap();
    activity.wait_for(0).await;

    // The listener remains usable after all four connection-local failures.
    let mut client = TcpStream::connect(address).await.unwrap();
    write_frame(&mut client, &query(100).into_wire().unwrap())
        .await
        .unwrap();
    let response = Message::from_wire(&read_frame(&mut client).await.unwrap()).unwrap();
    assert_eq!(response.headers.id, 100);
    assert_eq!(activity.maximum.load(Ordering::SeqCst), 1);

    drop(client);
    activity.wait_for(0).await;
    server.abort();
}

#[tokio::test]
async fn write_failure_releases_the_owned_connection_permit() {
    let permits = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&permits).acquire_owned().await.unwrap();
    let (mut client, server_stream) = tokio::io::duplex(4096);
    write_frame(&mut client, &query(101).into_wire().unwrap())
        .await
        .unwrap();
    drop(client);

    let task = spawn_connection(
        server_stream,
        "192.0.2.1:53".parse().unwrap(),
        Arc::new(FixedTcpResponses(vec![Message::builder().build().unwrap()])),
        test_server_policy(),
        permit,
        None,
    );
    task.await.unwrap();

    assert_eq!(permits.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn response_write_timeout_is_bounded_for_a_full_size_frame() {
    let start = time::Instant::now();
    let error = write_frame_with_timeout(
        &mut PendingWriter,
        &vec![0; MAX_TCP_MESSAGE_OCTETS],
        test_server_policy().response_write_timeout,
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        time::Instant::now().duration_since(start),
        test_server_policy().response_write_timeout
    );
}

#[tokio::test]
async fn reads_the_full_tcp_frame_length() {
    let packet = vec![0xa5; MAX_TCP_MESSAGE_OCTETS];
    let expected = packet.clone();
    let (mut writer, mut reader) = tokio::io::duplex(MAX_TCP_MESSAGE_OCTETS + 2);
    let writing = tokio::spawn(async move { write_frame(&mut writer, &packet).await });

    let received = read_frame(&mut reader).await.unwrap();
    writing.await.unwrap().unwrap();

    assert_eq!(received.len(), MAX_TCP_MESSAGE_OCTETS);
    assert_eq!(received, expected);
}

#[tokio::test]
async fn returns_decode_error_for_a_malformed_response_frame() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        write_frame(&mut stream, &[0, 1, 2]).await.unwrap();
    });

    let error = TcpTransport
        .exchange(address, &query(42), Duration::from_secs(1))
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(matches!(error, TransportError::Decode(_)));
}

#[test]
fn streamed_axfr_validation_rejects_distinct_rrsets_beyond_its_budget() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut validator = AxfrSeriesValidator::new(request.questions[0].clone(), true, 2);

    let mut first = response_for(&request, request.headers.id);
    first.headers.aa = true;
    first.answers = vec![soa(1), a_record()];
    assert!(matches!(
        validator.accept(&first),
        Some(axfr::AxfrFrameStatus::Continue)
    ));

    let mut third_rrset = a_record();
    third_rrset.name =
        dns::DomainName::from_labels(vec![b"other".to_vec(), b"example".to_vec()]).unwrap();
    let mut second = response_for(&request, request.headers.id);
    second.headers.aa = true;
    second.questions.clear();
    second.answers = vec![third_rrset];

    assert!(validator.accept(&second).is_none());
    assert!(!validator.finish());
}

#[test]
fn validates_axfr_identity_zone_and_class() {
    let mut query = query(42);
    query.questions[0].qtype = QueryType::AXFR;
    let mut response = response_for(&query, 42);
    response.answers.push(soa(10));
    assert!(validate_transfer_message(&response, &query, true).is_ok());

    let mut subsequent = response.clone();
    subsequent.questions.clear();
    assert!(validate_transfer_message(&subsequent, &query, false).is_ok());
    assert!(validate_transfer_message(&subsequent, &query, true).is_err());
    subsequent.answers.clear();
    assert!(validate_transfer_message(&subsequent, &query, false).is_err());

    response.headers.opcode = dns::OpCode::Status;
    assert!(matches!(
        validate_transfer_message(&response, &query, true),
        Err(TransportError::InvalidTransfer(_))
    ));

    let mut record = soa(10);
    assert!(validate_transfer_record(&record, &query.questions[0]).is_ok());
    record.class = ClassType::CH;
    assert!(matches!(
        validate_transfer_record(&record, &query.questions[0]),
        Err(TransportError::InvalidTransfer(_))
    ));
    record.class = ClassType::IN;
    record.name = dns::DomainName::from_labels(vec![b"outside".to_vec()]).unwrap();
    assert!(matches!(
        validate_transfer_record(&record, &query.questions[0]),
        Err(TransportError::InvalidTransfer(_))
    ));

    // DNS names inside RDATA compare case-insensitively, including the
    // opening/closing SOA identity required by RFC 5936 §2.2.
    let mut opening = soa(10);
    let mut closing = opening.clone();
    let RData::SOA { mname, rname, .. } = &mut opening.rdata else {
        unreachable!()
    };
    *mname = dns::DomainName::from_labels(vec![b"ns".to_vec(), b"example".to_vec()]).unwrap();
    *rname =
        dns::DomainName::from_labels(vec![b"hostmaster".to_vec(), b"example".to_vec()]).unwrap();
    let RData::SOA { mname, rname, .. } = &mut closing.rdata else {
        unreachable!()
    };
    *mname = dns::DomainName::from_labels(vec![b"NS".to_vec(), b"EXAMPLE".to_vec()]).unwrap();
    *rname =
        dns::DomainName::from_labels(vec![b"HOSTMASTER".to_vec(), b"EXAMPLE".to_vec()]).unwrap();
    assert!(same_resource_record(&opening, &closing));
    assert!(!same_resource_record(&soa(10), &soa(11)));
}
