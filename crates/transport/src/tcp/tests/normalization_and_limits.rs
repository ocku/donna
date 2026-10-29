use super::*;

#[tokio::test]
async fn normalizes_split_rrsig_ttls_by_type_covered() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let expected = request.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        let mut first = response_for(&expected, 42);
        first.headers.aa = true;
        first.answers = vec![soa(10), rrsig(RecordType::A, 60, 1)];
        write_frame(&mut stream, &first.into_wire().unwrap())
            .await
            .unwrap();

        let mut second = response_for(&expected, 42);
        second.questions.clear();
        second.answers = vec![rrsig(RecordType::A, 20, 2)];
        write_frame(&mut stream, &second.into_wire().unwrap())
            .await
            .unwrap();

        let mut third = response_for(&expected, 42);
        third.questions.clear();
        third.answers = vec![rrsig(RecordType::AAAA, 30, 3), soa(10)];
        write_frame(&mut stream, &third.into_wire().unwrap())
            .await
            .unwrap();
    });

    let records = TcpTransport
        .transfer(address, &request, Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(records.len(), 5);
    assert_eq!(records[1].ttl, 20);
    assert_eq!(records[2].ttl, 20);
    assert_eq!(records[3].ttl, 30);
}

#[tokio::test]
async fn normalizes_split_axfr_rrset_and_lower_ttl_duplicate() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let expected = request.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        let mut first = response_for(&expected, 42);
        first.headers.aa = true;
        first.answers = vec![soa(10), a_record()];
        write_frame(&mut stream, &first.into_wire().unwrap())
            .await
            .unwrap();

        let mut duplicate = a_record();
        duplicate.name =
            dns::DomainName::from_labels(vec![b"WWW".to_vec(), b"EXAMPLE".to_vec()]).unwrap();
        duplicate.ttl = 20;
        let mut second = response_for(&expected, 42);
        second.questions.clear();
        second.answers = vec![duplicate];
        write_frame(&mut stream, &second.into_wire().unwrap())
            .await
            .unwrap();

        let mut other = a_record();
        other.name =
            dns::DomainName::from_labels(vec![b"WwW".to_vec(), b"Example".to_vec()]).unwrap();
        other.ttl = 30;
        other.rdata = RData::A(std::net::Ipv4Addr::new(127, 0, 0, 2));
        let mut third = response_for(&expected, 42);
        third.questions.clear();
        third.answers = vec![other, soa(10)];
        write_frame(&mut stream, &third.into_wire().unwrap())
            .await
            .unwrap();
    });

    let records = TcpTransport
        .transfer(address, &request, Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(records.len(), 4);
    assert!(records[1..3].iter().all(|record| record.ttl == 20));
    assert_eq!(records[1].rdata, RData::A(std::net::Ipv4Addr::LOCALHOST));
    assert_eq!(
        records[2].rdata,
        RData::A(std::net::Ipv4Addr::new(127, 0, 0, 2))
    );
}

#[tokio::test]
async fn axfr_limits_accept_a_multiframe_transfer_exactly_at_both_limits() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let expected = request.clone();
    let mut first = response_for(&request, 42);
    first.headers.aa = true;
    first.answers = vec![soa(10), a_record()];
    let mut last = response_for(&request, 42);
    last.questions.clear();
    last.answers = vec![soa(10)];
    let first_packet = first.into_wire().unwrap();
    let last_packet = last.into_wire().unwrap();
    let byte_limit = first_packet.len() + last_packet.len();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        write_frame(&mut stream, &first_packet).await.unwrap();
        write_frame(&mut stream, &last_packet).await.unwrap();
    });

    let records = TcpTransport
        .transfer_with_limits(
            address,
            &request,
            Duration::from_secs(1),
            AxfrLimits::new(byte_limit, 3),
        )
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(records.len(), 3);
    assert!(same_resource_record(&records[0], &records[2]));
    assert!(AxfrLimits::default().max_wire_bytes() < usize::MAX);
    assert!(AxfrLimits::default().max_records() < usize::MAX);
    assert!(crate::same_questions(
        &expected.questions,
        &request.questions
    ));
}

#[tokio::test]
async fn axfr_wire_limit_is_charged_before_decode_and_stops_reading() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = response_for(&request, 42);
    first.headers.aa = true;
    first.answers = vec![soa(10), a_record()];
    let first_packet = first.into_wire().unwrap();
    let byte_limit = first_packet.len() + 2;
    let closed = Arc::new(AtomicBool::new(false));
    let server_closed = Arc::clone(&closed);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        write_frame(&mut stream, &first_packet).await.unwrap();
        write_frame(&mut stream, &[0, 1, 2]).await.unwrap();
        let mut byte = [0_u8; 1];
        server_closed.store(stream.read(&mut byte).await.unwrap() == 0, Ordering::SeqCst);
    });

    let error = TcpTransport
        .transfer_with_limits(
            address,
            &request,
            Duration::from_secs(1),
            AxfrLimits::new(byte_limit, usize::MAX),
        )
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(matches!(
        error,
        TransportError::InvalidTransfer("AXFR wire-byte limit exceeded")
    ));
    assert!(closed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn axfr_record_limit_is_charged_before_insertion_and_stops_reading() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = response_for(&request, 42);
    first.headers.aa = true;
    first.answers = vec![soa(10), a_record()];
    let first_packet = first.into_wire().unwrap();
    let closed = Arc::new(AtomicBool::new(false));
    let server_closed = Arc::clone(&closed);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        write_frame(&mut stream, &first_packet).await.unwrap();
        let mut byte = [0_u8; 1];
        server_closed.store(stream.read(&mut byte).await.unwrap() == 0, Ordering::SeqCst);
    });

    let error = TcpTransport
        .transfer_with_limits(
            address,
            &request,
            Duration::from_secs(1),
            AxfrLimits::new(usize::MAX, 1),
        )
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(matches!(
        error,
        TransportError::InvalidTransfer("AXFR record limit exceeded")
    ));
    assert!(closed.load(Ordering::SeqCst));
}
