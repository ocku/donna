use super::*;

#[tokio::test]
async fn deadline_overflow_returns_timeout_before_tcp_socket_io() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();

    let error = TcpTransport
        .exchange(address, &query(42), Duration::MAX)
        .await
        .unwrap_err();

    assert!(matches!(error, TransportError::Timeout));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn zero_tcp_timeout_retains_timeout_behavior() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    assert!(matches!(
        TcpTransport
            .exchange(listener.local_addr().unwrap(), &query(42), Duration::ZERO)
            .await,
        Err(TransportError::Timeout)
    ));
}

#[tokio::test]
async fn finite_tcp_timeout_retains_timeout_behavior() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        pending::<()>().await;
    });

    let error = TcpTransport
        .exchange(address, &query(42), Duration::from_millis(20))
        .await
        .unwrap_err();
    server.abort();

    assert!(matches!(error, TransportError::Timeout));
}

#[tokio::test]
async fn axfr_deadline_overflow_returns_timeout_before_tcp_socket_io() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;

    let error = TcpTransport
        .transfer(address, &request, Duration::MAX)
        .await
        .unwrap_err();

    assert!(matches!(error, TransportError::Timeout));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn finite_axfr_timeout_retains_timeout_behavior() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        pending::<()>().await;
    });

    let error = TcpTransport
        .transfer(address, &request, Duration::from_millis(20))
        .await
        .unwrap_err();
    server.abort();

    assert!(matches!(error, TransportError::Timeout));
}

#[tokio::test]
async fn invalid_tcp_and_axfr_queries_keep_precedence_over_deadline_overflow() {
    let mut padded = query(42);
    padded.additionals.push(
        dns::Edns {
            options: vec![dns::EdnsOption::padding(1)],
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );
    assert!(matches!(
        TcpTransport
            .exchange("127.0.0.1:53".parse().unwrap(), &padded, Duration::MAX)
            .await,
        Err(TransportError::InsecureEdnsPadding)
    ));
    assert!(matches!(
        TcpTransport
            .transfer("127.0.0.1:53".parse().unwrap(), &query(42), Duration::MAX,)
            .await,
        Err(TransportError::InvalidTransfer(_))
    ));
}

#[tokio::test]
async fn ignores_unrelated_tcp_frames_until_the_matching_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let query = query(42);
    let server_query = query.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        write_frame(
            &mut stream,
            &response_for(&server_query, 41).into_wire().unwrap(),
        )
        .await
        .unwrap();
        write_frame(
            &mut stream,
            &response_for(&server_query, 42).into_wire().unwrap(),
        )
        .await
        .unwrap();
    });

    let response = TcpTransport
        .exchange(address, &query, Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(response.headers.id, query.headers.id);
    assert!(matches_tcp_query(&response, &query));
}

#[tokio::test]
async fn normalizes_tcp_response_without_a_question_section() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let request = query(42);
    let server_query = request.clone();
    let mut server_response = response_for(&request, 42);
    server_response.headers.aa = true;
    server_response.headers.ra = true;
    server_response.answers.push(a_record());
    server_response.authorities.push(soa(1));
    server_response.questions.clear();
    let expected = server_response.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_frame(&mut stream).await.unwrap();
        assert!(server_response.questions.is_empty());
        write_frame(&mut stream, &server_response.into_wire().unwrap())
            .await
            .unwrap();
    });

    let response = TcpTransport
        .exchange(address, &request, Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();

    assert!(crate::same_questions(
        &response.questions,
        &request.questions
    ));
    assert!(crate::same_questions(
        &response.questions,
        &request.questions
    ));
    let mut server_fields = response.clone();
    server_fields.questions.clear();
    assert_eq!(
        server_fields.into_wire().unwrap(),
        expected.into_wire().unwrap()
    );
    assert!(matches_tcp_query(&response, &server_query));
}

#[test]
fn tcp_response_with_a_question_requires_an_exact_dns_match() {
    let request = query(42);
    let mut response = response_for(&request, 42);
    response.questions[0].qtype = QueryType::AAAA;
    assert!(!matches_tcp_query(&response, &request));

    response.questions.clear();
    assert!(matches_tcp_query(&response, &request));
}

#[test]
fn questionless_padding_only_frames_require_transfer_context() {
    let request = query(42);
    let mut edns = dns::Edns::new(1232);
    edns.set_padding(0);
    let response = Message::builder()
        .headers(Headers {
            id: 42,
            qr: true,
            aa: true,
            ..Headers::default()
        })
        .additionals([edns.into_record()])
        .build_unchecked();

    assert!(!matches_tcp_query(&response, &request));

    let mut transfer_request = request;
    transfer_request.questions[0].qtype = QueryType::AXFR;
    assert!(matches_tcp_query(&response, &transfer_request));
}

#[test]
fn combines_the_length_prefix_and_payload_in_one_write_buffer() {
    assert_eq!(
        frame_packet(&[0xde, 0xad, 0xbe, 0xef]).unwrap(),
        [0, 4, 0xde, 0xad, 0xbe, 0xef]
    );
}

#[tokio::test]
async fn uses_a_big_endian_two_octet_frame() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let query = query(42);
    let expected_request = query.into_wire().unwrap();
    let server_query = query.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut prefix = [0_u8; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(
            usize::from(u16::from_be_bytes(prefix)),
            expected_request.len()
        );
        let mut request = vec![0; expected_request.len()];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, expected_request);

        let response = response_for(&server_query, 42).into_wire().unwrap();
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
    });

    let response = TcpTransport
        .exchange(address, &query, Duration::from_secs(1))
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(response.headers.id, 42);
}

#[tokio::test]
async fn preserves_signed_questionless_update_responses() {
    for case in crate::tests::signed_responses::SignedResponse::cases(42) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handler = case.handler();
        let task = tokio::spawn(async move { serve_listener(listener, handler).await.unwrap() });
        let response = TcpTransport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.abort();
    }
}

#[tokio::test]
async fn preserves_inverse_response_discovered_questions() {
    for case in crate::tests::signed_responses::SignedResponse::inverse_cases(42) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handler = case.handler();
        let task = tokio::spawn(async move { serve_listener(listener, handler).await.unwrap() });
        let response = TcpTransport
            .exchange(address, &case.request, Duration::from_secs(2))
            .await
            .unwrap();
        case.verify(&response);
        task.abort();
    }
}
