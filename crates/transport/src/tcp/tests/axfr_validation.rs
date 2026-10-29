use super::*;

#[tokio::test]
async fn treats_badvers_as_an_immediate_axfr_error_response() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut badvers = badvers_response_for(&request, 7);
    badvers.questions.clear();

    let packets = responses_for(
        &FixedTcpResponses(vec![badvers]),
        "192.0.2.1:53".parse().unwrap(),
        &request.clone().into_wire().unwrap(),
    )
    .await
    .unwrap();
    let response = Message::from_wire(&packets[0]).unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(response.headers.rcode, dns::RCode::Ok);
    assert_eq!(response.extended_rcode(), 16);
    assert!(!response.headers.aa);
    assert!(crate::same_questions(
        &response.questions,
        &request.questions
    ));
    assert!(response.answers.is_empty());
}

#[test]
fn classifies_badvers_as_a_terminal_axfr_error_on_the_client() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let response = badvers_response_for(&request, 42);

    assert!(valid_axfr_response_series(
        std::slice::from_ref(&response),
        &request.questions[0],
        true,
    ));
    assert!(matches!(
        validate_transfer_message(&response, &request, true),
        Err(TransportError::InvalidTransfer("server rejected transfer"))
    ));
}

#[test]
fn axfr_client_rejects_duplicate_opt_before_reading_extended_rcode() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut response = successful_axfr_response_for(&request);
    response.additionals = vec![
        dns::Edns {
            extended_rcode: 1,
            ..dns::Edns::new(1232)
        }
        .into_record(),
        dns::Edns::new(1232).into_record(),
    ];

    // The general accessor intentionally falls back to the header nibble for
    // malformed EDNS, which must not make this response successful for AXFR.
    assert_eq!(response.extended_rcode(), 0);
    assert_malformed_axfr_edns_is_rejected(&request, &response);
}

#[test]
fn axfr_client_rejects_misplaced_opt_before_reading_extended_rcode() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut response = successful_axfr_response_for(&request);
    response.authorities.push(
        dns::Edns {
            extended_rcode: 1,
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );

    assert_eq!(response.extended_rcode(), 0);
    assert_malformed_axfr_edns_is_rejected(&request, &response);
}

#[test]
fn axfr_client_rejects_non_root_opt_before_reading_extended_rcode() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut response = successful_axfr_response_for(&request);
    let mut opt = dns::Edns {
        extended_rcode: 1,
        ..dns::Edns::new(1232)
    }
    .into_record();
    opt.name = dns::DomainName::from_labels(vec![b"not-root".to_vec()]).unwrap();
    response.additionals.push(opt);

    assert_eq!(response.extended_rcode(), 0);
    assert_malformed_axfr_edns_is_rejected(&request, &response);
}

#[test]
fn axfr_client_rejects_malformed_known_edns_option_before_extended_rcode() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut response = successful_axfr_response_for(&request);
    response.additionals.push(
        dns::Edns {
            extended_rcode: 1,
            options: vec![dns::EdnsOption {
                code: dns::EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
                data: vec![0],
            }],
            ..dns::Edns::new(1232)
        }
        .into_record(),
    );

    // Fixed OPT fields are valid, so only known-option validation prevents
    // this malformed response from being mistaken for an ordinary BADVERS.
    assert_eq!(response.extended_rcode(), 16);
    assert_malformed_axfr_edns_is_rejected(&request, &response);
}

#[tokio::test]
async fn rejects_empty_successful_axfr_message() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = response_for(&request, 7);
    first.answers = vec![soa(1), a_record()];
    let mut empty = response_for(&request, 7);
    empty.questions.clear();
    let mut last = response_for(&request, 7);
    last.questions.clear();
    last.answers = vec![soa(1)];

    assert!(
        responses_for(
            &FixedTcpResponses(vec![first, empty, last]),
            "192.0.2.1:53".parse().unwrap(),
            &request.into_wire().unwrap(),
        )
        .await
        .is_none()
    );
}

#[tokio::test]
async fn rejects_malformed_axfr_handler_series() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let peer = "192.0.2.1:53".parse().unwrap();

    let mut missing_boundaries = response_for(&request, 7);
    missing_boundaries.questions.clear();
    let mut mismatched_boundaries = response_for(&request, 7);
    mismatched_boundaries.answers = vec![soa(1), soa(2)];
    let mut nonempty_authority = response_for(&request, 7);
    nonempty_authority.answers = vec![soa(1), soa(1)];
    nonempty_authority.authorities.push(soa(1));
    let mut partial = response_for(&request, 7);
    partial.answers = vec![soa(1), a_record()];
    let mut error_with_data = response_for(&request, 7);
    error_with_data.headers.rcode = dns::RCode::ServerFailure;
    error_with_data.answers = vec![a_record()];

    for responses in [
        Vec::new(),
        vec![missing_boundaries],
        vec![mismatched_boundaries],
        vec![nonempty_authority],
        vec![partial, error_with_data],
    ] {
        assert!(
            responses_for(
                &FixedTcpResponses(responses),
                peer,
                &request.clone().into_wire().unwrap(),
            )
            .await
            .is_none()
        );
    }
}

#[tokio::test]
async fn streams_axfr_frames_and_rejects_an_invalid_later_frame_before_writing_it() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = response_for(&request, 7);
    first.questions.clear();
    first.answers = vec![soa(1), a_record()];
    let mut invalid = response_for(&request, 7);
    invalid.questions.clear();
    let mut outside = a_record();
    outside.name = dns::DomainName::from_labels(vec![b"outside".to_vec()]).unwrap();
    invalid.answers = vec![outside];
    let mut never_written = response_for(&request, 7);
    never_written.questions.clear();
    never_written.answers = vec![soa(1)];

    let (mut client, server_stream) = tokio::io::duplex(MAX_TCP_MESSAGE_OCTETS * 2);
    let server = tokio::spawn(serve_connection(
        server_stream,
        "192.0.2.1:53".parse().unwrap(),
        Arc::new(StreamingTcpResponses(vec![first, invalid, never_written])),
        test_server_policy(),
    ));
    write_frame(&mut client, &request.into_wire().unwrap())
        .await
        .unwrap();

    let first = Message::from_wire(&read_frame(&mut client).await.unwrap()).unwrap();
    assert_eq!(first.answers.len(), 2);
    let mut closed = [0_u8; 1];
    assert_eq!(client.read(&mut closed).await.unwrap(), 0);
    server.await.unwrap();
}

#[tokio::test]
async fn streamed_axfr_validation_failure_cancels_producer_and_releases_permit() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = response_for(&request, 7);
    first.questions.clear();
    first.answers = vec![soa(1), a_record()];
    let mut invalid = response_for(&request, 7);
    invalid.questions.clear();
    let mut outside = a_record();
    outside.name = dns::DomainName::from_labels(vec![b"outside".to_vec()]).unwrap();
    invalid.answers = vec![outside];
    let mut subsequent = response_for(&request, 7);
    subsequent.questions.clear();
    subsequent.answers = vec![a_record()];
    let cancelled = Arc::new(AtomicBool::new(false));
    let permits = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&permits).acquire_owned().await.unwrap();
    let (mut client, server_stream) = tokio::io::duplex(4096);
    write_frame(&mut client, &request.into_wire().unwrap())
        .await
        .unwrap();

    let task = spawn_connection(
        server_stream,
        "192.0.2.1:53".parse().unwrap(),
        Arc::new(InvalidThenRepeatingAxfrHandler {
            first,
            invalid,
            subsequent,
            cancelled: Arc::clone(&cancelled),
        }),
        test_server_policy(),
        permit,
        None,
    );
    let first = Message::from_wire(&read_frame(&mut client).await.unwrap()).unwrap();
    assert_eq!(first.answers.len(), 2);
    let mut closed = [0_u8; 1];
    assert_eq!(client.read(&mut closed).await.unwrap(), 0);
    task.await.unwrap();

    assert!(cancelled.load(Ordering::SeqCst));
    assert_eq!(permits.available_permits(), 1);
}

#[tokio::test]
async fn streams_a_complete_multiframe_axfr() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = response_for(&request, 7);
    first.questions.clear();
    first.answers = vec![soa(1), a_record()];
    let mut last = response_for(&request, 7);
    last.questions.clear();
    last.answers = vec![soa(1)];

    let (mut client, server_stream) = tokio::io::duplex(4096);
    let server = tokio::spawn(serve_connection(
        server_stream,
        "192.0.2.1:53".parse().unwrap(),
        Arc::new(StreamingTcpResponses(vec![first, last])),
        test_server_policy(),
    ));
    write_frame(&mut client, &request.into_wire().unwrap())
        .await
        .unwrap();

    let first = Message::from_wire(&read_frame(&mut client).await.unwrap()).unwrap();
    let last = Message::from_wire(&read_frame(&mut client).await.unwrap()).unwrap();
    assert_eq!(first.questions.len(), 1);
    assert!(last.questions.is_empty());
    assert!(same_resource_record(
        first.answers.first().unwrap(),
        last.answers.last().unwrap(),
    ));

    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn streamed_axfr_disconnect_cancels_producer_and_releases_permit() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = response_for(&request, 7);
    first.questions.clear();
    first.answers = vec![soa(1), a_record()];
    let mut subsequent = response_for(&request, 7);
    subsequent.questions.clear();
    subsequent.answers = vec![a_record()];
    let cancelled = Arc::new(AtomicBool::new(false));
    let permits = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&permits).acquire_owned().await.unwrap();
    let (mut client, server_stream) = tokio::io::duplex(256);
    write_frame(&mut client, &request.into_wire().unwrap())
        .await
        .unwrap();

    let task = spawn_connection(
        server_stream,
        "192.0.2.1:53".parse().unwrap(),
        Arc::new(RepeatingAxfrHandler {
            first,
            subsequent,
            cancelled: Arc::clone(&cancelled),
        }),
        test_server_policy(),
        permit,
        None,
    );
    let first = Message::from_wire(&read_frame(&mut client).await.unwrap()).unwrap();
    assert_eq!(first.answers.len(), 2);
    drop(client);
    time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();

    assert!(cancelled.load(Ordering::SeqCst));
    assert_eq!(permits.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn streamed_axfr_write_timeout_cancels_producer_and_releases_permit() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let large = ResourceRecord {
        name: dns::DomainName::from_labels(vec![b"large".to_vec(), b"example".to_vec()]).unwrap(),
        rtype: RecordType::Unknown(65_000),
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::Unknown(vec![0; 40_000]),
    };
    let mut first = response_for(&request, 7);
    first.questions.clear();
    first.answers = vec![soa(1), large.clone()];
    let mut subsequent = response_for(&request, 7);
    subsequent.questions.clear();
    subsequent.answers = vec![large];
    let cancelled = Arc::new(AtomicBool::new(false));
    let permits = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&permits).acquire_owned().await.unwrap();
    let (mut client, server_stream) = tokio::io::duplex(128);
    write_frame(&mut client, &request.into_wire().unwrap())
        .await
        .unwrap();

    let task = spawn_connection(
        server_stream,
        "192.0.2.1:53".parse().unwrap(),
        Arc::new(RepeatingAxfrHandler {
            first,
            subsequent,
            cancelled: Arc::clone(&cancelled),
        }),
        test_server_policy(),
        permit,
        None,
    );
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    time::advance(test_server_policy().response_write_timeout).await;
    tokio::task::yield_now().await;
    task.await.unwrap();

    assert!(cancelled.load(Ordering::SeqCst));
    assert_eq!(permits.available_permits(), 1);
}
