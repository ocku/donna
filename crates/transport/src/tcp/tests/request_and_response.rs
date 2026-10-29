use super::*;

#[test]
fn tcp_transport_remains_zero_sized() {
    assert_eq!(std::mem::size_of::<TcpTransport>(), 0);
}

#[tokio::test]
async fn tcp_request_owns_its_tcp_reply_path() {
    let peer = "192.0.2.1:53000".parse().unwrap();
    let request = query(42);

    let packets = responses_for(
        &StatefulTcpHandler { peer },
        peer,
        &request.into_wire().unwrap(),
    )
    .await
    .unwrap();
    let response = Message::from_wire(&packets[0]).unwrap();

    assert_eq!(response.headers.id, 42);
    assert!(response.headers.qr);
}

#[tokio::test(start_paused = true)]
async fn buffered_handler_response_and_completion_share_one_deadline() {
    let mut policy = test_server_policy();
    policy.handler_reply_timeout = Duration::from_secs(10);
    let handler = Arc::new(DelayedResponseThenPendingHandler {
        delay: Duration::from_secs(6),
    });
    let task = tokio::spawn(async move {
        write_handler_response(
            &mut tokio::io::sink(),
            "192.0.2.1:53".parse().unwrap(),
            handler,
            query(42),
            policy,
        )
        .await
    });

    time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    assert!(!task.await.unwrap());
}

#[tokio::test]
async fn buffered_handler_failure_after_responding_suppresses_the_response() {
    assert!(
        !write_handler_response(
            &mut tokio::io::sink(),
            "192.0.2.1:53".parse().unwrap(),
            Arc::new(ResponseThenPanicHandler),
            query(42),
            test_server_policy(),
        )
        .await
    );
}

#[tokio::test]
async fn tcp_malformed_edns_gets_minimal_opt_bearing_formerr() {
    let (query, packet) = malformed_edns_query();
    let responses = responses_for(
        &FixedTcpResponses(Vec::new()),
        "192.0.2.1:53".parse().unwrap(),
        &packet,
    )
    .await
    .unwrap();
    let response = Message::from_wire(&responses[0]).unwrap();

    assert_eq!(responses.len(), 1);
    assert_eq!(response.headers.rcode, dns::RCode::FormatError);
    assert!(crate::same_questions(&response.questions, &query.questions));
    assert!(response.edns().unwrap().is_some());
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert_eq!(response.additionals.len(), 1);
}

#[tokio::test]
async fn tcp_formerr_ignores_the_advertised_udp_payload_size() {
    let (query, packet) = malformed_edns_query_with_questions(40, 512);
    let responses = responses_for(
        &FixedTcpResponses(Vec::new()),
        "192.0.2.1:53".parse().unwrap(),
        &packet,
    )
    .await
    .unwrap();

    assert!(responses[0].len() > 512);
    assert!(responses[0].len() <= MAX_TCP_MESSAGE_OCTETS);
    let response = Message::from_wire(&responses[0]).unwrap();
    assert!(crate::same_questions(&response.questions, &query.questions));
    assert!(response.edns().unwrap().is_some());
}

#[tokio::test]
async fn near_maximum_tcp_formerr_stays_within_the_dns_frame_limit() {
    let (query, packet) = malformed_edns_query_with_questions(3400, u16::MAX);
    assert!(packet.len() > 60_000);
    assert!(packet.len() <= MAX_TCP_MESSAGE_OCTETS);

    let responses = responses_for(
        &FixedTcpResponses(Vec::new()),
        "192.0.2.1:53".parse().unwrap(),
        &packet,
    )
    .await
    .unwrap();

    assert_eq!(responses.len(), 1);
    assert!(responses[0].len() <= MAX_TCP_MESSAGE_OCTETS);
    let response = Message::from_wire(&responses[0]).unwrap();
    assert!(crate::same_questions(&response.questions, &query.questions));
}

#[tokio::test]
async fn standard_tcp_server_responses_echo_the_request_questions() {
    let request = query(42);
    let handler = FixedTcpResponses(vec![Message::builder().build().unwrap()]);

    let packets = responses_for(
        &handler,
        "192.0.2.1:53".parse().unwrap(),
        &request.into_wire().unwrap(),
    )
    .await
    .unwrap();
    let response = Message::from_wire(&packets[0]).unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(response.questions.len(), 1);
    assert!(
        response.questions[0]
            .qname
            .eq_dns(&request.questions[0].qname)
    );
    assert_eq!(response.questions[0].qtype, request.questions[0].qtype);
    assert_eq!(response.questions[0].qclass, request.questions[0].qclass);
}

#[tokio::test]
async fn noncanonical_standard_questions_keep_tcp_formerr_questionless() {
    for packet in [
        query_with_question_codes(0, u16::from(ClassType::IN)),
        query_with_question_codes(u16::from(QueryType::A), 0),
    ] {
        let packets = responses_for(
            &FixedTcpResponses(vec![unrelated_formerr()]),
            "192.0.2.1:53".parse().unwrap(),
            &packet,
        )
        .await
        .unwrap();
        let response = Message::from_wire(&packets[0]).unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(response.headers.rcode, dns::RCode::FormatError);
        assert!(response.questions.is_empty());
    }
}

#[tokio::test]
async fn keeps_sanitized_axfr_formerr_questionless_for_noncanonical_qclass() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut canonical = query(42);
    canonical.questions[0].qtype = QueryType::AXFR;
    let mut malformed_wire = canonical.clone().into_wire().unwrap();
    let qclass_offset = malformed_wire.len() - 2;
    malformed_wire[qclass_offset..].copy_from_slice(&0_u16.to_be_bytes());

    let mut formerr = response_for(&canonical, 7);
    formerr.headers.rcode = dns::RCode::FormatError;
    let server = tokio::spawn(serve_listener(listener, FixedTcpResponses(vec![formerr])));
    let mut stream = TcpStream::connect(address).await.unwrap();
    write_frame(&mut stream, &malformed_wire).await.unwrap();
    let packet = time::timeout(Duration::from_secs(1), read_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    server.abort();

    let response = Message::from_wire(&packet).unwrap();
    assert_eq!(response.headers.rcode, dns::RCode::FormatError);
    assert!(response.questions.is_empty());
}

#[test]
fn questionless_axfr_error_is_only_valid_as_the_complete_noncanonical_response() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;

    let mut unrelated = unrelated_formerr();
    unrelated.headers.qr = true;
    assert!(!valid_axfr_response_series(
        std::slice::from_ref(&unrelated),
        &request.questions[0],
        false,
    ));

    let mut immediate_error = response_for(&request, 42);
    immediate_error.headers.rcode = dns::RCode::FormatError;
    immediate_error.questions.clear();
    assert!(valid_axfr_response_series(
        std::slice::from_ref(&immediate_error),
        &request.questions[0],
        false,
    ));

    let mut unexpected_success = successful_axfr_response_for(&request);
    unexpected_success.questions.clear();
    assert!(!valid_axfr_response_series(
        std::slice::from_ref(&unexpected_success),
        &request.questions[0],
        false,
    ));

    let mut first = successful_axfr_response_for(&request);
    first.questions.clear();
    first.answers.pop();
    let mut terminating_error = immediate_error;
    terminating_error.answers.push(soa(1));
    assert!(!valid_axfr_response_series(
        &[first, terminating_error],
        &request.questions[0],
        false,
    ));
}

#[tokio::test]
async fn rejects_ambiguous_response_counts_for_a_standard_tcp_request() {
    let request = query(42).into_wire().unwrap();
    let peer = "192.0.2.1:53".parse().unwrap();

    assert!(
        responses_for(&FixedTcpResponses(Vec::new()), peer, &request)
            .await
            .is_none()
    );
    assert!(
        responses_for(
            &FixedTcpResponses(vec![
                Message::builder().build().unwrap(),
                Message::builder().build().unwrap(),
            ]),
            peer,
            &request,
        )
        .await
        .is_none()
    );
}

#[tokio::test]
async fn leaves_subsequent_axfr_question_sections_handler_controlled() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = response_for(&request, 7);
    first.questions.clear();
    first.answers.push(soa(1));
    let mut subsequent = response_for(&request, 7);
    subsequent.questions.clear();
    subsequent.answers.push(soa(1));
    let handler = FixedTcpResponses(vec![first, subsequent]);

    let packets = responses_for(
        &handler,
        "192.0.2.1:53".parse().unwrap(),
        &request.into_wire().unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(Message::from_wire(&packets[0]).unwrap().questions.len(), 1);
    assert!(
        Message::from_wire(&packets[1])
            .unwrap()
            .questions
            .is_empty()
    );
}

#[tokio::test]
async fn accepts_in_zone_descendant_soa_as_axfr_data() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut descendant_soa = soa(2);
    descendant_soa.name =
        dns::DomainName::from_labels(vec![b"occluded".to_vec(), b"example".to_vec()]).unwrap();
    let mut response = response_for(&request, 7);
    response.answers = vec![soa(1), descendant_soa, soa(1)];

    assert!(
        responses_for(
            &FixedTcpResponses(vec![response]),
            "192.0.2.1:53".parse().unwrap(),
            &request.into_wire().unwrap(),
        )
        .await
        .is_some()
    );
}

#[tokio::test]
async fn rejects_split_axfr_rrset_with_differing_ttls() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = response_for(&request, 7);
    first.answers = vec![soa(1), a_record()];
    let mut second_record = a_record();
    second_record.ttl = 30;
    second_record.rdata = RData::A(std::net::Ipv4Addr::new(127, 0, 0, 2));
    let mut second = response_for(&request, 7);
    second.questions.clear();
    second.answers = vec![second_record, soa(1)];

    assert!(
        responses_for(
            &FixedTcpResponses(vec![first, second]),
            "192.0.2.1:53".parse().unwrap(),
            &request.into_wire().unwrap(),
        )
        .await
        .is_none()
    );
}

#[test]
fn groups_short_rrsig_rdata_conservatively() {
    let mut empty = rrsig(RecordType::A, 60, 1);
    empty.rdata = RData::Unknown(Vec::new());
    let mut one_octet = rrsig(RecordType::AAAA, 30, 2);
    one_octet.rdata = RData::Unknown(vec![28]);

    assert_eq!(RrsetKey::from(&empty), RrsetKey::from(&one_octet));
}

#[tokio::test]
async fn validates_split_rrsig_ttls_by_type_covered() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let peer = "192.0.2.1:53".parse().unwrap();
    let request_wire = request.clone().into_wire().unwrap();

    let series = |second: ResourceRecord| {
        let mut first = response_for(&request, 7);
        first.answers = vec![soa(1), rrsig(RecordType::A, 60, 1)];
        let mut last = response_for(&request, 7);
        last.questions.clear();
        last.answers = vec![second, soa(1)];
        vec![first, last]
    };

    assert!(
        responses_for(
            &FixedTcpResponses(series(rrsig(RecordType::A, 30, 2))),
            peer,
            &request_wire,
        )
        .await
        .is_none()
    );
    assert!(
        responses_for(
            &FixedTcpResponses(series(rrsig(RecordType::AAAA, 30, 2))),
            peer,
            &request_wire,
        )
        .await
        .is_some()
    );
}

#[tokio::test]
async fn copies_questions_and_allows_both_axfr_error_answer_forms() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let request_wire = request.clone().into_wire().unwrap();
    let peer = "192.0.2.1:53".parse().unwrap();

    let mut immediate_error = response_for(&request, 7);
    immediate_error.questions.clear();
    immediate_error.headers.rcode = dns::RCode::ServerFailure;
    let packets = responses_for(
        &FixedTcpResponses(vec![immediate_error]),
        peer,
        &request_wire,
    )
    .await
    .unwrap();
    let error = Message::from_wire(&packets[0]).unwrap();
    assert!(crate::same_questions(&error.questions, &request.questions));
    assert!(error.answers.is_empty());

    let mut first = response_for(&request, 7);
    first.questions.clear();
    first.answers = vec![soa(1), a_record()];
    let mut terminating_error = response_for(&request, 7);
    terminating_error.questions.clear();
    terminating_error.headers.rcode = dns::RCode::ServerFailure;
    terminating_error.answers = vec![soa(1)];
    let packets = responses_for(
        &FixedTcpResponses(vec![first, terminating_error]),
        peer,
        &request_wire,
    )
    .await
    .unwrap();
    let first = Message::from_wire(&packets[0]).unwrap();
    let error = Message::from_wire(&packets[1]).unwrap();
    assert!(crate::same_questions(&first.questions, &request.questions));
    assert!(crate::same_questions(&error.questions, &request.questions));
    assert_eq!(error.answers.len(), 1);
    assert!(same_resource_record(&error.answers[0], &soa(1)));
}
