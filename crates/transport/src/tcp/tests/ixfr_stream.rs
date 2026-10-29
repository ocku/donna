use super::*;

#[tokio::test]
async fn streaming_ixfr_accepts_current_delta_and_fallback_and_rejects_bad_chains() {
    let cases = [
        (vec![soa(3)], false),
        (vec![soa(1)], true),
        (vec![soa(0)], true),
        (
            vec![soa(3), soa(1), a_record(), soa(2), soa(2), soa(3), soa(3)],
            true,
        ),
        (vec![soa(3), a_record(), soa(3)], true),
        (vec![soa(3), soa(3)], true),
        (vec![soa(3), soa(0), soa(3), soa(3)], false),
        (vec![soa(3), soa(1), soa(1), soa(3)], false),
        (vec![soa(3), soa(1), soa(2), soa(3)], false),
        (vec![soa(3), a_record(), soa(2)], false),
    ];
    for (answers, expected) in cases {
        let mut request = query(42);
        request.questions[0].qtype = QueryType::IXFR;
        request.authorities.push(soa(1));
        // Exercise both whole-message and every-record frame boundaries.
        for chunk_size in [answers.len(), 1, 2, 3] {
            let frames = answers
                .chunks(chunk_size)
                .map(|chunk| {
                    let mut response = response_for(&request, 7);
                    response.headers.aa = true;
                    response.questions.clear();
                    response.answers = chunk.to_vec();
                    response
                })
                .collect();
            let mut sink = tokio::io::sink();
            let accepted = write_handler_response(
                &mut sink,
                "192.0.2.1:53".parse().unwrap(),
                Arc::new(StreamingTcpResponses(frames)),
                request.clone(),
                test_server_policy(),
            )
            .await;
            assert_eq!(
                accepted, expected,
                "answers={answers:?}, chunk={chunk_size}"
            );
        }
    }
}

#[test]
fn streaming_ixfr_bounds_validation_state() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::IXFR;
    request.authorities.push(soa(1));
    let mut validator =
        TransferSeriesValidator::new(request.questions[0].clone(), true, 1, &request);
    let mut response = response_for(&request, 7);
    response.headers.aa = true;
    response.answers = vec![soa(3), a_record(), soa(3)];
    assert!(
        validator
            .prepare(response, &request.headers, &request.questions, None)
            .is_none()
    );
}

#[test]
fn streaming_ixfr_preserves_signed_frames() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::IXFR;
    request.authorities.push(soa(1));
    let key = dns::TsigKey::new(
        dns::DomainName::from_dotted("key.example.").unwrap(),
        dns::TsigAlgorithm::HmacSha256,
        vec![7; 32],
    )
    .unwrap();
    let mut validator =
        TransferSeriesValidator::new(request.questions[0].clone(), true, 10, &request);
    for (index, records) in [
        vec![soa(2)],
        vec![soa(1), a_record(), soa(2), a_record(), soa(2)],
    ]
    .into_iter()
    .enumerate()
    {
        let mut response = response_for(&request, 42);
        response.headers.aa = true;
        if index > 0 {
            response.questions.clear();
        }
        response.answers = records;
        key.sign_response_ixfr(
            &mut response,
            &request.questions[0],
            &[1; 32],
            42,
            150,
            300,
            dns::TsigErrorCode::NoError,
            vec![],
            None,
        )
        .unwrap();
        let expected = response.into_wire_ixfr(&request.questions[0]).unwrap();
        key.verify_response(&expected, &[1; 32], 150).unwrap();
        assert_eq!(
            validator
                .prepare(
                    response,
                    &request.headers,
                    &request.questions,
                    Some((&request, TransportProtocol::Tls))
                )
                .unwrap(),
            expected
        );
    }
    assert!(validator.finish());
}

#[test]
fn old_axfr_stream_validator_cannot_complete_current_only_ixfr() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::IXFR;
    request.authorities.push(soa(2));
    let mut response = response_for(&request, 42);
    response.headers.aa = true;
    response.answers = vec![soa(2)];
    let mut previous = AxfrSeriesValidator::new(request.questions[0].clone(), true, 10);
    assert!(previous.accept(&response).is_some());
    assert!(!previous.finish());
    let mut fixed = TransferSeriesValidator::new(request.questions[0].clone(), true, 10, &request);
    assert!(
        fixed
            .prepare(response, &request.headers, &request.questions, None)
            .is_some()
    );
    assert!(fixed.finish());
}

#[test]
fn single_soa_ixfr_uses_serial_arithmetic() {
    for (requested, current, expected) in [
        (10, 11, false),
        (1, 2, false),
        (1, 1, true),
        (1, 0, true),
        (0, u32::MAX, true),
        (u32::MAX, 0, false),
        (0, 1 << 31, false),
    ] {
        let mut request = query(42);
        request.questions[0].qtype = QueryType::IXFR;
        request.authorities.push(soa(requested));
        let mut validator =
            TransferSeriesValidator::new(request.questions[0].clone(), true, 10, &request);
        let mut response = response_for(&request, 42);
        response.headers.aa = true;
        response.answers = vec![soa(current)];
        assert_eq!(
            prepare_ixfr_response(
                vec![response.clone()],
                &request.headers,
                request.questions.clone(),
                &request,
                None,
            )
            .is_some(),
            expected,
            "buffered requested={requested}, current={current}"
        );
        assert!(
            validator
                .prepare(response, &request.headers, &request.questions, None)
                .is_some()
        );
        assert_eq!(
            validator.finish(),
            expected,
            "requested={requested}, current={current}"
        );
    }
}
