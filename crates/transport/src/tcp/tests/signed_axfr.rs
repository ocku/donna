use super::*;

fn sign(response: &mut Message) {
    let key = dns::TsigKey::new(
        dns::DomainName::from_dotted("key.example.").unwrap(),
        dns::TsigAlgorithm::HmacSha256,
        vec![7; 32],
    )
    .unwrap();
    key.sign_response(
        response,
        &[1; 32],
        42,
        150,
        300,
        dns::TsigErrorCode::NoError,
        vec![],
        None,
    )
    .unwrap();
}

#[tokio::test]
async fn rejects_signed_first_axfr_frame_without_question() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut response = successful_axfr_response_for(&request);
    response.questions.clear();
    response.answers = vec![soa(1)];
    sign(&mut response);
    let mut last = successful_axfr_response_for(&request);
    last.questions.clear();
    last.answers = vec![soa(1)];
    sign(&mut last);
    assert!(!valid_axfr_response_series(
        &[response.clone(), last.clone()],
        &request.questions[0],
        true
    ));
    assert!(
        responses_for(
            &FixedTcpResponses(vec![response, last]),
            "192.0.2.1:53".parse().unwrap(),
            &request.into_wire().unwrap()
        )
        .await
        .is_none()
    );
}

#[tokio::test]
async fn preserves_signed_later_axfr_frame_without_question() {
    let mut request = query(42);
    request.questions[0].qtype = QueryType::AXFR;
    let mut first = successful_axfr_response_for(&request);
    first.answers = vec![soa(1), a_record()];
    sign(&mut first);
    let mut last = successful_axfr_response_for(&request);
    last.questions.clear();
    last.answers = vec![soa(1)];
    sign(&mut last);
    assert!(valid_axfr_response_series(
        &[first.clone(), last.clone()],
        &request.questions[0],
        true
    ));
    let packets = responses_for(
        &FixedTcpResponses(vec![first, last.clone()]),
        "192.0.2.1:53".parse().unwrap(),
        &request.into_wire().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[1], last.into_wire().unwrap());
}
