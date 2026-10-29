use super::*;

#[test]
fn response_padding_never_exceeds_the_requestors_effective_payload() {
    let mut request = query();
    let mut request_edns = request.edns().unwrap().unwrap();
    request_edns.udp_payload_size = 511;
    request_edns.set_padding(0);
    request.additionals[0] = request_edns.into_record();

    let mut response = response();
    response.answers.push(crate::ResourceRecord {
        name: crate::DomainName::root(),
        rtype: crate::RecordType::NULL,
        class: crate::ClassType::IN,
        ttl: 0,
        rdata: crate::RData::NULL(vec![0; 450]),
    });

    let outcome = response
        .pad_response_for_encrypted_transport(&request, 1404)
        .unwrap();
    assert!(matches!(
        outcome,
        PaddingOutcome::Padded {
            block_aligned: false,
            ..
        }
    ));
    assert!(response.into_wire().unwrap().len() <= 512);
}

#[test]
fn unpadded_query_does_not_request_response_padding() {
    let request = query();
    let mut response = response();
    let before = response.into_wire().unwrap();

    assert_eq!(
        response
            .pad_response_for_encrypted_transport(&request, 1232)
            .unwrap(),
        PaddingOutcome::NotRequested
    );
    assert_eq!(response.into_wire().unwrap(), before);
}

#[test]
fn padding_is_replaced_and_is_always_the_last_edns_option() {
    let mut message = query();
    let mut edns = message.edns().unwrap().unwrap();
    edns.options = vec![
        EdnsOption::padding(17),
        EdnsOption {
            code: 65000,
            data: vec![1, 2, 3],
        },
    ];
    message.additionals[0] = edns.into_record();

    message.pad_query_for_encrypted_transport(1232).unwrap();
    let edns = message.edns().unwrap().unwrap();
    assert_eq!(edns.options.last().unwrap().as_padding().unwrap().len(), 89);
    assert_eq!(edns.options[0].code, 65000);
    assert_eq!(message.into_wire().unwrap().len(), 128);
}

#[test]
fn zero_length_option_is_used_when_full_block_would_exceed_limit() {
    let mut message = query();
    let outcome = message.pad_query_for_encrypted_transport(32).unwrap();
    assert_eq!(
        outcome,
        PaddingOutcome::Padded {
            padding_octets: 0,
            message_octets: 32,
            block_aligned: false,
        }
    );
    assert_outcome_matches_wire(&message, outcome, 128);

    let mut message = query();
    let outcome = message.pad_query_for_encrypted_transport(100).unwrap();
    assert_eq!(
        outcome,
        PaddingOutcome::Padded {
            padding_octets: 0,
            message_octets: 32,
            block_aligned: false,
        }
    );
    assert_outcome_matches_wire(&message, outcome, 128);
    assert_eq!(
        message.edns().unwrap().unwrap().padding(),
        Some([].as_slice())
    );
}

#[test]
fn padding_uses_the_final_encoding_across_the_compression_pointer_boundary() {
    let mut message = compression_boundary_query(16_414);
    assert_eq!(message.into_wire().unwrap().len(), 16_410);

    let outcome = message
        .pad_to_block_size_for_encrypted_transport(16_414, 16_414)
        .unwrap();
    assert_eq!(
        outcome,
        PaddingOutcome::OmittedInsufficientSpace {
            message_octets: 16_410,
        }
    );
    assert_outcome_matches_wire(&message, outcome, 16_414);
    assert!(message.into_wire().unwrap().len() <= 16_414);

    let mut message = compression_boundary_query(16_418);
    let outcome = message
        .pad_to_block_size_for_encrypted_transport(16_414, 16_418)
        .unwrap();
    assert_eq!(
        outcome,
        PaddingOutcome::Padded {
            padding_octets: 0,
            message_octets: 16_418,
            block_aligned: false,
        }
    );
    assert_outcome_matches_wire(&message, outcome, 16_414);
    assert!(message.into_wire().unwrap().len() <= 16_418);
}

#[test]
fn padding_is_omitted_only_when_its_four_octet_header_cannot_fit() {
    let mut message = query();
    let outcome = message.pad_query_for_encrypted_transport(31).unwrap();
    assert_eq!(
        outcome,
        PaddingOutcome::OmittedInsufficientSpace { message_octets: 28 }
    );
    assert_outcome_matches_wire(&message, outcome, 128);
    assert_eq!(message.edns().unwrap().unwrap().padding(), None);
}

#[test]
fn failures_do_not_partially_modify_the_message() {
    let mut message = query();
    let before = message.into_wire().unwrap();
    assert_eq!(
        message.pad_query_for_encrypted_transport(27),
        Err(PaddingPolicyError::MessageTooLarge {
            message_octets: 28,
            maximum_message_octets: 27,
        })
    );
    assert_eq!(message.into_wire().unwrap(), before);

    assert!(matches!(
        message.pad_to_block_size_for_encrypted_transport(0, 1232),
        Err(PaddingPolicyError::InvalidBlockSize { block_size: 0 })
    ));
    assert_eq!(message.into_wire().unwrap(), before);
}

#[test]
fn query_response_direction_and_edns_preconditions_are_enforced() {
    let mut request = query();
    let mut reply = response();
    assert_eq!(
        reply.pad_query_for_encrypted_transport(1232),
        Err(PaddingPolicyError::ExpectedQuery)
    );
    assert_eq!(
        request.pad_response_for_encrypted_transport(&query(), 1232),
        Err(PaddingPolicyError::ExpectedResponse)
    );

    let mut no_edns = Message::builder().build().unwrap();
    assert_eq!(
        no_edns.pad_query_for_encrypted_transport(1232),
        Err(PaddingPolicyError::MissingEdns)
    );
}
