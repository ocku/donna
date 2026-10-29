use super::*;

#[test]
fn recommended_query_policy_pads_dns_payload_to_128_octets() {
    let mut message = query();
    assert_eq!(message.into_wire().unwrap().len(), 28);

    let outcome = message.pad_query_for_encrypted_transport(1232).unwrap();
    assert_eq!(
        outcome,
        PaddingOutcome::Padded {
            padding_octets: 96,
            message_octets: 128,
            block_aligned: true,
        }
    );
    assert_outcome_matches_wire(&message, outcome, 128);
}

#[test]
fn query_padding_never_exceeds_its_effective_edns_payload() {
    let mut message = query();
    let mut edns = message.edns().unwrap().unwrap();
    edns.udp_payload_size = 600;
    message.additionals[0] = edns.into_record();
    message.additionals.push(crate::ResourceRecord {
        name: crate::DomainName::root(),
        rtype: crate::RecordType::NULL,
        class: crate::ClassType::IN,
        ttl: 0,
        rdata: crate::RData::NULL(vec![0; 520]),
    });
    assert_eq!(message.into_wire().unwrap().len(), 559);

    let outcome = message
        .pad_to_block_size_for_encrypted_transport(128, 4096)
        .unwrap();
    assert_eq!(
        outcome,
        PaddingOutcome::Padded {
            padding_octets: 0,
            message_octets: 563,
            block_aligned: false,
        }
    );
    assert_outcome_matches_wire(&message, outcome, 128);
    assert!(message.into_wire().unwrap().len() <= 600);
}

#[test]
fn tcp_length_prefix_is_excluded_from_policy_input() {
    let mut message = query();
    message.pad_query_for_encrypted_transport(1232).unwrap();
    let dns_payload = message.into_wire().unwrap();
    let mut tcp_frame = Vec::from((dns_payload.len() as u16).to_be_bytes());
    tcp_frame.extend_from_slice(&dns_payload);

    assert_eq!(dns_payload.len(), 128);
    assert_eq!(tcp_frame.len(), 130);
    assert_eq!(&tcp_frame[..2], &[0, 128]);
}

#[test]
fn padded_query_triggers_recommended_468_octet_response() {
    let mut request = query();
    request.pad_query_for_encrypted_transport(1232).unwrap();
    let mut response = response();

    assert_eq!(
        response
            .pad_response_for_encrypted_transport(&request, 1404)
            .unwrap(),
        PaddingOutcome::Padded {
            padding_octets: 436,
            message_octets: 468,
            block_aligned: true,
        }
    );
    assert_eq!(response.into_wire().unwrap().len(), 468);
}

#[test]
fn pads_an_empty_transfer_frame_without_encoding_its_invalid_unpadded_form() {
    let mut request = query();
    request.questions[0].qtype = QueryType::AXFR;
    request.pad_query_for_encrypted_transport(1232).unwrap();
    let mut response_edns = Edns::new(1232);
    response_edns.set_padding(0);
    let mut response = Message::builder()
        .headers(Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        })
        .questions(request.questions.clone())
        .additionals([response_edns.into_record()])
        .build()
        .unwrap();

    let outcome = response
        .pad_response_for_encrypted_transport(&request, 1232)
        .unwrap();

    assert_eq!(response.into_wire().unwrap().len(), 468);
    assert!(matches!(
        outcome,
        PaddingOutcome::Padded {
            message_octets: 468,
            block_aligned: true,
            ..
        }
    ));
}
