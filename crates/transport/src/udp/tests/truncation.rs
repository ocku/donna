use super::*;

#[test]
fn omits_optional_additional_rrsets_without_setting_tc() {
    let wire = truncate_response(oversized_response(), MAX_UDP_MESSAGE_OCTETS).unwrap();
    assert!(wire.len() <= MAX_UDP_MESSAGE_OCTETS);
    let decoded = Message::from_wire(&wire).unwrap();
    assert!(!decoded.headers.tc);
    assert_eq!(decoded.answers.len(), 1);
    assert_eq!(decoded.authorities.len(), 1);
    assert!(decoded.additionals.is_empty());
    assert_eq!(decoded.questions.len(), 1);
}

#[test]
fn drops_all_extended_errors_before_other_data_and_sets_tc() {
    let answer_name = DomainName::from_labels(vec![b"answer".to_vec()]).unwrap();
    let mut edns = Edns::new(512);
    edns.push_extended_dns_error(
        dns::ExtendedDnsError::new(
            dns::ExtendedDnsErrorCode::Other,
            "diagnostic text that does not affect DNS processing".repeat(12),
        )
        .unwrap(),
    )
    .unwrap();
    edns.push_extended_dns_error(dns::ExtendedDnsError::without_text(
        dns::ExtendedDnsErrorCode::NetworkError,
    ))
    .unwrap();
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .answers([ResourceRecord {
            name: answer_name,
            rtype: RecordType::NULL,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::NULL(vec![7; 300]),
        }])
        .additionals([edns.into_record()])
        .build()
        .unwrap();

    let wire = truncate_response(message, MAX_UDP_MESSAGE_OCTETS).unwrap();
    let decoded = Message::from_wire(&wire).unwrap();

    assert!(decoded.headers.tc);
    assert_eq!(decoded.answers.len(), 1);
    assert_eq!(
        decoded
            .edns()
            .unwrap()
            .unwrap()
            .extended_dns_errors()
            .count(),
        0
    );
}

#[test]
fn preserves_complete_additional_rrsets_when_tc_is_clear() {
    let owner =
        |label: &[u8]| DomainName::from_labels(vec![label.to_vec(), b"example".to_vec()]).unwrap();
    let record = |name: DomainName, length: usize, octet: u8| ResourceRecord {
        name,
        rtype: RecordType::NULL,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NULL(vec![octet; length]),
    };
    let kept = owner(b"kept");
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .additionals([
            record(kept.clone(), 100, 1),
            record(kept.clone(), 100, 2),
            record(owner(b"omitted"), 300, 3),
        ])
        .build()
        .unwrap();

    let wire = truncate_response(message, MAX_UDP_MESSAGE_OCTETS).unwrap();
    let decoded = Message::from_wire(&wire).unwrap();

    assert!(!decoded.headers.tc);
    assert_eq!(decoded.additionals.len(), 2);
    assert!(
        decoded
            .additionals
            .iter()
            .all(|record| record.name.eq_dns(&kept))
    );
}

#[test]
fn sets_tc_and_omits_a_required_rrset_that_cannot_fit_completely() {
    let owner = DomainName::from_labels(vec![b"answer".to_vec()]).unwrap();
    let record = |octet| ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::NULL,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NULL(vec![octet; 300]),
    };
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .answers([record(1), record(2)])
        .build()
        .unwrap();

    let wire = truncate_response(message, MAX_UDP_MESSAGE_OCTETS).unwrap();
    let decoded = Message::from_wire(&wire).unwrap();

    assert!(decoded.headers.tc);
    assert!(decoded.answers.is_empty());
}

#[test]
fn omits_a_malformed_optional_rrset_but_emits_only_valid_output() {
    let mut message = oversized_response();
    message.additionals[0].rtype = RecordType::A;
    message.additionals[0].rdata = RData::Unknown(Vec::new());

    let wire = truncate_response(message, MAX_UDP_MESSAGE_OCTETS).unwrap();
    let decoded = Message::from_wire(&wire).unwrap();

    assert!(!decoded.headers.tc);
    assert!(decoded.additionals.is_empty());
    assert!(decoded.validate_strict().is_ok());
}

#[test]
fn rejects_malformed_required_data_instead_of_emitting_invalid_output() {
    let mut message = oversized_response();
    message.additionals.clear();
    message.answers[0].rtype = RecordType::A;
    message.answers[0].rdata = RData::Unknown(Vec::new());

    assert!(matches!(
        truncate_response(message, MAX_UDP_MESSAGE_OCTETS),
        Err(TransportError::Encode(_))
    ));
}

#[test]
fn errors_when_the_mandatory_header_and_questions_cannot_fit() {
    let message = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    assert!(matches!(
        truncate_response(message, 12),
        Err(TransportError::MessageTooLong {
            length: 17,
            maximum: 12
        })
    ));
}

#[test]
fn preserves_an_exactly_512_octet_response() {
    let message = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: vec![ResourceRecord {
            name: DomainName::root(),
            rtype: RecordType::Unknown(65_000),
            class: ClassType::IN,
            ttl: 0,
            rdata: RData::Unknown(vec![0; 489]),
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    assert_eq!(message.into_wire().unwrap().len(), MAX_UDP_MESSAGE_OCTETS);

    let packet = truncate_response(message, MAX_UDP_MESSAGE_OCTETS).unwrap();
    let decoded = Message::from_wire(&packet).unwrap();
    assert_eq!(packet.len(), MAX_UDP_MESSAGE_OCTETS);
    assert!(!decoded.headers.tc);
    assert_eq!(decoded.answers.len(), 1);
}
