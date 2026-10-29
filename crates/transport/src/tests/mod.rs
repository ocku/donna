#[cfg(any(feature = "doh", feature = "doq"))]
pub(crate) mod fixtures;

use dns::{
    ClassType, DomainName, Edns, EdnsOption, FromWire, Headers, IntoWire, Message, OpCode,
    QClassType, QueryType, Question, RCode,
};

use super::{
    TransportError, format_error_response, matches_query, normalize_response_headers,
    recover_questions_from_edns_request, reject_cleartext_padding, remove_cleartext_padding,
    request_questions_are_safe_to_echo,
};

fn question(label: &[u8]) -> Question {
    Question {
        qname: DomainName::from_labels(vec![label.to_vec()]).unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn message(headers: Headers, questions: Vec<Question>) -> dns::Message {
    dns::Message {
        headers,
        questions,
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn message_with_padding() -> dns::Message {
    let mut edns = Edns::new(1232);
    edns.options = vec![
        EdnsOption {
            code: 65000,
            data: vec![1, 2, 3],
        },
        EdnsOption::padding_with_data(vec![0xff]),
    ];
    dns::Message::builder()
        .additionals([edns.into_record()])
        .build()
        .unwrap()
}

#[test]
fn cleartext_padding_is_rejected_for_sends_and_removable_for_server_responses() {
    let mut message = message_with_padding();
    assert!(matches!(
        reject_cleartext_padding(&message),
        Err(TransportError::InsecureEdnsPadding)
    ));

    remove_cleartext_padding(&mut message);

    reject_cleartext_padding(&message).unwrap();
    let edns = message.edns().unwrap().unwrap();
    assert_eq!(
        edns.options,
        vec![EdnsOption {
            code: 65000,
            data: vec![1, 2, 3]
        }]
    );
}

#[test]
fn request_questions_are_echoable_only_when_the_complete_section_is_canonical() {
    let canonical = question(b"canonical");
    let mut noncanonical = question(b"noncanonical");
    noncanonical.qclass = QClassType::Unknown(0);

    assert!(request_questions_are_safe_to_echo(std::slice::from_ref(
        &canonical
    )));
    assert!(!request_questions_are_safe_to_echo(&[
        canonical,
        noncanonical
    ]));
}

#[test]
fn matches_complete_standard_question_lists() {
    for questions in [Vec::new(), vec![question(b"one"), question(b"two")]] {
        let query = message(
            Headers {
                id: 42,
                ..Headers::default()
            },
            questions.clone(),
        );
        let reply = message(
            Headers {
                id: 42,
                qr: true,
                ..Headers::default()
            },
            questions,
        );
        assert!(matches_query(&reply, &query));
    }
}

#[test]
fn matches_inverse_errors_and_responses_with_generated_questions() {
    let query = message(
        Headers {
            id: 42,
            opcode: OpCode::IQuery,
            ..Headers::default()
        },
        Vec::new(),
    );
    let error = message(
        Headers {
            id: 42,
            qr: true,
            opcode: OpCode::IQuery,
            rcode: RCode::NotImplemented,
            ..Headers::default()
        },
        Vec::new(),
    );
    let success = message(
        Headers {
            id: 42,
            qr: true,
            opcode: OpCode::IQuery,
            ..Headers::default()
        },
        vec![question(b"one"), question(b"two")],
    );

    assert!(matches_query(&error, &query));
    assert!(matches_query(&success, &query));
}

#[test]
fn rejects_mismatched_replies() {
    let questions = vec![question(b"one"), question(b"two")];
    let query = message(
        Headers {
            id: 42,
            ..Headers::default()
        },
        questions.clone(),
    );
    // RFC 1035 §7.3: discard datagrams which are queries when responses
    // are expected, and match replies by their transaction ID.
    let not_a_response = message(
        Headers {
            id: 42,
            ..Headers::default()
        },
        questions.clone(),
    );
    let wrong_id = message(
        Headers {
            id: 43,
            qr: true,
            ..Headers::default()
        },
        questions.clone(),
    );
    let incomplete = message(
        Headers {
            id: 42,
            qr: true,
            ..Headers::default()
        },
        vec![questions[0].clone()],
    );
    let different = message(
        Headers {
            id: 42,
            qr: true,
            ..Headers::default()
        },
        vec![questions[0].clone(), question(b"other")],
    );
    let wrong_opcode = message(
        Headers {
            id: 42,
            qr: true,
            opcode: OpCode::Status,
            ..Headers::default()
        },
        questions,
    );

    assert!(!matches_query(&not_a_response, &query));
    assert!(!matches_query(&wrong_id, &query));
    assert!(!matches_query(&incomplete, &query));
    assert!(!matches_query(&different, &query));
    // RFC 1035 §4.1.1: a response's OPCODE must match the query's.
    assert!(!matches_query(&wrong_opcode, &query));
}

#[test]
fn formerr_copies_id_opcode_and_rd_from_a_malformed_packet() {
    // ID 0x1234; OPCODE=IQUERY and RD are set, but the header is incomplete.
    let reply = format_error_response(&[0x12, 0x34, 0x09]).unwrap();
    let message = dns::Message::from_wire(&reply).unwrap();

    assert_eq!(message.headers.id, 0x1234);
    assert!(message.headers.qr);
    assert_eq!(message.headers.opcode, OpCode::IQuery);
    assert!(message.headers.rd);
    assert_eq!(message.headers.rcode, RCode::FormatError);
    assert!(message.questions.is_empty());

    // RFC 1035 §4.1.1: AA, TC, RA, and the Z bits must be zero, and the
    // RCODE field must be exactly FORMERR (0x1).
    assert_eq!(reply[2] & 0x70, 0);
    assert_eq!(reply[3], 0x01);
}

#[test]
fn malformed_edns_formerr_recovers_canonical_question_and_includes_opt() {
    let query = Message::builder()
        .questions([question(b"example")])
        .additionals([dns::Edns::new(1232).into_record()])
        .build()
        .unwrap();
    let mut packet = query.into_wire().unwrap();
    let rdlength = packet.len() - 2;
    packet[rdlength..].copy_from_slice(&4_u16.to_be_bytes());
    // EDE says it contains one data octet, but the OPT RDLENGTH ends after its
    // tuple header, causing the regular decoder to reject the request.
    packet.extend_from_slice(&[0, 15, 0, 1]);

    let recovery = recover_questions_from_edns_request(&packet).unwrap();
    assert_eq!(recovery.udp_payload_size, 1232);

    let response = Message::from_wire(&format_error_response(&packet).unwrap()).unwrap();
    assert_eq!(response.headers.rcode, RCode::FormatError);
    assert!(super::same_questions(&response.questions, &query.questions));
    assert!(response.edns().unwrap().is_some());
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert_eq!(response.additionals.len(), 1);
}

#[test]
fn cannot_reply_to_a_packet_without_a_transaction_id() {
    assert!(format_error_response(&[0x12]).is_none());
}

#[test]
fn transport_errors_expose_underlying_error_sources() {
    let io = super::TransportError::Io(std::io::Error::other("network"));
    let wire = dns::wire::WireError::InvalidValue {
        field: "test",
        value: 1,
    };
    let encode = super::TransportError::Encode(wire.clone());
    let decode = super::TransportError::Decode(wire);

    assert!(std::error::Error::source(&io).is_some());
    assert!(std::error::Error::source(&encode).is_some());
    assert!(std::error::Error::source(&decode).is_some());
    assert!(std::error::Error::source(&super::TransportError::Timeout).is_none());
}

#[test]
fn normalizes_mandatory_response_headers() {
    let request = dns::Headers {
        id: 0x1234,
        opcode: OpCode::Status,
        rd: true,
        ..Headers::default()
    };
    let mut response = dns::Message {
        headers: Headers {
            id: 7,
            aa: true,
            tc: true,
            ra: true,
            rcode: RCode::Refused,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    normalize_response_headers(&request, &mut response);

    assert_eq!(response.headers.id, 0x1234);
    assert!(response.headers.qr);
    assert_eq!(response.headers.opcode, OpCode::Status);
    assert!(response.headers.rd);
    // Handler-set response fields are preserved.
    assert!(response.headers.aa);
    assert!(response.headers.tc);
    assert!(response.headers.ra);
    assert_eq!(response.headers.rcode, RCode::Refused);
}

#[cfg(feature = "tcp")]
pub(crate) mod signed_responses;

#[test]
fn questionless_update_correlation_keeps_header_and_zone_checks() {
    let request = message(
        Headers {
            id: 42,
            opcode: OpCode::Update,
            ..Headers::default()
        },
        vec![question(b"example")],
    );
    let mut response = message(
        Headers {
            qr: true,
            ..request.headers.clone()
        },
        vec![],
    );
    assert!(matches_query(&response, &request));
    response.headers.id += 1;
    assert!(!matches_query(&response, &request));
    response.headers.id = request.headers.id;
    response.questions.push(question(b"unrelated"));
    assert!(!matches_query(&response, &request));
    response.questions.clear();
    response.headers.opcode = OpCode::Query;
    let mut standard_request = request;
    standard_request.headers.opcode = OpCode::Query;
    assert!(!matches_query(&response, &standard_request));
}
