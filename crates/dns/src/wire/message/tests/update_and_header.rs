use super::*;

pub(super) fn update_message() -> Message {
    let zone = update_zone();
    let host = name(&[b"host", b"example", b"com"]);
    Message::builder()
        .headers(Headers {
            id: 0x2136,
            opcode: crate::OpCode::Update,
            ..Headers::default()
        })
        .questions([Question {
            qname: zone,
            qtype: QueryType::SOA,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .answers([
            // RFC 2136 sections 2.4.1 through 2.4.5.
            update_meta(host.clone(), RecordType::A, 255),
            ResourceRecord {
                name: host.clone(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl: 0,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            },
            update_meta(host.clone(), RecordType::AAAA, 254),
            update_meta(host.clone(), RecordType::Unknown(255), 255),
            update_meta(host.clone(), RecordType::Unknown(255), 254),
        ])
        .authorities([
            // RFC 2136 sections 2.5.1 through 2.5.4.
            ResourceRecord {
                name: host.clone(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 2)),
            },
            update_meta(host.clone(), RecordType::AAAA, 255),
            update_meta(host.clone(), RecordType::Unknown(255), 255),
            ResourceRecord {
                name: host,
                rtype: RecordType::A,
                class: ClassType::Unknown(254),
                ttl: 0,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 3)),
            },
            ResourceRecord {
                name: name(&[b"empty-null", b"example", b"com"]),
                rtype: RecordType::NULL,
                class: ClassType::Unknown(254),
                ttl: 0,
                rdata: RData::NULL(Vec::new()),
            },
        ])
        .build()
        .unwrap()
}

#[test]
fn round_trips_every_rfc2136_prerequisite_and_update_form() {
    let message = update_message();
    let wire = message.into_wire().unwrap();
    let decoded = Message::from_wire(&wire).unwrap();

    assert_eq!(decoded.headers.opcode, crate::OpCode::Update);
    assert_eq!(decoded.answers.len(), 5);
    assert_eq!(decoded.authorities.len(), 5);
    assert!(decoded.validate_strict().is_ok());
    assert_eq!(decoded.into_wire().unwrap(), wire);
    assert!(matches!(
        decoded.authorities[3],
        ResourceRecord {
            class: ClassType::Unknown(254),
            rdata: RData::A(address),
            ..
        } if address == Ipv4Addr::new(192, 0, 2, 3)
    ));
    assert!(matches!(
        &decoded.authorities[4].rdata,
        RData::NULL(bytes) if bytes.is_empty()
    ));
}

#[test]
fn accepts_an_rfc2136_response_with_omitted_sections() {
    let response = Message::builder()
        .headers(Headers {
            id: 0x2136,
            qr: true,
            opcode: crate::OpCode::Update,
            rcode: crate::RCode::Refused,
            ..Headers::default()
        })
        .build()
        .unwrap();
    let wire = response.into_wire().unwrap();
    assert_eq!(
        Message::from_wire(&wire).unwrap().into_wire().unwrap(),
        wire
    );
}

#[test]
fn receives_nonzero_update_reserved_bits_but_authors_them_as_zero() {
    let mut received = update_message();
    received.headers.aa = true;
    received.headers.tc = true;
    received.headers.rd = true;
    received.headers.ra = true;
    received.headers.ad = true;
    received.headers.cd = true;
    received.headers.rcode = crate::RCode::NameError;

    assert!(received.validate_for_forwarding().is_ok());
    assert!(matches!(
        received.validate_strict(),
        Err(MessageValidationError::InvalidUpdateMessage)
    ));
    let decoded = Message::from_wire(&received.into_wire().unwrap()).unwrap();
    assert!(decoded.headers.aa && decoded.headers.tc && decoded.headers.rd);
    assert!(decoded.headers.ra && decoded.headers.ad && decoded.headers.cd);
    assert_eq!(decoded.headers.rcode, crate::RCode::NameError);
}

#[test]
fn rejects_invalid_rfc2136_zone_and_metavalue_forms() {
    let invalid_messages = [
        {
            let mut message = update_message();
            message.questions[0].qtype = QueryType::A;
            message
        },
        {
            let mut message = update_message();
            message.answers[0].ttl = 1;
            message
        },
        {
            let mut message = update_message();
            message.answers[0].rdata = RData::Unknown(vec![1]);
            message
        },
        {
            let mut message = update_message();
            message.authorities[3].rtype = RecordType::Unknown(255);
            message
        },
        {
            let mut message = update_message();
            message.authorities[0].name = name(&[b"outside", b"test"]);
            message
        },
    ];

    for message in invalid_messages {
        assert!(matches!(
            message.validate_strict(),
            Err(MessageValidationError::InvalidUpdateMessage)
        ));
        assert!(message.into_wire().is_err());
    }
}

#[test]
fn decodes_but_does_not_reemit_unassigned_rcodes() {
    for rcode in 11..=15 {
        let bytes = [0x12, 0x34, 0x80, rcode, 0, 0, 0, 0, 0, 0, 0, 0];
        let message = Message::from_wire(&bytes).unwrap();
        assert_eq!(message.headers.rcode, crate::RCode::Unknown(rcode));
        assert!(matches!(
            message.into_wire(),
            Err(crate::wire::WireError::InvalidValue {
                field: "RCODE",
                value,
            }) if value == u64::from(rcode)
        ));
    }
}

#[test]
fn round_trips_assigned_update_rcodes() {
    for (value, rcode) in [
        (6, crate::RCode::YXDomain),
        (7, crate::RCode::YXRRSet),
        (8, crate::RCode::NXRRSet),
        (9, crate::RCode::NotAuthoritative),
        (10, crate::RCode::NotZone),
    ] {
        let bytes = [0x12, 0x34, 0x80, value, 0, 0, 0, 0, 0, 0, 0, 0];
        let message = Message::from_wire(&bytes).unwrap();
        assert_eq!(message.headers.rcode, rcode);
        assert_eq!(message.into_wire().unwrap(), bytes);
    }
}

#[test]
fn decodes_but_does_not_reemit_unassigned_opcodes_on_queries() {
    for (opcode, query_flags_high) in [
        (3, 0x18),
        (6, 0x30),
        (7, 0x38),
        (8, 0x40),
        (9, 0x48),
        (10, 0x50),
        (11, 0x58),
        (12, 0x60),
        (13, 0x68),
        (14, 0x70),
        (15, 0x78),
    ] {
        let bytes = [0x12, 0x34, query_flags_high, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let message = Message::from_wire(&bytes).unwrap();
        assert_eq!(message.headers.opcode, crate::OpCode::Unknown(opcode));
        assert!(matches!(
            message.into_wire(),
            Err(crate::wire::WireError::InvalidValue {
                field: "OPCODE",
                value,
            }) if value == u64::from(opcode)
        ));
    }
}

#[test]
fn reemits_an_unassigned_opcode_echoed_by_a_response() {
    // An unsupported OPCODE is copied into its NOTIMP response so the
    // client can match the response to its query.
    for opcode in [3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
        let bytes = [
            0x12,
            0x34,
            0x80 | (opcode << 3),
            0x04,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let message = Message::from_wire(&bytes).unwrap();
        assert_eq!(message.headers.opcode, crate::OpCode::Unknown(opcode));
        assert_eq!(message.headers.rcode, crate::RCode::NotImplemented);
        assert_eq!(message.into_wire().unwrap(), bytes);
    }
}
