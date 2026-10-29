use super::*;

#[test]
fn rejects_compression_pointers_to_non_name_data() {
    let bytes = [
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, // header
        0xc0, 0x00, 0, 1, 0, 1, // pointer targets the ID field
    ];
    assert!(matches!(
        Message::from_wire(&bytes),
        Err(crate::wire::WireError::CompressionPointerInvalidTarget { .. })
    ));
}

#[test]
fn rejects_non_backward_compression_pointers() {
    for (offset_octet, expected_offset) in [(0x0c, 12), (0x0e, 14)] {
        let bytes = [
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0xc0,
            offset_octet,
            0,
            1,
            0,
            1,
        ];
        assert!(matches!(
            Message::from_wire(&bytes),
            Err(crate::wire::WireError::CompressionPointerForward {
                position: 12,
                offset,
            }) if offset == expected_offset
        ));
    }
}

#[test]
fn round_trips_full_width_unsigned_soa_intervals() {
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .questions(vec![])
        .answers(vec![ResourceRecord {
            name: DomainName::root(),
            rtype: RecordType::SOA,
            class: ClassType::IN,
            ttl: 0,
            rdata: RData::SOA {
                mname: DomainName::root(),
                rname: DomainName::root(),
                serial: 0,
                refresh: u32::MAX,
                retry: 0x8000_0000,
                expire: i32::MAX as u32,
                minimum: 0,
            },
        }])
        .authorities(vec![])
        .additionals(vec![])
        .build()
        .unwrap();

    let decoded = Message::from_wire(&message.into_wire().unwrap()).unwrap();
    assert!(matches!(
        decoded.answers[0].rdata,
        RData::SOA {
            refresh: u32::MAX,
            retry: 0x8000_0000,
            expire: 0x7fff_ffff,
            ..
        }
    ));
}

#[test]
fn accepts_zero_extended_wks_bitmaps_and_rejects_oversized_ones() {
    let wks_message = |bitmap: Vec<u8>| {
        Message::builder()
            .headers(Headers {
                qr: true,
                ..Headers::default()
            })
            .answers([ResourceRecord {
                name: DomainName::root(),
                rtype: RecordType::WKS,
                class: ClassType::IN,
                ttl: 0,
                rdata: RData::WKS {
                    address: Ipv4Addr::UNSPECIFIED,
                    protocol: 6,
                    bitmap,
                },
            }])
            .build_unchecked()
    };

    let zero_extended = wks_message(vec![0x80, 0]).into_wire().unwrap();
    assert!(matches!(
        &Message::from_wire(&zero_extended).unwrap().answers[0].rdata,
        RData::WKS { bitmap, .. } if bitmap == &[0x80, 0]
    ));
    assert!(wks_message(vec![0x80; 8193]).into_wire().is_err());
    assert!(wks_message(Vec::new()).into_wire().is_ok());
    assert!(wks_message(vec![0x80; 8192]).into_wire().is_ok());

    let zero_extended_wire = [
        0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0, // response header
        0, 0, 11, 0, 1, 0, 0, 0, 0, 0, 7, // root WKS/IN, RDLENGTH 7
        0, 0, 0, 0, 6, 0x80, 0,
    ];
    assert!(Message::from_wire(&zero_extended_wire).is_ok());
}

#[test]
fn structured_rdata_must_consume_rdlength_exactly() {
    let too_short = [
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, // header
        0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 3, // root A/IN, TTL 0, RDLENGTH 3
        192, 0, 2,
    ];
    assert!(matches!(
        Message::from_wire(&too_short),
        Err(crate::wire::WireError::Truncated { .. })
    ));

    let too_long = [
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, // header
        0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 5, // root A/IN, TTL 0, RDLENGTH 5
        192, 0, 2, 1, 0,
    ];
    assert!(matches!(
        Message::from_wire(&too_long),
        Err(crate::wire::WireError::InvalidRData {
            detail: "RDATA length was not consumed exactly",
            ..
        })
    ));
}

/// RFC 1035 §4.1.4's worked compression example: F.ISI.ARPA at offset 20,
/// FOO.F.ISI.ARPA at 40 via a pointer, ARPA at 64 via a pointer to the
/// suffix of the name at 20, and the root at 92.
#[test]
fn decodes_the_rfc1035_section_4_1_4_compression_example() {
    let mut wire = vec![0; 20];
    wire.extend_from_slice(&[1, b'F', 3, b'I', b'S', b'I', 4, b'A', b'R', b'P', b'A', 0]);
    assert_eq!(wire.len(), 32); // F.ISI.ARPA occupies offsets 20..32
    wire.extend_from_slice(&[0; 8]); // pad to offset 40
    wire.extend_from_slice(&[3, b'F', b'O', b'O', 0xc0, 20]); // FOO.F.ISI.ARPA
    assert_eq!(wire.len(), 46);
    wire.extend_from_slice(&[0; 18]); // pad to offset 64
    wire.extend_from_slice(&[0xc0, 26]); // ARPA at offset 64
    wire.extend_from_slice(&[0; 26]); // pad to offset 92
    wire.push(0); // root at offset 92

    let mut decoder = Decoder::new(&wire);
    decoder.read_exact(20).unwrap();
    assert_eq!(
        decode_name(&mut decoder).unwrap().as_ref(),
        [b"F".to_vec(), b"ISI".to_vec(), b"ARPA".to_vec()]
    );
    decoder.read_exact(40 - decoder.position()).unwrap();
    assert_eq!(
        decode_name(&mut decoder).unwrap().as_ref(),
        [
            b"FOO".to_vec(),
            b"F".to_vec(),
            b"ISI".to_vec(),
            b"ARPA".to_vec()
        ]
    );
    // Skip to offset 64 and decode the suffix-pointer ARPA name.
    decoder.read_exact(64 - decoder.position()).unwrap();
    assert_eq!(
        decode_name(&mut decoder).unwrap().as_ref(),
        [b"ARPA".to_vec()]
    );
    decoder.read_exact(92 - decoder.position()).unwrap();
    assert_eq!(decode_name(&mut decoder).unwrap(), DomainName::root());
}

#[test]
fn rejects_encoding_messages_longer_than_the_tcp_length_field() {
    let oversized = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::NULL,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::NULL(vec![0; usize::from(u16::MAX)]),
    };
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .answers([
            oversized.clone(),
            ResourceRecord {
                name: DomainName::from_labels(vec![b"other".to_vec()]).unwrap(),
                ..oversized
            },
        ])
        .build_unchecked();
    assert!(matches!(
        message.into_wire(),
        Err(crate::wire::WireError::LengthOverflow {
            field: "message",
            maximum: 65_535,
            ..
        })
    ));
}

#[test]
fn header_counts_encode_and_decode_each_message_section() {
    let record = |owner: &[u8], address| ResourceRecord {
        name: DomainName::from_labels(vec![owner.to_vec()]).unwrap(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::A(address),
    };
    let message = Message::builder()
        .headers(Headers {
            qr: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::root(),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .answers([record(b"answer", Ipv4Addr::new(192, 0, 2, 1))])
        .authorities([record(b"authority", Ipv4Addr::new(192, 0, 2, 2))])
        .additionals([record(b"additional", Ipv4Addr::new(192, 0, 2, 3))])
        .build()
        .unwrap();

    let wire = message.into_wire().unwrap();
    assert_eq!(&wire[4..12], &[0, 1, 0, 1, 0, 1, 0, 1]);
    let decoded = Message::from_wire(&wire).unwrap();
    assert_eq!(decoded.questions.len(), 1);
    assert_eq!(
        decoded.answers[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(
        decoded.authorities[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 2))
    );
    assert_eq!(
        decoded.additionals[0].rdata,
        RData::A(Ipv4Addr::new(192, 0, 2, 3))
    );
}

#[test]
fn rejects_short_and_trailing_message_octets() {
    for length in 0..HEADER_OCTETS {
        assert!(matches!(
            Message::from_wire(&vec![0; length]),
            Err(crate::wire::WireError::Truncated { .. })
        ));
    }

    let mut wire = vec![0; HEADER_OCTETS];
    wire.push(0);
    assert!(matches!(
        Message::from_wire(&wire),
        Err(crate::wire::WireError::InvalidValue {
            field: "message trailing octets",
            value: 1,
        })
    ));

    let oversized = vec![0; usize::from(u16::MAX) + 1];
    assert!(matches!(
        Message::from_wire(&oversized),
        Err(crate::wire::WireError::LengthOverflow {
            field: "message",
            length: 65_536,
            maximum: 65_535,
        })
    ));
}

#[test]
fn wire_encoding_rejects_response_only_fields_on_a_query() {
    for headers in [
        Headers {
            aa: true,
            ..Headers::default()
        },
        Headers {
            tc: true,
            ..Headers::default()
        },
        Headers {
            ra: true,
            ..Headers::default()
        },
        Headers {
            rcode: crate::RCode::Refused,
            ..Headers::default()
        },
    ] {
        let message = Message::builder().headers(headers).build_unchecked();
        assert!(matches!(
            message.into_wire(),
            Err(crate::wire::WireError::InvalidValue {
                field: "query response-only header fields",
                ..
            })
        ));
    }
}
