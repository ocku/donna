use super::*;

#[test]
fn fixed_rdata_bytes_preserve_mx_width_and_character_string_order() {
    let mut mx = Encoder::new();
    super::super::encode_rdata(
        &RData::MX {
            preference: 0x1234,
            exchange: DomainName::from_labels(vec![b"mail".to_vec(), b"example".to_vec()]).unwrap(),
        },
        &mut mx,
    )
    .unwrap();
    assert_eq!(
        mx.into_bytes(),
        [
            0x12, 0x34, 4, b'm', b'a', b'i', b'l', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ]
    );

    let mut hinfo = Encoder::new();
    super::super::encode_rdata(
        &RData::HINFO {
            cpu: b"x86".to_vec(),
            os: b"unix".to_vec(),
        },
        &mut hinfo,
    )
    .unwrap();
    assert_eq!(
        hinfo.into_bytes(),
        [3, b'x', b'8', b'6', 4, b'u', b'n', b'i', b'x']
    );
}

#[test]
fn caa_uses_the_rfc6844_wire_layout_and_round_trips_binary_values() {
    let record = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::CAA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CAA(Caa {
            flags: Caa::ISSUER_CRITICAL_FLAG,
            tag: b"issue".to_vec(),
            value: b"ca.example.net\0binary".to_vec(),
        }),
    };

    let wire = record.into_wire().unwrap();
    assert_eq!(&wire[1..3], &[0x01, 0x01]);
    assert_eq!(&wire[11..], b"\x80\x05issueca.example.net\0binary");
    assert_eq!(
        ResourceRecord::from_wire(&wire).unwrap().rdata,
        record.rdata
    );
}

#[test]
fn caa_receiver_preserves_and_reencodes_reserved_flags_byte_for_byte() {
    let wire = [
        0, // root owner
        1, 1, // TYPE CAA (257)
        0, 1, // CLASS IN
        0, 0, 0, 0, // TTL
        0, 7, // RDLENGTH
        1, 5, b'i', b's', b's', b'u', b'e',
    ];

    let record = ResourceRecord::from_wire(&wire).unwrap();
    let RData::CAA(caa) = &record.rdata else {
        panic!("CAA RDATA was not decoded structurally")
    };
    assert!(caa.has_reserved_flags());
    assert!(!caa.is_issuer_critical());
    assert_eq!(record.into_wire().unwrap(), wire);
}

fn caa_record_wire(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let rdata_length = 2 + tag.len() + value.len();
    let mut wire = vec![0, 1, 1, 0, 1, 0, 0, 0, 0];
    wire.extend_from_slice(&(rdata_length as u16).to_be_bytes());
    wire.extend_from_slice(&[0, tag.len() as u8]);
    wire.extend_from_slice(tag);
    wire.extend_from_slice(value);
    wire
}

#[test]
fn caa_rejects_invalid_property_tags_on_receive() {
    for tag in [
        &b"!"[..],
        &b"iss-ue"[..],
        &b" "[..],
        &b"\t"[..],
        &b"_"[..],
        &[0xff][..],
    ] {
        assert!(matches!(
            ResourceRecord::from_wire(&caa_record_wire(tag, b"opaque\0value")),
            Err(WireError::InvalidRData {
                record_type: "CAA",
                detail: "property tag must contain only ASCII letters and digits",
            })
        ));
    }
}

#[test]
fn caa_accepts_alphanumeric_property_tags_without_changing_case() {
    for tag in [&b"issue"[..], &b"ISSUE123"[..], &b"IsSuE9"[..]] {
        let record = ResourceRecord::from_wire(&caa_record_wire(tag, b"opaque\0value")).unwrap();
        assert!(matches!(
            record.rdata,
            RData::CAA(Caa { tag: decoded, value, .. })
                if decoded.as_slice() == tag && value.as_slice() == b"opaque\0value"
        ));
    }
}

#[test]
fn caa_rejects_empty_and_truncated_tags_on_receive() {
    assert!(ResourceRecord::from_wire(&caa_record_wire(b"", b"")).is_err());

    let truncated = [0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 3, 0, 5, b'i'];
    assert!(ResourceRecord::from_wire(&truncated).is_err());
}

#[test]
fn caa_enforces_tag_and_total_rdata_length_boundaries() {
    let record = |tag_length, value_length| ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::CAA,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::CAA(Caa {
            flags: 0,
            tag: vec![b'a'; tag_length],
            value: vec![0xa5; value_length],
        }),
    };

    let maximum = record(255, usize::from(u16::MAX) - 257);
    let wire = maximum.into_wire().unwrap();
    assert_eq!(&wire[9..11], &[0xff, 0xff]);
    assert!(matches!(
        ResourceRecord::from_wire(&wire).unwrap().rdata,
        RData::CAA(Caa { tag, value, .. }) if tag.len() == 255 && value.len() == 65_278
    ));

    assert!(matches!(
        record(256, 0).into_wire(),
        Err(WireError::LengthOverflow {
            field: "CAA property tag",
            length: 256,
            maximum: 255,
        })
    ));
    assert!(matches!(
        record(255, usize::from(u16::MAX) - 256).into_wire(),
        Err(WireError::LengthOverflow {
            field: "RDATA",
            length: 65_536,
            maximum: 65_535,
        })
    ));
}
