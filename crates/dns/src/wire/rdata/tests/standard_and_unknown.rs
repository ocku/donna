use super::*;

#[test]
fn dname_target_is_uncompressed_even_when_it_repeats_the_owner() {
    let name = DomainName::from_dotted("MiXeD.example.").unwrap();
    let record = ResourceRecord {
        name: name.clone(),
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::DNAME(name.clone()),
    };
    let wire = record.into_wire().unwrap();
    let rdata_start = name.wire_len() + 10;
    assert_eq!(&wire[rdata_start..], &wire[..name.wire_len()]);
    assert_eq!(
        ResourceRecord::from_wire(&wire).unwrap().rdata,
        record.rdata
    );

    let mut compressed = wire[..rdata_start].to_vec();
    compressed[rdata_start - 2..rdata_start].copy_from_slice(&[0, 2]);
    compressed.extend_from_slice(&[0xc0, 0]);
    assert!(matches!(
        ResourceRecord::from_wire(&compressed),
        Err(WireError::InvalidRData {
            record_type: "DNAME",
            ..
        })
    ));
}

#[test]
fn encodes_and_decodes_aaaa_in_network_byte_order() {
    let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 2, 3, 4, 5);
    let record = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::AAAA,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::AAAA(address),
    };

    let wire = record.into_wire().unwrap();
    assert_eq!(&wire[..11], &[0, 0, 28, 0, 1, 0, 0, 0, 0, 0, 16]);
    assert_eq!(&wire[11..], &address.octets());
    assert_eq!(
        ResourceRecord::from_wire(&wire).unwrap().rdata,
        RData::AAAA(address)
    );
}

/// RFC 1035 §3.3: a `<character-string>` holds at most 255 octets; the
/// boundary value itself must round-trip through the wire codec.
#[test]
fn encodes_and_decodes_srv_fields_with_an_uncompressed_target() {
    let target = DomainName::from_labels(vec![b"host".to_vec(), b"example".to_vec()]).unwrap();
    let record = ResourceRecord {
        name: target.clone(),
        rtype: RecordType::SRV,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::SRV {
            priority: 10,
            weight: 20,
            port: 8443,
            target: target.clone(),
        },
    };

    let wire = record.into_wire().unwrap();
    let rdata_start = target.wire_len() + 10;
    assert_eq!(
        &wire[rdata_start..rdata_start + 6],
        &[0, 10, 0, 20, 0x20, 0xfb]
    );
    assert_eq!(
        &wire[rdata_start + 6..],
        &[
            4, b'h', b'o', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0
        ],
        "the target must be written literally even when it repeats the owner"
    );
    assert_eq!(
        ResourceRecord::from_wire(&wire).unwrap().rdata,
        record.rdata
    );
}

#[test]
fn rejects_a_compressed_srv_target() {
    let mut wire = vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0];
    wire.extend_from_slice(&[
        0, 33, // TYPE SRV
        0, 1, // CLASS IN
        0, 0, 0, 0, // TTL
        0, 8, // RDLENGTH
        0, 0, 0, 0, 0, 80, // priority, weight, port
        0xc0, 0x00, // compressed target pointing to the owner
    ]);

    assert!(matches!(
        ResourceRecord::from_wire(&wire),
        Err(WireError::InvalidRData {
            record_type: "SRV",
            detail: "target name must not use compression",
        })
    ));
}

#[test]
fn preserves_srv_as_opaque_data_outside_the_internet_class() {
    let wire = [
        0, // root owner
        0, 33, // TYPE SRV
        0, 3, // CLASS CH
        0, 0, 0, 0, // TTL
        0, 7, // RDLENGTH
        0, 1, 0, 2, 0, 3, 0,
    ];

    let record = ResourceRecord::from_wire(&wire).unwrap();
    assert_eq!(record.rtype, RecordType::SRV);
    assert_eq!(record.rdata, RData::Unknown(vec![0, 1, 0, 2, 0, 3, 0]));
    assert_eq!(record.into_wire().unwrap(), wire);
}

#[test]
fn nsec3_and_nsec3param_round_trip_their_rfc5155_wire_layouts() {
    let zone = DomainName::from_dotted("example").unwrap();
    let records = [
        ResourceRecord {
            name: DomainName::from_dotted("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example").unwrap(),
            rtype: RecordType::NSEC3,
            class: ClassType::IN,
            ttl: 3_600,
            rdata: RData::NSEC3(Nsec3 {
                hash_algorithm: 1,
                flags: Nsec3::OPT_OUT_FLAG,
                iterations: 12,
                salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
                next_hashed_owner_name: vec![0x17; 20],
                type_bitmap: Some(TypeBitmap::new([1, 2, 46, 48, 51]).unwrap()),
            }),
        },
        ResourceRecord {
            name: zone.clone(),
            rtype: RecordType::NSEC3PARAM,
            class: ClassType::IN,
            ttl: 3_600,
            rdata: RData::NSEC3PARAM(Nsec3param {
                hash_algorithm: 1,
                flags: 0,
                iterations: 12,
                salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
            }),
        },
        ResourceRecord {
            name: DomainName::from_dotted("empty.example").unwrap(),
            rtype: RecordType::NSEC3,
            class: ClassType::IN,
            ttl: 3_600,
            rdata: RData::NSEC3(Nsec3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: Vec::new(),
                next_hashed_owner_name: vec![0; 20],
                type_bitmap: None,
            }),
        },
    ];

    for record in records {
        let wire = record.clone().into_wire().unwrap();
        let decoded = ResourceRecord::from_wire(&wire).unwrap();
        assert_eq!(decoded.name, record.name);
        assert_eq!(decoded.rtype, record.rtype);
        assert_eq!(decoded.class, record.class);
        assert_eq!(decoded.ttl, record.ttl);
        assert_eq!(decoded.rdata, record.rdata);
    }
}

#[test]
fn accepts_character_strings_of_exactly_255_octets() {
    let record = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::HINFO,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::HINFO {
            cpu: vec![b'a'; 255],
            os: vec![b'b'; 255],
        },
    };
    let wire = record.into_wire().unwrap();
    assert_eq!(&wire[9..11], &[0x02, 0x00]); // RDLENGTH = 2 + 255 + 255
    let decoded = ResourceRecord::from_wire(&wire).unwrap();
    assert!(matches!(
        decoded.rdata,
        RData::HINFO { ref cpu, ref os } if cpu.len() == 255 && os.len() == 255
    ));
}

/// RFC 1035 §3.3: a `<character-string>` holds at most 255 octets, so a
/// longer TXT string cannot be represented on the wire and must be
/// rejected instead of silently truncated.
#[test]
fn rejects_txt_strings_longer_than_255_octets() {
    let record = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::TXT,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::TXT(vec![vec![b'a'; 256]]),
    };
    assert!(matches!(
        record.into_wire(),
        Err(WireError::LengthOverflow {
            field: "character-string",
            length: 256,
            maximum: 255,
        })
    ));
}

#[test]
fn rejects_empty_txt_rdata() {
    let wire = [
        0x00, // root owner name
        0x00, 0x10, // TYPE TXT
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x00, // TTL
        0x00, 0x00, // RDLENGTH
    ];
    assert!(ResourceRecord::from_wire(&wire).is_err());

    let record = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::TXT,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::TXT(vec![]),
    };
    assert!(record.into_wire().is_err());
}

#[test]
fn preserves_internet_specific_rdata_as_opaque_in_other_classes() {
    let wire = [
        0x00, // root owner name
        0x00, 0x01, // TYPE A
        0x00, 0x03, // CLASS CH
        0x00, 0x00, 0x00, 0x00, // TTL
        0x00, 0x04, // RDLENGTH
        192, 0, 2, 1,
    ];

    let record = ResourceRecord::from_wire(&wire).unwrap();
    assert!(matches!(&record.rdata, RData::Unknown(bytes) if bytes == &[192, 0, 2, 1]));
    assert_eq!(record.into_wire().unwrap(), wire);
}

#[test]
fn standard_rdata_is_structured_outside_the_internet_class() {
    let wire = [
        0x00, // root owner name
        0x00, 0x0f, // TYPE MX
        0x00, 0x03, // CLASS CH
        0x00, 0x00, 0x00, 0x00, // TTL
        0x00, 0x04, // RDLENGTH
        0x00, 0x0a, 0xc0, 0x00, // preference and compressed root exchange
    ];

    let record = ResourceRecord::from_wire(&wire).unwrap();
    assert!(matches!(
        &record.rdata,
        RData::MX { preference: 10, exchange } if exchange == &DomainName::root()
    ));
    let encoded = record.into_wire().unwrap();
    assert!(matches!(
        ResourceRecord::from_wire(&encoded).unwrap().rdata,
        RData::MX { preference: 10, exchange } if exchange == DomainName::root()
    ));
}

#[test]
fn unknown_records_round_trip_without_interpreting_rdata() {
    let wire = [
        0x00, // root owner name
        0xfd, 0xe8, // TYPE 65000
        0x00, 0x01, // CLASS IN
        0x01, 0x02, 0x03, 0x04, // TTL
        0x00, 0x05, // RDLENGTH
        0xde, 0xad, 0xbe, 0xef, 0x00,
    ];

    let record = ResourceRecord::from_wire(&wire).unwrap();
    assert!(matches!(record.rtype, RecordType::Unknown(65_000)));
    assert!(
        matches!(&record.rdata, RData::Unknown(bytes) if bytes == &[0xde, 0xad, 0xbe, 0xef, 0x00])
    );
    assert_eq!(record.into_wire().unwrap(), wire);
}

#[test]
fn unknown_rdata_accepts_the_full_rdlength_and_rejects_one_more_octet() {
    let record = |length| ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::Unknown(65_000),
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::Unknown(vec![0xa5; length]),
    };

    let wire = record(usize::from(u16::MAX)).into_wire().unwrap();
    assert_eq!(&wire[9..11], &[0xff, 0xff]);
    assert!(matches!(
        ResourceRecord::from_wire(&wire).unwrap().rdata,
        RData::Unknown(bytes) if bytes.len() == usize::from(u16::MAX)
    ));

    assert!(matches!(
        record(usize::from(u16::MAX) + 1).into_wire(),
        Err(WireError::LengthOverflow {
            field: "RDATA",
            length: 65_536,
            maximum: 65_535,
        })
    ));
}
