use super::*;

#[test]
fn rrset_compares_hinfo_nonalphabetic_octets_exactly() {
    assert!(
        RrSet::try_from_records(vec![
            hinfo_record(b"x86-64", b"Unix"),
            hinfo_record(b"x86_64", b"Unix"),
        ])
        .is_ok()
    );
}

#[test]
fn record_validation_rejects_invalid_caa_property_tags() {
    let caa_record = |tag: &[u8]| ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::CAA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CAA(Caa {
            flags: 0,
            tag: tag.to_vec(),
            value: b"opaque\0value".to_vec(),
        }),
    };

    assert_eq!(
        caa_record(b"").validate(),
        Err(RecordValidationError::EmptyCaaTag)
    );
    for tag in [&b"!"[..], &b"iss-ue"[..], &b" "[..], &b"\t"[..], &b"_"[..]] {
        assert_eq!(
            caa_record(tag).validate(),
            Err(RecordValidationError::InvalidCaaTag)
        );
    }
    for tag in [&b"issue"[..], &b"ISSUE123"[..], &b"IsSuE9"[..]] {
        assert!(caa_record(tag).validate().is_ok());
    }
}

#[test]
fn rrset_compares_caa_rdata_octets_exactly() {
    let caa_record = |flags: u8, tag: &[u8], value: &[u8]| ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::CAA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CAA(Caa {
            flags,
            tag: tag.to_vec(),
            value: value.to_vec(),
        }),
    };

    assert!(
        RrSet::try_from_records(vec![
            caa_record(0, b"issue", b"ca.example"),
            caa_record(0, b"ISSUE", b"ca.example"),
        ])
        .is_ok()
    );
    assert!(matches!(
        RrSet::try_from_records(vec![
            caa_record(0, b"issue", b"ca.example"),
            caa_record(0, b"issue", b"ca.example"),
        ]),
        Err(RecordValidationError::DuplicateRecord)
    ));
    assert!(
        RrSet::try_from_records(vec![
            caa_record(0, b"issue", b"ca.example"),
            caa_record(0, b"issue", b"CA.EXAMPLE"),
        ])
        .is_ok()
    );
    assert!(
        RrSet::try_from_records(vec![
            caa_record(0, b"issue", b"ca.example"),
            caa_record(Caa::ISSUER_CRITICAL_FLAG, b"issue", b"ca.example"),
        ])
        .is_ok()
    );
}

#[test]
fn rrset_compares_hinfo_non_ascii_octets_exactly_and_preserves_bytes() {
    let first = hinfo_record(&[b'X', 0xc0], b"Unix");
    let second = hinfo_record(&[b'x', 0xe0], b"uNIX");
    let set = RrSet::try_from_records(vec![first.clone(), second.clone()]).unwrap();

    assert_eq!(&set.records[0].rdata, &first.rdata);
    assert_eq!(&set.records[1].rdata, &second.rdata);
}

#[test]
fn zone_validation_permits_cname_and_data_at_different_owners() {
    let records = vec![
        ResourceRecord {
            name: DomainName::from_labels(vec![b"alias".to_vec()]).unwrap(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::CNAME(DomainName::root()),
        },
        ResourceRecord {
            name: DomainName::from_labels(vec![b"host".to_vec()]).unwrap(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        },
    ];
    assert!(validate_zone_records(&records).is_ok());
}

#[test]
fn zone_validation_rejects_cname_with_other_data() {
    let name = DomainName::from_labels(vec![b"alias".to_vec()]).unwrap();
    let records = vec![
        ResourceRecord {
            name: name.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::CNAME(DomainName::root()),
        },
        ResourceRecord {
            name,
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        },
    ];
    assert!(matches!(
        validate_zone_records(&records),
        Err(RecordValidationError::CnameWithOtherData)
    ));
}

#[test]
fn zone_validation_allows_dnssec_records_at_a_cname_owner() {
    let name = DomainName::from_labels(vec![b"alias".to_vec()]).unwrap();
    let mut records = vec![ResourceRecord {
        name: name.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(DomainName::root()),
    }];
    records.push(ResourceRecord {
        name: name.clone(),
        rtype: RecordType::KEY,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::KEY(crate::Key {
            flags: 0,
            protocol: 3,
            algorithm: 1,
            public_key: vec![25],
        }),
    });
    records.push(rrsig_record(60, 46));
    records.push(ResourceRecord {
        name: name.clone(),
        rtype: RecordType::NSEC,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NSEC(crate::Nsec {
            next_domain_name: DomainName::root(),
            type_bitmap: TypeBitmap::new([5, 46, 47]).unwrap(),
        }),
    });

    assert!(validate_zone_records(&records).is_ok());
}

#[test]
fn zone_validation_rejects_mixed_classes_per_rfc1035_section_5_2() {
    let records = vec![
        record(60, [192, 0, 2, 1]),
        ResourceRecord {
            class: ClassType::CH,
            rtype: RecordType::TXT,
            rdata: RData::TXT(vec![b"chaos".to_vec()]),
            ..record(60, [192, 0, 2, 2])
        },
    ];
    assert!(matches!(
        validate_zone_records(&records),
        Err(RecordValidationError::MixedZoneClass)
    ));
    assert!(validate_zone_records(&[record(60, [192, 0, 2, 1])]).is_ok());
}

#[test]
fn zone_publication_rejects_reserved_caa_flags_without_weakening_forwarding() {
    let caa = ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::CAA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CAA(Caa {
            flags: 0x01,
            tag: b"issue".to_vec(),
            value: b"ca.example".to_vec(),
        }),
    };

    assert!(caa.validate().is_ok());
    assert!(matches!(
        validate_zone_records(&[caa]),
        Err(RecordValidationError::ReservedCaaFlags { value: 0x01 })
    ));
}
