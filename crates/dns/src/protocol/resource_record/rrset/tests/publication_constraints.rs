use super::*;

#[test]
fn zone_publication_enforces_dnskey_and_nsec3_flags() {
    let dnskey = |flags, protocol| {
        dnssec_record(
            RecordType::DNSKEY,
            RData::DNSKEY(Dnskey {
                flags,
                protocol,
                algorithm: 8,
                public_key: vec![1],
            }),
        )
    };
    assert_eq!(
        dnskey(Dnskey::ZONE_KEY_FLAG, 2).validate_locally_authored(),
        Err(RecordValidationError::InvalidDnskeyProtocol { value: 2 })
    );
    assert_eq!(
        dnskey(Dnskey::ZONE_KEY_FLAG | 0x0002, 3).validate_locally_authored(),
        Err(RecordValidationError::ReservedDnskeyFlags {
            value: Dnskey::ZONE_KEY_FLAG | 0x0002,
        })
    );
    assert_eq!(
        dnskey(Dnskey::SECURE_ENTRY_POINT_FLAG, 3).validate_locally_authored(),
        Err(RecordValidationError::DnskeySepWithoutZoneKey)
    );
    assert!(
        dnskey(Dnskey::ZONE_KEY_FLAG | Dnskey::SECURE_ENTRY_POINT_FLAG, 3)
            .validate_locally_authored()
            .is_ok()
    );

    let nsec3 = dnssec_record(
        RecordType::NSEC3,
        RData::NSEC3(Nsec3 {
            hash_algorithm: 1,
            flags: 0x80,
            iterations: 0,
            salt: Vec::new(),
            next_hashed_owner_name: vec![0; 20],
            type_bitmap: None,
        }),
    );
    assert!(nsec3.validate().is_ok(), "receivers ignore reserved flags");
    assert_eq!(
        nsec3.validate_locally_authored(),
        Err(RecordValidationError::ReservedNsec3Flags { value: 0x80 })
    );

    let parameters = dnssec_record(
        RecordType::NSEC3PARAM,
        RData::NSEC3PARAM(Nsec3param {
            hash_algorithm: 1,
            flags: 1,
            iterations: 0,
            salt: Vec::new(),
        }),
    );
    assert!(parameters.validate().is_ok(), "receivers ignore flags");
    assert_eq!(
        parameters.validate_locally_authored(),
        Err(RecordValidationError::NonzeroNsec3paramFlags { value: 1 })
    );
}

#[test]
fn nsec3_wire_validation_enforces_one_octet_lengths() {
    let make = |salt: Vec<u8>, next_hashed_owner_name: Vec<u8>| {
        dnssec_record(
            RecordType::NSEC3,
            RData::NSEC3(Nsec3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt,
                next_hashed_owner_name,
                type_bitmap: None,
            }),
        )
    };
    assert_eq!(
        make(vec![0; 256], vec![0; 20]).validate(),
        Err(RecordValidationError::Nsec3SaltTooLong { length: 256 })
    );
    for length in [0, 256] {
        assert_eq!(
            make(Vec::new(), vec![0; length]).validate(),
            Err(RecordValidationError::InvalidNsec3HashLength { length })
        );
    }
    assert_eq!(
        make(Vec::new(), vec![0; 19]).validate(),
        Err(RecordValidationError::InvalidNsec3Sha1HashLength { length: 19 })
    );

    let mut future = make(Vec::new(), vec![0; 19]);
    let RData::NSEC3(nsec3) = &mut future.rdata else {
        unreachable!()
    };
    nsec3.hash_algorithm = 2;
    assert!(future.validate().is_ok());
}

#[test]
fn record_validation_enforces_rfc6895_data_type_and_class_ranges() {
    let mut record = ResourceRecord {
        name: DomainName::from_labels(vec![b"opaque".to_vec(), b"example".to_vec()]).unwrap(),
        rtype: RecordType::Unknown(127),
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::Unknown(vec![1]),
    };

    for code in [128, 200, 248] {
        record.rtype = RecordType::Unknown(code);
        assert_eq!(
            record.validate(),
            Err(RecordValidationError::NonCanonicalRecordType { value: code })
        );
    }
    for code in [127, 256, 61_439, 65_280, 65_534] {
        record.rtype = RecordType::Unknown(code);
        assert!(record.validate().is_ok(), "rejected data TYPE {code}");
    }
    record.rtype = RecordType::Unknown(249);
    assert!(record.validate().is_ok(), "rejected Meta-TYPE 249");
    record.rtype = RecordType::Unknown(250);
    assert_eq!(
        record.validate(),
        Err(RecordValidationError::NonCanonicalRecordType { value: 250 })
    );

    record.rtype = RecordType::Unknown(127);
    for code in [0, 128, 253, 254, 255, 57_344, 65_279, u16::MAX] {
        record.class = ClassType::Unknown(code);
        assert_eq!(
            record.validate(),
            Err(RecordValidationError::NonCanonicalClass { value: code })
        );
    }
    for code in [2, 5, 127, 256, 57_343, 65_280, 65_534] {
        record.class = ClassType::Unknown(code);
        assert!(record.validate().is_ok(), "rejected data CLASS {code}");
    }
}
