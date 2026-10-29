use super::*;

#[test]
fn rrset_rejects_mixed_ttls_and_duplicates() {
    assert!(matches!(
        RrSet::try_from_records(vec![record(60, [192, 0, 2, 1]), record(30, [192, 0, 2, 2])]),
        Err(RecordValidationError::InconsistentTtl { .. })
    ));
    assert!(matches!(
        RrSet::try_from_records(vec![record(60, [192, 0, 2, 1]), record(60, [192, 0, 2, 1])]),
        Err(RecordValidationError::DuplicateRecord)
    ));
}

#[test]
fn rrsig_records_are_partitioned_individually_without_a_common_ttl() {
    let records = vec![rrsig_record(60, 1), rrsig_record(30, 2)];
    let sets = rrsets_from_records(&records).unwrap();

    assert_eq!(sets.len(), 2);
    assert!(sets.iter().all(|set| set.records.len() == 1));
    assert!(validate_zone_records(&records).is_ok());
    assert!(matches!(
        RrSet::try_from_records(records),
        Err(RecordValidationError::MixedRrSet)
    ));
}

#[test]
fn rrsig_partitioning_still_rejects_duplicate_records() {
    assert!(matches!(
        rrsets_from_records(&[rrsig_record(60, 1), rrsig_record(30, 1)]),
        Err(RecordValidationError::DuplicateRecord)
    ));
}

#[test]
fn rrset_rejects_domain_name_rdata_that_differs_only_by_case() {
    let owner = DomainName::from_labels(vec![b"example".to_vec()]).unwrap();
    let first = ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(DomainName::from_labels(vec![b"Ns1".to_vec()]).unwrap()),
    };
    let second = ResourceRecord {
        name: owner,
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(DomainName::from_labels(vec![b"ns1".to_vec()]).unwrap()),
    };
    assert!(matches!(
        RrSet::try_from_records(vec![first, second]),
        Err(RecordValidationError::DuplicateRecord)
    ));
}

#[test]
fn rrset_compares_hinfo_character_strings_case_sensitively() {
    assert!(
        RrSet::try_from_records(vec![
            hinfo_record(b"x86", b"UNIX"),
            hinfo_record(b"X86", b"UNIX"),
        ])
        .is_ok()
    );
    assert!(
        RrSet::try_from_records(vec![
            hinfo_record(b"x86", b"Unix"),
            hinfo_record(b"x86", b"uNIX"),
        ])
        .is_ok()
    );
}

#[test]
fn record_validation_enforces_the_rfc2181_ttl_maximum() {
    assert!(record(MAX_TTL, [192, 0, 2, 1]).validate().is_ok());
    assert_eq!(
        record(MAX_TTL + 1, [192, 0, 2, 1]).validate(),
        Err(RecordValidationError::TtlTooLarge { value: MAX_TTL + 1 })
    );
}

#[test]
fn record_validation_enforces_dnssec_rdata_constraints() {
    for (digest_type, length, expected) in [(1, 19, 20), (2, 31, 32)] {
        let record = dnssec_record(
            RecordType::DS,
            RData::DS(Ds {
                key_tag: 1,
                algorithm: 8,
                digest_type,
                digest: vec![0; length],
            }),
        );
        assert_eq!(
            record.validate(),
            Err(RecordValidationError::InvalidDsDigestLength {
                digest_type,
                length,
                expected,
            })
        );
    }

    let mut rrsig = Rrsig {
        type_covered: 1,
        algorithm: 8,
        labels: 3,
        original_ttl: 60,
        signature_expiration: 2,
        signature_inception: 1,
        key_tag: 1,
        signer_name: DomainName::from_dotted("example").unwrap(),
        signature: vec![1],
    };
    let mut record = dnssec_record(RecordType::RRSIG, RData::RRSIG(rrsig.clone()));
    assert!(matches!(
        record.validate(),
        Err(RecordValidationError::RrsigLabelsTooLarge { .. })
    ));
    rrsig.labels = 2;
    for type_covered in [0, 41, 46, 128, 255, u16::MAX] {
        rrsig.type_covered = type_covered;
        record.rdata = RData::RRSIG(rrsig.clone());
        assert_eq!(
            record.validate(),
            Err(RecordValidationError::InvalidRrsigTypeCovered {
                value: type_covered,
            })
        );
    }
    rrsig.type_covered = 1;
    rrsig.original_ttl = MAX_TTL + 1;
    record.rdata = RData::RRSIG(rrsig);
    assert_eq!(
        record.validate(),
        Err(RecordValidationError::RrsigOriginalTtlTooLarge { value: MAX_TTL + 1 })
    );
}
