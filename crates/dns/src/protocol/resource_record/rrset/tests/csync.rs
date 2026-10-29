use super::*;

fn csync_record(flags: u16, codes: impl IntoIterator<Item = u16>) -> ResourceRecord {
    ResourceRecord {
        name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        rtype: RecordType::CSYNC,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CSYNC(Csync {
            soa_serial: 1,
            flags,
            type_bitmap: TypeBitmap::new(codes).unwrap(),
        }),
    }
}

#[test]
fn zone_publication_rejects_reserved_csync_flags_without_weakening_forwarding() {
    let csync = csync_record(0x8000, [1, 2, 28]);
    assert!(csync.validate().is_ok());
    assert!(matches!(
        validate_zone_records(&[csync]),
        Err(RecordValidationError::ReservedCsyncFlags { value: 0x8000 })
    ));
}

#[test]
fn zone_publication_rejects_types_that_csync_must_not_synchronize() {
    for code in [43, 48, 59, 60, 62] {
        assert!(matches!(
            validate_zone_records(&[csync_record(0, [1, code])]),
            Err(RecordValidationError::ForbiddenCsyncType { value }) if value == code
        ));
    }
    assert!(validate_zone_records(&[csync_record(3, [1, 2, 28])]).is_ok());
}

#[test]
fn zone_validation_rejects_multiple_cname_records() {
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
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::CNAME(DomainName::from_labels(vec![b"other".to_vec()]).unwrap()),
        },
    ];
    assert!(matches!(
        validate_zone_records(&records),
        Err(RecordValidationError::MultipleCnameRecords)
    ));
}
