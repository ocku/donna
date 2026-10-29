use super::*;

fn csync_wire(flags: u16, bitmap: &[u8]) -> Vec<u8> {
    let mut wire = vec![
        0, // root owner
        0, 62, // TYPE CSYNC
        0, 1, // CLASS IN
        0, 0, 0, 0, // TTL
    ];
    wire.extend_from_slice(&(6_u16 + u16::try_from(bitmap.len()).unwrap()).to_be_bytes());
    wire.extend_from_slice(&66_u32.to_be_bytes());
    wire.extend_from_slice(&flags.to_be_bytes());
    wire.extend_from_slice(bitmap);
    wire
}

#[test]
fn csync_uses_the_rfc7477_example_wire_format() {
    let record = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::CSYNC,
        class: ClassType::IN,
        ttl: 3_600,
        rdata: RData::CSYNC(Csync {
            soa_serial: 66,
            flags: Csync::IMMEDIATE_FLAG | Csync::SOA_MINIMUM_FLAG,
            type_bitmap: TypeBitmap::new([1, 2, 28]).unwrap(),
        }),
    };

    let wire = record.into_wire().unwrap();
    assert_eq!(&wire[11..], &[0, 0, 0, 0x42, 0, 3, 0, 4, 0x60, 0, 0, 8]);
    assert_eq!(
        ResourceRecord::from_wire(&wire).unwrap().rdata,
        record.rdata
    );
}

#[test]
fn csync_encodes_type_bitmap_windows_canonically() {
    let record = ResourceRecord {
        name: DomainName::root(),
        rtype: RecordType::CSYNC,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::CSYNC(Csync {
            soa_serial: 0,
            flags: 0,
            type_bitmap: TypeBitmap::new([257, 1, 257]).unwrap(),
        }),
    };

    let wire = record.into_wire().unwrap();
    assert_eq!(&wire[17..], &[0, 1, 0x40, 1, 1, 0x40]);
    let RData::CSYNC(decoded) = ResourceRecord::from_wire(&wire).unwrap().rdata else {
        panic!("CSYNC RDATA was not decoded structurally")
    };
    assert_eq!(decoded.type_bitmap.codes(), &[1, 257]);
}

#[test]
fn csync_receiver_preserves_unknown_flags() {
    let wire = csync_wire(0x8001, &[0, 1, 0x40]);
    let record = ResourceRecord::from_wire(&wire).unwrap();
    let RData::CSYNC(csync) = &record.rdata else {
        panic!("CSYNC RDATA was not decoded structurally")
    };
    assert_eq!(csync.unknown_flags(), 0x8000);
    assert_eq!(record.into_wire().unwrap(), wire);
}

#[test]
fn csync_ignores_pseudo_type_bits_on_receive() {
    let mut bitmap = vec![0, 32];
    bitmap.extend_from_slice(&[0; 32]);
    bitmap[2] = 0x40; // TYPE A
    bitmap[2 + 31] = 0x40; // query-only TYPE 249

    let RData::CSYNC(csync) = ResourceRecord::from_wire(&csync_wire(0, &bitmap))
        .unwrap()
        .rdata
    else {
        panic!("CSYNC RDATA was not decoded structurally")
    };
    assert_eq!(csync.type_bitmap.codes(), &[1]);
    assert!(!csync.type_bitmap.contains(249));
    let wire = csync_wire(0, &bitmap);
    assert_eq!(
        ResourceRecord::from_wire(&wire)
            .unwrap()
            .into_wire()
            .unwrap(),
        wire
    );
}

#[test]
fn csync_rejects_noncanonical_or_malformed_type_bitmaps() {
    let mut pseudo_only = vec![0, 32];
    pseudo_only.extend_from_slice(&[0; 32]);
    pseudo_only[33] = 0x40; // query-only TYPE 249
    let malformed = vec![
        vec![],                       // missing required bitmap
        vec![0, 0],                   // zero-length window
        vec![0, 33],                  // overlong window
        vec![0, 1, 0x80],             // reserved TYPE zero
        vec![0, 2, 0x40, 0],          // trailing zero octet
        vec![1, 1, 0x40, 0, 1, 0x40], // descending windows
        vec![0, 1, 0x40, 0, 1, 0x20], // duplicate windows
        vec![0, 2, 0x40],             // truncated bitmap
    ];
    let wire = csync_wire(0, &pseudo_only);
    let record = ResourceRecord::from_wire(&wire).unwrap();
    let RData::CSYNC(csync) = &record.rdata else {
        unreachable!()
    };
    assert!(csync.type_bitmap.codes().is_empty());
    assert_eq!(record.into_wire().unwrap(), wire);
    for bitmap in malformed {
        assert!(
            ResourceRecord::from_wire(&csync_wire(0, &bitmap)).is_err(),
            "accepted malformed bitmap {bitmap:?}"
        );
    }
}

#[test]
fn tsig_rdata_round_trips_48_bit_time_lengths_and_error_data() {
    let server_time = 0x0102_0304_0506_u64;
    let record = ResourceRecord {
        name: DomainName::from_labels(vec![b"key".to_vec()]).unwrap(),
        rtype: RecordType::TSIG,
        class: ClassType::Unknown(255),
        ttl: 0,
        rdata: RData::TSIG(Tsig {
            algorithm: TsigAlgorithm::HmacSha256.name(),
            time_signed: 0x0001_0203_0405,
            fudge: 300,
            mac: vec![0xaa, 0xbb, 0xcc],
            original_id: 0x1234,
            error: TsigErrorCode::BadTime,
            other_data: server_time.to_be_bytes()[2..].to_vec(),
        }),
    };

    let wire = record.into_wire().unwrap();
    let decoded = ResourceRecord::from_wire(&wire).unwrap();
    assert_eq!(decoded.rdata, record.rdata);
    let RData::TSIG(tsig) = decoded.rdata else {
        panic!("TSIG RDATA was not decoded structurally")
    };
    assert_eq!(tsig.bad_time_server_time(), Some(server_time));
}

#[test]
fn tsig_rejects_a_compressed_algorithm_name() {
    let wire = [
        0, // root owner
        0, 250, // TYPE TSIG
        0, 255, // CLASS ANY
        0, 0, 0, 0, // TTL
        0, 18, // RDLENGTH
        0xc0, 0x00, // compressed algorithm name
        0, 0, 0, 0, 0, 1, // time
        0, 1, // fudge
        0, 0, // MAC size
        0, 1, // original ID
        0, 17, // BADKEY
        0, 0, // Other Len
    ];
    assert!(matches!(
        ResourceRecord::from_wire(&wire),
        Err(WireError::InvalidRData {
            record_type: "TSIG",
            detail: "algorithm name must not use compression",
        })
    ));
}

#[test]
fn tlsa_and_smimea_round_trip_the_shared_wire_format() {
    for (rtype, rdata) in [
        (
            RecordType::TLSA,
            RData::TLSA(CertificateAssociation {
                certificate_usage: 3,
                selector: 1,
                matching_type: 1,
                association_data: vec![0xaa; 32],
            }),
        ),
        (
            RecordType::SMIMEA,
            RData::SMIMEA(CertificateAssociation {
                certificate_usage: 1,
                selector: 0,
                matching_type: 2,
                association_data: vec![0xbb; 64],
            }),
        ),
    ] {
        let record = ResourceRecord {
            name: DomainName::root(),
            rtype,
            class: ClassType::IN,
            ttl: 60,
            rdata,
        };
        let wire = record.clone().into_wire().unwrap();
        assert!(record.eq_dns(&ResourceRecord::from_wire(&wire).unwrap()));
    }
}
