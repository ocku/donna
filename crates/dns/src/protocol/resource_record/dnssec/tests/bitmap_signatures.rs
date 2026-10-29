use crate::{ClassType, FromWire, IntoWire, RecordType};

use super::*;

#[test]
fn ignored_bitmap_bits_remain_in_nsec_and_nsec3_signature_data() {
    // RFC 9824 uses NXNAME (TYPE128) in signed compact denial bitmaps.
    // RFC 4034 section 4.1.2 ignores meta-types semantically, while signature
    // verification and forwarding must preserve every authenticated bit.
    let bitmap = TypeBitmap::from_received_codes([46, 47, 128, 249].into()).unwrap();
    assert_eq!(bitmap.codes(), &[46, 47]);
    assert!(!bitmap.contains(128));
    assert!(!bitmap.contains(249));
    let mut expected_bitmap = vec![0, 32];
    expected_bitmap.extend_from_slice(&[0; 32]);
    expected_bitmap[2 + 5] = 0x03; // RRSIG and NSEC
    expected_bitmap[2 + 16] = 0x80; // NXNAME
    expected_bitmap[2 + 31] = 0x40; // ignored TKEY
    let nsec = RData::NSEC(Nsec {
        next_domain_name: name("next.example.test"),
        type_bitmap: bitmap.clone(),
    });
    let nsec3 = RData::NSEC3(Nsec3 {
        hash_algorithm: 1,
        flags: 0,
        iterations: 0,
        salt: Vec::new(),
        next_hashed_owner_name: vec![0; 20],
        type_bitmap: Some(bitmap),
    });
    for (rtype, rdata) in [(RecordType::NSEC, nsec), (RecordType::NSEC3, nsec3)] {
        let record = ResourceRecord {
            name: name("example.test"),
            rtype,
            class: ClassType::IN,
            ttl: 300,
            rdata,
        };
        let wire = record.into_wire().unwrap();
        assert!(wire.ends_with(&expected_bitmap));
        let decoded = ResourceRecord::from_wire(&wire).unwrap();
        assert_eq!(decoded.into_wire().unwrap(), wire);
        let mut signature = rrsig(2);
        signature.type_covered = u16::from(rtype);
        assert!(
            signature
                .signed_data(&[decoded])
                .unwrap()
                .ends_with(&expected_bitmap)
        );
    }
}

#[test]
fn nsec3_compact_denial_accepts_a_bitmap_containing_only_nxname() {
    // RFC 9824 section 4: compact NSEC3 NXDOMAIN uses only the NXNAME bit.
    let bitmap = TypeBitmap::from_received_codes([128].into()).unwrap();
    assert!(bitmap.codes().is_empty());
    let record = ResourceRecord {
        name: name("00000000000000000000000000000000.example.test"),
        rtype: RecordType::NSEC3,
        class: ClassType::IN,
        ttl: 300,
        rdata: RData::NSEC3(Nsec3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
            next_hashed_owner_name: vec![0; 20],
            type_bitmap: Some(bitmap),
        }),
    };
    let wire = record.into_wire().unwrap();
    assert_eq!(
        ResourceRecord::from_wire(&wire)
            .unwrap()
            .into_wire()
            .unwrap(),
        wire
    );
    let mut signature = rrsig(3);
    signature.type_covered = u16::from(RecordType::NSEC3);
    let mut expected = vec![0, 17];
    expected.extend_from_slice(&[0; 16]);
    expected.push(0x80);
    assert!(
        signature
            .signed_data(&[record])
            .unwrap()
            .ends_with(&expected)
    );
}
