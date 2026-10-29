use super::*;

#[test]
fn signed_dname_lowercases_target_for_canonical_input() {
    let record = ResourceRecord {
        name: name("old.example.test"),
        rtype: crate::RecordType::DNAME,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: RData::DNAME(name("MiXeD.Example.Test")),
    };
    let mut signature = rrsig(3);
    signature.type_covered = u16::from(crate::RecordType::DNAME);
    let data = signature.signed_data(&[record]).unwrap();
    assert!(data.ends_with(b"\x05mixed\x07example\x04test\0"));
}

#[test]
fn signed_data_canonicalizes_names_ttl_and_rdata_order() {
    let data = rrsig(3)
        .signed_data(&[
            a_record("WWW.Example.Test", 2),
            a_record("www.example.test", 1),
        ])
        .unwrap();

    let mut expected = vec![
        0, 1, 15, 3, 0, 0, 0x0e, 0x10, 0, 0, 0, 2, 0, 0, 0, 1, 0x12, 0x34,
    ];
    expected.extend_from_slice(b"\x07example\x04test\0");
    for last_octet in [1, 2] {
        expected.extend_from_slice(b"\x03www\x07example\x04test\0");
        expected.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4]);
        expected.extend_from_slice(&[192, 0, 2, last_octet]);
    }
    assert_eq!(data, expected);
    assert!(!data.ends_with(&[0xaa]), "the signature field is excluded");
}

#[test]
fn signed_data_reconstructs_the_original_wildcard_owner() {
    let data = rrsig(2)
        .signed_data(&[a_record("expanded.example.test", 1)])
        .unwrap();
    let header_length = 18 + b"\x07example\x04test\0".len();
    assert_eq!(
        &data[header_length..header_length + b"\x01*\x07example\x04test\0".len()],
        b"\x01*\x07example\x04test\0"
    );
}

#[test]
fn signed_data_applies_the_rfc6840_nsec_case_correction() {
    let record = ResourceRecord {
        name: name("a.example"),
        rtype: crate::RecordType::NSEC,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: RData::NSEC(Nsec {
            next_domain_name: name("MiXeD.Example"),
            type_bitmap: TypeBitmap::new([1, 46, 47]).unwrap(),
        }),
    };
    let signature = Rrsig {
        type_covered: u16::from(crate::RecordType::NSEC),
        labels: 2,
        ..rrsig(2)
    };
    let data = signature.signed_data(&[record]).unwrap();
    assert!(
        data.windows(b"\x05MiXeD\x07Example\0".len())
            .any(|window| window == b"\x05MiXeD\x07Example\0")
    );
    assert!(
        !data
            .windows(b"\x05mixed\x07example\0".len())
            .any(|window| window == b"\x05mixed\x07example\0")
    );
}

#[test]
fn signed_data_rejects_bad_labels_mixed_sets_and_canonical_duplicates() {
    assert!(matches!(
        rrsig(4).signed_data(&[a_record("www.example.test", 1)]),
        Err(RrsigDataError::TooManyLabels { .. })
    ));
    assert!(matches!(
        rrsig(3).signed_data(&[
            a_record("www.example.test", 1),
            a_record("other.example.test", 2),
        ]),
        Err(RrsigDataError::MixedRrset)
    ));

    let cname = |target: &str| ResourceRecord {
        name: name("alias.example.test"),
        rtype: crate::RecordType::CNAME,
        class: crate::ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(name(target)),
    };
    let mut signature = rrsig(3);
    signature.type_covered = u16::from(crate::RecordType::CNAME);
    assert_eq!(
        signature.signed_data(&[cname("Target.Example.Test"), cname("target.example.test"),]),
        Err(RrsigDataError::DuplicateRecord)
    );
}

#[test]
fn canonical_name_order_matches_rfc4034_section_6_1() {
    let mut names = [
        "*.z.example",
        "z.example",
        "zABC.a.EXAMPLE",
        "example",
        "Z.a.example",
        "a.example",
        "yljkjljk.a.example",
    ]
    .map(name);
    names.sort_by(DomainName::canonical_cmp);
    let labels = names
        .iter()
        .map(|name| name.as_ref().first().unwrap().as_slice())
        .collect::<Vec<_>>();
    assert_eq!(
        labels,
        [
            b"example".as_slice(),
            b"a",
            b"yljkjljk",
            b"Z",
            b"zABC",
            b"z",
            b"*",
        ]
    );
}

#[test]
fn constructs_the_rfc4509_sha256_ds_example() {
    let file = crate::master::MasterFile::parse(
        concat!(
            "dskey.example.com. 86400 IN DNSKEY 256 3 5 ( ",
            "AQOeiiR0GOMYkDshWoSKz9Xz fwJr1AYtsmx3TGkJaNXVbfi/ ",
            "2pHm822aJ5iI9BMzNXxeYCmZ DRD99WYwYqUSdjMmmAphXdvx ",
            "egXd/M5+X7OrzKBaMbCVdFLU Uh6DhweJBjEVv5f2wwjM9Xzc ",
            "nOf+EPbtG9DMBmADjFDc2w/r ljwvFw== )",
        ),
        None,
    )
    .unwrap();
    let RData::DNSKEY(dnskey) = &file.records[0].rdata else {
        panic!("example did not parse as DNSKEY")
    };
    let owner = name("dskey.example.com");
    let sha1_ds = dnskey.to_ds(&owner, 1).unwrap();
    assert_eq!(sha1_ds.key_tag, 60_485);
    assert_eq!(
        sha1_ds.digest,
        [
            0x2b, 0xb1, 0x83, 0xaf, 0x5f, 0x22, 0x58, 0x81, 0x79, 0xa5, 0x3b, 0x0a, 0x98, 0x63,
            0x1f, 0xad, 0x1a, 0x29, 0x21, 0x18,
        ]
    );
    let ds = dnskey.to_ds(&owner, 2).unwrap();

    assert_eq!(ds.key_tag, 60_485);
    assert_eq!(ds.algorithm, 5);
    assert_eq!(ds.digest_type, 2);
    assert_eq!(
        ds.digest,
        [
            0xd4, 0xb7, 0xd5, 0x20, 0xe7, 0xbb, 0x5f, 0x0f, 0x67, 0x67, 0x4a, 0x0c, 0xce, 0xb1,
            0xe3, 0xe0, 0x61, 0x4b, 0x93, 0xc4, 0xf9, 0xe9, 0x9b, 0x83, 0x83, 0xf6, 0xa1, 0xe4,
            0x46, 0x9d, 0xa5, 0x0a,
        ]
    );
    assert!(ds.matches_dnskey(&owner, dnskey).unwrap());
    assert!(
        !ds.matches_dnskey(&name("other.example.com"), dnskey)
            .unwrap()
    );
    assert!(matches!(
        dnskey.to_ds(&owner, 255),
        Err(DsDigestError::UnsupportedDigest { digest_type: 255 })
    ));
}

#[test]
fn matches_and_covers_rfc5155_nsec3_names() {
    let zone = name("example");
    let owner = name("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example");
    let nsec3 = Nsec3 {
        hash_algorithm: 1,
        flags: Nsec3::OPT_OUT_FLAG,
        iterations: 12,
        salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
        next_hashed_owner_name: decode_base32hex_label(b"2t7b4g4vsa5smi47k61mv5bv1a22bojr")
            .unwrap(),
        type_bitmap: None,
    };

    assert!(nsec3.matches_name(&owner, &zone, &zone, 12).unwrap());
    assert!(
        !nsec3
            .matches_name(&owner, &zone, &name("a.example"), 12)
            .unwrap()
    );
    assert!(
        nsec3
            .covers_name(&owner, &zone, &name("c.x.w.example"), 12)
            .unwrap()
    );
    assert!(!nsec3.covers_name(&owner, &zone, &zone, 12).unwrap());
    assert!(
        !nsec3
            .covers_name(&owner, &zone, &name("ns1.example"), 12)
            .unwrap()
    );
}

#[test]
fn nsec3_coverage_wraps_and_rejects_malformed_proofs() {
    let zone = name("example");
    let owner = name("t644ebqk9bibcna874givr6joj62mlhv.example");
    let mut nsec3 = Nsec3 {
        hash_algorithm: 1,
        flags: 0,
        iterations: 12,
        salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
        next_hashed_owner_name: decode_base32hex_label(b"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom")
            .unwrap(),
        type_bitmap: None,
    };

    assert!(
        nsec3
            .covers_name(&owner, &zone, &name("wrap9.example"), 12)
            .unwrap()
    );
    assert!(
        !nsec3
            .covers_name(&owner, &zone, &name("a.example"), 12)
            .unwrap()
    );
    assert!(matches!(
        nsec3.matches_name(&name("example"), &zone, &zone, 12),
        Err(Nsec3ProofError::InvalidOwner)
    ));
    assert!(matches!(
        nsec3.matches_name(&name("not-base32!.example"), &zone, &zone, 12),
        Err(Nsec3ProofError::InvalidOwnerHash)
    ));

    nsec3.next_hashed_owner_name.pop();
    assert!(matches!(
        nsec3.covers_name(&owner, &zone, &zone, 12),
        Err(Nsec3ProofError::HashLengthMismatch)
    ));
    assert!(matches!(
        nsec3.hash_name(&zone, 11),
        Err(Nsec3HashError::TooManyIterations { .. })
    ));
}

#[test]
fn nsec_intervals_and_nodata_use_canonical_dnssec_order() {
    let bitmap = TypeBitmap::new([1, 46, 47]).unwrap();
    let ordinary = Nsec {
        next_domain_name: name("d.example"),
        type_bitmap: bitmap.clone(),
    };
    assert!(ordinary.covers_name(&name("a.example"), &name("b.example")));
    assert!(!ordinary.covers_name(&name("a.example"), &name("a.example")));
    assert!(!ordinary.covers_name(&name("a.example"), &name("d.example")));
    assert!(ordinary.proves_nodata(15));
    assert!(!ordinary.proves_nodata(1));

    let wrapping = Nsec {
        next_domain_name: name("b.example"),
        type_bitmap: bitmap,
    };
    assert!(wrapping.covers_name(&name("z.example"), &name("a.example")));
    assert!(wrapping.covers_name(&name("z.example"), &name("zz.example")));
    assert!(!wrapping.covers_name(&name("z.example"), &name("c.example")));

    let cname = Nsec {
        next_domain_name: name("d.example"),
        type_bitmap: TypeBitmap::new([5, 46, 47]).unwrap(),
    };
    assert!(!cname.proves_nodata(15));
}

pub(super) fn nsec3_record(owner: &str, next: &str, types: &[u16]) -> ResourceRecord {
    ResourceRecord {
        name: name(owner),
        rtype: crate::RecordType::NSEC3,
        class: crate::ClassType::IN,
        ttl: 3_600,
        rdata: RData::NSEC3(Nsec3 {
            hash_algorithm: 1,
            flags: Nsec3::OPT_OUT_FLAG,
            iterations: 12,
            salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
            next_hashed_owner_name: decode_base32hex_label(next.as_bytes()).unwrap(),
            type_bitmap: (!types.is_empty())
                .then(|| TypeBitmap::new(types.iter().copied()).unwrap()),
        }),
    }
}

#[test]
fn finds_the_rfc5155_appendix_b_closest_encloser() {
    let records = [
        nsec3_record(
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example",
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
            &[2, 6, 15, 46, 48, 51],
        ),
        nsec3_record(
            "b4um86eghhds6nea196smvmlo4ors995.example",
            "gjeqe526plbf1g8mklp59enfd789njgi",
            &[15, 46],
        ),
    ];
    let proof = find_nsec3_closest_encloser(
        &records,
        &name("example"),
        crate::ClassType::IN,
        &name("a.c.x.w.example"),
        12,
    )
    .unwrap();
    assert_eq!(proof.closest_encloser, name("x.w.example"));
    assert_eq!(proof.matching_record, 1);
    assert_eq!(proof.covering_record, 0);
}
