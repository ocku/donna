use super::*;

#[test]
fn closest_encloser_rejects_inconsistent_and_replayable_proofs() {
    let mut records = [
        nsec3_record(
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example",
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
            &[2, 6, 46],
        ),
        nsec3_record(
            "b4um86eghhds6nea196smvmlo4ors995.example",
            "gjeqe526plbf1g8mklp59enfd789njgi",
            &[2, 46],
        ),
    ];
    assert_eq!(
        find_nsec3_closest_encloser(
            &records,
            &name("example"),
            crate::ClassType::IN,
            &name("a.c.x.w.example"),
            12,
        ),
        Err(Nsec3ClosestEncloserError::InvalidClosestEncloser)
    );

    if let RData::NSEC3(matching) = &mut records[1].rdata {
        matching.type_bitmap = Some(TypeBitmap::new([6, 39, 46]).unwrap());
    }
    assert_eq!(
        find_nsec3_closest_encloser(
            &records,
            &name("example"),
            crate::ClassType::IN,
            &name("a.c.x.w.example"),
            12,
        ),
        Err(Nsec3ClosestEncloserError::InvalidClosestEncloser)
    );

    if let RData::NSEC3(matching) = &mut records[1].rdata {
        matching.type_bitmap = Some(TypeBitmap::new([6, 46]).unwrap());
        matching.iterations = 11;
    }
    assert_eq!(
        find_nsec3_closest_encloser(
            &records,
            &name("example"),
            crate::ClassType::IN,
            &name("a.c.x.w.example"),
            12,
        ),
        Err(Nsec3ClosestEncloserError::InconsistentParameters)
    );
}

#[test]
fn builds_a_sorted_opt_out_nsec3_chain_with_empty_nonterminals() {
    let zone = name("example");
    let source = vec![
        ResourceRecord {
            name: zone.clone(),
            rtype: crate::RecordType::SOA,
            class: crate::ClassType::IN,
            ttl: 3_600,
            rdata: RData::SOA {
                mname: name("ns.example"),
                rname: name("hostmaster.example"),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 300,
            },
        },
        ResourceRecord {
            name: zone.clone(),
            rtype: crate::RecordType::NS,
            class: crate::ClassType::IN,
            ttl: 3_600,
            rdata: RData::NS(name("ns.example")),
        },
        a_record("deep.a.example", 1),
        ResourceRecord {
            name: name("child.example"),
            rtype: crate::RecordType::NS,
            class: crate::ClassType::IN,
            ttl: 3_600,
            rdata: RData::NS(name("ns.child.example")),
        },
        a_record("ns.child.example", 2),
    ];
    let parameters = Nsec3param {
        hash_algorithm: 1,
        flags: 0,
        iterations: 12,
        salt: vec![0xaa, 0xbb, 0xcc, 0xdd],
    };
    let chain = Nsec3Chain::build(
        &zone,
        crate::ClassType::IN,
        &source,
        parameters,
        300,
        true,
        12,
    )
    .unwrap();

    assert_eq!(chain.parameters.name, zone);
    assert_eq!(chain.records.len(), 3);
    assert!(
        chain
            .records
            .iter()
            .all(|record| { matches!(&record.rdata, RData::NSEC3(nsec3) if nsec3.opt_out()) })
    );
    for (index, record) in chain.records.iter().enumerate() {
        let RData::NSEC3(nsec3) = &record.rdata else {
            unreachable!()
        };
        let next_owner = &chain.records[(index + 1) % chain.records.len()].name;
        assert_eq!(
            nsec3.next_hashed_owner_name,
            nsec3_owner_hash(next_owner, &zone).unwrap()
        );
    }

    let apex = chain
        .records
        .iter()
        .find_map(|record| {
            let RData::NSEC3(nsec3) = &record.rdata else {
                return None;
            };
            nsec3
                .matches_name(&record.name, &zone, &zone, 12)
                .unwrap()
                .then_some(nsec3)
        })
        .unwrap();
    let apex_types = apex.type_bitmap.as_ref().unwrap();
    for rtype in [
        crate::RecordType::NS,
        crate::RecordType::SOA,
        crate::RecordType::RRSIG,
        crate::RecordType::NSEC3PARAM,
    ] {
        assert!(apex_types.contains(u16::from(rtype)));
    }
    assert!(!apex_types.contains(u16::from(crate::RecordType::NSEC3)));

    let empty = chain
        .records
        .iter()
        .find_map(|record| {
            let RData::NSEC3(nsec3) = &record.rdata else {
                return None;
            };
            nsec3
                .matches_name(&record.name, &zone, &name("a.example"), 12)
                .unwrap()
                .then_some(nsec3)
        })
        .unwrap();
    assert!(empty.type_bitmap.is_none());
    assert!(!chain.records.iter().any(|record| {
        let RData::NSEC3(nsec3) = &record.rdata else {
            return false;
        };
        nsec3
            .matches_name(&record.name, &zone, &name("child.example"), 12)
            .unwrap()
    }));

    let proof = find_nsec3_closest_encloser(
        &chain.records,
        &zone,
        crate::ClassType::IN,
        &name("child.example"),
        12,
    )
    .unwrap();
    let RData::NSEC3(covering) = &chain.records[proof.covering_record].rdata else {
        unreachable!()
    };
    assert!(covering.opt_out());

    assert!(matches!(
        Nsec3Chain::build(
            &zone,
            crate::ClassType::IN,
            &source,
            Nsec3param {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: Vec::new(),
            },
            0x8000_0000,
            false,
            0,
        ),
        Err(Nsec3ChainError::InvalidRecord(
            RecordValidationError::TtlTooLarge { value: 0x8000_0000 }
        ))
    ));
}

#[test]
fn verifies_the_rfc5702_rsa_sha2_examples() {
    for input in [
        concat!(
            "example.net. 3600 IN DNSKEY 256 3 8 ( ",
            "AwEAAcFcGsaxxdgiuuGmCkVI my4h99CqT7jwY3pexPGcnUFt ",
            "R2Fh36BponcwtkZ4cAgtvd4Qs8P kxUdp6p/DlUmObdk= )\n",
            "www.example.net. 3600 IN A 192.0.2.91\n",
            "www.example.net. 3600 IN RRSIG A 8 3 3600 ",
            "20300101000000 20000101000000 9033 example.net. ( ",
            "kRCOH6u7l0QGy9qpC9 l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa ",
            "cFYK/lPtPiVYP4bwg== )",
        ),
        concat!(
            "example.net. 3600 IN DNSKEY 256 3 10 ( ",
            "AwEAAdHoNTOW+et86KuJOWRD p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD ",
            "xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g ",
            "pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL )\n",
            "www.example.net. 3600 IN A 192.0.2.91\n",
            "www.example.net. 3600 IN RRSIG A 10 3 3600 ",
            "20300101000000 20000101000000 3740 example.net. ( ",
            "tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa ",
            "eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPl ",
            "vpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw= )",
        ),
    ] {
        let file = crate::master::MasterFile::parse(input, None).unwrap();
        let RData::DNSKEY(dnskey) = &file.records[0].rdata else {
            panic!("example did not parse as DNSKEY")
        };
        let RData::RRSIG(rrsig) = &file.records[2].rdata else {
            panic!("example did not parse as RRSIG")
        };
        let key_name = name("example.net");
        rrsig
            .verify(&file.records[1..2], &key_name, dnskey, 1_577_836_800)
            .unwrap();

        let mut changed = file.records[1].clone();
        changed.rdata = RData::A(Ipv4Addr::new(192, 0, 2, 92));
        assert!(matches!(
            rrsig.verify(&[changed], &key_name, dnskey, 1_577_836_800),
            Err(RrsigVerificationError::BadSignature)
        ));
        assert!(matches!(
            rrsig.verify(&file.records[1..2], &key_name, dnskey, 900_000_000),
            Err(RrsigVerificationError::BadTime)
        ));
    }
}

#[test]
fn verifies_the_rfc6605_p256_example_and_sha384_ds() {
    let file = crate::master::MasterFile::parse(
        concat!(
            "example.net. 3600 IN DNSKEY 257 3 13 ( ",
            "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb ",
            "krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== )\n",
            "www.example.net. 3600 IN A 192.0.2.1\n",
            "www.example.net. 3600 IN RRSIG A 13 3 3600 ",
            "20100909100439 20100812100439 55648 example.net. ( ",
            "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA ",
            "yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== )\n",
            "example.net. 3600 IN DS 55648 13 2 ( ",
            "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1 ",
            "e2770ce6d6e37df61d17 )\n",
        ),
        None,
    )
    .unwrap();
    let RData::DNSKEY(dnskey) = &file.records[0].rdata else {
        panic!("example did not parse as DNSKEY")
    };
    let RData::RRSIG(rrsig) = &file.records[2].rdata else {
        panic!("example did not parse as RRSIG")
    };
    let RData::DS(ds) = &file.records[3].rdata else {
        panic!("example did not parse as DS")
    };
    let key_name = name("example.net");

    rrsig
        .verify(&file.records[1..2], &key_name, dnskey, 1_283_000_000)
        .unwrap();
    assert!(ds.matches_dnskey(&key_name, dnskey).unwrap());
    assert_eq!(dnskey.to_ds(&key_name, 4).unwrap().digest.len(), 48);
}

#[test]
fn p256_signing_round_trips_with_fixed_width_dnssec_signatures() {
    let private = p256::ecdsa::SigningKey::from_slice(&[7_u8; 32]).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let signing_key =
        EcdsaP256DnssecSigningKey::from_pkcs8_der(Dnskey::ZONE_KEY_FLAG, der.as_bytes()).unwrap();
    let zone = name("example");
    let record = a_record("www.example", 7);
    let signature = signing_key
        .sign_rrset(std::slice::from_ref(&record), &zone, 10, 20)
        .unwrap();

    assert_eq!(signature.signature.len(), 64);
    signature
        .verify(
            std::slice::from_ref(&record),
            &zone,
            signing_key.dnskey(),
            15,
        )
        .unwrap();
    let mut changed = record;
    changed.rdata = RData::A(Ipv4Addr::new(192, 0, 2, 8));
    assert!(matches!(
        signature.verify(&[changed], &zone, signing_key.dnskey(), 15),
        Err(RrsigVerificationError::BadSignature)
    ));
}
