use super::*;

#[test]
fn parses_rfc4034_dnssec_presentation_formats() {
    let file = MasterFile::parse(
        concat!(
            "child IN 3600 DS 60485 RSASHA1 1 2BB183AF5F22588179A53B0A",
            "98631FAD1A292118\n",
            "example.test. IN 3600 DNSKEY 257 3 RSASHA256 ( AQID BA== )\n",
            "www IN 3600 RRSIG A ED25519 2 3600 20030507235959 ",
            "20030407235959 2642 example.test. ( AQID BA== )\n",
            "www IN 3600 NSEC next A RRSIG NSEC DNSKEY TYPE65000\n",
        ),
        Some(origin()),
    )
    .unwrap();

    let RData::DS(ds) = &file.records[0].rdata else {
        panic!("DS record did not have DS RDATA")
    };
    assert_eq!(ds.key_tag, 60485);
    assert_eq!(ds.algorithm, 5);
    assert_eq!(ds.digest_type, 1);
    assert_eq!(
        ds.digest,
        [
            0x2b, 0xb1, 0x83, 0xaf, 0x5f, 0x22, 0x58, 0x81, 0x79, 0xa5, 0x3b, 0x0a, 0x98, 0x63,
            0x1f, 0xad, 0x1a, 0x29, 0x21, 0x18,
        ]
    );

    let RData::DNSKEY(dnskey) = &file.records[1].rdata else {
        panic!("DNSKEY record did not have DNSKEY RDATA")
    };
    assert_eq!(
        (dnskey.flags, dnskey.protocol, dnskey.algorithm),
        (257, 3, 8)
    );
    assert_eq!(dnskey.public_key, [1, 2, 3, 4]);

    let RData::RRSIG(rrsig) = &file.records[2].rdata else {
        panic!("RRSIG record did not have RRSIG RDATA")
    };
    assert_eq!(rrsig.type_covered, u16::from(RecordType::A));
    assert_eq!(rrsig.algorithm, 15);
    assert_eq!(rrsig.signature_expiration, 1_052_351_999);
    assert_eq!(rrsig.signature_inception, 1_049_759_999);
    assert_eq!(rrsig.signature, [1, 2, 3, 4]);
    assert_eq!(rrsig.signer_name.as_ref(), origin().as_ref());

    let RData::NSEC(nsec) = &file.records[3].rdata else {
        panic!("NSEC record did not have NSEC RDATA")
    };
    assert_eq!(nsec.next_domain_name.as_ref()[0], b"next");
    assert_eq!(nsec.type_bitmap.codes(), &[1, 46, 47, 48, 65_000]);
}

#[test]
fn rejects_malformed_rfc4034_presentation_fields() {
    for input in [
        "@ IN 60 DS 1 8 2 ABC",
        "@ IN 60 DS 65536 8 2 AABB",
        "@ IN 60 DNSKEY 257 3 UNKNOWN AQID",
        "@ IN 60 RRSIG A 8 2 60 20230229000000 20230101000000 1 @ AQID",
        "@ IN 60 RRSIG A 8 2 60 21060208000000 20230101000000 1 @ AQID",
        "@ IN 60 NSEC next OPT",
        "@ IN 60 NSEC next",
    ] {
        assert!(MasterFile::parse(input, Some(origin())).is_err(), "{input}");
    }
}

#[test]
fn parses_rfc5155_nsec3_and_nsec3param_presentation() {
    let file = MasterFile::parse(
        concat!(
            "example. 3600 IN NSEC3PARAM 1 0 12 aabbccdd\n",
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. 3600 IN NSEC3 ",
            "1 1 12 aabbccdd ( 2t7b4g4vsa5smi47k61mv5bv1a22bojr ",
            "MX DNSKEY NS SOA NSEC3PARAM RRSIG )\n",
            "empty.example. 3600 IN NSEC3 1 0 0 - 00000000000000000000000000000000",
        ),
        None,
    )
    .unwrap();

    let RData::NSEC3PARAM(parameters) = &file.records[0].rdata else {
        panic!("record did not parse as NSEC3PARAM")
    };
    assert_eq!(parameters.hash_algorithm, 1);
    assert_eq!(parameters.flags, 0);
    assert_eq!(parameters.iterations, 12);
    assert_eq!(parameters.salt, [0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(
        parameters
            .hash_name_label(&DomainName::from_dotted("example").unwrap(), 12)
            .unwrap(),
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
    );

    let RData::NSEC3(nsec3) = &file.records[1].rdata else {
        panic!("record did not parse as NSEC3")
    };
    assert!(nsec3.opt_out());
    assert_eq!(nsec3.next_hashed_owner_name.len(), 20);
    assert_eq!(
        nsec3.type_bitmap.as_ref().unwrap().codes(),
        &[2, 6, 15, 46, 48, 51]
    );
    assert!(matches!(
        &file.records[2].rdata,
        RData::NSEC3(dnssec) if dnssec.salt.is_empty() && dnssec.type_bitmap.is_none()
    ));
}

#[test]
fn rejects_malformed_rfc5155_presentation() {
    for input in [
        "@ IN 60 NSEC3 1 0 0 - ZZZZ A",
        "@ IN 60 NSEC3 1 0 0 - 0 A",
        "@ IN 60 NSEC3 1 0 0 xyz 00000000000000000000000000000000 A",
        "@ IN 60 NSEC3PARAM 1 0 0",
        "@ IN 60 NSEC3PARAM 1 0 65536 -",
    ] {
        assert!(MasterFile::parse(input, Some(origin())).is_err(), "{input}");
    }
}

#[test]
fn parses_sig_calendar_dates_and_preserves_numeric_time_support() {
    for (expiration, inception) in [
        ("20030507235959", "20030407235959"),
        ("1052351999", "1049759999"),
    ] {
        let input =
            format!("sig.example. IN 60 SIG A 8 2 60 {expiration} {inception} 1 example. AQIDBA==");
        let file = MasterFile::parse(&input, None).unwrap();
        let RData::SIG(sig) = &file.records[0].rdata else {
            panic!("expected SIG")
        };
        assert_eq!(sig.algorithm, 8);
        assert_eq!(sig.signature_expiration, 1_052_351_999);
        assert_eq!(sig.signature_inception, 1_049_759_999);
        assert_eq!(sig.signature, [1, 2, 3, 4]);
    }
}

#[test]
fn parses_sig_and_key_algorithm_symbols() {
    // RFC 2535 section 7 permits symbolic algorithms in both record types.
    for (symbol, code) in [
        ("RSAMD5", 1),
        ("DH", 2),
        ("DSA", 3),
        ("ECC", 4),
        ("INDIRECT", 252),
        ("PRIVATEDNS", 253),
        ("PRIVATEOID", 254),
        ("ed25519", 15),
        ("253", 253),
    ] {
        let input = format!(
            "sig.example. IN 60 SIG A {symbol} 2 60 20030507235959 20030407235959 1 example. AQIDBA==\nkey.example. IN 60 KEY 0 3 {symbol} AQIDBA=="
        );
        let file = MasterFile::parse(&input, None).unwrap();
        let RData::SIG(sig) = &file.records[0].rdata else {
            panic!("expected SIG")
        };
        let RData::KEY(key) = &file.records[1].rdata else {
            panic!("expected KEY")
        };
        assert_eq!(sig.algorithm, code);
        assert_eq!(key.algorithm, code);
        assert_eq!(key.public_key, [1, 2, 3, 4]);
    }
}

#[test]
fn rejects_invalid_sig_dates_and_unknown_sig_key_algorithms() {
    for input in [
        "sig.example. IN 60 SIG A 8 2 60 20230229000000 20030407235959 1 example. AQID",
        "sig.example. IN 60 SIG A 8 2 60 20030507235959 20031307235959 1 example. AQID",
        "sig.example. IN 60 SIG A UNKNOWN 2 60 100 50 1 example. AQID",
        "key.example. IN 60 KEY 0 3 UNKNOWN AQID",
        "key.example. IN 60 KEY 0 3 256 AQID",
    ] {
        assert!(MasterFile::parse(input, None).is_err(), "{input}");
    }
}
