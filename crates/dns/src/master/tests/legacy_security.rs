use super::*;

#[test]
fn omitted_sig_original_ttl_inherits_explicit_default_or_previous_ttl() {
    for (prefix, rr_ttl, expected) in [
        ("", "60 ", 60),
        ("$TTL 120\n", "", 120),
        ("previous.example. IN 180 A 192.0.2.1\n", "", 180),
        ("$TTL 120\n", "60 ", 60),
    ] {
        let input = format!(
            "{prefix}x.example. IN {rr_ttl}SIG A 8 2 20030507235959 20030407235959 1 example. ( AQID BA== )"
        );
        let file = MasterFile::parse(&input, None).unwrap();
        let record = file.records.last().unwrap();
        let RData::SIG(sig) = &record.rdata else {
            panic!("expected SIG")
        };
        assert_eq!(record.ttl, expected);
        assert_eq!(sig.original_ttl, expected);
        assert_eq!(sig.signature_expiration, 1_052_351_999);
        assert_eq!(sig.signature_inception, 1_049_759_999);
        assert_eq!(sig.signature, [1, 2, 3, 4]);
    }
}

#[test]
fn explicit_sig_original_ttl_preserves_existing_ttl_rules() {
    for (rr_ttl, dates, expected) in [
        ("", "20030507235959 20030407235959", 90),
        ("60 ", "20030507235959 20030407235959", 60),
        ("60 ", "1052351999 1049759999", 60),
    ] {
        let file = MasterFile::parse(
            &format!("$TTL 120\nx.example. IN {rr_ttl}SIG A 8 2 90 {dates} 1 example. AQIDBA=="),
            None,
        )
        .unwrap();
        let record = &file.records[0];
        let RData::SIG(sig) = &record.rdata else {
            panic!("expected SIG")
        };
        assert_eq!(record.ttl, expected);
        assert_eq!(sig.original_ttl, 90);
    }
}

#[test]
fn rejects_sig_omission_without_ttl_and_does_not_guess_numeric_omission() {
    for input in [
        "x.example. IN SIG A 8 2 20030507235959 20030407235959 1 example. AQIDBA==",
        "x.example. IN 60 SIG A 8 2 1052351999 1049759999 1 example. AQIDBA==",
        "x.example. IN 60 SIG A 8 2 20230229000000 20030407235959 1 example. AQIDBA==",
        "x.example. IN 60 SIG A 8 2 999999999999 20030507235959 20030407235959 1 example. AQIDBA==",
    ] {
        assert!(MasterFile::parse(input, None).is_err(), "{input}");
    }
}

#[test]
fn parses_key_protocol_and_flag_symbols_and_numeric_equivalents() {
    for (protocol, expected_protocol) in [
        ("NONE", 0),
        ("TLS", 1),
        ("EMAIL", 2),
        ("DNSSEC", 3),
        ("IPSEC", 4),
        ("ALL", 255),
        ("dnssec", 3),
        ("255", 255),
    ] {
        for (flags, expected_flags) in [
            ("NOCONF|ZONE", 0x4100),
            ("16640", 0x4100),
            ("NOAUTH|HOST|SIG15", 0x820f),
            ("USER|SIG0", 0),
            (
                "FLAG2|EXTEND|FLAG4|FLAG5|NTYP3|FLAG8|FLAG9|FLAG10|FLAG11|SIG9",
                0x3ff9,
            ),
            ("noconf|zone", 0x4100),
        ] {
            let input = format!("x.example. IN 60 KEY {flags} {protocol} 8 AQIDBA==");
            let file = MasterFile::parse(&input, None).unwrap();
            let RData::KEY(key) = &file.records[0].rdata else {
                panic!("expected KEY")
            };
            assert_eq!(key.flags, expected_flags);
            assert_eq!(key.protocol, expected_protocol);
            assert_eq!(key.public_key, [1, 2, 3, 4]);
        }
    }
}

#[test]
fn no_key_flags_allow_exactly_three_fields() {
    for flags in ["NOKEY|ZONE", "NOCONF|NOAUTH|ZONE", "49408"] {
        let input = format!("x.example. IN 60 KEY {flags} DNSSEC RSASHA256");
        let file = MasterFile::parse(&input, None).unwrap();
        let RData::KEY(key) = &file.records[0].rdata else {
            panic!("expected KEY")
        };
        assert_eq!(key.flags, 0xc100);
        assert!(key.public_key.is_empty());
        assert!(MasterFile::parse(&format!("{input} AQID"), None).is_err());
    }
    assert!(MasterFile::parse("x.example. IN 60 KEY 0 3 8", None).is_err());
}

#[test]
fn rejects_invalid_key_flags_and_protocols() {
    for fields in [
        "ZONE|HOST 3 8",
        "USER|ZONE 3 8",
        "SIG1|SIG2 3 8",
        "SIG16 3 8",
        "NOCONF|BOGUS 3 8",
        "ZONE| 3 8",
        "65536 3 8",
        "ZONE UNKNOWN 8",
        "ZONE 256 8",
        "ZONE DNSSEC UNKNOWN",
    ] {
        let input = format!("x.example. IN 60 KEY {fields} AQIDBA==");
        assert!(MasterFile::parse(&input, None).is_err(), "{input}");
    }
}
