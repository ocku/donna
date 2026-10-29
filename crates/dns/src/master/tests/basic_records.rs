use super::*;

#[test]
fn resolves_defaults_relative_names_escapes_and_multiline_soa() {
    let file = MasterFile::parse(
        concat!(
            "@ IN 3600 SOA ns hostmaster ( 1 2 3 4 5 )\n",
            "  IN NS ns\n",
            "www A 192.0.2.1\n",
            "txt TXT \"hello world\" foo\\032bar\n",
        ),
        Some(origin()),
    )
    .unwrap();
    assert_eq!(file.records.len(), 4);
    assert_eq!(file.records[1].name.as_ref(), origin().as_ref());
    assert_eq!(file.records[2].name.as_ref()[0], b"www");
    assert!(matches!(
        &file.records[3].rdata,
        RData::TXT(text)
            if text == &vec![b"hello world".to_vec(), b"foo bar".to_vec()]
    ));
}

/// RFC 1035 §5.1: "( ) Parentheses are used to group data that crosses a
/// line boundary. In effect, line terminations are not recognized within
/// parentheses." The group may wrap any contiguous run of RR fields.
#[test]
fn parses_parenthesized_groups_around_any_rr_fields() {
    let origin = origin();

    // Head fields and RDATA together inside one group.
    let file = MasterFile::parse("www ( IN 3600 A 192.0.2.1 )\n", Some(origin.clone())).unwrap();
    assert_eq!(file.records[0].ttl, 3600);
    assert!(matches!(
        &file.records[0].rdata,
        RData::A(address) if *address == Ipv4Addr::new(192, 0, 2, 1)
    ));

    // A group spanning line boundaries around the head fields and RDATA.
    let file = MasterFile::parse(
        "www (\n    IN  3600  A\n    192.0.2.1\n)\n",
        Some(origin.clone()),
    )
    .unwrap();
    assert!(matches!(
        &file.records[0].rdata,
        RData::A(address) if *address == Ipv4Addr::new(192, 0, 2, 1)
    ));

    // Head fields before the group, with the rest inside it.
    let file = MasterFile::parse("www IN ( 3600 A 192.0.2.1 )\n", Some(origin.clone())).unwrap();
    assert_eq!(file.records[0].ttl, 3600);
    assert!(matches!(
        &file.records[0].rdata,
        RData::A(address) if *address == Ipv4Addr::new(192, 0, 2, 1)
    ));

    // Head fields inside the group with the RDATA following it.
    let file = MasterFile::parse(
        "www (\n    IN 3600  MX\n) 10 mail.example.\n",
        Some(origin.clone()),
    )
    .unwrap();
    assert!(matches!(
        &file.records[0].rdata,
        RData::MX { preference: 10, .. }
    ));

    // RDATA tokens that resemble head fields stay RDATA after the TYPE.
    let file = MasterFile::parse("txt ( 3600 IN TXT 600 IN )\n", Some(origin)).unwrap();
    assert_eq!(file.records[0].ttl, 3600);
    assert!(matches!(
        &file.records[0].rdata,
        RData::TXT(text) if text == &vec![b"600".to_vec(), b"IN".to_vec()]
    ));
}

#[test]
fn rejects_groups_without_an_rr_type_or_with_data_before_the_type() {
    assert!(MasterFile::parse("www ( 192.0.2.1 )\n", Some(origin())).is_err());
    assert!(MasterFile::parse("www ( 192.0.2.1 IN A )\n", Some(origin())).is_err());
}

#[test]
fn parses_the_rfc1035_example_with_an_rfc2308_ttl_default() {
    let isi_edu = DomainName::from_labels(vec![b"ISI".to_vec(), b"EDU".to_vec()]).unwrap();
    let input = r#"$TTL 60
@   IN  SOA     VENERA      Action\.domains (
                                 20     ; SERIAL
                                 7200   ; REFRESH
                                 600    ; RETRY
                                 3600000; EXPIRE
                                 60)    ; MINIMUM
        NS      A.ISI.EDU.
        NS      VENERA
        NS      VAXA
        MX      10      VENERA
        MX      20      VAXA
A       A       26.3.0.103
VENERA  A       10.1.0.52
        A       128.9.0.32
VAXA    A       10.2.0.27
        A       128.9.0.33
"#;

    let file = MasterFile::parse(input, Some(isi_edu)).unwrap();

    assert_eq!(file.records.len(), 11);
    assert!(file.records.iter().all(|record| record.ttl == 60));
    assert!(
        file.records
            .iter()
            .all(|record| record.class == ClassType::IN)
    );
    assert!(matches!(
        file.records[0].rdata,
        RData::SOA { minimum: 60, .. }
    ));
}

#[test]
fn accepts_mixed_case_origin_directive() {
    let file = MasterFile::parse(
        "$oRiGiN child\n@ IN 1 SOA ns hostmaster 1 2 3 4 5",
        Some(origin()),
    )
    .unwrap();

    assert_eq!(
        file.records[0].name.as_ref(),
        &[b"child".to_vec(), b"example".to_vec(), b"test".to_vec(),]
    );
}

#[test]
fn accepts_plain_records_in_both_ttl_and_class_orders() {
    // RFC 1035 §5.1 allows [<TTL>] [<class>] and [<class>] [<TTL>] before
    // the type in a non-grouped entry.
    let file = MasterFile::parse(
        "ttl-first 3600 IN A 192.0.2.1\nclass-first IN 3600 A 192.0.2.2",
        Some(origin()),
    )
    .unwrap();

    assert_eq!(file.records[0].ttl, 3600);
    assert_eq!(file.records[0].class, ClassType::IN);
    assert_eq!(file.records[0].rdata, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(file.records[1].ttl, 3600);
    assert_eq!(file.records[1].class, ClassType::IN);
    assert_eq!(file.records[1].rdata, RData::A(Ipv4Addr::new(192, 0, 2, 2)));
}

#[test]
fn rejects_null_records_in_master_files() {
    for input in ["@ IN 1 NULL opaque", "@ IN 1 null \\000\\255"] {
        let error = MasterFile::parse(input, Some(origin())).unwrap_err();
        assert_eq!(
            error.to_string(),
            "NULL records are not allowed in master files"
        );
    }
}

#[test]
fn parses_aaaa_mnemonic_and_canonical_type28() {
    let file = MasterFile::parse(
        "host IN 60 AAAA 2001:db8::1\nnumeric IN 60 TYPE28 2001:db8:0:1::5",
        Some(origin()),
    )
    .unwrap();

    assert_eq!(file.records[0].rtype, RecordType::AAAA);
    assert_eq!(
        file.records[0].rdata,
        RData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!(file.records[1].rtype, RecordType::AAAA);
    assert_eq!(
        file.records[1].rdata,
        RData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 5))
    );

    for input in [
        "host IN 60 AAAA 192.0.2.1",
        "host IN 60 AAAA 2001:db8::1 extra",
    ] {
        assert!(MasterFile::parse(input, Some(origin())).is_err(), "{input}");
    }
}

#[test]
fn parses_srv_mnemonic_and_canonical_type33() {
    let file = MasterFile::parse(
        "_ldap._tcp IN 60 SRV 10 25 389 ldap\nnumeric IN 60 TYPE33 20 0 8443 host.example.",
        Some(origin()),
    )
    .unwrap();

    assert!(matches!(
        &file.records[0],
        ResourceRecord {
            rtype: RecordType::SRV,
            rdata: RData::SRV {
                priority: 10,
                weight: 25,
                port: 389,
                target,
            },
            ..
        } if target.as_ref()[0] == b"ldap"
    ));
    assert!(matches!(
        &file.records[1].rdata,
        RData::SRV {
            priority: 20,
            weight: 0,
            port: 8443,
            target,
        } if target.as_ref() == [b"host".to_vec(), b"example".to_vec()]
    ));

    for input in [
        "_ldap._tcp IN 60 SRV 10 20 389",
        "_ldap._tcp IN 60 SRV 65536 20 389 host",
        "_ldap._tcp IN 60 SRV 10 -1 389 host",
        "_ldap._tcp IN 60 SRV 10 20 70000 host",
        "_ldap._tcp IN 60 SRV 10 20 389 host extra",
    ] {
        assert!(MasterFile::parse(input, Some(origin())).is_err(), "{input}");
    }
}

#[test]
fn srv_uses_generic_rdata_outside_the_internet_class() {
    let file = MasterFile::parse("service CH 60 SRV \\# 7 00010002000300", Some(origin())).unwrap();

    assert_eq!(file.records[0].rtype, RecordType::SRV);
    assert_eq!(
        file.records[0].rdata,
        RData::Unknown(vec![0, 1, 0, 2, 0, 3, 0])
    );
    assert!(file.records[0].validate().is_ok());
}

#[test]
fn parses_rfc3597_unknown_records_and_generic_codes() {
    let file = MasterFile::parse(
        concat!(
            "opaque CLASS42 60 TyPe65000 \\# 6 abcd ( ef 01 23 45 )\n",
            "empty HS 60 TYPE62347 \\# 0\n",
            "known CLASS1 60 TYPE1 192.0.2.1",
        ),
        Some(origin()),
    )
    .unwrap();

    assert_eq!(file.records[0].class, ClassType::Unknown(42));
    assert_eq!(file.records[0].rtype, RecordType::Unknown(65000));
    assert_eq!(
        file.records[0].rdata,
        RData::Unknown(vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45])
    );
    assert_eq!(file.records[1].class, ClassType::HS);
    assert_eq!(file.records[1].rtype, RecordType::Unknown(62347));
    assert_eq!(file.records[1].rdata, RData::Unknown(Vec::new()));
    assert_eq!(file.records[2].class, ClassType::IN);
    assert_eq!(file.records[2].rtype, RecordType::A);
    assert_eq!(file.records[2].rdata, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
}

#[test]
fn treats_class_2_as_unassigned_per_rfc6895() {
    let file = MasterFile::parse("future CLASS2 60 TYPE65000 \\# 0", Some(origin())).unwrap();

    assert_eq!(file.records[0].class, ClassType::Unknown(2));
    assert!(file.records[0].validate().is_ok());
    assert!(MasterFile::parse("obsolete CS 60 TYPE65000 \\# 0", Some(origin())).is_err());
}

#[test]
fn class_specific_types_use_generic_rdata_outside_in() {
    let file = MasterFile::parse(
        concat!(
            "a CH 60 A \\# 4 c0000201\n",
            "wks HS 60 WKS \\# 5 c000020106\n",
            "aaaa CH 60 AAAA \\# 16 20010db8000000000000000000000001",
        ),
        Some(origin()),
    )
    .unwrap();

    assert!(
        file.records.iter().all(|record| {
            matches!(record.rdata, RData::Unknown(_)) && record.validate().is_ok()
        })
    );
    for input in [
        "a CH 60 A 192.0.2.1",
        "wks HS 60 WKS 192.0.2.1 TCP",
        "aaaa CH 60 AAAA 2001:db8::1",
    ] {
        assert!(MasterFile::parse(input, Some(origin())).is_err(), "{input}");
    }
}

#[test]
fn rejects_malformed_rfc3597_unknown_records() {
    for input in [
        "x IN 60 TYPE65000 opaque",
        "x IN 60 TYPE65000 \\# 2 AA",
        "x IN 60 TYPE65000 \\# 1 A",
        "x IN 60 TYPE65000 \\# 1 GG",
        "x IN 60 TYPE65000 \\# 0 00",
        "x IN 60 TYPE65536 \\# 0",
        "x IN 60 TYPE251 \\# 0",
    ] {
        assert!(MasterFile::parse(input, Some(origin())).is_err(), "{input}");
    }
}

#[test]
fn treats_only_a_standalone_at_sign_as_the_current_origin() {
    let file = MasterFile::parse(
        "@ IN 1 A 192.0.2.1\n@host IN 1 A 192.0.2.2\n@foo.example. IN 1 A 192.0.2.3",
        Some(origin()),
    )
    .unwrap();

    assert_eq!(file.records[0].name, origin());
    assert_eq!(file.records[1].name.as_ref()[0], b"@host");
    assert_eq!(
        file.records[2].name.as_ref(),
        &[b"@foo".to_vec(), b"example".to_vec()]
    );
}

#[test]
fn parses_full_width_unsigned_soa_intervals_and_rejects_negative_values() {
    let file = MasterFile::parse(
        "@ IN 1 SOA ns hostmaster 1 2147483648 4294967295 2147483647 5",
        Some(origin()),
    )
    .unwrap();
    assert!(matches!(
        file.records[0].rdata,
        RData::SOA {
            refresh: 2_147_483_648,
            retry: u32::MAX,
            expire: 2_147_483_647,
            ..
        }
    ));
    assert!(MasterFile::parse("@ IN 1 SOA ns hostmaster 1 -1 2 3 4", Some(origin()),).is_err());
}

#[test]
fn rejects_obsolete_mail_routing_records_in_master_files() {
    for rtype in ["MD", "MF", "TYPE3", "TYPE4"] {
        let error = MasterFile::parse(
            &format!("mail IN 60 {rtype} target.example."),
            Some(origin()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("obsolete"));
    }
}

#[test]
fn parses_quoted_domain_name_labels() {
    let file = MasterFile::parse("\"a.b\".example. IN 1 A 192.0.2.1\n", Some(origin())).unwrap();

    assert_eq!(
        file.records[0].name.as_ref(),
        &[b"a.b".to_vec(), b"example".to_vec()]
    );
}
