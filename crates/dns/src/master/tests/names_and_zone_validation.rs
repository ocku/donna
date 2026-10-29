use super::*;

/// RFC 1035 §5.1: "Domain names that end in a dot are called absolute";
/// the root owner is the absolute name ".".
#[test]
fn parses_the_root_name_as_an_absolute_owner_and_rdata_target() {
    let file = MasterFile::parse(". IN 1 NS a.root-servers.net.", Some(origin())).unwrap();

    assert_eq!(file.records[0].name, DomainName::root());
    assert!(matches!(
        &file.records[0].rdata,
        RData::NS(name)
            if name.as_ref()
                == [
                    b"a".to_vec(),
                    b"root-servers".to_vec(),
                    b"net".to_vec(),
                ]
    ));
}

/// RFC 1035 §5.1: "A free standing @ is used to denote the current
/// origin", including in RDATA position.
#[test]
fn resolves_at_sign_to_the_origin_in_rdata() {
    let file = MasterFile::parse("x IN 1 MX 10 @", Some(origin())).unwrap();

    assert!(matches!(
        &file.records[0].rdata,
        RData::MX { exchange, .. } if exchange == &origin()
    ));
}

#[test]
fn domain_names_require_escapes_for_raw_unusual_octets() {
    for raw_name in ["\u{1f}.example.", "\u{7f}.example.", "é.example."] {
        let input = format!("{raw_name} IN 1 A 192.0.2.1");
        assert!(MasterFile::parse(&input, Some(origin())).is_err());
    }

    let file = MasterFile::parse(
        "\\031.\\127.\\195\\169.example. IN 1 TXT \"é and \\000 remain RDATA\"",
        Some(origin()),
    )
    .unwrap();
    assert_eq!(file.records[0].name.as_ref()[0], &[31]);
    assert_eq!(file.records[0].name.as_ref()[1], &[127]);
    assert_eq!(file.records[0].name.as_ref()[2], &[195, 169]);
    assert!(matches!(
        &file.records[0].rdata,
        RData::TXT(strings) if strings == &vec!["é and \0 remain RDATA".as_bytes().to_vec()]
    ));
}

#[test]
fn quoted_domain_labels_accept_delimiters_and_embedded_crlf() {
    let file = MasterFile::parse(
        concat!(
            "\"a b;c(d)\".example. IN 1 A 192.0.2.1\n",
            "\"line1\r\nline2\".example. IN 1 A 192.0.2.2\n",
            "\\032.example. IN 1 A 192.0.2.3",
        ),
        Some(origin()),
    )
    .unwrap();

    assert_eq!(file.records[0].name.as_ref()[0], b"a b;c(d)");
    assert_eq!(file.records[1].name.as_ref()[0], b"line1\r\nline2");
    assert_eq!(file.records[2].name.as_ref()[0], b" ");
}

/// RFC 1035 §3.1: labels are 0 to 63 octets; the master file enforces this
/// on decoded presentation labels.
#[test]
fn rejects_a_label_longer_than_63_octets() {
    assert!(
        MasterFile::parse(
            &format!("{} IN 1 A 192.0.2.1", "a".repeat(64)),
            Some(origin())
        )
        .is_err()
    );
}

#[test]
fn strict_zone_validation_rejects_rfc6895_meta_types() {
    // RFC 6891 strengthens OPT's prohibition: it must not be stored in or
    // loaded from a master file, so reject it during parsing.
    assert!(MasterFile::parse("meta IN 60 TYPE41 \\# 0", Some(origin())).is_err());

    // TSIG is also transaction-only. Now that TYPE250 has structured RDATA,
    // reject both its generic and mnemonic forms at the master-file boundary.
    assert!(MasterFile::parse("meta IN 60 TYPE250 \\# 0", Some(origin())).is_err());
    assert!(MasterFile::parse("meta IN 60 TSIG anything", Some(origin())).is_err());

    let file = MasterFile::parse("meta IN 60 TYPE249 \\# 0", Some(origin())).unwrap();
    assert!(file.records[0].validate().is_ok());
    assert_eq!(
        file.validate_strict(),
        Err(RecordValidationError::MetaTypeInZone { value: 249 })
    );
}

#[test]
fn strict_validation_rejects_invalid_zone_record_sets() {
    let file = MasterFile::parse(
        "alias IN 60 CNAME target\nalias IN 60 A 192.0.2.1",
        Some(origin()),
    )
    .unwrap();
    assert!(matches!(
        file.validate_strict(),
        Err(RecordValidationError::CnameWithOtherData)
    ));
}

#[test]
fn parses_rfc6844_caa_examples_and_canonicalizes_tags() {
    let file = MasterFile::parse(
        concat!(
            "$ORIGIN example.com.\n",
            "$TTL 3600\n",
            ". IN CAA 0 IsSuE \"ca.example.net; account=230123\"\n",
            ". CAA 0 issuewild \"wild.example.net\"\n",
            ". CAA 0 iodef \"mailto:security@example.com\"\n",
            ". CAA 128 tbs \"Unknown\"\n",
        ),
        None,
    )
    .unwrap();

    let values = file
        .records
        .iter()
        .map(|record| {
            assert_eq!(record.rtype, RecordType::CAA);
            let RData::CAA(caa) = &record.rdata else {
                panic!("CAA record did not have CAA RDATA")
            };
            (caa.flags, caa.tag.clone(), caa.value.clone())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        values[0],
        (
            0,
            b"issue".to_vec(),
            b"ca.example.net; account=230123".to_vec()
        )
    );
    assert_eq!(
        values[1],
        (0, b"issuewild".to_vec(), b"wild.example.net".to_vec())
    );
    assert_eq!(
        values[2],
        (
            0,
            b"iodef".to_vec(),
            b"mailto:security@example.com".to_vec()
        )
    );
    assert_eq!(values[3], (128, b"tbs".to_vec(), b"Unknown".to_vec()));
    assert!(file.validate_strict().is_ok());
}

#[test]
fn caa_master_format_enforces_canonical_fields_and_allows_long_values() {
    let long_tag = "abcdefghijklmnop"; // RFC 6844 says 15 is only a SHOULD.
    let file =
        MasterFile::parse(&format!("x IN 60 CAA 0 {long_tag} value"), Some(origin())).unwrap();
    assert!(matches!(
        &file.records[0].rdata,
        RData::CAA(caa) if caa.tag == long_tag.as_bytes()
    ));

    for input in [
        "x IN 60 CAA 1 issue value",
        "x IN 60 CAA 256 issue value",
        "x IN 60 CAA 0 \"\" value",
        "x IN 60 CAA 0 iss-ue value",
        "x IN 60 CAA 0 issue",
        "x IN 60 CAA 0 issue value extra",
    ] {
        assert!(MasterFile::parse(input, Some(origin())).is_err(), "{input}");
    }

    // RFC 6844 erratum 4062 clarifies that the value uses presentation
    // quoting and escaping but does not inherit <character-string>'s
    // 255-octet length limit.
    let long_value = "x".repeat(256);
    let input = format!("x IN 60 CAA 0 issue \"{long_value}\"");
    let file = MasterFile::parse(&input, Some(origin())).unwrap();
    assert!(matches!(
        &file.records[0].rdata,
        RData::CAA(caa) if caa.value == long_value.as_bytes()
    ));
}

#[test]
fn parses_the_rfc7477_csync_example_and_generic_type_names() {
    let file = MasterFile::parse(
        concat!(
            "example.com. 3600 IN CSYNC 66 3 A NS AAAA\n",
            "other.example.com. 3600 IN CSYNC 0 0 TYPE65000",
        ),
        None,
    )
    .unwrap();

    let RData::CSYNC(example) = &file.records[0].rdata else {
        panic!("CSYNC record did not have CSYNC RDATA")
    };
    assert_eq!(example.soa_serial, 66);
    assert_eq!(example.flags, 3);
    assert_eq!(example.type_bitmap.codes(), &[1, 2, 28]);

    let RData::CSYNC(generic) = &file.records[1].rdata else {
        panic!("CSYNC record did not have CSYNC RDATA")
    };
    assert_eq!(generic.type_bitmap.codes(), &[65_000]);
}

#[test]
fn parses_tlsa_and_smimea_certificate_associations() {
    let file = MasterFile::parse(
        concat!(
            "_443._tcp.example. 60 IN TLSA 3 1 1 ( ",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa )\n",
            "hash._smimecert.example. 60 IN SMIMEA 3 0 2 ( ",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb )",
        ),
        None,
    )
    .unwrap();

    assert!(matches!(
        &file.records[0].rdata,
        RData::TLSA(association)
            if association.certificate_usage == 3
                && association.selector == 1
                && association.matching_type == 1
                && association.association_data == vec![0xaa; 32]
    ));
    assert!(matches!(
        &file.records[1].rdata,
        RData::SMIMEA(association)
            if association.matching_type == 2
                && association.association_data == vec![0xbb; 64]
    ));
}

#[test]
fn csync_master_format_rejects_missing_or_pseudo_type_maps() {
    for input in [
        "@ IN 60 CSYNC 66 3",
        "@ IN 60 CSYNC 66 3 OPT",
        "@ IN 60 CSYNC 66 3 TYPE251",
        "@ IN 60 CSYNC nope 3 A",
        "@ IN 60 CSYNC 66 65536 A",
    ] {
        assert!(MasterFile::parse(input, Some(origin())).is_err(), "{input}");
    }
}

#[test]
fn strict_zone_validation_rejects_unsafe_csync_publication_fields() {
    let reserved = MasterFile::parse("@ IN 60 CSYNC 66 32768 A", Some(origin())).unwrap();
    assert!(matches!(
        reserved.validate_strict(),
        Err(RecordValidationError::ReservedCsyncFlags { value: 0x8000 })
    ));

    let forbidden = MasterFile::parse("@ IN 60 CSYNC 66 0 TYPE43", Some(origin())).unwrap();
    assert!(matches!(
        forbidden.validate_strict(),
        Err(RecordValidationError::ForbiddenCsyncType { value: 43 })
    ));
}
