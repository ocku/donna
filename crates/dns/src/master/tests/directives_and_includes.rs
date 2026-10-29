use super::*;

#[test]
fn parses_rfc_1010_wks_protocol_and_service_mnemonics() {
    let file = MasterFile::parse(
        concat!(
            "finger IN 1 WKS 192.0.2.1 TCP FINGER\n",
            "egp IN 1 WKS 192.0.2.2 EGP 0\n",
            "decimal IN 1 WKS 192.0.2.3 17 69\n",
        ),
        Some(origin()),
    )
    .unwrap();

    assert!(matches!(
        &file.records[0].rdata,
        RData::WKS { protocol: 6, bitmap, .. }
            if bitmap.len() == 10 && bitmap[9] == 0x01
    ));
    assert!(matches!(
        &file.records[1].rdata,
        RData::WKS { protocol: 8, bitmap, .. }
            if bitmap.as_slice() == [0x80]
    ));
    assert!(matches!(
        &file.records[2].rdata,
        RData::WKS { protocol: 17, bitmap, .. }
            if bitmap.len() == 9 && bitmap[8] == 0x04
    ));
}

#[test]
fn resolves_wks_services_for_the_selected_protocol() {
    let file = MasterFile::parse("tftp IN 1 WKS 192.0.2.1 UDP TFTP\n", Some(origin())).unwrap();
    assert!(matches!(
        &file.records[0].rdata,
        RData::WKS { protocol: 17, bitmap, .. }
            if bitmap.len() == 9 && bitmap[8] == 0x04
    ));

    assert!(MasterFile::parse("tftp IN 1 WKS 192.0.2.1 TCP TFTP", Some(origin())).is_err());
    assert!(MasterFile::parse("finger IN 1 WKS 192.0.2.1 UDP FINGER", Some(origin())).is_err());
}

#[test]
fn accepts_an_empty_wks_bitmap() {
    let file = MasterFile::parse("wks IN 1 WKS 192.0.2.1 TCP\n", Some(origin())).unwrap();
    assert!(matches!(
        &file.records[0].rdata,
        RData::WKS { protocol: 6, bitmap, .. } if bitmap.is_empty()
    ));
}

#[test]
fn preserves_escaped_domain_name_characters() {
    let file = MasterFile::parse(
        "\\@ IN 1 A 192.0.2.1\n. IN 1 NS target\\.name\n",
        Some(origin()),
    )
    .unwrap();

    assert_eq!(
        file.records[0].name.as_ref(),
        &[b"@".to_vec(), b"example".to_vec(), b"test".to_vec()]
    );
    assert!(matches!(
        &file.records[1].rdata,
        RData::NS(name)
            if name.as_ref()
                == [
                    b"target.name".to_vec(),
                    b"example".to_vec(),
                    b"test".to_vec(),
                ]
    ));
}

#[test]
fn resolves_relative_origin_and_checks_character_string_limit() {
    let maximum_string = "a".repeat(255);
    let file = MasterFile::parse(
        &format!("$ORIGIN child\nx 1 IN HINFO {maximum_string} os"),
        Some(origin()),
    )
    .unwrap();
    assert_eq!(
        file.records[0].name.as_ref(),
        &[
            b"x".to_vec(),
            b"child".to_vec(),
            b"example".to_vec(),
            b"test".to_vec(),
        ]
    );
    assert_eq!(file.records[0].ttl, 1);
    assert_eq!(file.records[0].class, ClassType::IN);
    assert!(matches!(
        &file.records[0].rdata,
        RData::HINFO { cpu, os } if cpu.len() == 255 && os == b"os"
    ));

    let oversized_string = "a".repeat(256);
    assert!(
        MasterFile::parse(
            &format!("x 1 IN HINFO {oversized_string} os"),
            Some(origin())
        )
        .is_err()
    );
}

#[test]
fn include_restores_parent_origin_and_path_but_keeps_inserted_defaults() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("donna-master-state-{unique}"));
    fs::create_dir(&directory).unwrap();
    let subdirectory = directory.join("sub");
    fs::create_dir(&subdirectory).unwrap();
    let parent = directory.join("parent.zone");
    let included = subdirectory.join("included.zone");
    let sibling = directory.join("sibling.zone");
    fs::write(
        &parent,
        concat!(
            "parent IN 300 A 192.0.2.1\n",
            "$iNcLuDe sub/included.zone child.example.\n",
            "  A \\# 4 c0000202\n",
            "after A \\# 4 c0000204\n",
            "$InClUdE sibling.zone\n",
        ),
    )
    .unwrap();
    fs::write(&included, "included CH 60 A \\# 4 c0000203\n").unwrap();
    fs::write(&sibling, "sibling A \\# 4 c0000205\n").unwrap();

    let file = MasterFile::from_path(&parent, Some(origin())).unwrap();
    let inherited = &file.records[2];
    assert_eq!(
        inherited.name.as_ref(),
        &[b"included".to_vec(), b"child".to_vec(), b"example".to_vec(),]
    );
    assert_eq!(inherited.class, ClassType::CH);
    assert_eq!(inherited.ttl, 60);

    let after = &file.records[3];
    assert_eq!(
        after.name.as_ref(),
        &[b"after".to_vec(), b"example".to_vec(), b"test".to_vec(),]
    );
    assert_eq!(after.class, ClassType::CH);
    assert_eq!(after.ttl, 60);

    let sibling = &file.records[4];
    assert_eq!(
        sibling.name.as_ref(),
        &[b"sibling".to_vec(), b"example".to_vec(), b"test".to_vec(),]
    );
    assert_eq!(sibling.class, ClassType::CH);
    assert_eq!(sibling.ttl, 60);

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn ttl_directives_and_explicit_ttls_keep_distinct_state_across_includes() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("donna-master-ttl-{unique}"));
    fs::create_dir(&directory).unwrap();
    let parent = directory.join("parent.zone");
    let included = directory.join("included.zone");
    fs::write(
        &parent,
        "$TTL 300\nparent IN A 192.0.2.1\n$INCLUDE included.zone\nafter IN A 192.0.2.5\n",
    )
    .unwrap();
    fs::write(
        &included,
        concat!(
            "explicit IN 60 A 192.0.2.2\n",
            "defaulted IN A 192.0.2.3\n",
            "$TTL 120\n",
            "new-default IN A 192.0.2.4\n",
        ),
    )
    .unwrap();

    let file = MasterFile::from_path(&parent, Some(origin())).unwrap();
    assert_eq!(
        file.records
            .iter()
            .map(|record| record.ttl)
            .collect::<Vec<_>>(),
        [300, 60, 300, 120, 120]
    );

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_cyclic_includes() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("donna-master-{unique}"));
    fs::create_dir(&directory).unwrap();
    let first = directory.join("first.zone");
    let second = directory.join("second.zone");
    fs::write(&first, "$INCLUDE second.zone\n").unwrap();
    fs::write(&second, "$INCLUDE first.zone\n").unwrap();

    let error = MasterFile::from_path(&first, Some(origin())).unwrap_err();
    assert!(error.to_string().contains("cyclic $INCLUDE"));
    fs::remove_dir_all(directory).unwrap();
}

/// RFC 1035 §5.1: "The format of these files is a sequence of entries",
/// where blank and comment-only entries carry no records and any entry may
/// end with a comment.
#[test]
fn skips_blank_and_comment_entries_and_trailing_comments() {
    let file = MasterFile::parse(
        concat!(
            "; zone comment\r\n",
            "\r\n",
            "   \n",
            "@ IN 1 A 192.0.2.1 ; trailing comment\n",
            "; full-line comment\n",
            "www IN 1 A 192.0.2.2\r\n",
        ),
        Some(origin()),
    )
    .unwrap();

    assert_eq!(file.records.len(), 2);
    assert_eq!(file.records[0].name, origin());
    assert_eq!(file.records[1].name.as_ref()[0], b"www");
}

#[test]
fn enforces_the_rfc2181_ttl_maximum_in_records_and_directives() {
    let file = MasterFile::parse(&format!("@ IN {MAX_TTL} A 192.0.2.1"), Some(origin())).unwrap();
    assert_eq!(file.records[0].ttl, MAX_TTL);

    for input in [
        format!("@ IN {} A 192.0.2.1", MAX_TTL + 1),
        format!("$TTL {}\n@ IN A 192.0.2.1", MAX_TTL + 1),
    ] {
        assert!(MasterFile::parse(&input, Some(origin())).is_err());
    }
}

#[test]
fn rejects_missing_initial_ttl_and_relative_names_without_origin() {
    assert!(MasterFile::parse("x IN A 192.0.2.1", Some(origin())).is_err());
    assert!(MasterFile::parse("@ IN SOA ns hostmaster 1 2 3 4 5", Some(origin())).is_err());
    assert!(MasterFile::parse("x IN 1 A 192.0.2.1", None).is_err());
}

#[test]
fn rejects_a_record_when_no_class_has_been_stated() {
    assert!(MasterFile::parse("x 1 A 192.0.2.1", Some(origin())).is_err());
}

#[test]
fn rejects_at_sign_without_an_origin() {
    assert!(MasterFile::parse("@ IN 1 A 192.0.2.1", None).is_err());
}

#[test]
fn rejects_invalid_escapes_in_character_strings() {
    assert!(MasterFile::parse("txt IN 1 TXT a\\256b", Some(origin())).is_err());
    assert!(MasterFile::parse("txt IN 1 TXT a\\", Some(origin())).is_err());
}

#[test]
fn rejects_include_directives_when_parsing_from_memory() {
    let error = MasterFile::parse("$INCLUDE included.zone", Some(origin())).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires loading the master file from a path")
    );
}

/// RFC 2308 §4: "$TTL <ttl> [comment]" states the TTL used for records
/// that omit one; an explicit record TTL still takes precedence.
#[test]
fn ttl_directive_sets_the_default_ttl_for_records_that_omit_one() {
    let file = MasterFile::parse(
        "$TTL 3600\nx IN A 192.0.2.1\ny 60 IN A 192.0.2.2\nz IN A 192.0.2.3",
        Some(origin()),
    )
    .unwrap();

    assert_eq!(file.records[0].ttl, 3600);
    assert_eq!(file.records[1].ttl, 60);
    assert_eq!(file.records[2].ttl, 3600);
}

#[test]
fn ttl_less_legacy_sig_uses_its_original_ttl_instead_of_the_ttl_directive() {
    let file = MasterFile::parse(
        "$TTL 3600\n@ IN TYPE24 \\# 19 000101020000007b0000000000000000000000\n@ IN 60 TYPE24 \\# 19 000101020000007b0000000000000000000000",
        Some(origin()),
    )
    .unwrap();

    assert_eq!(file.records[0].ttl, 123);
    assert_eq!(file.records[1].ttl, 60);

    let without_default = MasterFile::parse(
        "@ IN TYPE24 \\# 19 000101020000007b0000000000000000000000",
        Some(origin()),
    )
    .unwrap();
    assert_eq!(without_default.records[0].ttl, 123);

    assert!(MasterFile::parse("$TTL 60\n@ IN TYPE24 \\# 4 00000102", Some(origin())).is_err());
}

#[test]
fn last_explicit_ttl_remains_the_legacy_fallback_without_a_ttl_directive() {
    let file = MasterFile::parse("x IN 60 A 192.0.2.1\ny IN A 192.0.2.2", Some(origin())).unwrap();
    assert_eq!(file.records[1].ttl, 60);
}

/// RFC 1035 §5.1: inside a " delimited string any character can occur, and
/// "text literals can contain CRLF within the text".
#[test]
fn quoted_strings_hold_special_characters_and_embedded_crlf() {
    let file =
        MasterFile::parse("txt IN 1 TXT \"a;b(c)\" \"line1\r\nline2\"", Some(origin())).unwrap();

    assert!(matches!(
        &file.records[0].rdata,
        RData::TXT(text) if text == &vec![b"a;b(c)".to_vec(), b"line1\r\nline2".to_vec()]
    ));
}

/// RFC 1035 §5.1: class and type use standard mnemonics, matched without
/// regard to case.
#[test]
fn matches_class_and_type_mnemonics_without_regard_to_case() {
    let file = MasterFile::parse("x in 1 a 192.0.2.1", Some(origin())).unwrap();

    assert_eq!(file.records[0].class, ClassType::IN);
    assert_eq!(file.records[0].rtype, RecordType::A);
}
