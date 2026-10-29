use super::*;

include!("lexer_golden.rs");

#[test]
fn matches_legacy_record_snapshots() {
    let origin = DomainName::from_dotted("example.test.").unwrap();
    let owners = [
        "@",
        "a",
        "a.example.",
        r"a\046b",
        r#""a.b""#,
        r"a\000\255",
        "a..b",
        "",
        r"bad\999",
    ];
    let heads = [
        "IN 30", "30 IN", "IN", "30", "( IN 30", "IN ( 30", "IN 30 (",
    ];
    let data = [
        "A 192.0.2.1",
        "TXT \"hello world\"",
        "TXT one two",
        "TXT \";()\"",
        r"TXT \000\255",
        "TYPE65280 \\# 2 00ff",
        "A",
        "TXT \"broken",
        "TXT bad\\",
        "TXT bad\\1",
        "TXT a\"b\"",
        "TXT ()",
    ];
    let endings = ["\n", "\r\n", "\r", ""];
    let mut count = 0;
    for owner in owners {
        for head in heads {
            for data in data {
                for ending in endings {
                    let group = if head.contains('(') { " )" } else { "" };
                    let text = format!(
                        "$TTL 60\nfirst IN A 192.0.2.9\n{owner} {head} {data}{group}{ending}"
                    );
                    let result = MasterFile::parse(&text, Some(origin.clone())).map(|m| m.records);
                    let actual = result
                        .map(|records| format!("{records:?}"))
                        .unwrap_or_else(|_| "ERR".to_owned());
                    assert_eq!(actual, EXPECTED[RECORDS[count]], "{text:?}");
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 3024);
}

#[test]
fn matches_legacy_boundary_snapshots() {
    let origin = DomainName::from_dotted("example.test.").unwrap();
    let cases = [
        "$owner IN A 192.0.2.1",
        "$TTL IN A 192.0.2.1",
        "$ORIGIN IN A ( 192.0.2.1 )",
        "a IN TXT a\\\nb\n",
        "a IN TXT a\\\r\nb\n",
        "a IN TXT a\\;b ;tail",
        "a IN TXT ( one ;comment\r\n two )\r\n",
        "a IN TXT ( ( one ) two )",
        "a IN TXT ( )",
        "a IN TXT ( one )two",
        "a IN TXT one(two)",
        "( a IN A 192.0.2.1 )",
        "a ( IN A 192.0.2.1 )",
        "a IN ( A ) 192.0.2.1",
        "a IN A ( 192.0.2.1 )",
        "$TTL ( 30 )",
        " $TTL 30",
        "$ORIGIN .\r",
        "$ORIGIN a.\"b\".\r\n",
        "a IN TXT \"é\"",
        "é IN TXT x",
        "a\\é IN TXT x",
        "a IN TXT a\\é",
        "a IN TXT \\",
        "a IN TXT \\000",
        "a IN TXT \\255",
        "a IN TXT \\256",
        "a IN TYPE65280 \\# 2 00 ff",
        "a IN TYPE65280 \\# 2 00ff",
        "a IN TYPE65280 \\# 2 00",
        "a IN TXT a.\"b\"",
        "a.\"b\" IN TXT x",
        "a\\.\"b\" IN TXT x",
        "a IN TXT \"a\".b",
        "a IN TXT \"a\"\"b\"",
        "a IN TXT \"x\r\ny\"",
        "a IN A 192.0.2.1\r b IN A 192.0.2.2",
        "a IN TXT ( one ; no newline",
        "a IN TXT one )",
        "a IN TXT ( one",
    ];
    for (index, case) in cases.into_iter().enumerate() {
        let text = format!("$TTL 60\n{case}");
        let result = MasterFile::parse(&text, Some(origin.clone())).map(|m| m.records);
        let actual = result
            .map(|records| format!("{records:?}"))
            .unwrap_or_else(|_| "ERR".to_owned());
        assert_eq!(actual, EXPECTED[BOUNDARIES[index]], "{text:?}");
    }
}

#[test]
fn lexical_errors_report_physical_line_and_column() {
    for newline in ["\n", "\r\n", "\r"] {
        let input = format!("$TTL 60{newline}a IN TXT \"bad");
        let error = MasterFile::parse(&input, None).unwrap_err().to_string();
        assert!(error.contains("line 2, column 10"), "{error}");
    }
}

#[test]
fn deeply_nested_groups_do_not_use_the_call_stack() {
    let input = format!(
        "$ORIGIN example.\n$TTL 60\na IN TXT {}x {}",
        "( ".repeat(4096),
        ") ".repeat(4096)
    );
    let file = MasterFile::parse(&input, None).unwrap();
    assert!(matches!(&file.records[0].rdata, RData::TXT(fields) if fields == &[b"x".to_vec()]));
}

#[test]
fn rr_headers_follow_rfc1035_optional_fields_and_grouping() {
    // RFC 1035 §5.1 lists TTL and class once each, in either order;
    // parentheses suppress physical line boundaries without changing fields.
    for header in ["IN ( IN A", "30 ( 40 IN A", "( IN IN A", "( 30 40 IN A"] {
        let input = format!("$ORIGIN example.\n$TTL 60\na {header} 192.0.2.1 )");
        assert!(MasterFile::parse(&input, None).is_err(), "{input}");
    }
    for header in ["( IN 30 ) A", "( 30 IN ) A", "IN ( 30 ) A", "30 ( IN ) A"] {
        let input = format!("$ORIGIN example.\n$TTL 60\na {header} 192.0.2.1");
        let file = MasterFile::parse(&input, None).unwrap();
        assert_eq!(file.records.len(), 1);
        assert_eq!(file.records[0].ttl, 30);
        assert_eq!(file.records[0].class, ClassType::IN);
        assert!(
            matches!(file.records[0].rdata, RData::A(address) if address == Ipv4Addr::new(192, 0, 2, 1))
        );
    }
}
