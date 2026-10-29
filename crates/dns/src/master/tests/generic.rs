use super::*;

#[test]
fn known_types_accept_generic_rdata_equivalent_to_mnemonics() {
    for (kind, mnemonic, hexadecimal) in [
        ("A", "192.0.2.1", "C0000201"),
        (
            "SOA",
            ". . 1 2 3 4 5",
            "00000000000100000002000000030000000400000005",
        ),
        ("MX", "10 .", "000A00"),
        ("SRV", "0 0 80 .", "00000000005000"),
        ("AAAA", "2001:db8::1", "20010DB8000000000000000000000001"),
        ("NS", "ns.example.", "026E73076578616D706C6500"),
        ("CNAME", "ns.example.", "026E73076578616D706C6500"),
        ("DNAME", "ns.example.", "026E73076578616D706C6500"),
        ("TXT", "\"hello\" \"world\"", "0568656C6C6F05776F726C64"),
        (
            "CAA",
            "0 issue \"ca.example\"",
            "0005697373756563612E6578616D706C65",
        ),
        ("CSYNC", "1 0 A NS", "000000010000000160"),
    ] {
        let plain = MasterFile::parse(&format!("x. IN 60 {kind} {mnemonic}"), None).unwrap();
        let generic = MasterFile::parse(
            &format!(
                "x. IN 60 {kind} \\# {} {hexadecimal}",
                hexadecimal.len() / 2
            ),
            None,
        )
        .unwrap();
        assert_eq!(generic.records[0].rdata, plain.records[0].rdata, "{kind}");
        generic.validate_strict().unwrap();
    }
}

#[test]
fn generic_known_rdata_rejects_bad_lengths_and_compressed_names() {
    for text in [
        "x. IN 60 A \\# 4 C00002",
        "x. IN 60 A \\# 3 C00002",
        "x. IN 60 NS \\# 2 C000",
        // The second SOA name points at the earlier root name. Although this
        // works in message RDATA, standalone RFC 3597 data forbids pointers.
        "x. IN 60 SOA \\# 23 00C0000000000100000002000000030000000400000005",
        "x. IN 60 NULL \\# 0",
        "x. IN 60 OPT \\# 0",
        "x. IN 60 TSIG \\# 0",
        "x. IN 60 MD \\# 1 00",
        "x. IN 60 MF \\# 1 00",
    ] {
        assert!(MasterFile::parse(text, None).is_err(), "{text}");
    }
}

#[test]
fn generic_known_rdata_preserves_strict_publication_validation() {
    for text in [
        "x. IN 60 CAA \\# 4 01016976",
        "x. IN 60 CSYNC \\# 9 000000010004000160",
    ] {
        let file = MasterFile::parse(text, None).unwrap();
        assert!(file.validate_strict().is_err());
    }
}
