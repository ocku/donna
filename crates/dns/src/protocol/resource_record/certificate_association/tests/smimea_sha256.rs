use super::*;

#[test]
fn owner_matches_independent_ring_over_utf8_and_hash_boundaries() {
    let domain = DomainName::from_dotted("mail.example.").unwrap();
    let mut values = vec![
        String::new(),
        "hugh".into(),
        "Case.Sensitive+tag".into(),
        "é".into(),
        "e\u{301}".into(),
        "한글".into(),
        "😀".into(),
        "\0".into(),
    ];
    for n in [
        1, 27, 28, 31, 32, 55, 56, 63, 64, 65, 111, 112, 127, 128, 255, 512, 4096,
    ] {
        values.push("x".repeat(n));
        values.push("e\u{301}".repeat(n));
    }
    for value in values {
        let normalized = value.nfc().collect::<String>();
        let digest = ring::digest::digest(&ring::digest::SHA256, normalized.as_bytes());
        let expected_label = digest.as_ref()[..28]
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<String>();
        let expected =
            DomainName::from_dotted(&format!("{expected_label}._smimecert.mail.example.")).unwrap();
        assert_eq!(
            smimea_owner_name(&value, &domain).unwrap(),
            expected,
            "input {value:?}"
        );
    }
    assert_eq!(
        smimea_owner_name("é", &domain),
        smimea_owner_name("e\u{301}", &domain)
    );
    assert_ne!(
        smimea_owner_name("ABC", &domain),
        smimea_owner_name("abc", &domain)
    );
}

#[test]
fn rejects_root_and_owner_name_overflow() {
    let root = DomainName::root();
    assert_eq!(
        smimea_owner_name("hugh", &root),
        Err(CertificateAssociationError::InvalidMailDomain)
    );
    let domain = DomainName::from_labels(vec![
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 40],
    ])
    .unwrap();
    assert!(matches!(
        smimea_owner_name("hugh", &domain),
        Err(CertificateAssociationError::InvalidOwnerName(_))
    ));
}
