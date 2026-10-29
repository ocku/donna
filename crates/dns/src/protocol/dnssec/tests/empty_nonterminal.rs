use super::*;

fn nsec_records() -> Vec<ResourceRecord> {
    MasterFile::parse(
        concat!(
            "a.example. 17 IN NSEC leaf.deep.empty.example. TXT RRSIG NSEC\n",
            "leaf.deep.empty.example. 11 IN NSEC z.example. TXT RRSIG NSEC",
        ),
        None,
    )
    .unwrap()
    .records
}

fn sign_all(
    records: &[ResourceRecord],
    zone: &DomainName,
    key: &Dnskey,
    private: &rsa::RsaPrivateKey,
) -> Vec<ResourceRecord> {
    records
        .iter()
        .map(|r| sign_record(r, zone, key, private))
        .collect()
}

#[test]
fn signed_nsec_proves_empty_nonterminal_nodata_with_descendant_endpoint() {
    let zone = name("example");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let records = nsec_records();
    let signatures = sign_all(&records, &zone, &key, &private);
    // QTYPE is absent at the empty name even when it is present at the
    // NSEC owner; that owner's bitmap describes a different name.
    for qname in [name("empty.example"), name("deep.empty.example")] {
        for qtype in [1, 5, 16, 28, 43] {
            let result = keys.validate_nsec_nodata(&qname, qtype, &records, &signatures, 100);
            let proof = result.secure().unwrap();
            assert_eq!(proof.kind(), DnssecDenialKind::NoData);
            assert_eq!(proof.proof_record_indices(), &[0]);
            assert_eq!(proof.authenticated_ttl(), 17);
        }
        assert_eq!(
            keys.validate_nsec_nodata(&qname, 1, &records, &[], 100)
                .status(),
            DnssecSecurityStatus::Bogus
        );
        assert_eq!(
            keys.validate_nsec_nodata(&qname, 1, &records, &signatures, 10_001)
                .status(),
            DnssecSecurityStatus::Bogus
        );
        let mut corrupt = signatures.clone();
        let RData::RRSIG(sig) = &mut corrupt[0].rdata else {
            unreachable!()
        };
        sig.signature[0] ^= 1;
        assert_eq!(
            keys.validate_nsec_nodata(&qname, 1, &records, &corrupt, 100)
                .status(),
            DnssecSecurityStatus::Bogus
        );
    }
    // A non-descendant endpoint denies existence, not an existing empty name.
    assert_eq!(
        keys.validate_nsec_nodata(&name("missing.example"), 1, &records, &signatures, 100)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    // An exact endpoint exists but its types require that owner's own proof.
    assert_eq!(
        keys.validate_nsec_nodata(
            &name("leaf.deep.empty.example"),
            16,
            &records[..1],
            &signatures[..1],
            100
        )
        .status(),
        DnssecSecurityStatus::Bogus
    );
}

#[test]
fn signed_nsec_nxdomain_infers_empty_closest_encloser_from_both_endpoints() {
    let zone = name("example");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let records = nsec_records();
    let signatures = sign_all(&records, &zone, &key, &private);
    for qname in [
        name("missing.empty.example"),
        name("missing.deep.empty.example"),
    ] {
        let result = keys.validate_nsec_name_error(&qname, &records, &signatures, 100);
        let proof = result.secure().unwrap();
        assert_eq!(proof.kind(), DnssecDenialKind::NameError);
        assert_eq!(proof.proof_record_indices(), &[0, 1]);
        assert_eq!(proof.authenticated_ttl(), 11);
        for omitted in 0..2 {
            let incomplete = vec![signatures[1 - omitted].clone()];
            assert_eq!(
                keys.validate_nsec_name_error(&qname, &records, &incomplete, 100)
                    .status(),
                DnssecSecurityStatus::Bogus
            );
        }
        // Cannot replay this NXDOMAIN to deny the existing empty owner.
        assert_eq!(
            keys.validate_nsec_name_error(&name("empty.example"), &records, &signatures, 100)
                .status(),
            DnssecSecurityStatus::Bogus
        );
    }
}

#[test]
fn empty_nsec_inference_preserves_class_zone_delegation_and_dname_boundaries() {
    let zone = name("example");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let empty = name("empty.example");
    let missing = name("missing.empty.example");
    let records = nsec_records();
    for mutation in [
        "class",
        "owner-zone",
        "next-zone",
        "delegation",
        "dname",
        "expanded-signature",
    ] {
        let mut changed = records.clone();
        match mutation {
            "class" => changed.iter_mut().for_each(|r| r.class = ClassType::CH),
            "owner-zone" => changed[0].name = name("a.invalid"),
            "next-zone" => {
                let RData::NSEC(nsec) = &mut changed[0].rdata else {
                    unreachable!()
                };
                nsec.next_domain_name = name("leaf.empty.invalid");
            }
            "delegation" | "dname" => {
                changed.push(
                    MasterFile::parse(
                        &format!(
                            "example. 20 IN NSEC a.example. {} RRSIG NSEC",
                            if mutation == "dname" { "TYPE39" } else { "NS" }
                        ),
                        None,
                    )
                    .unwrap()
                    .records
                    .remove(0),
                );
            }
            _ => {}
        }
        let mut signatures = sign_all(&changed, &zone, &key, &private);
        if mutation == "expanded-signature" {
            // A cryptographically valid higher-wildcard signature cannot
            // authenticate a literal authority proof owner.
            let RData::RRSIG(sig) = &mut signatures[0].rdata else {
                unreachable!()
            };
            sig.labels = 0;
            sig.signature = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private.clone())
                .sign(&sig.signed_data(&changed[..1]).unwrap())
                .to_vec();
        }
        assert_eq!(
            keys.validate_nsec_nodata(&empty, 1, &changed, &signatures, 100)
                .status(),
            DnssecSecurityStatus::Bogus,
            "NODATA: {mutation}"
        );
        assert_eq!(
            keys.validate_nsec_name_error(&missing, &changed, &signatures, 100)
                .status(),
            DnssecSecurityStatus::Bogus,
            "NXDOMAIN: {mutation}"
        );
    }
    let signatures = sign_all(&records, &zone, &key, &private);
    assert_eq!(
        keys.validate_nsec_nodata(&name("empty.invalid"), 1, &records, &signatures, 100)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    assert_eq!(
        keys.validate_nsec_name_error(&name("missing.empty.invalid"), &records, &signatures, 100)
            .status(),
        DnssecSecurityStatus::Bogus
    );
}

#[test]
fn wrapping_nsec_cannot_prove_nodata_outside_its_authenticated_zone() {
    let zone = name("example.com");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let records = MasterFile::parse(
        "z.example.com. 20 IN NSEC example.com. TXT RRSIG NSEC",
        None,
    )
    .unwrap()
    .records;
    let signatures = sign_all(&records, &zone, &key, &private);
    for qname in [name("com"), DomainName::root()] {
        assert_eq!(
            keys.validate_nsec_nodata(&qname, 1, &records, &signatures, 100)
                .status(),
            DnssecSecurityStatus::Bogus
        );
        assert_eq!(
            keys.validate_nsec_name_error(&qname, &records, &signatures, 100)
                .status(),
            DnssecSecurityStatus::Bogus
        );
    }
}

#[test]
fn complete_nsec_proof_cannot_replay_ent_existence_as_nxdomain() {
    let zone = name("example");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let mut records = nsec_records();
    records.extend(
        MasterFile::parse("example. 20 IN NSEC a.example. NS SOA RRSIG NSEC", None)
            .unwrap()
            .records,
    );
    let signatures = sign_all(&records, &zone, &key, &private);
    // The first interval covers empty.example and proves it is an ENT;
    // the apex interval also covers *.example. They cannot deny that ENT.
    for qname in [
        name("empty.example"),
        name("deep.empty.example"),
        name("leaf.deep.empty.example"),
    ] {
        assert_eq!(
            keys.validate_nsec_name_error(&qname, &records, &signatures, 100)
                .status(),
            DnssecSecurityStatus::Bogus
        );
    }
}
