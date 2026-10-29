use super::*;

fn signatures(
    records: &[ResourceRecord],
    zone: &DomainName,
    key: &Dnskey,
    private: &rsa::RsaPrivateKey,
) -> Vec<ResourceRecord> {
    records
        .iter()
        .map(|record| {
            let mut signature = sign_record(record, zone, key, private);
            if record
                .name
                .as_ref()
                .first()
                .is_some_and(|label| label == b"*")
            {
                let RData::RRSIG(rrsig) = &mut signature.rdata else {
                    unreachable!()
                };
                rrsig.labels -= 1;
                rrsig.signature =
                    rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private.clone())
                        .sign(&rrsig.signed_data(std::slice::from_ref(record)).unwrap())
                        .to_vec();
            }
            signature
        })
        .collect()
}

#[test]
fn nsec_wildcard_nodata_requires_next_closer_and_authenticated_type_absence() {
    let zone = name("example");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let records = MasterFile::parse("*.example. 21 IN NSEC a.example. A RRSIG NSEC\na.example. 11 IN NSEC z.example. A RRSIG NSEC", None).unwrap().records;
    let sigs = signatures(&records, &zone, &key, &private);
    let qname = name("foo.m.example");
    let result = keys.validate_nsec_nodata(&qname, 28, &records, &sigs, 100);
    let proof = result.secure().unwrap();
    assert_eq!(proof.proof_record_indices(), &[0, 1]);
    assert_eq!(proof.authenticated_ttl(), 11);
    // A valid wildcard RRset signature cannot authenticate an expanded
    // owner as an exact-match denial in the authority section.
    let mut expanded_record = records[0].clone();
    expanded_record.name = qname.clone();
    let mut expanded_signature = sigs[0].clone();
    expanded_signature.name = qname.clone();
    assert_eq!(
        keys.validate_nsec_nodata(&qname, 28, &[expanded_record], &[expanded_signature], 100)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    for qtype in [1, 5] {
        // A is present; CNAME cannot be denied by a wildcard containing it.
        let mut changed = records.clone();
        if qtype == 5 {
            let RData::NSEC(nsec) = &mut changed[0].rdata else {
                unreachable!()
            };
            nsec.type_bitmap = crate::TypeBitmap::new([5, 46, 47]).unwrap();
        }
        let sigs = signatures(&changed, &zone, &key, &private);
        assert_eq!(
            keys.validate_nsec_nodata(&qname, qtype, &changed, &sigs, 100)
                .status(),
            DnssecSecurityStatus::Bogus
        );
    }
    assert_eq!(
        keys.validate_nsec_nodata(&qname, 28, &records[..1], &sigs, 100)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    assert_eq!(
        keys.validate_nsec_nodata(&qname, 28, &records, &sigs[..1], 100)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    // This signed interval denies only QNAME, leaving m.example possible.
    let replay = MasterFile::parse("*.example. 21 IN NSEC a.example. A RRSIG NSEC\na.m.example. 11 IN NSEC z.m.example. A RRSIG NSEC", None).unwrap().records;
    let replay_sigs = signatures(&replay, &zone, &key, &private);
    assert_eq!(
        keys.validate_nsec_nodata(&qname, 28, &replay, &replay_sigs, 100)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    for codes in [[2, 46, 47], [39, 46, 47], [5, 46, 47]] {
        let mut changed = records.clone();
        let RData::NSEC(nsec) = &mut changed[0].rdata else {
            unreachable!()
        };
        nsec.type_bitmap = crate::TypeBitmap::new(codes).unwrap();
        let sigs = signatures(&changed, &zone, &key, &private);
        assert_eq!(
            keys.validate_nsec_nodata(&qname, 28, &changed, &sigs, 100)
                .status(),
            DnssecSecurityStatus::Bogus
        );
    }
}

#[test]
fn nsec3_wildcard_nodata_requires_complete_non_opt_out_proof() {
    let zone = name("example");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let source = MasterFile::parse("example. 60 IN SOA ns.example. hostmaster.example. 1 2 3 4 60\n*.example. 60 IN A 192.0.2.1", None).unwrap().records;
    let chain = crate::Nsec3Chain::build(
        &zone,
        ClassType::IN,
        &source,
        crate::Nsec3param {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: vec![],
        },
        60,
        false,
        0,
    )
    .unwrap();
    let records = chain.records();
    let sigs = signatures(records, &zone, &key, &private);
    let qname = name("foo.m.example");
    let result = keys.validate_nsec3_nodata(&qname, 28, records, &sigs, 100, 0);
    let proof = result.secure().unwrap();
    assert_eq!(proof.kind(), DnssecDenialKind::NoData);
    assert_eq!(proof.authenticated_ttl(), 60);
    assert_eq!(
        keys.validate_nsec3_nodata(&qname, 1, records, &sigs, 100, 0)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    assert_eq!(
        keys.validate_nsec3_nodata(&qname, 28, records, &[], 100, 0)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    assert_eq!(
        keys.validate_nsec3_nodata(&qname, 43, records, &sigs, 100, 0)
            .secure()
            .unwrap()
            .kind(),
        DnssecDenialKind::NoData
    );
    assert_eq!(
        keys.validate_nsec3_insecure_delegation(&qname, records, &sigs, 100, 0)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    let closest = find_nsec3_closest_encloser(records, &zone, ClassType::IN, &qname, 0).unwrap();
    let mut mixed = records.to_vec();
    let RData::NSEC3(nsec3) = &mut mixed[0].rdata else {
        unreachable!()
    };
    nsec3.salt.push(1);
    let mixed_sigs = signatures(&mixed, &zone, &key, &private);
    assert_eq!(
        keys.validate_nsec3_nodata(&qname, 28, &mixed, &mixed_sigs, 100, 0)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    for removed in 0..records.len() {
        let mut incomplete = records.to_vec();
        incomplete.remove(removed);
        let incomplete_sigs = signatures(&incomplete, &zone, &key, &private);
        assert_eq!(
            keys.validate_nsec3_nodata(&qname, 28, &incomplete, &incomplete_sigs, 100, 0)
                .status(),
            DnssecSecurityStatus::Bogus
        );
    }
    let mut opt_out = records.to_vec();
    let RData::NSEC3(nsec3) = &mut opt_out[closest.covering_record].rdata else {
        unreachable!()
    };
    nsec3.flags = crate::Nsec3::OPT_OUT_FLAG;
    let sigs = signatures(&opt_out, &zone, &key, &private);
    let result = keys.validate_nsec3_nodata(&qname, 28, &opt_out, &sigs, 100, 0);
    assert!(result.secure().unwrap().opt_out());
    assert_eq!(result.secure().unwrap().authenticated_ttl(), 60);
    assert_eq!(
        keys.validate_nsec3_nodata(&qname, 28, &opt_out, &[], 100, 0)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    let result = keys.validate_nsec3_wildcard_expansion(&qname, &zone, &opt_out, &sigs, 100, 0);
    assert!(result.secure().unwrap().opt_out());
    // Exact hashed ordinary names and the apex cannot prove a delegation.
    let ordinary_sigs = signatures(records, &zone, &key, &private);
    for ordinary in [&zone, &name("*.example")] {
        assert_eq!(
            keys.validate_nsec3_insecure_delegation(ordinary, records, &ordinary_sigs, 100, 0)
                .status(),
            DnssecSecurityStatus::Bogus
        );
    }
}

#[test]
fn literal_wildcard_denial_rejects_higher_wildcard_replay_and_tries_valid_signatures() {
    let zone = name("example");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let original = MasterFile::parse("*.example. 30 IN NSEC a.example. A RRSIG NSEC", None)
        .unwrap()
        .records;
    let mut replay_signature = signatures(&original, &zone, &key, &private).remove(0);
    let mut records = MasterFile::parse("*.m.example. 30 IN NSEC a.example. A RRSIG NSEC\na.m.example. 30 IN NSEC z.m.example. A RRSIG NSEC", None).unwrap().records;
    replay_signature.name = records[0].name.clone();
    let literal_signatures = signatures(&records, &zone, &key, &private);
    let qname = name("foo.m.example");
    let replay_signatures = vec![replay_signature.clone(), literal_signatures[1].clone()];
    assert_eq!(
        keys.validate_nsec_nodata(&qname, 28, &records, &replay_signatures, 100)
            .status(),
        DnssecSecurityStatus::Bogus
    );
    let mut candidates = vec![replay_signature];
    candidates.extend(literal_signatures);
    assert_eq!(
        keys.validate_nsec_nodata(&qname, 28, &records, &candidates, 100)
            .status(),
        DnssecSecurityStatus::Secure
    );
    // Also verify a non-wildcard owner skips an expanded valid candidate
    // before accepting its own literal signature.
    records[0].name = name("foo.m.example");
    let literal_signatures = signatures(&records[..1], &zone, &key, &private);
    let mut expanded = candidates[0].clone();
    expanded.name = records[0].name.clone();
    let candidates = vec![expanded, literal_signatures[0].clone()];
    assert_eq!(
        keys.validate_nsec_nodata(&qname, 28, &records[..1], &candidates, 100)
            .status(),
        DnssecSecurityStatus::Secure
    );
}
