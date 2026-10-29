use super::*;

#[test]
fn cached_nsec_and_nxt_membership_keeps_class_delegation_scope_and_order() {
    let nsec = |owner| {
        record(
            owner,
            RecordType::NSEC,
            RData::NSEC(dns::Nsec {
                next_domain_name: name(&["example"]),
                type_bitmap: TypeBitmap::new([1]).unwrap(),
            }),
        )
    };
    let visible = nsec(name(&["www", "example"]));
    let cut = nsec(name(&["child", "example"]));
    let below = nsec(name(&["leaf", "child", "example"]));
    let mut foreign = visible.clone();
    foreign.class = ClassType::CH;
    let nxt = record(
        name(&["example"]),
        RecordType::Unknown(30),
        RData::Unknown(vec![0]),
    );
    let hidden_nxt = record(
        name(&["leaf", "child", "example"]),
        RecordType::Unknown(30),
        RData::Unknown(vec![0]),
    );
    let zone = zone(
        vec![
            soa(),
            visible.clone(),
            below,
            foreign,
            nxt.clone(),
            record(
                name(&["child", "example"]),
                RecordType::NS,
                RData::NS(name(&["ns", "external"])),
            ),
            cut.clone(),
            hidden_nxt,
        ],
        soa(),
    );
    let selected = |indices: &[usize]| {
        indices
            .iter()
            .map(|&i| zone.records[i].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        encoded(&selected(&zone.nsec_records)),
        encoded(&[visible, cut])
    );
    assert_eq!(encoded(&selected(&zone.nxt_records)), encoded(&[nxt]));
}

#[test]
fn indexed_signature_lookup_preserves_legacy_and_current_wire_order() {
    let legacy = ring(false, 0, true)
        .into_iter()
        .find(|record| record.rtype == RecordType::SIG)
        .unwrap();
    let mut legacy_upper = legacy.clone();
    legacy_upper.name = name(&["EXAMPLE"]);
    if let RData::SIG(sig) = &mut legacy_upper.rdata {
        sig.signature = vec![3];
    }
    let modern = signature(name(&["example"]), RecordType::SOA);
    let mut modern_upper = modern.clone();
    modern_upper.name = name(&["EXAMPLE"]);
    if let RData::RRSIG(sig) = &mut modern_upper.rdata {
        sig.signature = vec![4];
    }
    let mut foreign = modern.clone();
    foreign.class = ClassType::CH;
    let zone = zone(
        vec![
            soa(),
            modern.clone(),
            legacy_upper.clone(),
            signature(name(&["other", "example"]), RecordType::SOA),
            legacy.clone(),
            signature(name(&["example"]), RecordType::A),
            modern_upper.clone(),
            foreign,
        ],
        soa(),
    );
    let missing = name(&["missing", "example"]);
    for dnssec_ok in [false, true] {
        let mut expected = vec![soa(), legacy_upper.clone(), legacy.clone()];
        if dnssec_ok {
            expected.extend([modern.clone(), modern_upper.clone()]);
        }
        assert_eq!(
            encoded(&zone.negative_response_authorities(&missing, &missing, true, dnssec_ok)),
            encoded(&expected)
        );
    }
}

fn nsec_ring(single: bool) -> Vec<ResourceRecord> {
    let mut source = ring(false, 0, single)
        .into_iter()
        .filter(|record| {
            !matches!(record.rtype, RecordType::NSEC3 | RecordType::NSEC3PARAM)
                && !matches!(&record.rdata, RData::RRSIG(sig) if sig.type_covered == 50)
        })
        .collect::<Vec<_>>();
    let mut owners = source
        .iter()
        .filter(|record| record.name != name(&["ns", "child", "example"]))
        .map(|record| record.name.clone())
        .collect::<Vec<_>>();
    owners.sort_by(DomainName::canonical_cmp);
    owners.dedup_by(|a, b| a.eq_dns(b));
    let mut proofs = Vec::new();
    for i in 0..owners.len() {
        proofs.push(record(
            owners[i].clone(),
            RecordType::NSEC,
            RData::NSEC(dns::Nsec {
                next_domain_name: owners[(i + 1) % owners.len()].clone(),
                type_bitmap: TypeBitmap::new([1, 46, 47]).unwrap(),
            }),
        ));
    }
    for proof in proofs.into_iter().rev() {
        source.push(signature(proof.name.clone(), RecordType::NSEC));
        source.push(proof);
    }
    source
}

#[test]
fn canonical_nsec_index_preserves_matching_coverage_empty_nodes_and_order() {
    for single in [false, true] {
        let records = nsec_ring(single);
        assert!(zone(records.clone(), soa()).nsec_index.is_some());
        assert_equivalent(records);
    }
    let records = nsec_ring(false);
    let proof = records
        .iter()
        .position(|record| record.rtype == RecordType::NSEC)
        .unwrap();
    for mutation in 0..4 {
        let mut changed = records.clone();
        match mutation {
            0 => changed.push(changed[proof].clone()),
            1 => {
                changed.remove(proof);
            }
            2 => {
                let RData::NSEC(nsec) = &mut changed[proof].rdata else {
                    unreachable!()
                };
                nsec.next_domain_name = name(&["outside"]);
            }
            3 => changed[proof].rdata = RData::Unknown(vec![0]),
            _ => unreachable!(),
        }
        assert!(zone(changed.clone(), soa()).nsec_index.is_none());
        assert_equivalent(changed);
    }
}

#[test]
fn bind_signed_zones_use_indexes_and_preserve_original_proofs() {
    for (nsec3, text) in [
        (false, include_str!("../fixtures/bind-nsec.zone")),
        (true, include_str!("../fixtures/bind-nsec3.zone")),
    ] {
        let apex = DomainName::from_dotted("example.test.").unwrap();
        let master = MasterFile::parse(text, Some(apex.clone())).unwrap();
        let indexed = Zone::from_master(apex.clone(), master).unwrap();
        if nsec3 {
            assert!(indexed.nsec3_index.is_some());
        } else {
            assert!(
                indexed.nsec_index.is_some(),
                "NSEC candidates={}",
                indexed.nsec_records.len()
            );
        }
        let mut reference = Zone::new(
            apex,
            indexed.class,
            indexed.records.clone(),
            indexed.soa.clone(),
        );
        reference.nsec3_index = None;
        reference.nsec_index = None;
        for (text, name_error) in [
            ("www.example.test.", false),
            ("missing.example.test.", true),
            ("empty.example.test.", false),
            ("deep.empty.example.test.", false),
            ("missing.empty.example.test.", true),
            ("child.example.test.", false),
        ] {
            let owner = DomainName::from_dotted(text).unwrap();
            assert_eq!(
                encoded(&indexed.negative_response_authorities(&owner, &owner, name_error, true)),
                encoded(&reference.negative_response_authorities(&owner, &owner, name_error, true))
            );
        }
        for text in ["m.wild.example.test.", "p.q.wild.example.test."] {
            let expanded = DomainName::from_dotted(text).unwrap();
            let wildcard = DomainName::from_dotted("*.wild.example.test.").unwrap();
            assert_eq!(
                encoded(&indexed.negative_response_authorities(&wildcard, &expanded, false, true)),
                encoded(
                    &reference.negative_response_authorities(&wildcard, &expanded, false, true)
                )
            );
            let mut answer = signature(expanded, RecordType::TXT);
            if let RData::RRSIG(sig) = &mut answer.rdata {
                sig.labels = 3;
            }
            let (mut actual, mut expected) = (vec![], vec![]);
            indexed.append_wildcard_denial(&[answer.clone()], &mut actual);
            reference.append_wildcard_denial(&[answer], &mut expected);
            assert_eq!(encoded(&actual), encoded(&expected));
        }
    }
}
