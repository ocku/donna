use super::*;
use dns::{IntoWire, Rrsig, master::MasterFile};

// Independent record scan at the exact owner or the sole wildcard source.
fn reference(zone: &Zone, records: &mut Vec<ResourceRecord>) {
    let covered: Vec<_> = records
        .iter()
        .filter(|r| r.rtype != RecordType::RRSIG)
        .map(|r| (r.name.clone(), u16::from(r.rtype)))
        .collect();
    for (owner, covered_type) in covered {
        let source_owner = if zone.node_exists(&owner) {
            owner.clone()
        } else if let Some((wildcard, _)) = zone.wildcard_records_at_closest_encloser(&owner) {
            wildcard
        } else {
            continue;
        };
        for source in &zone.records {
            let RData::RRSIG(sig) = &source.rdata else {
                continue;
            };
            if source.rtype != RecordType::RRSIG
                || source.class != zone.class
                || sig.type_covered != covered_type
                || !source.name.eq_dns(&source_owner)
            {
                continue;
            }
            let labels = usize::from(sig.labels);
            let wildcard = (labels < owner.as_ref().len())
                .then(|| {
                    let mut name = vec![b"*".to_vec()];
                    name.extend_from_slice(&owner.as_ref()[owner.as_ref().len() - labels..]);
                    DomainName::from_labels(name).ok()
                })
                .flatten();
            if !source.name.eq_dns(&owner)
                && !wildcard.is_some_and(|name| source.name.eq_dns(&name))
            {
                continue;
            }
            let mut signature = source.clone();
            signature.name = owner.clone();
            if !super::super::response::contains_record(records, &signature) {
                records.push(signature);
            }
        }
    }
}

fn compare(zone: &Zone, input: &[ResourceRecord]) {
    let mut expected = input.to_vec();
    reference(zone, &mut expected);
    let mut actual = input.to_vec();
    zone.append_rrsigs_for(&mut actual);
    // Include exact name spelling, TTL and order even for defensive test
    // records whose advisory fields are rejected by the checked encoder.
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    let encode = |records: &[ResourceRecord]| {
        records
            .iter()
            .map(|r| r.into_wire().map_err(|e| e.to_string()))
            .collect::<Vec<_>>()
    };
    assert_eq!(encode(&actual), encode(&expected));
}

#[test]
fn indexed_signature_selection_matches_source_scan_on_real_bind_snapshots() {
    for text in [
        include_str!("fixtures/bind-nsec.zone"),
        include_str!("fixtures/bind-nsec3.zone"),
    ] {
        let apex = DomainName::from_dotted("example.test.").unwrap();
        let parsed =
            Zone::from_master(apex.clone(), MasterFile::parse(text, Some(apex)).unwrap()).unwrap();
        for reverse in [false, true] {
            let mut records = parsed.records.clone();
            if reverse {
                records.reverse();
            }
            let zone = Zone::new(
                parsed.apex.clone(),
                parsed.class,
                records,
                parsed.soa.clone(),
            );
            for owner in [
                "www.example.test.",
                "alias.example.test.",
                "m.wild.example.test.",
                "*.wild.example.test.",
                "CHILD.Example.TEST.",
                ".",
            ] {
                for qtype in [
                    QueryType::A,
                    QueryType::TXT,
                    QueryType::CNAME,
                    QueryType::ANY,
                    QueryType::DS,
                ] {
                    let question = Question {
                        qname: DomainName::from_dotted(owner).unwrap(),
                        qtype,
                        qclass: QClassType::Class(ClassType::IN),
                    };
                    match zone.lookup(&question) {
                        Lookup::Answer(records) | Lookup::Cname { records, .. } => {
                            compare(&zone, &records)
                        }
                        _ => compare(
                            &zone,
                            &[record(
                                question.qname,
                                RecordType::A,
                                RData::A(Ipv4Addr::LOCALHOST),
                            )],
                        ),
                    }
                }
            }
        }
    }
}

fn signature(
    owner: DomainName,
    labels: u8,
    covered: u16,
    class: ClassType,
    tag: u16,
) -> ResourceRecord {
    let mut value = record(
        owner,
        RecordType::RRSIG,
        RData::RRSIG(Rrsig {
            type_covered: covered,
            algorithm: 15,
            labels,
            original_ttl: 300,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: tag,
            signer_name: name(&["example"]),
            signature: vec![tag as u8; 64],
        }),
    );
    value.class = class;
    value.ttl = u32::from(tag) + 1;
    value
}

#[test]
fn indexed_signature_selection_preserves_root_binary_maximum_labels_order_and_duplicates() {
    for labels in [
        vec![],
        vec![b"MiXeD".to_vec(), b"example".to_vec()],
        vec![b"*".to_vec(), b"example".to_vec()],
        vec![vec![0, 255, 0xc0, b'A'], b"example".to_vec()],
        vec![vec![b'A']; 127],
        vec![vec![b'A'; 63], vec![0; 63], vec![255; 63], vec![b'z'; 61]],
    ] {
        let owner = DomainName::from_labels(labels.clone()).unwrap();
        let mut sources = vec![owner.clone()];
        for count in 0..labels.len() {
            let mut source = vec![b"*".to_vec()];
            source.extend_from_slice(&labels[labels.len() - count..]);
            sources.push(DomainName::from_labels(source).unwrap());
        }
        let mut records = Vec::new();
        for (i, source) in sources.iter().enumerate() {
            for labels in [
                0,
                source.as_ref().len().saturating_sub(1) as u8,
                owner.as_ref().len() as u8,
                127,
                255,
            ] {
                for covered in [1, 16] {
                    for class in [ClassType::IN, ClassType::CH] {
                        records.push(signature(source.clone(), labels, covered, class, i as u16));
                    }
                }
            }
        }
        // Distinct source owners can become the same emitted signature after
        // owner rewriting. The earliest source must retain its TTL/spelling.
        if let Some(wildcard) = sources.get(1) {
            let mut duplicate = signature(owner.clone(), 0, 1, ClassType::IN, 900);
            records.insert(0, duplicate.clone());
            duplicate.name = wildcard.clone();
            duplicate.ttl = 999;
            records.push(duplicate);
        }
        records.push(signature(
            name(&["unrelated", "elsewhere"]),
            0,
            1,
            ClassType::IN,
            901,
        ));
        for reverse in [false, true] {
            let mut snapshot = records.clone();
            if reverse {
                snapshot.reverse();
            }
            // Private builder intentionally exercises odd fields/classes that
            // public admission may reject, without weakening admission itself.
            let zone = Zone::new(DomainName::root(), ClassType::IN, snapshot, soa());
            let first = record(owner.clone(), RecordType::A, RData::A(Ipv4Addr::LOCALHOST));
            let mut second = first.clone();
            second.ttl = 7;
            let third = record(
                owner.clone(),
                RecordType::TXT,
                RData::TXT(vec![b"data".to_vec()]),
            );
            compare(&zone, &[first.clone(), second, third]);
            let mut prepopulated = vec![first];
            reference(&zone, &mut prepopulated);
            if let Some(sig) = prepopulated.get_mut(1) {
                sig.ttl = 3;
            }
            compare(&zone, &prepopulated);
        }
    }
}

#[test]
fn signatures_follow_the_selected_source_for_exact_wildcard_and_cname_answers() {
    fn add_pair(records: &mut Vec<ResourceRecord>, owner: &DomainName, covered: u16, tag: u16) {
        let labels = (owner.as_ref().len()
            - usize::from(
                owner
                    .as_ref()
                    .first()
                    .is_some_and(|label| label.as_slice() == b"*"),
            )) as u8;
        let first = signature(owner.clone(), labels, covered, ClassType::IN, tag);
        let mut second = signature(owner.clone(), labels, covered, ClassType::IN, tag + 1);
        if let RData::RRSIG(sig) = &mut second.rdata {
            sig.algorithm = 13;
        }
        records.extend([first.clone(), second, first]);
    }

    fn tags(records: impl IntoIterator<Item = ResourceRecord>) -> Vec<u16> {
        records
            .into_iter()
            .filter_map(|record| match record.rdata {
                RData::RRSIG(sig) => Some(sig.key_tag),
                _ => None,
            })
            .collect()
    }

    let apex = name(&["example"]);
    let exact = name(&["www", "example"]);
    let ancestor = name(&["*", "example"]);
    let wildcard = name(&["*", "wild", "example"]);
    let mut records = vec![
        record(exact.clone(), RecordType::A, RData::A(Ipv4Addr::LOCALHOST)),
        record(
            ancestor.clone(),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ),
        record(
            ancestor.clone(),
            RecordType::TXT,
            RData::TXT(vec![b"ancestor".to_vec()]),
        ),
        record(
            wildcard.clone(),
            RecordType::TXT,
            RData::TXT(vec![b"selected".to_vec()]),
        ),
    ];
    add_pair(&mut records, &ancestor, 1, 30);
    add_pair(&mut records, &ancestor, 16, 40);
    add_pair(&mut records, &exact, 1, 10);
    add_pair(&mut records, &wildcard, 16, 20);
    let zone = Zone::new(apex.clone(), ClassType::IN, records, soa());
    for (owner, qtype, expected) in [
        (exact.clone(), QueryType::A, vec![10, 11]),
        (
            name(&["m", "wild", "example"]),
            QueryType::TXT,
            vec![20, 21],
        ),
        (
            name(&["p", "q", "wild", "example"]),
            QueryType::TXT,
            vec![20, 21],
        ),
        (wildcard.clone(), QueryType::TXT, vec![20, 21]),
    ] {
        let question = Question {
            qname: owner,
            qtype,
            qclass: QClassType::Class(ClassType::IN),
        };
        let Lookup::Answer(mut structured) = zone.lookup(&question) else {
            panic!("answer expected")
        };
        zone.append_rrsigs_for(&mut structured);
        assert_eq!(tags(structured), expected);
        let super::super::positive::InitialLookup::Positive(selection) =
            zone.lookup_initial(&question)
        else {
            panic!("borrowed answer expected")
        };
        let mut borrowed = selection.references();
        zone.append_positive_rrsig_refs(&mut borrowed, selection.source_indices());
        let borrowed = borrowed.into_iter().map(|(record, _)| record.clone());
        assert_eq!(tags(borrowed), expected);
    }

    // ANY and explicit RRSIG queries already contain the source signatures.
    for qtype in [QueryType::ANY, QueryType::RRSIG] {
        let question = Question {
            qname: name(&["m", "wild", "example"]),
            qtype,
            qclass: QClassType::Class(ClassType::IN),
        };
        let super::super::positive::InitialLookup::Positive(selection) =
            zone.lookup_initial(&question)
        else {
            panic!("borrowed answer expected")
        };
        let mut borrowed = selection.references();
        zone.append_positive_rrsig_refs(&mut borrowed, selection.source_indices());
        assert_eq!(
            tags(borrowed.into_iter().map(|(record, _)| record.clone())),
            vec![20, 21, 20]
        );
    }

    let cname_source = name(&["*", "alias", "example"]);
    let mut records = vec![
        record(
            ancestor.clone(),
            RecordType::CNAME,
            RData::CNAME(name(&["wrong", "example"])),
        ),
        record(
            cname_source.clone(),
            RecordType::CNAME,
            RData::CNAME(name(&["right", "example"])),
        ),
    ];
    add_pair(&mut records, &ancestor, 5, 50);
    add_pair(&mut records, &cname_source, 5, 60);
    let zone = Zone::new(apex, ClassType::IN, records, soa());
    let question = Question {
        qname: name(&["x", "alias", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let Lookup::Cname { mut records, .. } = zone.lookup(&question) else {
        panic!("CNAME expected")
    };
    zone.append_rrsigs_for(&mut records);
    assert_eq!(tags(records), vec![60, 61]);
}
