//! Retained pre-borrowing selection algorithm, independent of lookup_initial.
use super::*;
use dns::IntoWire;

fn original_matches(record: &ResourceRecord, qtype: QueryType) -> bool {
    match qtype {
        QueryType::ANY => true,
        QueryType::MAILA => matches!(record.rtype, RecordType::MD | RecordType::MF),
        QueryType::MAILB => matches!(
            record.rtype,
            RecordType::MB | RecordType::MG | RecordType::MR
        ),
        other => u16::from(record.rtype) == u16::from(other),
    }
}

fn original_owner<'a>(
    records: impl Iterator<Item = &'a ResourceRecord> + Clone,
    qtype: QueryType,
    proof_owner: &DomainName,
) -> Lookup {
    let answers = records
        .clone()
        .filter(|record| original_matches(record, qtype))
        .cloned()
        .collect::<Vec<_>>();
    if !answers.is_empty() {
        return Lookup::Answer(answers);
    }
    let cnames = records
        .filter(|record| record.rtype == RecordType::CNAME)
        .cloned()
        .collect::<Vec<_>>();
    let target = cnames.iter().find_map(|record| match &record.rdata {
        RData::CNAME(target) => Some(target.clone()),
        _ => None,
    });
    if let Some(target) = target {
        Lookup::Cname {
            records: cnames,
            target,
        }
    } else {
        Lookup::NoData {
            proof_owner: proof_owner.clone(),
        }
    }
}

fn original(zone: &Zone, question: &Question) -> Lookup {
    if !zone.supports_class(question) {
        return Lookup::NoData {
            proof_owner: question.qname.clone(),
        };
    }
    if question.qtype.value() == 43 && zone.index.is_exact_delegation_cut(&question.qname) {
        let answers = zone
            .index
            .records_at(&question.qname)
            .into_iter()
            .flatten()
            .map(|&i| &zone.records[i])
            .filter(|record| original_matches(record, question.qtype))
            .cloned()
            .collect::<Vec<_>>();
        return if answers.is_empty() {
            Lookup::NoData {
                proof_owner: question.qname.clone(),
            }
        } else {
            Lookup::Answer(answers)
        };
    }
    if let Some(records) = zone.delegation(&question.qname) {
        return Lookup::Referral(records);
    }
    if let Some(indices) = zone.index.records_at(&question.qname) {
        return original_owner(
            indices.iter().map(|&i| &zone.records[i]),
            question.qtype,
            &question.qname,
        );
    }
    if zone.node_exists(&question.qname) {
        return Lookup::NoData {
            proof_owner: question.qname.clone(),
        };
    }
    let Some((wildcard, indices)) = zone.wildcard_records_at_closest_encloser(&question.qname)
    else {
        return Lookup::NameError;
    };
    // The original algorithm cloned/expanded the complete source first.
    let expanded = indices
        .iter()
        .map(|&i| {
            let mut record = zone.records[i].clone();
            record.name = question.qname.clone();
            record
        })
        .collect::<Vec<_>>();
    original_owner(expanded.iter(), question.qtype, &wildcard)
}

fn assert_same(actual: Lookup, expected: Lookup) {
    let wire = |records: &[ResourceRecord]| {
        records
            .iter()
            .map(|record| record.into_wire())
            .collect::<Vec<_>>()
    };
    match (actual, expected) {
        (Lookup::Answer(a), Lookup::Answer(b)) | (Lookup::Referral(a), Lookup::Referral(b)) => {
            assert_eq!(wire(&a), wire(&b))
        }
        (
            Lookup::Cname {
                records: a,
                target: at,
            },
            Lookup::Cname {
                records: b,
                target: bt,
            },
        ) => {
            assert_eq!(wire(&a), wire(&b));
            assert_eq!(at.as_ref(), bt.as_ref());
        }
        (Lookup::NoData { proof_owner: a }, Lookup::NoData { proof_owner: b }) => {
            assert_eq!(a.as_ref(), b.as_ref())
        }
        (Lookup::NameError, Lookup::NameError) => {}
        _ => panic!("borrowed selector changed lookup kind"),
    }
}

#[test]
fn initial_selection_matches_retained_original_across_all_query_shapes() {
    for text in [
        include_str!("fixtures/bind-nsec.zone"),
        include_str!("fixtures/bind-nsec3.zone"),
    ] {
        let apex = DomainName::from_dotted("example.test.").unwrap();
        let zone =
            Zone::from_master(apex.clone(), MasterFile::parse(text, Some(apex)).unwrap()).unwrap();
        let mut names = zone
            .records
            .iter()
            .map(|r| r.name.clone())
            .collect::<Vec<_>>();
        for text in [
            "MiSsInG.example.test.",
            "m.wild.example.test.",
            "p.q.WILD.EXAMPLE.TEST.",
            "empty.example.test.",
            "child.example.test.",
            "x.child.example.test.",
            "outside.invalid.",
            ".",
        ] {
            names.push(DomainName::from_dotted(text).unwrap());
        }
        names.push(
            DomainName::from_labels(vec![
                vec![0, 255, b'A'],
                b"wild".to_vec(),
                b"example".to_vec(),
                b"test".to_vec(),
            ])
            .unwrap(),
        );
        for qname in names {
            for qtype in [
                QueryType::A,
                QueryType::AAAA,
                QueryType::CNAME,
                QueryType::TXT,
                QueryType::NS,
                QueryType::MX,
                QueryType::DS,
                QueryType::DNSKEY,
                QueryType::NSEC,
                QueryType::NSEC3,
                QueryType::RRSIG,
                QueryType::ANY,
                QueryType::MAILA,
                QueryType::MAILB,
                QueryType::AXFR,
                QueryType::IXFR,
                QueryType::Unknown(65280),
            ] {
                for qclass in [
                    QClassType::Class(ClassType::IN),
                    QClassType::Class(ClassType::CH),
                    QClassType::ANY,
                    QClassType::Unknown(65000),
                ] {
                    let question = Question {
                        qname: qname.clone(),
                        qtype,
                        qclass,
                    };
                    assert_same(zone.lookup(&question), original(&zone, &question));
                }
            }
        }
    }
}

#[test]
fn node_cursor_matches_old_probes_across_nested_cuts_ents_and_literal_wildcards() {
    let binary = DomainName::from_labels(vec![
        vec![0, 255, b'A'],
        b"wild".to_vec(),
        b"example".to_vec(),
    ])
    .unwrap();
    let maximum = DomainName::from_labels(vec![vec![b'A']; 127]).unwrap();
    for mask in 0..64 {
        let mut records = vec![soa()];
        let mut add = |owner, rtype, rdata| records.push(record(owner, rtype, rdata));
        if mask & 1 != 0 {
            add(
                name(&["*", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::LOCALHOST),
            );
        }
        if mask & 2 != 0 {
            add(
                name(&["*", "wild", "example"]),
                RecordType::CNAME,
                RData::CNAME(name(&["target", "example"])),
            );
        }
        if mask & 4 != 0 {
            add(
                name(&["leaf", "*", "empty", "example"]),
                RecordType::TXT,
                RData::TXT(vec![b"empty wildcard".to_vec()]),
            );
        }
        if mask & 8 != 0 {
            add(
                name(&["child", "example"]),
                RecordType::NS,
                RData::NS(name(&["ns", "child", "example"])),
            );
            add(name(&["child", "example"]), RecordType::DS, ds(1));
            add(
                name(&["child", "example"]),
                RecordType::CNAME,
                RData::CNAME(name(&["target", "example"])),
            );
        }
        if mask & 16 != 0 {
            add(
                name(&["grand", "child", "example"]),
                RecordType::NS,
                RData::NS(name(&["ns", "example"])),
            );
        }
        if mask & 32 != 0 {
            add(
                name(&["ns", "child", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::LOCALHOST),
            );
            add(
                name(&["leaf", "deep", "example"]),
                RecordType::TXT,
                RData::TXT(vec![b"ENT".to_vec()]),
            );
            add(binary.clone(), RecordType::A, RData::A(Ipv4Addr::LOCALHOST));
            add(
                maximum.clone(),
                RecordType::A,
                RData::A(Ipv4Addr::LOCALHOST),
            );
        }
        let zone = zone(records, soa());
        let mut names = [
            "example.",
            "*.example.",
            "m.example.",
            "wild.example.",
            "*.wild.example.",
            "p.q.WiLd.ExAmPlE.",
            "child.example.",
            "x.child.example.",
            "grand.child.example.",
            "x.grand.child.example.",
            "ns.child.example.",
            "empty.example.",
            "*.empty.example.",
            "x.empty.example.",
            "deep.example.",
            "x.deep.example.",
            "outside.invalid.",
            ".",
        ]
        .map(|s| DomainName::from_dotted(s).unwrap())
        .to_vec();
        names.extend([binary.clone(), maximum.clone()]);
        for qname in names {
            for qtype in [
                QueryType::A,
                QueryType::CNAME,
                QueryType::NS,
                QueryType::DS,
                QueryType::TXT,
                QueryType::RRSIG,
                QueryType::NSEC3,
                QueryType::ANY,
            ] {
                for qclass in [
                    QClassType::Class(ClassType::IN),
                    QClassType::Class(ClassType::CH),
                    QClassType::ANY,
                ] {
                    let question = Question {
                        qname: qname.clone(),
                        qtype,
                        qclass,
                    };
                    assert_same(zone.lookup(&question), original(&zone, &question));
                }
            }
        }
    }
}

#[test]
fn cursor_reuses_one_key_and_probes_each_suffix_and_wildcard_once() {
    let apex = DomainName::from_dotted("example.test.").unwrap();
    let zone = Zone::from_master(
        apex.clone(),
        MasterFile::parse(include_str!("fixtures/bind-nsec3.zone"), Some(apex)).unwrap(),
    )
    .unwrap();
    let question = Question {
        qname: DomainName::from_dotted("m.wild.example.test.").unwrap(),
        qtype: QueryType::TXT,
        qclass: QClassType::Class(ClassType::IN),
    };
    let ((old, old_keys), old_probes) = super::super::lookup::counted_probes(|| {
        crate::name::counted_keys(|| original(&zone, &question))
    });
    let ((new, new_keys), new_probes) = super::super::lookup::counted_probes(|| {
        crate::name::counted_keys(|| zone.lookup(&question))
    });
    assert_same(new, old);
    assert_eq!((old_keys, old_probes), (4, 11));
    assert_eq!((new_keys, new_probes), (1, 6));
}
