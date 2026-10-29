use super::*;
use dns::{IntoWire, master::MasterFile};

// Retain the previous eager expansion as an independent selection oracle.
fn eager_lookup(zone: &Zone, question: &Question) -> Lookup {
    let Some((_, indices)) = zone.wildcard_records_at_closest_encloser(&question.qname) else {
        return Lookup::NameError;
    };
    // Rebuild the original query-spelled wildcard independently, rather than
    // allowing the optimized source-owner selection to become its own oracle.
    let closest = zone.closest_encloser_labels(&question.qname).unwrap();
    let mut labels = vec![b"*".to_vec()];
    labels.extend_from_slice(closest);
    let wildcard = DomainName::from_labels(labels).unwrap();
    let expanded = indices
        .iter()
        .map(|&index| {
            let mut record = zone.records[index].clone();
            record.name = question.qname.clone();
            record
        })
        .collect::<Vec<_>>();
    zone.lookup_owner_records(expanded.iter(), question.qtype, &wildcard)
}

fn compare(zone: &Zone, question: &Question) {
    let wire =
        |records: &[ResourceRecord]| records.iter().map(|rr| rr.into_wire()).collect::<Vec<_>>();
    let (mut actual, mut expected) = (zone.lookup(question), eager_lookup(zone, question));
    match (&mut actual, &mut expected) {
        (Lookup::Answer(a), Lookup::Answer(b)) => {
            assert_eq!(wire(a), wire(b));
            // The positive DNSSEC selector sees expanded owners and original
            // RRSIG Labels, including an explicit RRSIG or ANY request.
            zone.append_rrsigs_for(a);
            zone.append_rrsigs_for(b);
            assert_eq!(wire(a), wire(b));
            let (mut aa, mut ba) = (vec![], vec![]);
            zone.append_wildcard_denial(a, &mut aa);
            zone.append_wildcard_denial(b, &mut ba);
            assert_eq!(wire(&aa), wire(&ba));
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
            assert_eq!(at.as_ref(), bt.as_ref());
            assert_eq!(wire(a), wire(b));
            zone.append_rrsigs_for(a);
            zone.append_rrsigs_for(b);
            assert_eq!(wire(a), wire(b));
        }
        (Lookup::NoData { proof_owner: a }, Lookup::NoData { proof_owner: b }) => {
            assert_eq!(a.as_ref(), b.as_ref());
            assert_eq!(
                wire(&zone.negative_response_authorities(a, &question.qname, false, true)),
                wire(&zone.negative_response_authorities(b, &question.qname, false, true))
            );
        }
        (Lookup::NameError, Lookup::NameError) => {}
        _ => panic!("selection changed for {:?}", question),
    }
}

fn compare_questions(zone: &Zone) {
    let mut names = vec![
        name(&["m", "wild", "example"]),
        name(&["p", "q", "WILD", "EXAMPLE"]),
        name(&["p", "q", "WiLd", "ExAmPlE"]),
        DomainName::from_labels(vec![
            vec![0, 255, b'A'],
            b"wild".to_vec(),
            b"example".to_vec(),
        ])
        .unwrap(),
        DomainName::from_labels(vec![
            vec![b'A'; 63],
            vec![0; 63],
            vec![255; 63],
            vec![b'Z'; 48],
            b"wild".to_vec(),
            b"example".to_vec(),
        ])
        .unwrap(),
    ];
    names.push(name(&["m", "*", "wild", "example"]));
    for qname in names {
        for qtype in [
            QueryType::A,
            QueryType::AAAA,
            QueryType::TXT,
            QueryType::CNAME,
            QueryType::RRSIG,
            QueryType::NSEC,
            QueryType::ANY,
            QueryType::MAILA,
            QueryType::MAILB,
            QueryType::Unknown(65280),
        ] {
            compare(
                zone,
                &Question {
                    qname: qname.clone(),
                    qtype,
                    qclass: QClassType::Class(ClassType::IN),
                },
            );
        }
    }
}

#[test]
fn selection_before_expansion_preserves_all_query_types_cnames_and_empty_sources() {
    for wildcard in [
        name(&["*", "wild", "example"]),
        name(&["*", "WiLd", "ExAmPlE"]),
    ] {
        for cname in [false, true] {
            let mut records = vec![record(
                wildcard.clone(),
                RecordType::TXT,
                RData::TXT(vec![vec![b'x'; 255], vec![b'y'; 255]]),
            )];
            for (rtype, rdata) in [
                (RecordType::A, RData::A(Ipv4Addr::LOCALHOST)),
                (RecordType::MB, RData::MB(name(&["mail", "example"]))),
                (RecordType::MD, RData::MD(name(&["old-mail", "example"]))),
                (RecordType::Unknown(65280), RData::Unknown(vec![255; 1024])),
            ] {
                records.push(record(wildcard.clone(), rtype, rdata));
            }
            if cname {
                records.push(record(
                    wildcard.clone(),
                    RecordType::CNAME,
                    RData::CNAME(name(&["Target", "example"])),
                ));
            }
            compare_questions(&zone(records, soa()));
        }
    }
    compare_questions(&zone(
        vec![record(
            name(&["leaf", "*", "wild", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::LOCALHOST),
        )],
        soa(),
    ));
}

#[test]
fn bind_signed_wildcards_keep_expanded_owners_signature_labels_and_denial_proofs() {
    for source in [
        include_str!("fixtures/bind-nsec.zone"),
        include_str!("fixtures/bind-nsec3.zone"),
    ] {
        let apex = DomainName::from_dotted("example.test.").unwrap();
        let zone = Zone::from_master(apex.clone(), MasterFile::parse(source, Some(apex)).unwrap())
            .unwrap();
        for text in ["m.wild.example.test.", "p.q.WILD.EXAMPLE.TEST."] {
            for qtype in [
                QueryType::TXT,
                QueryType::A,
                QueryType::ANY,
                QueryType::RRSIG,
                QueryType::CNAME,
            ] {
                compare(
                    &zone,
                    &Question {
                        qname: DomainName::from_dotted(text).unwrap(),
                        qtype,
                        qclass: QClassType::Class(ClassType::IN),
                    },
                );
            }
        }
    }
}
