use super::*;
use dns::master::MasterFile;

fn matches(records: &[ResourceRecord], apex: &DomainName, owner: &DomainName) -> bool {
    records.iter().any(|record| {
        matches!(&record.rdata, RData::NSEC3(nsec3)
            if nsec3.matches_name(&record.name, apex, owner, 150).unwrap())
    })
}

#[test]
fn signed_wildcard_answers_only_need_the_next_closer_nsec3_witness() {
    let source = include_str!("fixtures/bind-nsec3.zone");
    let apex = DomainName::from_dotted("example.test.").unwrap();
    let closest = DomainName::from_dotted("wild.example.test.").unwrap();
    let wildcard = DomainName::from_dotted("*.wild.example.test.").unwrap();
    for indexed in [false, true] {
        let mut zone = Zone::from_master(
            apex.clone(),
            MasterFile::parse(source, Some(apex.clone())).unwrap(),
        )
        .unwrap();
        if !indexed {
            zone.nsec3_index = None;
        }
        for (owner, next) in [
            ("m.wild.example.test.", "m.wild.example.test."),
            ("p.q.wild.example.test.", "q.wild.example.test."),
        ] {
            let expanded = DomainName::from_dotted(owner).unwrap();
            let next_closer = DomainName::from_dotted(next).unwrap();
            for qtype in [QueryType::TXT, QueryType::ANY] {
                let Lookup::Answer(mut answers) = zone.lookup(&Question {
                    qname: expanded.clone(),
                    qtype,
                    qclass: QClassType::Class(ClassType::IN),
                }) else {
                    panic!("fixture wildcard must answer {qtype:?}");
                };
                zone.append_rrsigs_for(&mut answers);
                let mut authorities = Vec::new();
                zone.append_wildcard_denial(&answers, &mut authorities);
                assert_eq!(
                    authorities
                        .iter()
                        .filter(|rr| rr.rtype == RecordType::NSEC3)
                        .count(),
                    1
                );
                assert!(authorities.iter().any(|rr| {
                    matches!(&rr.rdata, RData::NSEC3(nsec3)
                        if nsec3.covers_name(&rr.name, &apex, &next_closer, 150).unwrap())
                }));
                assert!(!matches(&authorities, &apex, &closest));
                assert!(authorities.iter().any(|rr| {
                    matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == 50)
                }));

                let mut foreign = answers.clone();
                for record in &mut foreign {
                    if let RData::RRSIG(sig) = &mut record.rdata {
                        sig.signer_name = DomainName::from_dotted("other.test.").unwrap();
                    }
                }
                let mut conservative = Vec::new();
                zone.append_wildcard_denial(&foreign, &mut conservative);
                assert!(matches(&conservative, &apex, &closest));

                // An unpaired signature is not evidence of an expanded RRset.
                answers.retain(|rr| rr.rtype == RecordType::RRSIG);
                let mut conservative = Vec::new();
                zone.append_wildcard_denial(&answers, &mut conservative);
                assert!(matches(&conservative, &apex, &closest));
            }
            // RFC 5155 section 7.2.5 still requires the full closest-encloser
            // proof and matching wildcard bitmap for an absent wildcard type.
            let nodata = zone.negative_response_authorities(&wildcard, &expanded, false, true);
            assert!(matches(&nodata, &apex, &closest));
            assert!(matches(&nodata, &apex, &wildcard));
        }
    }
}

// Use BIND's actual signatures, rather than synthetic RRSIG metadata, to
// establish that the reduced RFC 5155 section 7.2.6 proof remains verifiable.
#[test]
fn reduced_wildcard_nsec3_proofs_authenticate_and_reject_missing_or_tampered_witnesses() {
    let apex = DomainName::from_dotted("example.test.").unwrap();
    let file =
        MasterFile::parse(include_str!("fixtures/bind-nsec3.zone"), Some(apex.clone())).unwrap();
    let dnskeys = file
        .records
        .iter()
        .filter(|rr| rr.rtype == RecordType::DNSKEY)
        .cloned()
        .collect::<Vec<_>>();
    let anchor = dnskeys
        .iter()
        .find_map(|rr| match &rr.rdata {
            RData::DNSKEY(key) if key.flags == 257 => Some(key),
            _ => None,
        })
        .unwrap();
    // Fixture time is fixed so this cryptographic regression does not expire.
    let now = file
        .records
        .iter()
        .find_map(|rr| match &rr.rdata {
            RData::RRSIG(sig) if sig.type_covered == 48 => Some(sig.signature_inception + 1),
            _ => None,
        })
        .unwrap();
    let authenticated = dns::authenticate_dnskey_with_anchor(
        &apex,
        ClassType::IN,
        &dnskeys,
        &file.records,
        anchor,
        now,
    );
    let keys = authenticated
        .secure()
        .expect("BIND fixture DNSKEY must authenticate");
    let closest = DomainName::from_dotted("wild.example.test.").unwrap();
    for indexed in [false, true] {
        let mut zone = Zone::from_master(apex.clone(), file.clone()).unwrap();
        if !indexed {
            zone.nsec3_index = None;
        }
        for owner in ["m.wild.example.test.", "p.q.wild.example.test."] {
            let expanded = DomainName::from_dotted(owner).unwrap();
            let Lookup::Answer(mut answers) = zone.lookup(&Question {
                qname: expanded.clone(),
                qtype: QueryType::TXT,
                qclass: QClassType::Class(ClassType::IN),
            }) else {
                panic!("fixture wildcard must answer");
            };
            zone.append_rrsigs_for(&mut answers);
            let rrset = answers
                .iter()
                .filter(|rr| rr.rtype == RecordType::TXT)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                keys.validate_rrset(&rrset, &answers, now)
                    .secure()
                    .is_some()
            );
            let mut authorities = Vec::new();
            zone.append_wildcard_denial(&answers, &mut authorities);
            let mut witnesses = authorities
                .iter()
                .filter(|rr| rr.rtype == RecordType::NSEC3)
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(witnesses.len(), 1);
            let validate = |records: &[ResourceRecord], signatures: &[ResourceRecord]| {
                keys.validate_nsec3_wildcard_expansion(
                    &expanded, &closest, records, signatures, now, 150,
                )
                .secure()
                .is_some()
            };
            assert!(validate(&witnesses, &authorities));
            assert!(!validate(&[], &authorities));
            assert!(!validate(&witnesses, &[]));
            // Keep the covering interval intact while changing signed bytes.
            let RData::NSEC3(nsec3) = &mut witnesses[0].rdata else {
                unreachable!()
            };
            nsec3.type_bitmap = Some(TypeBitmap::new([1]).unwrap());
            assert!(!validate(&witnesses, &authorities));

            // The positive shortcut must not weaken wildcard NODATA: there
            // is no requested RRset to authenticate the closest encloser.
            let wildcard = DomainName::from_dotted("*.wild.example.test.").unwrap();
            let authorities = zone.negative_response_authorities(&wildcard, &expanded, false, true);
            let mut witnesses = authorities
                .iter()
                .filter(|rr| rr.rtype == RecordType::NSEC3)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                keys.validate_nsec3_nodata(
                    &expanded,
                    u16::from(RecordType::A),
                    &witnesses,
                    &authorities,
                    now,
                    150,
                )
                .secure()
                .is_some()
            );
            witnesses.retain(|record| {
                !matches!(&record.rdata, RData::NSEC3(nsec3)
                if nsec3.matches_name(&record.name, &apex, &closest, 150).unwrap())
            });
            assert!(
                !keys
                    .validate_nsec3_nodata(
                        &expanded,
                        u16::from(RecordType::A),
                        &witnesses,
                        &authorities,
                        now,
                        150,
                    )
                    .secure()
                    .is_some()
            );
        }
    }
}

#[test]
fn empty_nonterminal_wildcard_synthesizes_nodata_at_multiple_depths() {
    let wildcard = name(&["*", "emptywild", "example"]);
    let zone = zone(
        vec![record(
            name(&["leaf", "*", "emptywild", "example"]),
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )],
        soa(),
    );
    for labels in [
        vec!["m", "emptywild", "example"],
        vec!["p", "q", "emptywild", "example"],
    ] {
        for qtype in [QueryType::A, QueryType::TXT, QueryType::ANY] {
            assert!(matches!(zone.lookup(&Question {
                qname: name(&labels), qtype, qclass: QClassType::Class(ClassType::IN),
            }), Lookup::NoData { proof_owner } if proof_owner.eq_dns(&wildcard)));
        }
    }
}
