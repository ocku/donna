use super::*;
use dns::master::MasterFile;

fn fixture() -> (MasterFile, DomainName, DomainName) {
    let apex = DomainName::from_dotted("example.test.").unwrap();
    let master =
        MasterFile::parse(include_str!("fixtures/bind-nsec3.zone"), Some(apex.clone())).unwrap();
    let hashed = master
        .records
        .iter()
        .find(|rr| {
            matches!(&rr.rdata, RData::NSEC3(nsec3)
        if nsec3.matches_name(&rr.name, &apex, &apex, 150).unwrap())
        })
        .unwrap()
        .name
        .clone();
    (master, apex, hashed)
}

fn beneath(owner: &DomainName, prefix: &[&str]) -> DomainName {
    let mut labels: Vec<Vec<u8>> = prefix
        .iter()
        .map(|label| label.as_bytes().to_vec())
        .collect();
    labels.extend_from_slice(owner.as_ref());
    DomainName::from_labels(labels).unwrap()
}

fn query(owner: DomainName, qtype: QueryType) -> Question {
    Question {
        qname: owner,
        qtype,
        qclass: QClassType::Class(ClassType::IN),
    }
}

#[test]
fn metadata_only_nsec3_owners_are_not_original_names_or_closest_enclosers() {
    let (master, apex, hashed) = fixture();
    let zone = Zone::from_master(apex, master).unwrap();
    for owner in [hashed.clone(), beneath(&hashed, &["missing"])] {
        for qtype in [
            QueryType::A,
            QueryType::RRSIG,
            QueryType::NSEC3,
            QueryType::ANY,
        ] {
            assert!(
                matches!(zone.lookup(&query(owner.clone(), qtype)), Lookup::NameError),
                "{owner:?} {qtype:?}"
            );
        }
        assert!(!zone.node_exists(&owner));
    }
}

#[test]
fn hidden_nsec3_owners_keep_complete_raw_proofs_and_signatures() {
    let (master, apex, hashed) = fixture();
    let original_count = master.records.len();
    let zone = Zone::from_master(apex, master).unwrap();
    assert_eq!(zone.records().len(), original_count);
    assert!(zone.records().iter().any(|rr| rr.name.eq_dns(&hashed)
        && matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == 50)));
    let authorities = zone.negative_response_authorities(&hashed, &hashed, true, true);
    let proofs: Vec<_> = authorities
        .iter()
        .filter(|rr| rr.rtype == RecordType::NSEC3)
        .collect();
    assert!(!proofs.is_empty());
    for proof in proofs {
        assert!(authorities.iter().any(|rr| rr.name.eq_dns(&proof.name)
            && matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == 50)));
    }
}

#[test]
fn ordinary_owner_data_and_descendants_preserve_original_existence() {
    for descendant in [false, true] {
        let (mut master, apex, hashed) = fixture();
        master.records.push(record(
            DomainName::from_dotted("*.example.test.").unwrap(),
            RecordType::A,
            RData::A("192.0.2.89".parse().unwrap()),
        ));
        let owner = if descendant {
            beneath(&hashed, &["leaf"])
        } else {
            hashed.clone()
        };
        master.records.push(record(
            owner,
            RecordType::A,
            RData::A("192.0.2.88".parse().unwrap()),
        ));
        let zone = Zone::from_master(apex, master).unwrap();
        assert!(zone.node_exists(&hashed));
        let lookup = zone.lookup(&query(hashed.clone(), QueryType::A));
        assert!(if descendant {
            matches!(lookup, Lookup::NoData { .. })
        } else {
            matches!(lookup, Lookup::Answer(_))
        });
        assert!(zone.records().iter().any(|rr| rr.name.eq_dns(&hashed)
            && matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == 50)));
        assert!(matches!(
            zone.lookup(&query(beneath(&hashed, &["missing"]), QueryType::A)),
            Lookup::NameError
        ));
    }
}

#[test]
fn hidden_metadata_does_not_block_apex_wildcard_at_owner_or_descendants() {
    let (mut master, apex, hashed) = fixture();
    master.records.push(record(
        DomainName::from_dotted("*.example.test.").unwrap(),
        RecordType::A,
        RData::A("192.0.2.89".parse().unwrap()),
    ));
    let zone = Zone::from_master(apex, master).unwrap();
    for owner in [
        hashed.clone(),
        beneath(&hashed, &["missing"]),
        beneath(&hashed, &["multi", "label"]),
    ] {
        let Lookup::Answer(answers) = zone.lookup(&query(owner.clone(), QueryType::A)) else {
            panic!("wildcard blocked at {owner:?}");
        };
        assert_eq!(answers.len(), 1);
        assert!(answers[0].name.eq_dns(&owner));
        assert_eq!(answers[0].rdata, RData::A("192.0.2.89".parse().unwrap()));
    }
}

#[test]
fn orphan_nsec3_signature_and_other_denial_data_do_not_disappear() {
    let (mut master, apex, hashed) = fixture();
    let mut orphan = master
        .records
        .iter()
        .find(|rr| matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == 50))
        .unwrap()
        .clone();
    let orphan_owner = DomainName::from_dotted("orphan.example.test.").unwrap();
    orphan.name = orphan_owner.clone();
    master.records.push(orphan);
    master.records.push(record(
        hashed.clone(),
        RecordType::NSEC,
        RData::NSEC(dns::Nsec {
            next_domain_name: DomainName::from_dotted("next.example.test.").unwrap(),
            type_bitmap: TypeBitmap::new([47]).unwrap(),
        }),
    ));
    let zone = Zone::from_master(apex, master).unwrap();
    assert!(matches!(
        zone.lookup(&query(orphan_owner, QueryType::RRSIG)),
        Lookup::Answer(_)
    ));
    assert!(zone.node_exists(&hashed));
    assert!(matches!(
        zone.lookup(&query(hashed, QueryType::NSEC)),
        Lookup::Answer(_)
    ));
}
