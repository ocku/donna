use super::*;
use dns::{ClassType, IntoWire, Nsec, TypeBitmap, master::MasterFile};

fn old_nodata<'a>(zone: &'a Zone, owner: &DomainName) -> Option<&'a ResourceRecord> {
    zone.nsecs()
        .find(|record| record.name.eq_dns(owner))
        .or_else(|| {
            zone.nsecs().find(|record| {
                matches!(&record.rdata, RData::NSEC(nsec)
            if !nsec.next_domain_name.eq_dns(owner)
                && nsec.next_domain_name.is_descendant_of(owner)
                && nsec.covers_name(&record.name, owner))
            })
        })
}

#[test]
fn direct_nsec_nodata_lookup_matches_original_scan_and_visibility() {
    let apex = DomainName::from_dotted("example.test.").unwrap();
    let parsed = Zone::from_master(
        apex.clone(),
        MasterFile::parse(
            include_str!("../../tests/fixtures/bind-nsec.zone"),
            Some(apex.clone()),
        )
        .unwrap(),
    )
    .unwrap();
    let binary = DomainName::from_labels(vec![
        vec![0, 255, b'A'],
        b"example".to_vec(),
        b"test".to_vec(),
    ])
    .unwrap();
    let mut labels = vec![vec![b'A']; 120];
    labels.extend([b"example".to_vec(), b"test".to_vec()]);
    let maximum = DomainName::from_labels(labels).unwrap();
    let mut owners: Vec<_> = [
        "example.test.",
        "www.example.test.",
        "empty.example.test.",
        "deep.empty.example.test.",
        "leaf.deep.empty.example.test.",
        "missing.example.test.",
        "child.example.test.",
        "hidden.child.example.test.",
        "*.wild.example.test.",
        "m.wild.example.test.",
        "WWW.Example.TEST.",
        ".",
    ]
    .into_iter()
    .map(|s| DomainName::from_dotted(s).unwrap())
    .collect();
    owners.extend([binary.clone(), maximum.clone()]);
    for irregular in [false, true] {
        let mut records = parsed.records.clone();
        if irregular {
            for owner in [
                binary.clone(),
                maximum.clone(),
                DomainName::from_dotted("hidden.child.example.test.").unwrap(),
            ] {
                for class in [ClassType::CH, ClassType::IN, ClassType::IN] {
                    records.push(ResourceRecord {
                        name: owner.clone(),
                        rtype: RecordType::NSEC,
                        class,
                        ttl: 30,
                        rdata: RData::NSEC(Nsec {
                            next_domain_name: apex.clone(),
                            type_bitmap: TypeBitmap::new([16, 46, 47]).unwrap(),
                        }),
                    });
                }
            }
            // A wrong-class record preceding an actual exact owner cannot
            // shadow its eligible record; duplicates retain the first source.
            let mut wrong = records
                .iter()
                .find(|r| r.rtype == RecordType::NSEC)
                .unwrap()
                .clone();
            wrong.class = ClassType::CH;
            records.insert(0, wrong);
        }
        for reverse in [false, true] {
            let mut source = records.clone();
            if reverse {
                source.reverse();
            }
            let zone = Zone::new(apex.clone(), ClassType::IN, source, parsed.soa.clone());
            for owner in &owners {
                let expected = old_nodata(&zone, owner).into_iter().collect::<Vec<_>>();
                let actual = zone.nsec_proof_refs(owner, false);
                assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                assert_eq!(
                    actual
                        .iter()
                        .map(|r| r.into_wire().unwrap())
                        .collect::<Vec<_>>(),
                    expected
                        .iter()
                        .map(|r| r.into_wire().unwrap())
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}
