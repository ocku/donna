use super::*;
use dns::{IntoWire, master::MasterFile};

// Independent reference for the former per-query SOA/SIG/RRSIG selection.
fn reference(zone: &Zone, dnssec_ok: bool) -> Vec<ResourceRecord> {
    let mut soa = zone.soa.clone();
    let RData::SOA { minimum, .. } = soa.rdata else {
        unreachable!()
    };
    soa.ttl = soa.ttl.min(minimum);
    let ttl = soa.ttl;
    let mut records = vec![soa];
    for modern in [false, true] {
        if modern && !dnssec_ok {
            continue;
        }
        for record in &zone.records {
            let covered = match &record.rdata {
                RData::SIG(sig) if !modern && record.rtype == RecordType::SIG => sig.type_covered,
                RData::RRSIG(sig) if modern && record.rtype == RecordType::RRSIG => {
                    sig.type_covered
                }
                _ => continue,
            };
            if record.class == zone.class && record.name.eq_dns(&zone.apex) && covered == 6 {
                let mut record = record.clone();
                record.ttl = record.ttl.min(ttl);
                records.push(record);
            }
        }
    }
    records
}

fn assert_prefix(zone: &Zone) {
    let qname = DomainName::from_dotted("missing.example.test.").unwrap();
    for dnssec_ok in [false, true] {
        let expected = reference(zone, dnssec_ok);
        let response = zone.negative_response_authorities(&qname, &qname, true, dnssec_ok);
        assert!(response.len() >= expected.len());
        for (actual, expected) in response.iter().zip(&expected) {
            assert_eq!(actual.into_wire().unwrap(), expected.into_wire().unwrap());
        }
        assert!(response[expected.len()..].iter().all(|record| !matches!(
            &record.rdata,
            RData::SIG(sig) if sig.type_covered == 6
        ) && !matches!(&record.rdata, RData::RRSIG(sig) if sig.type_covered == 6)));
    }
}

#[test]
fn negative_prefix_replacement_preserves_old_snapshot_and_rebuilds_trimmed_signatures() {
    for text in [
        include_str!("fixtures/bind-nsec.zone"),
        include_str!("fixtures/bind-nsec3.zone"),
    ] {
        let apex = DomainName::from_dotted("example.test.").unwrap();
        let old = Zone::from_master(
            apex.clone(),
            MasterFile::parse(text, Some(apex.clone())).unwrap(),
        )
        .unwrap();
        assert_prefix(&old);
        for minimum in [1, 17, 600] {
            let mut records = old.records.clone();
            for record in &mut records {
                if let RData::SOA {
                    minimum: value,
                    serial,
                    ..
                } = &mut record.rdata
                {
                    *value = minimum;
                    *serial += minimum;
                    record.ttl = 31;
                }
            }
            let mut modern = records
                .iter()
                .find(|record| {
                    matches!(
                        &record.rdata, RData::RRSIG(sig) if sig.type_covered == 6
                    )
                })
                .unwrap()
                .clone();
            modern.ttl = 7;
            modern.name = DomainName::from_dotted("EXAMPLE.test.").unwrap();
            let RData::RRSIG(sig) = &mut modern.rdata else {
                unreachable!()
            };
            sig.key_tag ^= 1;
            let legacy = ResourceRecord {
                rtype: RecordType::SIG,
                rdata: RData::SIG(dns::Sig {
                    type_covered: 6,
                    algorithm: sig.algorithm,
                    labels: sig.labels,
                    original_ttl: sig.original_ttl,
                    signature_expiration: sig.signature_expiration,
                    signature_inception: sig.signature_inception,
                    key_tag: sig.key_tag,
                    signer_name: sig.signer_name.clone(),
                    signature: sig.signature.clone(),
                }),
                ttl: 11,
                ..modern.clone()
            };
            // Interleave legacy/current signatures. Prefix order remains legacy first.
            records.insert(1, modern);
            records.push(legacy);
            let new = Zone::from_dynamic_records(apex.clone(), old.class, records).unwrap();
            assert_prefix(&new);
            assert_prefix(&old);
            assert_ne!(
                new.negative_response_authorities(&apex, &apex, false, false)[0].ttl,
                old.negative_response_authorities(&apex, &apex, false, false)[0].ttl
            );
        }
    }
}
