use super::denial_index::ring;
use super::*;
use dns::IntoWire;

fn compare(zone: &Zone, qname: &DomainName) {
    let index = zone.nsec3_index.as_ref().unwrap();
    assert_eq!(
        index.matching_linked(qname, &zone.index),
        index.matching(qname)
    );
    let actual = index.closest_encloser_linked(&zone.apex, qname, &zone.index);
    let expected = index.closest_encloser(&zone.apex, qname);
    assert_eq!(actual, expected, "{qname:?}");
    let mut proofs = Vec::new();
    if let Some(proof) = expected {
        proofs.extend([proof.matching_record, proof.covering_record]);
        let mut labels = vec![b"*".to_vec()];
        labels.extend_from_slice(proof.closest_encloser.as_ref());
        let wildcard = DomainName::from_labels(labels).ok();
        if let Some(record) = wildcard.as_ref().and_then(|name| index.covering(name)) {
            proofs.push(record);
        }
    }
    assert_eq!(
        index
            .name_error_proof_indices(&zone.apex, qname, &zone.index)
            .as_slice(),
        proofs
    );
}

#[test]
fn linked_selection_matches_original_for_optout_invalid_enclosers_and_binary_names() {
    for opt_out in [false, true] {
        for iterations in [0, 2] {
            for single in [false, true] {
                let zone = zone(ring(opt_out, iterations, single), soa());
                for labels in [
                    vec![b"example".to_vec()],
                    vec![b"missing".to_vec(), b"ExAmPlE".to_vec()],
                    vec![
                        b"p".to_vec(),
                        b"q".to_vec(),
                        b"wild".to_vec(),
                        b"example".to_vec(),
                    ],
                    vec![b"x".to_vec(), b"empty".to_vec(), b"example".to_vec()],
                    vec![b"x".to_vec(), b"child".to_vec(), b"example".to_vec()],
                    vec![b"x".to_vec(), b"redirect".to_vec(), b"example".to_vec()],
                    vec![vec![0, 255, b'A'], b"EXAMPLE".to_vec()],
                    vec![b"outside".to_vec()],
                    vec![],
                ] {
                    compare(&zone, &DomainName::from_labels(labels).unwrap());
                }
                compare(
                    &zone,
                    &DomainName::from_labels(
                        [vec![vec![b'A']; 123], vec![b"example".to_vec()]].concat(),
                    )
                    .unwrap(),
                );
                for record in &zone.records {
                    compare(&zone, &record.name);
                }
            }
        }
    }
}

#[test]
fn metadata_replacement_preserves_old_snapshot_and_query_names_never_grow_it() {
    let old = zone(ring(false, 0, false), soa());
    let replacement = zone(ring(true, 2, false), soa());
    let usage = old.nsec3_index.as_ref().unwrap().metadata_usage();
    let question = name(&["missing", "example"]);
    let encoded = |zone: &Zone| {
        zone.negative_response_authorities(&question, &question, true, true)
            .iter()
            .map(|record| record.into_wire().unwrap())
            .collect::<Vec<_>>()
    };
    let before = encoded(&old);
    for i in 0..512 {
        compare(&old, &name(&[&format!("not-stored-{i}"), "example"]));
    }
    assert_eq!(old.nsec3_index.as_ref().unwrap().metadata_usage(), usage);
    assert_eq!(encoded(&old), before);
    assert_ne!(encoded(&replacement), before);
    let (nodes, node_bytes, slot_bytes) = old.index.metadata_slots();
    println!(
        "prelink resource profile: total_nodes={nodes} node_bytes={node_bytes} metadata_word_bytes={slot_bytes} linked_nodes={} metadata_capacity_bytes={}",
        usage.0, usage.1
    );
}
