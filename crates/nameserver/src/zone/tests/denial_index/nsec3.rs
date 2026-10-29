use super::*;

#[test]
fn indexed_denials_match_original_proofs_and_wire_order() {
    for opt_out in [false, true] {
        for iterations in [0, 2] {
            for single in [false, true] {
                let records = ring(opt_out, iterations, single);
                assert!(zone(records.clone(), soa()).nsec3_index.is_some());
                assert_equivalent(records);
            }
        }
    }
}

#[test]
fn unsupported_mixed_duplicate_and_irregular_rings_retain_original_selection() {
    let records = ring(false, 0, false);
    let proof = records
        .iter()
        .position(|record| record.rtype == RecordType::NSEC3)
        .unwrap();
    for mutation in 0..9 {
        let mut changed = records.clone();
        if mutation == 0 {
            changed.push(changed[proof].clone());
        } else if mutation == 1 {
            changed.remove(proof);
        } else if mutation == 2 {
            changed[proof].name = name(&["INVALID", "example"]);
        } else {
            let RData::NSEC3(nsec3) = &mut changed[proof].rdata else {
                unreachable!()
            };
            match mutation {
                3 => nsec3.flags = 2,
                4 => nsec3.hash_algorithm = 2,
                5 => nsec3.salt = vec![7],
                6 => nsec3.iterations = 1,
                7 => nsec3.next_hashed_owner_name = vec![0; 20],
                8 => nsec3.next_hashed_owner_name = vec![0; 19],
                _ => unreachable!(),
            }
        }
        assert!(
            zone(changed.clone(), soa()).nsec3_index.is_none(),
            "mutation={mutation}"
        );
        assert_equivalent(changed);
    }
}

#[test]
fn opt_out_flags_may_differ_and_nsec3param_is_presence_only() {
    let mut records = ring(false, 0, false);
    let mut flagged = false;
    for record in &mut records {
        match &mut record.rdata {
            RData::NSEC3(nsec3) if !flagged => {
                nsec3.flags = 1;
                flagged = true;
            }
            RData::NSEC3PARAM(parameters) => {
                parameters.iterations = 7;
                parameters.salt = vec![9];
            }
            _ => {}
        }
    }
    assert!(zone(records.clone(), soa()).nsec3_index.is_some());
    assert_equivalent(records);
}

#[test]
fn invalid_matching_encloser_does_not_fall_back_to_an_ancestor() {
    let indexed = zone(ring(false, 0, false), soa());
    for owner in [
        name(&["x", "redirect", "example"]),
        name(&["x", "child", "example"]),
    ] {
        let response = indexed.negative_response_authorities(&owner, &owner, true, true);
        assert!(
            !response
                .iter()
                .any(|record| record.rtype == RecordType::NSEC3)
        );
    }
}

#[test]
fn uppercase_hash_owners_and_zone_case_preserve_selection() {
    let mut records = ring(true, 2, false);
    for record in &mut records {
        let mut labels = record.name.as_ref().to_vec();
        for label in &mut labels {
            label.make_ascii_uppercase();
        }
        record.name = DomainName::from_labels(labels).unwrap();
    }
    assert!(zone(records.clone(), soa()).nsec3_index.is_some());
    assert_equivalent(records);
}

#[test]
fn replacement_snapshots_rebuild_their_own_denial_index() {
    let apex = name(&["example"]);
    let old =
        Zone::from_dynamic_records(apex.clone(), ClassType::IN, ring(false, 0, false)).unwrap();
    let question = name(&["missing", "example"]);
    let before = encoded(&old.negative_response_authorities(&question, &question, true, true));
    let new = Zone::from_dynamic_records(apex, ClassType::IN, ring(true, 2, false)).unwrap();
    assert!(old.nsec3_index.is_some() && new.nsec3_index.is_some());
    assert_eq!(
        before,
        encoded(&old.negative_response_authorities(&question, &question, true, true))
    );
    assert_ne!(
        before,
        encoded(&new.negative_response_authorities(&question, &question, true, true))
    );
}
