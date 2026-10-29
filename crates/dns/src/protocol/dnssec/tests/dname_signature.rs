use super::*;

fn fixture() -> (AuthenticatedDnskeySet, ResourceRecord, ResourceRecord) {
    let zone = name("example.test.");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let record = ResourceRecord {
        name: name("old.example.test."),
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::DNAME(name("destination.example.test.")),
    };
    let signature = sign_record(&record, &zone, &key, &private);
    (keys, record, signature)
}

fn equivalent(
    keys: &AuthenticatedDnskeySet,
    records: &[ResourceRecord],
    signatures: &[ResourceRecord],
    now: u32,
) {
    let ordinary = super::super::authentication::validate_rrset_with_keys(
        records,
        signatures,
        &keys.zone,
        &keys.records,
        now,
        None,
    );
    let cached = keys.validate_rrset(records, signatures, now);
    assert_eq!(format!("{cached:?}"), format!("{ordinary:?}"));
}

#[test]
fn warm_dname_rechecks_all_ttl_and_signature_time_bounds() {
    let (keys, record, signature) = fixture();
    assert!(keys.dname_signature.get().is_none());
    assert_eq!(
        keys.validate_rrset(
            std::slice::from_ref(&record),
            std::slice::from_ref(&signature),
            100
        )
        .status(),
        DnssecSecurityStatus::Secure
    );
    assert!(keys.dname_signature.get().unwrap().is_populated());
    assert!(!keys.soa_signature.is_populated());
    for now in [0, 100, 9_999, 10_000, 10_001, u32::MAX] {
        for ttl in [0, 1, 30, 3600] {
            for signature_ttl in [0, 7, 30, 3600] {
                let mut data = record.clone();
                let mut signed = signature.clone();
                data.ttl = ttl;
                signed.ttl = signature_ttl;
                equivalent(&keys, &[data], &[signed], now);
            }
        }
    }
}

#[test]
fn warm_dname_rejects_changed_records_and_signatures_and_preserves_order() {
    let (keys, record, signature) = fixture();
    equivalent(
        &keys,
        std::slice::from_ref(&record),
        std::slice::from_ref(&signature),
        100,
    );
    equivalent(&keys, &[], std::slice::from_ref(&signature), 100);
    equivalent(&keys, std::slice::from_ref(&record), &[], 100);
    let mut changed = record.clone();
    changed.rdata = RData::DNAME(name("different.example.test."));
    equivalent(&keys, &[changed], std::slice::from_ref(&signature), 100);
    let mut changed_owner = record.clone();
    changed_owner.name = name("different.example.test.");
    equivalent(
        &keys,
        &[changed_owner],
        std::slice::from_ref(&signature),
        100,
    );
    let mut wrong_class = record.clone();
    wrong_class.class = ClassType::CH;
    equivalent(&keys, &[wrong_class], std::slice::from_ref(&signature), 100);
    equivalent(
        &keys,
        &[record.clone(), record.clone()],
        std::slice::from_ref(&signature),
        100,
    );
    for mutation in 0..5 {
        let mut bad = signature.clone();
        let RData::RRSIG(sig) = &mut bad.rdata else {
            unreachable!()
        };
        match mutation {
            0 => sig.signature[0] ^= 1,
            1 => sig.original_ttl += 1,
            2 => sig.signature_inception = 200,
            3 => sig.labels += 1,
            _ => sig.signer_name = name("other.test."),
        }
        for sigs in [
            vec![bad.clone()],
            vec![bad.clone(), signature.clone()],
            vec![signature.clone(), bad],
        ] {
            equivalent(&keys, std::slice::from_ref(&record), &sigs, 100);
        }
    }
}

#[test]
fn warm_dname_binds_full_public_key_despite_key_tag_collision() {
    let (keys, record, signature) = fixture();
    assert_eq!(
        keys.validate_rrset(
            std::slice::from_ref(&record),
            std::slice::from_ref(&signature),
            100
        )
        .status(),
        DnssecSecurityStatus::Secure
    );
    let mut changed = keys.clone();
    let RData::DNSKEY(key) = &mut std::sync::Arc::make_mut(&mut changed.records)[0].rdata else {
        unreachable!()
    };
    let tag = key.key_tag();
    let original = key.public_key.clone();
    let other = (10..key.public_key.len())
        .step_by(2)
        .find(|&i| key.public_key[i] != key.public_key[8])
        .unwrap();
    key.public_key.swap(8, other);
    assert_eq!(key.key_tag(), tag);
    assert_ne!(key.public_key, original);
    equivalent(
        &changed,
        std::slice::from_ref(&record),
        std::slice::from_ref(&signature),
        100,
    );
    assert_eq!(
        changed
            .validate_rrset(&[record], &[signature], 100)
            .status(),
        DnssecSecurityStatus::Bogus
    );
}

#[test]
fn alternating_dnames_replace_only_their_single_bounded_slot() {
    let zone = name("example.test.");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let (a, b) = ("a.example.test.", "b.example.test.");
    let make = |owner: &str| ResourceRecord {
        name: name(owner),
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::DNAME(name("destination.example.test.")),
    };
    let first = make(a);
    let second = make(b);
    let first_sig = sign_record(&first, &zone, &key, &private);
    let second_sig = sign_record(&second, &zone, &key, &private);
    for (current, sig, prior, prior_sig) in [
        (&first, &first_sig, &second, &second_sig),
        (&second, &second_sig, &first, &first_sig),
        (&first, &first_sig, &second, &second_sig),
    ] {
        equivalent(
            &keys,
            std::slice::from_ref(current),
            std::slice::from_ref(sig),
            100,
        );
        let contains = |record: &ResourceRecord, record_sig: &ResourceRecord| {
            let RData::RRSIG(signature) = &record_sig.rdata else {
                unreachable!()
            };
            keys.dname_signature.get().unwrap().contains_exact(
                signature.algorithm,
                &key.public_key,
                &signature.signed_data(std::slice::from_ref(record)).unwrap(),
                &signature.signature,
            )
        };
        assert!(contains(current, sig));
        assert!(!contains(prior, prior_sig));
        assert!(!keys.soa_signature.is_populated());
    }
}

#[test]
fn concurrent_valid_and_forged_dnames_never_reuse_failure() {
    let zone = name("example.test.");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let data: Vec<_> = (0..4)
        .map(|i| {
            let record = ResourceRecord {
                name: name(&format!("n{i}.example.test.")),
                rtype: RecordType::DNAME,
                class: ClassType::IN,
                ttl: 30,
                rdata: RData::DNAME(name("destination.example.test.")),
            };
            let signature = sign_record(&record, &zone, &key, &private);
            (record, signature)
        })
        .collect();
    equivalent(
        &keys,
        std::slice::from_ref(&data[0].0),
        std::slice::from_ref(&data[0].1),
        100,
    );
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let keys = keys.clone();
            let data = &data;
            scope.spawn(move || {
                for step in 0..80 {
                    let (record, valid) = &data[(worker + step) % data.len()];
                    let mut signature = valid.clone();
                    if (worker + step) % 3 == 0 {
                        let RData::RRSIG(sig) = &mut signature.rdata else {
                            unreachable!()
                        };
                        sig.signature[0] ^= 1;
                    }
                    equivalent(&keys, std::slice::from_ref(record), &[signature], 100);
                }
            });
        }
    });
}

#[test]
fn reports_single_slot_object_size_for_memory_accounting() {
    println!(
        "OnceLock<Arc> inline: {} bytes; initialized SuccessfulSignatureCache object: {} bytes; Arc header: at least {} bytes; payload cap: 2560 bytes plus allocation overhead",
        std::mem::size_of::<
            std::sync::OnceLock<std::sync::Arc<crate::protocol::SuccessfulSignatureCache>>,
        >(),
        std::mem::size_of::<crate::protocol::SuccessfulSignatureCache>(),
        2 * std::mem::size_of::<usize>()
    );
}

#[test]
fn clones_before_initialization_are_independent_and_afterward_share() {
    let (keys, record, signature) = fixture();
    let before = keys.clone();
    assert!(keys.dname_signature.get().is_none());
    assert!(before.dname_signature.get().is_none());
    equivalent(
        &keys,
        std::slice::from_ref(&record),
        std::slice::from_ref(&signature),
        100,
    );
    let after = keys.clone();
    assert!(std::sync::Arc::ptr_eq(
        keys.dname_signature.get().unwrap(),
        after.dname_signature.get().unwrap()
    ));
    equivalent(
        &before,
        std::slice::from_ref(&record),
        std::slice::from_ref(&signature),
        100,
    );
    assert!(!std::sync::Arc::ptr_eq(
        keys.dname_signature.get().unwrap(),
        before.dname_signature.get().unwrap()
    ));
}

#[test]
fn concurrent_first_access_initializes_one_shared_slot() {
    let (keys, record, signature) = fixture();
    assert!(keys.dname_signature.get().is_none());
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                equivalent(
                    &keys,
                    std::slice::from_ref(&record),
                    std::slice::from_ref(&signature),
                    100,
                );
            });
        }
    });
    assert!(keys.dname_signature.get().unwrap().is_populated());
}

#[test]
fn bad_signature_never_populates_the_memo_before_or_after_valid_data() {
    let (keys, record, valid) = fixture();
    let mut bad = valid.clone();
    let RData::RRSIG(signature) = &mut bad.rdata else {
        unreachable!()
    };
    signature.signature[0] ^= 1;
    assert_eq!(
        keys.validate_rrset(
            std::slice::from_ref(&record),
            std::slice::from_ref(&bad),
            100
        )
        .status(),
        DnssecSecurityStatus::Bogus
    );
    assert!(!keys.dname_signature.get().unwrap().is_populated());
    assert_eq!(
        keys.validate_rrset(
            std::slice::from_ref(&record),
            std::slice::from_ref(&valid),
            100
        )
        .status(),
        DnssecSecurityStatus::Secure
    );
    assert!(keys.dname_signature.get().unwrap().is_populated());
    assert_eq!(
        keys.validate_rrset(&[record], &[bad], 100).status(),
        DnssecSecurityStatus::Bogus
    );
}

#[test]
fn external_dnskey_snapshot_excludes_the_mathematical_memo() {
    let (mut keys, record, signature) = fixture();
    keys.signature_expiration = 10_000;
    let secret = [7; 32];
    let before = keys
        .export_cache_material(&secret, b"test binding")
        .unwrap();
    equivalent(
        &keys,
        std::slice::from_ref(&record),
        std::slice::from_ref(&signature),
        100,
    );
    assert!(keys.dname_signature.get().unwrap().is_populated());
    let after = keys
        .export_cache_material(&secret, b"test binding")
        .unwrap();
    assert_eq!(before, after);
    let restored =
        AuthenticatedDnskeySet::import_cache_material(&after, &secret, b"test binding", 100)
            .unwrap();
    assert!(restored.dname_signature.get().is_none());
    equivalent(&restored, &[record], &[signature], 100);
}
