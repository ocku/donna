use super::*;

fn fixture() -> (AuthenticatedDnskeySet, ResourceRecord, ResourceRecord) {
    let zone = name("example.test.");
    let (keys, private, key) = authenticated_test_zone(&zone);
    let record = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::SOA,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::SOA {
            mname: name("ns.example.test."),
            rname: name("hostmaster.example.test."),
            serial: 1,
            refresh: 300,
            retry: 60,
            expire: 3600,
            minimum: 30,
        },
    };
    let signature = sign_record(&record, &zone, &key, &private);
    assert_eq!(
        keys.validate_rrset(
            std::slice::from_ref(&record),
            std::slice::from_ref(&signature),
            100
        )
        .status(),
        DnssecSecurityStatus::Secure
    );
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
fn warmed_soa_rechecks_time_and_recomputes_current_ttl_bounds() {
    let (keys, record, signature) = fixture();
    for now in [0, 100, 9_999, 10_000, 10_001, u32::MAX] {
        for ttl in [0, 1, 30, 3600] {
            for signature_ttl in [0, 7, 30, 3600] {
                let mut record = record.clone();
                record.ttl = ttl;
                let mut signature = signature.clone();
                signature.ttl = signature_ttl;
                equivalent(&keys, &[record], &[signature], now);
            }
        }
    }
}

#[test]
fn warmed_soa_rejects_modified_data_signatures_and_preserves_error_order() {
    let (keys, record, signature) = fixture();
    equivalent(&keys, &[], std::slice::from_ref(&signature), 100);
    equivalent(&keys, std::slice::from_ref(&record), &[], 100);
    let mut wrong_class = record.clone();
    wrong_class.class = ClassType::CH;
    equivalent(&keys, &[wrong_class], std::slice::from_ref(&signature), 100);
    let mut changed = record.clone();
    let RData::SOA { serial, .. } = &mut changed.rdata else {
        unreachable!()
    };
    *serial += 1;
    equivalent(&keys, &[changed], std::slice::from_ref(&signature), 100);
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
        equivalent(
            &keys,
            std::slice::from_ref(&record),
            std::slice::from_ref(&bad),
            100,
        );
        equivalent(
            &keys,
            std::slice::from_ref(&record),
            &[bad.clone(), signature.clone()],
            100,
        );
        equivalent(
            &keys,
            std::slice::from_ref(&record),
            &[signature.clone(), bad],
            100,
        );
    }
}

#[test]
fn warmed_soa_binds_full_public_key_despite_key_tag_collision() {
    let (keys, record, signature) = fixture();
    let mut changed = keys.clone(); // Deliberately shares the private memo.
    let RData::DNSKEY(key) = &mut std::sync::Arc::make_mut(&mut changed.records)[0].rdata else {
        unreachable!()
    };
    let tag = key.key_tag();
    let original = key.public_key.clone();
    // Exchanging same-parity octets preserves the RFC4034 additive key tag.
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
