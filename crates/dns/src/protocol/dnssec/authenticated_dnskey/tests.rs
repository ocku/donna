use super::*;

fn fixture() -> AuthenticatedDnskeySet {
    let zone = DomainName::from_dotted("example.test.").unwrap();
    AuthenticatedDnskeySet {
        zone: zone.clone(),
        class: ClassType::IN,
        records: vec![ResourceRecord {
            name: zone,
            rtype: RecordType::DNSKEY,
            class: ClassType::IN,
            ttl: 300,
            rdata: RData::DNSKEY(Dnskey {
                flags: 256,
                protocol: 3,
                algorithm: 13,
                public_key: vec![1; 64],
            }),
        }]
        .into(),
        authenticated_ttl: 300,
        signature_expiration: 1000,
        soa_signature: Default::default(),
        dname_signature: Default::default(),
        denial_signatures: None,
    }
}

#[test]
fn dnskey_cache_bytes_match_ring_incremental_mac_and_preserve_authentication_policy() {
    let keys = fixture();
    let secret = [17; 32];
    for binding in [&[][..], b"tenant/policy".as_slice(), &[0xff; 129][..]] {
        let bytes = keys.export_cache_material(&secret, binding).unwrap();
        let (payload, tag) = bytes.split_at(bytes.len() - 32);
        let old_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret);
        let mut old = ring::hmac::Context::with_key(&old_key);
        old.update(b"donna authenticated DNSKEY cache v1\0");
        old.update(&(binding.len() as u64).to_be_bytes());
        old.update(binding);
        old.update(payload);
        assert_eq!(tag, old.sign().as_ref());
        let restored =
            AuthenticatedDnskeySet::import_cache_material(&bytes, &secret, binding, 100).unwrap();
        assert_eq!(
            restored.export_cache_material(&secret, binding).unwrap(),
            bytes
        );
        assert!(
            AuthenticatedDnskeySet::import_cache_material(&bytes, &[18; 32], binding, 100)
                .is_none()
        );
        assert!(
            AuthenticatedDnskeySet::import_cache_material(&bytes, &secret, b"wrong policy", 100)
                .is_none()
        );
        assert!(
            AuthenticatedDnskeySet::import_cache_material(&bytes, &secret, binding, 1000).is_none()
        );
        for index in [8, 16, bytes.len() - 1] {
            let mut bad = bytes.clone();
            bad[index] ^= 1;
            assert!(
                AuthenticatedDnskeySet::import_cache_material(&bad, &secret, binding, 100)
                    .is_none()
            );
        }
        for length in [0, 1, 31, 32, bytes.len() - 1] {
            assert!(
                AuthenticatedDnskeySet::import_cache_material(
                    &bytes[..length],
                    &secret,
                    binding,
                    100
                )
                .is_none()
            );
        }
    }
}

#[test]
fn scoped_denial_memo_shares_immutable_key_records_and_stays_out_of_export() {
    let original = fixture();
    let scoped = original.with_denial_validation_cache();
    assert!(std::sync::Arc::ptr_eq(&original.records, &scoped.records));
    assert!(std::sync::Arc::ptr_eq(
        &original.soa_signature,
        &scoped.soa_signature
    ));
    assert!(original.denial_signatures.is_none());
    assert!(scoped.denial_signatures.is_some());
    let secret = [17; 32];
    let binding = b"denial-scope";
    let bytes = scoped.export_cache_material(&secret, binding).unwrap();
    assert_eq!(
        bytes,
        original.export_cache_material(&secret, binding).unwrap()
    );
    let restored =
        AuthenticatedDnskeySet::import_cache_material(&bytes, &secret, binding, 100).unwrap();
    assert!(restored.denial_signatures.is_none());
    assert_eq!(restored.records().len(), original.records().len());
    assert!(
        restored
            .records()
            .iter()
            .zip(original.records())
            .all(|(a, b)| a.eq_dns(b) && a.ttl == b.ttl)
    );
    println!(
        "authenticated_keyset_bytes={}",
        std::mem::size_of::<AuthenticatedDnskeySet>()
    );
}
