//! Public-provider integration: no private cache stores or snapshot interface.
mod provider;
mod support;

use provider::Provider;
use resolver as resolver_api;
use resolver::{
    CacheCategory, CacheEngineConfig, CacheEntryFamily, CacheEntryKey, ResolveError, Resolver,
};
use std::sync::{Arc, atomic::Ordering};
use support::{Authority, config, question};

fn resolver(provider: Arc<Provider>, authority: Authority) -> Resolver<Authority> {
    Resolver::with_cache_engine(
        authority,
        config(),
        CacheEngineConfig::new(provider, b"public-provider".to_vec(), [19; 32]).unwrap(),
    )
}

#[tokio::test]
async fn public_provider_declines_admission_and_core_does_not_keep_a_shadow_answer() {
    let provider = Arc::new(Provider::default());
    provider.no_store.store(true, Ordering::SeqCst);
    let authority = Authority::default();
    let resolver = resolver(provider.clone(), authority.clone());
    for _ in 0..2 {
        let reply = resolver.resolve(question("www.example")).await.unwrap();
        assert_eq!(reply.answers.len(), 1);
    }
    assert_eq!(authority.requests.lock().unwrap().len(), 2);
    assert!(provider.entries().is_empty());
    assert!(provider.put_count(CacheCategory::Positive) >= 2);
}

#[tokio::test]
async fn public_provider_owns_restart_reuse_and_eviction() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    resolver(provider.clone(), authority.clone())
        .resolve(question("www.example"))
        .await
        .unwrap();
    assert_eq!(authority.requests.lock().unwrap().len(), 1);
    resolver(provider.clone(), authority.clone())
        .resolve(question("www.example"))
        .await
        .unwrap();
    assert_eq!(
        authority.requests.lock().unwrap().len(),
        1,
        "independent resolver must read caller-owned entries"
    );
    provider.clear();
    resolver(provider, authority.clone())
        .resolve(question("www.example"))
        .await
        .unwrap();
    assert_eq!(
        authority.requests.lock().unwrap().len(),
        2,
        "provider eviction must remove the only cached answer"
    );
}

#[tokio::test]
async fn corrupted_opaque_value_is_not_accepted_as_a_cache_hit() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    resolver(provider.clone(), authority.clone())
        .resolve(question("www.example"))
        .await
        .unwrap();
    provider.corrupt.store(true, Ordering::SeqCst);
    let result = resolver(provider, authority.clone())
        .resolve(question("www.example"))
        .await;
    assert!(matches!(result, Err(ResolveError::CacheBackend(_))));
    assert_eq!(
        authority.requests.lock().unwrap().len(),
        1,
        "invalid cache contents are an explicit provider error"
    );
}

#[tokio::test]
async fn public_metadata_cannot_move_an_authenticated_value_to_a_different_owner_or_expiry() {
    for change_owner in [false, true] {
        let provider = Arc::new(Provider::default());
        let authority = Authority::default();
        resolver(provider.clone(), authority.clone())
            .resolve(question("www.example"))
            .await
            .unwrap();
        let mut entry = provider
            .entries()
            .into_iter()
            .find(|e| e.key.family.category == CacheCategory::Positive)
            .unwrap();
        let target = if change_owner {
            "other.example"
        } else {
            "www.example"
        };
        if change_owner {
            use dns::IntoWire;
            entry.key.family.owner = support::name(target).into_wire().unwrap();
        } else {
            entry.expires_unix_nanos += 3_600_000_000_000;
        }
        provider.replace_entry(entry);
        let result = resolver(provider, authority)
            .resolve(question(target))
            .await;
        assert!(matches!(result, Err(ResolveError::CacheBackend(_))));
    }
}

#[test]
fn public_key_codec_preserves_category_class_binary_names_and_discriminators() {
    for category in [
        CacheCategory::Positive,
        CacheCategory::Negative,
        CacheCategory::Delegation,
        CacheCategory::Bad,
        CacheCategory::Failure,
        CacheCategory::AuthenticatedKeys,
    ] {
        let key = CacheEntryKey {
            family: CacheEntryFamily {
                category,
                owner: vec![3, 0, 128, 255, 0],
                class: 1,
            },
            discriminator: vec![0, 255, 0, 1],
        };
        let encoded = key.encode().unwrap();
        assert_eq!(CacheEntryKey::decode(&encoded).unwrap(), key);
        for length in 0..encoded.len() {
            assert!(CacheEntryKey::decode(&encoded[..length]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(CacheEntryKey::decode(&trailing).is_err());
    }
    let mut key = CacheEntryKey {
        family: CacheEntryFamily {
            category: CacheCategory::Positive,
            owner: vec![1, b'A', 0],
            class: 1,
        },
        discriminator: vec![],
    };
    assert!(key.encode().is_err(), "index owners must be canonical");
    key.family.owner = vec![0xc0, 0];
    assert!(
        key.encode().is_err(),
        "index keys cannot carry compressed DNS names"
    );
    key.family.owner = vec![0];
    key.discriminator = vec![0; 513];
    assert!(key.encode().is_err());
}

#[tokio::test]
async fn exact_hit_reads_only_the_requested_families_among_unrelated_entries() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    let resolver = resolver(provider.clone(), authority.clone());
    for index in 0..64 {
        resolver
            .resolve(question(&format!("owner{index}.example")))
            .await
            .unwrap();
    }
    assert_eq!(provider.namespace_count(), 1);
    assert!(provider.entries().len() >= 64);
    provider.read_keys.lock().unwrap().clear();
    resolver.resolve(question("owner0.example")).await.unwrap();
    assert_eq!(authority.requests.lock().unwrap().len(), 64);
    let reads = provider.read_keys.lock().unwrap();
    let returned: Vec<_> = reads.iter().flatten().collect();
    assert!(!returned.is_empty());
    assert!(returned.iter().all(|key| key.family.owner
        == vec![
            6, b'o', b'w', b'n', b'e', b'r', b'0', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0
        ]));
    assert!(
        reads.iter().all(|keys| keys.len() <= 2),
        "unrelated cache population must not be checked out"
    );
}

#[tokio::test]
async fn late_cname_dependency_reads_do_not_duplicate_access_accounting() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    let first = resolver(provider.clone(), authority.clone());
    let reply = first.resolve(question("alias.example")).await.unwrap();
    assert!(
        reply
            .answers
            .iter()
            .any(|rr| rr.rtype == dns::RecordType::CNAME)
    );
    assert_eq!(authority.requests.lock().unwrap().len(), 2);
    provider.accesses.lock().unwrap().clear();
    let before = provider.applies.load(Ordering::Relaxed);
    let repeated = resolver(provider.clone(), authority.clone())
        .resolve(question("alias.example"))
        .await
        .unwrap();
    assert_eq!(repeated.answers.len(), 2);
    assert_eq!(authority.requests.lock().unwrap().len(), 2);
    let accesses = provider.accesses.lock().unwrap();
    let positive: Vec<_> = accesses
        .iter()
        .filter(|(key, _)| key.family.category == CacheCategory::Positive)
        .collect();
    assert_eq!(
        positive.len(),
        2,
        "both alias and terminal selections must be accounted for"
    );
    assert!(
        positive.iter().all(|(_, count)| **count == 1),
        "read discovery or post-commit reselection must not publish another touch"
    );
    assert_eq!(
        provider.applies.load(Ordering::Relaxed) - before,
        1,
        "incomplete dependency readsets must never reach apply"
    );
}

#[tokio::test]
async fn negative_admission_is_also_optional_for_the_public_provider() {
    let provider = Arc::new(Provider::default());
    provider.no_store.store(true, Ordering::SeqCst);
    let authority = Authority::default();
    let resolver = resolver(provider.clone(), authority.clone());
    for _ in 0..2 {
        assert_eq!(
            resolver
                .resolve(question("missing.example"))
                .await
                .unwrap()
                .headers
                .rcode,
            dns::RCode::NameError
        );
    }
    assert_eq!(authority.requests.lock().unwrap().len(), 2);
    assert!(provider.put_count(CacheCategory::Negative) >= 2);
    assert!(provider.entries().is_empty());
}

#[tokio::test]
async fn expired_entries_returned_after_a_slow_provider_read_cannot_answer() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    authority.ttl.store(2, Ordering::Relaxed);
    let resolver = resolver(provider.clone(), authority.clone());
    resolver.resolve(question("short.example")).await.unwrap();
    assert_eq!(authority.requests.lock().unwrap().len(), 1);
    provider.read_delay_ms.store(2100, Ordering::SeqCst);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        resolver.resolve(question("short.example")),
    )
    .await
    .expect("provider/cache locks must not be held across await")
    .unwrap();
    assert_eq!(
        authority.requests.lock().unwrap().len(),
        2,
        "entry must be refreshed after it expires during await"
    );
}

#[tokio::test]
async fn wrong_entry_secret_cannot_reuse_a_different_resolvers_authenticated_values() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    resolver(provider.clone(), authority.clone())
        .resolve(question("www.example"))
        .await
        .unwrap();
    let other = Resolver::with_cache_engine(
        authority.clone(),
        config(),
        CacheEngineConfig::new(provider, b"public-provider".to_vec(), [20; 32]).unwrap(),
    );
    assert!(matches!(
        other.resolve(question("www.example")).await,
        Err(ResolveError::CacheBackend(_))
    ));
    assert_eq!(authority.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn apply_conflicts_do_not_publish_duplicate_access_effects() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    resolver(provider.clone(), authority.clone())
        .resolve(question("www.example"))
        .await
        .unwrap();
    provider.accesses.lock().unwrap().clear();
    provider.conflicts.store(3, Ordering::SeqCst);
    resolver(provider.clone(), authority.clone())
        .resolve(question("www.example"))
        .await
        .unwrap();
    assert_eq!(provider.conflicts.load(Ordering::SeqCst), 0);
    assert_eq!(authority.requests.lock().unwrap().len(), 1);
    let accesses = provider.accesses.lock().unwrap();
    let positive: Vec<_> = accesses
        .iter()
        .filter(|(key, _)| key.family.category == CacheCategory::Positive)
        .collect();
    assert_eq!(positive.len(), 1);
    assert_eq!(
        *positive[0].1, 1,
        "failed revisions must not accumulate policy/access effects"
    );
}

#[tokio::test]
async fn zero_capacity_disables_all_provider_io() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    let mut policy = config();
    policy.cache_capacity = 0;
    let resolver = Resolver::with_cache_engine(
        authority.clone(),
        policy,
        CacheEngineConfig::new(provider.clone(), b"disabled".to_vec(), [19; 32]).unwrap(),
    );
    for _ in 0..2 {
        resolver.resolve(question("www.example")).await.unwrap();
    }
    assert_eq!(authority.requests.lock().unwrap().len(), 2);
    assert!(provider.read_keys.lock().unwrap().is_empty());
    assert_eq!(provider.applies.load(Ordering::Relaxed), 0);
    assert_eq!(provider.namespace_count(), 0);
}

#[tokio::test]
async fn provider_eviction_during_apply_is_observed_before_returning_a_cache_hit() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    let resolver = resolver(provider.clone(), authority.clone());
    resolver.resolve(question("www.example")).await.unwrap();
    provider.evict_on_access.store(true, Ordering::SeqCst);
    resolver.resolve(question("www.example")).await.unwrap();
    assert_eq!(
        authority.requests.lock().unwrap().len(),
        2,
        "post-apply selection must use retained provider state, not staged pre-eviction data"
    );
}

#[tokio::test]
async fn entry_expiring_during_apply_is_not_returned_from_the_precommit_selection() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    authority.ttl.store(2, Ordering::Relaxed);
    let resolver = resolver(provider.clone(), authority.clone());
    resolver.resolve(question("short.example")).await.unwrap();
    provider.apply_delay_ms.store(2100, Ordering::SeqCst);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        resolver.resolve(question("short.example")),
    )
    .await
    .expect("apply must not hold a core cache/policy mutex across await")
    .unwrap();
    assert_eq!(
        authority.requests.lock().unwrap().len(),
        2,
        "a precommit live selection must expire while the provider is awaited"
    );
}

#[tokio::test]
async fn provider_retention_is_independent_of_nonzero_native_cache_capacity() {
    let provider = Arc::new(Provider::default());
    let authority = Authority::default();
    let mut policy = config();
    policy.cache_capacity = 1;
    let resolver = Resolver::with_cache_engine(
        authority.clone(),
        policy,
        CacheEngineConfig::new(provider.clone(), b"provider-capacity".to_vec(), [43; 32]).unwrap(),
    );
    for owner in ["one.example", "two.example", "three.example"] {
        resolver.resolve(question(owner)).await.unwrap();
    }
    assert_eq!(authority.requests.lock().unwrap().len(), 3);
    assert_eq!(
        provider
            .entries()
            .iter()
            .filter(|e| e.key.family.category == CacheCategory::Positive)
            .count(),
        3
    );
    for owner in ["three.example", "one.example", "two.example"] {
        resolver.resolve(question(owner)).await.unwrap();
    }
    assert_eq!(
        authority.requests.lock().unwrap().len(),
        3,
        "a nonzero native capacity must not impose a hidden eviction algorithm on the provider"
    );
}
