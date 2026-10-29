//! Persistent DNSKEY material must retain both authentication and chain expiry.
use super::*;
use crate::{CacheEngineConfig, resolver::tests::external_backend::Backend};
use dns::ClassType;
use std::time::Duration;

#[derive(Default)]
struct DelayedCommit {
    inner: Backend,
    delay: std::sync::atomic::AtomicBool,
}

impl crate::CacheEngine for DelayedCommit {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: Option<&'a [u8]>,
        plan: &'a crate::CacheReadPlan,
    ) -> transport::BoxFuture<'a, std::io::Result<crate::CacheReadResult>> {
        self.inner.read(namespace, expected_revision, plan)
    }

    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        revision: &'a [u8],
        bytes: &'a crate::CacheMutationBatch,
    ) -> transport::BoxFuture<'a, std::io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            if self.delay.swap(false, std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2200)).await;
            }
            self.inner.apply(namespace, revision, bytes).await
        })
    }
}

#[tokio::test]
async fn external_key_selection_expires_while_commit_is_pending() {
    let (mut transport, anchor, _) = delegated_fixture();
    for record in &mut transport.ds.answers {
        record.ttl = 2;
    }
    let config = resolver(transport.clone(), anchor).config.clone();
    let backend = Arc::new(DelayedCommit::default());
    let resolver = Resolver::with_cache_engine(
        transport,
        config,
        CacheEngineConfig::new(backend.clone(), b"key-slow-commit".to_vec(), [12; 32]).unwrap(),
    );
    let zone = name(&["child", "example"]);
    resolver
        .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
        .await
        .unwrap();
    let key = super::super::key_cache::ZoneKey {
        zone,
        class: ClassType::IN,
        anchor: resolver.config.trust_anchors[0].name.clone(),
    };
    assert!(
        resolver
            .cached_authenticated_zone_backend(&key, super::super::key_cache::ValidationTime::now())
            .await
            .unwrap()
            .is_some(),
        "fixture must begin with a live cached chain"
    );
    backend
        .delay
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        resolver
            .cached_authenticated_zone_backend(&key, super::super::key_cache::ValidationTime::now())
            .await
            .unwrap()
            .is_none()
    );
    assert!(!backend.delay.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn external_authenticated_chain_is_reused_after_restart_and_expires() {
    let (mut transport, anchor, _) = delegated_fixture();
    // Only the parent DS dependency is short lived. Restoring the child keys
    // must retain this complete-chain limit rather than just their own TTL.
    for record in &mut transport.ds.answers {
        record.ttl = 1;
    }
    let requests = Arc::clone(&transport.requests);
    let config = resolver(transport.clone(), anchor).config.clone();
    let backend = Arc::new(Backend::default());
    let make = || {
        Resolver::with_cache_engine(
            transport.clone(),
            config.clone(),
            CacheEngineConfig::new(backend.clone(), b"authenticated".to_vec(), [9; 32]).unwrap(),
        )
    };
    let zone = name(&["child", "example"]);
    let first = make();
    first
        .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
        .await
        .unwrap();
    let before = requests.lock().unwrap().len();
    assert!(before >= 3);
    drop(first);
    let restarted = make();
    restarted
        .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
        .await
        .unwrap();
    assert_eq!(requests.lock().unwrap().len(), before);
    drop(restarted);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let expired = make();
    expired
        .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
        .await
        .unwrap();
    let requests = requests.lock().unwrap();
    assert!(requests.len() > before);
    assert!(
        requests[before..]
            .iter()
            .any(|request| request.questions[0].qtype == QueryType::DS)
    );
}

#[tokio::test]
async fn active_external_key_identities_survive_more_live_selections_than_cache_slots() {
    let (transport, anchor, _) = delegated_fixture();
    let mut config = resolver(transport.clone(), anchor).config.clone();
    config.cache_capacity = 2;
    let external = CacheEngineConfig::new(
        Arc::new(Backend::default()),
        b"identities".to_vec(),
        [11; 32],
    )
    .unwrap();
    // Active selections can exceed retained cache slots. They own their keys;
    // the identity index must retain only weak references, without silently
    // dropping a live identity and mistaking unchanged keys for a rollover.
    let filler = Arc::new((*trusted_keys()).clone());
    {
        let mut identities = external.key_identities.lock().unwrap();
        for value in 0u8..32 {
            identities.insert([value; 32], Arc::downgrade(&filler));
        }
    }
    let resolver = Resolver::with_cache_engine(transport, config, external);
    let zone = name(&["child", "example"]);
    let keys = match resolver
        .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
        .await
        .unwrap()
    {
        super::super::chain::ChainStatus::Secure { keys, .. } => keys,
        _ => panic!("fixture must authenticate"),
    };
    let selected = match resolver
        .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
        .await
        .unwrap()
    {
        super::super::chain::ChainStatus::Secure { keys, .. } => keys,
        _ => panic!("cached fixture must authenticate"),
    };
    assert!(Arc::ptr_eq(&keys, &selected));
    drop(filler);
    resolver
        .cache_transaction_for(
            &[crate::resolver::engine::zone(&zone, ClassType::IN)],
            |_| Ok(()),
        )
        .await
        .unwrap();
    assert!(
        resolver
            .cache_engine
            .as_ref()
            .unwrap()
            .key_identities
            .lock()
            .unwrap()
            .len()
            <= 2
    );
}
