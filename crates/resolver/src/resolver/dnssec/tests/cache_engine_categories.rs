//! Genuine resolution paths must offer every cache role to the public engine.
use super::{fixtures, negative::negative_fixture, support::name};
use crate::{
    CacheCategory, CacheEngine, CacheEngineConfig, CacheMutation, CacheMutationBatch,
    CacheReadPlan, CacheReadResult, CacheReadSet, Resolver, ResolverConfig,
};
use dns::{ClassType, Headers, Message, QueryType, RCode, RData, RecordType, ResourceRecord};
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use transport::{Transport, TransportError};

/// Independent no-store algorithm: never creates a snapshot or a native cache.
#[derive(Default)]
struct NoStore {
    state: Mutex<(u64, HashMap<CacheCategory, usize>)>,
}
impl NoStore {
    fn offered(&self, role: CacheCategory) -> usize {
        self.state
            .lock()
            .unwrap()
            .1
            .get(&role)
            .copied()
            .unwrap_or(0)
    }
    fn config(self: &Arc<Self>) -> CacheEngineConfig {
        CacheEngineConfig::new(self.clone(), b"all-roles".to_vec(), [31; 32]).unwrap()
    }
}
impl CacheEngine for NoStore {
    fn read<'a>(
        &'a self,
        _: &'a [u8],
        expected: Option<&'a [u8]>,
        _: &'a CacheReadPlan,
    ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>> {
        Box::pin(async move {
            let revision = self.state.lock().unwrap().0.to_be_bytes().to_vec();
            Ok(if expected.is_some_and(|old| old != revision) {
                CacheReadResult::Conflict
            } else {
                CacheReadResult::Read(CacheReadSet {
                    revision,
                    entries: vec![],
                })
            })
        })
    }
    fn apply<'a>(
        &'a self,
        _: &'a [u8],
        expected: &'a [u8],
        batch: &'a CacheMutationBatch,
    ) -> transport::BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            if expected != state.0.to_be_bytes() {
                return Ok(None);
            }
            for mutation in &batch.mutations {
                if let CacheMutation::Put(entry) = mutation {
                    *state.1.entry(entry.key.family.category).or_default() += 1;
                }
            }
            // All puts are declined. Mandatory removals already hold: no entry exists.
            state.0 = state.0.checked_add(1).unwrap();
            Ok(Some(state.0.to_be_bytes().to_vec()))
        })
    }
}

#[tokio::test]
async fn no_store_engine_controls_genuine_authenticated_keys_and_positive_answers() {
    let provider = Arc::new(NoStore::default());
    let (transport, anchor, q) = fixtures::signed_fixture(false);
    let requests = transport.requests.clone();
    let policy = fixtures::resolver(transport.clone(), anchor).config.clone();
    let resolver = Resolver::with_cache_engine(transport, policy, provider.config());
    for _ in 0..2 {
        assert!(resolver.resolve(q.clone()).await.unwrap().headers.ad);
    }
    assert!(provider.offered(CacheCategory::Positive) >= 2);
    assert!(provider.offered(CacheCategory::AuthenticatedKeys) >= 2);
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.questions[0].qtype == QueryType::DNSKEY)
            .count()
            >= 2,
        "declined authenticated keys must not survive in a core shadow store"
    );
}

#[tokio::test]
async fn no_store_engine_controls_genuine_negative_proofs() {
    let provider = Arc::new(NoStore::default());
    let (transport, anchor, q) = negative_fixture();
    let requests = transport.requests.clone();
    let policy = fixtures::resolver(transport.clone(), anchor).config.clone();
    let resolver = Resolver::with_cache_engine(transport, policy, provider.config());
    for _ in 0..2 {
        let reply = resolver.resolve(q.clone()).await.unwrap();
        assert!(reply.headers.ad);
        assert_eq!(reply.headers.rcode, RCode::NameError);
    }
    assert!(provider.offered(CacheCategory::Negative) >= 2);
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.questions[0].qtype == q.qtype)
            .count()
            >= 2
    );
}

#[tokio::test]
async fn no_store_engine_controls_real_bogus_failure_and_bad_threshold_state() {
    let provider = Arc::new(NoStore::default());
    let (transport, anchor, q) = fixtures::signed_fixture(true);
    let requests = transport.requests.clone();
    let policy = fixtures::resolver(transport.clone(), anchor).config.clone();
    let resolver = Resolver::with_cache_engine(transport, policy, provider.config());
    for _ in 0..3 {
        assert!(matches!(
            resolver.resolve(q.clone()).await,
            Err(crate::ResolveError::DnssecBogus(_))
        ));
    }
    assert!(provider.offered(CacheCategory::Bad) >= 3);
    assert!(provider.offered(CacheCategory::Failure) >= 3);
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.questions[0].qtype == q.qtype)
            .count()
            >= 3,
        "declined BAD and failure state must not suppress the next real acquisition"
    );
}

struct ReferralAuthority {
    requests: Arc<Mutex<Vec<SocketAddr>>>,
}
impl Transport for ReferralAuthority {
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(server);
            let first = server.ip() == Ipv4Addr::new(192, 0, 2, 53);
            let rr = |owner, rtype, rdata| ResourceRecord {
                name: owner,
                rtype,
                class: ClassType::IN,
                ttl: 300,
                rdata,
            };
            Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: !first,
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: if first {
                    vec![]
                } else {
                    vec![rr(
                        query.questions[0].qname.clone(),
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 8)),
                    )]
                },
                authorities: if first {
                    vec![rr(
                        name(&["child", "example"]),
                        RecordType::NS,
                        RData::NS(name(&["ns", "child", "example"])),
                    )]
                } else {
                    vec![]
                },
                additionals: if first {
                    vec![rr(
                        name(&["ns", "child", "example"]),
                        RecordType::A,
                        RData::A(Ipv4Addr::new(192, 0, 2, 54)),
                    )]
                } else {
                    vec![]
                },
            })
        })
    }
}

#[tokio::test]
async fn no_store_engine_controls_real_referral_admission_and_routing() {
    let provider = Arc::new(NoStore::default());
    let requests = Arc::new(Mutex::new(vec![]));
    let resolver = Resolver::with_cache_engine(
        ReferralAuthority {
            requests: requests.clone(),
        },
        ResolverConfig {
            root_servers: vec!["192.0.2.53:53".parse().unwrap()],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
        provider.config(),
    );
    for owner in ["one", "two"] {
        let q = dns::Question {
            qname: name(&[owner, "child", "example"]),
            qtype: QueryType::A,
            qclass: dns::QClassType::Class(ClassType::IN),
        };
        assert_eq!(resolver.resolve(q).await.unwrap().answers.len(), 1);
    }
    assert!(provider.offered(CacheCategory::Delegation) >= 2);
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.ip() == Ipv4Addr::new(192, 0, 2, 53))
            .count(),
        2,
        "provider-declined referrals must not become a retained native routing shortcut"
    );
}

use crate as resolver_api;

// Shared application provider also compiled as an external-crate integration test.
// These unit fixtures exercise a subset of its independent fault/eviction controls.
#[allow(dead_code)]
#[path = "../../../../tests/cache_engine/provider.rs"]
mod public_provider;

#[tokio::test]
async fn changed_anchor_and_validation_policy_cannot_reuse_previous_authenticated_entries() {
    let provider = Arc::new(public_provider::Provider::default());
    let (transport, anchor, q) = fixtures::signed_fixture(false);
    let requests = transport.requests.clone();
    let policy = fixtures::resolver(transport.clone(), anchor).config.clone();
    let engine =
        || CacheEngineConfig::new(provider.clone(), b"policy-switch".to_vec(), [37; 32]).unwrap();
    let original = Resolver::with_cache_engine(transport.clone(), policy.clone(), engine());
    assert!(original.resolve(q.clone()).await.unwrap().headers.ad);
    let before = requests.lock().unwrap().len();
    let (_, different_anchor, _) = negative_fixture();
    let mut changed = policy.clone();
    changed.trust_anchors = vec![different_anchor];
    let replacement = Resolver::with_cache_engine(transport.clone(), changed, engine());
    assert!(matches!(
        replacement.resolve(q.clone()).await,
        Err(crate::ResolveError::DnssecBogus(_))
    ));
    assert!(
        requests.lock().unwrap().len() > before,
        "new trust anchor must acquire and authenticate again"
    );
    let before = requests.lock().unwrap().len();
    let mut disabled = policy;
    disabled.trust_anchors.clear();
    let unvalidated = Resolver::with_cache_engine(transport, disabled, engine());
    assert!(!unvalidated.resolve(q).await.unwrap().headers.ad);
    assert!(requests.lock().unwrap().len() > before);
    assert_eq!(
        provider.namespace_count(),
        3,
        "trust policy must participate in entry namespace/seal binding"
    );
}

#[tokio::test]
async fn declined_refresh_lease_put_does_not_prevent_fresh_network_authentication() {
    let provider = Arc::new(public_provider::Provider::default());
    let (transport, anchor, _) = fixtures::signed_fixture(false);
    let zone = anchor.name.clone();
    let requests = transport.requests.clone();
    let policy = fixtures::resolver(transport.clone(), anchor).config.clone();
    let resolver = Resolver::with_cache_engine(
        transport,
        policy,
        CacheEngineConfig::new(provider.clone(), b"declined-refresh".to_vec(), [41; 32]).unwrap(),
    );
    let used = match resolver
        .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
        .await
        .unwrap()
    {
        super::super::chain::ChainStatus::Secure { keys, .. } => keys,
        _ => panic!("fixture must genuinely authenticate"),
    };
    let retained_key = provider
        .entries()
        .into_iter()
        .find(|e| e.key.family.category == CacheCategory::AuthenticatedKeys)
        .expect("fixture must retain a genuinely authenticated key");
    let before = requests
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.questions[0].qtype == QueryType::DNSKEY)
        .count();
    provider
        .no_store
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let refreshed = tokio::time::timeout(
        Duration::from_secs(5),
        resolver.refresh_authenticated_zone(&used),
    )
    .await
    .expect("refresh must not deadlock on an acquisition gate")
    .unwrap();
    assert!(
        refreshed.is_some(),
        "declining a refresh lease is not another live claim and cannot make cache writes necessary for DNSSEC"
    );
    let after = requests
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.questions[0].qtype == QueryType::DNSKEY)
        .count();
    assert_eq!(
        after,
        before + 1,
        "fresh chain must be authenticated over the transport despite declined storage"
    );
    assert!(
        provider
            .entries()
            .iter()
            .any(|entry| entry.key == retained_key.key && entry.value == retained_key.value),
        "declining lease/renewal puts must not unnecessarily remove otherwise live retained DNSKEY material"
    );
}
