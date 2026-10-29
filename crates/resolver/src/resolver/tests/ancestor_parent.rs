//! A locally busy NS provider must not discard an available parent alternative.
use super::{Resolver, ancestor::Hierarchy};
use crate::{ResolverConfig, protocol::Referral};
use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use transport::{Transport, TransportError, TransportProtocol};
fn name(s: &str) -> DomainName {
    DomainName::from_dotted(s).unwrap()
}
fn addr(n: u8) -> SocketAddr {
    format!("192.0.2.{n}:53").parse().unwrap()
}
struct Parents {
    healthy: Hierarchy,
    bad_calls: Arc<AtomicUsize>,
    all_busy: bool,
    fail_backend: Option<Arc<std::sync::atomic::AtomicBool>>,
}
impl Transport for Parents {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a Message,
        timeout: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            if server == addr(1) || (self.all_busy && server == addr(2)) {
                if let Some(fail) = &self.fail_backend {
                    fail.store(true, Ordering::SeqCst);
                }
                self.bad_calls.fetch_add(1, Ordering::SeqCst);
                return Ok(Message {
                    headers: Headers {
                        qr: true,
                        id: query.headers.id,
                        ..Headers::default()
                    },
                    questions: query.questions.clone(),
                    answers: vec![],
                    authorities: vec![ResourceRecord {
                        name: name("example.test."),
                        rtype: RecordType::NS,
                        class: ClassType::IN,
                        ttl: 300,
                        rdata: RData::NS(name("ns.blocked.test.")),
                    }],
                    additionals: vec![],
                });
            }
            self.healthy.exchange(server, query, timeout).await
        })
    }
}
#[tokio::test]
async fn busy_glueless_provider_does_not_cancel_an_already_available_parent_reply() {
    let healthy = Hierarchy::new();
    let bad_calls = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver::new(
        Parents {
            healthy: healthy.clone(),
            bad_calls: bad_calls.clone(),
            all_busy: false,
            fail_backend: None,
        },
        ResolverConfig {
            root_servers: vec![addr(2), addr(1)],
            max_concurrent_queries: 2,
            ..ResolverConfig::default()
        },
    );
    resolver.delegation_cache.insert(
        &Referral {
            zone: name("blocked.test."),
            class: ClassType::IN,
            candidates: vec![],
            candidate_ttls: vec![],
            trusted_glue: vec![],
            name_servers: vec![name("ns.blocked.test.")],
            ttl: Duration::from_secs(300),
        },
        Duration::from_secs(300),
    );
    resolver.delegation_cache.claim_refresh(
        &name("blocked.test."),
        ClassType::IN,
        false,
        Duration::from_secs(1),
    );
    let answer = resolver
        .resolve(Question {
            qname: name("www.example.test."),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        })
        .await
        .unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(bad_calls.load(Ordering::SeqCst), 1);
    assert!(healthy.snapshot().contains_key(&addr(2)) && healthy.snapshot().contains_key(&addr(3)));
}

fn query() -> Question {
    Question {
        qname: name("www.example.test."),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}
fn seed_busy<T: Transport>(resolver: &Resolver<T>) {
    resolver.delegation_cache.insert(
        &Referral {
            zone: name("blocked.test."),
            class: ClassType::IN,
            candidates: vec![],
            candidate_ttls: vec![],
            trusted_glue: vec![],
            name_servers: vec![name("ns.blocked.test.")],
            ttl: Duration::from_secs(300),
        },
        Duration::from_secs(300),
    );
    resolver.delegation_cache.claim_refresh(
        &name("blocked.test."),
        ClassType::IN,
        false,
        Duration::from_secs(1),
    );
}
#[tokio::test]
async fn all_deferred_parent_replies_return_noncacheable_coordination_error() {
    let resolver = Resolver::new(
        Parents {
            healthy: Hierarchy::new(),
            bad_calls: Arc::new(AtomicUsize::new(0)),
            all_busy: true,
            fail_backend: None,
        },
        ResolverConfig {
            root_servers: vec![addr(2), addr(1)],
            max_concurrent_queries: 2,
            ..ResolverConfig::default()
        },
    );
    seed_busy(&resolver);
    assert!(matches!(
        resolver.resolve(query()).await,
        Err(crate::ResolveError::DelegationRefreshInProgress)
    ));
    assert!(resolver.failure_cache.get(&query(), false).is_none());
}
#[tokio::test]
async fn accepted_parent_progress_discards_earlier_deferred_error_before_real_child_failure() {
    let healthy = Hierarchy::new();
    healthy.fail();
    let resolver = Resolver::new(
        Parents {
            healthy,
            bad_calls: Arc::new(AtomicUsize::new(0)),
            all_busy: false,
            fail_backend: None,
        },
        ResolverConfig {
            root_servers: vec![addr(2), addr(1)],
            max_concurrent_queries: 2,
            max_steps: 96,
            ..ResolverConfig::default()
        },
    );
    seed_busy(&resolver);
    let error = resolver.resolve(query()).await.unwrap_err();
    assert!(
        matches!(
            error,
            crate::ResolveError::NoReachableServer | crate::ResolveError::TemporaryServerFailure
        ),
        "{error:?}"
    );
    assert!(resolver.failure_cache.get(&query(), false).is_some());
}

struct FatalBackend {
    inner: crate::resolver::tests::external_backend::Backend,
    fail: Arc<std::sync::atomic::AtomicBool>,
}
impl crate::CacheEngine for FatalBackend {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: Option<&'a [u8]>,
        plan: &'a crate::CacheReadPlan,
    ) -> transport::BoxFuture<'a, std::io::Result<crate::CacheReadResult>> {
        crate::CacheEngine::read(&self.inner, namespace, expected_revision, plan)
    }
    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        expected: &'a [u8],
        value: &'a crate::CacheMutationBatch,
    ) -> transport::BoxFuture<'a, std::io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            if self.fail.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("fatal injected backend"));
            }
            crate::CacheEngine::apply(&self.inner, namespace, expected, value).await
        })
    }
}
#[tokio::test]
async fn fatal_backend_error_still_aborts_even_when_another_parent_reply_is_available() {
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let healthy = Hierarchy::new();
    let resolver = Resolver::with_cache_engine(
        Parents {
            healthy: healthy.clone(),
            bad_calls: Arc::new(AtomicUsize::new(0)),
            all_busy: false,
            fail_backend: Some(fail.clone()),
        },
        ResolverConfig {
            root_servers: vec![addr(2), addr(1)],
            max_concurrent_queries: 2,
            ..ResolverConfig::default()
        },
        crate::CacheEngineConfig::new(
            Arc::new(FatalBackend {
                inner: Default::default(),
                fail: fail.clone(),
            }),
            b"fatal-parent".to_vec(),
            [8; 32],
        )
        .unwrap(),
    );
    assert!(matches!(
        resolver.resolve(query()).await,
        Err(crate::ResolveError::CacheBackend(_))
    ));
    assert!(
        !healthy.snapshot().contains_key(&addr(2)),
        "healthy alternative must not hide a fatal backend failure"
    );
    fail.store(false, Ordering::SeqCst);
    assert!(
        resolver
            .cache_transaction_for(&[query()], |c| Ok(c
                .failure_cache
                .get(&query(), false)
                .is_none()))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn cached_ns_provider_failure_keeps_parent_alternatives_and_never_mints_parent_failure() {
    for all_busy in [false, true] {
        let resolver = Resolver::new(
            Parents {
                healthy: Hierarchy::new(),
                bad_calls: Arc::new(AtomicUsize::new(0)),
                all_busy,
                fail_backend: None,
            },
            ResolverConfig {
                root_servers: vec![addr(2), addr(1)],
                max_concurrent_queries: 2,
                ..ResolverConfig::default()
            },
        );
        for kind in [QueryType::A, QueryType::AAAA] {
            let dependency = Question {
                qname: name("ns.blocked.test."),
                qtype: kind,
                qclass: QClassType::Class(ClassType::IN),
            };
            resolver.failure_cache.insert(
                &dependency,
                false,
                crate::cache::failure::FailureKind::Server,
                Duration::from_secs(1),
            );
        }
        let result = resolver.resolve(query()).await;
        if all_busy {
            assert!(matches!(
                result,
                Err(crate::ResolveError::CachedNameServerFailure)
            ));
            assert!(
                resolver.failure_cache.get(&query(), false).is_none(),
                "a cached dependency cannot mint a fresh parent deadline"
            );
        } else {
            assert_eq!(result.unwrap().answers.len(), 1);
        }
    }
}
