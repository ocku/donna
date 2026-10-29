use super::{AlgorithmSignals, Resolver};
use crate::{ResolveError, ResolverConfig};
use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use transport::{Transport, TransportError};

struct Authority {
    calls: Arc<AtomicUsize>,
    recovered: Arc<AtomicBool>,
}

impl Transport for Authority {
    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let failed =
                query.questions[0].qtype == QueryType::A && !self.recovered.load(Ordering::SeqCst);
            Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: !failed,
                    rcode: if failed {
                        RCode::ServerFailure
                    } else {
                        RCode::Ok
                    },
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: if failed {
                    vec![]
                } else if query.questions[0].qtype == QueryType::A {
                    vec![ResourceRecord {
                        name: query.questions[0].qname.clone(),
                        rtype: RecordType::A,
                        class: ClassType::IN,
                        ttl: 0,
                        rdata: RData::A("192.0.2.42".parse().unwrap()),
                    }]
                } else {
                    vec![ResourceRecord {
                        name: query.questions[0].qname.clone(),
                        rtype: RecordType::AAAA,
                        class: ClassType::IN,
                        ttl: 30,
                        rdata: RData::AAAA("2001:db8::1".parse().unwrap()),
                    }]
                },
                authorities: vec![],
                additionals: vec![],
            })
        })
    }
}

#[tokio::test]
async fn persistent_failure_backoff_and_recovery_in_memory_and_after_backend_restart() {
    use crate::{CacheEngineConfig, resolver::tests::external_backend::Backend};
    for external in [false, true] {
        let backend = Arc::new(Backend::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let recovered = Arc::new(AtomicBool::new(false));
        let make = || {
            let transport = Authority {
                calls: calls.clone(),
                recovered: recovered.clone(),
            };
            let config = ResolverConfig {
                root_servers: vec!["192.0.2.1:53".parse().unwrap()],
                cache_capacity: 8,
                ..ResolverConfig::default()
            };
            if external {
                Resolver::with_cache_engine(
                    transport,
                    config,
                    CacheEngineConfig::new(backend.clone(), b"backoff-restart".to_vec(), [23; 32])
                        .unwrap(),
                )
            } else {
                Resolver::new(transport, config)
            }
        };
        let resolver = make();
        assert_terminal_failure(resolver.resolve(question()).await, external);
        let initial = calls.load(Ordering::SeqCst);
        assert_terminal_failure(resolver.resolve(question()).await, external);
        assert_eq!(calls.load(Ordering::SeqCst), initial);

        // Reconstruct before the retry to verify the persisted interval/history.
        let restarted = if external { Some(make()) } else { None };
        let active = restarted.as_ref().unwrap_or(&resolver);
        assert_terminal_failure(
            retry_after_suppression(active, &calls, Duration::from_secs(1), external).await,
            external,
        );
        let second = calls.load(Ordering::SeqCst);
        assert!(second > initial);
        assert_terminal_failure(active.resolve(question()).await, external);
        assert_eq!(calls.load(Ordering::SeqCst), second);

        recovered.store(true, Ordering::SeqCst);
        let response = retry_after_suppression(active, &calls, Duration::from_secs(2), external)
            .await
            .unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(
            response.answers[0].rdata,
            RData::A("192.0.2.42".parse().unwrap())
        );
        assert!(
            failure_timing(active).await.is_none(),
            "success must remove old history"
        );

        recovered.store(false, Ordering::SeqCst);
        assert_terminal_failure(active.resolve(question()).await, external);
        let third = calls.load(Ordering::SeqCst);
        assert_terminal_failure(active.resolve(question()).await, external);
        assert_eq!(calls.load(Ordering::SeqCst), third);
        assert_terminal_failure(
            retry_after_suppression(active, &calls, Duration::from_secs(1), external).await,
            external,
        );
        assert!(calls.load(Ordering::SeqCst) > third);
    }
}

fn assert_terminal_failure(result: Result<Message, ResolveError>, external: bool) {
    let error = result.unwrap_err();
    assert!(
        matches!(error, ResolveError::TemporaryServerFailure),
        "external={external}: {error:?}"
    );
}

async fn failure_timing(resolver: &Resolver<Authority>) -> Option<(Duration, Instant)> {
    resolver
        .cache_select_for(&[question()], |context| {
            Ok(context.failure_cache.timing_for_test(&question(), false))
        })
        .await
        .unwrap()
}

async fn retry_after_suppression(
    resolver: &Resolver<Authority>,
    calls: &AtomicUsize,
    expected_interval: Duration,
    external: bool,
) -> Result<Message, ResolveError> {
    const RETRY_WAIT_LIMIT: Duration = Duration::from_secs(10);

    let before = calls.load(Ordering::SeqCst);
    let limit = Instant::now() + RETRY_WAIT_LIMIT;
    loop {
        let (interval, suppress_until) = failure_timing(resolver).await.unwrap();
        assert_eq!(interval, expected_interval, "external={external}");
        let now = Instant::now();
        assert!(
            now < limit,
            "external={external}, suppression never expired"
        );

        // Persisted deadlines use wall time across reconstruction. A VM clock
        // correction can move them relative to a fixed monotonic sleep, so wait
        // for the actual deadline while separately asserting the exact policy.
        tokio::time::sleep(
            suppress_until
                .saturating_duration_since(now)
                .min(limit - now),
        )
        .await;
        let result = resolver.resolve(question()).await;
        if calls.load(Ordering::SeqCst) > before {
            return result;
        }
        assert_terminal_failure(result, external);
    }
}

fn question() -> Question {
    Question {
        qname: DomainName::from_dotted("failure.example.").unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn resolver(capacity: usize) -> (Resolver<Authority>, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let recovered = Arc::new(AtomicBool::new(false));
    (
        Resolver::new(
            Authority {
                calls: calls.clone(),
                recovered: recovered.clone(),
            },
            ResolverConfig {
                root_servers: vec!["192.0.2.1:53".parse().unwrap()],
                cache_capacity: capacity,
                ..ResolverConfig::default()
            },
        ),
        calls,
        recovered,
    )
}

#[tokio::test]
async fn repeated_terminal_failure_is_cached_with_question_and_cd_scope() {
    let (resolver, calls, _) = resolver(8);
    assert!(matches!(
        resolver.resolve(question()).await,
        Err(ResolveError::TemporaryServerFailure)
    ));
    let first = calls.load(Ordering::SeqCst);
    assert!(resolver.resolve_with_stats(question()).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), first);
    assert!(
        resolver
            .resolve_with_algorithm_signals(question(), AlgorithmSignals::default(), true)
            .await
            .is_err()
    );
    assert!(calls.load(Ordering::SeqCst) > first);
    let cd = calls.load(Ordering::SeqCst);
    assert!(
        resolver
            .resolve_with_algorithm_signals(question(), AlgorithmSignals::default(), true)
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), cd);
    let mut other = question();
    other.qtype = QueryType::AAAA;
    assert!(resolver.resolve(other).await.is_ok());
    assert!(calls.load(Ordering::SeqCst) > cd);
}

#[tokio::test]
async fn explicit_zero_capacity_does_not_retain_terminal_failures() {
    let (resolver, calls, _) = resolver(0);
    assert!(resolver.resolve(question()).await.is_err());
    let first = calls.load(Ordering::SeqCst);
    assert!(resolver.resolve(question()).await.is_err());
    assert!(calls.load(Ordering::SeqCst) > first);
}

#[tokio::test]
async fn local_work_limit_is_not_cached() {
    let (mut resolver, calls, _) = resolver(8);
    resolver.config.max_steps = 0;
    assert!(matches!(
        resolver.resolve(question()).await,
        Err(ResolveError::WorkLimitExceeded)
    ));
    resolver.config.max_steps = 32;
    let mut other = question();
    other.qtype = QueryType::AAAA;
    assert!(resolver.resolve(other).await.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(resolver.failure_cache.get(&question(), false).is_none());
}

#[tokio::test]
async fn external_backend_retains_failure_across_resolver_reconstruction() {
    use crate::{CacheEngineConfig, resolver::tests::external_backend::Backend};
    let backend = Arc::new(Backend::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let recovered = Arc::new(AtomicBool::new(false));
    let policy = ResolverConfig {
        root_servers: vec!["192.0.2.1:53".parse().unwrap()],
        failure_ttl: Duration::from_secs(5),
        ..ResolverConfig::default()
    };
    let construct = || {
        Resolver::with_cache_engine(
            Authority {
                calls: calls.clone(),
                recovered: recovered.clone(),
            },
            policy.clone(),
            CacheEngineConfig::new(backend.clone(), b"failure-restart".to_vec(), [17; 32]).unwrap(),
        )
    };
    assert!(construct().resolve(question()).await.is_err());
    let first = calls.load(Ordering::SeqCst);
    let restarted = construct();
    assert!(restarted.resolve_with_stats(question()).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), first);
    assert!(
        restarted
            .resolve_with_algorithm_signals(question(), AlgorithmSignals::default(), true)
            .await
            .is_err()
    );
    assert!(
        calls.load(Ordering::SeqCst) > first,
        "CD must not inherit the validating failure"
    );
}

struct HandshakeFailure {
    calls: Arc<AtomicUsize>,
    kind: std::io::ErrorKind,
    healthy: Option<SocketAddr>,
}

impl Transport for HandshakeFailure {
    fn protocol(&self) -> Option<transport::TransportProtocol> {
        Some(transport::TransportProtocol::Tls)
    }
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.healthy == Some(server) {
                return Ok(Message {
                    headers: Headers {
                        id: query.headers.id,
                        qr: true,
                        aa: true,
                        ..Headers::default()
                    },
                    questions: query.questions.clone(),
                    answers: vec![ResourceRecord {
                        name: query.questions[0].qname.clone(),
                        rtype: RecordType::A,
                        class: ClassType::IN,
                        ttl: 30,
                        rdata: RData::A("192.0.2.1".parse().unwrap()),
                    }],
                    authorities: vec![],
                    additionals: vec![],
                });
            }
            Err(TransportError::Io(std::io::Error::new(
                self.kind,
                "fixture handshake failure",
            )))
        })
    }
}

#[tokio::test]
async fn remote_tls_invalid_data_is_cached_but_local_input_and_resource_errors_are_not() {
    for kind in [
        std::io::ErrorKind::InvalidData,
        std::io::ErrorKind::InvalidInput,
        std::io::ErrorKind::OutOfMemory,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::new(
            HandshakeFailure {
                calls: calls.clone(),
                kind,
                healthy: None,
            },
            ResolverConfig {
                root_servers: vec!["192.0.2.1:853".parse().unwrap()],
                ..ResolverConfig::default()
            },
        );
        for _ in 0..2 {
            let result = resolver.resolve(question()).await;
            if kind == std::io::ErrorKind::InvalidData {
                assert!(
                    matches!(result, Err(ResolveError::NoReachableServer)),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(ResolveError::Transport(_))),
                    "{result:?}"
                );
            }
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if kind == std::io::ErrorKind::InvalidData {
                1
            } else {
                2
            },
            "{kind:?}"
        );
    }
}

#[tokio::test]
async fn invalid_remote_tls_peer_preserves_sequential_and_racing_healthy_candidates() {
    for concurrency in [1, 2] {
        let good = "192.0.2.1:853".parse().unwrap();
        let bad = "192.0.2.2:853".parse().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::new(
            HandshakeFailure {
                calls: calls.clone(),
                kind: std::io::ErrorKind::InvalidData,
                healthy: Some(good),
            },
            ResolverConfig {
                root_servers: vec![good, bad],
                max_concurrent_queries: concurrency,
                ..ResolverConfig::default()
            },
        );
        assert_eq!(resolver.resolve(question()).await.unwrap().answers.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(resolver.failure_cache.get(&question(), false).is_none());
    }
}
