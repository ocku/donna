//! Exercise caller-owned persistence across independently constructed resolvers.
use super::*;
use crate::{CacheEngine, CacheEngineConfig, CacheReadResult};
use std::{io, sync::atomic::AtomicUsize};
mod provider;
pub(in crate::resolver) use provider::Backend;
mod admission_deadline;
mod ancestor_refresh;
mod cached_hit_deadlines;
mod cname_deadline;
mod failures;
mod ns_failures;
#[tokio::test]
async fn zero_cache_capacity_does_not_contact_an_unavailable_external_store() {
    let backend = Arc::new(Backend::default());
    backend.unavailable.store(true, Ordering::Relaxed);
    let query = question(&["disabled", "example"]);
    let mut policy = config(vec!["192.0.2.53:53".parse().unwrap()]);
    policy.cache_capacity = 0;
    let resolver = Resolver::with_cache_engine(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![address_record(query.qname.clone(), 8)],
            )])),
            requests: Arc::new(Mutex::new(Vec::new())),
        },
        policy,
        CacheEngineConfig::new(backend.clone(), b"disabled".to_vec(), [7; 32]).unwrap(),
    );
    assert_eq!(resolver.resolve(query).await.unwrap().answers.len(), 1);
    assert!(backend.values.lock().unwrap().is_empty());
}
fn external(backend: Arc<Backend>, replies: Vec<Message>) -> Resolver<MockTransport> {
    Resolver::with_cache_engine(
        MockTransport {
            replies: Arc::new(Mutex::new(replies)),
            requests: Arc::new(Mutex::new(Vec::new())),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
        CacheEngineConfig::new(backend, b"tests".to_vec(), [7; 32]).unwrap(),
    )
}

#[tokio::test]
async fn externally_cached_answer_survives_resolver_restart_without_upstream_io() {
    let backend = Arc::new(Backend::default());
    backend.conflicts.store(1, Ordering::Relaxed);
    let query = question(&["www", "example"]);
    let resolver = external(
        backend.clone(),
        vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 8)],
        )],
    );
    assert_eq!(
        resolver.resolve(query.clone()).await.unwrap().answers.len(),
        1
    );
    assert_eq!(resolver.transport.requests.lock().unwrap().len(), 1);
    // External mode must not silently keep an independent built-in answer copy.
    assert!(resolver.cached_positive_response(&query).is_none());
    drop(resolver);
    let restarted = external(backend, vec![]);
    let reply = restarted.resolve(query).await.unwrap();
    assert!(matches!(reply.answers[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 8)));
    assert!(reply.answers[0].ttl <= 60);
    assert!(restarted.transport.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn concurrent_external_transactions_preserve_bad_failure_admission() {
    let backend = Arc::new(Backend::default());
    let first = external(backend.clone(), vec![]);
    let second = external(backend.clone(), vec![]);
    let query = question(&["bad", "example"]);
    let (a, b) = tokio::join!(
        first.record_bad_backend(&query),
        second.record_bad_backend(&query)
    );
    a.unwrap();
    b.unwrap();
    let restarted = external(backend, vec![]);
    assert!(restarted.bad_contains_backend(&query).await.unwrap());
    assert!(!restarted.bad_cache.contains(&query));
}

#[tokio::test]
async fn external_negative_replaces_conflicting_positive_atomically() {
    let backend = Arc::new(Backend::default());
    let resolver = external(backend.clone(), vec![]);
    let query = question(&["gone", "example"]);
    let positive = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 1)],
    );
    resolver
        .cache_positive_entries_backend(0, &positive, &query)
        .await
        .unwrap();
    let mut negative = response(
        Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        vec![],
    );
    negative
        .authorities
        .push(soa_record(name(&["example"]), 60, 30));
    resolver
        .cache_response_entries_backend(0, &negative, &query, &query, true)
        .await
        .unwrap();
    let restarted = external(backend, vec![]);
    let reply = restarted.resolve(query).await.unwrap();
    assert_eq!(reply.headers.rcode, RCode::NameError);
    assert!(reply.answers.is_empty());
    assert!(
        reply
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::SOA)
    );
    assert!(restarted.transport.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn backend_failures_and_entry_tampering_fail_closed() {
    let backend = Arc::new(Backend::default());
    let resolver = external(backend.clone(), vec![]);
    let query = question(&["www", "example"]);
    resolver.record_bad_backend(&query).await.unwrap();
    {
        let mut values = backend.values.lock().unwrap();
        let (_, bytes) = values.values_mut().next().unwrap();
        bytes.values_mut().next().unwrap().value[12] ^= 1;
    }
    assert!(matches!(
        resolver.resolve(query.clone()).await,
        Err(ResolveError::CacheBackend(_))
    ));
    assert!(resolver.transport.requests.lock().unwrap().is_empty());
    backend.unavailable.store(true, Ordering::Relaxed);
    assert!(matches!(
        resolver.resolve(query).await,
        Err(ResolveError::CacheBackend(_))
    ));
}

#[tokio::test]
async fn exhausted_external_conflict_budget_does_not_claim_a_commit() {
    let backend = Arc::new(Backend::default());
    backend.conflicts.store(100, Ordering::Relaxed);
    let resolver = external(backend.clone(), vec![]);
    let error = resolver
        .record_bad_backend(&question(&["bad", "example"]))
        .await
        .unwrap_err();
    assert!(
        matches!(error, ResolveError::CacheBackend(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(backend.values.lock().unwrap().is_empty());
}

#[derive(Clone)]
struct Gated {
    calls: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Semaphore>,
}

impl Transport for Gated {
    fn exchange<'future>(
        &'future self,
        _: SocketAddr,
        query: &'future Message,
        _: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.release.acquire().await.unwrap().forget();
            let mut reply = response(
                Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![address_record(query.questions[0].qname.clone(), 1)],
            );
            reply.questions = query.questions.clone();
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn external_cache_retains_configured_in_flight_capacity() {
    let transport = Gated {
        calls: Arc::new(AtomicUsize::new(0)),
        release: Arc::new(tokio::sync::Semaphore::new(0)),
    };
    let resolver = Arc::new(Resolver::with_cache_engine(
        transport.clone(),
        config(vec!["192.0.2.53:53".parse().unwrap()]),
        CacheEngineConfig::new(Arc::new(Backend::default()), b"in-flight".to_vec(), [7; 32])
            .unwrap(),
    ));
    let mut leaders = Vec::new();
    let mut last = question(&["unused", "example"]);
    // Exceed the 16-slot fallback used when the built-in caches are disabled.
    for index in 0..17 {
        last = question(&[&format!("host{index}"), "example"]);
        let resolver = resolver.clone();
        let query = last.clone();
        leaders.push(tokio::spawn(async move { resolver.resolve(query).await }));
        tokio::time::timeout(Duration::from_secs(1), async {
            while transport.calls.load(Ordering::SeqCst) < index + 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    let following = resolver.clone();
    let query = last.clone();
    let follower = tokio::spawn(async move { following.resolve(query).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while resolver.in_flight.participant_count(&last) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("17th question must still be eligible for coalescing");
    assert_eq!(transport.calls.load(Ordering::SeqCst), 17);
    transport.release.add_permits(17);
    for task in leaders {
        task.await.unwrap().unwrap();
    }
    follower.await.unwrap().unwrap();
}

#[tokio::test]
async fn external_round_trips_do_not_renew_positive_negative_or_bad_deadlines() {
    let backend = Arc::new(Backend::default());
    let mut resolver = external(backend.clone(), vec![]);
    resolver.config.max_bad_ttl = Duration::from_secs(1);
    let positive_query = question(&["positive", "example"]);
    let negative_query = question(&["negative", "example"]);
    let bad_query = question(&["bad", "example"]);
    let mut answer = address_record(positive_query.qname.clone(), 8);
    answer.ttl = 1;
    let positive = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![answer],
    );
    resolver
        .cache_positive_entries_backend(0, &positive, &positive_query)
        .await
        .unwrap();
    let mut negative = response(
        Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        vec![],
    );
    negative
        .authorities
        .push(soa_record(name(&["example"]), 1, 1));
    resolver
        .cache_response_entries_backend(0, &negative, &negative_query, &negative_query, true)
        .await
        .unwrap();
    resolver.record_bad_backend(&bad_query).await.unwrap();
    resolver.record_bad_backend(&bad_query).await.unwrap();
    assert!(
        resolver
            .cached_client_response_backend(&positive_query)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        resolver
            .cached_client_response_backend(&negative_query)
            .await
            .unwrap()
            .is_some()
    );
    assert!(resolver.bad_contains_backend(&bad_query).await.unwrap());
    // Every read above decodes and re-encodes the selected entries. Its original absolute
    // deadlines must survive these transactions and reconstruction from storage.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    drop(resolver);
    let mut restarted = external(backend, vec![]);
    restarted.config.max_bad_ttl = Duration::from_secs(1);
    assert!(
        restarted
            .cached_client_response_backend(&positive_query)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        restarted
            .cached_client_response_backend(&negative_query)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!restarted.bad_contains_backend(&bad_query).await.unwrap());
}

#[derive(Clone, Default)]
struct RoutingTransport(Arc<Mutex<Vec<SocketAddr>>>);

impl Transport for RoutingTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(server);
            let mut reply = if server.ip() == Ipv4Addr::new(192, 0, 2, 53) {
                let mut referral =
                    referral_response(name(&["example"]), name(&["ns", "example"]), 9);
                for record in referral
                    .authorities
                    .iter_mut()
                    .chain(&mut referral.additionals)
                {
                    record.ttl = 1;
                }
                referral
            } else {
                assert_eq!(server, "192.0.2.9:53".parse().unwrap());
                response(
                    Headers {
                        qr: true,
                        aa: true,
                        ..Headers::default()
                    },
                    vec![address_record(query.questions[0].qname.clone(), 8)],
                )
            };
            reply.headers.id = query.headers.id;
            reply.questions = query.questions.clone();
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn external_delegation_routes_new_owners_after_restart_until_original_expiry() {
    let backend = Arc::new(Backend::default());
    let transport = RoutingTransport::default();
    let make = || {
        Resolver::with_cache_engine(
            transport.clone(),
            config(vec!["192.0.2.53:53".parse().unwrap()]),
            CacheEngineConfig::new(backend.clone(), b"delegation".to_vec(), [8; 32]).unwrap(),
        )
    };
    let first = make();
    assert_eq!(
        first
            .resolve(question(&["one", "example"]))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    drop(first);
    let restarted = make();
    assert_eq!(
        restarted
            .resolve(question(&["two", "example"]))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    assert_eq!(
        *transport.0.lock().unwrap(),
        vec![
            "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
            "192.0.2.9:53".parse().unwrap(),
            "192.0.2.9:53".parse().unwrap(),
        ]
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    drop(restarted);
    assert_eq!(
        make()
            .resolve(question(&["three", "example"]))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    let routes = transport.0.lock().unwrap();
    assert_eq!(routes.len(), 5);
    assert_eq!(routes[3], "192.0.2.53:53".parse().unwrap());
    assert_eq!(routes[4], "192.0.2.9:53".parse().unwrap());
}
