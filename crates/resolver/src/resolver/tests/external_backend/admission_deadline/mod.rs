//! Received packet TTLs cannot be restarted by external cache waits.
use super::*;
use tokio::sync::{Notify, Semaphore};

mod delegation;

struct DelayedBackend {
    inner: Backend,
    checkout_wait: AtomicBool,
    cas_wait: AtomicBool,
    entered: Notify,
    release: Semaphore,
}

impl Default for DelayedBackend {
    fn default() -> Self {
        Self {
            inner: Backend::default(),
            checkout_wait: AtomicBool::new(false),
            cas_wait: AtomicBool::new(false),
            entered: Notify::new(),
            release: Semaphore::new(0),
        }
    }
}

impl DelayedBackend {
    async fn wait_for_release(&self) {
        self.entered.notify_one();
        self.release.acquire().await.unwrap().forget();
    }
}

impl CacheEngine for DelayedBackend {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: Option<&'a [u8]>,
        plan: &'a crate::CacheReadPlan,
    ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>> {
        Box::pin(async move {
            if self.checkout_wait.swap(false, Ordering::SeqCst) {
                self.wait_for_release().await;
            }
            self.inner.read(namespace, expected_revision, plan).await
        })
    }

    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        expected: &'a [u8],
        value: &'a crate::CacheMutationBatch,
    ) -> transport::BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            if self.cas_wait.swap(false, Ordering::SeqCst) {
                self.wait_for_release().await;
            }
            self.inner.apply(namespace, expected, value).await
        })
    }
}

fn make_resolver(backend: Arc<DelayedBackend>) -> Resolver<MockTransport> {
    Resolver::with_cache_engine(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![])),
            requests: Arc::new(Mutex::new(Vec::new())),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
        CacheEngineConfig::new(backend, b"admission-deadline".to_vec(), [7; 32]).unwrap(),
    )
}

async fn release_after(backend: &DelayedBackend, delay: Duration) {
    tokio::time::timeout(Duration::from_secs(3), backend.entered.notified())
        .await
        .expect("transaction did not enter the delayed operation");
    tokio::time::sleep(delay).await;
    backend.release.add_permits(1);
}

#[tokio::test]
async fn delayed_checkout_does_not_admit_expired_positive_negative_or_aliases() {
    for mode in 0..3 {
        let backend = Arc::new(DelayedBackend::default());
        let resolver = Arc::new(make_resolver(backend.clone()));
        let alias = question(&["alias", "example"]);
        let target = question(&["target", "example"]);
        let mut positive = response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(target.qname.clone(), 42)],
        );
        positive.answers[0].ttl = 2;
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
            .push(soa_record(name(&["example"]), 2, 2));
        let mut alias_record = cname_record(alias.qname.clone(), target.qname.clone());
        alias_record.ttl = 2;
        let mut composed = positive.clone();
        composed.answers.insert(0, alias_record);
        backend.checkout_wait.store(true, Ordering::SeqCst);
        let waiting = {
            let resolver = resolver.clone();
            let target = target.clone();
            let alias = alias.clone();
            tokio::spawn(async move {
                let at = std::time::Instant::now();
                match mode {
                    0 => {
                        resolver
                            .cache_positive_entries_backend_at(0, &positive, &target, at)
                            .await
                    }
                    1 => resolver
                        .cache_response_entries_backend_at(0, &negative, &target, &target, true, at)
                        .await
                        .map(|_| ()),
                    _ => resolver
                        .cache_cname_completed_backend_at(
                            crate::resolver::cache::CnameCompletedCacheContext {
                                id: 0,
                                terminal_reply: &positive,
                                terminal_question: &target,
                                reply: &composed,
                                positive_question: &alias,
                                negative_question: &target,
                                negative_authoritative: true,
                            },
                            at,
                        )
                        .await
                        .map(|_| ()),
                }
            })
        };
        release_after(&backend, Duration::from_millis(2200)).await;
        waiting.await.unwrap().unwrap();
        assert!(
            resolver
                .cached_client_response_backend(&target)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            resolver
                .cached_client_response_backend(&alias)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn retry_and_delayed_commit_do_not_renew_the_selected_response() {
    let backend = Arc::new(DelayedBackend::default());
    let resolver = Arc::new(make_resolver(backend.clone()));
    let query = question(&["fresh", "example"]);
    let mut reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 9)],
    );
    reply.answers[0].ttl = 6;
    backend.inner.conflicts.store(1, Ordering::SeqCst);
    backend.cas_wait.store(true, Ordering::SeqCst);
    let waiting = {
        let resolver = resolver.clone();
        let query = query.clone();
        tokio::spawn(async move {
            resolver
                .cache_response_entries_backend_at(
                    0,
                    &reply,
                    &query,
                    &query,
                    true,
                    std::time::Instant::now(),
                )
                .await
        })
    };
    release_after(&backend, Duration::from_millis(1200)).await;
    let selected = waiting
        .await
        .unwrap()
        .unwrap()
        .expect("selected positive answer");
    assert!(
        selected.answers[0].ttl < 6,
        "selected reply renewed its TTL"
    );
    let cached = resolver
        .cached_client_response_backend(&query)
        .await
        .unwrap()
        .unwrap();
    assert!(
        cached.response.answers[0].ttl < 6,
        "retry renewed its cached TTL"
    );
}

#[tokio::test]
async fn live_subsecond_positive_and_negative_entries_are_not_dropped_or_renewed() {
    for negative in [false, true] {
        let backend = Arc::new(DelayedBackend::default());
        let resolver = make_resolver(backend.clone());
        let query = question(&["short", "example"]);
        let observed_at = std::time::Instant::now() - Duration::from_millis(200);
        if negative {
            let mut reply = response(
                Headers {
                    qr: true,
                    aa: true,
                    rcode: RCode::NameError,
                    ..Headers::default()
                },
                vec![],
            );
            reply.authorities.push(soa_record(name(&["example"]), 1, 1));
            resolver
                .cache_response_entries_backend_at(0, &reply, &query, &query, true, observed_at)
                .await
                .unwrap();
        } else {
            let mut answer = address_record(query.qname.clone(), 1);
            answer.ttl = 1;
            let reply = response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![answer],
            );
            resolver
                .cache_positive_entries_backend_at(0, &reply, &query, observed_at)
                .await
                .unwrap();
        }
        let hit = resolver
            .cached_client_response_backend(&query)
            .await
            .unwrap();
        assert!(
            hit.is_some(),
            "a still-live subsecond entry must remain cacheable"
        );
        tokio::time::sleep(Duration::from_millis(900)).await;
        let restarted = make_resolver(backend);
        assert!(
            restarted
                .cached_client_response_backend(&query)
                .await
                .unwrap()
                .is_none(),
            "restart cannot renew the original deadline"
        );
    }
}

#[tokio::test]
async fn authenticated_deadline_cap_survives_entry_engine_round_trip() {
    let backend = Arc::new(DelayedBackend::default());
    let resolver = make_resolver(backend.clone());
    let query = question(&["bounded", "example"]);
    let reply = response(
        Headers {
            qr: true,
            aa: true,
            ad: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 9)],
    );
    let observed_at = std::time::Instant::now();
    let deadline = observed_at + Duration::from_secs(1);
    resolver
        .cache_transaction_for(std::slice::from_ref(&query), |context| {
            context.cache_positive_entries_at(0, &reply, &query, observed_at, Some(deadline));
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        resolver
            .cached_client_response_backend(&query)
            .await
            .unwrap()
            .is_some()
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let restarted = make_resolver(backend);
    assert!(
        restarted
            .cached_client_response_backend(&query)
            .await
            .unwrap()
            .is_none()
    );
}

#[derive(Clone)]
struct NegativeTransport {
    backend: Arc<DelayedBackend>,
    calls: Arc<AtomicUsize>,
}

impl Transport for NegativeTransport {
    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut reply = response(
                Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    rcode: RCode::NameError,
                    ..Headers::default()
                },
                vec![],
            );
            reply.questions = query.questions.clone();
            reply.authorities.push(soa_record(name(&["example"]), 2, 2));
            self.backend.cas_wait.store(true, Ordering::SeqCst);
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn network_negative_reply_ages_during_delayed_admission_commit() {
    let backend = Arc::new(DelayedBackend::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = Arc::new(Resolver::with_cache_engine(
        NegativeTransport {
            backend: backend.clone(),
            calls: calls.clone(),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
        CacheEngineConfig::new(
            backend.clone(),
            b"negative-delayed-delivery".to_vec(),
            [7; 32],
        )
        .unwrap(),
    ));
    let query = question(&["missing", "example"]);
    let waiting = {
        let resolver = resolver.clone();
        let query = query.clone();
        tokio::spawn(async move { resolver.resolve(query).await })
    };
    release_after(&backend, Duration::from_millis(2200)).await;
    let reply = waiting.await.unwrap().unwrap();
    assert_eq!(reply.headers.rcode, RCode::NameError);
    let soa = reply
        .authorities
        .iter()
        .find(|rr| rr.rtype == RecordType::SOA)
        .unwrap();
    assert_eq!(
        soa.ttl, 0,
        "backend commit cannot renew the delivered negative TTL"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        resolver
            .cached_client_response_backend(&query)
            .await
            .unwrap()
            .is_none()
    );
}
