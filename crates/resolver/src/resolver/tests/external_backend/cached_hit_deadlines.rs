//! A selected external-cache answer must not outlive a slow commit.
use super::*;
use tokio::sync::Semaphore;

struct GatedBackend {
    inner: Backend,
    delay_next: AtomicBool,
    fail_next: AtomicBool,
    entered: Semaphore,
    release: Semaphore,
}

impl Default for GatedBackend {
    fn default() -> Self {
        Self {
            inner: Backend::default(),
            delay_next: AtomicBool::new(false),
            fail_next: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }
}

impl CacheEngine for GatedBackend {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: Option<&'a [u8]>,
        plan: &'a crate::CacheReadPlan,
    ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>> {
        self.inner.read(namespace, expected_revision, plan)
    }

    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        expected: &'a [u8],
        value: &'a crate::CacheMutationBatch,
    ) -> transport::BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            if self.delay_next.swap(false, Ordering::SeqCst) {
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
                if self.fail_next.swap(false, Ordering::SeqCst) {
                    return Err(io::Error::other("delayed commit failed"));
                }
            }
            self.inner.apply(namespace, expected, value).await
        })
    }
}

fn gated(backend: Arc<GatedBackend>, replies: Vec<Message>) -> Resolver<MockTransport> {
    Resolver::with_cache_engine(
        MockTransport {
            replies: Arc::new(Mutex::new(replies)),
            requests: Arc::new(Mutex::new(Vec::new())),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
        CacheEngineConfig::new(backend, b"cache-hit-deadline".to_vec(), [7; 32]).unwrap(),
    )
}

async fn release_after(backend: &GatedBackend, wait: Duration) {
    tokio::time::timeout(Duration::from_secs(3), backend.entered.acquire())
        .await
        .expect("cache transaction did not reach commit")
        .unwrap()
        .forget();
    tokio::time::sleep(wait).await;
    backend.release.add_permits(1);
}

#[tokio::test]
async fn expired_positive_and_negative_hits_requery_after_slow_commit() {
    for negative in [false, true] {
        let backend = Arc::new(GatedBackend::default());
        let query = question(&["held", "example"]);
        let fresh = response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 42)],
        );
        let resolver = Arc::new(gated(backend.clone(), vec![fresh]));
        if negative {
            let mut old = response(
                Headers {
                    qr: true,
                    aa: true,
                    rcode: RCode::NameError,
                    ..Headers::default()
                },
                vec![],
            );
            old.authorities.push(soa_record(name(&["example"]), 2, 2));
            resolver
                .cache_response_entries_backend(0, &old, &query, &query, true)
                .await
                .unwrap();
        } else {
            let mut old = response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![address_record(query.qname.clone(), 1)],
            );
            old.answers[0].ttl = 2;
            resolver
                .cache_positive_entries_backend(0, &old, &query)
                .await
                .unwrap();
        }
        backend.delay_next.store(true, Ordering::SeqCst);
        let waiting = {
            let resolver = Arc::clone(&resolver);
            let query = query.clone();
            tokio::spawn(async move { resolver.resolve(query).await })
        };
        release_after(&backend, Duration::from_millis(2200)).await;
        let reply = waiting.await.unwrap().unwrap();
        assert!(
            matches!(reply.answers[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 42))
        );
        assert_eq!(resolver.transport.requests.lock().unwrap().len(), 1);

        // A new process sees the fresh committed answer, not the expired hit.
        let restarted = gated(backend, vec![]);
        let reply = restarted.resolve(query).await.unwrap();
        assert!(
            matches!(reply.answers[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 42))
        );
    }
}

#[tokio::test]
async fn slow_live_hit_loses_ttl_and_failed_commit_is_not_returned() {
    let backend = Arc::new(GatedBackend::default());
    let query = question(&["live", "example"]);
    let resolver = Arc::new(gated(backend.clone(), vec![]));
    let mut reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 9)],
    );
    reply.answers[0].ttl = 30;
    resolver
        .cache_positive_entries_backend(0, &reply, &query)
        .await
        .unwrap();
    let before = resolver
        .cached_client_response_backend(&query)
        .await
        .unwrap()
        .unwrap();
    backend.delay_next.store(true, Ordering::SeqCst);
    let waiting = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.cached_client_response_backend(&query).await })
    };
    release_after(&backend, Duration::from_millis(1200)).await;
    let after = waiting.await.unwrap().unwrap().unwrap();
    assert!(after.response.answers[0].ttl < before.response.answers[0].ttl);
    assert!(resolver.transport.requests.lock().unwrap().is_empty());

    backend.fail_next.store(true, Ordering::SeqCst);
    backend.delay_next.store(true, Ordering::SeqCst);
    let waiting = {
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move { resolver.cached_client_response_backend(&query).await })
    };
    release_after(&backend, Duration::from_millis(10)).await;
    assert!(matches!(
        waiting.await.unwrap(),
        Err(ResolveError::CacheBackend(_))
    ));
}

#[tokio::test]
async fn iterative_cache_selection_is_rechecked_after_delayed_commit() {
    for negative in [false, true] {
        let backend = Arc::new(GatedBackend::default());
        let query = question(&["iterative", "example"]);
        let resolver = Arc::new(gated(backend.clone(), vec![]));
        if negative {
            let mut old = response(
                Headers {
                    qr: true,
                    aa: true,
                    rcode: RCode::NameError,
                    ..Headers::default()
                },
                vec![],
            );
            old.authorities.push(soa_record(name(&["example"]), 1, 1));
            resolver
                .cache_response_entries_backend(0, &old, &query, &query, true)
                .await
                .unwrap();
        } else {
            let mut record = address_record(query.qname.clone(), 1);
            record.ttl = 1;
            let old = response(
                Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![record],
            );
            resolver
                .cache_positive_entries_backend(0, &old, &query)
                .await
                .unwrap();
        }
        backend.delay_next.store(true, Ordering::SeqCst);
        let waiting = {
            let resolver = Arc::clone(&resolver);
            let query = query.clone();
            tokio::spawn(async move {
                resolver
                    .cached_resolution_backend(
                        &query,
                        query.clone(),
                        vec![],
                        vec![],
                        crate::name::NameSet::from_name(&query.qname),
                        None,
                    )
                    .await
            })
        };
        release_after(&backend, Duration::from_millis(1100)).await;
        assert!(matches!(
            waiting.await.unwrap().unwrap(),
            crate::resolver::cache::CachedResolution::Continue { .. }
        ));
    }
}

#[tokio::test]
async fn expired_cached_alias_loop_does_not_survive_a_delayed_commit() {
    let backend = Arc::new(GatedBackend::default());
    let resolver = Arc::new(gated(backend.clone(), vec![]));
    let query = question(&["a", "example"]);
    let other = question(&["b", "example"]);
    for (owner, target) in [(&query, &other), (&other, &query)] {
        let alias_query = Question {
            qtype: QueryType::CNAME,
            ..owner.clone()
        };
        let mut alias = cname_record(owner.qname.clone(), target.qname.clone());
        alias.ttl = 2;
        let reply = response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![alias],
        );
        resolver
            .cache_positive_entries_backend(0, &reply, &alias_query)
            .await
            .unwrap();
    }
    assert!(matches!(
        resolver.cached_client_response_backend(&query).await,
        Err(ResolveError::CnameLoop)
    ));
    backend.delay_next.store(true, Ordering::SeqCst);
    let waiting = {
        let resolver = Arc::clone(&resolver);
        let query = query.clone();
        tokio::spawn(async move { resolver.cached_client_response_backend(&query).await })
    };
    release_after(&backend, Duration::from_millis(2200)).await;
    assert!(waiting.await.unwrap().unwrap().is_none());
}
