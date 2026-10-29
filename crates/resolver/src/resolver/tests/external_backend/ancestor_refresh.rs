//! Lease claims and tombstones must survive independent adapter transactions.
use super::*;

fn zone() -> DomainName {
    name(&["example", "test"])
}

#[tokio::test]
async fn external_recovery_claims_are_exclusive_stale_safe_and_expire_without_resurrection() {
    let backend = Arc::new(Backend::default());
    backend.conflicts.store(2, Ordering::Relaxed);
    let a = external(backend.clone(), vec![]);
    let b = external(backend.clone(), vec![]);
    let zone = zone();
    let claim = |context: &Resolver<MockTransport>| {
        Ok(context.delegation_cache.claim_refresh(
            &zone,
            ClassType::IN,
            false,
            Duration::from_secs(1),
        ))
    };
    let scope = [crate::resolver::engine::zone(&zone, ClassType::IN)];
    let (first, second) = tokio::join!(
        a.cache_transaction_for(&scope, claim),
        b.cache_transaction_for(&scope, claim)
    );
    let (winner, loser, old) = match (first.unwrap(), second.unwrap()) {
        (Some(token), None) => (&a, &b, token),
        (None, Some(token)) => (&b, &a, token),
        other => panic!("{other:?}"),
    };
    assert!(
        a.transport.requests.lock().unwrap().is_empty()
            && b.transport.requests.lock().unwrap().is_empty()
    );
    // A process cannot reconstruct the outstanding owner's private in-flight grant.
    let restart = external(backend.clone(), vec![]);
    assert!(
        restart
            .cache_transaction_for(
                &[crate::resolver::engine::zone(&zone, ClassType::IN)],
                claim
            )
            .await
            .unwrap()
            .is_none()
    );
    tokio::time::sleep(Duration::from_millis(1050)).await;
    let fresh = loser
        .cache_transaction_for(
            &[crate::resolver::engine::zone(&zone, ClassType::IN)],
            claim,
        )
        .await
        .unwrap()
        .unwrap();
    assert_ne!(old, fresh);
    assert!(
        !winner
            .cache_transaction_for(
                &[crate::resolver::engine::zone(&zone, ClassType::IN)],
                |c| Ok(c.delegation_cache.start_refresh(
                    &zone,
                    ClassType::IN,
                    false,
                    old,
                    Duration::from_secs(1)
                ))
            )
            .await
            .unwrap()
    );
    assert!(
        loser
            .cache_transaction_for(
                &[crate::resolver::engine::zone(&zone, ClassType::IN)],
                |c| Ok(c.delegation_cache.start_refresh(
                    &zone,
                    ClassType::IN,
                    false,
                    fresh,
                    Duration::from_secs(1)
                ))
            )
            .await
            .unwrap()
    );
    winner
        .cache_transaction_for(
            &[crate::resolver::engine::zone(&zone, ClassType::IN)],
            |c| {
                c.delegation_cache.finish_refresh_failure(
                    &zone,
                    ClassType::IN,
                    false,
                    old,
                    Duration::from_secs(1),
                );
                Ok(())
            },
        )
        .await
        .unwrap();
    assert_eq!(
        restart
            .cache_transaction_for(
                &[crate::resolver::engine::zone(&zone, ClassType::IN)],
                |c| Ok(c
                    .delegation_cache
                    .refresh_status(&zone, ClassType::IN, false))
            )
            .await
            .unwrap(),
        Some(false)
    );
    loser
        .cache_transaction_for(
            &[crate::resolver::engine::zone(&zone, ClassType::IN)],
            |c| {
                c.delegation_cache.finish_refresh_failure(
                    &zone,
                    ClassType::IN,
                    false,
                    fresh,
                    Duration::from_secs(1),
                );
                Ok(())
            },
        )
        .await
        .unwrap();
    drop(a);
    drop(b);
    drop(restart);
    let query = question(&["fresh", "example", "test"]);
    let restart = external(backend.clone(), vec![]);
    assert!(matches!(
        restart.resolve(query.clone()).await,
        Err(ResolveError::CachedDelegationFailure)
    ));
    assert!(restart.transport.requests.lock().unwrap().is_empty());
    assert!(
        restart
            .cache_transaction_for(
                &[crate::resolver::engine::zone(&zone, ClassType::IN)],
                |c| Ok(c.failure_cache.get(&query, false).is_none())
            )
            .await
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    let another = external(backend.clone(), vec![]);
    assert!(matches!(
        another.resolve(query.clone()).await,
        Err(ResolveError::CachedDelegationFailure)
    ));
    tokio::time::sleep(Duration::from_millis(450)).await;
    let expired = external(
        backend,
        vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(query.qname.clone(), 8)],
        )],
    );
    assert!(!matches!(
        expired.resolve(query).await,
        Err(ResolveError::CachedDelegationFailure)
    ));
    assert!(
        !expired.transport.requests.lock().unwrap().is_empty(),
        "expired tombstone must allow ordinary discovery"
    );
}

#[derive(Default)]
pub(super) struct FailingStartBackend {
    inner: Backend,
    pub(super) fail_next_commit: AtomicBool,
}
impl CacheEngine for FailingStartBackend {
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
            if self.fail_next_commit.swap(false, Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "injected recovery-start commit failure",
                ));
            }
            self.inner.apply(namespace, expected, value).await
        })
    }
}
struct FailingStartAuthority {
    inner: crate::resolver::tests::ancestor::Hierarchy,
    backend: Arc<FailingStartBackend>,
    armed: Arc<AtomicBool>,
}
impl Transport for FailingStartAuthority {
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
            if self.armed.load(Ordering::SeqCst)
                && query.questions[0]
                    .qname
                    .eq_dns(&name(&["ns", "example", "test"]))
            {
                self.backend.fail_next_commit.store(true, Ordering::SeqCst);
            }
            self.inner.exchange(server, query, timeout).await
        })
    }
}

#[tokio::test]
async fn ns_address_recovery_start_commit_error_propagates_without_dns_failure_publication() {
    let backend = Arc::new(FailingStartBackend::default());
    let authority = crate::resolver::tests::ancestor::Hierarchy::new();
    let armed = Arc::new(AtomicBool::new(false));
    let resolver = Resolver::with_cache_engine(
        FailingStartAuthority {
            inner: authority.clone(),
            backend: backend.clone(),
            armed: armed.clone(),
        },
        ResolverConfig {
            root_servers: vec!["192.0.2.1:53".parse().unwrap()],
            ..ResolverConfig::default()
        },
        CacheEngineConfig::new(backend, b"start-failure".to_vec(), [9; 32]).unwrap(),
    );
    resolver
        .resolve(question(&["cached", "example", "test"]))
        .await
        .unwrap();
    authority.fail();
    armed.store(true, Ordering::SeqCst);
    let before = authority.snapshot();
    let q = question(&["uncached", "example", "test"]);
    assert!(
        matches!(resolver.resolve(q.clone()).await,Err(ResolveError::CacheBackend(ref e))
        if e.kind()==io::ErrorKind::ConnectionReset)
    );
    let after = authority.snapshot();
    for server in ["192.0.2.1:53", "192.0.2.2:53"] {
        let server: SocketAddr = server.parse().unwrap();
        assert_eq!(
            before.get(&server),
            after.get(&server),
            "failed CAS must precede ancestor I/O"
        );
    }
    assert_eq!(
        resolver
            .cache_transaction_for(
                &[crate::resolver::engine::zone(&zone(), ClassType::IN)],
                |c| Ok(c
                    .delegation_cache
                    .refresh_status(&zone(), ClassType::IN, false))
            )
            .await
            .unwrap(),
        Some(false)
    );
    assert!(
        resolver
            .cache_transaction_for(
                &[crate::resolver::engine::zone(&zone(), ClassType::IN)],
                |c| Ok(c.failure_cache.get(&q, false).is_none())
            )
            .await
            .unwrap()
    );
    assert!(
        resolver.delegation_cache.get(&q).is_none(),
        "external mode must not publish a builtin fallback"
    );
}
