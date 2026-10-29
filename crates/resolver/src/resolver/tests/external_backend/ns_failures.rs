use super::ancestor_refresh::FailingStartBackend;
use super::*;

fn ns() -> DomainName {
    name(&["ns", "example", "test"])
}
fn refusal() -> Message {
    response(
        Headers {
            qr: true,
            rcode: RCode::Refused,
            ..Headers::default()
        },
        vec![],
    )
}
async fn lookup<'a, T: Transport>(
    resolver: &'a Resolver<T>,
    cd: bool,
) -> crate::resolver::address::NameServerAddressResolution<'a> {
    let signals = crate::resolver::AlgorithmSignals {
        checking_disabled: cd,
        ..crate::resolver::AlgorithmSignals::default()
    };
    resolver
        .resolve_name_server_addresses(
            &[ns()],
            &[],
            Arc::new(AtomicUsize::new(64)),
            None,
            Arc::new(signals),
        )
        .await
}
#[tokio::test]
async fn exact_ns_failures_survive_engine_restart_keep_cd_scope_and_do_not_renew_on_read() {
    let backend = Arc::new(Backend::default());
    let first = external(backend.clone(), vec![refusal(), refusal()]);
    assert!(lookup(&first, false).await.error.is_none());
    assert_eq!(first.transport.requests.lock().unwrap().len(), 2);
    drop(first);
    let repeated = external(backend.clone(), vec![]);
    assert!(matches!(
        lookup(&repeated, false).await.error,
        Some(ResolveError::CachedNameServerFailure)
    ));
    assert!(repeated.transport.requests.lock().unwrap().is_empty());
    let cd = external(backend.clone(), vec![refusal(), refusal()]);
    assert!(lookup(&cd, true).await.error.is_none());
    assert_eq!(cd.transport.requests.lock().unwrap().len(), 2);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let middle = external(backend.clone(), vec![]);
    assert!(matches!(
        lookup(&middle, false).await.error,
        Some(ResolveError::CachedNameServerFailure)
    ));
    tokio::time::sleep(Duration::from_millis(450)).await;
    let q = Question {
        qname: ns(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let recovered = external(
        backend,
        vec![response(
            Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            vec![address_record(q.qname, 90)],
        )],
    );
    let answer = lookup(&recovered, false).await;
    assert_eq!(answer.addresses, ["192.0.2.90:53".parse().unwrap()]);
    assert_eq!(
        recovered.transport.requests.lock().unwrap().len(),
        1,
        "original NS failure deadline must expire after repeated external reads"
    );
}

struct RefusingWithCommitFault {
    backend: Arc<FailingStartBackend>,
    requests: Arc<AtomicUsize>,
}
impl Transport for RefusingWithCommitFault {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Udp)
    }
    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            self.requests.fetch_add(1, Ordering::SeqCst);
            self.backend.fail_next_commit.store(true, Ordering::SeqCst);
            let mut reply = refusal();
            reply.headers.id = query.headers.id;
            reply.questions = query.questions.clone();
            Ok(reply)
        })
    }
}
#[tokio::test]
async fn failure_memo_commit_error_is_fatal_without_builtin_fallback_or_false_memo() {
    let backend = Arc::new(FailingStartBackend::default());
    let requests = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver::with_cache_engine(
        RefusingWithCommitFault {
            backend: backend.clone(),
            requests: requests.clone(),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
        CacheEngineConfig::new(backend, b"ns-memo-fault".to_vec(), [8; 32]).unwrap(),
    );
    assert!(matches!(
        lookup(&resolver, false).await.error,
        Some(ResolveError::CacheBackend(_))
    ));
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "fatal commit failure must not become ordinary AAAA absence"
    );
    let q = Question {
        qname: ns(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(resolver.failure_cache.get(&q, false).is_none());
    assert!(
        resolver
            .cache_transaction_for(std::slice::from_ref(&q), |c| Ok(c
                .failure_cache
                .get(&q, false)
                .is_none()))
            .await
            .unwrap()
    );
}
